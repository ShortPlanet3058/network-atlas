"""Local HTTP viewer: read APIs, scan control and a server-sent event stream."""

from __future__ import annotations

import json
import queue
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, netinfo, scheduler, webid
from .collectors import PROFILE_LABELS, PROFILES
from .db import AtlasDB
from .jobs import JobError, JobManager
from .util import can_capture, nmap_privileged, utc_now


STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}
MAX_BODY = 64 * 1024

# Mutating requests must prove they came from the app rather than from a page the
# user happened to visit. The token is minted per process and read from /api/session.
CSRF_TOKEN = secrets.token_urlsafe(24)


class AtlasHandler(BaseHTTPRequestHandler):
    db_path: Path
    jobs: JobManager
    scheduler: scheduler.Scheduler | None = None
    server_version = f"NetworkAtlas/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- plumbing -------------------------------------------------------------
    def _headers(self, status: int, content_type: str, length: int | None = None, **extra: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("Cache-Control", "no-store")
        for key, value in extra.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        if self.command != "HEAD":
            self.wfile.write(body)

    def _static(self, name: str) -> None:
        content_type = STATIC_FILES.get(name)
        path = (STATIC_DIR / name).resolve()
        if content_type is None or STATIC_DIR.resolve() not in path.parents or not path.is_file():
            self._json({"error": "not found"}, 404)
            return
        body = path.read_bytes()
        self._headers(200, content_type, len(body))
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("Request body too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")
        return payload

    def _authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Atlas-Token", ""), CSRF_TOKEN)

    def _flag(self, query: dict[str, list[str]], name: str, default: bool = True) -> bool:
        raw = query.get(name, [None])[0]
        if raw is None:
            return default
        return raw.lower() not in ("0", "false", "no")

    # -- event stream ---------------------------------------------------------
    def _events(self) -> None:
        channel = self.jobs.events.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    message = channel.get(timeout=20)
                except queue.Empty:
                    # Comment frames keep the connection alive through idle periods.
                    self.wfile.write(b": keep-alive\n\n")
                else:
                    self.wfile.write(message.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.jobs.events.unsubscribe(channel)

    # -- routes ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path
        try:
            if route == "/api/stream":
                self._events()
                return
            if route == "/api/session":
                self._json({
                    "version": __version__,
                    "token": CSRF_TOKEN,
                    "capabilities": {
                        "raw_packets": nmap_privileged(),
                        "passive_capture": can_capture(),
                        "web_identity": webid.available(),
                    },
                    "profiles": [
                        {"id": profile, "label": PROFILE_LABELS[profile]} for profile in PROFILES
                    ],
                    "vantage": netinfo.summary(),
                    "server_time": utc_now(),
                })
                return

            online = self._flag(query, "online", True)
            if route == "/api/summary":
                with AtlasDB(self.db_path) as db:
                    db.reap_stale_scans()
                    self._json(db.summary())
            elif route == "/api/graph":
                with AtlasDB(self.db_path) as db:
                    self._json(db.graph(online_only=online))
            elif route == "/api/tree":
                with AtlasDB(self.db_path) as db:
                    self._json(db.tree(online_only=online))
            elif route == "/api/devices":
                with AtlasDB(self.db_path) as db:
                    self._json(db.devices(online_only=online))
            elif route == "/api/services":
                with AtlasDB(self.db_path) as db:
                    self._json(db.services_overview(online_only=online))
            elif route == "/api/changes":
                with AtlasDB(self.db_path) as db:
                    self._json(db.changes(int(query.get("limit", ["40"])[0])))
            elif route == "/api/scans":
                with AtlasDB(self.db_path) as db:
                    self._json(db.scans(int(query.get("limit", ["30"])[0])))
            elif route == "/api/findings":
                with AtlasDB(self.db_path) as db:
                    self._json({
                        "findings": db.findings(
                            include_resolved=self._flag(query, "resolved", False),
                            include_muted=self._flag(query, "muted", False),
                        ),
                        "summary": db.summary()["findings"],
                    })
            elif route == "/api/events":
                with AtlasDB(self.db_path) as db:
                    self._json(db.events(limit=int(query.get("limit", ["120"])[0])))
            elif route == "/api/flows":
                with AtlasDB(self.db_path) as db:
                    self._json(db.flows(limit=int(query.get("limit", ["300"])[0])))
            elif route == "/api/schedule":
                with AtlasDB(self.db_path) as db:
                    self._json({
                        "entries": scheduler.entries(db),
                        "monitoring": scheduler.monitoring_active(db),
                        "running": self.scheduler is not None,
                    })
            elif route == "/api/jobs":
                self._json(self.jobs.list_jobs())
            elif route in ("/", "/index.html"):
                self._static("index.html")
            elif route.lstrip("/") in STATIC_FILES:
                self._static(route.lstrip("/"))
            else:
                self._json({"error": "not found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self.log_error("request failed: %s", exc)
            self._json({"error": "internal server error"}, 500)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if not self._authorized():
                self._json({"error": "missing or invalid X-Atlas-Token"}, 403)
                return
            payload = self._body()
            if parsed.path == "/api/scan":
                kind = str(payload.get("kind") or "scan")
                parameters = payload.get("parameters")
                job = self.jobs.submit(kind, parameters if isinstance(parameters, dict) else {})
                self._json(job.snapshot(), 202)
            elif parsed.path == "/api/scan/cancel":
                job_id = str(payload.get("id") or "")
                self._json({"cancelled": self.jobs.cancel(job_id)})
            elif parsed.path == "/api/label":
                selector = str(payload.get("selector") or "")
                name = payload.get("name")
                device_type = payload.get("type")
                with AtlasDB(self.db_path) as db:
                    device_id = db.set_manual_label(
                        selector,
                        None if name is None else str(name),
                        None if device_type is None else str(device_type),
                    )
                self.jobs.events.publish("inventory", {"reason": "label", "at": utc_now()})
                self._json({"device_id": device_id, "status": "updated"})
            elif parsed.path == "/api/monitoring":
                enabled = bool(payload.get("enabled"))
                with AtlasDB(self.db_path) as db:
                    changed = scheduler.set_monitoring(db, enabled)
                    active = scheduler.monitoring_active(db)
                self.jobs.events.publish(
                    "schedule", {"monitoring": active, "at": utc_now()}
                )
                self._json({"monitoring": active, "changed": changed})
            elif parsed.path == "/api/schedule":
                kind = str(payload.get("kind") or "")
                with AtlasDB(self.db_path) as db:
                    if "enabled" in payload:
                        scheduler.set_enabled(db, kind, bool(payload["enabled"]))
                    if "interval_seconds" in payload:
                        scheduler.set_interval(db, kind, int(payload["interval_seconds"]))
                    entries = scheduler.entries(db)
                    active = scheduler.monitoring_active(db)
                self.jobs.events.publish(
                    "schedule", {"monitoring": active, "at": utc_now()}
                )
                self._json({"entries": entries, "monitoring": active})
            elif parsed.path == "/api/findings/mute":
                finding_id = int(payload.get("id") or 0)
                with AtlasDB(self.db_path) as db:
                    db.set_finding_muted(finding_id, bool(payload.get("muted", True)))
                self.jobs.events.publish("inventory", {"reason": "finding", "at": utc_now()})
                self._json({"id": finding_id, "muted": bool(payload.get("muted", True))})
            elif parsed.path == "/api/events/acknowledge":
                with AtlasDB(self.db_path) as db:
                    count = db.acknowledge_events(payload.get("before"))
                self._json({"acknowledged": count})
            elif parsed.path == "/api/device":
                # Ownership and expectations, which only a person can supply.
                selector = str(payload.get("selector") or "")
                fields: dict[str, object] = {}
                for key in ("owner", "location", "notes"):
                    if key in payload:
                        value = payload[key]
                        fields[key] = None if value in (None, "") else str(value)
                if "approved" in payload:
                    approved = payload["approved"]
                    fields["approved"] = None if approved is None else int(bool(approved))
                if not fields:
                    raise ValueError("Nothing to update")
                with AtlasDB(self.db_path) as db:
                    device_id = db.resolve_selector(selector)
                    db.update_device(device_id, **fields)
                    db.commit()
                self.jobs.events.publish("inventory", {"reason": "device", "at": utc_now()})
                self._json({"device_id": device_id, "updated": sorted(fields)})
            elif parsed.path == "/api/prune":
                with AtlasDB(self.db_path) as db:
                    removed = db.prune_ghosts()
                self.jobs.events.publish("inventory", {"reason": "prune", "at": utc_now()})
                self._json({"removed": removed})
            else:
                self._json({"error": "not found"}, 404)
        except JobError as exc:
            self._json({"error": str(exc)}, 409)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self.log_error("request failed: %s", exc)
            self._json({"error": "internal server error"}, 500)

    def log_message(self, format_string: str, *args: object) -> None:
        if "/api/stream" in str(args):
            return
        print(f"[viewer] {self.address_string()} {format_string % args}", flush=True)


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    manager = JobManager(db_path)

    def submit(kind: str, parameters: dict[str, object]) -> object:
        return manager.submit(kind, parameters)

    periodic = scheduler.Scheduler(db_path, submit)
    handler = type(
        "ConfiguredAtlasHandler",
        (AtlasHandler,),
        {"db_path": db_path, "jobs": manager, "scheduler": periodic},
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    with AtlasDB(db_path) as db:
        db.reap_stale_scans()
        scheduler.ensure_defaults(db)
        monitoring = scheduler.monitoring_active(db)
    periodic.start()
    print(f"Network Atlas {__version__}: http://{host}:{port}", flush=True)
    print(f"Database: {db_path}", flush=True)
    print(
        f"Raw packets: {nmap_privileged()} | Passive capture: {can_capture()}",
        flush=True,
    )
    print(
        "Continuous monitoring: "
        + ("on" if monitoring else "off (enable it in the viewer or with `make monitor`)"),
        flush=True,
    )
    container = netinfo.container_info()
    if container["network_isolated"]:
        # Loud, because every scan will otherwise come back empty for a reason
        # that has nothing to do with the network being scanned.
        print(
            "\nWARNING: this container cannot see the network you want to map — "
            f"{container['isolation_reason']}.\n"
            "         Scans will return almost nothing. Use host networking or "
            "macvlan on Linux;\n"
            "         on Docker Desktop for macOS/Windows, run it natively or on a "
            "Linux host instead.\n"
            "         See https://github.com/ShortPlanet3058/network-atlas/wiki/Docker.\n",
            flush=True,
        )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping viewer")
    finally:
        periodic.stop()
        httpd.server_close()
