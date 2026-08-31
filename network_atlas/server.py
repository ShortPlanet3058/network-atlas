"""Local HTTP viewer: read APIs, scan control and a server-sent event stream."""

from __future__ import annotations

import errno
import json
import queue
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, auth, netinfo, scheduler, webid
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
# Deliberately absent from STATIC_FILES: it carries a nonce placeholder that has
# to be substituted per response, so serving it as a plain file would ship
# "__CSP_NONCE__" to the browser under a policy that then blocks its own styles
# and script. _login_page is the only way it goes out.
LOGIN_PAGE = "login.html"

# The only paths reachable without a session. Kept as an explicit set rather than
# a pattern: a rule like "anything under /login" is one typo away from exposing
# the API, and this list should be read in full whenever it changes.
#
# login.html is self-contained -- its CSS is inline -- so an unauthenticated
# browser needs no stylesheet or script from here to render the login form.
PUBLIC_ROUTES = frozenset({"/login", "/login.html", "/api/login", "/healthz"})
# The app page loads its CSS and JS as separate files, so it needs no inline
# anything and the policy can stay this tight. form-action 'none' is safe because
# every submission goes through fetch(), not a form POST.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'"
)

# The login page is the exception: it must render before any authenticated
# request can succeed, so its CSS and JS are inline rather than fetched from a
# protected path. A per-response nonce lets exactly those two blocks run without
# opening the policy to inline content generally -- 'unsafe-inline' here would
# apply to every page the viewer serves.
CSP_NONCE_PLACEHOLDER = "__CSP_NONCE__"

MAX_BODY = 64 * 1024

# Mutating requests must prove they came from the app rather than from a page the
# user happened to visit. The token is minted per process and read from /api/session.
CSRF_TOKEN = secrets.token_urlsafe(24)


class AtlasHandler(BaseHTTPRequestHandler):
    db_path: Path
    jobs: JobManager
    scheduler: scheduler.Scheduler | None = None
    sessions: auth.SessionStore
    server_version = f"NetworkAtlas/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- plumbing -------------------------------------------------------------
    def _headers(
        self,
        status: int,
        content_type: str,
        length: int | None = None,
        *,
        csp: str | None = None,
        **extra: str,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", csp or CSP)
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

    def _login_page(self) -> None:
        """Serve the login form with a nonce authorising its inline blocks."""
        path = (STATIC_DIR / LOGIN_PAGE).resolve()
        if STATIC_DIR.resolve() not in path.parents or not path.is_file():
            self._json({"error": "not found"}, 404)
            return
        nonce = secrets.token_urlsafe(16)
        html = path.read_text(encoding="utf-8").replace(CSP_NONCE_PLACEHOLDER, nonce)
        body = html.encode("utf-8")
        self._headers(
            200, "text/html; charset=utf-8", len(body),
            csp=(
                f"default-src 'self'; script-src 'nonce-{nonce}'; "
                f"style-src 'nonce-{nonce}'; img-src 'self' data:; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'"
            ),
        )
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

    # -- authentication -------------------------------------------------------
    def _cookie(self, name: str) -> str | None:
        """Read one cookie without pulling in the whole http.cookies machinery."""
        header = self.headers.get("Cookie") or ""
        for part in header.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value or None
        return None

    def _session(self) -> auth.Session | None:
        return self.sessions.get(self._cookie(auth.SESSION_COOKIE))

    def _client(self) -> str:
        """The address used for login throttling.

        Deliberately the peer address and never X-Forwarded-For: a header the
        client controls would let one attacker present as thousands and defeat the
        lockout entirely.
        """
        return self.client_address[0] if self.client_address else "unknown"

    def _set_session_cookie(self, token: str) -> str:
        # No Secure flag: this serves plain HTTP, and setting Secure would stop the
        # cookie being sent at all. SameSite=Strict is the CSRF defence here.
        return (
            f"{auth.SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; "
            f"Max-Age={auth.SESSION_TTL_SECONDS}"
        )

    def _require_session(self, route: str) -> auth.Session | None:
        """Return the caller's session, or answer them and return None.

        An API call gets 401 JSON so the page can react; a navigation gets the
        login page, so typing the address in a browser lands somewhere useful.
        """
        session = self._session()
        if session is not None:
            return session
        if route.startswith("/api/"):
            self._json({"error": "authentication required"}, 401)
        else:
            self._login_page()
        return None

    def _flag(self, query: dict[str, list[str]], name: str, default: bool = True) -> bool:
        raw = query.get(name, [None])[0]
        if raw is None:
            return default
        return raw.lower() not in ("0", "false", "no")

    # -- login ----------------------------------------------------------------
    def _login(self) -> None:
        """Check a username and password and issue a session.

        Failures say only that the credentials were wrong. Distinguishing "no such
        user" from "wrong password" would confirm which account names exist, and
        there is one account, so the distinction buys the caller nothing anyway.
        """
        client = self._client()
        locked = self.sessions.lockout_remaining(client)
        if locked:
            self._json(
                {"error": f"Too many failed attempts. Try again in {locked} seconds."},
                429,
            )
            return
        payload = self._body()
        username = str(payload.get("username") or "").strip().lower()
        password = str(payload.get("password") or "")

        with AtlasDB(self.db_path) as db:
            account = db.account()
            ok = bool(
                account
                and username == account["username"]
                and auth.verify_password(
                    password, account["password_salt"], account["password_hash"]
                )
            )
            if not ok:
                lockout = self.sessions.record_failure(client)
                self.log_message("failed login for %r from %s", username, client)
                message = "Incorrect username or password."
                if lockout:
                    message = f"Too many failed attempts. Try again in {lockout} seconds."
                self._json({"error": message}, 401)
                return
            db.touch_account_login(int(account["id"]))

        self.sessions.record_success(client)
        session = self.sessions.open(int(account["id"]), account["username"])
        body = json.dumps({"username": session.username}).encode("utf-8")
        self._headers(
            200, "application/json; charset=utf-8", len(body),
            Set_Cookie=self._set_session_cookie(session.token),
        )
        self.wfile.write(body)

    def _change_password(self, payload: dict[str, object]) -> None:
        """Replace the account password, then sign every other browser out.

        The password arrives printed in a terminal, so it is likely to be sitting
        in scrollback or a chat message. Being able to replace it from the viewer
        is what makes that acceptable.
        """
        session = self._session()
        if session is None:
            self._json({"error": "authentication required"}, 401)
            return
        current = str(payload.get("current_password") or "")
        replacement = str(payload.get("new_password") or "")
        with AtlasDB(self.db_path) as db:
            account = db.account()
            if not account or not auth.verify_password(
                current, account["password_salt"], account["password_hash"]
            ):
                # Throttled like a login: this endpoint accepts a password too.
                self.sessions.record_failure(self._client())
                self._json({"error": "The current password is not correct."}, 403)
                return
            try:
                auth.check_password_strength(replacement)
            except auth.AuthError as exc:
                self._json({"error": str(exc)}, 400)
                return
            salt, hashed = auth.hash_password(replacement)
            db.set_account_password(int(account["id"]), hashed, salt)

        # Everyone is signed out, including this browser, which is then handed a
        # fresh session so the person who made the change is not logged out.
        self.sessions.close_user(session.user_id)
        renewed = self.sessions.open(session.user_id, session.username)
        body = json.dumps({"changed": True}).encode("utf-8")
        self._headers(
            200, "application/json; charset=utf-8", len(body),
            Set_Cookie=self._set_session_cookie(renewed.token),
        )
        self.wfile.write(body)

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
            if route == "/healthz":
                # Liveness only, and deliberately public: the container health
                # check runs before anyone has logged in. It reveals nothing about
                # the network -- no counts, no names, no version.
                self._json({"status": "ok"})
                return
            if route not in PUBLIC_ROUTES and self._require_session(route) is None:
                return
            if route in ("/login", "/login.html"):
                # Already signed in: no reason to show the form again.
                if self._session() is not None:
                    self._headers(303, "text/plain; charset=utf-8", 0, Location="/")
                    return
                self._login_page()
                return
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
                    "account": (lambda s: {"username": s.username} if s else None)(
                        self._session()
                    ),
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
            if parsed.path == "/api/login":
                self._login()
                return
            if self._require_session(parsed.path) is None:
                return
            if not self._authorized():
                self._json({"error": "missing or invalid X-Atlas-Token"}, 403)
                return
            payload = self._body()
            if parsed.path == "/api/logout":
                self.sessions.close(self._cookie(auth.SESSION_COOKIE))
                self._headers(
                    204, "application/json; charset=utf-8", 0,
                    Set_Cookie=f"{auth.SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                )
                return
            if parsed.path == "/api/account/password":
                self._change_password(payload)
                return
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

    # Requests that say nothing and arrive constantly. The container health check
    # runs every 30s, which produced 1293 of the 1297 lines in a day's container
    # log and buried the startup output -- including the one-time credential
    # banner, which is the whole reason someone reads `docker logs`. The event
    # stream is long-lived and equally uninformative. Only these two: a data
    # endpoint being polled is real traffic and should stay visible.
    _QUIET_ROUTES = ("/healthz", "/api/stream")

    def log_message(self, format_string: str, *args: object) -> None:
        rendered = format_string % args
        if any(route in rendered for route in self._QUIET_ROUTES) and " 200 " in f" {rendered} ":
            return
        print(f"[viewer] {self.address_string()} {rendered}", flush=True)


def ensure_account(db_path: Path) -> str | None:
    """Make sure a usable password has been shown. Returns the one to print.

    A password is generated and printed on every start until someone actually
    signs in. Only a hash is kept, so a credential printed to a log that was then
    lost -- a recreated container, a truncated log, a terminal scrolled past --
    would otherwise be unrecoverable except by resetting it, and the account it
    guards has never been used by anyone.

    Once there has been a successful login the password is settled and never
    reprinted: from then on it is something a person is relying on, and replacing
    it is an explicit act.

    Reprinting costs nothing an attacker could not already have. Reading the
    output, or restarting the server to produce it, both need access to the host,
    which is more than the viewer grants.
    """
    with AtlasDB(db_path) as db:
        account = db.account()
        if account and account["last_login"]:
            return None
        password = auth.generate_password()
        salt, hashed = auth.hash_password(password)
        if account:
            db.set_account_password(int(account["id"]), hashed, salt)
        else:
            db.create_account(auth.DEFAULT_USERNAME, hashed, salt)
        return password


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    manager = JobManager(db_path)
    sessions = auth.SessionStore()

    def submit(kind: str, parameters: dict[str, object]) -> object:
        return manager.submit(kind, parameters)

    periodic = scheduler.Scheduler(db_path, submit)
    handler = type(
        "ConfiguredAtlasHandler",
        (AtlasHandler,),
        {
            "db_path": db_path, "jobs": manager, "scheduler": periodic,
            "sessions": sessions,
        },
    )

    # Bind before touching the account. Creating it first meant a failed bind
    # created the account, died before reaching the line that prints its password,
    # and left an account whose password nobody had ever seen -- recoverable only
    # with `account --reset-password`. The port being taken must not cost a
    # credential.
    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            raise RuntimeError(
                f"Port {port} is already in use. Another viewer, or the Network "
                f"Atlas container -- which uses host networking and so holds the "
                f"host's port -- may be running. Stop it, or choose another port "
                f"with --port."
            ) from exc
        raise
    httpd.daemon_threads = True
    new_password = ensure_account(db_path)
    with AtlasDB(db_path) as db:
        db.reap_stale_scans()
        scheduler.ensure_defaults(db)
        monitoring = scheduler.monitoring_active(db)
    periodic.start()
    print(f"Network Atlas {__version__}: http://{host}:{port}", flush=True)
    print(f"Database: {db_path}", flush=True)
    if new_password:
        # Boxed because in a container this scrolls past in `docker logs` and is
        # easy to miss.
        # Boxed because in a container this scrolls past in `docker logs` and is
        # easy to miss. The width is computed rather than hand-aligned: the box
        # characters made a literal drift out of true every time it was edited.
        lines = [
            "Sign in to the viewer with these credentials.",
            "Shown until the first successful sign-in, then not again.",
            None,  # divider
            f"username   {auth.DEFAULT_USERNAME}",
            f"password   {new_password}",
        ]
        width = max(len(line) for line in lines if line) + 4
        rendered = ["  ┌" + "─" * width + "┐"]
        for line in lines:
            if line is None:
                rendered.append("  ├" + "─" * width + "┤")
            else:
                rendered.append("  │  " + line.ljust(width - 4) + "  │")
        rendered.append("  └" + "─" * width + "┘")
        print(
            "\n" + "\n".join(rendered) + "\n\n"
            "  Change it from the viewer, or reset it with:\n"
            "      network-atlas account --reset-password\n",
            flush=True,
        )
    else:
        print("Sign in as 'admin'. Lost the password? network-atlas account --reset-password", flush=True)
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
