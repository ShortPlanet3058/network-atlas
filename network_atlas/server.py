from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .db import AtlasDB


STATIC_DIR = Path(__file__).parent / "static"


class AtlasHandler(BaseHTTPRequestHandler):
    db_path: Path
    server_version = "NetworkAtlas/0.1"

    def _headers(self, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8")
        self.wfile.write(body)

    def _static(self, name: str) -> None:
        allowed = {"index.html", "app.js", "style.css"}
        if name not in allowed:
            self._json({"error": "not found"}, 404)
            return
        path = STATIC_DIR / name
        if not path.is_file():
            self._json({"error": "asset missing"}, 500)
            return
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self._headers(200, f"{mime}; charset=utf-8" if mime.startswith("text/") else mime)
        self.wfile.write(path.read_bytes())

    def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/summary":
                with AtlasDB(self.db_path) as db:
                    self._json(db.summary())
            elif parsed.path == "/api/graph":
                with AtlasDB(self.db_path) as db:
                    self._json(db.graph())
            elif parsed.path == "/api/devices":
                with AtlasDB(self.db_path) as db:
                    self._json(db.devices())
            elif parsed.path == "/api/scans":
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["30"])[0])
                with AtlasDB(self.db_path) as db:
                    self._json(db.scans(limit))
            elif parsed.path in ("/", "/index.html"):
                self._static("index.html")
            elif parsed.path == "/app.js":
                self._static("app.js")
            elif parsed.path == "/style.css":
                self._static("style.css")
            else:
                self._json({"error": "not found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:
            self.log_error("request failed: %s", exc)
            self._json({"error": "internal server error"}, 500)

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"[viewer] {self.address_string()} {format_string % args}")

    def do_POST(self) -> None:  # noqa: N802
        self._json({"error": "viewer is read-only; use the CLI for changes"}, 405)


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    handler = type("ConfiguredAtlasHandler", (AtlasHandler,), {"db_path": db_path})
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"Network Atlas viewer: http://{host}:{port}")
    print(f"Database: {db_path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping viewer")
    finally:
        httpd.server_close()
