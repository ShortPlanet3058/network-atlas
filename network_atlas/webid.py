"""Identify devices from their web interface, using whatweb.

The devices hardest to identify are the ones that expose nothing but a management
page: no mDNS, no NetBIOS, no useful OS fingerprint. Their web interface is often
the only place the model is written down, and it is usually written in the page
title -- "Brother DCP-L3550CDW series", "Pharos OS".

whatweb is run at its lowest aggression level, which fetches the landing page and
reads the response. It sends ordinary GET requests and nothing else: no
credentials, no injection, no path guessing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from .util import clean_text


WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888)
TLS_PORTS = frozenset({443, 8443})

# whatweb names its vendor plugins after what they detect, so the plugin name
# itself carries the device type. Matched as a suffix on the plugin name.
PLUGIN_TYPE_HINTS: tuple[tuple[str, str, str], ...] = (
    ("printer", "printer", "printer web interface"),
    ("-fax", "printer", "fax interface"),
    ("jetdirect", "printer", "print server"),
    ("camera", "camera", "camera web interface"),
    ("webcam", "camera", "camera web interface"),
    ("nvr", "camera", "video recorder"),
    ("router", "router", "router web interface"),
    ("switch", "switch", "switch web interface"),
    ("firewall", "firewall", "firewall web interface"),
    ("nas", "storage", "storage web interface"),
    ("synology", "storage", "Synology interface"),
    ("qnap", "storage", "QNAP interface"),
)

# Response fields worth keeping as evidence even when they identify nothing.
_DETAIL_PLUGINS = ("HTTPServer", "X-Powered-By", "PoweredBy", "Via-Proxy", "Cookies")


def available() -> bool:
    return bool(shutil.which("whatweb"))


def _run(url: str, timeout: int) -> list[dict[str, Any]]:
    binary = shutil.which("whatweb")
    if not binary:
        return []
    try:
        process = subprocess.run(
            [
                binary, "--log-json=-", "--no-errors", "--aggression", "1",
                "--open-timeout", "5", "--read-timeout", str(max(5, timeout // 2)),
                "--user-agent", "Network Atlas (local inventory)", url,
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = (process.stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Older builds emit one object per line rather than an array.
        payload = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return [entry for entry in payload if isinstance(entry, dict)]


# Page titles that identify nothing: framework placeholders, loading screens and
# default pages. Storing these as a hardware model is worse than storing nothing.
_JUNK_TITLES = frozenset({
    "loading", "loading...", "default site", "welcome", "index", "home",
    "login", "log in", "sign in", "untitled", "untitled document", "document",
    "error", "it works!", "test page", "web server", "redirecting",
    "403 forbidden", "404 not found", "401 unauthorized", "please wait",
    "apache2 ubuntu default page: it works", "welcome to nginx!",
})


def looks_like_a_model(title: str | None) -> bool:
    """Whether a page title is specific enough to record as a hardware model.

    Appliance titles usually name the product ("Brother DCP-L3550CDW series").
    Placeholders and default pages do not, and promoting one to the model field
    puts "Loading..." where a model number belongs.
    """
    if not title:
        return False
    normalized = title.strip().lower().rstrip(".")
    if normalized in _JUNK_TITLES or len(normalized) < 4:
        return False
    if any(junk in normalized for junk in ("loading", "default page", "welcome to")):
        return False
    # A model designation carries a number; a generic page title usually does not.
    return any(character.isdigit() for character in title)


def _plugin_values(info: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("string", "version", "model", "firmware", "os", "module", "account"):
        raw = info.get(key)
        if not raw:
            continue
        for item in raw if isinstance(raw, list) else [raw]:
            cleaned = clean_text(str(item), 120)
            if cleaned:
                values.append(cleaned)
    return values


def identify(host: str, port: int, *, timeout: int = 45) -> dict[str, Any] | None:
    """Fetch and interpret one web interface."""
    scheme = "https" if port in TLS_PORTS else "http"
    entries = _run(f"{scheme}://{host}:{port}", timeout)
    if not entries:
        return None

    title: str | None = None
    server: str | None = None
    type_hints: list[tuple[str, str]] = []
    details: list[str] = []
    plugin_names: list[str] = []

    for entry in entries:
        plugins = entry.get("plugins") or {}
        for name, info in plugins.items():
            if not isinstance(info, dict):
                continue
            lowered = name.lower()
            plugin_names.append(name)
            values = _plugin_values(info)

            if lowered == "title" and values and not title:
                title = values[0]
            if name in _DETAIL_PLUGINS and values:
                if lowered == "httpserver" and not server:
                    server = values[0]
                detail = f"{name}: {', '.join(values[:2])}"
                if detail not in details:
                    details.append(detail)

            for needle, kind, label in PLUGIN_TYPE_HINTS:
                if needle in lowered:
                    hint = (kind, f"{label} ({name})")
                    # whatweb reports the redirect and its target separately, so
                    # the same plugin appears more than once per identification.
                    if hint not in type_hints:
                        type_hints.append(hint)
                    break

    if not (title or server or type_hints):
        return None
    return {
        "host": host,
        "port": port,
        "url": f"{scheme}://{host}:{port}",
        "title": title,
        "server": server,
        "type_hints": type_hints,
        "details": details[:6],
        "plugins": sorted(set(plugin_names)),
    }
