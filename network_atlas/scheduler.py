"""Periodic collection, so the map reflects the network rather than a moment.

Monitoring is off until the operator turns it on: scanning sends packets to other
people's devices, and a tool should not start doing that on its own because it
happens to be running. Enabling it is one switch; the defaults below describe what
that switch turns on.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable

from .db import AtlasDB
from .util import utc_now


# kind -> (interval seconds, part of the recommended monitoring set, parameters)
# Cheap and silent passes run often; anything that probes runs rarely. Every row
# is seeded DISABLED -- the flag means "included when monitoring is switched on",
# not "starts by itself".
DEFAULT_SCHEDULE: dict[str, tuple[int, bool, dict[str, Any]]] = {
    "neighbours": (300, True, {}),
    "passive": (1800, True, {"duration": 60}),
    "scan": (3600, True, {"profile": "quick"}),
    "names": (21600, False, {}),
    "audit": (43200, False, {}),
}

# How often the loop wakes to look for due work.
TICK_SECONDS = 20


def ensure_defaults(db: AtlasDB) -> None:
    """Create any missing schedule rows without disturbing the operator's edits."""
    for kind, (interval, _recommended, parameters) in DEFAULT_SCHEDULE.items():
        db.conn.execute(
            """INSERT INTO schedule(kind,interval_seconds,enabled,parameters_json)
               VALUES(?,?,0,?)
               ON CONFLICT(kind) DO NOTHING""",
            (kind, interval, json.dumps(parameters)),
        )
    db.commit()


def recommended(kind: str) -> bool:
    entry = DEFAULT_SCHEDULE.get(kind)
    return bool(entry and entry[1])


def entries(db: AtlasDB) -> list[dict[str, Any]]:
    ensure_defaults(db)
    rows = db.conn.execute(
        "SELECT * FROM schedule ORDER BY interval_seconds"
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
        except json.JSONDecodeError:
            item["parameters"] = {}
        item["enabled"] = bool(item["enabled"])
        item["recommended"] = recommended(item["kind"])
        result.append(item)
    return result


def set_enabled(db: AtlasDB, kind: str, enabled: bool) -> None:
    if kind not in DEFAULT_SCHEDULE:
        raise ValueError(f"Unknown scheduled task: {kind}")
    db.conn.execute(
        "UPDATE schedule SET enabled=? WHERE kind=?", (int(enabled), kind)
    )
    db.commit()


def set_interval(db: AtlasDB, kind: str, seconds: int) -> None:
    if kind not in DEFAULT_SCHEDULE:
        raise ValueError(f"Unknown scheduled task: {kind}")
    if not 60 <= seconds <= 604800:
        raise ValueError("Interval must be between 1 minute and 7 days")
    db.conn.execute(
        "UPDATE schedule SET interval_seconds=? WHERE kind=?", (int(seconds), kind)
    )
    db.commit()


def set_monitoring(db: AtlasDB, enabled: bool) -> list[str]:
    """Turn the whole default monitoring set on or off in one action."""
    ensure_defaults(db)
    changed = []
    for kind, (_interval, recommended, _parameters) in DEFAULT_SCHEDULE.items():
        if not recommended:
            continue
        set_enabled(db, kind, enabled)
        changed.append(kind)
    return changed


def monitoring_active(db: AtlasDB) -> bool:
    ensure_defaults(db)
    row = db.conn.execute(
        "SELECT COUNT(*) FROM schedule WHERE enabled=1"
    ).fetchone()
    return bool(row[0])


def _due(entry: dict[str, Any], now: float) -> bool:
    if not entry["enabled"]:
        return False
    last = entry.get("last_run_at")
    if not last:
        return True
    try:
        from datetime import datetime
        stamp = datetime.fromisoformat(last.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return True
    return (now - stamp) >= entry["interval_seconds"]


class Scheduler:
    """Submits due collections through the normal job pipeline.

    Deliberately submits rather than executing: a scheduled scan then behaves
    exactly like one started from the browser -- same concurrency limit, same
    progress stream, same audit trail -- and cannot run two at once.
    """

    def __init__(self, db_path, submit: Callable[[str, dict[str, Any]], Any]):
        self.db_path = db_path
        self.submit = submit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def start(self) -> None:
        with AtlasDB(self.db_path) as db:
            ensure_defaults(db)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(TICK_SECONDS):
            try:
                self._tick()
            except Exception as exc:  # a scheduler must never die of one bad tick
                self.last_error = f"{type(exc).__name__}: {exc}"

    def _tick(self) -> None:
        now = time.time()
        with AtlasDB(self.db_path) as db:
            candidates = [entry for entry in entries(db) if _due(entry, now)]
            if not candidates:
                return
            # One at a time, cheapest first, so a long scan never starves the
            # quick passes that keep presence current.
            entry = min(candidates, key=lambda item: item["interval_seconds"])
            try:
                self.submit(entry["kind"], entry["parameters"])
                status = "submitted"
            except Exception as exc:
                # Almost always "a scan is already running"; retry next tick.
                status = f"skipped: {type(exc).__name__}"
                db.conn.execute(
                    "UPDATE schedule SET last_status=? WHERE kind=?",
                    (status[:120], entry["kind"]),
                )
                db.commit()
                return
            db.conn.execute(
                "UPDATE schedule SET last_run_at=?, last_status=? WHERE kind=?",
                (utc_now(), status, entry["kind"]),
            )
            db.commit()
