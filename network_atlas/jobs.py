"""Background scan jobs plus a subscribable event stream for the viewer.

Scans take minutes, so the HTTP request that starts one must return immediately.
Jobs run on worker threads and publish progress that the viewer consumes over
server-sent events.
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from . import collectors, netinfo
from .db import AtlasDB
from .util import clean_text, utc_now, validate_target


# One scan at a time: concurrent Nmap runs against the same segment distort each
# other's timing and race on the same device rows.
MAX_CONCURRENT = 1
MAX_HISTORY = 40

JobRunner = Callable[["Job", AtlasDB], dict[str, Any]]


class JobError(RuntimeError):
    """A scan could not be accepted because something else is already running."""


class UnknownJobError(ValueError):
    """The requested scan type does not exist."""


class Job:
    def __init__(self, kind: str, parameters: dict[str, Any]):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.parameters = parameters
        self.status = "queued"
        self.progress = 0.0
        self.detail = "Queued"
        self.error: str | None = None
        self.result: dict[str, Any] | None = None
        self.started_at = utc_now()
        self.finished_at: str | None = None
        self.cancelled = False
        # Set by JobManager._execute before the runner starts.
        self.report: Callable[[float, str], None] = lambda percent, detail: None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "parameters": self.parameters,
            "status": self.status, "progress": round(self.progress, 1),
            "detail": self.detail, "error": self.error, "result": self.result,
            "started_at": self.started_at, "finished_at": self.finished_at,
        }


class EventBus:
    """Fan-out of job events to any number of SSE subscribers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue[str]] = set()

    def subscribe(self) -> queue.Queue[str]:
        channel: queue.Queue[str] = queue.Queue(maxsize=256)
        with self._lock:
            self._subscribers.add(channel)
        return channel

    def unsubscribe(self, channel: queue.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(channel)

    def publish(self, event: str, payload: dict[str, Any]) -> None:
        message = f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"
        with self._lock:
            targets = list(self._subscribers)
        for channel in targets:
            try:
                channel.put_nowait(message)
            except queue.Full:
                # A subscriber that cannot keep up is dropped rather than blocking a scan.
                self.unsubscribe(channel)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


class JobManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.events = EventBus()
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._active = 0

    # -- inspection -----------------------------------------------------------
    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._jobs[job_id].snapshot() for job_id in reversed(self._order)]

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    # -- submission -----------------------------------------------------------
    def submit(self, kind: str, parameters: dict[str, Any]) -> Job:
        runner = _RUNNERS.get(kind)
        if runner is None:
            known = ", ".join(sorted(_RUNNERS))
            raise UnknownJobError(f"Unknown scan type {kind!r}; expected one of: {known}")
        # Validate before the concurrency check so a malformed request is reported
        # as such, rather than being masked by "a scan is already running", and so
        # bad input never becomes a job that only fails once it starts.
        _validate(kind, parameters)
        with self._lock:
            if self._active >= MAX_CONCURRENT:
                raise JobError("A scan is already running; wait for it to finish or cancel it")
            job = Job(kind, parameters)
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > MAX_HISTORY:
                stale = self._order.pop(0)
                if self._jobs[stale].status in ("queued", "running"):
                    self._order.insert(0, stale)
                    break
                self._jobs.pop(stale, None)
            self._active += 1
        self.events.publish("job", job.snapshot())
        threading.Thread(target=self._execute, args=(job, runner), daemon=True).start()
        return job

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job or job.status not in ("queued", "running"):
            return False
        job.cancelled = True
        job.detail = "Cancelling…"
        self.events.publish("job", job.snapshot())
        return True

    # -- execution ------------------------------------------------------------
    def _execute(self, job: Job, runner: JobRunner) -> None:
        job.status = "running"
        job.detail = "Starting"
        job.report = self._hook(job)
        self.events.publish("job", job.snapshot())
        try:
            with AtlasDB(self.db_path) as db:
                job.result = runner(job, db)
            job.status = "complete"
            job.progress = 100.0
            job.detail = job.detail if job.cancelled else "Finished"
        except Exception as exc:  # collectors raise many subprocess-related types
            job.status = "failed"
            job.error = clean_text(str(exc), 600) or exc.__class__.__name__
            job.detail = "Failed"
        finally:
            job.finished_at = utc_now()
            with self._lock:
                self._active = max(0, self._active - 1)
            self.events.publish("job", job.snapshot())
            self.events.publish("inventory", {"reason": job.kind, "at": utc_now()})

    def _hook(self, job: Job) -> collectors.ProgressHook:
        """Progress callback that republishes the job whenever a collector reports."""
        def report(percent: float, detail: str) -> None:
            if job.cancelled:
                raise JobError("Cancelled by request")
            if percent >= 0:
                job.progress = percent
            job.detail = clean_text(detail, 200) or job.detail
            self.events.publish("job", job.snapshot())
        return report


# -- validation ---------------------------------------------------------------
def _validate(kind: str, parameters: dict[str, Any]) -> None:
    """Reject a request at submit time rather than failing the job later."""
    if kind in ("scan", "sweep"):
        profile = parameters.get("profile", "standard")
        if profile not in collectors.PROFILES:
            raise UnknownJobError(
                f"Unknown profile {profile!r}; expected one of: "
                f"{', '.join(collectors.PROFILES)}"
            )
        target = parameters.get("target") or netinfo.primary_target()
        if not target:
            raise UnknownJobError(
                "No target given and no local IPv4 subnet could be detected"
            )
        # Raises ValueError for a malformed, public or oversized range.
        validate_target(
            str(target),
            allow_public=bool(parameters.get("allow_public")),
            allow_large=bool(parameters.get("allow_large")),
        )
    if kind in ("passive", "sweep"):
        duration = parameters.get("duration", 60)
        try:
            duration = int(duration)
        except (TypeError, ValueError):
            raise UnknownJobError("Listen duration must be a whole number of seconds") from None
        if not 5 <= duration <= 900:
            raise UnknownJobError("Listen duration must be between 5 and 900 seconds")
        interface = parameters.get("interface")
        if interface and not set(str(interface)).issubset(_SAFE_INTERFACE):
            raise UnknownJobError(f"Invalid interface name: {interface!r}")


_SAFE_INTERFACE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
)


# -- runners ------------------------------------------------------------------
def _band(job: Job, low: float, high: float) -> collectors.ProgressHook:
    """Map a collector's own 0-100% onto a slice of a multi-stage job's bar.

    Without this, each stage of a sweep reports its own percentage and the bar
    lurches between stages instead of advancing once from start to finish.
    """
    def report(percent: float, detail: str) -> None:
        if percent >= 0:
            job.report(low + (high - low) * max(0.0, min(percent, 100.0)) / 100.0, detail)
        else:
            job.report(-1.0, detail)
    return report



def _run_scan(
    job: Job, db: AtlasDB, report: collectors.ProgressHook | None = None
) -> dict[str, Any]:
    target = job.parameters.get("target") or netinfo.primary_target()
    if not target:
        raise UnknownJobError(
            "No target given and no local IPv4 subnet could be detected"
        )
    profile = job.parameters.get("profile", "standard")
    if profile not in collectors.PROFILES:
        raise UnknownJobError(
            f"Unknown profile {profile!r}; expected one of: {', '.join(collectors.PROFILES)}"
        )
    validate_target(
        target,
        allow_public=bool(job.parameters.get("allow_public")),
        allow_large=bool(job.parameters.get("allow_large")),
    )
    timeouts = {"quick": 600, "standard": 3600, "deep": 21600}
    return collectors.collect_nmap(
        db, target, profile=profile,
        allow_public=bool(job.parameters.get("allow_public")),
        allow_large=bool(job.parameters.get("allow_large")),
        timeout=timeouts[profile],
        on_progress=report or job.report,
    )


def _run_passive(job: Job, db: AtlasDB) -> dict[str, Any]:
    duration = int(job.parameters.get("duration") or 60)
    return collectors.collect_passive(
        db, job.parameters.get("interface") or None,
        duration=max(10, min(duration, 900)),
        on_progress=job.report,
    )


def _run_names(job: Job, db: AtlasDB) -> dict[str, Any]:
    return collectors.collect_names(
        db, job.parameters.get("target") or None, on_progress=job.report
    )


def _run_neighbours(job: Job, db: AtlasDB) -> dict[str, Any]:
    return collectors.collect_neighbours(db)


def _run_web_identity(job: Job, db: AtlasDB) -> dict[str, Any]:
    return collectors.collect_web_identity(db, on_progress=job.report)


def _run_mdns(job: Job, db: AtlasDB) -> dict[str, Any]:
    return collectors.collect_mdns(db)


def _run_audit(job: Job, db: AtlasDB) -> dict[str, Any]:
    return collectors.collect_audit(
        db, on_progress=job.report, skip_tls=bool(job.parameters.get("skip_tls"))
    )


def _run_sweep(job: Job, db: AtlasDB) -> dict[str, Any]:
    """Everything, in the order that makes each later pass smarter.

    Each stage owns a band of the progress bar, so the bar advances once from
    start to finish rather than restarting with every stage.
    """
    results: dict[str, Any] = {}

    job.report(2.0, "Reading neighbour caches")
    results["neighbours"] = collectors.collect_neighbours(db)

    job.report(6.0, "Active scan")
    results["scan"] = _run_scan(job, db, _band(job, 6.0, 62.0))

    job.report(58.0, "Reading web interfaces")
    try:
        results["web_identity"] = collectors.collect_web_identity(
            db, on_progress=_band(job, 58.0, 66.0)
        )
    except Exception as exc:
        results["web_identity"] = {"error": clean_text(str(exc), 300)}

    job.report(66.0, "Resolving names")
    results["names"] = collectors.collect_names(
        db, job.parameters.get("target") or None, on_progress=_band(job, 66.0, 74.0)
    )

    job.report(74.0, "Passive listen")
    try:
        # Best effort: a sweep should still deliver its active findings if capture
        # is unavailable, so the failure is recorded rather than raised.
        results["passive"] = collectors.collect_passive(
            db, job.parameters.get("interface") or None,
            duration=int(job.parameters.get("duration") or 45),
            on_progress=_band(job, 74.0, 89.0),
        )
    except Exception as exc:
        results["passive"] = {"error": clean_text(str(exc), 300)}

    job.report(90.0, "Auditing for issues")
    try:
        results["audit"] = collectors.collect_audit(
            db, on_progress=_band(job, 90.0, 99.0)
        )
    except Exception as exc:
        results["audit"] = {"error": clean_text(str(exc), 300)}

    job.report(100.0, "Sweep finished")
    return results


_RUNNERS: dict[str, JobRunner] = {
    "scan": _run_scan,
    "passive": _run_passive,
    "names": _run_names,
    "neighbours": _run_neighbours,
    "mdns": _run_mdns,
    "audit": _run_audit,
    "web-identity": _run_web_identity,
    "sweep": _run_sweep,
}
