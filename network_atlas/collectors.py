from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from .classifier import classify_all
from .db import AtlasDB
from .parsers import import_arp_scan, import_avahi, import_nmap_xml
from .util import utc_now, validate_target


class CollectorError(RuntimeError):
    pass


def _require(binary: str) -> str:
    resolved = shutil.which(binary)
    if not resolved:
        raise CollectorError(f"Required command not found: {binary}")
    return resolved


def _run(
    command: Sequence[str], timeout: int, *, live_stderr: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=None if live_stderr else subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectorError(f"Command timed out after {timeout}s: {command[0]}") from exc


def _save_raw(db: AtlasDB, prefix: str, suffix: str, content: str) -> Path:
    scan_dir = db.path.parent / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "")
    path = scan_dir / f"{prefix}-{stamp}.{suffix}"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def collect_nmap(
    db: AtlasDB,
    target: str,
    *,
    profile: str = "discovery",
    allow_public: bool = False,
    allow_large: bool = False,
    timeout: int = 1800,
    dry_run: bool = False,
    use_sudo: bool = False,
    verbose: bool = False,
) -> dict[str, object]:
    network = validate_target(target, allow_public=allow_public, allow_large=allow_large)
    nmap = _require("nmap")
    privileged = (hasattr(os, "geteuid") and os.geteuid() == 0) or use_sudo
    prefix = [_require("sudo"), "--"] if use_sudo and os.geteuid() != 0 else []
    if profile == "discovery":
        command = [*prefix, nmap, "-sn", "--reason", "-oX", "-", str(network)]
    elif profile == "inventory":
        scan_type = "-sS" if privileged else "-sT"
        command = [
            *prefix, nmap, scan_type, "-sV", "--top-ports", "100", "--reason", "-T3",
        ]
        if privileged:
            command.extend(["-O", "--osscan-limit", "--traceroute"])
        command.extend(["-oX", "-", str(network)])
    else:
        raise ValueError(f"Unknown scan profile: {profile}")

    if verbose:
        option_index = command.index(nmap) + 1
        command[option_index:option_index] = ["-v", "--stats-every", "5s"]

    if dry_run:
        return {"command": command, "privileged": privileged, "imported": 0}

    scan_id = db.begin_scan("nmap", str(network), command)
    raw_path: Path | None = None
    try:
        if verbose:
            print(
                f"[Network Atlas] Starting {profile} scan of {network}. "
                "Nmap progress follows:",
                file=sys.stderr,
                flush=True,
            )
        process = _run(command, timeout, live_stderr=verbose)
        if process.returncode != 0:
            error = process.stderr.strip() if process.stderr else ""
            raise CollectorError(error or f"Nmap exited with {process.returncode}")
        raw_path = _save_raw(db, f"nmap-{profile}", "xml", process.stdout)
        db.mark_network_offline(network)
        imported = import_nmap_xml(db, process.stdout.encode("utf-8"))
        classify_all(db)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        if verbose:
            print(
                f"[Network Atlas] Scan complete: imported {imported} hosts.",
                file=sys.stderr,
                flush=True,
            )
        return {
            "command": command,
            "privileged": privileged,
            "imported": imported,
            "raw_path": str(raw_path),
            "warning": (
                None if privileged or profile == "discovery"
                else "Unprivileged inventory omitted OS fingerprinting and traceroute"
            ),
        }
    except Exception as exc:
        db.finish_scan(
            scan_id, "failed", error=str(exc), raw_path=str(raw_path) if raw_path else None
        )
        raise


def collect_arp(
    db: AtlasDB, interface: str, *, timeout: int = 120, use_sudo: bool = False
) -> dict[str, object]:
    if not interface or not all(character.isalnum() or character in "_.:-" for character in interface):
        raise ValueError("Invalid interface name")
    prefix = [_require("sudo"), "--"] if use_sudo and os.geteuid() != 0 else []
    command = [*prefix, _require("arp-scan"), "--interface", interface, "--localnet"]
    scan_id = db.begin_scan("arp-scan", "localnet", command)
    try:
        process = _run(command, timeout)
        if process.returncode not in (0, 1):
            raise CollectorError(process.stderr.strip() or f"arp-scan exited with {process.returncode}")
        raw_path = _save_raw(db, "arp-scan", "txt", process.stdout)
        imported = import_arp_scan(db, process.stdout)
        classify_all(db)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        return {"command": command, "imported": imported, "raw_path": str(raw_path)}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def collect_mdns(db: AtlasDB, *, timeout: int = 45) -> dict[str, object]:
    command = [
        _require("avahi-browse"), "--all", "--resolve", "--terminate", "--parsable"
    ]
    scan_id = db.begin_scan("mdns", "localnet", command)
    try:
        process = _run(command, timeout)
        if process.returncode != 0:
            error = process.stderr.strip() or process.stdout.strip()
            if "Daemon not running" in error or "Failed to create client object" in error:
                raise CollectorError(
                    "Avahi is installed but avahi-daemon is not running. Start it with "
                    "`sudo systemctl start avahi-daemon`, then retry `python3 -m network_atlas mdns`; "
                    "or skip mDNS because Nmap and arp-scan data remain usable."
                )
            raise CollectorError(error or f"avahi-browse exited with {process.returncode}")
        raw_path = _save_raw(db, "mdns", "txt", process.stdout)
        imported = import_avahi(db, process.stdout)
        classify_all(db)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        return {"command": command, "imported": imported, "raw_path": str(raw_path)}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise
