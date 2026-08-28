"""Subprocess collectors. Each records a scan row, saves raw output, then imports."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from . import (
    enrich,
    events,
    findings,
    fingerprint,
    ingest,
    netinfo,
    passive,
    tlsaudit,
    vulns,
    webid,
)
from .classifier import classify_all, classify_model
from .db import AtlasDB
from .parsers import import_arp_scan, import_avahi, import_nmap_xml
from .util import nmap_privileged, utc_now, validate_target


ProgressHook = Callable[[float, str], None]

# Nmap reports progress on STDOUT, not stderr, and `-oX -` suppresses it entirely
# because the XML then occupies stdout. Scans therefore write XML to a file and
# this parses stdout. A percentage only appears once a phase runs long enough to
# estimate, so phase and discovery lines are parsed too: they are what make the
# first minute of a scan legible.
_PERCENT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_STATS_RE = re.compile(r"(\d+)\s+hosts?\s+completed\s+\((\d+)\s+up\)")
_PHASE_RE = re.compile(
    r"Initiating\s+([A-Za-z][A-Za-z0-9 /_-]*?)"
    r"(?:\s*\(try\s*#\d+\))?"
    r"\s+(?:at\s+\d|against\b)"
)
_NSE_RE = re.compile(r"NSE:\s+Script scanning\s+(\d+)\s+hosts?")
_SCANNING_RE = re.compile(r"Scanning\s+(\d+)\s+hosts?")
_OPEN_PORT_RE = re.compile(r"Discovered open port\s+(\d+/\w+)\s+on\s+(\S+)")
_COMPLETED_RE = re.compile(r"Completed\s+(.+?)\s+at\s+.*?\((\d+)\s+total\s+(hosts|ports)\)")
_REPORT_RE = re.compile(r"Nmap scan report for\s+(\S+)")
_HOST_DOWN = "[host down"

# Nmap's "About X% done" is the progress of the CURRENT phase, not of the scan, so
# reporting it directly would show 47% while six phases remain. Each phase is given
# a share of the bar and its own percentage is scaled into that share.
_PHASE_SHARES: tuple[tuple[str, float, float], ...] = (
    ("arp ping scan", 4.0, 4.0),
    ("ping scan", 4.0, 4.0),
    ("parallel dns resolution", 8.0, 2.0),
    ("syn stealth scan", 10.0, 32.0),
    ("connect scan", 10.0, 32.0),
    ("udp scan", 10.0, 32.0),
    ("service scan", 42.0, 28.0),
    ("os detection", 70.0, 10.0),
    ("traceroute", 80.0, 6.0),
    ("nse", 86.0, 12.0),
)


def _phase_share(phase: str) -> tuple[float, float] | None:
    lowered = phase.lower()
    for name, base, span in _PHASE_SHARES:
        if name in lowered:
            return base, span
    return None
_DONE_RE = re.compile(r"Nmap done:.*?\((\d+)\s+hosts? up\)")

PROFILES = ("quick", "standard", "deep")
PROFILE_LABELS = {
    "quick": "Quick sweep — who is online (seconds)",
    "standard": "Standard — ports, versions, OS and path (minutes)",
    "deep": "Deep — every port and service script (slow, thorough)",
}


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


def _run_streaming(
    command: Sequence[str],
    timeout: int,
    on_progress: ProgressHook | None = None,
    *,
    echo: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a collector, reporting progress from its stdout as it arrives.

    Nmap writes its running commentary to stdout, so stdout is consumed line by
    line here and stderr is drained by a thread. `communicate()` cannot be used:
    it reads both pipes itself, racing this reader and swallowing the very lines
    that make a scan legible while it runs.
    """
    try:
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise CollectorError(f"Could not start {command[0]}: {exc}") from exc

    output: list[str] = []
    errors: list[str] = []
    progress_state: dict[str, Any] = {}

    def drain_stderr() -> None:
        if process.stderr is None:
            return
        try:
            for line in process.stderr:
                line = line.rstrip()
                if line:
                    errors.append(line)
                    del errors[:-40]
                    if echo:
                        print(f"  {line}", file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass

    watcher = threading.Thread(target=drain_stderr, daemon=True)
    watcher.start()

    deadline = time.monotonic() + timeout
    try:
        if process.stdout is not None:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    output.append(line)
                    if echo:
                        print(f"  {line}", file=sys.stderr, flush=True)
                    if on_progress:
                        _report_line(line, on_progress, progress_state)
                if time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(command[0], timeout)
        process.wait(timeout=max(1.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise CollectorError(f"Command timed out after {timeout}s: {command[0]}") from exc
    finally:
        watcher.join(timeout=10)
    return subprocess.CompletedProcess(
        list(command), process.returncode, "\n".join(output), "\n".join(errors)
    )


def _failure_reason(process: subprocess.CompletedProcess[str], tool: str) -> str:
    """Best available explanation for a non-zero exit.

    Nmap explains itself on stdout, so the last line there is usually the reason;
    stderr is checked first for the tools that use it.
    """
    for stream in (process.stderr, process.stdout):
        lines = [line for line in (stream or "").strip().splitlines() if line.strip()]
        if lines:
            return lines[-1][:400]
    return f"{tool} exited with {process.returncode}"


def _report_line(line: str, on_progress: ProgressHook, state: dict[str, Any]) -> None:
    """Translate one line of Nmap chatter into a progress update.

    `state` carries the current phase and the highest progress reported so far, so
    the bar advances monotonically instead of jumping backwards at each new phase.
    """
    discovered: set[str] = state.setdefault("discovered", set())

    def advance(percent: float, detail: str) -> None:
        # Never regress: a new phase starting must not undo the previous one.
        best = max(float(state.get("percent", 0.0)), percent)
        state["percent"] = best
        on_progress(best, detail)

    if match := _PERCENT_RE.search(line):
        phase = line.split(" Timing:")[0].strip()
        share = _phase_share(phase) or _phase_share(str(state.get("phase", "")))
        fraction = float(match.group(1))
        if share:
            base, span = share
            advance(base + span * fraction / 100.0, f"{phase}: {fraction:.0f}% done")
        else:
            on_progress(-1.0, f"{phase}: {fraction:.0f}% done")
    elif match := _STATS_RE.search(line):
        completed, up = int(match.group(1)), int(match.group(2))
        on_progress(-1.0, f"{completed} hosts finished, {up} responding")
    elif match := _OPEN_PORT_RE.search(line):
        discovered.add(match.group(2))
        plural = "s" if len(discovered) != 1 else ""
        on_progress(
            -1.0,
            f"Found port {match.group(1)} on {match.group(2)} "
            f"({len(discovered)} host{plural} with services)",
        )
    elif match := _COMPLETED_RE.search(line):
        share = _phase_share(match.group(1))
        detail = f"Finished {match.group(1)} ({match.group(2)} {match.group(3)})"
        if share:
            advance(share[0] + share[1], detail)
        else:
            on_progress(-1.0, detail)
    elif match := _PHASE_RE.search(line):
        phase = match.group(1)
        state["phase"] = phase
        share = _phase_share(phase)
        if share:
            advance(share[0], phase)
        else:
            on_progress(-1.0, phase)
    elif match := _SCANNING_RE.search(line):
        on_progress(-1.0, f"Probing {match.group(1)} hosts")
    elif match := _NSE_RE.search(line):
        share = _phase_share("nse")
        state["phase"] = "NSE"
        advance(share[0], f"Running service scripts on {match.group(1)} hosts")
    elif match := _DONE_RE.search(line):
        advance(100.0, f"{match.group(1)} hosts responding")
    elif match := _REPORT_RE.search(line):
        if _HOST_DOWN not in line:
            on_progress(-1.0, f"Found host {match.group(1)}")


def _save_raw(db: AtlasDB, prefix: str, suffix: str, content: str) -> Path:
    scan_dir = db.path.parent / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "")
    path = scan_dir / f"{prefix}-{stamp}.{suffix}"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def _finalize(db: AtlasDB, before: dict[str, Any] | None = None) -> None:
    """Shared post-import pass: enrich, structure, classify, tidy, then diff.

    `before` is a snapshot taken by the caller prior to importing. With it, every
    collector reports what actually changed rather than only what now exists.
    """
    ingest.apply_vendors(db)
    ingest.register_local_host(db)
    ingest.fold_link_local_duplicates(db)
    ingest.link_gateway(db)
    db.resolve_address_conflicts()
    db.rerank_hostnames()
    db.prune_ghosts()
    classify_all(db)
    findings.evaluate(db)
    events.promote_conflicts(db)
    if before is not None:
        events.diff(db, before)


def collect_audit(
    db: AtlasDB, *, on_progress: ProgressHook | None = None, skip_tls: bool = False
) -> dict[str, object]:
    """Correlate the inventory against exploitdb and check TLS posture.

    Sends no new probes for the exploit correlation -- it reasons over service
    versions already collected -- and connects only to TLS ports for the
    certificate and protocol checks.
    """
    scan_id = db.begin_scan("audit", "inventory", ["searchsploit", "sslscan"])
    try:
        if on_progress:
            on_progress(2.0, "Re-evaluating inventory findings")
        db.set_scan_progress(scan_id, 2.0, "Re-evaluating inventory findings")
        rule_counts = findings.evaluate(db)

        def exploit_progress(percent: float, detail: str) -> None:
            scaled = 5.0 + percent * 0.45
            db.set_scan_progress(scan_id, scaled, detail)
            if on_progress:
                on_progress(scaled, detail)

        exploits = vulns.audit_services(db, on_progress=exploit_progress)

        tls: dict[str, int] = {"scanned": 0, "findings": 0}
        if not skip_tls:
            def tls_progress(percent: float, detail: str) -> None:
                scaled = 50.0 + percent * 0.48
                db.set_scan_progress(scan_id, scaled, detail)
                if on_progress:
                    on_progress(scaled, detail)

            tls = tlsaudit.audit(db, on_progress=tls_progress)

        summary = findings.summary(db)
        detail = (
            f"{summary['open']} open findings "
            f"({summary['high']} high, {summary['medium']} medium, {summary['low']} low)"
        )
        db.set_scan_progress(scan_id, 100.0, detail, summary["open"])
        db.finish_scan(scan_id, "complete")
        return {
            "rules": rule_counts, "exploits": exploits, "tls": tls, "summary": summary,
        }
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def nmap_command(
    target: str, profile: str, *, verbose: bool = True, xml_path: Path | str | None = None
) -> list[str]:
    """Build the Nmap invocation for a profile, using raw packets when available.

    `xml_path` keeps the XML out of stdout, which is where Nmap reports progress.
    """
    nmap = _require("nmap")
    privileged = nmap_privileged()
    command = [nmap, "--reason", "-oX", str(xml_path) if xml_path else "-"]
    if verbose:
        command[1:1] = ["-v", "--stats-every", "3s"]

    if profile == "quick":
        # Multiple probe types; a host that ignores ICMP often answers a SYN.
        command[1:1] = ["-sn", "-PE", "-PS21,22,80,443,3389", "-PA80,443", "-PP"]
        if privileged:
            command[1:1] = ["-PR"]
    elif profile in ("standard", "deep"):
        command[1:1] = ["-sS" if privileged else "-sT", "-sV", "-T4"]
        # Two scripts that identify a host outright rather than guessing:
        # smb-os-discovery returns the exact OS, hostname and domain, and nbstat
        # the NetBIOS name and hardware address. Both run only where SMB is open,
        # so they cost nothing on hosts without it, and both only read.
        command[1:1] = ["--script", "smb-os-discovery,nbstat"]
        if profile == "standard":
            command[1:1] = ["--top-ports", "200"]
        else:
            command[1:1] = ["-p-", "--version-all", "-sC"]
        if privileged:
            command[1:1] = ["-O", "--osscan-limit", "--traceroute"]
    else:
        raise ValueError(f"Unknown scan profile: {profile}")
    command.append(target)
    return command


def collect_nmap(
    db: AtlasDB,
    target: str,
    *,
    profile: str = "standard",
    allow_public: bool = False,
    allow_large: bool = False,
    timeout: int = 3600,
    dry_run: bool = False,
    verbose: bool = False,
    on_progress: ProgressHook | None = None,
) -> dict[str, object]:
    network = validate_target(target, allow_public=allow_public, allow_large=allow_large)
    privileged = nmap_privileged()

    if dry_run:
        return {
            "command": nmap_command(str(network), profile),
            "privileged": privileged,
            "imported": 0,
        }

    scan_dir = db.path.parent / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "")
    raw_path = scan_dir / f"nmap-{profile}-{stamp}.xml"
    command = nmap_command(str(network), profile, xml_path=raw_path)
    scan_id = db.begin_scan("nmap", str(network), command)
    before = events.snapshot(db)

    def report(percent: float, detail: str) -> None:
        if percent >= 0:
            db.set_scan_progress(scan_id, percent, detail)
        else:
            db.set_scan_progress(scan_id, _current_progress(db, scan_id), detail)
        if on_progress:
            on_progress(percent, detail)

    try:
        if verbose:
            print(
                f"[Network Atlas] {profile} scan of {network} "
                f"({'raw packets' if privileged else 'unprivileged fallback'})",
                file=sys.stderr, flush=True,
            )
        process = _run_streaming(command, timeout, report, echo=verbose)
        if process.returncode != 0:
            raise CollectorError(_failure_reason(process, "Nmap"))
        if not raw_path.exists():
            raise CollectorError("Nmap produced no XML output")
        raw_path.chmod(0o600)
        db.mark_network_offline(network)
        imported = import_nmap_xml(db, raw_path)
        _finalize(db, before)
        db.set_scan_progress(scan_id, 100.0, f"Imported {imported} responding hosts", imported)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        if verbose:
            print(f"[Network Atlas] Complete: {imported} hosts online.", file=sys.stderr, flush=True)
        return {
            "command": command, "privileged": privileged, "imported": imported,
            "raw_path": str(raw_path),
            "warning": None if privileged else "Unprivileged scan: no OS detection or traceroute",
        }
    except Exception as exc:
        db.finish_scan(
            scan_id, "failed", error=str(exc),
            raw_path=str(raw_path) if raw_path.exists() else None,
        )
        raise


def _current_progress(db: AtlasDB, scan_id: int) -> float:
    row = db.conn.execute("SELECT progress FROM scans WHERE id=?", (scan_id,)).fetchone()
    return float(row["progress"]) if row else 0.0


def collect_passive(
    db: AtlasDB,
    interface: str | None = None,
    *,
    duration: int = 60,
    on_progress: ProgressHook | None = None,
) -> dict[str, object]:
    """Listen only. Finds devices that never answer a probe, and reads LLDP/CDP."""
    if not interface:
        interface = netinfo.capture_interface()
        if not interface:
            raise CollectorError("No interface is up for passive capture")
    scan_id = db.begin_scan("passive", f"{interface} ({duration}s)", ["tshark", "-i", interface])
    capture_path: Path | None = None
    try:
        if on_progress:
            on_progress(2.0, f"Listening on {interface} for {duration}s")
        db.set_scan_progress(scan_id, 2.0, f"Listening on {interface} for {duration}s")
        before = events.snapshot(db)
        capture_path = passive.capture(interface, duration)
        db.set_scan_progress(scan_id, 70.0, "Analyzing capture")
        if on_progress:
            on_progress(70.0, "Analyzing capture")
        analysis = passive.analyze(capture_path)
        result = ingest.import_passive(db, analysis)

        # The same capture answers three more questions at no extra cost.
        db.set_scan_progress(scan_id, 80.0, "Reading DHCP leases and traffic pairs")
        if on_progress:
            on_progress(80.0, "Reading DHCP leases and traffic pairs")
        result["leases"] = ingest.import_leases(db, analysis.get("leases", []))
        result["flows"] = ingest.import_flows(db, analysis.get("flows", []))

        result["fingerprints"] = 0
        if fingerprint.available():
            db.set_scan_progress(scan_id, 88.0, "Passive OS fingerprinting")
            if on_progress:
                on_progress(88.0, "Passive OS fingerprinting")
            prints = fingerprint.analyze(capture_path)
            result["fingerprints"] = ingest.apply_fingerprints(
                db, fingerprint.to_observations(prints)
            )

        _finalize(db, before)
        detail = (
            f"{result['devices']} devices, {result['links']} physical links, "
            f"{result['leases']} leases, {result['flows']} traffic pairs, "
            f"{sum(analysis['counters'].values())} packets"
        )
        db.set_scan_progress(scan_id, 100.0, detail, result["devices"])
        db.finish_scan(scan_id, "complete")
        return {
            "interface": interface, "duration": duration,
            "counters": analysis["counters"], **result,
        }
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise
    finally:
        if capture_path:
            capture_path.unlink(missing_ok=True)


def collect_web_identity(
    db: AtlasDB, *, timeout: int = 45, on_progress: ProgressHook | None = None
) -> dict[str, object]:
    """Identify devices from their web interface.

    Aimed squarely at the devices nothing else can name: appliances whose only
    clue is a management page. The model is usually in the page title.
    """
    scan_id = db.begin_scan("web-identity", "inventory", ["whatweb"])
    try:
        if not webid.available():
            raise CollectorError(
                "whatweb is not installed; install it to identify devices from "
                "their web interface"
            )
        before = events.snapshot(db)
        placeholders = ",".join("?" for _ in webid.WEB_PORTS)
        rows = db.conn.execute(
            f"""SELECT s.device_id, s.port,
                       COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) name,
                       (SELECT a.address FROM addresses a WHERE a.device_id=s.device_id
                         AND a.family='ipv4' ORDER BY a.last_seen DESC LIMIT 1) address
                FROM services s JOIN devices d ON d.id = s.device_id
                WHERE s.state LIKE 'open%' AND d.status='online'
                  AND s.protocol='tcp' AND s.port IN ({placeholders})
                ORDER BY s.device_id, s.port""",
            webid.WEB_PORTS,
        ).fetchall()

        identified = titles = 0
        for index, row in enumerate(rows, start=1):
            if not row["address"]:
                continue
            if on_progress:
                on_progress(
                    100.0 * index / max(len(rows), 1),
                    f"Reading {row['name']} on port {row['port']}",
                )
            result = webid.identify(row["address"], int(row["port"]), timeout=timeout)
            if not result:
                continue
            identified += 1
            device_id = int(row["device_id"])
            if result["title"]:
                titles += 1
                db.add_observation(
                    device_id, "web", "web_title", result["title"], 0.85, utc_now()
                )
                # Only a title that actually looks like a model designation, and
                # only where a better source has not already supplied one.
                known = webid.looks_like_a_model(result["title"]) or bool(
                    classify_model(result["title"])
                )
                existing = db.conn.execute(
                    "SELECT model FROM devices WHERE id=?", (device_id,)
                ).fetchone()["model"]
                if known and not existing:
                    db.update_device(device_id, model=result["title"])
            if result["server"]:
                db.add_observation(
                    device_id, "web", "web_server", result["server"], 0.6, utc_now()
                )
            for kind, label in result["type_hints"]:
                db.add_observation(
                    device_id, "web", "web_device_type", f"{kind}: {label}", 0.9, utc_now()
                )
            for detail in result["details"]:
                db.add_observation(device_id, "web", "web_detail", detail, 0.5, utc_now())
        db.commit()
        _finalize(db, before)
        detail = f"{identified} interface(s) read, {titles} named their model"
        db.set_scan_progress(scan_id, 100.0, detail, identified)
        db.finish_scan(scan_id, "complete")
        return {"probed": len(rows), "identified": identified, "titles": titles}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def collect_neighbours(db: AtlasDB) -> dict[str, object]:
    """Read the kernel ARP/NDP caches. Instant, silent, and covers IPv6."""
    scan_id = db.begin_scan("neighbours", "kernel cache", ["ip", "neigh", "show"])
    try:
        before = events.snapshot(db)
        count = ingest.import_neighbours(db)
        _finalize(db, before)
        db.set_scan_progress(scan_id, 100.0, f"{count} neighbour entries", count)
        db.finish_scan(scan_id, "complete")
        return {"imported": count}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def collect_names(
    db: AtlasDB, target: str | None = None, *, timeout: int = 90,
    on_progress: ProgressHook | None = None,
) -> dict[str, object]:
    """Resolve names for the known inventory: PTR, mDNS and NetBIOS."""
    target = target or netinfo.primary_target()
    scan_id = db.begin_scan("names", target or "inventory", ["nbtscan", "avahi-resolve"])
    try:
        before = events.snapshot(db)
        addresses = [
            row["address"]
            for row in db.conn.execute(
                """SELECT DISTINCT a.address FROM addresses a JOIN devices d ON d.id=a.device_id
                   WHERE d.status='online' AND a.family='ipv4'"""
            )
        ]
        if on_progress:
            on_progress(10.0, f"Resolving {len(addresses)} addresses")
        db.set_scan_progress(scan_id, 10.0, f"Resolving {len(addresses)} addresses")
        reverse = enrich.reverse_dns(addresses)
        db.set_scan_progress(scan_id, 40.0, f"{len(reverse)} PTR records")
        mdns = enrich.mdns_names(addresses)
        db.set_scan_progress(scan_id, 65.0, f"{len(mdns)} mDNS names")
        netbios = enrich.netbios_names(target, timeout=timeout) if target else []
        db.set_scan_progress(scan_id, 85.0, f"{len(netbios)} NetBIOS names")
        applied = ingest.apply_enrichment(db, reverse=reverse, mdns=mdns, netbios=netbios)
        _finalize(db, before)
        db.set_scan_progress(scan_id, 100.0, f"{applied} names applied", applied)
        db.finish_scan(scan_id, "complete")
        return {
            "reverse_dns": len(reverse), "mdns": len(mdns),
            "netbios": len(netbios), "applied": applied,
        }
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def collect_arp(
    db: AtlasDB, interface: str, *, timeout: int = 120, use_sudo: bool = False
) -> dict[str, object]:
    if not interface or not all(character.isalnum() or character in "_.:-" for character in interface):
        raise ValueError("Invalid interface name")
    import os

    prefix = [_require("sudo"), "--"] if use_sudo and os.geteuid() != 0 else []
    command = [*prefix, _require("arp-scan"), "--interface", interface, "--localnet"]
    scan_id = db.begin_scan("arp-scan", "localnet", command)
    try:
        before = events.snapshot(db)
        process = _run(command, timeout)
        if process.returncode not in (0, 1):
            raise CollectorError(process.stderr.strip() or f"arp-scan exited with {process.returncode}")
        raw_path = _save_raw(db, "arp-scan", "txt", process.stdout)
        imported = import_arp_scan(db, process.stdout)
        _finalize(db, before)
        db.set_scan_progress(scan_id, 100.0, f"{imported} hosts", imported)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        return {"command": command, "imported": imported, "raw_path": str(raw_path)}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise


def collect_mdns(db: AtlasDB, *, timeout: int = 45) -> dict[str, object]:
    command = [_require("avahi-browse"), "--all", "--resolve", "--terminate", "--parsable"]
    scan_id = db.begin_scan("mdns", "localnet", command)
    try:
        before = events.snapshot(db)
        process = _run(command, timeout)
        if process.returncode != 0:
            error = process.stderr.strip() or process.stdout.strip()
            if "Daemon not running" in error or "Failed to create client object" in error:
                raise CollectorError(
                    "Avahi is installed but avahi-daemon is not running. Start it with "
                    "`sudo systemctl start avahi-daemon`, then retry."
                )
            raise CollectorError(error or f"avahi-browse exited with {process.returncode}")
        raw_path = _save_raw(db, "mdns", "txt", process.stdout)
        imported = import_avahi(db, process.stdout)
        _finalize(db, before)
        db.set_scan_progress(scan_id, 100.0, f"{imported} advertised services", imported)
        db.finish_scan(scan_id, "complete", raw_path=str(raw_path))
        return {"command": command, "imported": imported, "raw_path": str(raw_path)}
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc))
        raise
