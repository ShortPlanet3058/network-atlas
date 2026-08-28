from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Callable

from . import __version__
from . import findings as findings_module
from . import ingest, netinfo, scheduler, wireless
from . import events
from .classifier import classify_all
from .collectors import (
    PROFILE_LABELS,
    PROFILES,
    collect_arp,
    collect_audit,
    collect_mdns,
    collect_names,
    collect_neighbours,
    collect_nmap,
    collect_passive,
)
from .db import AtlasDB
from .parsers import import_arp_scan, import_avahi, import_nmap_xml
from .server import serve
from .snmp import collect_switch, load_switches
from .util import can_capture, nmap_privileged


DEFAULT_DB = Path(
    os.environ.get(
        "NETWORK_ATLAS_DB",
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        / "network-atlas"
        / "atlas.db",
    )
)
DEVICE_TYPES = (
    "unknown", "computer", "phone", "server", "printer", "router", "switch",
    "access-point", "firewall", "network-device", "storage", "media", "camera",
    "game-console", "iot",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-atlas", description="Discover and map an authorized local network"
    )
    parser.add_argument(
        "--version", action="version", version=f"network-atlas {__version__}"
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite database (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create or migrate the database")
    sub.add_parser("doctor", help="Report detected interfaces, gateway and capabilities")

    scan = sub.add_parser("scan", help="Run Nmap against an explicitly authorized CIDR")
    scan.add_argument("--target", help="CIDR such as 10.23.45.0/24 (default: detected subnet)")
    scan.add_argument(
        "--profile", choices=PROFILES, default="standard",
        help="; ".join(f"{key}: {label}" for key, label in PROFILE_LABELS.items()),
    )
    scan.add_argument("--allow-public", action="store_true", help="Confirm that an administered public range is intended")
    scan.add_argument("--allow-large", action="store_true", help="Confirm a range larger than 4096 addresses")
    scan.add_argument("--timeout", type=int, default=3600)
    scan.add_argument("--dry-run", action="store_true", help="Validate and print the command without scanning")
    scan.add_argument("--quiet", action="store_true", help="Suppress live Nmap progress")

    listen = sub.add_parser("passive", help="Discover devices by listening, without sending packets")
    listen.add_argument("--interface", help="Interface to listen on (default: first interface that is up)")
    listen.add_argument("--duration", type=int, default=60, help="Capture window in seconds")

    names = sub.add_parser("names", help="Resolve device names via PTR, mDNS and NetBIOS")
    names.add_argument("--target", help="CIDR for the NetBIOS sweep (default: detected subnet)")

    sub.add_parser("neighbours", help="Import the kernel ARP and IPv6 neighbour caches")

    arp = sub.add_parser("arp", help="Discover the directly attached LAN with arp-scan")
    arp.add_argument("--interface", required=True, help="Interface such as eth0")
    arp.add_argument("--timeout", type=int, default=120)
    arp.add_argument("--sudo", action="store_true", help="Elevate only the arp-scan subprocess")

    mdns = sub.add_parser("mdns", help="Collect advertised mDNS/DNS-SD services")
    mdns.add_argument("--timeout", type=int, default=45)

    snmp = sub.add_parser("snmp", help="Collect LLDP and switch-port topology over read-only SNMP")
    snmp.add_argument("--config", type=Path, required=True, help="Switch configuration JSON")
    snmp.add_argument("--timeout", type=int, default=30, help="Timeout for each SNMP walk")

    nmap_import = sub.add_parser("import-nmap", help="Import an existing Nmap XML file")
    nmap_import.add_argument("path", type=Path)
    arp_import = sub.add_parser("import-arp", help="Import saved arp-scan text output")
    arp_import.add_argument("path", type=Path)
    mdns_import = sub.add_parser("import-mdns", help="Import saved parsable avahi-browse output")
    mdns_import.add_argument("path", type=Path)

    viewer = sub.add_parser("serve", help="Start the interactive viewer")
    viewer.add_argument("--host", default="127.0.0.1")
    viewer.add_argument("--port", type=int, default=8765)
    viewer.add_argument(
        "--allow-remote", action="store_true",
        help="Acknowledge that the unauthenticated viewer will be remotely reachable",
    )

    label = sub.add_parser("label", help="Apply a trusted name or type override")
    label.add_argument("selector", help="Device ID, IP address, or MAC address")
    label.add_argument("--name")
    label.add_argument("--type", choices=DEVICE_TYPES)

    wifi = sub.add_parser(
        "wifi",
        help="Survey Wi-Fi to map clients to access points (needs root; "
             "disconnects the interface while it runs)",
    )
    wifi.add_argument("--interface", help="Wireless interface (default: the first one)")
    wifi.add_argument("--duration", type=int, default=45, help="Survey length in seconds")
    wifi.add_argument("--band", default="abg", choices=("a", "b", "g", "bg", "abg"))
    wifi.add_argument(
        "--yes", action="store_true",
        help="Skip the confirmation prompt about losing connectivity",
    )

    audit = sub.add_parser(
        "audit", help="Check the inventory for issues and report how to fix them"
    )
    audit.add_argument(
        "--skip-tls", action="store_true", help="Skip certificate and protocol checks"
    )

    report = sub.add_parser("findings", help="List open findings with their remediation")
    report.add_argument(
        "--severity", choices=("high", "medium", "low", "info"), help="Filter by severity"
    )
    report.add_argument("--json", action="store_true", help="Emit JSON instead of text")

    monitor = sub.add_parser(
        "monitor", help="Turn continuous monitoring on or off, or show its state"
    )
    monitor.add_argument(
        "action", nargs="?", choices=("on", "off", "status"), default="status"
    )

    log = sub.add_parser("events", help="Show the change log")
    log.add_argument("--limit", type=int, default=40)

    sub.add_parser("summary", help="Print inventory summary as JSON")
    sub.add_parser("classify", help="Recalculate all automatic device classifications")
    sub.add_parser("prune", help="Delete address-only rows left behind by range scans")
    return parser


def _print_result(result: object) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


def _print_findings(rows: list[dict[str, object]], db: AtlasDB) -> None:
    """Human-readable findings report, grouped by severity."""
    if not rows:
        print("No open findings. Run `audit` after a scan to re-check.")
        return
    summary = findings_module.summary(db)
    print(
        f"{summary['open']} open findings: "
        f"{summary['high']} high, {summary['medium']} medium, {summary['low']} low"
    )
    labels = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    current = None
    for row in rows:
        if row["severity"] != current:
            current = row["severity"]
            print(f"\n== {labels.get(current, current)} " + "=" * 52)
        where = row["device_name"]
        if row.get("device_address"):
            where += f" ({row['device_address']})"
        print(f"\n  {row['title']}")
        print(f"    device: {where}")
        if row.get("evidence"):
            print(f"    evidence: {row['evidence']}")
        if row.get("detail"):
            print(f"    why: {row['detail']}")
        if row.get("remediation"):
            print(f"    fix: {row['remediation']}")


def _record_import(
    db: AtlasDB,
    source: str,
    path: Path,
    importer: Callable[[AtlasDB, object], int],
    *,
    text: bool = False,
) -> int:
    resolved = path.expanduser().resolve()
    scan_id = db.begin_scan(source, str(resolved), [])
    try:
        payload: object = resolved.read_text(encoding="utf-8") if text else resolved
        count = importer(db, payload)
        ingest.apply_vendors(db)
        db.prune_ghosts()
        classify_all(db)
        db.finish_scan(scan_id, "complete", raw_path=str(resolved))
        return count
    except Exception as exc:
        db.finish_scan(scan_id, "failed", error=str(exc), raw_path=str(resolved))
        raise


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "serve":
            if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
                raise ValueError("Refusing a remote bind without --allow-remote; the viewer has no authentication")
            with AtlasDB(args.db):
                pass
            serve(args.db.expanduser().resolve(), args.host, args.port)
            return
        if args.command == "doctor":
            _print_result({
                "version": __version__,
                "capabilities": {
                    "nmap_raw_packets": nmap_privileged(),
                    "passive_capture": can_capture(),
                },
                **netinfo.summary(),
            })
            return

        with AtlasDB(args.db) as db:
            if args.command == "init":
                _print_result({"database": str(db.path), "status": "ready"})
            elif args.command == "scan":
                target = args.target or netinfo.primary_target()
                if not target:
                    raise ValueError("No local IPv4 subnet detected; pass --target")
                _print_result(
                    collect_nmap(
                        db, target,
                        profile=args.profile,
                        allow_public=args.allow_public,
                        allow_large=args.allow_large,
                        timeout=args.timeout,
                        dry_run=args.dry_run,
                        verbose=not args.quiet,
                    )
                )
            elif args.command == "passive":
                _print_result(
                    collect_passive(db, args.interface, duration=args.duration)
                )
            elif args.command == "names":
                _print_result(collect_names(db, args.target))
            elif args.command == "neighbours":
                _print_result(collect_neighbours(db))
            elif args.command == "arp":
                _print_result(
                    collect_arp(db, args.interface, timeout=args.timeout, use_sudo=args.sudo)
                )
            elif args.command == "mdns":
                _print_result(collect_mdns(db, timeout=args.timeout))
            elif args.command == "snmp":
                results = []
                for switch in load_switches(args.config):
                    results.append({"host": switch.get("host"), **collect_switch(db, switch, timeout=args.timeout)})
                classify_all(db)
                _print_result(results)
            elif args.command == "import-nmap":
                count = _record_import(db, "nmap-import", args.path, import_nmap_xml)
                _print_result({"imported_hosts": count})
            elif args.command == "import-arp":
                count = _record_import(db, "arp-import", args.path, import_arp_scan, text=True)
                _print_result({"imported_hosts": count})
            elif args.command == "import-mdns":
                count = _record_import(db, "mdns-import", args.path, import_avahi, text=True)
                _print_result({"imported_services": count})
            elif args.command == "label":
                device_id = db.set_manual_label(args.selector, args.name, args.type)
                _print_result({"device_id": device_id, "status": "updated"})
            elif args.command == "wifi":
                ready, reason = wireless.available()
                if not ready:
                    raise RuntimeError(reason)
                interface = args.interface or next(iter(wireless.wireless_interfaces()), None)
                if not interface:
                    raise RuntimeError("No wireless interface found")
                if not args.yes:
                    print(
                        f"A Wi-Fi survey puts {interface} into monitor mode for "
                        f"{args.duration}s. The interface will be disconnected for that "
                        "time, and any traffic over it will stop.",
                        file=sys.stderr,
                    )
                    answer = input("Continue? [y/N] ").strip().lower()
                    if answer not in ("y", "yes"):
                        _print_result({"cancelled": True})
                        return
                scan_id = db.begin_scan("wifi", interface, ["airodump-ng"])
                try:
                    before = events.snapshot(db)
                    result = wireless.survey(
                        interface, duration=args.duration, band=args.band
                    )
                    imported = ingest.import_wireless(db, result)
                    ingest.apply_vendors(db)
                    classify_all(db)
                    findings_module.evaluate(db)
                    events.diff(db, before)
                    rogues = wireless.rogue_access_points(result["access_points"])
                    db.set_scan_progress(
                        scan_id, 100.0,
                        f"{imported['access_points']} access points, "
                        f"{imported['associations']} associations",
                        imported["access_points"],
                    )
                    db.finish_scan(scan_id, "complete")
                    _print_result({
                        "interface": interface,
                        "duration": result["duration"],
                        **imported,
                        "stations_seen": len(result["stations"]),
                        "ssids_with_multiple_bssids": rogues,
                    })
                except Exception as exc:
                    db.finish_scan(scan_id, "failed", error=str(exc))
                    raise
            elif args.command == "audit":
                _print_result(collect_audit(db, skip_tls=args.skip_tls))
            elif args.command == "findings":
                rows = db.findings()
                if args.severity:
                    rows = [row for row in rows if row["severity"] == args.severity]
                if args.json:
                    _print_result(rows)
                else:
                    _print_findings(rows, db)
            elif args.command == "monitor":
                if args.action == "on":
                    changed = scheduler.set_monitoring(db, True)
                    _print_result({
                        "monitoring": True, "enabled_tasks": changed,
                        "note": "The viewer runs these while it is running; "
                                "start it with `make start`.",
                    })
                elif args.action == "off":
                    scheduler.set_monitoring(db, False)
                    _print_result({"monitoring": False})
                else:
                    _print_result({
                        "monitoring": scheduler.monitoring_active(db),
                        "tasks": scheduler.entries(db),
                    })
            elif args.command == "events":
                for event in reversed(db.events(limit=args.limit)):
                    marker = {"high": "!!", "medium": " !", "low": "  ", "info": "  "}
                    print(
                        f"{event['occurred_at']}  {marker.get(event['severity'], '  ')}  "
                        f"{event['title']}"
                        + (f"\n{'':>34}{event['detail']}" if event["detail"] else "")
                    )
            elif args.command == "summary":
                _print_result(db.summary())
            elif args.command == "classify":
                classify_all(db)
                _print_result({"classified_devices": len(db.device_ids())})
            elif args.command == "prune":
                _print_result({"removed": db.prune_ghosts()})
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
