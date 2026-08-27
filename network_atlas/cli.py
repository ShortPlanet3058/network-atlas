from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Callable

from .classifier import classify_all
from .collectors import collect_arp, collect_mdns, collect_nmap
from .db import AtlasDB
from .parsers import import_arp_scan, import_avahi, import_nmap_xml
from .server import serve
from .snmp import collect_switch, load_switches


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
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite database (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create or migrate the database")

    scan = sub.add_parser("scan", help="Run Nmap against an explicitly authorized CIDR")
    scan.add_argument("--target", required=True, help="CIDR such as 10.23.45.0/24")
    scan.add_argument("--profile", choices=("discovery", "inventory"), default="discovery")
    scan.add_argument("--allow-public", action="store_true", help="Confirm that an administered public range is intended")
    scan.add_argument("--allow-large", action="store_true", help="Confirm a range larger than 4096 addresses")
    scan.add_argument("--timeout", type=int, default=1800)
    scan.add_argument("--dry-run", action="store_true", help="Validate and print the command without scanning")
    scan.add_argument("--sudo", action="store_true", help="Elevate only the Nmap subprocess, not the viewer/database")
    scan.add_argument("--verbose", action="store_true", help="Show Nmap status while the scan runs")

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

    viewer = sub.add_parser("serve", help="Start the read-only interactive viewer")
    viewer.add_argument("--host", default="127.0.0.1")
    viewer.add_argument("--port", type=int, default=8765)
    viewer.add_argument(
        "--allow-remote", action="store_true", help="Acknowledge that the unauthenticated viewer will be remotely reachable"
    )

    label = sub.add_parser("label", help="Apply a trusted name or type override")
    label.add_argument("selector", help="Device ID, IP address, or MAC address")
    label.add_argument("--name")
    label.add_argument("--type", choices=DEVICE_TYPES)

    sub.add_parser("summary", help="Print inventory summary as JSON")
    sub.add_parser("classify", help="Recalculate all automatic device classifications")
    return parser


def _print_result(result: object) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


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

        with AtlasDB(args.db) as db:
            if args.command == "init":
                _print_result({"database": str(db.path), "status": "ready"})
            elif args.command == "scan":
                _print_result(
                    collect_nmap(
                        db,
                        args.target,
                        profile=args.profile,
                        allow_public=args.allow_public,
                        allow_large=args.allow_large,
                        timeout=args.timeout,
                        dry_run=args.dry_run,
                        use_sudo=args.sudo,
                        verbose=args.verbose,
                    )
                )
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
            elif args.command == "summary":
                _print_result(db.summary())
            elif args.command == "classify":
                classify_all(db)
                _print_result({"classified_devices": len(db.device_ids())})
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
