from __future__ import annotations

import json
import ipaddress
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import netinfo
from .util import (
    STATUS_ONLINE,
    clean_text,
    normalize_mac,
    normalize_status,
    utc_now,
)


SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac TEXT UNIQUE,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    confidence REAL NOT NULL DEFAULT 0.0,
    os_name TEXT,
    os_accuracy INTEGER,
    nmap_device_type TEXT,
    model TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    manual_name TEXT,
    manual_type TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    family TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, address)
);
CREATE INDEX IF NOT EXISTS idx_addresses_address ON addresses(address);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    name TEXT,
    product TEXT,
    version TEXT,
    extra TEXT,
    cpe TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, protocol, port)
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_device ON observations(device_id);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    edge_key TEXT NOT NULL UNIQUE,
    source_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL,
    source_port TEXT,
    target_port TEXT,
    vlan TEXT,
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    detail TEXT,
    occurred_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    finding_key TEXT NOT NULL UNIQUE,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    title TEXT NOT NULL,
    detail TEXT,
    remediation TEXT,
    evidence TEXT,
    port INTEGER,
    protocol TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    muted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(resolved_at, muted);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    flow_key TEXT NOT NULL UNIQUE,
    source_device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    target_device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    target_address TEXT,
    protocol TEXT NOT NULL,
    port INTEGER,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    external INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_source ON flows(source_device_id);

CREATE TABLE IF NOT EXISTS schedule (
    kind TEXT PRIMARY KEY,
    interval_seconds INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    parameters_json TEXT NOT NULL DEFAULT '{}',
    last_run_at TEXT,
    last_status TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    target TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    command_json TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    raw_path TEXT,
    progress REAL NOT NULL DEFAULT 0.0,
    detail TEXT,
    found INTEGER NOT NULL DEFAULT 0
);
"""

# Columns added after the initial release. SQLite has no ADD COLUMN IF NOT EXISTS,
# so each is applied only when absent from the live table.
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("devices", "is_local", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "sources", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "os_family", "TEXT"),
    ("devices", "notes", "TEXT"),
    ("devices", "last_active", "TEXT"),
    ("addresses", "interface", "TEXT"),
    ("scans", "progress", "REAL NOT NULL DEFAULT 0.0"),
    ("scans", "detail", "TEXT"),
    ("scans", "found", "INTEGER NOT NULL DEFAULT 0"),
    # Ownership and expectations: the difference between "a device" and
    # "an unapproved device", which is what makes an alert actionable.
    ("devices", "owner", "TEXT"),
    ("devices", "location", "TEXT"),
    ("devices", "approved", "INTEGER"),
    # Wireless association, filled in by a Wi-Fi survey.
    ("devices", "wifi_bssid", "TEXT"),
    ("devices", "wifi_ssid", "TEXT"),
    ("devices", "wifi_signal", "INTEGER"),
    ("devices", "wifi_seen_at", "TEXT"),
)


# Discovery advertisements sometimes carry a bare UUID as the instance name. It is
# a valid identifier but useless in a device list, so an address reads better.
_UUID_NAME = re.compile(
    r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$",
    re.IGNORECASE,
)


def _readable_name(hostname: str | None) -> str | None:
    if not hostname:
        return None
    candidate = hostname.strip()
    for zone in (".local", ".lan", ".home", ".localdomain"):
        if candidate.lower().endswith(zone):
            candidate = candidate[: -len(zone)]
            break
    if not candidate or _UUID_NAME.match(candidate):
        return None
    # A name that is only a service or enumeration label identifies no device.
    if candidate.startswith("_") or "._tcp" in candidate or "._udp" in candidate:
        return None
    return candidate


def _address_sort_key(address: str) -> tuple[int, Any]:
    """IPv4 numerically before IPv6, so 192.168.1.9 precedes 192.168.1.10."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return (2, address)
    return (0 if parsed.version == 4 else 1, int(parsed))


# Ports worth calling out in a network overview. Everything else reads as routine.
_RISK_PORTS = {
    21: "FTP transfers credentials in clear text",
    23: "Telnet transfers credentials in clear text",
    69: "TFTP has no authentication",
    111: "RPC portmapper is widely exploitable",
    135: "Windows RPC endpoint mapper",
    445: "SMB file sharing is exposed",
    512: "rexec is unauthenticated",
    513: "rlogin transfers credentials in clear text",
    514: "rsh transfers credentials in clear text",
    1433: "Database reachable on the network",
    3306: "Database reachable on the network",
    3389: "Remote Desktop is exposed",
    5432: "Database reachable on the network",
    5900: "VNC is often unauthenticated",
    6379: "Redis is unauthenticated by default",
    27017: "MongoDB is unauthenticated by default",
}


def _service_risk(port: int, name: str) -> dict[str, Any] | None:
    note = _RISK_PORTS.get(port)
    if not note:
        if "telnet" in name.lower():
            note = "Telnet transfers credentials in clear text"
        else:
            return None
    return {"level": "attention", "note": note}


class AtlasDB:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=15.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _purge_orphans(self) -> int:
        """Delete child rows whose device is gone.

        SQLite enforces foreign keys only when the connecting client enables the
        pragma, so rows deleted by another tool can leave children behind.
        """
        removed = 0
        statements = (
            "DELETE FROM addresses WHERE device_id NOT IN (SELECT id FROM devices)",
            "DELETE FROM services WHERE device_id NOT IN (SELECT id FROM devices)",
            """DELETE FROM observations WHERE device_id IS NOT NULL
                 AND device_id NOT IN (SELECT id FROM devices)""",
            """DELETE FROM edges WHERE source_device_id NOT IN (SELECT id FROM devices)
                 OR target_device_id NOT IN (SELECT id FROM devices)""",
            """DELETE FROM events WHERE device_id IS NOT NULL
                 AND device_id NOT IN (SELECT id FROM devices)""",
            """DELETE FROM findings WHERE device_id IS NOT NULL
                 AND device_id NOT IN (SELECT id FROM devices)""",
            """DELETE FROM flows WHERE source_device_id NOT IN (SELECT id FROM devices)""",
        )
        for statement in statements:
            removed += self.conn.execute(statement).rowcount or 0
        if removed:
            self.conn.commit()
        return removed

    def _migrate(self) -> None:
        for table, column, definition in MIGRATIONS:
            existing = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})")
            }
            if column not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        self.conn.commit()
        self._purge_orphans()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "AtlasDB":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def begin_scan(self, source: str, target: str | None, command: list[str]) -> int:
        cursor = self.conn.execute(
            "INSERT INTO scans(source,target,started_at,status,command_json) VALUES(?,?,?,?,?)",
            (source, target, utc_now(), "running", json.dumps(command)),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def finish_scan(
        self,
        scan_id: int,
        status: str,
        *,
        error: str | None = None,
        raw_path: str | None = None,
    ) -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at=?,status=?,error=?,raw_path=? WHERE id=?",
            (utc_now(), status, clean_text(error, 2000), raw_path, scan_id),
        )
        self.conn.commit()

    def find_device_by_address(self, address: str) -> int | None:
        row = self.conn.execute(
            "SELECT device_id FROM addresses WHERE address=? ORDER BY last_seen DESC LIMIT 1",
            (address,),
        ).fetchone()
        return int(row[0]) if row else None

    def ensure_device(
        self,
        *,
        mac: str | None = None,
        address: str | None = None,
        family: str = "ipv4",
        hostname: str | None = None,
        vendor: str | None = None,
        status: str = "online",
        seen_at: str | None = None,
        source: str | None = None,
        is_local: bool = False,
        interface: str | None = None,
    ) -> int:
        seen_at = seen_at or utc_now()
        status = normalize_status(status)
        mac = normalize_mac(mac)
        row = None
        if mac:
            row = self.conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if not row and address:
            device_id = self.find_device_by_address(address)
            if device_id:
                existing = self.conn.execute(
                    "SELECT mac FROM devices WHERE id=?", (device_id,)
                ).fetchone()
                if existing is None:
                    # The address row outlived its device; drop the dangling reference.
                    self.conn.execute("DELETE FROM addresses WHERE device_id=?", (device_id,))
                # Do not overwrite a historical device when DHCP reuses its IP for a new MAC.
                elif not mac or not existing["mac"]:
                    row = (device_id,)
        if not row and not mac and not address and hostname:
            row = self.conn.execute(
                "SELECT id FROM devices WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
                (hostname,),
            ).fetchone()

        if row:
            device_id = int(row[0])
            fields: list[str] = ["last_seen=?"]
            values: list[Any] = [seen_at]
            # Never let a later probe downgrade a host that answered this round.
            current = self.conn.execute(
                "SELECT status,sources FROM devices WHERE id=?", (device_id,)
            ).fetchone()
            if status == STATUS_ONLINE or current["status"] != STATUS_ONLINE:
                fields.append("status=?")
                values.append(status)
            if status == STATUS_ONLINE:
                fields.append("last_active=?")
                values.append(seen_at)
            for field, value in (("mac", mac), ("hostname", hostname), ("vendor", vendor)):
                if value:
                    fields.append(f"{field}=?")
                    values.append(clean_text(value))
            if is_local:
                fields.append("is_local=1")
            if source:
                merged = sorted({*(current["sources"] or "").split(","), source} - {""})
                fields.append("sources=?")
                values.append(",".join(merged))
            values.append(device_id)
            self.conn.execute(f"UPDATE devices SET {','.join(fields)} WHERE id=?", values)
        else:
            cursor = self.conn.execute(
                """INSERT INTO devices(mac,hostname,vendor,status,first_seen,last_seen,
                                      last_active,sources,is_local)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    mac, clean_text(hostname), clean_text(vendor), status, seen_at, seen_at,
                    seen_at if status == STATUS_ONLINE else None, source or "", int(is_local),
                ),
            )
            device_id = int(cursor.lastrowid)

        if address:
            # One IPv4 address cannot belong to two devices at once. When another
            # online device with a different hardware address already holds it, the
            # established holder keeps it and the claim is recorded as evidence:
            # a spoofed or misattributed announcement should not fork the map into
            # two competing copies of the same host. A genuine handover is picked
            # up by the next active scan, which demotes stale holders first.
            holder = self.conn.execute(
                """SELECT a.device_id, d.mac, d.status FROM addresses a
                   JOIN devices d ON d.id = a.device_id
                   WHERE a.address = ? AND a.device_id != ?
                   ORDER BY a.last_seen DESC LIMIT 1""",
                (address, device_id),
            ).fetchone()
            contested = bool(
                holder
                and mac
                and holder["mac"]
                and holder["mac"] != mac
                and holder["status"] == STATUS_ONLINE
            )
            if contested:
                self.add_observation(
                    device_id, "conflict", "address_claim",
                    f"Claimed {address}, which is held by {holder['mac']}",
                    0.4, seen_at,
                )
            else:
                self.conn.execute(
                    """INSERT INTO addresses(device_id,address,family,first_seen,last_seen,interface)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(device_id,address) DO UPDATE SET
                           last_seen=excluded.last_seen,
                           interface=COALESCE(excluded.interface,addresses.interface)""",
                    (device_id, address, family, seen_at, seen_at, interface),
                )
        return device_id

    def update_device(self, device_id: int, **fields: Any) -> None:
        allowed = {
            "hostname", "vendor", "device_type", "confidence", "os_name", "os_accuracy",
            "nmap_device_type", "model", "status", "manual_name", "manual_type",
            "metadata_json", "os_family", "notes", "sources", "is_local",
            "owner", "location", "approved",
            "wifi_bssid", "wifi_ssid", "wifi_signal", "wifi_seen_at",
        }
        selected = {key: value for key, value in fields.items() if key in allowed}
        if not selected:
            return
        assignments = ",".join(f"{key}=?" for key in selected)
        self.conn.execute(
            f"UPDATE devices SET {assignments} WHERE id=?",
            (*selected.values(), device_id),
        )

    def mark_network_offline(
        self, network: ipaddress.IPv4Network | ipaddress.IPv6Network
    ) -> int:
        device_ids: set[int] = set()
        for row in self.conn.execute("SELECT device_id,address FROM addresses"):
            try:
                if ipaddress.ip_address(row["address"]) in network:
                    device_ids.add(int(row["device_id"]))
            except ValueError:
                continue
        if device_ids:
            placeholders = ",".join("?" for _ in device_ids)
            self.conn.execute(
                f"UPDATE devices SET status='offline' WHERE id IN ({placeholders})",
                tuple(device_ids),
            )
            self.conn.commit()
        return len(device_ids)

    def set_scan_progress(
        self, scan_id: int, progress: float, detail: str | None = None, found: int | None = None
    ) -> None:
        fields = ["progress=?"]
        values: list[Any] = [max(0.0, min(float(progress), 100.0))]
        if detail is not None:
            fields.append("detail=?")
            values.append(clean_text(detail, 300))
        if found is not None:
            fields.append("found=?")
            values.append(int(found))
        values.append(scan_id)
        self.conn.execute(f"UPDATE scans SET {','.join(fields)} WHERE id=?", values)
        self.conn.commit()

    def reap_stale_scans(self, max_age_seconds: int = 7200) -> int:
        """Fail scans whose process died without writing a terminal status."""
        cursor = self.conn.execute(
            """UPDATE scans SET status='failed', finished_at=?,
                   error='Interrupted; the collector did not finish'
               WHERE status='running'
                 AND (julianday(?) - julianday(started_at)) * 86400 > ?""",
            (utc_now(), utc_now(), max_age_seconds),
        )
        self.conn.commit()
        return cursor.rowcount or 0

    def add_service(
        self,
        device_id: int,
        protocol: str,
        port: int,
        *,
        name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        extra: str | None = None,
        cpe: str | None = None,
        state: str = "open",
        seen_at: str | None = None,
    ) -> None:
        seen_at = seen_at or utc_now()
        values = tuple(clean_text(v) for v in (name, product, version, extra, cpe))
        self.conn.execute(
            """INSERT INTO services(
                   device_id,protocol,port,name,product,version,extra,cpe,state,first_seen,last_seen
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(device_id,protocol,port) DO UPDATE SET
                   name=excluded.name,product=excluded.product,version=excluded.version,
                   extra=excluded.extra,cpe=excluded.cpe,state=excluded.state,last_seen=excluded.last_seen""",
            (device_id, protocol, port, *values, state, seen_at, seen_at),
        )

    def add_observation(
        self,
        device_id: int | None,
        source: str,
        key: str,
        value: str,
        confidence: float = 0.5,
        observed_at: str | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO observations(device_id,source,key,value,confidence,observed_at) VALUES(?,?,?,?,?,?)",
            (device_id, source, key, clean_text(value, 2000), confidence, observed_at or utc_now()),
        )

    def add_edge(
        self,
        source_device_id: int,
        target_device_id: int,
        edge_type: str,
        *,
        source_port: str | None = None,
        target_port: str | None = None,
        vlan: str | None = None,
        confidence: float = 0.5,
        evidence: str | None = None,
        seen_at: str | None = None,
    ) -> None:
        if source_device_id == target_device_id:
            return
        seen_at = seen_at or utc_now()
        edge_key = "|".join(
            str(part or "")
            for part in (edge_type, source_device_id, target_device_id, source_port, target_port, vlan)
        )
        self.conn.execute(
            """INSERT INTO edges(
                   edge_key,source_device_id,target_device_id,edge_type,source_port,target_port,
                   vlan,confidence,evidence,first_seen,last_seen
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(edge_key) DO UPDATE SET
                   confidence=excluded.confidence,evidence=excluded.evidence,last_seen=excluded.last_seen""",
            (
                edge_key, source_device_id, target_device_id, edge_type, clean_text(source_port),
                clean_text(target_port), clean_text(vlan), confidence, clean_text(evidence, 1000),
                seen_at, seen_at,
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def device_ids(self) -> list[int]:
        return [int(row[0]) for row in self.conn.execute("SELECT id FROM devices")]

    def classification_input(self, device_id: int) -> dict[str, Any]:
        device = dict(self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone())
        device["services"] = [
            dict(row) for row in self.conn.execute("SELECT * FROM services WHERE device_id=?", (device_id,))
        ]
        device["observations"] = [
            dict(row)
            for row in self.conn.execute(
                "SELECT * FROM observations WHERE device_id=? ORDER BY observed_at DESC LIMIT 100",
                (device_id,),
            )
        ]
        return device

    def summary(self) -> dict[str, Any]:
        online = self.conn.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
        type_rows = self.conn.execute(
            """SELECT COALESCE(manual_type,device_type) type,COUNT(*) count
               FROM devices WHERE status='online' GROUP BY type ORDER BY count DESC"""
        ).fetchall()
        vendor_rows = self.conn.execute(
            """SELECT vendor,COUNT(*) count FROM devices
               WHERE status='online' AND vendor IS NOT NULL AND vendor!=''
               GROUP BY vendor ORDER BY count DESC LIMIT 8"""
        ).fetchall()
        last_scan = self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        unknown = next((row["count"] for row in type_rows if row["type"] == "unknown"), 0)
        named = self.conn.execute(
            """SELECT COUNT(*) FROM devices WHERE status='online'
                 AND (COALESCE(manual_name,hostname,'') != '')"""
        ).fetchone()[0]
        return {
            "devices": online,
            "known_total": self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "online": online,
            "services": self.conn.execute(
                """SELECT COUNT(*) FROM services s JOIN devices d ON d.id=s.device_id
                   WHERE s.state LIKE 'open%' AND d.status='online'"""
            ).fetchone()[0],
            "links": self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
            "identified": online - unknown,
            "named": named,
            "types": {row["type"]: row["count"] for row in type_rows},
            "vendors": {row["vendor"]: row["count"] for row in vendor_rows},
            "attention": sum(
                1 for service in self.services_overview() if service.get("risk")
            ),
            "findings": {
                row["severity"]: row["count"]
                for row in self.conn.execute(
                    """SELECT severity, COUNT(*) count FROM findings
                       WHERE resolved_at IS NULL AND muted=0 GROUP BY severity"""
                )
            },
            "findings_resolved": self.conn.execute(
                "SELECT COUNT(*) FROM findings WHERE resolved_at IS NOT NULL"
            ).fetchone()[0],
            "unacknowledged_events": self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE acknowledged=0"
            ).fetchone()[0],
            "flows": self.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0],
            "last_scan": dict(last_scan) if last_scan else None,
        }

    def devices(
        self,
        *,
        online_only: bool = True,
        include_services: bool = True,
        include_evidence: bool = True,
    ) -> list[dict[str, Any]]:
        """Inventory rows. Offline hosts are excluded by default: a scanned /24
        yields 250-odd addresses that answered nothing, and listing them buries
        the devices that actually exist."""
        condition = "WHERE d.status='online'" if online_only else ""
        rows = self.conn.execute(
            f"""SELECT d.*,
                   GROUP_CONCAT(DISTINCT a.address) addresses
               FROM devices d LEFT JOIN addresses a ON a.device_id=d.id
               {condition}
               GROUP BY d.id ORDER BY COALESCE(d.manual_name,d.hostname,d.mac)"""
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["addresses"] = sorted(
                item["addresses"].split(",") if item["addresses"] else [],
                key=_address_sort_key,
            )
            item["display_name"] = (
                item["manual_name"] or _readable_name(item["hostname"])
                or next(iter(item["addresses"]), None)
                or item["mac"] or f"Device {item['id']}"
            )
            item["effective_type"] = item["manual_type"] or item["device_type"]
            item["primary_address"] = next(iter(item["addresses"]), None)
            item["source_list"] = [s for s in (item.get("sources") or "").split(",") if s]
            try:
                item["metadata"] = json.loads(item.get("metadata_json") or "{}")
            except json.JSONDecodeError:
                item["metadata"] = {}
            if include_services:
                item["services"] = [
                    dict(service)
                    for service in self.conn.execute(
                        """SELECT protocol,port,name,product,version,extra,cpe,state,first_seen,last_seen
                           FROM services WHERE device_id=? AND state LIKE 'open%' ORDER BY port""",
                        (item["id"],),
                    )
                ]
                item["service_count"] = len(item["services"])
            if include_evidence:
                item["evidence"] = [
                    dict(obs)
                    for obs in self.conn.execute(
                        """SELECT source,key,value,confidence,observed_at FROM observations
                           WHERE device_id=? ORDER BY observed_at DESC LIMIT 40""",
                        (item["id"],),
                    )
                ]
            result.append(item)
        return result

    def graph(self, *, online_only: bool = True) -> dict[str, Any]:
        nodes = self.devices(online_only=online_only)
        visible = {node["id"] for node in nodes}
        edges = [
            dict(row)
            for row in self.conn.execute("SELECT * FROM edges ORDER BY id")
            if row["source_device_id"] in visible and row["target_device_id"] in visible
        ]
        return {"nodes": nodes, "edges": edges}

    def tree(self, *, online_only: bool = True) -> dict[str, Any]:
        """Parent/child topology rooted at the gateway.

        Physical evidence wins: an LLDP or switch-port edge names the real parent.
        Everything else on a directly attached segment hangs off its gateway, which
        is what a flat home or office LAN actually looks like.
        """
        nodes = self.devices(online_only=online_only, include_evidence=False)
        by_id = {node["id"]: node for node in nodes}
        infrastructure = {"router", "switch", "access-point", "firewall", "network-device"}

        parent: dict[int, int] = {}
        reason: dict[int, str] = {}
        # Strongest evidence last so it overwrites weaker inference.
        # Weakest evidence first so the strongest overwrites it. A Wi-Fi
        # association is authoritative for a wireless client.
        for kind in ("attachment", "route", "cdp", "switch-port", "lldp", "wireless"):
            for row in self.conn.execute(
                "SELECT * FROM edges WHERE edge_type=? ORDER BY confidence", (kind,)
            ):
                child, host = row["target_device_id"], row["source_device_id"]
                if child not in by_id or host not in by_id or child == host:
                    continue
                # Infrastructure should not be parented to a leaf it merely reported.
                if by_id[child]["effective_type"] in infrastructure and kind == "route":
                    continue
                parent[child] = host
                reason[child] = row["evidence"] or kind
                if row["source_port"] or row["target_port"]:
                    by_id[child]["uplink_port"] = row["source_port"] or row["target_port"]

        # Anchor on the address the routing table actually names, rather than on
        # whichever device merely classified as a router.
        gateway_id = None
        for gateway in netinfo.gateways():
            candidate = self.find_device_by_address(gateway["address"])
            if candidate in by_id:
                gateway_id = candidate
                break
        if gateway_id is None:
            routers = [
                node for node in nodes
                if not node.get("is_local") and node["effective_type"] == "router"
            ]
            gateway_id = routers[0]["id"] if routers else None

        for node in nodes:
            if node["id"] in parent or node["id"] == gateway_id:
                continue
            if gateway_id is not None:
                parent[node["id"]] = gateway_id
                reason.setdefault(node["id"], "Same routed segment as the gateway")

        # Break any cycle so the renderer can never recurse forever.
        for node_id in list(parent):
            seen = {node_id}
            cursor = parent.get(node_id)
            while cursor is not None:
                if cursor in seen:
                    parent.pop(node_id, None)
                    break
                seen.add(cursor)
                cursor = parent.get(cursor)

        for node in nodes:
            node["parent_id"] = parent.get(node["id"])
            node["parent_reason"] = reason.get(node["id"])
            node["is_infrastructure"] = node["effective_type"] in infrastructure

        children: dict[int | None, list[int]] = {}
        for node in nodes:
            children.setdefault(node["parent_id"], []).append(node["id"])
        for node in nodes:
            node["child_count"] = len(children.get(node["id"], []))

        return {
            "nodes": nodes,
            "roots": children.get(None, []),
            "gateway_id": gateway_id,
        }

    def services_overview(self, *, online_only: bool = True) -> list[dict[str, Any]]:
        """Open ports aggregated across the network, busiest service first."""
        condition = "AND d.status='online'" if online_only else ""
        rows = self.conn.execute(
            f"""SELECT s.port, s.protocol,
                       COALESCE(NULLIF(s.name,''),'unknown') name,
                       COUNT(DISTINCT s.device_id) device_count,
                       GROUP_CONCAT(DISTINCT s.product) products,
                       GROUP_CONCAT(DISTINCT s.device_id) device_ids
                FROM services s JOIN devices d ON d.id=s.device_id
                WHERE s.state LIKE 'open%' {condition}
                GROUP BY s.port, s.protocol, name
                ORDER BY device_count DESC, s.port"""
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["device_ids"] = [int(v) for v in (item["device_ids"] or "").split(",") if v]
            item["products"] = [p for p in (item["products"] or "").split(",") if p]
            item["risk"] = _service_risk(int(item["port"]), item["name"])
            result.append(item)
        return result

    def changes(self, limit: int = 40) -> list[dict[str, Any]]:
        """Recently appeared devices and newly observed open ports."""
        events: list[dict[str, Any]] = []
        for row in self.conn.execute(
            """SELECT id, COALESCE(manual_name,hostname,mac,'Device '||id) name,
                      COALESCE(manual_type,device_type) type, first_seen, status
               FROM devices WHERE status='online' ORDER BY first_seen DESC LIMIT ?""",
            (limit,),
        ):
            events.append({
                "kind": "device-appeared", "device_id": row["id"], "name": row["name"],
                "device_type": row["type"], "at": row["first_seen"],
                "detail": "First seen on the network",
            })
        for row in self.conn.execute(
            """SELECT s.device_id, s.port, s.protocol, s.name, s.first_seen,
                      COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) device_name
               FROM services s JOIN devices d ON d.id=s.device_id
               WHERE s.state LIKE 'open%' AND d.status='online'
               ORDER BY s.first_seen DESC LIMIT ?""",
            (limit,),
        ):
            events.append({
                "kind": "port-opened", "device_id": row["device_id"], "name": row["device_name"],
                "at": row["first_seen"],
                "detail": f"{row['port']}/{row['protocol']} {row['name'] or ''}".strip(),
            })
        events.sort(key=lambda item: item["at"] or "", reverse=True)
        return events[:limit]

    def findings(
        self, *, include_resolved: bool = False, include_muted: bool = False, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Open findings, most severe first, each with the device it belongs to."""
        conditions = []
        if not include_resolved:
            conditions.append("f.resolved_at IS NULL")
        if not include_muted:
            conditions.append("f.muted = 0")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self.conn.execute(
            f"""SELECT f.*,
                       COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) device_name,
                       COALESCE(d.manual_type,d.device_type) device_type,
                       (SELECT a.address FROM addresses a WHERE a.device_id=d.id
                         AND a.family='ipv4' ORDER BY a.last_seen DESC LIMIT 1) device_address
                FROM findings f LEFT JOIN devices d ON d.id = f.device_id
                {where}
                ORDER BY CASE f.severity
                             WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                             WHEN 'low' THEN 2 ELSE 3 END,
                         f.kind, f.device_id, f.port
                LIMIT ?""",
            (max(1, min(limit, 2000)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def set_finding_muted(self, finding_id: int, muted: bool) -> None:
        self.conn.execute(
            "UPDATE findings SET muted=? WHERE id=?", (int(muted), finding_id)
        )
        self.commit()

    def events(self, *, limit: int = 100, severity: str | None = None) -> list[dict[str, Any]]:
        query = """SELECT e.*,
                          COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) device_name,
                          COALESCE(d.manual_type,d.device_type) device_type
                   FROM events e LEFT JOIN devices d ON d.id = e.device_id"""
        parameters: list[Any] = []
        if severity:
            query += " WHERE e.severity = ?"
            parameters.append(severity)
        query += " ORDER BY e.occurred_at DESC, e.id DESC LIMIT ?"
        parameters.append(max(1, min(limit, 1000)))
        return [dict(row) for row in self.conn.execute(query, parameters)]

    def acknowledge_events(self, before: str | None = None) -> int:
        cursor = self.conn.execute(
            "UPDATE events SET acknowledged=1 WHERE acknowledged=0"
            + (" AND occurred_at <= ?" if before else ""),
            (before,) if before else (),
        )
        self.commit()
        return cursor.rowcount or 0

    def flows(self, *, limit: int = 300, online_only: bool = True) -> list[dict[str, Any]]:
        """Observed traffic pairs, busiest first."""
        condition = "WHERE src.status='online'" if online_only else ""
        rows = self.conn.execute(
            f"""SELECT f.*,
                       COALESCE(src.manual_name,src.hostname,src.mac,'Device '||src.id) source_name,
                       COALESCE(src.manual_type,src.device_type) source_type,
                       COALESCE(dst.manual_name,dst.hostname,dst.mac,'Device '||dst.id) target_name,
                       COALESCE(dst.manual_type,dst.device_type) target_type
                FROM flows f
                JOIN devices src ON src.id = f.source_device_id
                LEFT JOIN devices dst ON dst.id = f.target_device_id
                {condition}
                ORDER BY f.packets DESC, f.last_seen DESC
                LIMIT ?""",
            (max(1, min(limit, 2000)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def prune_ghosts(self) -> int:
        """Delete address-only rows left behind by scanning a whole range.

        A discovery sweep of a /24 records every address it probed. Rows that never
        answered, carry no MAC, no name, no service and no observation are scan
        residue rather than devices, and they crowd out the real inventory.
        """
        cursor = self.conn.execute(
            """DELETE FROM devices WHERE status!='online' AND mac IS NULL
                 AND (hostname IS NULL OR hostname='')
                 AND (manual_name IS NULL OR manual_name='')
                 AND (vendor IS NULL OR vendor='')
                 AND is_local=0
                 AND id NOT IN (SELECT device_id FROM services WHERE device_id IS NOT NULL)
                 AND id NOT IN (SELECT device_id FROM observations WHERE device_id IS NOT NULL)
                 AND id NOT IN (SELECT source_device_id FROM edges)
                 AND id NOT IN (SELECT target_device_id FROM edges)"""
        )
        self.conn.commit()
        return cursor.rowcount or 0

    def scans(self, limit: int = 30) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (max(1, min(limit, 200)),)
            )
        ]

    def resolve_selector(self, selector: str) -> int:
        """Resolve a device by id, MAC or address, the way the CLI accepts them."""
        selector = (selector or "").strip()
        device_id: int | None = None
        if selector.isdigit():
            row = self.conn.execute(
                "SELECT id FROM devices WHERE id=?", (int(selector),)
            ).fetchone()
            device_id = int(row[0]) if row else None
        if device_id is None:
            mac = normalize_mac(selector)
            if mac:
                row = self.conn.execute(
                    "SELECT id FROM devices WHERE mac=?", (mac,)
                ).fetchone()
                device_id = int(row[0]) if row else None
        if device_id is None:
            device_id = self.find_device_by_address(selector)
        if device_id is None:
            raise ValueError(f"No device matches {selector!r}")
        return device_id

    def set_manual_label(self, selector: str, name: str | None, device_type: str | None) -> int:
        device_id = self.resolve_selector(selector)
        fields: dict[str, str | None] = {}
        if name is not None:
            fields["manual_name"] = clean_text(name)
        if device_type is not None:
            fields["manual_type"] = clean_text(device_type)
        if not fields:
            raise ValueError("Provide --name and/or --type")
        self.update_device(device_id, **fields)
        self.commit()
        return device_id
