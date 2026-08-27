from __future__ import annotations

import json
import ipaddress
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .util import clean_text, normalize_mac, utc_now


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

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    target TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    command_json TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    raw_path TEXT
);
"""


class AtlasDB:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

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
    ) -> int:
        seen_at = seen_at or utc_now()
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
                # Do not overwrite a historical device when DHCP reuses its IP for a new MAC.
                if not mac or not existing["mac"]:
                    row = (device_id,)
        if not row and not mac and not address and hostname:
            row = self.conn.execute(
                "SELECT id FROM devices WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
                (hostname,),
            ).fetchone()

        if row:
            device_id = int(row[0])
            fields: list[str] = ["last_seen=?", "status=?"]
            values: list[Any] = [seen_at, status]
            for field, value in (("mac", mac), ("hostname", hostname), ("vendor", vendor)):
                if value:
                    fields.append(f"{field}=?")
                    values.append(clean_text(value))
            values.append(device_id)
            self.conn.execute(f"UPDATE devices SET {','.join(fields)} WHERE id=?", values)
        else:
            cursor = self.conn.execute(
                """INSERT INTO devices(mac,hostname,vendor,status,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?)""",
                (mac, clean_text(hostname), clean_text(vendor), status, seen_at, seen_at),
            )
            device_id = int(cursor.lastrowid)

        if address:
            self.conn.execute(
                """INSERT INTO addresses(device_id,address,family,first_seen,last_seen)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(device_id,address) DO UPDATE SET last_seen=excluded.last_seen""",
                (device_id, address, family, seen_at, seen_at),
            )
        return device_id

    def update_device(self, device_id: int, **fields: Any) -> None:
        allowed = {
            "hostname", "vendor", "device_type", "confidence", "os_name", "os_accuracy",
            "nmap_device_type", "model", "status", "manual_name", "manual_type", "metadata_json",
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
        type_rows = self.conn.execute(
            "SELECT COALESCE(manual_type,device_type) type,COUNT(*) count FROM devices GROUP BY type"
        ).fetchall()
        last_scan = self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return {
            "devices": self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "online": self.conn.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0],
            "services": self.conn.execute("SELECT COUNT(*) FROM services WHERE state='open'").fetchone()[0],
            "links": self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
            "types": {row["type"]: row["count"] for row in type_rows},
            "last_scan": dict(last_scan) if last_scan else None,
        }

    def devices(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT d.*,
                   GROUP_CONCAT(DISTINCT a.address) addresses
               FROM devices d LEFT JOIN addresses a ON a.device_id=d.id
               GROUP BY d.id ORDER BY COALESCE(d.manual_name,d.hostname,d.mac)"""
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["addresses"] = item["addresses"].split(",") if item["addresses"] else []
            item["display_name"] = (
                item["manual_name"] or item["hostname"] or next(iter(item["addresses"]), None)
                or item["mac"] or f"Device {item['id']}"
            )
            item["effective_type"] = item["manual_type"] or item["device_type"]
            item["services"] = [
                dict(service)
                for service in self.conn.execute(
                    "SELECT protocol,port,name,product,version,state FROM services WHERE device_id=? ORDER BY port",
                    (item["id"],),
                )
            ]
            item["evidence"] = [
                dict(obs)
                for obs in self.conn.execute(
                    """SELECT source,key,value,confidence,observed_at FROM observations
                       WHERE device_id=? ORDER BY observed_at DESC LIMIT 12""",
                    (item["id"],),
                )
            ]
            result.append(item)
        return result

    def graph(self) -> dict[str, Any]:
        return {
            "nodes": self.devices(),
            "edges": [dict(row) for row in self.conn.execute("SELECT * FROM edges ORDER BY id")],
        }

    def scans(self, limit: int = 30) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (max(1, min(limit, 200)),)
            )
        ]

    def set_manual_label(self, selector: str, name: str | None, device_type: str | None) -> int:
        device_id: int | None = None
        if selector.isdigit():
            row = self.conn.execute("SELECT id FROM devices WHERE id=?", (int(selector),)).fetchone()
            device_id = int(row[0]) if row else None
        if device_id is None:
            mac = normalize_mac(selector)
            if mac:
                row = self.conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
                device_id = int(row[0]) if row else None
        if device_id is None:
            device_id = self.find_device_by_address(selector)
        if device_id is None:
            raise ValueError(f"No device matches {selector!r}")
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
