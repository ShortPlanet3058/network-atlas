"""State-transition detection and the event log.

An inventory answers "what is here now". Most of the value is in "what changed":
a device that appeared, a port that opened, an address that changed hands. Those
are transitions, so they can only be found by comparing a before and after
snapshot around each collection.
"""

from __future__ import annotations

import json
from typing import Any

from .db import AtlasDB
from .util import clean_text, utc_now


# Severity ladder used by both events and findings.
INFO, LOW, MEDIUM, HIGH = "info", "low", "medium", "high"
SEVERITY_ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}


def snapshot(db: AtlasDB) -> dict[str, Any]:
    """Capture the comparable state of the inventory.

    Deliberately narrow: only facts whose change is worth telling someone about.
    """
    devices: dict[int, dict[str, Any]] = {}
    for row in db.conn.execute(
        """SELECT id, mac, hostname, manual_name, vendor, status, device_type,
                  manual_type, approved, os_family
           FROM devices"""
    ):
        devices[int(row["id"])] = dict(row)

    addresses: dict[str, int] = {}
    for row in db.conn.execute("SELECT address, device_id FROM addresses"):
        addresses[row["address"]] = int(row["device_id"])

    services: dict[tuple[int, str, int], str] = {}
    for row in db.conn.execute(
        "SELECT device_id, protocol, port, state FROM services WHERE state LIKE 'open%'"
    ):
        services[(int(row["device_id"]), row["protocol"], int(row["port"]))] = row["state"]

    return {"devices": devices, "addresses": addresses, "services": services}


def record(
    db: AtlasDB,
    kind: str,
    title: str,
    *,
    device_id: int | None = None,
    severity: str = INFO,
    detail: str | None = None,
    metadata: dict[str, Any] | None = None,
    occurred_at: str | None = None,
) -> int:
    cursor = db.conn.execute(
        """INSERT INTO events(device_id,kind,severity,title,detail,occurred_at,metadata_json)
           VALUES(?,?,?,?,?,?,?)""",
        (
            device_id, kind, severity, clean_text(title, 200) or kind,
            clean_text(detail, 600), occurred_at or utc_now(),
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )
    return int(cursor.lastrowid)


def _name(device: dict[str, Any] | None, device_id: int) -> str:
    if not device:
        return f"Device {device_id}"
    return (
        device.get("manual_name") or device.get("hostname")
        or device.get("mac") or f"Device {device_id}"
    )


def diff(db: AtlasDB, before: dict[str, Any], *, occurred_at: str | None = None) -> list[dict[str, Any]]:
    """Compare a snapshot against current state and log every transition."""
    occurred_at = occurred_at or utc_now()
    after = snapshot(db)
    emitted: list[dict[str, Any]] = []

    def emit(kind: str, title: str, **kwargs: Any) -> None:
        record(db, kind, title, occurred_at=occurred_at, **kwargs)
        emitted.append({"kind": kind, "title": title, **kwargs})

    old_devices, new_devices = before["devices"], after["devices"]

    # -- devices appearing and leaving ---------------------------------------
    for device_id in new_devices.keys() - old_devices.keys():
        device = new_devices[device_id]
        if device["status"] != "online":
            continue
        approved = device.get("approved")
        # An unapproved arrival is the alert that matters; everything else is news.
        severity = MEDIUM if approved == 0 else INFO
        emit(
            "device-appeared",
            f"New device on the network: {_name(device, device_id)}",
            device_id=device_id,
            severity=severity,
            detail=f"Identified as {device.get('manual_type') or device.get('device_type')}"
                   + (f", vendor {device['vendor']}" if device.get("vendor") else ""),
        )

    for device_id in old_devices.keys() & new_devices.keys():
        was, now = old_devices[device_id], new_devices[device_id]
        if was["status"] == "online" and now["status"] != "online":
            emit(
                "device-left", f"{_name(now, device_id)} went offline",
                device_id=device_id, severity=INFO,
            )
        elif was["status"] != "online" and now["status"] == "online":
            emit(
                "device-returned", f"{_name(now, device_id)} came back online",
                device_id=device_id, severity=INFO,
            )
        for field, label in (("hostname", "name"), ("vendor", "vendor"), ("os_family", "system")):
            old_value, new_value = was.get(field), now.get(field)
            if old_value and new_value and old_value != new_value:
                emit(
                    f"{field}-changed",
                    f"{_name(now, device_id)} changed {label}",
                    device_id=device_id, severity=LOW,
                    detail=f"{old_value} -> {new_value}",
                )
        if was.get("device_type") != now.get("device_type") and was.get("device_type"):
            emit(
                "type-changed",
                f"{_name(now, device_id)} reclassified",
                device_id=device_id, severity=INFO,
                detail=f"{was['device_type']} -> {now['device_type']}",
            )

    # -- addresses changing hands -------------------------------------------
    # An address moving to a different hardware address is either DHCP churn or
    # someone impersonating a host. It is the single most security-relevant
    # transition this tool can observe, so it is always surfaced.
    for address, device_id in after["addresses"].items():
        previous = before["addresses"].get(address)
        if previous is None or previous == device_id:
            continue
        old_mac = (old_devices.get(previous) or {}).get("mac")
        new_mac = (new_devices.get(device_id) or {}).get("mac")
        if not old_mac or not new_mac or old_mac == new_mac:
            continue
        emit(
            "address-reassigned",
            f"{address} moved to a different device",
            device_id=device_id, severity=MEDIUM,
            detail=f"Was {old_mac}, now {new_mac}. Normal after a DHCP lease change; "
                   "unexpected otherwise.",
            metadata={"address": address, "previous_mac": old_mac, "current_mac": new_mac},
        )

    # -- services opening and closing ---------------------------------------
    for key in after["services"].keys() - before["services"].keys():
        device_id, protocol, port = key
        device = new_devices.get(device_id)
        emit(
            "port-opened",
            f"{_name(device, device_id)} opened {port}/{protocol}",
            device_id=device_id, severity=LOW,
            metadata={"port": port, "protocol": protocol},
        )
    for key in before["services"].keys() - after["services"].keys():
        device_id, protocol, port = key
        if device_id not in new_devices:
            continue
        emit(
            "port-closed",
            f"{_name(new_devices.get(device_id), device_id)} closed {port}/{protocol}",
            device_id=device_id, severity=INFO,
            metadata={"port": port, "protocol": protocol},
        )

    db.commit()
    return emitted


def promote_conflicts(db: AtlasDB, *, since: str | None = None) -> int:
    """Turn recorded address-claim conflicts into events.

    `ensure_device` refuses to hand a live address to a second claimant and files
    an observation. That observation is the raw evidence of an impersonation
    attempt or a misconfigured host, and belongs in the event log.
    """
    query = """SELECT o.device_id, o.value, o.observed_at, d.mac
               FROM observations o LEFT JOIN devices d ON d.id = o.device_id
               WHERE o.key = 'address_claim'"""
    parameters: tuple[Any, ...] = ()
    if since:
        query += " AND o.observed_at > ?"
        parameters = (since,)
    count = 0
    for row in db.conn.execute(query, parameters).fetchall():
        existing = db.conn.execute(
            """SELECT id FROM events WHERE kind='address-conflict'
               AND device_id IS ? AND occurred_at = ?""",
            (row["device_id"], row["observed_at"]),
        ).fetchone()
        if existing:
            continue
        record(
            db, "address-conflict",
            "A device claimed an address already in use",
            device_id=row["device_id"], severity=HIGH,
            detail=f"{row['value']}. This is what ARP spoofing looks like; it is also "
                   "what a statically configured duplicate address looks like.",
            occurred_at=row["observed_at"],
        )
        count += 1
    if count:
        db.commit()
    return count
