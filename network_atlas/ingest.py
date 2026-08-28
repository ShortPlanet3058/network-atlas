"""Write paths that turn collector output into inventory, links and topology."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from . import netinfo, oui
from .db import AtlasDB
from .util import clean_text, normalize_mac, utc_now


INFRASTRUCTURE_CAPABILITIES = {
    "router": "router",
    "bridge": "switch",
    "wlan-access-point": "access-point",
    "telephone": "phone",
}


def apply_vendors(db: AtlasDB) -> int:
    """Fill in vendors from the local IEEE registry for every device with a MAC."""
    updated = 0
    rows = db.conn.execute("SELECT id,mac,vendor FROM devices WHERE mac IS NOT NULL").fetchall()
    for row in rows:
        if row["vendor"]:
            continue
        vendor = oui.lookup(row["mac"])
        if vendor:
            db.update_device(row["id"], vendor=vendor)
            db.add_observation(row["id"], "oui", "ieee_vendor", vendor, 0.4)
            updated += 1
        elif oui.is_randomized(row["mac"]):
            # A privacy MAC is itself a signal: phones and laptops randomize, printers do not.
            db.add_observation(
                row["id"], "oui", "randomized_mac",
                "Locally administered (randomized) hardware address", 0.3,
            )
    db.commit()
    return updated


def import_neighbours(db: AtlasDB, *, observed_at: str | None = None) -> int:
    """Ingest the kernel ARP/NDP caches, including IPv6, which no other pass covers."""
    observed_at = observed_at or utc_now()
    count = 0
    for entry in netinfo.neighbours():
        # Link-local addresses identify an interface, not a routable device, but they
        # still prove the neighbour exists, so record them against the MAC.
        device_id = db.ensure_device(
            mac=entry["mac"],
            address=None if entry["link_local"] else entry["address"],
            family=entry["family"],
            status="online" if entry["reachable"] else "unknown",
            seen_at=observed_at,
            source="neighbour",
            interface=entry["interface"],
        )
        db.add_observation(
            device_id, "neighbour", f"{entry['family']}_neighbour",
            f"{entry['address']} via {entry['interface']} ({entry['state']})", 0.55, observed_at,
        )
        count += 1
    db.commit()
    return count


def register_local_host(db: AtlasDB, *, observed_at: str | None = None) -> list[int]:
    """Record this machine so the map has an explicit 'you are here'."""
    observed_at = observed_at or utc_now()
    device_ids: list[int] = []
    import socket

    hostname = clean_text(socket.gethostname(), 80)
    live = [entry for entry in netinfo.interfaces() if entry["state"] == "UP"]
    if not live:
        return []

    # This host is one device with several NICs. Keying on MAC would otherwise
    # create a separate row per interface and show the operator twice on the map.
    primary = live[0]
    device_id = db.ensure_device(
        mac=primary["mac"],
        address=primary["address"],
        family=primary["family"],
        hostname=hostname,
        status="online",
        seen_at=observed_at,
        source="local",
        is_local=True,
        interface=primary["interface"],
    )
    db.update_device(device_id, device_type="computer", confidence=0.99)
    for interface in live:
        db.conn.execute(
            """INSERT INTO addresses(device_id,address,family,first_seen,last_seen,interface)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(device_id,address) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   interface=COALESCE(excluded.interface,addresses.interface)""",
            (
                device_id, interface["address"], interface["family"],
                observed_at, observed_at, interface["interface"],
            ),
        )
        db.add_observation(
            device_id, "local", "interface",
            f"{interface['interface']} {interface['address']}/{interface['prefixlen']}"
            f"{' (wireless)' if interface['wireless'] else ''}",
            0.99, observed_at,
        )
    # Fold away any duplicate rows a previous run created from the other NICs.
    for interface in live[1:]:
        mac = interface["mac"]
        if not mac:
            continue
        duplicate = db.conn.execute(
            "SELECT id FROM devices WHERE mac=? AND id!=?", (mac, device_id)
        ).fetchone()
        if duplicate:
            db.conn.execute("DELETE FROM devices WHERE id=?", (int(duplicate["id"]),))
    device_ids.append(device_id)
    db.commit()
    return device_ids


def import_passive(db: AtlasDB, analysis: dict[str, Any], *, observed_at: str | None = None) -> dict[str, int]:
    """Ingest a passive capture: hosts, advertised names, fingerprints and LLDP links."""
    observed_at = observed_at or utc_now()
    devices = 0
    links = 0

    for host in analysis.get("hosts", []):
        addresses = [
            address for address in host.get("addresses", [])
            if not ipaddress.ip_address(address).is_link_local
        ] or [None]
        hostname = next(iter(host.get("hostnames") or []), None)
        device_id = db.ensure_device(
            mac=host.get("mac"),
            address=addresses[0],
            family="ipv6" if addresses[0] and ":" in addresses[0] else "ipv4",
            hostname=hostname,
            # Anything that transmitted during the capture window is demonstrably present,
            # even when it never answers an active probe.
            status="online",
            seen_at=observed_at,
            source="passive",
        )
        for extra in addresses[1:]:
            db.ensure_device(
                mac=host.get("mac"), address=extra,
                family="ipv6" if ":" in extra else "ipv4",
                status="online", seen_at=observed_at, source="passive",
            )
        for protocol in host.get("protocols", []):
            db.add_observation(
                device_id, "passive", "protocol_seen",
                f"Observed speaking {protocol.upper()}", 0.5, observed_at,
            )
        for name in host.get("hostnames", []):
            db.add_observation(device_id, "passive", "advertised_name", name, 0.8, observed_at)
        for service in host.get("services", []):
            db.add_observation(device_id, "passive", "advertised_service", service, 0.75, observed_at)
        for fingerprint in host.get("fingerprints", []):
            db.add_observation(device_id, "passive", "fingerprint", fingerprint, 0.85, observed_at)
        for vendor_class in host.get("vendor_classes", []):
            # DHCP is broadcast, so this reaches us even across a switch -- the one
            # passive OS signal that survives switched Ethernet and Wi-Fi.
            db.add_observation(
                device_id, "dhcp", "dhcp_vendor_class", vendor_class, 0.9, observed_at
            )
        devices += 1

    # LLDP/CDP neighbours are the only source of true physical attachment, and they
    # describe the port on the switch that this host is plugged into.
    local_ids = [
        int(row["id"]) for row in db.conn.execute("SELECT id FROM devices WHERE is_local=1")
    ]
    for link in analysis.get("links", []):
        mac = normalize_mac(link.get("mac"))
        if not mac:
            continue
        row = db.conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if not row:
            continue
        switch_id = int(row["id"])
        if name := clean_text(link.get("system_name"), 120):
            db.update_device(switch_id, hostname=name)
        capabilities = link.get("capabilities") or []
        if capabilities:
            # Recorded under one key so the classifier treats LLDP and CDP alike.
            db.add_observation(
                switch_id, link["protocol"], "lldp_capabilities",
                ", ".join(capabilities), 0.95, observed_at,
            )
        # A neighbour is only our uplink if it actually forwards traffic. IP phones
        # flood CDP announcing a telephone capability; treating that as an uplink
        # would hang this host off the phone instead of the switch it shares.
        forwards_traffic = bool(
            {"bridge", "wlan-access-point", "router"}.intersection(capabilities)
        )
        if not forwards_traffic:
            continue
        for local_id in local_ids:
            db.add_edge(
                switch_id, local_id, link["protocol"],
                source_port=link.get("port_id"),
                target_port=None,
                confidence=0.97 if link["protocol"] == "lldp" else 0.85,
                evidence=(
                    f"{link['protocol'].upper()} neighbour on "
                    f"{link.get('port_desc') or link.get('port_id') or 'unknown port'}"
                ),
                seen_at=observed_at,
            )
            links += 1
    db.commit()
    return {"devices": devices, "links": links}


def import_leases(
    db: AtlasDB, leases: list[dict[str, Any]], *, observed_at: str | None = None
) -> int:
    """Ingest DHCP leases observed on the wire.

    A lease is the router's own record of a device: hardware address, the address
    it handed out, how long for, and the name the device asked to be called. It
    needs no router integration -- any device renewing during the capture window
    supplies it.
    """
    observed_at = observed_at or utc_now()
    count = 0
    for lease in leases:
        device_id = db.ensure_device(
            mac=lease.get("mac"), address=lease.get("address"),
            hostname=lease.get("hostname"), status="online",
            seen_at=observed_at, source="dhcp",
        )
        detail = f"{lease['address']} leased to {lease['mac']}"
        if lease.get("lease_seconds"):
            hours = lease["lease_seconds"] / 3600
            detail += f" for {hours:.1f} h"
        if lease.get("server"):
            detail += f" by {lease['server']}"
        db.add_observation(device_id, "dhcp", "lease", detail, 0.95, observed_at)
        if lease.get("hostname"):
            db.add_observation(
                device_id, "dhcp", "requested_hostname", lease["hostname"], 0.9, observed_at
            )
        if lease.get("vendor_class"):
            db.add_observation(
                device_id, "dhcp", "dhcp_vendor_class", lease["vendor_class"], 0.9, observed_at
            )
        count += 1
    db.commit()
    return count


def import_flows(
    db: AtlasDB, flows: list[dict[str, Any]], *, observed_at: str | None = None
) -> int:
    """Record who connects to whom, from handshake packets only.

    This is the relationship layer the physical map cannot show: two devices on
    the same switch look identical in topology whether they talk constantly or
    never.
    """
    observed_at = observed_at or utc_now()
    local_networks = [
        ipaddress.ip_network(entry["network"]) for entry in netinfo.local_networks()
    ]

    def is_local(address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(parsed in network for network in local_networks)

    count = 0
    for flow in flows:
        source_id = db.find_device_by_address(flow["source"])
        if source_id is None:
            continue
        target_address = flow["target"]
        external = not is_local(target_address)
        target_id = None if external else db.find_device_by_address(target_address)
        if not external and target_id is None:
            continue
        flow_key = f"{source_id}|{target_id or target_address}|tcp|{flow['port']}"
        db.conn.execute(
            """INSERT INTO flows(
                   flow_key,source_device_id,target_device_id,target_address,
                   protocol,port,packets,external,first_seen,last_seen
               ) VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(flow_key) DO UPDATE SET
                   packets = flows.packets + excluded.packets,
                   last_seen = excluded.last_seen""",
            (
                flow_key, source_id, target_id,
                target_address if external else None,
                "tcp", int(flow["port"]), int(flow["count"]), int(external),
                observed_at, observed_at,
            ),
        )
        count += 1
    db.commit()
    return count


def apply_fingerprints(
    db: AtlasDB, observations: dict[str, list[tuple[str, str, float]]],
    *, observed_at: str | None = None,
) -> int:
    """Attach p0f fingerprints to the devices holding those addresses."""
    observed_at = observed_at or utc_now()
    count = 0
    for address, entries in observations.items():
        device_id = db.find_device_by_address(address)
        if device_id is None:
            continue
        for key, value, confidence in entries:
            db.add_observation(device_id, "p0f", key, value, confidence, observed_at)
            count += 1
    db.commit()
    return count


def import_wireless(
    db: AtlasDB, survey: dict[str, Any], *, observed_at: str | None = None
) -> dict[str, int]:
    """Record access points and which one each wireless client is using."""
    observed_at = observed_at or utc_now()
    access_points = 0
    associations = 0

    ap_ids: dict[str, int] = {}
    for access_point in survey.get("access_points", []):
        bssid = access_point.get("bssid")
        if not bssid:
            continue
        device_id = db.ensure_device(
            mac=bssid, hostname=access_point.get("ssid"),
            status="online", seen_at=observed_at, source="wifi",
        )
        ap_ids[bssid] = device_id
        db.update_device(
            device_id,
            wifi_bssid=bssid, wifi_ssid=access_point.get("ssid"),
            wifi_signal=access_point.get("signal"), wifi_seen_at=observed_at,
        )
        # A beaconing BSSID is an access point by definition.
        db.add_observation(
            device_id, "wifi", "lldp_capabilities", "wlan-access-point", 0.95, observed_at
        )
        detail = f"Broadcasts {access_point.get('ssid') or 'a hidden network'}"
        if access_point.get("channel"):
            detail += f" on channel {access_point['channel']}"
        if access_point.get("privacy"):
            detail += f", {access_point['privacy']}"
        db.add_observation(device_id, "wifi", "access_point", detail, 0.95, observed_at)
        if (access_point.get("privacy") or "").upper() in ("OPN", "OPEN", "WEP"):
            db.add_observation(
                device_id, "wifi", "weak_wireless_security",
                f"Network {access_point.get('ssid') or '(hidden)'} uses "
                f"{access_point['privacy']}", 0.95, observed_at,
            )
        access_points += 1

    for station in survey.get("stations", []):
        mac = station.get("mac")
        if not mac:
            continue
        device_id = db.ensure_device(
            mac=mac, status="online", seen_at=observed_at, source="wifi",
        )
        db.update_device(
            device_id,
            wifi_bssid=station.get("bssid"), wifi_signal=station.get("signal"),
            wifi_seen_at=observed_at,
        )
        bssid = station.get("bssid")
        access_point_id = ap_ids.get(bssid) if bssid else None
        if access_point_id and access_point_id != device_id:
            db.add_edge(
                access_point_id, device_id, "wireless",
                confidence=0.9,
                evidence=f"Associated over Wi-Fi, signal {station.get('signal')} dBm",
                seen_at=observed_at,
            )
            associations += 1
        if station.get("probed"):
            db.add_observation(
                device_id, "wifi", "probed_networks", station["probed"], 0.6, observed_at
            )
    db.commit()
    return {"access_points": access_points, "associations": associations}


def apply_enrichment(
    db: AtlasDB,
    *,
    reverse: dict[str, str] | None = None,
    mdns: dict[str, str] | None = None,
    netbios: Iterable[dict[str, Any]] | None = None,
    observed_at: str | None = None,
) -> int:
    """Attach resolved names, preferring sources that name the device itself."""
    observed_at = observed_at or utc_now()
    applied = 0
    # Weakest source first so stronger ones overwrite the stored hostname.
    ordered: list[tuple[str, str, dict[str, str]]] = [
        ("reverse-dns", "ptr_record", reverse or {}),
        ("mdns", "mdns_name", mdns or {}),
    ]
    for source, key, mapping in ordered:
        for address, name in mapping.items():
            device_id = db.find_device_by_address(address)
            if not device_id:
                continue
            db.update_device(device_id, hostname=name)
            db.add_observation(device_id, source, key, name, 0.8, observed_at)
            applied += 1
    for entry in netbios or []:
        device_id = None
        if entry.get("mac"):
            row = db.conn.execute(
                "SELECT id FROM devices WHERE mac=?", (normalize_mac(entry["mac"]),)
            ).fetchone()
            device_id = int(row["id"]) if row else None
        if device_id is None and entry.get("address"):
            device_id = db.find_device_by_address(entry["address"])
        if device_id is None or not entry.get("hostname"):
            continue
        db.update_device(device_id, hostname=entry["hostname"])
        db.add_observation(
            device_id, "netbios", "netbios_name", entry["hostname"], 0.85, observed_at
        )
        applied += 1
    db.commit()
    return applied


def fold_link_local_duplicates(db: AtlasDB) -> int:
    """Merge rows that only ever held an IPv6 link-local address.

    A router is reached by both an IPv4 address and an IPv6 link-local one. If the
    link-local side is recorded before its hardware address is known, it becomes a
    second row for a device already in the inventory and the map shows one router
    twice. The neighbour table resolves which device it really is.
    """
    macs = {entry["address"]: entry["mac"] for entry in netinfo.neighbours() if entry["mac"]}
    if not macs:
        return 0
    folded = 0
    candidates = [
        int(row["id"])
        for row in db.conn.execute("SELECT id FROM devices WHERE mac IS NULL")
    ]
    for device_id in candidates:
        addresses = [
            row["address"]
            for row in db.conn.execute(
                "SELECT address FROM addresses WHERE device_id=?", (device_id,)
            )
        ]
        if not addresses:
            continue
        try:
            if not all(ipaddress.ip_address(a).is_link_local for a in addresses):
                continue
        except ValueError:
            continue
        owners = {macs[address] for address in addresses if address in macs}
        if len(owners) != 1:
            continue
        owner = db.conn.execute(
            "SELECT id FROM devices WHERE mac=? AND id!=?", (owners.pop(), device_id)
        ).fetchone()
        if not owner:
            continue
        owner_id = int(owner["id"])
        db.conn.execute(
            """UPDATE OR IGNORE addresses SET device_id=? WHERE device_id=?""",
            (owner_id, device_id),
        )
        db.conn.execute(
            "UPDATE observations SET device_id=? WHERE device_id=?", (owner_id, device_id)
        )
        # Edges cascade away with the row and are rebuilt by the topology pass.
        db.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        folded += 1
    if folded:
        db.commit()
    return folded


def link_gateway(db: AtlasDB, *, observed_at: str | None = None) -> int:
    """Attach every device on a directly connected segment to its gateway.

    Nmap traceroute cannot supply this: on a flat segment every host is one hop
    away, so the hop list collapses and no edge is ever recorded. Without it the
    map has no structure at all.
    """
    observed_at = observed_at or utc_now()
    created = 0
    gateway_ids: dict[str, int] = {}
    # A router answers on both an IPv4 address and an IPv6 link-local one. Supplying
    # the hardware address from the neighbour table lets both fold into one device
    # instead of the map showing the same router twice.
    neighbour_macs = {
        entry["address"]: entry["mac"] for entry in netinfo.neighbours() if entry["mac"]
    }
    for gateway in netinfo.gateways():
        device_id = db.find_device_by_address(gateway["address"])
        if device_id is None:
            device_id = db.ensure_device(
                mac=neighbour_macs.get(gateway["address"]),
                address=gateway["address"], family=gateway["family"],
                status="online", seen_at=observed_at, source="route",
            )
        gateway_ids[gateway["address"]] = device_id
        db.add_observation(
            device_id, "route", "default_gateway",
            f"Default gateway for {', '.join(filter(None, gateway['interfaces']))}",
            0.99, observed_at,
        )
        # A default gateway routes by definition, which the classifier should weigh.
        db.add_observation(device_id, "route", "configured_role", "router", 0.9, observed_at)

    if not gateway_ids:
        return 0

    networks = [
        (ipaddress.ip_network(entry["network"]), entry)
        for entry in netinfo.local_networks()
    ]
    rows = db.conn.execute(
        """SELECT DISTINCT a.device_id, a.address FROM addresses a
           JOIN devices d ON d.id=a.device_id WHERE d.status='online'"""
    ).fetchall()
    for row in rows:
        try:
            address = ipaddress.ip_address(row["address"])
        except ValueError:
            continue
        for network, entry in networks:
            if address.version != network.version or address not in network:
                continue
            gateway_id = next(
                (
                    device_id for gateway_address, device_id in gateway_ids.items()
                    if ipaddress.ip_address(gateway_address) in network
                ),
                None,
            )
            if gateway_id is None or gateway_id == row["device_id"]:
                continue
            db.add_edge(
                gateway_id, int(row["device_id"]), "attachment",
                confidence=0.6,
                evidence=f"On {entry['network']} via {entry['interface']}",
                seen_at=observed_at,
            )
            created += 1
            break
    db.commit()
    return created
