from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import netinfo
from .db import AtlasDB
from .util import clean_text, normalize_mac, utc_now


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_CAP_ENABLED = "1.0.8802.1.1.2.1.4.1.1.12"
# The management address a neighbour publishes. The address is encoded in the OID
# index rather than the value, which is what makes crawling possible: a switch
# tells you how to reach the next switch.
LLDP_REM_MAN_ADDR_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"
BRIDGE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
BRIDGE_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# ipNetToMediaPhysAddress: the device's own ARP/neighbour table. On a router this
# is every host it has spoken to recently -- including ones that ignore our probes.
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"


SAFE_VALUE = re.compile(r"^[^\r\n]+$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.:-]+$")
SAFE_SECRET = re.compile(r"^[A-Za-z0-9!$%&()*+,./:;<=>?@\[\]^_{}~-]+$")


def _config_value(value: str, label: str) -> str:
    if not value or not SAFE_VALUE.match(value):
        raise ValueError(f"Invalid {label}")
    return value


def _secret_from_env(config: dict[str, Any], key: str) -> str | None:
    env_name = config.get(key)
    if not env_name:
        return None
    secret = os.environ.get(str(env_name))
    if not secret:
        raise ValueError(f"Environment variable {env_name} is required")
    if not SAFE_SECRET.match(secret):
        raise ValueError(
            f"{env_name} contains whitespace or Net-SNMP configuration metacharacters; use a passphrase without quotes, #, or backslashes"
        )
    return secret


def _snmp_conf(config: dict[str, Any]) -> str:
    version = str(config.get("version", "3"))
    lines = [f"defVersion {_config_value(version, 'SNMP version')}"]
    if version == "3":
        lines.extend(
            [
                f"defSecurityName {_config_value(str(config.get('username', '')), 'SNMP username')}",
                f"defSecurityLevel {_config_value(str(config.get('security_level', 'authPriv')), 'security level')}",
            ]
        )
        auth = _secret_from_env(config, "auth_password_env")
        privacy = _secret_from_env(config, "privacy_password_env")
        if auth:
            lines.append(f"defAuthPassphrase {auth}")
            lines.append(f"defAuthType {_config_value(str(config.get('auth_protocol', 'SHA')), 'auth protocol')}")
        if privacy:
            lines.append(f"defPrivPassphrase {privacy}")
            lines.append(f"defPrivType {_config_value(str(config.get('privacy_protocol', 'AES')), 'privacy protocol')}")
    elif version in ("1", "2c"):
        community = _secret_from_env(config, "community_env")
        if not community:
            raise ValueError("SNMPv1/v2c requires community_env")
        lines.append(f"defCommunity {community}")
    else:
        raise ValueError(f"Unsupported SNMP version: {version}")
    return "\n".join(lines) + "\n"


def _parse_value(value: str) -> str:
    if ": " in value:
        _kind, value = value.split(": ", 1)
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return clean_text(value, 2000) or ""


def parse_walk(content: str, base_oid: str) -> dict[str, str]:
    base = base_oid.lstrip(".")
    results: dict[str, str] = {}
    for line in content.splitlines():
        if " = " not in line:
            continue
        oid, value = line.split(" = ", 1)
        oid = oid.lstrip(".")
        if oid == base:
            suffix = ""
        elif oid.startswith(base + "."):
            suffix = oid[len(base) + 1 :]
        else:
            continue
        parsed = _parse_value(value)
        if parsed and not parsed.startswith("No Such"):
            results[suffix] = parsed
    return results


# Lines Net-SNMP prints when no MIB modules are installed. Every OID here is
# numeric, so the modules are never needed -- but the warnings are verbose enough
# to bury the line that says what actually went wrong.
_MIB_NOISE = ("cannot find module", "mib search path", "at line", "unlinked oid")


def _snmp_error(stderr: str, stdout: str) -> str:
    """Pick the line that explains the failure.

    Net-SNMP reports a timeout or an authentication failure in one short line,
    preceded by however many MIB warnings the installation happens to produce.
    Reporting the first 300 characters shows the noise and hides the cause.
    """
    for stream in (stderr, stdout):
        for line in (stream or "").splitlines():
            line = line.strip()
            if not line or any(noise in line.lower() for noise in _MIB_NOISE):
                continue
            return clean_text(line, 300) or line[:300]
    return "no response"


def _walk(host: str, oid: str, config_dir: str, timeout: int) -> dict[str, str]:
    # -m '' disables MIB loading: the OIDs are numeric, and without this every
    # walk emits a wall of "Cannot find module" warnings on a stock install.
    command = ["snmpwalk", "-On", "-m", "", "-t", "2", "-r", "1", host, oid]
    env = os.environ.copy()
    env["SNMPCONFPATH"] = config_dir
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"{host} did not answer within {timeout}s. Check that SNMP is enabled "
            "and that this machine is permitted to query it."
        ) from None
    if process.returncode != 0:
        raise RuntimeError(
            f"{host} rejected the query: {_snmp_error(process.stderr, process.stdout)}"
        )
    return parse_walk(process.stdout, oid)


def _first(values: dict[str, str]) -> str | None:
    return next(iter(values.values()), None)


def _mac_from_chassis(value: str) -> str | None:
    hex_octets = re.findall(r"[0-9A-Fa-f]{2}", value)
    if len(hex_octets) == 6:
        return normalize_mac(":".join(hex_octets))
    return normalize_mac(value)


def _mac_from_fdb_suffix(suffix: str) -> str | None:
    try:
        octets = [int(part) for part in suffix.split(".")[-6:]]
    except ValueError:
        return None
    if len(octets) != 6 or any(value < 0 or value > 255 for value in octets):
        return None
    if octets[0] & 1:  # multicast/broadcast
        return None
    return ":".join(f"{value:02x}" for value in octets)


def _address_from_arp_suffix(suffix: str) -> str | None:
    """The last four sub-identifiers of an ipNetToMedia OID are the IPv4 address."""
    parts = suffix.split(".")
    if len(parts) < 5:
        return None
    try:
        octets = [int(part) for part in parts[-4:]]
    except ValueError:
        return None
    if any(value < 0 or value > 255 for value in octets):
        return None
    candidate = ".".join(str(value) for value in octets)
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return None
    return candidate


def _management_address_from_suffix(suffix: str) -> str | None:
    """Decode the management address held in an lldpRemManAddrTable index.

    The index is timeMark.localPort.remIndex.addrSubtype.addrLen.address-bytes,
    where subtype 1 is IPv4 and 2 is IPv6. Anything else is a form of address this
    cannot reach, so it is ignored rather than guessed at.
    """
    parts = suffix.split(".")
    if len(parts) < 6:
        return None
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return None
    subtype, length = numbers[3], numbers[4]
    octets = numbers[5:5 + length]
    if len(octets) != length or any(value < 0 or value > 255 for value in octets):
        return None
    try:
        if subtype == 1 and length == 4:
            parsed = ipaddress.ip_address(".".join(str(value) for value in octets))
        elif subtype == 2 and length == 16:
            parsed = ipaddress.ip_address(bytes(octets))
        else:
            return None
    except ValueError:
        return None
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return None
    return str(parsed)


def _forwards_traffic(capabilities: str | None) -> bool:
    """Whether an LLDP capability string describes something worth crawling.

    Only a bridge or a router forwards other devices' traffic and therefore has a
    forwarding table worth reading. A phone or an access point that merely speaks
    LLDP does not.
    """
    text = (capabilities or "").lower()
    return any(word in text for word in ("bridge", "router", "switch"))


# A port carrying more than this share of everything known is reaching the rest
# of the network rather than fanning out a desk. Deliberately generous: a real
# unmanaged switch rarely has more than a handful of devices behind it, while an
# uplink carries almost everything.
_UPLINK_SHARE = 0.5
_UPLINK_MINIMUM = 6


def _uplink_ports(db: AtlasDB, by_port: dict[str, list[str]]) -> set[str]:
    """Identify ports that lead toward the rest of the network.

    Without this every address the switch has ever learned hangs off whichever
    port faces the gateway, which draws the entire network as children of one
    switch port. The reliable tell is the gateway's own hardware address: traffic
    to the gateway leaves through the uplink by definition.
    """
    gateway_macs: set[str] = set()
    for gateway in netinfo.gateways():
        device_id = db.find_device_by_address(gateway.get("address", ""))
        if not device_id:
            continue
        row = db.conn.execute(
            "SELECT mac FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        if row and row["mac"]:
            gateway_macs.add(str(row["mac"]).lower())

    total = sum(len(macs) for macs in by_port.values())
    uplinks: set[str] = set()
    for ifindex, macs in by_port.items():
        if gateway_macs & {mac.lower() for mac in macs}:
            uplinks.add(ifindex)
        elif len(macs) >= _UPLINK_MINIMUM and total and len(macs) > total * _UPLINK_SHARE:
            uplinks.add(ifindex)
    return uplinks


def import_arp_table(
    db: AtlasDB, host: str, config_dir: str, timeout: int, observed_at: str
) -> int:
    """Import the queried device's ARP table.

    A router's ARP table is the closest portable equivalent of its DHCP lease
    list: every address it has resolved recently, with the hardware address behind
    it. Devices that firewall themselves still appear, because the router had to
    resolve them to route their traffic.
    """
    try:
        entries = _walk(host, IP_NET_TO_MEDIA_PHYS, config_dir, timeout)
    except RuntimeError:
        # Not every agent exposes the table; that is not a failure of the walk.
        return 0
    imported = 0
    for suffix, value in entries.items():
        address = _address_from_arp_suffix(suffix)
        mac = _mac_from_chassis(value)
        if not address or not mac:
            continue
        device_id = db.ensure_device(
            mac=mac, address=address, status="online",
            seen_at=observed_at, source="snmp-arp",
        )
        db.add_observation(
            device_id, "snmp", "router_arp_entry",
            f"{address} resolved to {mac} by {host}", 0.85, observed_at,
        )
        imported += 1
    db.commit()
    return imported


def collect_switch(db: AtlasDB, config: dict[str, Any], *, timeout: int = 30) -> dict[str, int]:
    host = str(config.get("host", ""))
    if host.startswith("-") or not SAFE_HOST.match(host):
        raise ValueError(f"Invalid switch host: {host!r}")
    try:
        ipaddress.ip_address(host)
        address = host
        hostname = None
    except ValueError:
        address = None
        hostname = host

    observed_at = utc_now()
    with tempfile.TemporaryDirectory(prefix="network-atlas-snmp-") as temp_dir:
        conf_path = Path(temp_dir) / "snmp.conf"
        conf_path.write_text(_snmp_conf(config), encoding="utf-8")
        conf_path.chmod(0o600)

        sys_descr = _first(_walk(host, SYS_DESCR, temp_dir, timeout))
        sys_name = _first(_walk(host, SYS_NAME, temp_dir, timeout)) or hostname
        switch_id = db.ensure_device(
            address=address,
            hostname=sys_name,
            status="online",
            seen_at=observed_at,
            name_source="snmp",
        )
        if sys_name:
            db.add_observation(switch_id, "snmp", "snmp_sysname", sys_name, 0.9, observed_at)
        db.add_observation(
            switch_id, "configuration", "configured_role", "switch", 0.99, observed_at
        )
        if sys_descr:
            db.add_observation(switch_id, "snmp", "snmp_sysdescr", sys_descr, 0.9, observed_at)

        arp_entries = import_arp_table(db, host, temp_dir, timeout, observed_at)

        local_ids = _walk(host, LLDP_LOC_PORT_ID, temp_dir, timeout)
        local_desc = _walk(host, LLDP_LOC_PORT_DESC, temp_dir, timeout)
        remote_columns = {
            "chassis": _walk(host, LLDP_REM_CHASSIS, temp_dir, timeout),
            "port_id": _walk(host, LLDP_REM_PORT_ID, temp_dir, timeout),
            "port_desc": _walk(host, LLDP_REM_PORT_DESC, temp_dir, timeout),
            "sys_name": _walk(host, LLDP_REM_SYS_NAME, temp_dir, timeout),
            "sys_desc": _walk(host, LLDP_REM_SYS_DESC, temp_dir, timeout),
            "capabilities": _walk(host, LLDP_REM_CAP_ENABLED, temp_dir, timeout),
        }
        # Keyed on localPort.remIndex so a management address can be matched back
        # to the neighbour that published it.
        man_addr_by_neighbour: dict[str, str] = {}
        for suffix in _walk(host, LLDP_REM_MAN_ADDR_SUBTYPE, temp_dir, timeout):
            address = _management_address_from_suffix(suffix)
            if not address:
                continue
            parts = suffix.split(".")
            if len(parts) >= 3:
                man_addr_by_neighbour.setdefault(".".join(parts[1:3]), address)
        management: dict[str, dict[str, Any]] = {}
        remote_keys = set().union(*(column.keys() for column in remote_columns.values()))
        lldp_local_ports: set[str] = set()
        lldp_links = 0
        for key in remote_keys:
            parts = key.split(".")
            if len(parts) < 3:
                continue
            local_port_number = parts[-2]
            lldp_local_ports.add(local_port_number)
            values = {name: column.get(key) for name, column in remote_columns.items()}
            remote_mac = _mac_from_chassis(values.get("chassis") or "")
            remote_address = man_addr_by_neighbour.get(".".join(parts[-2:]))
            remote_id = db.ensure_device(
                mac=remote_mac,
                address=remote_address,
                family="ipv6" if remote_address and ":" in remote_address else "ipv4",
                hostname=values.get("sys_name") or (values.get("chassis") if not remote_mac else None),
                status="online",
                seen_at=observed_at,
                name_source="snmp" if values.get("sys_name") else None,
            )
            if remote_address and _forwards_traffic(values.get("capabilities")):
                management[remote_address] = {
                    "sys_name": values.get("sys_name"),
                    "capabilities": values.get("capabilities"),
                }
            if values.get("sys_desc"):
                db.add_observation(
                    remote_id, "lldp", "snmp_sysdescr", values["sys_desc"], 0.85, observed_at
                )
            if values.get("capabilities"):
                db.add_observation(
                    remote_id,
                    "lldp",
                    "lldp_capabilities",
                    values["capabilities"],
                    0.95,
                    observed_at,
                )
            source_port = local_desc.get(local_port_number) or local_ids.get(local_port_number) or local_port_number
            target_port = values.get("port_desc") or values.get("port_id")
            db.add_edge(
                switch_id,
                remote_id,
                "lldp",
                source_port=source_port,
                target_port=target_port,
                confidence=0.98,
                evidence="LLDP neighbor table via read-only SNMP",
                seen_at=observed_at,
            )
            lldp_links += 1

        bridge_to_ifindex = _walk(host, BRIDGE_PORT_IFINDEX, temp_dir, timeout)
        if_names = _walk(host, IF_NAME, temp_dir, timeout)
        if not if_names:
            if_names = _walk(host, IF_DESCR, temp_dir, timeout)
        fdb_ports = _walk(host, BRIDGE_FDB_PORT, temp_dir, timeout)

        # Group the forwarding table by port before drawing anything. A port is
        # only a direct attachment when exactly one device is behind it; several
        # devices sharing a port means something is fanning it out.
        by_port: dict[str, list[str]] = defaultdict(list)
        port_labels: dict[str, str] = {}
        for suffix, bridge_port in fdb_ports.items():
            mac = _mac_from_fdb_suffix(suffix)
            if not mac:
                continue
            ifindex = bridge_to_ifindex.get(bridge_port, bridge_port)
            # MACs learned behind an LLDP uplink are not direct attachments.
            if ifindex in lldp_local_ports:
                continue
            by_port[ifindex].append(mac)
            port_labels[ifindex] = if_names.get(ifindex, f"bridge-port {bridge_port}")

        uplinks = _uplink_ports(db, by_port)
        attachment_links = 0
        inferred_switches = 0
        for ifindex, macs in by_port.items():
            label = port_labels[ifindex]
            if ifindex in uplinks:
                # The rest of the network is reached through here, not attached to
                # it. Drawing an edge per MAC would hang the whole network off one
                # port of one switch.
                db.add_observation(
                    switch_id, "snmp", "switch_uplink_port",
                    f"{label} carries {len(macs)} address(es) toward the rest of the network",
                    0.8, observed_at,
                )
                continue
            if len(macs) == 1:
                endpoint_id = db.ensure_device(
                    mac=macs[0], status="online", seen_at=observed_at
                )
                db.add_edge(
                    switch_id, endpoint_id, "switch-port",
                    source_port=label,
                    confidence=0.78,
                    evidence="Bridge forwarding table; the only address on this port",
                    seen_at=observed_at,
                )
                attachment_links += 1
                continue

            # Several devices on one port that is not an uplink. An unmanaged
            # switch answers nothing and appears in no scan, so this is the only
            # evidence it exists -- which is why a network can look like it has one
            # switch when it has three.
            hidden_id = db.ensure_inferred_device(
                f"unmanaged-switch:{switch_id}:{ifindex}",
                hostname=f"Unmanaged switch on {label}",
                device_type="switch",
                confidence=0.6,
                seen_at=observed_at,
            )
            db.add_observation(
                hidden_id, "configuration", "configured_role", "switch", 0.9, observed_at
            )
            db.add_observation(
                hidden_id, "snmp", "inferred_from",
                f"{len(macs)} addresses share port {label} on {sys_name or host} "
                f"with no LLDP neighbour, so an unmanaged switch or hub sits there",
                0.75, observed_at,
            )
            db.add_edge(
                switch_id, hidden_id, "switch-port",
                source_port=label,
                confidence=0.7,
                evidence=f"{len(macs)} addresses share this port and none announces itself",
                seen_at=observed_at,
            )
            inferred_switches += 1
            for mac in macs:
                endpoint_id = db.ensure_device(
                    mac=mac, status="online", seen_at=observed_at
                )
                db.add_edge(
                    hidden_id, endpoint_id, "inferred-attachment",
                    confidence=0.55,
                    evidence=(
                        f"Reached through port {label} of {sys_name or host}; "
                        "which of the hidden switch's ports is unknowable"
                    ),
                    seen_at=observed_at,
                )
                attachment_links += 1

        neighbours = [
            {
                "address": address,
                "sys_name": info.get("sys_name"),
                "capabilities": info.get("capabilities"),
            }
            for address, info in management.items()
        ]

    db.commit()
    return {
        "host": host,
        "sys_name": sys_name,
        "lldp_links": lldp_links,
        "attachment_links": attachment_links,
        "inferred_switches": inferred_switches,
        "arp_entries": arp_entries,
        "neighbours": neighbours,
    }


def load_switches(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    switches = data.get("switches") if isinstance(data, dict) else None
    if not isinstance(switches, list):
        raise ValueError("SNMP configuration must contain a 'switches' list")
    return [item for item in switches if isinstance(item, dict) and item.get("enabled", True)]

# How far a crawl will follow LLDP neighbours from a configured switch. Three hops
# covers any small or mid-sized site; the limit exists so a misreported neighbour
# cannot start an unbounded walk.
MAX_CRAWL_DEPTH = 3
MAX_CRAWL_HOSTS = 32


def _local_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for entry in netinfo.local_networks():
        try:
            networks.append(ipaddress.ip_network(entry["network"], strict=False))
        except (ValueError, KeyError):
            continue
    return networks


def _is_reachable_locally(address: str) -> bool:
    """Whether an address is on a network this machine is actually attached to.

    A crawl follows addresses that devices report, not addresses a person chose,
    so it must not leave the networks the operator is administering. A neighbour
    advertising a management address elsewhere is recorded but never queried.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return False
    return any(parsed in network for network in _local_networks())


def crawl_switches(
    db: AtlasDB,
    switches: list[dict[str, Any]],
    *,
    timeout: int = 30,
    max_depth: int = MAX_CRAWL_DEPTH,
) -> dict[str, Any]:
    """Walk the configured switches, then the switches they can see.

    LLDP is a single-hop protocol: a switch only ever hears its immediate
    neighbours, which is why listening passively finds exactly one switch -- the
    one this machine is plugged into. Asking each switch for its own neighbour
    table is what turns that into a fabric, because every switch knows the ones
    next to it.

    Credentials are reused from the switch that led to a neighbour, since a site
    almost always shares one read-only community or user. A neighbour with its own
    entry in the configuration is queried with that instead.
    """
    configured: dict[str, dict[str, Any]] = {}
    queue: list[tuple[dict[str, Any], int]] = []
    for config in switches:
        host = str(config.get("host", ""))
        if not host:
            continue
        configured[host] = config
        queue.append((config, 0))

    visited: set[str] = set()
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    while queue:
        if len(visited) >= MAX_CRAWL_HOSTS:
            skipped.append({
                "host": "(remaining)",
                "reason": f"crawl limit of {MAX_CRAWL_HOSTS} devices reached",
            })
            break
        config, depth = queue.pop(0)
        host = str(config.get("host", ""))
        if host in visited:
            continue
        visited.add(host)
        try:
            result = collect_switch(db, config, timeout=timeout)
        except (ValueError, RuntimeError, OSError) as exc:
            failures.append({"host": host, "error": clean_text(str(exc), 300) or "failed"})
            continue
        result["depth"] = depth
        results.append(result)
        if depth >= max_depth:
            continue
        for neighbour in result.get("neighbours", []):
            address = neighbour.get("address")
            if not address or address in visited:
                continue
            if address in configured:
                queue.append((configured[address], depth + 1))
                continue
            if not _is_reachable_locally(address):
                skipped.append({
                    "host": address,
                    "reason": "not on a network this machine is attached to",
                })
                visited.add(address)
                continue
            # Inherit the credentials that reached the switch which named it.
            inherited = dict(config)
            inherited["host"] = address
            queue.append((inherited, depth + 1))

    return {
        "queried": [
            {
                "host": result["host"],
                "sys_name": result.get("sys_name"),
                "depth": result["depth"],
                "lldp_links": result["lldp_links"],
                "attachment_links": result["attachment_links"],
                "inferred_switches": result["inferred_switches"],
            }
            for result in results
        ],
        "switches_reached": len(results),
        "inferred_switches": sum(r["inferred_switches"] for r in results),
        "lldp_links": sum(r["lldp_links"] for r in results),
        "attachment_links": sum(r["attachment_links"] for r in results),
        "arp_entries": sum(r["arp_entries"] for r in results),
        "unreachable": failures,
        "skipped": skipped,
    }

