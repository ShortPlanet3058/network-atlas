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


def _walk(host: str, oid: str, config_dir: str, timeout: int) -> dict[str, str]:
    command = ["snmpwalk", "-On", "-t", "2", "-r", "1", host, oid]
    env = os.environ.copy()
    env["SNMPCONFPATH"] = config_dir
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    if process.returncode != 0:
        error = clean_text(process.stderr or process.stdout, 1000) or "unknown SNMP error"
        raise RuntimeError(f"SNMP walk {host} {oid} failed: {error}")
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
        )
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
            remote_id = db.ensure_device(
                mac=remote_mac,
                hostname=values.get("sys_name") or (values.get("chassis") if not remote_mac else None),
                status="online",
                seen_at=observed_at,
            )
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
        attachment_links = 0
        for suffix, bridge_port in fdb_ports.items():
            mac = _mac_from_fdb_suffix(suffix)
            if not mac:
                continue
            ifindex = bridge_to_ifindex.get(bridge_port, bridge_port)
            # MACs learned behind an LLDP uplink are not direct attachments.
            if ifindex in lldp_local_ports:
                continue
            endpoint_id = db.ensure_device(mac=mac, status="online", seen_at=observed_at)
            db.add_edge(
                switch_id,
                endpoint_id,
                "switch-port",
                source_port=if_names.get(ifindex, f"bridge-port {bridge_port}"),
                confidence=0.78,
                evidence="Bridge forwarding table; direct when the port is not an LLDP uplink",
                seen_at=observed_at,
            )
            attachment_links += 1

    db.commit()
    return {
        "lldp_links": lldp_links,
        "attachment_links": attachment_links,
        "arp_entries": arp_entries,
    }


def load_switches(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    switches = data.get("switches") if isinstance(data, dict) else None
    if not isinstance(switches, list):
        raise ValueError("SNMP configuration must contain a 'switches' list")
    return [item for item in switches if isinstance(item, dict) and item.get("enabled", True)]
