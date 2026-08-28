from __future__ import annotations

import csv
import io
import ipaddress
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .db import AtlasDB
from .util import (
    STATUS_ONLINE,
    clean_hostname,
    clean_text,
    normalize_status,
    utc_now,
)


AVAHI_ESCAPE = re.compile(r"\\(\d{3})")


def unescape_avahi(value: str) -> str:
    r"""Decode avahi's \NNN decimal escapes so names read as their real text."""
    def replace(match: re.Match[str]) -> str:
        code = int(match.group(1))
        return chr(code) if 32 <= code < 127 else " "
    return AVAHI_ESCAPE.sub(replace, value)


ARP_LINE = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*(?P<vendor>.*)$"
)
DOCTYPE_RE = re.compile(br"<!DOCTYPE\s+([^>]+)>", re.IGNORECASE)


def import_arp_scan(db: AtlasDB, content: str, *, observed_at: str | None = None) -> int:
    observed_at = observed_at or utc_now()
    count = 0
    for line in content.splitlines():
        match = ARP_LINE.match(line.strip())
        if not match:
            continue
        ip = match.group("ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        vendor = match.group("vendor").strip()
        if vendor.startswith("(") and vendor.endswith(")"):
            vendor = vendor[1:-1]
        if vendor.lower() in ("unknown", "unknown: locally administered", ""):
            vendor = ""
        device_id = db.ensure_device(
            mac=match.group("mac"), address=ip, vendor=vendor or None,
            seen_at=observed_at, source="arp",
        )
        if vendor:
            db.add_observation(device_id, "arp-scan", "oui_vendor", vendor, 0.3, observed_at)
        count += 1
    db.commit()
    return count


def _safe_xml(data: bytes) -> ET.Element:
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Refusing XML input larger than 100 MiB")
    if b"<!ENTITY" in data.upper():
        raise ValueError("Nmap XML must not contain entity declarations")
    # Nmap emits this exact, internal-subset-free declaration by default. Strip it
    # before parsing, while rejecting external/system DTDs and custom declarations.
    declarations = DOCTYPE_RE.findall(data)
    if any(declaration.strip().lower() != b"nmaprun" for declaration in declarations):
        raise ValueError("Nmap XML contains an unexpected DOCTYPE declaration")
    data = DOCTYPE_RE.sub(b"", data)
    return ET.fromstring(data)


def import_nmap_xml(
    db: AtlasDB,
    source: str | Path | bytes,
    *,
    observed_at: str | None = None,
) -> int:
    observed_at = observed_at or utc_now()
    if isinstance(source, bytes):
        data = source
    else:
        data = Path(source).read_bytes()
    root = _safe_xml(data)
    imported = 0
    skipped = 0

    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        if normalize_status(status) != STATUS_ONLINE:
            skipped += 1
            continue
        addresses = {node.get("addrtype"): node for node in host.findall("address")}
        ip_node = addresses.get("ipv4")
        if ip_node is None:
            ip_node = addresses.get("ipv6")
        if ip_node is None:
            continue
        address = ip_node.get("addr")
        if not address:
            continue
        mac_node = addresses.get("mac")
        hostname_nodes = host.findall("hostnames/hostname")
        hostname = next(
            (node.get("name") for node in hostname_nodes if node.get("type") == "user"),
            hostname_nodes[0].get("name") if hostname_nodes else None,
        )
        device_id = db.ensure_device(
            mac=mac_node.get("addr") if mac_node is not None else None,
            address=address,
            family=ip_node.get("addrtype", "ipv4"),
            hostname=clean_hostname(hostname),
            vendor=mac_node.get("vendor") if mac_node is not None else None,
            status=status,
            seen_at=observed_at,
            source="nmap",
        )

        os_matches = host.findall("os/osmatch")
        if os_matches:
            best = max(os_matches, key=lambda node: int(node.get("accuracy", "0")))
            os_class = max(
                best.findall("osclass"),
                key=lambda node: int(node.get("accuracy", "0")),
                default=None,
            )
            device_type = os_class.get("type") if os_class is not None else None
            db.update_device(
                device_id,
                os_name=clean_text(best.get("name")),
                os_accuracy=int(best.get("accuracy", "0")),
                nmap_device_type=clean_text(device_type),
            )
            db.add_observation(
                device_id,
                "nmap",
                "os_match",
                f"{best.get('name')} ({best.get('accuracy', '0')}%)",
                int(best.get("accuracy", "0")) / 100,
                observed_at,
            )

        for port_node in host.findall("ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue
            service = port_node.find("service")
            cpe_node = service.find("cpe") if service is not None else None
            db.add_service(
                device_id,
                port_node.get("protocol", "tcp"),
                int(port_node.get("portid", "0")),
                name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
                extra=service.get("extrainfo") if service is not None else None,
                cpe=cpe_node.text if cpe_node is not None else None,
                state=state,
                seen_at=observed_at,
            )

        path_ids: list[int] = []
        for hop in host.findall("trace/hop"):
            hop_ip = hop.get("ipaddr")
            if not hop_ip:
                continue
            hop_id = db.ensure_device(
                address=hop_ip,
                family="ipv6" if ":" in hop_ip else "ipv4",
                hostname=clean_hostname(hop.get("host")),
                status="online",
                seen_at=observed_at,
                source="traceroute",
            )
            path_ids.append(hop_id)
        if path_ids and path_ids[-1] != device_id:
            path_ids.append(device_id)
        for source_id, target_id in zip(path_ids, path_ids[1:]):
            db.add_edge(
                source_id,
                target_id,
                "route",
                confidence=0.75,
                evidence="Nmap traceroute hop",
                seen_at=observed_at,
            )

        for script in host.findall("hostscript/script"):
            output = clean_text(script.get("output"), 2000)
            if output:
                db.add_observation(
                    device_id, "nmap-nse", script.get("id", "script"), output, 0.65, observed_at
                )
        imported += 1

    db.commit()
    return imported


def import_avahi(db: AtlasDB, content: str, *, observed_at: str | None = None) -> int:
    """Import `avahi-browse --all --resolve --terminate --parsable` output."""
    observed_at = observed_at or utc_now()
    count = 0
    reader = csv.reader(io.StringIO(content), delimiter=";", escapechar="\\")
    for fields in reader:
        if len(fields) < 9 or fields[0] != "=":
            continue
        _marker, interface, protocol, instance, service_type, domain, hostname, address, port, *txt = fields
        instance = unescape_avahi(instance)
        hostname = unescape_avahi(hostname)
        try:
            ip = ipaddress.ip_address(address)
            port_number = int(port)
        except ValueError:
            continue
        device_id = db.ensure_device(
            address=str(ip),
            family="ipv6" if ip.version == 6 else "ipv4",
            hostname=clean_hostname(hostname),
            seen_at=observed_at,
            source="mdns",
        )
        description = f"{service_type} — {instance}"
        db.add_observation(device_id, "mdns", "service", description, 0.75, observed_at)
        db.add_service(
            device_id,
            "tcp" if service_type.endswith("._tcp") else "udp",
            port_number,
            name=service_type,
            product=instance,
            extra=" ".join(txt),
            seen_at=observed_at,
        )
        count += 1
    db.commit()
    return count
