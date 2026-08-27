from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .db import AtlasDB


TYPE_ALIASES = {
    "router": "router",
    "switch": "switch",
    "bridge": "switch",
    "broadband router": "router",
    "firewall": "firewall",
    "wap": "access-point",
    "wireless access point": "access-point",
    "printer": "printer",
    "print server": "printer",
    "phone": "phone",
    "voip phone": "phone",
    "pbx": "phone",
    "media device": "media",
    "game console": "game-console",
    "storage-misc": "storage",
    "storage": "storage",
    "webcam": "camera",
    "camera": "camera",
    "general purpose": "computer",
}

NETWORK_VENDORS = (
    "cisco", "juniper", "aruba", "ubiquiti", "mikrotik", "fortinet", "netgear",
    "extreme networks", "ruckus", "arista", "tp-link", "arcadyan",
)
PRINTER_VENDORS = ("brother", "epson", "lexmark", "kyocera", "ricoh", "xerox", "canon")
PHONE_VENDORS = ("yealink", "polycom", "grandstream", "snom", "fanvil")


def classify(data: dict[str, Any]) -> tuple[str, float, list[str]]:
    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)

    def vote(kind: str, weight: float, reason: str) -> None:
        scores[kind] += weight
        reasons[kind].append(reason)

    nmap_type = (data.get("nmap_device_type") or "").lower()
    if nmap_type in TYPE_ALIASES:
        mapped = TYPE_ALIASES[nmap_type]
        accuracy = max(0.25, min(float(data.get("os_accuracy") or 50) / 100, 1.0))
        vote(mapped, 0.72 * accuracy, f"Nmap classified it as {nmap_type} ({accuracy:.0%})")

    os_name = (data.get("os_name") or "").lower()
    if "android" in os_name or "iphone" in os_name or "ios " in os_name:
        vote("phone", 0.72, f"OS resembles a mobile platform: {data.get('os_name')}")
    elif any(term in os_name for term in ("windows", "mac os", "linux")):
        vote("computer", 0.14, f"General-purpose operating system: {data.get('os_name')}")

    hostname = (data.get("hostname") or "").lower().split(".", 1)[0]
    server_named = any(
        token in hostname.replace("_", "-").split("-")
        for token in ("server", "srv", "hypervisor")
    )
    if server_named:
        vote("server", 0.82, f"Server role indicated by hostname: {data.get('hostname')}")

    service_ports = {int(service.get("port") or 0) for service in data.get("services", [])}
    if server_named and 22 in service_ports and service_ports.intersection({80, 443, 8080, 8443}):
        vote("server", 0.38, "Server-like hostname corroborated by SSH and a web service")

    vendor = (data.get("vendor") or "").lower()
    if any(name in vendor for name in PRINTER_VENDORS):
        vote("printer", 0.35, f"MAC vendor commonly makes printers: {data.get('vendor')}")
    if any(name in vendor for name in NETWORK_VENDORS):
        vote("network", 0.25, f"MAC vendor commonly makes network equipment: {data.get('vendor')}")
    if any(name in vendor for name in PHONE_VENDORS):
        vote("phone", 0.88, f"MAC vendor commonly makes VoIP phones: {data.get('vendor')}")
    if "raspberry pi" in vendor:
        vote("computer", 0.20, "Raspberry Pi MAC allocation")
    if any(name in vendor for name in NETWORK_VENDORS) and service_ports.intersection({22, 53, 1900, 49152}) and service_ports.intersection({80, 443, 8080}):
        vote("network", 0.68, "Network-equipment vendor corroborated by management services")
    if "openwrt" in os_name or "routeros" in os_name:
        vote("router", 0.96, f"Network operating system: {data.get('os_name')}")
    if {8008, 8009}.issubset(service_ports):
        vote("media", 1.65, "Google Cast service pair on ports 8008 and 8009")

    for service in data.get("services", []):
        port = int(service.get("port") or 0)
        name = (service.get("name") or "").lower()
        product = " ".join(
            str(service.get(key) or "") for key in ("product", "extra", "cpe")
        ).lower()
        signature = f"{name} {product}"
        if port in (631, 9100, 515) or any(term in signature for term in ("ipp", "jetdirect")):
            vote("printer", 0.92, f"Printing service on {service.get('protocol')}/{port}")
        if port == 3389 or "remote desktop" in signature:
            vote("computer", 0.55, "Remote Desktop service")
        if port in (445, 139):
            vote("computer", 0.30, f"SMB/NetBIOS service on port {port}")
        if port == 62078:
            vote("phone", 0.45, "Apple device synchronization service")
        if port in (5060, 5061) or "voip phone" in signature or " sipd" in signature:
            vote("phone", 0.96, f"SIP/VoIP phone service on port {port}")
        if port in (25, 53, 88, 389, 636, 3306, 5432, 6443):
            vote("server", 0.48, f"Server-oriented service on port {port}")
        if "synology" in signature or "qnap" in signature:
            vote("storage", 0.80, f"NAS product signature: {service.get('product')}")
        if any(term in signature for term in ("routeros", "cisco ios", "junos", "fortios")):
            vote("network", 0.82, f"Network operating system: {service.get('product')}")

    for observation in data.get("observations", []):
        key = (observation.get("key") or "").lower()
        value = (observation.get("value") or "").lower()
        combined = f"{key} {value}"
        if any(term in combined for term in ("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp")):
            vote("printer", 0.95, f"mDNS printing advertisement: {observation.get('value')}")
        if any(term in combined for term in ("_googlecast._tcp", "_airplay._tcp", "mediarenderer")):
            vote("media", 0.72, f"Media discovery advertisement: {observation.get('value')}")
        if "_androidtvremote" in combined:
            vote("media", 0.88, "Android TV remote service")
        if any(term in combined for term in ("_companion-link._tcp", "_apple-mobdev2._tcp")):
            vote("phone", 0.62, f"Mobile-device advertisement: {observation.get('value')}")
        if "lldp_capabilities" in key:
            if "router" in value:
                vote("router", 0.97, "LLDP router capability")
            if "bridge" in value:
                vote("switch", 0.94, "LLDP bridge capability")
        if key == "configured_role" and value == "switch":
            vote("switch", 0.99, "Device is configured as a managed switch collector target")
        if key == "snmp_sysdescr":
            if any(term in value for term in ("printer", "laserjet", "officejet")):
                vote("printer", 0.92, "SNMP system description identifies a printer")
            if any(term in value for term in ("switch", "router", "routeros", "junos", "ios xe")):
                vote("network", 0.86, "SNMP system description identifies network equipment")

    if not scores:
        return "unknown", 0.15, ["No strong classification evidence yet"]

    kind, score = max(scores.items(), key=lambda item: item[1])
    if kind == "network":
        kind = "network-device"
    confidence = min(0.99, 0.25 + score * 0.75)
    return kind, round(confidence, 3), reasons[max(scores, key=scores.get)]


def classify_all(db: AtlasDB) -> None:
    for device_id in db.device_ids():
        data = db.classification_input(device_id)
        device_type, confidence, reasons = classify(data)
        metadata = json.loads(data.get("metadata_json") or "{}")
        metadata["classification_reasons"] = reasons
        db.update_device(
            device_id,
            device_type=device_type,
            confidence=confidence,
            metadata_json=json.dumps(metadata, sort_keys=True),
        )
    db.commit()
