"""Evidence-weighted device classification.

Every signal casts a weighted vote for a device type and records why. The highest
total wins, and the winning reasons are stored so the viewer can always answer
"why is this a printer?". Signals that identify a device directly (its own
advertised name, an LLDP capability) outrank fuzzy inference such as an OS guess.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from .db import AtlasDB
from .fingerprint import classify_dhcp


# Nmap's own device_type vocabulary mapped onto ours.
TYPE_ALIASES = {
    "router": "router",
    "switch": "switch",
    "bridge": "switch",
    "broadband router": "router",
    "wireless broadband router": "router",
    "firewall": "firewall",
    "wap": "access-point",
    "wireless access point": "access-point",
    "printer": "printer",
    "print server": "printer",
    "phone": "phone",
    "voip phone": "phone",
    "voip adapter": "phone",
    "pbx": "phone",
    "media device": "media",
    "game console": "game-console",
    "storage-misc": "storage",
    "storage": "storage",
    "webcam": "camera",
    "camera": "camera",
    "security-misc": "camera",
    "specialized": "iot",
    "terminal": "computer",
    "general purpose": "computer",
}

# Hostnames are chosen by people and by manufacturers, which makes them the single
# most reliable signal on a real network. Patterns are matched against the short name.
HOSTNAME_RULES: tuple[tuple[str, str, float, str], ...] = (
    (r"androidtv|smarttv|firetv|appletv|webos|bravia|viera|aquos|chromecast|shield"
     r"|\btv\b|\broku\b",
     "media", 1.30, "Hostname names a television or streaming device"),
    (r"\b(printer|laserjet|officejet|deskjet|envy|kyocera|mfc|mfp)\b|\bbr[nw][0-9a-f]{6}",
     "printer", 1.35, "Hostname names a printer"),
    (r"synology|diskstation|truenas|freenas|unraid|\bqnap\b|\bnas\b|\bstorage\b",
     "storage", 1.30, "Hostname names network storage"),
    (r"\b(cam|camera|ipcam|doorbell|reolink|hikvision|dahua|unifi-?protect)\b",
     "camera", 1.20, "Hostname names a camera"),
    (r"macbook|thinkpad|elitebook|probook|latitude|optiplex|workstation"
     r"|\bimac\b|\bdesktop\b|\blaptop\b|\bpc\b|\bws\b",
     "computer", 1.15, "Hostname names a personal computer"),
    (r"iphone|ipad(?!dle)|oneplus|redmi|\bandroid\b|\bpixel\b|\bgalaxy\b|\bphone\b",
     "phone", 1.10, "Hostname names a phone or tablet"),
    (r"\b(server|srv|hypervisor|proxmox|esxi|vmhost|docker|k8s|kube)\b",
     "server", 1.05, "Hostname names a server"),
    (r"\b(router|gateway|gw|openwrt|pfsense|opnsense|edgerouter|fritz|livebox|freebox)\b",
     "router", 1.10, "Hostname names a router"),
    (r"\b(switch|sw\d+|sg\d{3,}|gs\d{3,}|catalyst|nexus)\b",
     "switch", 1.15, "Hostname names a switch"),
    (r"\b(ap|accesspoint|unifi|uap|deco|omada|eero)\b",
     "access-point", 1.05, "Hostname names an access point"),
    (r"playstation|xbox|nintendo|steamdeck|\bps[45]\b",
     "game-console", 1.30, "Hostname names a game console"),
    (r"\b(echo|alexa|nest|hue|shelly|tasmota|sonoff|tuya|esp[-_]?[0-9a-f]+|thermostat|plug)\b",
     "iot", 1.20, "Hostname names a smart-home device"),
    (r"\b(sonos|heos|homepod|speaker|receiver|denon|yamaha|bose)\b",
     "media", 1.20, "Hostname names an audio device"),
)

NETWORK_VENDORS = (
    "cisco", "juniper", "aruba", "ubiquiti", "mikrotik", "fortinet", "netgear",
    "extreme networks", "ruckus", "arista", "tp-link", "arcadyan", "zyxel",
    "d-link", "huawei technolog", "sagemcom", "technicolor", "avm", "draytek",
    "sophos", "watchguard", "palo alto", "unifi", "edgecore", "h3c", "tenda",
)
PRINTER_VENDORS = (
    "brother", "epson", "lexmark", "kyocera", "ricoh", "xerox", "canon",
    "oki data", "sharp", "konica minolta", "zebra tech",
)
PHONE_VENDORS = (
    "yealink", "polycom", "grandstream", "snom", "fanvil", "audiocodes",
    "mitel", "avaya", "gigaset", "alcatel-lucent enterprise",
)
MOBILE_VENDORS = (
    "apple", "samsung electro", "xiaomi", "oneplus", "oppo", "vivo mobile",
    "google", "motorola mobility", "sony mobile",
)
MEDIA_VENDORS = (
    "roku", "sonos", "vizio", "lg electronics", "samsung visual", "amazon techno",
    "nvidia", "bose", "denon", "harman", "sagem", "humax",
)
CAMERA_VENDORS = ("hikvision", "dahua", "axis communication", "reolink", "amcrest", "ubnt")
IOT_VENDORS = (
    "espressif", "tuya", "shelly", "sonoff", "itead", "signify", "philips lighting",
    "tado", "netatmo", "withings", "ikea of sweden",
)
COMPUTER_VENDORS = (
    "dell", "hewlett packard", "hp inc", "lenovo", "asustek", "micro-star",
    "gigabyte", "intel corporate", "realtek", "clevo", "framework", "system76",
    "supermicro", "msi",
)

# Coarse OS families, checked in order; the first match wins.
OS_FAMILIES: tuple[tuple[str, str], ...] = (
    (r"windows server", "windows-server"),
    (r"windows", "windows"),
    # Network platforms first: "Cisco IOS" must never be read as Apple iOS.
    (r"openwrt|routeros|junos|cisco ios|ios xe|ios xr|fortios|edgeos|dd-wrt|vyos",
     "network-os"),
    (r"iphone os|ipados|\bios \d|\bios\b", "apple-mobile"),
    (r"mac ?os|macos|darwin|os x", "apple"),
    (r"android", "android"),
    (r"freebsd|openbsd|netbsd", "bsd"),
    (r"linux", "linux"),
    (r"embedded|vxworks|qnx|rtos", "embedded"),
)


def _short_hostname(value: str | None) -> str:
    if not value:
        return ""
    return value.split(".", 1)[0].lower().replace("_", "-")


def os_family(os_name: str | None, extra: str = "") -> str | None:
    """Coarse OS grouping for display, tolerant of Nmap's multi-OS strings.

    `extra` is consulted only when Nmap reported no OS at all, so a passive
    fingerprint can still name the platform without overriding a real match.
    """
    haystack = (os_name or "").lower().strip() or (extra or "").lower()
    if not haystack.strip():
        return None
    # Nmap often reports "macOS ... or iOS ...". A desktop OS named first wins,
    # because the alternative reading would relabel every Mac as a phone.
    if re.search(r"mac ?os|macos|os x", haystack) and "iphone" not in haystack:
        return "apple"
    for pattern, family in OS_FAMILIES:
        if re.search(pattern, haystack):
            return family
    return None


def classify(data: dict[str, Any]) -> tuple[str, float, list[str], str | None]:
    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)

    def vote(kind: str, weight: float, reason: str) -> None:
        scores[kind] += weight
        if reason not in reasons[kind]:
            reasons[kind].append(reason)

    services = data.get("services", [])
    observations = data.get("observations", [])
    service_ports = {int(service.get("port") or 0) for service in services}
    observation_text = " ".join(
        f"{observation.get('key') or ''} {observation.get('value') or ''}"
        for observation in observations
    ).lower()

    hostname = _short_hostname(data.get("hostname") or data.get("manual_name"))
    vendor = (data.get("vendor") or "").lower()
    family = os_family(data.get("os_name"), observation_text)
    # A DHCP vendor class is the device stating its own platform, so it settles the
    # OS family when Nmap could not fingerprint one.
    os_evidence = data.get("os_name")
    if not os_evidence:
        # Nmap named no OS. The device's own DHCP vendor class can both settle the
        # family and supply a readable explanation, so reasons never read "None".
        for observation in observations:
            if (observation.get("key") or "") != "dhcp_vendor_class":
                continue
            interpreted = classify_dhcp(observation.get("value"))
            if not interpreted:
                continue
            os_evidence = f"{interpreted['label']} (from its DHCP request)"
            if family is None and interpreted["os_family"]:
                family = interpreted["os_family"]
            break
    network_os_guess: str | None = None

    # -- this machine ---------------------------------------------------------
    if data.get("is_local"):
        vote("computer", 2.0, "This is the machine running Network Atlas")

    # -- hostname -------------------------------------------------------------
    for pattern, kind, weight, reason in HOSTNAME_RULES:
        if hostname and re.search(pattern, hostname):
            vote(kind, weight, f"{reason}: {data.get('hostname')}")

    # -- operating system -----------------------------------------------------
    if family == "apple-mobile":
        vote("phone", 0.85, f"Mobile Apple OS: {os_evidence}")
    elif family == "android":
        vote("phone", 0.70, f"Android detected: {os_evidence}")
    elif family == "apple":
        vote("computer", 0.55, f"macOS detected: {os_evidence}")
    elif family == "windows-server":
        vote("server", 0.80, f"Windows Server: {os_evidence}")
    elif family == "windows":
        vote("computer", 0.45, f"Windows detected: {os_evidence}")
    elif family == "network-os":
        # Deferred: weighed at the end, once hostname, vendor and service evidence
        # have been counted. A generic Linux host is often mis-read as OpenWrt, and
        # that guess must not outrank the device's own name or manufacturer.
        network_os_guess = data.get("os_name")
    elif family in ("linux", "bsd"):
        vote("computer", 0.20, f"General-purpose operating system: {os_evidence}")
    elif family == "embedded":
        vote("iot", 0.35, f"Embedded operating system: {os_evidence}")

    nmap_type = (data.get("nmap_device_type") or "").lower()
    if nmap_type in TYPE_ALIASES:
        accuracy = max(0.25, min(float(data.get("os_accuracy") or 50) / 100, 1.0))
        # "general purpose" is Nmap's default and carries almost no information.
        base = 0.18 if nmap_type == "general purpose" else 0.70
        vote(
            TYPE_ALIASES[nmap_type], base * accuracy,
            f"Nmap classified it as {nmap_type} ({accuracy:.0%})",
        )

    # -- vendor ---------------------------------------------------------------
    vendor_rules = (
        (PRINTER_VENDORS, "printer", 0.55, "commonly makes printers"),
        (PHONE_VENDORS, "phone", 0.95, "makes VoIP phones"),
        (CAMERA_VENDORS, "camera", 0.60, "makes cameras"),
        (IOT_VENDORS, "iot", 0.65, "makes smart-home hardware"),
        (MEDIA_VENDORS, "media", 0.50, "makes media devices"),
        (COMPUTER_VENDORS, "computer", 0.30, "makes computers"),
        (MOBILE_VENDORS, "phone", 0.22, "makes mobile devices"),
        (NETWORK_VENDORS, "network-device", 0.30, "makes network equipment"),
    )
    for names, kind, weight, description in vendor_rules:
        if vendor and any(name in vendor for name in names):
            vote(kind, weight, f"MAC vendor {description}: {data.get('vendor')}")

    if vendor and any(name in vendor for name in NETWORK_VENDORS):
        if service_ports.intersection({22, 23, 53, 161, 1900}) and service_ports.intersection({80, 443, 8080, 8443}):
            vote("network-device", 0.55, "Network-equipment vendor with management services")

    if "randomized_mac" in observation_text:
        # Only phones, tablets and laptops randomize their hardware address.
        vote("phone", 0.30, "Randomized hardware address, typical of a phone or laptop")
        vote("computer", 0.15, "Randomized hardware address, typical of a phone or laptop")

    # -- services -------------------------------------------------------------
    for service in services:
        port = int(service.get("port") or 0)
        name = (service.get("name") or "").lower()
        product = " ".join(
            str(service.get(key) or "") for key in ("product", "extra", "cpe", "version")
        ).lower()
        signature = f"{name} {product}"
        if port in (631, 9100, 515) or any(term in signature for term in ("ipp", "jetdirect", "printer")):
            vote("printer", 0.95, f"Printing service on {service.get('protocol')}/{port}")
        if port == 3389 or "remote desktop" in signature:
            vote("computer", 0.55, "Remote Desktop service")
        if port in (445, 139):
            vote("computer", 0.28, f"SMB/NetBIOS service on port {port}")
        if port == 62078:
            vote("phone", 0.60, "Apple device synchronization service")
        if port in (5060, 5061) or "sip" in name:
            vote("phone", 0.90, f"SIP/VoIP service on port {port}")
        if port in (25, 88, 389, 636, 3306, 5432, 6443, 1433, 27017):
            vote("server", 0.45, f"Server-oriented service on port {port}")
        if port == 53:
            vote("server", 0.25, "DNS service")
        if port in (554, 8554) or "rtsp" in name:
            vote("camera", 0.70, f"RTSP video stream on port {port}")
        if any(term in signature for term in ("synology", "qnap", "truenas", "netatalk")):
            vote("storage", 0.85, f"NAS product signature: {service.get('product')}")
        if any(term in signature for term in ("routeros", "cisco ios", "junos", "fortios", "openwrt")):
            vote("network-device", 0.80, f"Network operating system: {service.get('product')}")
        if port in (8008, 8009, 8060, 7000) or "airplay" in signature:
            vote("media", 0.70, f"Media streaming service on port {port}")
        if port == 1883 or "mqtt" in name:
            vote("iot", 0.60, "MQTT broker or client")
    if {8008, 8009}.issubset(service_ports):
        vote("media", 1.20, "Google Cast service pair on ports 8008 and 8009")

    # -- discovery advertisements --------------------------------------------
    advertisement_rules: tuple[tuple[tuple[str, ...], str, float, str], ...] = (
        (("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp"),
         "printer", 1.00, "mDNS printing advertisement"),
        (("_googlecast._tcp", "googlecast", "airplay", "mediarenderer", "_raop._tcp",
          "_airtunes", "_spotify-connect", "_sonos", "_androidtvremote"),
         "media", 0.85, "Media streaming advertisement"),
        (("_apple-mobdev2._tcp",),
         "phone", 0.55, "iOS device-pairing advertisement"),
        (("_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_nfs._tcp"),
         "storage", 0.45, "File-sharing advertisement"),
        (("_hap._tcp", "_matter", "_homekit", "_hue._tcp", "_shelly"),
         "iot", 0.40, "Smart-home advertisement"),
        (("_rdlink._tcp", "_sftp-ssh._tcp", "_workstation._tcp", "_ssh._tcp"),
         "computer", 0.30, "Workstation advertisement"),
        (("_axis-video", "_rtsp._tcp", "_onvif"),
         "camera", 0.70, "Camera advertisement"),
    )
    for terms, kind, weight, label in advertisement_rules:
        matched = next((term for term in terms if term in observation_text), None)
        if matched:
            vote(kind, weight, f"{label}: {matched}")

    for observation in observations:
        key = (observation.get("key") or "").lower()
        value = (observation.get("value") or "").lower()
        if key == "lldp_capabilities":
            if "router" in value and "bridge" not in value:
                vote("router", 1.40, "LLDP advertises router capability")
            if "bridge" in value:
                vote("switch", 1.45, "LLDP advertises bridge (switch) capability")
            if "wlan-access-point" in value:
                vote("access-point", 1.35, "LLDP advertises wireless access point capability")
            if "telephone" in value:
                vote("phone", 1.30, "LLDP advertises telephone capability")
        elif key == "configured_role":
            vote(value if value in TYPE_ALIASES.values() else "router", 0.90,
                 f"Recorded role: {value}")
        elif key == "default_gateway":
            vote("router", 1.20, "Acts as the default gateway for this network")
        elif key == "snmp_sysdescr":
            if any(term in value for term in ("printer", "laserjet", "officejet")):
                vote("printer", 0.95, "SNMP description identifies a printer")
            if any(term in value for term in ("switch", "l2+", "l3 switch")):
                vote("switch", 0.95, "SNMP description identifies a switch")
            if any(term in value for term in ("router", "routeros", "junos", "ios xe")):
                vote("router", 0.90, "SNMP description identifies a router")
            if "access point" in value:
                vote("access-point", 0.95, "SNMP description identifies an access point")
        elif key == "dhcp_vendor_class":
            # The device names its own platform in its DHCP request. That is a
            # first-party statement, so it outranks an inferred OS fingerprint.
            interpreted = classify_dhcp(observation.get("value"))
            if interpreted:
                if interpreted["device_type"]:
                    vote(
                        interpreted["device_type"], 0.95,
                        f"DHCP request identifies it as {interpreted['label']} "
                        f"({interpreted['vendor_class']})",
                    )
                elif interpreted["os_family"] in ("windows", "linux", "apple"):
                    vote(
                        "computer", 0.50,
                        f"DHCP request identifies {interpreted['label']} "
                        f"({interpreted['vendor_class']})",
                    )
        elif key == "fingerprint":
            if "android" in value:
                vote("phone", 0.55, f"Passive fingerprint: {observation.get('value')}")
            if "msft" in value or "windows" in value:
                vote("computer", 0.45, f"Passive fingerprint: {observation.get('value')}")
            if "switch" in value or "l2+" in value:
                vote("switch", 1.10, f"Passive fingerprint: {observation.get('value')}")
            if "router advertisement" in value:
                vote("router", 0.75, "Sends IPv6 router advertisements")
            if any(term in value for term in ("tv", "webos", "roku", "bravia")):
                vote("media", 0.85, f"Passive fingerprint: {observation.get('value')}")
        elif key == "protocol_seen" and "cdp" in value:
            vote("network-device", 0.55, "Speaks Cisco Discovery Protocol")

    if network_os_guess:
        # Nmap fingerprints OpenWrt and generic Linux almost identically, so this
        # reading is only credible when the hardware also comes from a network
        # vendor, or when nothing else identifies the device at all.
        competing = max(
            (score for kind, score in scores.items() if kind != "router"), default=0.0
        )
        vendor_makes_network_gear = bool(
            vendor and any(name in vendor for name in NETWORK_VENDORS)
        )
        weight = 0.95 if (vendor_makes_network_gear or competing <= 0.0) else 0.25
        vote("router", weight, f"Network operating system: {network_os_guess}")

    if not scores:
        return "unknown", 0.15, ["No classification evidence yet"], family

    kind = max(scores.items(), key=lambda item: item[1])[0]
    score = scores[kind]
    runner_up = sorted(scores.values(), reverse=True)
    margin = score - (runner_up[1] if len(runner_up) > 1 else 0.0)
    # Confidence reflects both how much evidence exists and how clearly it beats
    # the alternative, so a close two-way split never reads as certain.
    confidence = min(0.99, 0.25 + min(score, 2.0) * 0.30 + min(margin, 1.0) * 0.15)
    return kind, round(confidence, 3), reasons[kind], family


def classify_all(db: AtlasDB) -> None:
    for device_id in db.device_ids():
        data = db.classification_input(device_id)
        device_type, confidence, why, family = classify(data)
        metadata = json.loads(data.get("metadata_json") or "{}")
        metadata["classification_reasons"] = why
        db.update_device(
            device_id,
            device_type=device_type,
            confidence=confidence,
            os_family=family,
            metadata_json=json.dumps(metadata, sort_keys=True),
        )
    db.commit()
