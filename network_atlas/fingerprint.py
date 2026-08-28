"""Passive OS fingerprinting with p0f.

p0f infers an operating system from the shape of a TCP handshake -- window size,
option order, TTL -- so it identifies hosts that never answer an active probe and
corroborates or contradicts Nmap's guess. It reads the capture the passive
collector already takes, so this costs no extra packets.

Two limits worth stating plainly, because they decide what this is good for:

  * On a switched network or on Wi-Fi in managed mode, a host never sees other
    devices' unicast traffic at all -- it goes to the switch port or the access
    point and is never delivered here. So p0f can only fingerprint this machine
    and whatever talks *to* it. Fingerprinting the rest of the network needs a
    mirror/SPAN port, or for this host to be the gateway.
  * Even for traffic we do see, p0f's stock database holds far more client (SYN)
    signatures than server (SYN+ACK) ones, so a device we only connect *to*
    usually returns "os = ???".

What it reliably supplies for those hosts is uptime, hop distance and link type.
For passive OS identification of other devices on a switched network the useful
signal is DHCP, which is broadcast and therefore actually reaches us -- see
`classify_dhcp` below.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any


# p0f writes indented blocks: ".-[ a -> b (syn) ]-" then "| key = value" lines.
# The kind can be "syn", "syn+ack", "mtu", "uptime", "host change" -- not \w+ only.
_HEADER_RE = re.compile(r"^\.-\[\s*(\S+?)\s*->\s*(\S+?)\s*\(([^)]+)\)\s*\]-")
_FIELD_RE = re.compile(r"^\|\s*(\w+)\s*=\s*(.*?)\s*$")


def available() -> bool:
    return bool(shutil.which("p0f"))


def _address(endpoint: str) -> str | None:
    """Strip the /port suffix p0f appends and validate what remains."""
    host = endpoint.rsplit("/", 1)[0]
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return None
    return str(parsed)


def analyze(capture: Path, *, timeout: int = 180) -> dict[str, dict[str, Any]]:
    """Fingerprints keyed by IP address, merged across every block for that host."""
    binary = shutil.which("p0f")
    if not binary or not capture.exists():
        return {}
    try:
        process = subprocess.run(
            [binary, "-r", str(capture)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}

    hosts: dict[str, dict[str, Any]] = defaultdict(dict)
    subject: str | None = None

    for line in process.stdout.splitlines():
        header = _HEADER_RE.match(line)
        if header:
            source, destination, _kind = header.groups()
            # Which endpoint a block describes is stated by its own client/server
            # field; default to the source and let that field correct it.
            subject = _address(source)
            continue
        field = _FIELD_RE.match(line)
        if not field or subject is None:
            continue
        key, value = field.group(1), field.group(2)
        if key in ("client", "server"):
            resolved = _address(value)
            if resolved:
                subject = resolved
                hosts[subject]["role"] = key
            continue
        if not value or value == "???":
            continue
        if key in ("os", "link", "dist", "params", "app", "lang", "mtu", "uptime"):
            hosts[subject][key] = value
    return {address: data for address, data in hosts.items() if data}


def to_observations(fingerprints: dict[str, dict[str, Any]]) -> dict[str, list[tuple[str, str, float]]]:
    """Convert fingerprints into (key, value, confidence) observation tuples."""
    result: dict[str, list[tuple[str, str, float]]] = {}
    for address, data in fingerprints.items():
        entries: list[tuple[str, str, float]] = []
        operating_system = data.get("os")
        if operating_system and operating_system not in ("???", "unknown"):
            # A server-side fingerprint describes the remote host, so it is worth
            # more than a client-side one seen in passing.
            confidence = 0.7 if data.get("role") == "server" else 0.5
            entries.append(("p0f_os", operating_system, confidence))
        if link := data.get("link"):
            entries.append(("p0f_link", link, 0.4))
        if distance := data.get("dist"):
            entries.append(("p0f_distance", f"{distance} hop(s) away", 0.5))
        if application := data.get("app"):
            entries.append(("p0f_application", application, 0.6))
        if uptime := data.get("uptime"):
            # Uptime is one of the few things p0f reports for hosts whose OS
            # signature it cannot match, and a reboot is worth noticing.
            entries.append(("p0f_uptime", uptime, 0.6))
        if entries:
            result[address] = entries
    return result


# ---------------------------------------------------------------------------
# DHCP fingerprinting
#
# Option 60 (vendor class identifier) is sent by the client in its own DHCP
# request. DHCP is broadcast, so unlike TCP this reaches every host on the
# segment -- which makes it the one passive OS signal that survives a switch.
# Matched longest/most-specific first.
# ---------------------------------------------------------------------------
DHCP_VENDOR_CLASSES: tuple[tuple[str, str | None, str | None, str], ...] = (
    # (regex, os_family, device_type, human label)
    (r"^msft\s*5\.0|^msft\s*98|^msft$", "windows", None, "Windows DHCP client"),
    (r"android-dhcp-(\d+)", "android", "phone", "Android"),
    (r"^aaplbm|^aapl:|^apple", "apple", None, "Apple device"),
    (r"dhcpcd[-\s]", "linux", None, "Linux (dhcpcd)"),
    (r"^dhclient|isc-dhclient", "linux", None, "Linux (ISC dhclient)"),
    (r"^udhcp", "embedded", "iot", "Embedded Linux (BusyBox udhcp)"),
    (r"^linux", "linux", None, "Linux"),
    (r"^roku", None, "media", "Roku streaming device"),
    (r"lge?[_\s-]?dtv|^lg[_\s-]|webos", None, "media", "LG television"),
    (r"samsung.*(tv|dtv)|^samsungtv", None, "media", "Samsung television"),
    (r"^sony.*(bravia|tv)", None, "media", "Sony television"),
    (r"playstation|^ps[45]|sony computer entertainment", None, "game-console", "PlayStation"),
    (r"^xbox|microsoft xbox", None, "game-console", "Xbox"),
    (r"nintendo|^nds", None, "game-console", "Nintendo console"),
    (r"^hp\b|hewlett[-\s]?packard|^jetdirect", None, "printer", "HP device"),
    (r"^brother|^canon|^epson|^kyocera|^lexmark", None, "printer", "Printer"),
    (r"arubaap|cisco\s*ap|aironet|^ubnt|ubiquiti|^unifi", None, "access-point", "Access point"),
    (r"mikrotik|routeros", "network-os", "router", "MikroTik"),
    (r"docsis|^cablemodem", None, "network-device", "Cable modem"),
    (r"^dell|^lenovo|^asus\b", None, "computer", "PC vendor DHCP client"),
    (r"^espressif|^esp_|tasmota|shelly", "embedded", "iot", "ESP-based smart device"),
    (r"^huawei|^xiaomi|^oppo|^vivo", None, "phone", "Mobile vendor"),
)

_COMPILED_VENDOR_CLASSES = tuple(
    (re.compile(pattern, re.IGNORECASE), family, kind, label)
    for pattern, family, kind, label in DHCP_VENDOR_CLASSES
)


def classify_dhcp(vendor_class: str | None) -> dict[str, Any] | None:
    """Interpret a DHCP vendor class identifier.

    Returns the OS family, a device type where the string implies one, and a
    readable label -- or None when the string matches nothing known, which is
    common and not an error.
    """
    if not vendor_class:
        return None
    text = vendor_class.strip()
    if not text:
        return None
    for pattern, family, kind, label in _COMPILED_VENDOR_CLASSES:
        if pattern.search(text):
            return {
                "os_family": family,
                "device_type": kind,
                "label": label,
                "vendor_class": text[:160],
            }
    return None

# DHCP option 55, the parameter request list. A client's DHCP implementation
# decides which options it asks for and in which order, so the sequence is a
# fingerprint of the OS rather than of anything an owner configured. It is the
# only OS signal available for a device that sends no vendor class, which covers
# most phones and many appliances.
#
# Matching is exact and the table is deliberately short. A prefix or subset match
# would cover more devices but would also confidently mislabel them, and these
# lists overlap heavily between OS families: the shared opening "1,3,6,15" says
# nothing on its own. A signature absent from this table yields no claim.
DHCP_PARAM_LISTS: tuple[tuple[str, str | None, str | None, str], ...] = (
    # (option 55 sequence, os_family, device_type, human label)
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "windows", "computer", "Windows"),
    ("1,15,3,6,44,46,47,31,33,121,249,43", "windows", "computer", "Windows"),
    ("1,15,3,6,44,46,47,31,33,121,249,43,252", "windows", "computer", "Windows"),
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252,12", "windows", "computer", "Windows"),
    ("1,121,3,6,15,119,252,95,44,46", "apple", None, "macOS"),
    ("1,121,3,6,15,119,252,95,44,46,101", "apple", None, "macOS"),
    ("1,3,6,15,119,95,252,44,46,47", "apple", None, "macOS"),
    ("1,121,3,6,15,119,252", "apple", "phone", "iOS or iPadOS"),
    ("1,3,6,15,119,252", "apple", "phone", "iOS or iPadOS"),
    ("1,3,6,15,26,28,51,58,59,43", "android", "phone", "Android"),
    ("1,3,6,15,26,28,51,58,59,43,114", "android", "phone", "Android"),
    ("1,3,6,15,26,28,51,58,59", "android", "phone", "Android"),
    ("1,28,2,3,15,6,119,12,44,47,26,121,42", "linux", None, "Linux (ISC dhclient)"),
    ("1,2,6,12,15,26,28,121,3,33,40,41,42,119", "linux", None, "Linux (systemd-networkd)"),
    ("1,3,6,12,15,26,28,42,51,54,58,59,119", "linux", None, "Linux (NetworkManager)"),
    ("1,3,6,12,15,17,23,28,29,31,33,40,41,42", "linux", None, "Linux (dhcpcd)"),
    ("1,3,6,12,15,28,42,43,66,67", "embedded", "iot", "Embedded Linux (BusyBox udhcp)"),
    ("1,3,6,12,15,28,51,58,59", "embedded", "iot", "Embedded device"),
)

_PARAM_LIST_INDEX: dict[str, tuple[str | None, str | None, str]] = {
    sequence: (family, kind, label)
    for sequence, family, kind, label in DHCP_PARAM_LISTS
}


def classify_param_list(param_list: str | None) -> dict[str, Any] | None:
    """Interpret a DHCP option 55 sequence.

    Returns None for any sequence not in the table, which is the common case and
    not an error.
    """
    if not param_list:
        return None
    sequence = ",".join(
        part.strip() for part in param_list.split(",") if part.strip().isdigit()
    )
    match = _PARAM_LIST_INDEX.get(sequence)
    if not match:
        return None
    family, kind, label = match
    return {
        "os_family": family,
        "device_type": kind,
        "label": label,
        "param_list": sequence,
    }
