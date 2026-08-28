from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from functools import lru_cache


MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Placeholders that tools emit when a hardware address is unknown.
_INVALID_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12:
        return None
    mac = ":".join(compact[i : i + 2] for i in range(0, 12, 2)).lower()
    if not MAC_RE.match(mac) or mac in _INVALID_MACS:
        return None
    # Multicast bit set in the first octet is never a real host address.
    if int(mac[:2], 16) & 0x01:
        return None
    return mac


def validate_target(
    value: str,
    *,
    allow_public: bool = False,
    allow_large: bool = False,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR target: {value}") from exc

    permitted = network.is_private or network.is_link_local
    if not permitted and not allow_public:
        raise ValueError(
            f"Refusing public target {network}; use --allow-public only for a range you administer"
        )
    if network.num_addresses > 4096 and not allow_large:
        raise ValueError(
            f"Target {network} contains {network.num_addresses:,} addresses; use --allow-large to confirm"
        )
    return network


def clean_text(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:limit] or None


# Status vocabulary: collectors report Nmap's raw states, which must be folded into
# a single set the viewer can rely on for filtering and display.
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_UNKNOWN = "unknown"
_STATUS_MAP = {
    "up": STATUS_ONLINE,
    "online": STATUS_ONLINE,
    "reachable": STATUS_ONLINE,
    "down": STATUS_OFFLINE,
    "offline": STATUS_OFFLINE,
    "unreachable": STATUS_OFFLINE,
}


def normalize_status(value: str | None) -> str:
    if not value:
        return STATUS_UNKNOWN
    return _STATUS_MAP.get(value.strip().lower(), STATUS_UNKNOWN)


@lru_cache(maxsize=1)
def nmap_privileged() -> bool:
    """Whether Nmap can send raw packets here, by euid or by file capabilities.

    Kali grants `cap_net_raw,cap_net_admin` to /usr/lib/nmap/nmap, so an
    unprivileged viewer can still run -sS/-O/--traceroute. Probing beats
    assuming, because a euid check alone silently downgrades every scan.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    binary = shutil.which("nmap")
    if not binary:
        return False
    try:
        process = subprocess.run(
            [binary, "-sS", "-p", "1", "-n", "--max-retries", "0", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if process.returncode != 0:
        return False
    combined = f"{process.stdout}\n{process.stderr}".lower()
    return "requires root" not in combined and "quitting" not in combined


@lru_cache(maxsize=1)
def can_capture() -> bool:
    """Whether passive capture is possible without elevation."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    dumpcap = shutil.which("dumpcap")
    if not dumpcap or not shutil.which("tshark"):
        return False
    try:
        process = subprocess.run(
            ["getcap", dumpcap], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "cap_net_raw" in process.stdout


# Discovery artefacts that look like names but identify nothing.
_JUNK_HOSTNAMES = frozenset({
    "*", "<unknown>", "__msbrowse__", "workgroup", "localhost", "any", "unknown",
})
_LOCAL_ZONES = (".local", ".lan", ".home", ".home.arpa", ".localdomain", ".internal")


def clean_hostname(value: str | None, limit: int = 120) -> str | None:
    """Normalize a discovered name: strip record suffixes, local zones and junk.

    Inside a local zone the domain carries no information, so only the first
    label is kept; `vault.lyrs.lan` reads better as `vault` in a device list.
    """
    cleaned = clean_text(value, limit)
    if not cleaned:
        return None
    cleaned = cleaned.strip().strip(".")
    # NetBIOS appends a record-type suffix such as <00> or <20>.
    while cleaned.endswith(">") and "<" in cleaned:
        cleaned = cleaned[: cleaned.rindex("<")].strip()
    lowered = cleaned.lower()
    if any(lowered.endswith(zone) for zone in _LOCAL_ZONES):
        cleaned = cleaned.split(".")[0]
    if not cleaned or cleaned.lower() in _JUNK_HOSTNAMES:
        return None
    if not any(character.isalnum() for character in cleaned):
        return None
    return cleaned
