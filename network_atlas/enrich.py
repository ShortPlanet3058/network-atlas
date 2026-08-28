"""Name resolution passes that turn bare addresses into recognizable devices.

A scan yields IPs and MACs; users recognize names. These probes are cheap and
independent of any port being open, so they run over the whole known inventory.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

from .util import clean_hostname, normalize_mac


NBTSCAN_LINE = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<name>\S+)\s+.*?"
    r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\s*$"
)


def _clean_name(value: str | None) -> str | None:
    return clean_hostname(value)


def reverse_dns(addresses: Iterable[str], *, workers: int = 24, timeout: float = 2.0) -> dict[str, str]:
    """PTR lookups in parallel; most home routers answer for their DHCP clients."""
    targets = [address for address in dict.fromkeys(addresses) if address]
    if not targets:
        return {}
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    def lookup(address: str) -> tuple[str, str | None]:
        try:
            name = socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return address, None
        return address, _clean_name(name)

    try:
        with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
            results = list(pool.map(lookup, targets))
    finally:
        socket.setdefaulttimeout(previous)
    return {address: name for address, name in results if name}


def netbios_names(target: str, *, timeout: int = 60) -> list[dict[str, Any]]:
    """NetBIOS names via nbtscan; the most reliable source for Windows and SMB hosts."""
    binary = shutil.which("nbtscan")
    if not binary:
        return []
    try:
        process = subprocess.run(
            [binary, "-q", "-s", "\t", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    results: list[dict[str, Any]] = []
    for line in process.stdout.splitlines():
        # The -s form is tab separated; fall back to the padded default layout.
        parts = [part.strip() for part in line.split("\t") if part.strip()]
        if len(parts) >= 2 and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", parts[0]):
            mac = next((normalize_mac(part) for part in reversed(parts) if normalize_mac(part)), None)
            name = _clean_name(parts[1])
            if name or mac:
                results.append({"address": parts[0], "hostname": name, "mac": mac})
            continue
        match = NBTSCAN_LINE.match(line.strip())
        if match:
            results.append({
                "address": match.group("ip"),
                "hostname": _clean_name(match.group("name")),
                "mac": normalize_mac(match.group("mac")),
            })
    return results


def mdns_names(addresses: Iterable[str], *, timeout: int = 20) -> dict[str, str]:
    """Reverse mDNS resolution for .local names that unicast DNS cannot answer."""
    binary = shutil.which("avahi-resolve")
    targets = [address for address in dict.fromkeys(addresses) if address]
    if not binary or not targets:
        return {}
    command = [binary, "-a", *targets[:256]]
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    resolved: dict[str, str] = {}
    for line in process.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = _clean_name(parts[1])
            if name:
                resolved[parts[0]] = name
    return resolved
