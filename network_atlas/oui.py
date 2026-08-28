"""IEEE OUI vendor lookup backed by the local Nmap and arp-scan databases."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


# Nmap ships a generated IEEE registry (~52k prefixes); arp-scan ships the raw file.
OUI_SOURCES = (
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/arp-scan/ieee-oui.txt"),
)
_OUI_LINE = re.compile(r"^([0-9A-Fa-f]{6,12})\s+(.+)$")

# Locally administered addresses are randomized privacy MACs, not real vendors.
_RANDOM_NIBBLES = frozenset("2637abef")


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    for source in OUI_SOURCES:
        try:
            content = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in content.splitlines():
            if not line or line.startswith("#"):
                continue
            match = _OUI_LINE.match(line)
            if not match:
                continue
            prefix, vendor = match.group(1).upper(), match.group(2).strip()
            # Keep the first source that defines a prefix; Nmap's is the cleaner one.
            if prefix not in table and vendor:
                table[prefix] = vendor
    return table


def is_randomized(mac: str | None) -> bool:
    """True when the MAC is locally administered, so no vendor can exist for it."""
    if not mac or len(mac) < 2:
        return False
    return mac.lower()[1] in _RANDOM_NIBBLES


def lookup(mac: str | None) -> str | None:
    """Resolve a normalized MAC to its registered vendor, longest prefix first."""
    if not mac:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(compact) < 6:
        return None
    if is_randomized(mac):
        return None
    table = _table()
    # MA-S (36-bit) and MA-M (28-bit) assignments share the MA-L 24-bit space.
    for length in (9, 7, 6):
        vendor = table.get(compact[:length])
        if vendor:
            return vendor
    return None


def size() -> int:
    return len(_table())
