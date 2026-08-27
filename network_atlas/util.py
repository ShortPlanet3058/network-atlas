from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime


MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12:
        return None
    mac = ":".join(compact[i : i + 2] for i in range(0, 12, 2)).lower()
    return mac if MAC_RE.match(mac) else None


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
