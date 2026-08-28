"""Local routing, interface and neighbour introspection via iproute2."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _ip_json(*arguments: str) -> list[dict[str, Any]]:
    binary = shutil.which("ip")
    if not binary:
        return []
    try:
        process = subprocess.run(
            [binary, "-json", *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if process.returncode != 0:
        return []
    try:
        payload = json.loads(process.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def link_macs() -> dict[str, str]:
    """Interface name to hardware address; `ip addr` omits it under a scope filter."""
    macs: dict[str, str] = {}
    for entry in _ip_json("link", "show"):
        name, mac = entry.get("ifname"), entry.get("address")
        if name and mac and mac != "00:00:00:00:00:00":
            macs[name] = mac
    return macs


def interfaces() -> list[dict[str, Any]]:
    """Global-scope IPv4/IPv6 interfaces with their CIDR networks."""
    macs = link_macs()
    result: list[dict[str, Any]] = []
    for family in ("-4", "-6"):
        for entry in _ip_json(family, "addr", "show", "scope", "global"):
            name = entry.get("ifname")
            if not name or name == "lo":
                continue
            for address in entry.get("addr_info", []):
                local, prefix = address.get("local"), address.get("prefixlen")
                if not local or prefix is None:
                    continue
                try:
                    network = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
                except ValueError:
                    continue
                result.append(
                    {
                        "interface": name,
                        "address": local,
                        "prefixlen": int(prefix),
                        "network": str(network),
                        "family": f"ipv{network.version}",
                        "mac": entry.get("address") or macs.get(name),
                        "state": entry.get("operstate", "UNKNOWN"),
                        "wireless": name.startswith(("wl", "wlan", "wlp")),
                    }
                )
    return result


def gateways() -> list[dict[str, Any]]:
    """Default gateways, lowest metric first, deduplicated by gateway address."""
    found: dict[str, dict[str, Any]] = {}
    for family in ("-4", "-6"):
        for entry in _ip_json(family, "route", "show", "default"):
            gateway = entry.get("gateway")
            if not gateway:
                continue
            metric = int(entry.get("metric") or 0)
            existing = found.get(gateway)
            if existing and existing["metric"] <= metric:
                existing.setdefault("interfaces", []).append(entry.get("dev"))
                continue
            found[gateway] = {
                "address": gateway,
                "interface": entry.get("dev"),
                "interfaces": [entry.get("dev")],
                "metric": metric,
                "source": entry.get("prefsrc"),
                "family": "ipv6" if ":" in gateway else "ipv4",
            }
    return sorted(found.values(), key=lambda item: item["metric"])


def local_networks() -> list[dict[str, Any]]:
    """Directly attached (link-scope) networks reachable without a router."""
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for family in ("-4", "-6"):
        for entry in _ip_json(family, "route", "show"):
            destination = entry.get("dst")
            if not destination or destination == "default":
                continue
            if entry.get("scope") != "link" and entry.get("gateway"):
                continue
            if "linkdown" in (entry.get("flags") or []):
                continue
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError:
                continue
            if network.is_loopback or network.is_link_local or str(network) in seen:
                continue
            seen.add(str(network))
            result.append(
                {
                    "network": str(network),
                    "interface": entry.get("dev"),
                    "family": f"ipv{network.version}",
                    "source": entry.get("prefsrc"),
                    "addresses": network.num_addresses,
                }
            )
    return result


def neighbours() -> list[dict[str, Any]]:
    """Kernel ARP/NDP cache entries that resolved to a hardware address."""
    result: list[dict[str, Any]] = []
    for family in ("-4", "-6"):
        for entry in _ip_json(family, "neigh", "show"):
            address, lladdr = entry.get("dst"), entry.get("lladdr")
            if not address or not lladdr:
                continue
            states = entry.get("state") or []
            if "FAILED" in states or "INCOMPLETE" in states:
                continue
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            result.append(
                {
                    "address": address,
                    "mac": lladdr,
                    "interface": entry.get("dev"),
                    "family": f"ipv{parsed.version}",
                    "state": states[0] if states else "UNKNOWN",
                    "reachable": "REACHABLE" in states or "PERMANENT" in states,
                    "link_local": parsed.is_link_local,
                }
            )
    return result


def primary_target() -> str | None:
    """The IPv4 network behind the lowest-metric default route."""
    candidates = local_networks()
    for gateway in gateways():
        if gateway["family"] != "ipv4":
            continue
        try:
            address = ipaddress.ip_address(gateway["address"])
        except ValueError:
            continue
        for candidate in candidates:
            if candidate["family"] != "ipv4":
                continue
            if address in ipaddress.ip_network(candidate["network"]):
                return candidate["network"]
    for candidate in candidates:
        if candidate["family"] == "ipv4" and candidate["addresses"] <= 4096:
            return candidate["network"]
    return None


def capture_interface() -> str | None:
    """Best interface for passive capture.

    LLDP and CDP are only forwarded on wired links, so a wired interface is worth
    far more than a wireless one here. Among candidates, the one carrying the
    lowest-metric default route sees the most traffic.
    """
    candidates = [entry for entry in interfaces() if entry["state"] == "UP"]
    if not candidates:
        return None
    preferred = {gateway["interface"] for gateway in gateways() if gateway["interface"]}

    def rank(entry: dict[str, Any]) -> tuple[int, int, str]:
        return (
            0 if entry["interface"] in preferred else 1,
            1 if entry["wireless"] else 0,
            entry["interface"],
        )

    return sorted(candidates, key=rank)[0]["interface"]


def local_addresses() -> set[str]:
    return {entry["address"] for entry in interfaces()}


# Docker Desktop's Linux VM presents this gateway to containers. Seeing it means
# the "host" network is the VM, not the user's machine.
DOCKER_DESKTOP_GATEWAYS = frozenset({"192.168.65.1"})
# Docker's default bridge pool. A container whose only route out lands here is on
# a private NAT segment of its own, not on the network the operator wants mapped.
BRIDGE_POOL = ipaddress.ip_network("172.16.0.0/12")


def container_info() -> dict[str, Any]:
    """Whether this is running in a container, and whether its network can see the LAN.

    This matters because the failure is silent otherwise: a container on a NAT'd
    network namespace discovers its own bridge, reports a plausible-looking target
    like 172.17.0.0/16, and returns an almost empty map with nothing to indicate
    why. Detecting it lets the application say so instead.
    """
    runtime: str | None = None
    if Path("/.dockerenv").exists():
        runtime = "docker"
    elif Path("/run/.containerenv").exists():
        runtime = "podman"
    else:
        try:
            cgroup = Path("/proc/1/cgroup").read_text()
        except OSError:
            cgroup = ""
        for marker, name in (("docker", "docker"), ("containerd", "containerd"), ("lxc", "lxc")):
            if marker in cgroup:
                runtime = name
                break

    try:
        kernel = Path("/proc/version").read_text().lower()
    except OSError:
        kernel = ""
    wsl = "microsoft" in kernel or "wsl" in kernel

    info: dict[str, Any] = {
        "in_container": runtime is not None,
        "runtime": runtime,
        "wsl": wsl,
        "network_isolated": False,
        "isolation_reason": None,
    }
    if runtime is None:
        return info

    default_gateways = [entry["address"] for entry in gateways()]
    global_interfaces = [entry for entry in interfaces() if entry["state"] == "UP"]

    if any(address in DOCKER_DESKTOP_GATEWAYS for address in default_gateways):
        info["network_isolated"] = True
        info["isolation_reason"] = (
            "the container's network is Docker Desktop's Linux VM, not this machine"
        )
        return info

    # A single eth0 whose only way out is Docker's bridge pool is the signature of
    # bridge networking. Host networking on Linux shows the machine's real
    # interfaces and a gateway on the real LAN, so this does not fire there.
    names = {entry["interface"] for entry in global_interfaces}
    if names <= {"eth0"} and default_gateways:
        try:
            in_bridge = all(
                ipaddress.ip_address(address) in BRIDGE_POOL
                for address in default_gateways
            )
        except ValueError:
            in_bridge = False
        if in_bridge:
            info["network_isolated"] = True
            info["isolation_reason"] = (
                "the container is on a private bridge network behind NAT, so the "
                "real network is not reachable from inside it"
            )
    return info


def summary() -> dict[str, Any]:
    """Everything the viewer needs to describe the vantage point of this host."""
    gateway_list = gateways()
    return {
        "interfaces": interfaces(),
        "gateways": gateway_list,
        "networks": local_networks(),
        "primary_gateway": gateway_list[0]["address"] if gateway_list else None,
        "primary_target": primary_target(),
        "capture_interface": capture_interface(),
        "container": container_info(),
    }
