"""Passive discovery: observe the broadcast domain without sending any packets.

Active probes miss devices that firewall themselves or sleep. Passive capture
picks them up whenever they speak, and DHCP/mDNS/NBNS chatter carries hostnames
and vendor fingerprints that no port scan can supply.

Capture runs once into a temporary pcap; each protocol is then extracted with a
separate read pass, so field sets stay independent and the capture window is short.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from .util import can_capture, clean_hostname, clean_text, normalize_mac


# Only broadcast/multicast control traffic is captured: discovery protocols and
# link-layer advertisements. Unicast payload is never recorded.
CAPTURE_FILTER = (
    "arp"
    " or (udp port 67 or udp port 68)"
    " or (udp port 546 or udp port 547)"
    " or udp port 5353"
    " or (udp port 137 or udp port 138)"
    " or udp port 5355"
    " or udp port 1900"
    " or ether proto 0x88cc"
    " or ether dst 01:00:0c:cc:cc:cc"
    " or icmp6"
    # Handshake packets only: no payload is ever recorded, but these carry the
    # TCP/IP stack fingerprint p0f reads and the endpoint pairs that make up the
    # traffic map.
    " or (tcp[tcpflags] & tcp-syn != 0)"
    # Plaintext HTTP requests, for the User-Agent alone. Almost all traffic is
    # HTTPS now, so this is a small addition that occasionally names a device
    # outright; no response bodies are captured.
    " or (tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0))"
)

SAFE_INTERFACE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")


class PassiveError(RuntimeError):
    """Passive capture could not run or could not be read."""


def _hostname(value: str, limit: int = 120) -> str | None:
    return clean_hostname(value, limit)


# TXT keys that carry a hardware model, across the vendors that use mDNS.
# "md" is Google Cast, "model"/"am" are Apple, "ty"/"usb_MDL"/"product" are IPP
# printers, "mdl" is UPnP-style.
_TXT_MODEL_KEYS = frozenset({"md", "model", "am", "ty", "usb_mdl", "product", "mdl"})
# Keys holding a name a person chose, which beats a hostname every time.
_TXT_NAME_KEYS = frozenset({"fn", "n", "friendlyname", "nm"})
# Keys worth recording as evidence without driving classification.
_TXT_DETAIL_KEYS = frozenset({
    "usb_mfg", "mfg", "vn", "manufacturer", "os", "osxvers", "srcvers",
    "fw", "fv", "version", "rs", "note", "location", "adminurl",
})


def _split_txt(value: str) -> list[str]:
    """Split a tshark TXT field into its key=value strings.

    tshark joins the strings of one TXT record with commas, and values can
    themselves contain commas, so a split on "," followed by re-joining fragments
    that carry no "=" keeps values intact.
    """
    if not value:
        return []
    pairs: list[str] = []
    for fragment in value.split(","):
        if "=" in fragment or not pairs:
            pairs.append(fragment)
        else:
            # A continuation of the previous value rather than a new key.
            pairs[-1] = f"{pairs[-1]},{fragment}"
    return [pair for pair in pairs if pair.strip()]


def _validate_interface(interface: str) -> str:
    if not interface or not set(interface).issubset(SAFE_INTERFACE):
        raise ValueError(f"Invalid interface name: {interface!r}")
    return interface


def capture(interface: str, duration: int, *, packet_limit: int = 20000) -> Path:
    """Capture discovery traffic for `duration` seconds into a temporary pcap."""
    _validate_interface(interface)
    if not can_capture():
        raise PassiveError(
            "Passive capture needs packet-capture rights. Add your user to the "
            "'wireshark' group (`sudo usermod -aG wireshark $USER`, then log in "
            "again) or run `sudo dpkg-reconfigure wireshark-common`."
        )
    tshark = shutil.which("tshark")
    if not tshark:
        raise PassiveError("Required command not found: tshark")
    handle = tempfile.NamedTemporaryFile(prefix="atlas-passive-", suffix=".pcap", delete=False)
    handle.close()
    target = Path(handle.name)
    target.chmod(0o600)
    command = [
        tshark, "-i", interface, "-a", f"duration:{max(5, min(duration, 900))}",
        "-c", str(packet_limit), "-w", str(target), "-q", "-f", CAPTURE_FILTER,
    ]
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=duration + 45, check=False
        )
    except subprocess.TimeoutExpired as exc:
        target.unlink(missing_ok=True)
        raise PassiveError(f"Capture did not finish within {duration + 45}s") from exc
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise PassiveError(f"Could not start tshark: {exc}") from exc
    # tshark exits non-zero when the duration elapses with zero packets, which is
    # a legitimate outcome on a quiet network.
    if process.returncode != 0 and not target.exists():
        target.unlink(missing_ok=True)
        raise PassiveError(clean_text(process.stderr, 400) or "Capture failed")
    return target


def _read(
    path: Path, display_filter: str, fields: list[str], *, occurrence: str = "f"
) -> Iterator[list[str]]:
    """Extract fields from a capture.

    `occurrence` is tshark's: "f" takes the first value of a repeated field, "a"
    takes all of them joined by commas. A DNS TXT record holds several strings and
    the interesting one is rarely the first, so that read needs "a".
    """
    tshark = shutil.which("tshark")
    if not tshark:
        return
    command = [tshark, "-r", str(path), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    command.extend(["-E", "separator=\t", "-E", f"occurrence={occurrence}"])
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=180, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    for line in process.stdout.splitlines():
        if line.strip():
            yield line.split("\t")


def _request_list(raw: str) -> str:
    """Normalise a DHCP option 55 list into a stable comma-separated signature.

    tshark yields the items in the order the client sent them, which is the part
    that carries the fingerprint, so the order is deliberately preserved.
    """
    items: list[str] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part.isdigit() and len(items) < 32:
            items.append(part)
    return ",".join(items)


def _field(row: list[str], index: int) -> str:
    return row[index].strip() if index < len(row) else ""


def analyze(path: Path) -> dict[str, Any]:
    """Extract per-host observations and link-layer neighbours from a capture."""
    hosts: dict[str, dict[str, Any]] = {}
    links: list[dict[str, Any]] = []
    counters: dict[str, int] = defaultdict(int)

    def host(mac: str | None = None, address: str | None = None) -> dict[str, Any] | None:
        normalized = normalize_mac(mac)
        if address:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                address = None
            else:
                if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
                    address = None
        key = normalized or address
        if not key:
            return None
        entry = hosts.setdefault(
            key,
            {"mac": normalized, "addresses": set(), "hostnames": set(),
             "services": set(), "fingerprints": set(), "protocols": set(),
             "vendor_classes": set(), "models": set(), "friendly_names": set(),
             "user_agents": set(), "browsed_services": set(), "param_lists": set()},
        )
        if normalized and not entry["mac"]:
            entry["mac"] = normalized
        if address:
            entry["addresses"].add(address)
        return entry

    # ARP: the broadest signal — anything that talks IPv4 on the segment appears here.
    for row in _read(path, "arp", ["arp.src.hw_mac", "arp.src.proto_ipv4"]):
        entry = host(_field(row, 0), _field(row, 1))
        if entry:
            entry["protocols"].add("arp")
            counters["arp"] += 1

    # DHCP: hostname, a vendor-class fingerprint that names the OS family, and
    # the parameter request list. Option 55 is the order in which a client asks
    # for options, which is decided by its DHCP implementation rather than by
    # configuration, so it identifies the OS even on devices that send no vendor
    # class at all. Every request is a broadcast, so this survives switches.
    dhcp_fields = [
        "dhcp.hw.mac_addr", "dhcp.ip.client", "dhcp.option.hostname",
        "dhcp.option.vendor_class_id", "dhcp.option.request_list_item",
    ]
    for row in _read(path, "dhcp", dhcp_fields, occurrence="a"):
        entry = host(_field(row, 0), _field(row, 1))
        if not entry:
            continue
        entry["protocols"].add("dhcp")
        if hostname := _hostname(_field(row, 2)):
            entry["hostnames"].add(hostname)
        if vendor_class := clean_text(_field(row, 3), 160):
            # Kept as its own field: the classifier interprets it, rather than
            # substring-matching a prose sentence.
            entry["vendor_classes"].add(vendor_class)
        if request_list := _request_list(_field(row, 4)):
            entry["param_lists"].add(request_list)
        counters["dhcp"] += 1

    # mDNS, LLMNR, NetBIOS and SSDP travel over IP and are routinely relayed or
    # reflected by access points and mesh nodes. The Ethernet source is then the
    # relay, not the origin, so these are keyed on the IP address alone; ARP is
    # what binds an address to a hardware address.
    #
    # Responses only. A query says what a device is LOOKING FOR, not what it
    # offers: every Mac and Android browses for "_pdl-datastream._tcp", and
    # reading queries as advertisements classified them all as printers.
    for row in _read(
        path, "mdns && dns.flags.response == 1", ["eth.src", "ip.src", "dns.resp.name"],
        occurrence="a",
    ):
        entry = host(None, _field(row, 1))
        if not entry:
            continue
        entry["protocols"].add("mdns")
        for name in dict.fromkeys(_field(row, 2).split(",")):
            name = clean_text(name, 200)
            if not name:
                continue
            is_service = (
                name.startswith("_") or "._tcp" in name or "._udp" in name
                or "_dns-sd" in name or "in-addr.arpa" in name
            )
            if is_service:
                entry["services"].add(name)
            elif name.endswith(".local"):
                if resolved := _hostname(name, 200):
                    entry["hostnames"].add(resolved)
        counters["mdns"] += 1

    # Queries are still worth recording: a device browsing for printers is a
    # client of printing, which is weak evidence that it is a computer or phone.
    for row in _read(
        path, "(mdns || llmnr) && dns.flags.response == 0", ["ip.src", "dns.qry.name"]
    ):
        entry = host(None, _field(row, 0))
        name = clean_text(_field(row, 1), 200)
        if entry and name and ("._tcp" in name or "._udp" in name):
            entry["browsed_services"].add(name)
            counters["mdns_query"] += 1

    # NetBIOS: names for Windows and SMB-capable hosts.
    for row in _read(path, "nbns", ["eth.src", "ip.src", "nbns.name"]):
        entry = host(None, _field(row, 1))
        if not entry:
            continue
        entry["protocols"].add("netbios")
        if name := _hostname(_field(row, 2), 80):
            entry["hostnames"].add(name)
        counters["netbios"] += 1

    # SSDP: UPnP announcements from TVs, consoles, media players and IoT.
    ssdp_fields = ["eth.src", "ip.src", "http.request.line", "http.server"]
    for row in _read(path, "ssdp", ssdp_fields):
        entry = host(None, _field(row, 1))
        if not entry:
            continue
        entry["protocols"].add("ssdp")
        server = clean_text(_field(row, 3), 160)
        if server:
            entry["fingerprints"].add(f"UPnP server: {server}")
        counters["ssdp"] += 1

    # LLDP: authoritative physical topology, straight off the wire, no credentials.
    lldp_fields = [
        "eth.src", "lldp.chassis.id.mac", "lldp.tlv.system.name", "lldp.tlv.system.desc",
        "lldp.port.id", "lldp.port.desc", "lldp.tlv.system_cap.router",
        "lldp.tlv.system_cap.bridge", "lldp.tlv.system_cap.wlan_access_pt",
        "lldp.tlv.system_cap.telephone", "lldp.chassis.id.ip4",
    ]
    for row in _read(path, "lldp", lldp_fields):
        source_mac = normalize_mac(_field(row, 1)) or normalize_mac(_field(row, 0))
        entry = host(source_mac, _field(row, 10) or None)
        if not entry:
            continue
        entry["protocols"].add("lldp")
        if name := _hostname(_field(row, 2)):
            entry["hostnames"].add(name)
        if description := clean_text(_field(row, 3), 400):
            entry["fingerprints"].add(f"LLDP system description: {description}")
        capabilities = [
            label
            for label, index in (("router", 6), ("bridge", 7), ("wlan-access-point", 8), ("telephone", 9))
            if _field(row, index) in ("1", "True", "true")
        ]
        links.append({
            "protocol": "lldp",
            "mac": source_mac,
            "system_name": clean_text(_field(row, 2), 120),
            "port_id": clean_text(_field(row, 4), 80),
            "port_desc": clean_text(_field(row, 5), 120),
            "capabilities": capabilities,
        })
        counters["lldp"] += 1

    # CDP: the Cisco equivalent, same purpose. Its capability bits must be read
    # rather than assumed: IP phones flood CDP too, and treating every CDP speaker
    # as a bridge turns desk phones into switches.
    cdp_fields = [
        "eth.src", "cdp.deviceid", "cdp.portid", "cdp.platform", "cdp.software_version",
        "cdp.capabilities.router", "cdp.capabilities.switch",
        "cdp.capabilities.trans_bridge", "cdp.capabilities.voip_phone",
        "cdp.capabilities.host",
    ]
    for row in _read(path, "cdp", cdp_fields):
        source_mac = normalize_mac(_field(row, 0))
        entry = host(source_mac)
        if not entry:
            continue
        entry["protocols"].add("cdp")
        if device_id := _hostname(_field(row, 1)):
            entry["hostnames"].add(device_id)
        if platform := clean_text(_field(row, 3), 160):
            entry["fingerprints"].add(f"CDP platform: {platform}")
        capabilities = [
            label
            for label, index in (
                ("router", 5), ("bridge", 6), ("bridge", 7),
                ("telephone", 8), ("station-only", 9),
            )
            if _field(row, index) in ("1", "True", "true")
        ]
        capabilities = sorted(set(capabilities))
        if capabilities:
            entry["fingerprints"].add(f"CDP capabilities: {', '.join(capabilities)}")
        links.append({
            "protocol": "cdp",
            "mac": source_mac,
            "system_name": clean_text(_field(row, 1), 120),
            "port_id": clean_text(_field(row, 2), 80),
            "port_desc": clean_text(_field(row, 3), 120),
            "capabilities": capabilities,
        })
        counters["cdp"] += 1

    # DHCP lease detail: the server's ACK carries the address it assigned, the
    # lease duration and the client's own hostname -- lease-table data for any
    # device that renews during the window, with no router integration at all.
    lease_fields = [
        "dhcp.hw.mac_addr", "dhcp.ip.your", "dhcp.option.dhcp_server_id",
        "dhcp.option.ip_address_lease_time", "dhcp.option.hostname",
        "dhcp.option.domain_name",
    ]
    leases: list[dict[str, Any]] = []
    for row in _read(path, "dhcp.option.dhcp == 5", lease_fields):
        assigned = _field(row, 1)
        mac = normalize_mac(_field(row, 0))
        if not assigned or not mac:
            continue
        try:
            ipaddress.ip_address(assigned)
        except ValueError:
            continue
        leases.append({
            "mac": mac,
            "address": assigned,
            "server": _field(row, 2) or None,
            "lease_seconds": int(_field(row, 3)) if _field(row, 3).isdigit() else None,
            "hostname": _hostname(_field(row, 4)),
            "domain": clean_text(_field(row, 5), 80) or None,
        })
        counters["dhcp_lease"] += 1
        entry = host(mac, assigned)
        if entry and leases[-1]["hostname"]:
            entry["hostnames"].add(leases[-1]["hostname"])

    # Traffic pairs from handshake packets: which device talks to which, and on
    # what port. Only the SYN is needed, so no conversation content is examined.
    flows: dict[tuple[str, str, int], int] = defaultdict(int)
    for row in _read(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                     ["ip.src", "ip.dst", "tcp.dstport", "eth.src"]):
        source_ip, destination_ip, port = _field(row, 0), _field(row, 1), _field(row, 2)
        if not source_ip or not destination_ip or not port.isdigit():
            continue
        try:
            parsed_source = ipaddress.ip_address(source_ip)
            parsed_destination = ipaddress.ip_address(destination_ip)
        except ValueError:
            continue
        if parsed_source.is_multicast or parsed_destination.is_multicast:
            continue
        flows[(source_ip, destination_ip, int(port))] += 1
        counters["flow"] += 1
        # A host initiating connections is demonstrably present.
        entry = host(_field(row, 3) or None, source_ip)
        if entry:
            entry["protocols"].add("tcp")

    # IPv6: neighbour solicitation and router advertisement reveal the v6 half.
    for row in _read(path, "icmpv6.type == 133 || icmpv6.type == 134 || icmpv6.type == 136",
                     ["eth.src", "ipv6.src", "icmpv6.type"]):
        entry = host(_field(row, 0), _field(row, 1))  # NDP is link-local, never relayed
        if not entry:
            continue
        entry["protocols"].add("icmpv6")
        if _field(row, 2) == "134":
            entry["fingerprints"].add("Sends IPv6 router advertisements")
        counters["icmpv6"] += 1

    return {
        "leases": leases,
        "flows": [
            {"source": source, "target": target, "port": port, "count": count}
            for (source, target, port), count in sorted(
                flows.items(), key=lambda item: item[1], reverse=True
            )[:400]
        ],
        "hosts": [
            {
                "mac": entry["mac"],
                "addresses": sorted(entry["addresses"]),
                "hostnames": sorted(name for name in entry["hostnames"] if name),
                "services": sorted(entry["services"]),
                "fingerprints": sorted(entry["fingerprints"]),
                "vendor_classes": sorted(entry["vendor_classes"]),
                "models": sorted(entry["models"]),
                "friendly_names": sorted(entry["friendly_names"]),
                "user_agents": sorted(entry["user_agents"]),
                "param_lists": sorted(entry["param_lists"]),
                "browsed_services": sorted(entry["browsed_services"]),
                "protocols": sorted(entry["protocols"]),
            }
            for entry in hosts.values()
        ],
        "links": links,
        "counters": dict(counters),
    }
