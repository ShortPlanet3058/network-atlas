"""The audit engine: turn inventory facts into findings with a fix for each.

A finding says what is wrong, on which device, why it matters, and what to do
about it. Findings are keyed and upserted, so one that persists keeps its
`first_seen` and one that gets fixed is marked resolved rather than deleted --
the history of "this was open for three weeks" is worth as much as the finding.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from . import netinfo
from .db import AtlasDB
from .events import HIGH, INFO, LOW, MEDIUM
from .util import clean_text, utc_now


# Services that should not be reachable on a local network without a deliberate
# decision. Each entry carries the reason and the concrete remediation.
RISKY_SERVICES: dict[int, tuple[str, str, str, str]] = {
    21:    (MEDIUM, "FTP is exposed", "FTP sends credentials and file contents in clear text; anyone on the network can read them.", "Replace with SFTP (over SSH) or disable the FTP service."),
    23:    (HIGH,   "Telnet is exposed", "Telnet sends passwords in clear text and is a standard target for automated attacks.", "Disable Telnet and use SSH instead. On embedded devices this is often on by default in the admin panel."),
    69:    (MEDIUM, "TFTP is exposed", "TFTP has no authentication at all; any host can read or write files it serves.", "Disable TFTP unless it is actively needed for device provisioning, and firewall it to the provisioning host."),
    111:   (MEDIUM, "RPC portmapper is exposed", "rpcbind enumerates other RPC services and is widely used for reflection attacks.", "Disable rpcbind if NFS is not in use, or restrict it to known clients."),
    135:   (LOW,    "Windows RPC endpoint mapper is exposed", "Reachable RPC widens the attack surface of a Windows host on the local network.", "Enable the Windows firewall for this network profile, or set the network to Private/Domain rather than Public sharing."),
    139:   (LOW,    "NetBIOS session service is exposed", "Legacy SMB transport, superseded by port 445 and rarely needed.", "Disable NetBIOS over TCP/IP in the adapter's advanced TCP/IP settings."),
    445:   (MEDIUM, "SMB file sharing is exposed", "SMB is the most commonly attacked service on a local network and has a long history of critical vulnerabilities.", "Confirm sharing is intended. If it is, require SMB3, disable SMBv1, and restrict shares to specific accounts."),
    512:   (HIGH,   "rexec is exposed", "rexec accepts credentials in clear text and executes commands remotely.", "Disable the rexec/rsh/rlogin family entirely; they have no safe configuration."),
    513:   (HIGH,   "rlogin is exposed", "rlogin trusts the client's claimed identity and sends credentials in clear text.", "Disable the rexec/rsh/rlogin family entirely and use SSH."),
    514:   (HIGH,   "rsh is exposed", "rsh executes remote commands with no meaningful authentication.", "Disable the rexec/rsh/rlogin family entirely and use SSH."),
    1433:  (MEDIUM, "Microsoft SQL Server is reachable", "A database reachable from the whole network can be brute-forced or exploited directly.", "Bind the instance to localhost, or firewall it to the application hosts that need it."),
    3306:  (MEDIUM, "MySQL/MariaDB is reachable", "A database reachable from the whole network can be brute-forced or exploited directly.", "Set bind-address=127.0.0.1, or firewall the port to the application hosts that need it."),
    3389:  (MEDIUM, "Remote Desktop is exposed", "RDP is a primary target for credential stuffing and has had several pre-auth vulnerabilities.", "Require Network Level Authentication, enforce strong passwords, and restrict the port to known hosts."),
    5432:  (MEDIUM, "PostgreSQL is reachable", "A database reachable from the whole network can be brute-forced or exploited directly.", "Set listen_addresses='localhost', or firewall the port to the application hosts that need it."),
    5900:  (HIGH,   "VNC is exposed", "VNC is frequently unauthenticated or password-only, and streams the desktop in clear text.", "Tunnel VNC over SSH and disable direct access, or require authentication and TLS."),
    6379:  (HIGH,   "Redis is reachable", "Redis has no authentication by default and reachable instances are routinely used to gain code execution.", "Bind to 127.0.0.1, set requirepass, and enable protected-mode."),
    9200:  (MEDIUM, "Elasticsearch is reachable", "Elasticsearch exposes full read/write over HTTP with no authentication in default configurations.", "Bind to localhost or enable authentication, and firewall the port."),
    11211: (HIGH,   "Memcached is reachable", "Memcached is unauthenticated and is the classic amplification-attack reflector.", "Bind to 127.0.0.1 and disable the UDP listener."),
    27017: (HIGH,   "MongoDB is reachable", "MongoDB historically ships without authentication; exposed instances are mass-scanned and ransomed.", "Enable authorization, bind to localhost, and firewall the port."),
}

CLEARTEXT_SERVICE_NAMES = {
    "telnet": (HIGH, "Telnet"), "ftp": (MEDIUM, "FTP"), "http": (INFO, "HTTP"),
    "pop3": (MEDIUM, "POP3"), "imap": (MEDIUM, "IMAP"), "smtp": (LOW, "SMTP"),
    "snmp": (MEDIUM, "SNMP"), "rsh": (HIGH, "rsh"), "rlogin": (HIGH, "rlogin"),
}


def _key(*parts: Any) -> str:
    return "|".join(str(p) for p in parts)


def upsert(
    db: AtlasDB,
    finding_key: str,
    *,
    seen_keys: set[str] | None = None,
    device_id: int | None,
    kind: str,
    severity: str,
    title: str,
    detail: str | None = None,
    remediation: str | None = None,
    evidence: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    seen_at: str | None = None,
) -> None:
    """Record a finding, preserving first_seen and clearing any prior resolution."""
    seen_at = seen_at or utc_now()
    if seen_keys is not None:
        seen_keys.add(finding_key)
    db.conn.execute(
        """INSERT INTO findings(
               finding_key,device_id,kind,severity,title,detail,remediation,evidence,
               port,protocol,first_seen,last_seen
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(finding_key) DO UPDATE SET
               severity=excluded.severity, title=excluded.title,
               detail=excluded.detail, remediation=excluded.remediation,
               evidence=excluded.evidence, last_seen=excluded.last_seen,
               resolved_at=NULL""",
        (
            finding_key, device_id, kind, severity, clean_text(title, 200),
            clean_text(detail, 800), clean_text(remediation, 800),
            clean_text(evidence, 800), port, protocol, seen_at, seen_at,
        ),
    )


def resolve_missing(db: AtlasDB, kinds: Iterable[str], seen_keys: set[str]) -> int:
    """Resolve findings of the given kinds that this pass did not re-observe.

    Keyed on what was actually seen rather than on a timestamp: two passes within
    the same second share a timestamp, so a `last_seen < cutoff` comparison would
    never fire and a fixed issue would stay open forever.
    """
    kinds = list(kinds)
    if not kinds:
        return 0
    kind_slots = ",".join("?" for _ in kinds)
    query = (
        f"UPDATE findings SET resolved_at=? "
        f"WHERE resolved_at IS NULL AND kind IN ({kind_slots})"
    )
    parameters: list[Any] = [utc_now(), *kinds]
    if seen_keys:
        key_slots = ",".join("?" for _ in seen_keys)
        query += f" AND finding_key NOT IN ({key_slots})"
        parameters.extend(sorted(seen_keys))
    cursor = db.conn.execute(query, parameters)
    db.commit()
    return cursor.rowcount or 0


# -- rules -------------------------------------------------------------------
def _exposed_services(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    count = 0
    rows = db.conn.execute(
        """SELECT s.device_id, s.port, s.protocol, s.name, s.product, s.version,
                  d.status, COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) name
           FROM services s JOIN devices d ON d.id = s.device_id
           WHERE s.state LIKE 'open%' AND d.status='online'"""
    ).fetchall()
    for row in rows:
        port = int(row["port"])
        entry = RISKY_SERVICES.get(port)
        if entry:
            severity, title, detail, remediation = entry
            product = " ".join(filter(None, (row["product"], row["version"]))) or row["name"] or "unknown"
            upsert(
                db, _key("exposed", row["device_id"], row["protocol"], port),
                seen_keys=seen, device_id=int(row["device_id"]), kind="exposed-service",
                severity=severity, title=f"{title} on {row['name']}",
                detail=detail, remediation=remediation,
                evidence=f"{port}/{row['protocol']} — {product}",
                port=port, protocol=row["protocol"], seen_at=seen_at,
            )
            count += 1
            continue
        service_name = (row["name"] or "").lower()
        cleartext = CLEARTEXT_SERVICE_NAMES.get(service_name)
        if cleartext and cleartext[0] != INFO:
            severity, label = cleartext
            upsert(
                db, _key("cleartext", row["device_id"], row["protocol"], port),
                seen_keys=seen, device_id=int(row["device_id"]), kind="cleartext-service",
                severity=severity, title=f"{label} without encryption on {row['name']}",
                detail=f"{label} transmits credentials and content in clear text, readable by "
                       "anyone able to observe traffic on this network.",
                remediation=f"Switch to the encrypted equivalent of {label}, or disable it.",
                evidence=f"{port}/{row['protocol']} — {row['product'] or service_name}",
                port=port, protocol=row["protocol"], seen_at=seen_at,
            )
            count += 1
    return count


def _unapproved_devices(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    """Only meaningful once the user has started approving devices."""
    approved_any = db.conn.execute(
        "SELECT COUNT(*) FROM devices WHERE approved=1"
    ).fetchone()[0]
    if not approved_any:
        return 0
    count = 0
    for row in db.conn.execute(
        """SELECT id, COALESCE(manual_name,hostname,mac,'Device '||id) name,
                  COALESCE(manual_type,device_type) type, vendor, approved
           FROM devices WHERE status='online' AND is_local=0
             AND (approved IS NULL OR approved=0)"""
    ).fetchall():
        explicit = row["approved"] == 0
        upsert(
            db, _key("unapproved", row["id"]),
            seen_keys=seen, device_id=int(row["id"]), kind="unapproved-device",
            severity=MEDIUM if explicit else LOW,
            title=f"{'Unapproved' if explicit else 'Unreviewed'} device online: {row['name']}",
            detail=f"Classified as {row['type']}"
                   + (f", vendor {row['vendor']}" if row["vendor"] else "")
                   + ". You have started marking devices as approved, so this one stands out.",
            remediation="Open the device and mark it approved if you recognise it, or "
                        "investigate and remove it from the network if you do not.",
            seen_at=seen_at,
        )
        count += 1
    return count


def _unidentified_devices(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    count = 0
    for row in db.conn.execute(
        """SELECT id, COALESCE(hostname,mac,'Device '||id) name, mac, vendor, confidence
           FROM devices
           WHERE status='online' AND is_local=0
             AND COALESCE(manual_type,device_type)='unknown'"""
    ).fetchall():
        upsert(
            db, _key("unidentified", row["id"]),
            seen_keys=seen, device_id=int(row["id"]), kind="unidentified-device",
            severity=LOW, title=f"Could not identify {row['name']}",
            detail="Nothing observed so far says what this device is. It answers on the "
                   "network but exposes no services, name or recognisable vendor.",
            remediation="Run a Standard or Deep scan to inventory its ports, or a passive "
                        "listen to catch the names it advertises. If you know what it is, "
                        "set the type manually so it stops being flagged.",
            evidence=f"MAC {row['mac'] or 'not observed'}, vendor {row['vendor'] or 'unknown'}",
            seen_at=seen_at,
        )
        count += 1
    return count


def _default_credentials_hint(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    """Flag admin interfaces that are worth checking, without testing credentials."""
    count = 0
    # One finding per appliance: a router serving both 80 and 443 has one
    # management interface, not two problems.
    for row in db.conn.execute(
        """SELECT s.device_id, GROUP_CONCAT(s.port || '/' || s.protocol) ports,
                  MIN(s.port) first_port, MIN(s.protocol) first_protocol,
                  COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) name,
                  COALESCE(d.manual_type,d.device_type) type
           FROM services s JOIN devices d ON d.id = s.device_id
           WHERE s.state LIKE 'open%' AND d.status='online'
             AND s.port IN (80,443,8080,8443)
             AND COALESCE(d.manual_type,d.device_type) IN
                 ('router','switch','access-point','printer','camera','iot','network-device')
           GROUP BY s.device_id"""
    ).fetchall():
        upsert(
            db, _key("admin-interface", row["device_id"]),
            seen_keys=seen, device_id=int(row["device_id"]), kind="admin-interface",
            severity=LOW,
            title=f"Management interface reachable on {row['name']}",
            detail=f"This {row['type']} serves a web interface on {row['ports']}. "
                   "Network appliances, printers and cameras are the devices most often left "
                   "on factory credentials.",
            remediation="Confirm the default password has been changed and that firmware is "
                        "current. Restrict management access to a trusted subnet if the device "
                        "supports it.",
            evidence=f"Reachable on {row['ports']}",
            port=int(row["first_port"]), protocol=row["first_protocol"], seen_at=seen_at,
        )
        count += 1
    return count


def _ipv6_exposure(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    """A globally routable IPv6 address bypasses the NAT people assume protects them."""
    count = 0
    rows = db.conn.execute(
        """SELECT a.device_id, a.address,
                  COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) name,
                  (SELECT COUNT(*) FROM services s
                    WHERE s.device_id=a.device_id AND s.state LIKE 'open%') open_ports
           FROM addresses a JOIN devices d ON d.id = a.device_id
           WHERE a.family='ipv6' AND d.status='online'"""
    ).fetchall()
    for row in rows:
        try:
            address = ipaddress.ip_address(row["address"])
        except ValueError:
            continue
        if address.is_link_local or address.is_private or address.is_loopback:
            continue
        if not row["open_ports"]:
            continue
        upsert(
            db, _key("ipv6-global", row["device_id"], row["address"]),
            seen_keys=seen, device_id=int(row["device_id"]), kind="ipv6-exposure",
            severity=MEDIUM,
            title=f"{row['name']} has a globally routable IPv6 address with open ports",
            detail="IPv6 hosts are reachable from the internet directly unless the router "
                   "firewalls them. IPv4 NAT does not apply, so services you believe are "
                   "internal may be reachable from outside.",
            remediation="Check that your router's IPv6 firewall blocks unsolicited inbound "
                        f"connections, then verify from outside the network whether "
                        f"{row['address']} answers on those ports.",
            evidence=f"{row['address']} with {row['open_ports']} open port(s)",
            seen_at=seen_at,
        )
        count += 1
    return count


def _container_isolation(db: AtlasDB, seen_at: str, seen: set[str]) -> int:
    """Report a container that cannot see the network it is supposed to map.

    Without this the failure is silent: the container discovers its own bridge,
    reports a plausible target, and returns an empty map. Better to say so.
    """
    container = netinfo.container_info()
    if not container["network_isolated"]:
        return 0
    upsert(
        db, _key("container-isolated"),
        seen_keys=seen, device_id=None, kind="container-isolated",
        severity=HIGH,
        title="Discovery cannot see your network from inside this container",
        detail=(
            f"Network Atlas is running in a {container['runtime']} container and "
            f"{container['isolation_reason']}. Address scans, broadcast discovery "
            "(mDNS, DHCP, SSDP, NetBIOS) and LLDP/CDP all describe the container's "
            "own segment, so the map will be nearly empty no matter how often you "
            "scan. This is a deployment problem, not a fault on your network."
        ),
        remediation=(
            "On Linux: start the container with host networking "
            "(`network_mode: host`, which docker-compose.yml already sets), or "
            "attach it to a macvlan network so it gets its own address on the LAN. "
            "On Docker Desktop for macOS or Windows: host networking reaches only "
            "the Linux VM, so run Network Atlas natively, or in a VM bridged to "
            "the network, or on a Linux machine that is already on it. Windows 11 "
            "users can try WSL2 mirrored networking. See https://github.com/ShortPlanet3058/network-atlas/wiki/Docker."
        ),
        evidence=f"runtime={container['runtime']}, wsl={container['wsl']}",
        seen_at=seen_at,
    )
    return 1


def evaluate(db: AtlasDB, *, seen_at: str | None = None) -> dict[str, int]:
    """Run every inventory-derived rule and resolve findings that no longer apply."""
    seen_at = seen_at or utc_now()
    seen: set[str] = set()
    counts = {
        "exposed-service": _exposed_services(db, seen_at, seen),
        "unapproved-device": _unapproved_devices(db, seen_at, seen),
        "unidentified-device": _unidentified_devices(db, seen_at, seen),
        "admin-interface": _default_credentials_hint(db, seen_at, seen),
        "ipv6-exposure": _ipv6_exposure(db, seen_at, seen),
        "container-isolated": _container_isolation(db, seen_at, seen),
    }
    db.commit()
    # Inventory rules are fully re-derived each pass, so anything not re-observed
    # has genuinely gone away. Scanner-backed kinds (exploits, TLS) are excluded:
    # they only refresh when their own collector runs.
    resolve_missing(
        db,
        ("exposed-service", "cleartext-service", "unapproved-device",
         "unidentified-device", "admin-interface", "ipv6-exposure",
         "container-isolated"),
        seen,
    )
    return counts


def summary(db: AtlasDB) -> dict[str, Any]:
    rows = db.conn.execute(
        """SELECT severity, COUNT(*) count FROM findings
           WHERE resolved_at IS NULL AND muted=0 GROUP BY severity"""
    ).fetchall()
    by_severity = {row["severity"]: row["count"] for row in rows}
    return {
        "open": sum(by_severity.values()),
        "by_severity": by_severity,
        "high": by_severity.get(HIGH, 0),
        "medium": by_severity.get(MEDIUM, 0),
        "low": by_severity.get(LOW, 0),
        "resolved": db.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE resolved_at IS NOT NULL"
        ).fetchone()[0],
    }
