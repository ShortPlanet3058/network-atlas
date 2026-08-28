"""TLS posture for every HTTPS-capable service, via sslscan.

Unlike exploit correlation, these findings are definitive: a certificate either
has expired or it has not, and a protocol version is either offered or it is not.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .db import AtlasDB
from .events import HIGH, LOW, MEDIUM
from .findings import upsert
from .util import utc_now


# Ports worth probing for TLS even when Nmap did not name the service https.
TLS_PORTS = (443, 8443, 9443, 4443, 10000, 636, 989, 990, 993, 995, 8834, 5986)

# Protocol versions that should no longer be offered, with the reason.
DEPRECATED_PROTOCOLS = {
    ("ssl", "2"): (HIGH, "SSLv2 is fundamentally broken and enables the DROWN attack."),
    ("ssl", "3"): (HIGH, "SSLv3 is broken by POODLE and must not be offered."),
    ("tls", "1.0"): (MEDIUM, "TLS 1.0 is deprecated and disallowed by current standards."),
    ("tls", "1.1"): (MEDIUM, "TLS 1.1 is deprecated and disallowed by current standards."),
}


def available() -> bool:
    return bool(shutil.which("sslscan"))


def _scan(host: str, port: int, *, timeout: int = 90) -> ET.Element | None:
    binary = shutil.which("sslscan")
    if not binary:
        return None
    handle = tempfile.NamedTemporaryFile(prefix="atlas-ssl-", suffix=".xml", delete=False)
    handle.close()
    path = Path(handle.name)
    try:
        subprocess.run(
            [binary, "--no-colour", f"--xml={path}", f"{host}:{port}"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if not path.stat().st_size:
            return None
        return ET.parse(path).getroot()
    except (OSError, subprocess.TimeoutExpired, ET.ParseError):
        return None
    finally:
        path.unlink(missing_ok=True)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _evaluate(
    db: AtlasDB, device_id: int, device_name: str, host: str, port: int,
    root: ET.Element, seen_at: str,
) -> int:
    created = 0
    base = f"tls|{device_id}|{port}"

    for protocol in root.iter("protocol"):
        if protocol.get("enabled") != "1":
            continue
        key = (protocol.get("type", ""), protocol.get("version", ""))
        entry = DEPRECATED_PROTOCOLS.get(key)
        if not entry:
            continue
        severity, reason = entry
        label = f"{key[0].upper()}v{key[1]}" if key[0] == "ssl" else f"TLS {key[1]}"
        upsert(
            db, f"{base}|protocol|{key[0]}{key[1]}",
            device_id=device_id, kind="tls-protocol", severity=severity,
            title=f"{device_name} still offers {label}",
            detail=reason + " Clients that negotiate it are downgraded to weak cryptography.",
            remediation=f"Disable {label} in the service's TLS configuration and offer only "
                        "TLS 1.2 and TLS 1.3.",
            evidence=f"{host}:{port} accepts {label}",
            port=port, protocol="tcp", seen_at=seen_at,
        )
        created += 1

    for heartbleed in root.iter("heartbleed"):
        if heartbleed.get("vulnerable") == "1":
            upsert(
                db, f"{base}|heartbleed",
                device_id=device_id, kind="tls-vulnerability", severity=HIGH,
                title=f"{device_name} is vulnerable to Heartbleed",
                detail="The service leaks adjacent process memory to any client, which can "
                       "include private keys, session tokens and credentials (CVE-2014-0160).",
                remediation="Update OpenSSL immediately, then replace the certificate and "
                            "private key and invalidate existing sessions -- key material "
                            "must be assumed compromised.",
                evidence=f"{host}:{port} on {heartbleed.get('sslversion')}",
                port=port, protocol="tcp", seen_at=seen_at,
            )
            created += 1

    weak = [
        c for c in root.iter("cipher")
        if (c.get("strength") or "").lower() in ("weak", "null", "broken")
    ]
    if weak:
        names = ", ".join(sorted({c.get("cipher", "?") for c in weak})[:8])
        upsert(
            db, f"{base}|ciphers",
            device_id=device_id, kind="tls-ciphers", severity=MEDIUM,
            title=f"{device_name} accepts weak TLS ciphers",
            detail=f"{len(weak)} cipher suite(s) rated weak or broken are accepted, so a "
                   "client can be steered onto cryptography that no longer protects traffic.",
            remediation="Restrict the cipher list to forward-secret AEAD suites "
                        "(ECDHE with AES-GCM or ChaCha20-Poly1305) and drop the rest.",
            evidence=names, port=port, protocol="tcp", seen_at=seen_at,
        )
        created += 1

    for certificate in root.iter("certificate"):
        def text(tag: str) -> str | None:
            node = certificate.find(tag)
            return (node.text or "").strip() if node is not None and node.text else None

        subject = text("subject") or host
        expires = _parse_date(text("not-valid-after"))
        now = datetime.now(UTC)

        if text("expired") == "true":
            upsert(
                db, f"{base}|cert-expired",
                device_id=device_id, kind="tls-certificate", severity=MEDIUM,
                title=f"{device_name} serves an expired certificate",
                detail=f"The certificate for {subject} expired"
                       + (f" on {expires.date()}" if expires else "")
                       + ". Clients show security warnings, which trains people to click through them.",
                remediation="Renew the certificate. If it is self-managed, automate renewal so "
                            "it cannot lapse again.",
                evidence=f"{host}:{port} — subject {subject}",
                port=port, protocol="tcp", seen_at=seen_at,
            )
            created += 1
        elif expires is not None:
            days = (expires - now).days
            if 0 <= days <= 30:
                upsert(
                    db, f"{base}|cert-expiring",
                    device_id=device_id, kind="tls-certificate", severity=LOW,
                    title=f"{device_name} certificate expires in {days} day(s)",
                    detail=f"The certificate for {subject} expires on {expires.date()}.",
                    remediation="Renew it before it lapses, and automate renewal if possible.",
                    evidence=f"{host}:{port} — subject {subject}",
                    port=port, protocol="tcp", seen_at=seen_at,
                )
                created += 1

        if text("self-signed") == "true":
            upsert(
                db, f"{base}|cert-self-signed",
                device_id=device_id, kind="tls-certificate", severity=LOW,
                title=f"{device_name} uses a self-signed certificate",
                detail="Nothing verifies the identity behind this certificate, so a "
                       "man-in-the-middle cannot be distinguished from the real service. "
                       "Common and often acceptable on internal appliances.",
                remediation="Issue a certificate from an internal CA that your clients trust, "
                            "or accept the risk deliberately for this device.",
                evidence=f"{host}:{port} — subject {subject}",
                port=port, protocol="tcp", seen_at=seen_at,
            )
            created += 1

        algorithm = (text("signature-algorithm") or "").lower()
        if any(bad in algorithm for bad in ("md5", "sha1")):
            upsert(
                db, f"{base}|cert-signature",
                device_id=device_id, kind="tls-certificate", severity=MEDIUM,
                title=f"{device_name} certificate uses a broken signature algorithm",
                detail=f"The certificate is signed with {algorithm}, for which practical "
                       "collision attacks exist, so the signature no longer proves authenticity.",
                remediation="Reissue the certificate with SHA-256 or better.",
                evidence=f"{host}:{port} — {algorithm}",
                port=port, protocol="tcp", seen_at=seen_at,
            )
            created += 1

    return created


def audit(
    db: AtlasDB, *, seen_at: str | None = None, on_progress: Any = None
) -> dict[str, int]:
    """Probe every plausible TLS endpoint on the online inventory."""
    seen_at = seen_at or utc_now()
    if not available():
        return {"scanned": 0, "findings": 0}

    placeholders = ",".join("?" for _ in TLS_PORTS)
    rows = db.conn.execute(
        f"""SELECT s.device_id, s.port,
                   COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) device_name,
                   (SELECT a.address FROM addresses a
                     WHERE a.device_id = s.device_id AND a.family='ipv4'
                     ORDER BY a.last_seen DESC LIMIT 1) address
            FROM services s JOIN devices d ON d.id = s.device_id
            WHERE s.state LIKE 'open%' AND d.status='online' AND s.protocol='tcp'
              AND (s.port IN ({placeholders})
                   OR s.name LIKE '%https%' OR s.name LIKE '%ssl%' OR s.name LIKE '%tls%')
            ORDER BY s.device_id, s.port""",
        TLS_PORTS,
    ).fetchall()

    scanned = created = 0
    for index, row in enumerate(rows, start=1):
        host = row["address"]
        if not host:
            continue
        if on_progress:
            on_progress(
                100.0 * index / max(len(rows), 1),
                f"TLS check {host}:{row['port']} ({row['device_name']})",
            )
        root = _scan(host, int(row["port"]))
        scanned += 1
        if root is None:
            continue
        created += _evaluate(
            db, int(row["device_id"]), row["device_name"], host, int(row["port"]), root, seen_at
        )
    db.commit()
    return {"scanned": scanned, "findings": created}
