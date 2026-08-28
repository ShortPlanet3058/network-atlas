"""Correlate detected service versions against the local exploit database.

Nmap already records a product and version for every service it fingerprints, and
Kali ships exploitdb locally, so this correlation costs nothing in privacy: no
service fingerprint ever leaves the machine. That rules out the obvious
alternative -- vulners.nse -- which POSTs the CPE of every service to a third
party.

The claim this module makes is deliberately weak. Exploit records are matched by
product name and, where possible, by version appearing in the record's title;
that is evidence worth reading, not proof of exploitability. Nothing here reports
a device as vulnerable.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from .db import AtlasDB
from .events import LOW, MEDIUM
from .findings import upsert
from .util import clean_text, utc_now


EXPLOITDB_DIR = "/usr/share/exploitdb"

# Exploit types ordered by how much a hit should worry someone.
_SERIOUS_TYPES = {"remote", "webapps"}
_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")

# Product strings that are too generic to correlate: a match would be noise.
_TOO_GENERIC = {
    "", "unknown", "http", "https", "tcpwrapped", "generic", "linux", "unix",
    "microsoft windows", "windows", "sun", "oracle", "apache", "microsoft",
}


def available() -> bool:
    return bool(shutil.which("searchsploit"))


# Daemon executable names and packaging suffixes that are not the product.
_DAEMON_WORDS = {
    "httpd", "smbd", "nmbd", "sshd", "ftpd", "telnetd", "snmpd", "named",
    "server", "daemon", "service", "d",
}
_DISTRO_WORDS = {
    "debian", "ubuntu", "raspbian", "centos", "rhel", "fedora", "suse",
    "alpine", "freebsd", "openbsd", "windows", "linux", "unix", "protocol",
}


def _candidate_terms(product: str) -> list[str]:
    """Search terms to try for one Nmap product string, best first.

    Nmap names products inconsistently: "Apache httpd" needs the daemon word kept
    to be specific, "Samba smbd" needs it dropped to match anything, and
    "MiniServ 1.830 (Webmin httpd)" hides the recognisable product in the
    parenthetical. Try each shape and use the first that returns records.
    """
    terms: list[str] = []
    strict = _normalize_product(product)
    loose = _normalize_product(product, keep_daemon_words=True)
    inner = re.findall(r"\(([^)]*)\)", product)
    for candidate in (strict, loose, *(_normalize_product(text) for text in inner)):
        if (
            candidate
            and len(candidate) >= 3
            and candidate not in _TOO_GENERIC
            and candidate not in terms
        ):
            terms.append(candidate)
    return terms


def _normalize_product(product: str, *, keep_daemon_words: bool = False) -> str:
    """Reduce Nmap's product string to a searchable name.

    Nmap reports strings like "OpenSSH 8.4p1 Debian" and "Samba smbd 4.13.13".
    Version-qualified queries almost always return nothing, because exploitdb
    titles carry their own versions, so the product name is the useful key: keep
    the words before the first version-looking token and drop daemon and distro
    noise around them.
    """
    text = re.sub(r"[^a-z0-9 .+_-]", " ", product.lower())
    words: list[str] = []
    for word in text.split():
        # The first token containing a digit begins the version; stop there.
        if any(character.isdigit() for character in word):
            break
        if word in _DISTRO_WORDS:
            continue
        if word in _DAEMON_WORDS and not keep_daemon_words:
            continue
        words.append(word)
    return " ".join(words).strip()


def _query(term: str, *, timeout: int = 45) -> list[dict[str, Any]]:
    binary = shutil.which("searchsploit")
    if not binary or not term:
        return []
    try:
        process = subprocess.run(
            [binary, "-j", "--disable-colour", term],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        payload = json.loads(process.stdout or "{}")
    except json.JSONDecodeError:
        return []
    records = payload.get("RESULTS_EXPLOIT") or []
    return [record for record in records if isinstance(record, dict)]


def _versions_in(text: str) -> set[str]:
    return set(_VERSION_RE.findall(text or ""))


def _version_matches(detected: str | None, title: str) -> bool:
    """Whether the exploit title names the detected version.

    A bare major version is rejected: matching "4" against a title would hit
    "Sambar Server 4.x", an unrelated product, and wrongly present it as an exact
    version match. At least major.minor is required for the claim to mean anything.
    """
    if not detected:
        return False
    # Upstream versions carry non-numeric suffixes ("9.6p1", "4.13.13-Ubuntu");
    # reduce each component to its leading digits so 9.6p1 matches 9.6.
    parts = [
        re.match(r"\d*", component).group(0)
        for component in detected.strip().split(".")
    ]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return False
    major_minor = ".".join(parts[:2])
    detected = ".".join(part for part in parts if part)
    for found in _versions_in(title):
        found_parts = found.split(".")
        if len(found_parts) < 2:
            continue
        if found == detected or ".".join(found_parts[:2]) == major_minor:
            return True
    return False


def _rank(records: list[dict[str, Any]], term: str) -> list[dict[str, Any]]:
    """Titles that begin with the product name first.

    Name matching alone pulls in different products that merely share a word --
    "nginx" matches "Ingress-NGINX", a separate project -- so records whose title
    actually starts with the product are shown before the incidental matches.
    """
    head = term.split()[0].lower() if term else ""

    def score(record: dict[str, Any]) -> tuple[int, str]:
        title = str(record.get("Title") or "")
        return (0 if title.lower().startswith(head) else 1, title)

    return sorted(records, key=score)


def _cves(record: dict[str, Any]) -> list[str]:
    codes = str(record.get("Codes") or "")
    return sorted({code for code in codes.split(";") if code.startswith("CVE-")})


def audit_services(
    db: AtlasDB,
    *,
    seen_at: str | None = None,
    max_records: int = 6,
    on_progress: Any = None,
) -> dict[str, int]:
    """Correlate every fingerprinted service against exploitdb."""
    seen_at = seen_at or utc_now()
    if not available():
        return {"queried": 0, "findings": 0, "skipped": 0}

    # Grouped by device and product: the same daemon on three ports is one issue,
    # not three, and listing it once with its ports reads far better.
    rows = db.conn.execute(
        """SELECT s.device_id, s.product, s.version,
                  GROUP_CONCAT(s.port || '/' || s.protocol) ports,
                  MIN(s.port) first_port, MIN(s.protocol) first_protocol,
                  COALESCE(d.manual_name,d.hostname,d.mac,'Device '||d.id) device_name
           FROM services s JOIN devices d ON d.id = s.device_id
           WHERE s.state LIKE 'open%' AND d.status='online'
             AND s.product IS NOT NULL AND s.product != ''
           GROUP BY s.device_id, s.product, s.version
           ORDER BY s.device_id, first_port"""
    ).fetchall()

    cache: dict[str, list[dict[str, Any]]] = {}
    queried = created = skipped = 0

    for index, row in enumerate(rows, start=1):
        raw_product = row["product"] or ""
        terms = _candidate_terms(raw_product)
        if not terms:
            skipped += 1
            continue
        if on_progress:
            on_progress(
                100.0 * index / max(len(rows), 1),
                f"Checking {raw_product} on {row['device_name']}",
            )
        product, records = "", []
        for candidate in terms:
            if candidate not in cache:
                cache[candidate] = _query(candidate)
                queried += 1
            if cache[candidate]:
                product, records = candidate, cache[candidate]
                break
        if not records:
            continue

        version = (row["version"] or "").strip()
        matched = [r for r in records if _version_matches(version, str(r.get("Title") or ""))]
        serious = [
            r for r in (matched or records)
            if str(r.get("Type") or "").lower() in _SERIOUS_TYPES
        ]
        # A version-specific hit on a remotely exploitable record is worth raising;
        # a product-name hit alone is a prompt to check, nothing more.
        if matched and serious:
            severity, confidence = MEDIUM, "names this exact version"
        elif matched:
            severity, confidence = LOW, "names this version, but only for local or denial-of-service issues"
        else:
            severity, confidence = LOW, "matches the product only, not the version"

        shown = _rank(matched or records, product)[:max_records]
        cves = sorted({cve for record in shown for cve in _cves(record)})
        titles = "; ".join(str(record.get("Title"))[:110] for record in shown)
        product_label = " ".join(filter(None, (row["product"], version))) or product

        ports = row["ports"] or f"{row['first_port']}/{row['first_protocol']}"
        upsert(
            db, f"exploitdb|{row['device_id']}|{product}",
            device_id=int(row["device_id"]), kind="known-exploits",
            severity=severity,
            title=f"Public exploit records exist for {product_label}",
            detail=f"The local exploit database has {len(matched or records)} record(s) for "
                   f"this product and {confidence}. Exploit records are historical: many "
                   "describe issues already fixed in your version. Treat this as a prompt to "
                   "verify the version, not as proof of a vulnerability."
                   + (f" Referenced CVEs: {', '.join(cves[:10])}." if cves else ""),
            remediation=f"Check the installed version of {row['product']} against its "
                        "current release, and update if it is behind. Inspect the matching "
                        f"records with: searchsploit {product}",
            evidence=clean_text(f"On {ports}. {titles}", 800),
            port=int(row["first_port"]), protocol=row["first_protocol"], seen_at=seen_at,
        )
        created += 1

    db.commit()
    return {"queried": queried, "findings": created, "skipped": skipped}
