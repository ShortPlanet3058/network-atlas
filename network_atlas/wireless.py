"""Wi-Fi survey: which access point each wireless device is associated with.

This is the one collector that cannot run unattended, and it is deliberately
CLI-only:

  * it requires root, because putting a card into monitor mode is a privileged
    operation that file capabilities do not cover;
  * it disconnects the interface for the duration of the survey, so a viewer that
    started it in the background would take the network down under the operator.

In exchange it supplies what nothing else can: the association between a client
and its access point, signal strength, and the evidence needed to spot an access
point advertising a network it should not.
"""

from __future__ import annotations

import csv
import glob
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .util import clean_text, normalize_mac


SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]+$")


class WirelessError(RuntimeError):
    pass


def available() -> tuple[bool, str]:
    """Whether a survey can run here, and why not when it cannot."""
    for binary in ("airmon-ng", "airodump-ng", "iw"):
        if not shutil.which(binary):
            return False, f"Required command not found: {binary}"
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False, (
            "A Wi-Fi survey needs root: monitor mode is a privileged operation. "
            "Re-run with sudo."
        )
    return True, "ready"


def wireless_interfaces() -> list[str]:
    binary = shutil.which("iw")
    if not binary:
        return []
    try:
        process = subprocess.run(
            [binary, "dev"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return re.findall(r"^\s*Interface\s+(\S+)", process.stdout, re.M)


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )


def _monitor_name(output: str, interface: str) -> str:
    """airmon-ng reports the monitor interface it created; fall back to convention."""
    match = re.search(r"monitor mode (?:vif )?enabled (?:for \S+ )?on \[?\w*\]?(\S+)", output)
    if match:
        return match.group(1).strip("]")
    match = re.search(r"\(monitor mode enabled(?: on (\S+))?\)", output)
    if match and match.group(1):
        return match.group(1)
    return f"{interface}mon"


def parse_csv(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse airodump-ng's CSV: an access-point section, then a station section."""
    text = path.read_text(encoding="utf-8", errors="replace")
    access_points: list[dict[str, Any]] = []
    stations: list[dict[str, Any]] = []
    section = None

    for row in csv.reader(text.splitlines()):
        cells = [cell.strip() for cell in row]
        if not cells or not cells[0]:
            continue
        if cells[0] == "BSSID" and "ESSID" in cells:
            section = "ap"
            continue
        if cells[0].startswith("Station MAC"):
            section = "station"
            continue
        if section == "ap" and len(cells) >= 14:
            bssid = normalize_mac(cells[0])
            if not bssid:
                continue
            access_points.append({
                "bssid": bssid,
                "channel": _int(cells[3]),
                "privacy": clean_text(cells[5], 40),
                "cipher": clean_text(cells[6], 40),
                "authentication": clean_text(cells[7], 40),
                "signal": _int(cells[8]),
                "beacons": _int(cells[9]),
                "ssid": clean_text(cells[13], 64),
            })
        elif section == "station" and len(cells) >= 6:
            station = normalize_mac(cells[0])
            bssid = normalize_mac(cells[5])
            if not station:
                continue
            stations.append({
                "mac": station,
                "signal": _int(cells[3]),
                "packets": _int(cells[4]),
                "bssid": bssid,
                "probed": clean_text(",".join(cells[6:]), 200) or None,
            })
    return {"access_points": access_points, "stations": stations}


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def survey(interface: str, duration: int = 45, *, band: str = "abg") -> dict[str, Any]:
    """Run a monitor-mode survey and restore the interface afterwards.

    The restore runs in a finally block: leaving the operator's card in monitor
    mode would silently take their network down, which is a far worse outcome than
    a failed survey.
    """
    ready, reason = available()
    if not ready:
        raise WirelessError(reason)
    if not SAFE_INTERFACE.match(interface or ""):
        raise WirelessError(f"Invalid interface name: {interface!r}")
    if interface not in wireless_interfaces():
        raise WirelessError(
            f"{interface} is not a wireless interface. Available: "
            + (", ".join(wireless_interfaces()) or "none")
        )
    duration = max(10, min(duration, 600))
    if band not in ("a", "b", "g", "bg", "abg"):
        raise WirelessError(f"Invalid band: {band!r}")

    airmon = shutil.which("airmon-ng")
    airodump = shutil.which("airodump-ng")
    monitor = None
    try:
        start = _run([airmon, "start", interface], 60)
        monitor = _monitor_name(start.stdout + start.stderr, interface)
        if monitor not in wireless_interfaces():
            raise WirelessError(
                "Could not enable monitor mode. Output: "
                + (clean_text(start.stdout + start.stderr, 300) or "no output")
            )
        with tempfile.TemporaryDirectory(prefix="atlas-wifi-") as directory:
            prefix = Path(directory) / "survey"
            process = subprocess.Popen(
                [
                    airodump, "--band", band, "--output-format", "csv",
                    "--write", str(prefix), "--write-interval", "5", monitor,
                ],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                process.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
            files = sorted(glob.glob(f"{prefix}-*.csv"))
            if not files:
                raise WirelessError("airodump-ng produced no output")
            result = parse_csv(Path(files[-1]))
    finally:
        if monitor:
            # Best effort, and never allowed to mask the original error.
            try:
                _run([airmon, "stop", monitor], 60)
            except (OSError, subprocess.TimeoutExpired):
                pass
    result["interface"] = interface
    result["duration"] = duration
    return result


def rogue_access_points(access_points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SSIDs advertised by more than one BSSID.

    Legitimate on a mesh or multi-AP network, and exactly what an impersonating
    access point looks like -- so this reports the grouping and leaves the
    judgement to someone who knows the network.
    """
    by_ssid: dict[str, list[dict[str, Any]]] = {}
    for access_point in access_points:
        ssid = access_point.get("ssid")
        if not ssid:
            continue
        by_ssid.setdefault(ssid, []).append(access_point)
    return [
        {"ssid": ssid, "bssids": [entry["bssid"] for entry in entries], "count": len(entries)}
        for ssid, entries in by_ssid.items()
        if len(entries) > 1
    ]
