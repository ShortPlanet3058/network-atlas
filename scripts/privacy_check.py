#!/usr/bin/env python3
"""Fail when Git tracks files that commonly contain private network data."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


BLOCKED_NAMES = {
    ".env",
    "switches.json",
    "config.json",
}
BLOCKED_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
    ".pem",
    ".key",
    ".nmap",
    ".gnmap",
}
BLOCKED_PARTS = {"__pycache__", "scans"}
CONTENT_RULES = {
    "absolute home-directory path": re.compile(rb"(?:/home/|/Users/)[A-Za-z0-9._-]+/"),
    "Windows user-directory path": re.compile(rb"[A-Za-z]:\\Users\\[^\\\r\n]+\\"),
    "SQLite database": re.compile(rb"^SQLite format 3\x00"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    )
    return [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


def main() -> int:
    problems: list[str] = []
    for path in tracked_files():
        pure = PurePosixPath(path.as_posix())
        lower_name = pure.name.lower()
        lower_suffix = pure.suffix.lower()
        if lower_name in BLOCKED_NAMES or lower_suffix in BLOCKED_SUFFIXES:
            problems.append(f"blocked tracked file: {pure}")
            continue
        if BLOCKED_PARTS.intersection(pure.parts):
            problems.append(f"private/generated directory is tracked: {pure}")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"cannot read tracked file {pure}: {exc}")
            continue
        for label, pattern in CONTENT_RULES.items():
            if pattern.search(data):
                problems.append(f"{label} found in {pure}")

    if problems:
        print("Privacy check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"Privacy check passed for {len(tracked_files())} tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
