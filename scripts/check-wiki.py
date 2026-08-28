#!/usr/bin/env python3
"""Validate the wiki sources: internal links, anchors, and README coverage.

Broken wiki links are invisible until someone clicks one, so they are worth
checking mechanically.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def slug(heading: str) -> str:
    """Approximate GitHub's heading-to-anchor conversion."""
    text = heading.strip().lower()
    text = re.sub(r"`|\*|_", "", text)
    text = re.sub(r"[^a-z0-9 \-]", "", text)
    return text.strip().replace(" ", "-")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    source = root / "wiki"
    if not source.is_dir():
        print("No wiki/ directory.", file=sys.stderr)
        return 1

    pages = {path.stem: path for path in sorted(source.glob("*.md"))}
    problems: list[str] = []

    for name, path in pages.items():
        text = path.read_text(encoding="utf-8")
        for target, anchor in re.findall(r"\]\(([A-Z][A-Za-z-]*)(?:#([a-z0-9-]+))?\)", text):
            if target not in pages:
                problems.append(f"{name}: link to missing page '{target}'")
                continue
            if anchor:
                headings = {
                    slug(h)
                    for h in re.findall(r"^#{1,6} (.+)$", pages[target].read_text(), re.M)
                }
                if anchor not in headings:
                    problems.append(f"{name}: '{target}#{anchor}' matches no heading")

    readme = root / "README.md"
    if readme.is_file():
        linked = set(re.findall(r"/wiki/([A-Za-z-]+)\)", readme.read_text()))
        for missing in sorted(linked - pages.keys()):
            problems.append(f"README.md: links to missing wiki page '{missing}'")
        for orphan in sorted(pages.keys() - linked - {"Home"}):
            problems.append(f"README.md: does not link wiki page '{orphan}'")

    if problems:
        print(f"Wiki check failed ({len(problems)} problem(s)):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"Wiki check passed: {len(pages)} pages, all links resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
