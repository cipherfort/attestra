#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail if any relative Markdown link or #anchor in the repository does not resolve.

Anchors are computed the way GitHub renders headings (lower-case, punctuation removed, spaces → hyphens).
Usage: python3 tools/docs/check_links.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6} (.+)$", re.M)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv"}


def slug(heading: str) -> str:
    h = re.sub(r"[`*_~]", "", heading.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def markdown_files() -> list[Path]:
    return [p for p in ROOT.rglob("*.md") if not SKIP_DIRS & set(p.relative_to(ROOT).parts)]


def main() -> int:
    files = markdown_files()
    anchors = {p.resolve(): {slug(m.group(1)) for m in HEADING.finditer(p.read_text())} for p in files}
    bad = []
    for md in files:
        for m in LINK.finditer(md.read_text()):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, anchor = target.partition("#")
            resolved = (md.parent / path).resolve() if path else md.resolve()
            rel = md.relative_to(ROOT)
            if not resolved.exists():
                bad.append(f"{rel}: missing {target}")
            elif anchor and resolved.suffix == ".md" and anchor not in anchors.get(resolved, set()):
                bad.append(f"{rel}: bad anchor {target}")
    for b in bad:
        print(f"ERROR {b}", file=sys.stderr)
    print(f"{'FAIL' if bad else 'OK'} {len(files)} markdown files checked")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
