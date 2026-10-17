#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Licence gate for the runtime dependencies this project ships (Apache-2.0 compatible only).

Backend: the runtime closure from `uv export --no-dev` (backend/uv.lock), licences read from the installed
distributions' metadata (run inside the backend environment: `uv run --project backend python tools/licenses/check.py`).
Frontend: non-dev packages in frontend/package-lock.json (lockfile v3 records each package's licence).

Policy:
  allowed   permissive (Apache, MIT, BSD, ISC, PSF, Unlicense, CC0, Zlib, 0BSD)
  allowed   weak copyleft used as an unmodified library (MPL-2.0, LGPL): Apache-2.0 compatible when not modified
  refused   strong copyleft (GPL without the LGPL, AGPL, SSPL, EUPL, OSL) and anything unrecognised
Exceptions need a reason in tools/licenses/exceptions.yaml (reviewed by a maintainer).

Usage: check.py [--list]
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PERMISSIVE = re.compile(r"\b(apache|mit|bsd|isc|psf|python software foundation|unlicense|cc0|zlib|0bsd|hpnd)\b", re.I)
WEAK = re.compile(r"\b(mpl|mozilla public|lgpl|lesser general)\b", re.I)
STRONG = re.compile(r"\b(agpl|affero|sspl|server side public|eupl|osl|(?<!l)gpl(?!.*lesser))\b", re.I)


def classify(text: str) -> str:
    if not text:
        return "unknown"
    if STRONG.search(text) and not WEAK.search(text):
        return "refused"
    if PERMISSIVE.search(text):
        return "allowed"
    if WEAK.search(text):
        return "weak-copyleft"
    return "unknown"


def licence_of(dist: metadata.Distribution) -> str:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    lic = (md.get("License") or "").strip()
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic + (f" ({', '.join(classifiers)})" if classifiers else "")
    if classifiers:
        return ", ".join(classifiers)
    for f in dist.files or []:  # only a License-File: read its first meaningful line
        if Path(str(f)).name.upper().startswith(("LICENSE", "LICENCE", "COPYING")):
            text = (dist.locate_file(f).read_text(errors="replace") if dist.locate_file(f).exists() else "").strip()
            first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
            if first:
                return f"{first[:60]} (from {Path(str(f)).name})"
    return lic[:80]


def backend() -> list[tuple[str, str]]:
    out = subprocess.run(
        ["uv", "export", "--no-dev", "--no-hashes", "--frozen", "--no-emit-project", "--project", str(ROOT / "backend")],
        check=True, capture_output=True, text=True,
    ).stdout
    names = [re.split(r"[=<>; \[]", line.strip())[0] for line in out.splitlines() if line and not line.startswith(("#", " "))]
    rows = []
    for name in sorted(set(names), key=str.lower):
        try:
            rows.append((name, licence_of(metadata.distribution(name))))
        except metadata.PackageNotFoundError:
            rows.append((name, ""))
    return rows


def frontend() -> list[tuple[str, str]]:
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    rows = []
    for path, pkg in lock.get("packages", {}).items():
        if not path or pkg.get("dev") or pkg.get("devOptional"):
            continue
        rows.append((path.split("node_modules/")[-1], str(pkg.get("license", ""))))
    return sorted(rows)


def main() -> int:
    exceptions_file = Path(__file__).with_name("exceptions.yaml")
    exceptions: dict[str, str] = {}
    if exceptions_file.exists():
        for line in exceptions_file.read_text().splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.@/-]+)\s*:\s*(.+)$", line)
            if m and not line.lstrip().startswith("#"):
                exceptions[m[1].lower()] = m[2].strip()
    problems = 0
    for ecosystem, rows in (("python", backend()), ("npm", frontend())):
        for name, lic in rows:
            verdict = classify(lic)
            if verdict in ("refused", "unknown") and name.lower() in exceptions:
                verdict = "excepted"
            if "--list" in sys.argv or verdict in ("refused", "unknown"):
                print(f"{verdict:<14} {ecosystem:<7} {name:<32} {lic}")
            problems += verdict in ("refused", "unknown")
    if problems:
        print(f"FAIL {problems} dependenc{'y' if problems == 1 else 'ies'} need review (tools/licenses/exceptions.yaml)")
        return 1
    print("OK all runtime dependencies have Apache-2.0-compatible licences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
