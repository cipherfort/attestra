#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate config/metrics.yaml and render docs/standards/kpi-kri-catalogue.md.

Usage: python3 tools/metrics/render.py [--check]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "config/metrics.yaml"
OUTPUT = ROOT / "docs/standards/kpi-kri-catalogue.md"
REQUIRED = {"id", "name", "kind", "category", "definition", "unit", "frequency", "owner"}
CATEGORIES = ["coverage", "pipeline", "vulnerability", "maturity", "evidence", "people", "risk"]


def validate(metrics: list[dict]) -> list[str]:
    errors = []
    ids = Counter(m.get("id") for m in metrics)
    errors += [f"duplicate id {i}" for i, n in ids.items() if n > 1]
    for m in metrics:
        mid = m.get("id", "?")
        errors += [f"{mid}: missing {f}" for f in sorted(REQUIRED - set(m))]
        if m.get("kind") == "kri" and "threshold" not in m:
            errors.append(f"{mid}: KRI needs a threshold")
        if m.get("kind") == "kpi" and "target" not in m:
            errors.append(f"{mid}: KPI needs a target")
        if m.get("kind") in ("kpi", "context") and "anti_gaming" not in m:
            errors.append(f"{mid}: KPI/context metric needs an anti_gaming note")
        if m.get("category") not in CATEGORIES:
            errors.append(f"{mid}: unknown category {m.get('category')}")
    return errors


def fmt_target(m: dict) -> str:
    if "threshold" in m:
        return f"escalate if {m['threshold']}"
    target = m.get("target")
    if not target:
        return "–"
    return ", ".join(f"{k}: {v}" for k, v in target.items())


def render(doc: dict) -> str:
    metrics = doc["metrics"]
    lines = [
        "# KPI / KRI Catalogue (rendered)\n",
        "> **Generated** from `config/metrics.yaml` by `tools/metrics/render.py`. Do not edit by hand.  ",
        "> Status: DESIGNED. Targets and thresholds are PROPOSED and need Governance Board approval.\n",
        "Design rules: no metric rewards finding fewer issues; every metric is computed by the platform from its ledgers; "
        "reporting is at team, application or directorate level, **never per person** "
        "([TOM §7](../../adoption-kit/governance/target-operating-model.md#7-how-the-tom-avoids-gaming)).\n",
        f"**{len(metrics)} metrics**: "
        + ", ".join(f"{n} {k.upper() if k != 'context' else 'context'}" for k, n in Counter(m['kind'] for m in metrics).items())
        + ".\n",
    ]
    for cat in CATEGORIES:
        group = [m for m in metrics if m["category"] == cat]
        if not group:
            continue
        lines.append(f"## {cat.capitalize()}\n")
        lines.append("| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for m in group:
            lines.append(
                f"| {m['id']} | {m['name']} | {m['kind']} | {m['definition']} | {m['unit']} | {fmt_target(m)} | "
                f"{m['frequency']} | {m['owner']} | {m.get('anti_gaming', '–')} |"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    doc = yaml.safe_load(SOURCE.read_text())
    errors = validate(doc["metrics"])
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    if errors:
        return 1
    rendered = render(doc)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print(f"ERROR {OUTPUT.relative_to(ROOT)} is stale; run tools/metrics/render.py", file=sys.stderr)
            return 1
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered)
    print(f"OK {len(doc['metrics'])} metrics valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
