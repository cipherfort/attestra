#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate the control catalogue and render docs/standards/control-catalogue.md.

Checks beyond JSON Schema:
  * control IDs unique and prefixed with their domain
  * every SAMM stream reference exists in catalogue/frameworks/samm.yaml
  * every evidence type exists in config/evidence-types.yaml
  * min_confidence is reachable by at least one of the control's evidence types
    (a control demanding C3 from evidence that can only ever be C1 is unsatisfiable)
  * manual-mode controls do not claim automated-only confidence, and vice versa

Usage:  python3 tools/catalogue/validate.py [--check]
        --check  validate and verify the rendered markdown is up to date (CI mode)
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = ROOT / "catalogue/controls/controls.yaml"
SCHEMA = ROOT / "schemas/catalogue/controls.schema.json"
SAMM = ROOT / "catalogue/frameworks/samm.yaml"
EVIDENCE_TYPES = ROOT / "config/evidence-types.yaml"
OUTPUT = ROOT / "docs/standards/control-catalogue.md"

AUTOMATED_ORDER = ["C0", "C1", "C2", "C3"]
MANUAL_ORDER = ["M1", "M2"]


def stringify_keys(node):
    # YAML reads tier keys (1..4) as ints; JSON Schema object keys are always strings.
    if isinstance(node, dict):
        return {str(k): stringify_keys(v) for k, v in node.items()}
    if isinstance(node, list):
        return [stringify_keys(v) for v in node]
    return node


def load_yaml(path: Path):
    with path.open() as f:
        return stringify_keys(yaml.safe_load(f))


def reachable(required: str, type_maxima: list[str]) -> bool:
    order = AUTOMATED_ORDER if required in AUTOMATED_ORDER else MANUAL_ORDER
    return any(m in order and order.index(m) >= order.index(required) for m in type_maxima)


def check_confidence(cid: str, c: dict, types: dict) -> list[str]:
    a = c["assessment"]
    maxima = [types[t]["confidence_max"] for t in a["evidence_types"]]
    required = a["min_confidence"]
    required_values = set(required.values()) if isinstance(required, dict) else {required}
    errors = []
    for r in sorted(required_values):
        if not reachable(r, maxima):
            errors.append(f"{cid}: min_confidence {r} unreachable from evidence types {a['evidence_types']} (max {maxima})")
        if a["mode"] == "manual" and r in AUTOMATED_ORDER:
            errors.append(f"{cid}: manual control cannot require automated confidence {r}")
        if a["mode"] == "automated" and r in MANUAL_ORDER:
            errors.append(f"{cid}: automated control cannot require manual confidence {r}")
    if isinstance(required, dict):
        applicable = {t for t, lvl in c["applicability"]["tiers"].items() if lvl != "n/a"}
        missing = applicable - set(required)
        if missing:
            errors.append(f"{cid}: per-tier min_confidence missing tiers {sorted(missing)}")
    return errors


def check_control(c: dict, streams: set[str], types: dict) -> list[str]:
    cid = c["id"]
    errors = []
    if not cid.startswith(f"ASC-{c['domain']}-"):
        errors.append(f"{cid}: id prefix does not match domain {c['domain']}")
    errors += [f"{cid}: unknown SAMM stream {m['stream']}" for m in c["mappings"].get("samm", []) if m["stream"] not in streams]
    unknown = [t for t in c["assessment"]["evidence_types"] if t not in types]
    errors += [f"{cid}: unknown evidence type {t}" for t in unknown]
    if not unknown:
        errors += check_confidence(cid, c, types)
    return errors


def validate(catalogue, samm, evidence_types) -> list[str]:
    schema = yaml.safe_load(SCHEMA.read_text())
    errors = [
        f"schema: {'/'.join(map(str, err.absolute_path))}: {err.message}"
        for err in jsonschema.Draft202012Validator(schema).iter_errors(catalogue)
    ]
    if errors:
        return errors  # structural errors make the semantic checks unreliable

    streams = {s["id"] for bf in samm["business_functions"] for p in bf["practices"] for s in p["streams"]}
    ids = [c["id"] for c in catalogue["controls"]]
    errors += [f"{cid}: duplicate id" for cid in sorted({i for i in ids if ids.count(i) > 1})]
    for c in catalogue["controls"]:
        errors += check_control(c, streams, evidence_types["types"])
    return errors


def fmt_conf(value) -> str:
    if isinstance(value, dict):
        return " / ".join(f"T{k}:{v}" for k, v in sorted(value.items()))
    return value


def tier_cell(level: str) -> str:
    return {"mandatory": "M", "recommended": "R", "n/a": "–"}[level]


def render_summary(controls: list[dict], w) -> None:
    w("## Summary\n")
    w("| ID | Control | Type | T1 | T2 | T3 | T4 | Mode | Min confidence | Evidence | SAMM | SSDF |")
    w("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for c in controls:
        t = c["applicability"]["tiers"]
        a = c["assessment"]
        samm_refs = ", ".join(f"{m['stream']}{m['level']}" for m in c["mappings"].get("samm", []))
        tiers = " | ".join(tier_cell(t.get(k, "n/a")) for k in ("1", "2", "3", "4"))
        w(
            f"| [{c['id']}](#{c['id'].lower()}) | {c['title']} | {c['objective_type']} | {tiers} | "
            f"{a['mode']} | {fmt_conf(a['min_confidence'])} | {', '.join(a['evidence_types'])} | {samm_refs} | "
            f"{', '.join(c['mappings'].get('ssdf', []))} |"
        )


def render_samm_coverage(controls: list[dict], samm: dict, w) -> None:
    w("\n## SAMM coverage by controls\n")
    w("Which SAMM stream levels have at least one control producing evidence. A gap (·) means that activity can only be assessed manually (SAMM interview). That is expected for much of Governance.\n")
    w("| Practice | Stream | L1 | L2 | L3 |")
    w("|---|---|---|---|---|")
    covered = defaultdict(set)
    for c in controls:
        for m in c["mappings"].get("samm", []):
            covered[(m["stream"], m["level"])].add(c["id"])
    for bf in samm["business_functions"]:
        for p in bf["practices"]:
            for s in p["streams"]:
                cells = [", ".join(sorted(covered.get((s["id"], lvl), []))) or "·" for lvl in (1, 2, 3)]
                w(f"| {bf['name']} / {p['name']} | {s['id']} {s['name']} | " + " | ".join(cells) + " |")


def mapping_refs(mp: dict) -> str:
    refs = []
    if mp.get("samm"):
        refs.append("SAMM: " + ", ".join(f"{m['stream']} L{m['level']}" for m in mp["samm"]))
    for key, label in (("asvs", "ASVS 5.0"), ("ssdf", "SSDF"), ("csf", "CSF 2.0"), ("other", "Other")):
        if mp.get(key):
            refs.append(f"{label}: {', '.join(mp[key])}")
    return " · ".join(refs)


def render_detail(c: dict, defaults: dict, w) -> None:
    a = c["assessment"]
    exc = c.get("exception", defaults["exception"])
    conds = c["applicability"].get("conditions")
    w(f"### {c['id']}\n")
    w(f"**{c['title']}** · domain `{c['domain']}` · {c['objective_type']} · owner `{c.get('owner', defaults['owner'])}` · review every {c.get('review_months', defaults['review_months'])} months\n")
    w(f"{c['description'].strip()}\n")
    w(f"- **Rationale:** {c['rationale'].strip()}")
    w(f"- **Applies when:** {', '.join(conds) if conds else 'always'}")
    w(f"- **Assessment:** {a['mode']} · evaluator `{a['evaluator']}` · min confidence {fmt_conf(a['min_confidence'])} · evidence {', '.join(f'`{e}`' for e in a['evidence_types'])}")
    if a.get("params"):
        w(f"- **Parameters:** `{yaml.safe_dump(a['params'], default_flow_style=True, width=1000).strip()}`")
    w(f"- **How we prove it operates:** {c['proof'].strip()}")
    w(f"- **Implementation:** {c['implementation'].strip()}")
    w(f"- **Remediation:** {c['remediation'].strip()}")
    if exc["allowed"]:
        md = exc.get("max_days", defaults["exception"]["max_days"])
        w(f"- **Exceptions:** allowed, max days {' / '.join(f'T{k}:{v}' for k, v in sorted(md.items()))}")
    else:
        w("- **Exceptions:** not permitted")
    w(f"- **Mappings:** {mapping_refs(c['mappings'])}")
    if c.get("notes"):
        w(f"- **Notes:** {c['notes'].strip()}")
    w("")


def render(catalogue, samm) -> str:
    controls = catalogue["controls"]
    out: list[str] = []
    w = out.append
    w("# Control Catalogue (rendered)\n")
    w("> **Generated** from `catalogue/controls/controls.yaml` by `tools/catalogue/validate.py`. Do not edit by hand.  ")
    w(f"> Catalogue version **{catalogue['catalogue_version']}**: the default catalogue: review and adapt it with your control owner.  ")
    w("> Tier columns: **M** mandatory · **R** recommended · **–** not applicable.  ")
    w("> Mappings are framework references. Control wording, thresholds and evidence rules are organisation-specific.\n")
    by_mode = defaultdict(int)
    for c in controls:
        by_mode[c["assessment"]["mode"]] += 1
    w(f"**{len(controls)} controls**: {by_mode['automated']} automated, {by_mode['hybrid']} hybrid, {by_mode['manual']} manual.\n")
    render_summary(controls, w)
    render_samm_coverage(controls, samm, w)
    w("\n## Control detail\n")
    for c in controls:
        render_detail(c, catalogue["defaults"], w)
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if rendered output is stale")
    args = parser.parse_args()

    catalogue = load_yaml(CATALOGUE)
    samm = load_yaml(SAMM)
    evidence_types = load_yaml(EVIDENCE_TYPES)

    errors = validate(catalogue, samm, evidence_types)
    if errors:
        for e in errors:
            print(f"ERROR {e}", file=sys.stderr)
        return 1

    rendered = render(catalogue, samm)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print(f"ERROR {OUTPUT.relative_to(ROOT)} is stale; run tools/catalogue/validate.py", file=sys.stderr)
            return 1
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered)
    print(f"OK {len(catalogue['controls'])} controls valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
