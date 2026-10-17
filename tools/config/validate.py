#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate platform configuration, JSON Schemas and repo-contract templates.

Complements tools/catalogue/validate.py (which owns the control catalogue). Checks:
  * every JSON Schema under schemas/ is itself a valid Draft 2020-12 schema
  * repo-contract templates validate against their schemas
  * threat-model templates are internally consistent (threat/asset/flow/boundary references resolve)
  * config cross-references: trusted producers and SIEM events, SAMM targets vs SAMM ids,
    exception policy completeness, classification and risk-model structure, licence-policy disjointness,
    maturity bands, ASVS applicability chapters
  * OpenAPI document validity (if openapi-spec-validator is installed)

Usage: python3 tools/config/validate.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates/repo-contract"
TIERS = {"1", "2", "3", "4"}
PRIORITIES = {"P1", "P2", "P3", "P4"}


def load(rel: str):
    with (ROOT / rel).open() as f:
        return stringify_keys(yaml.safe_load(f))


def stringify_keys(node):
    if isinstance(node, dict):
        return {str(k): stringify_keys(v) for k, v in node.items()}
    if isinstance(node, list):
        return [stringify_keys(v) for v in node]
    return node


def schema_errors(schema: dict, instance, label: str) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{label}: {'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator.iter_errors(instance)]


# ---------------------------------------------------------------- schemas and templates

def check_schemas() -> list[str]:
    errors = []
    for path in sorted((ROOT / "schemas").rglob("*.json")):
        try:
            jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))
        except (json.JSONDecodeError, jsonschema.SchemaError) as e:
            errors.append(f"{path.relative_to(ROOT)}: invalid schema: {e}")
    return errors


def check_templates() -> list[str]:
    schemas = ROOT / "schemas/repo-contract"
    app_schema = json.loads((schemas / "application.schema.json").read_text())
    asvs_schema = json.loads((schemas / "asvs.schema.json").read_text())
    tm_schema = json.loads((schemas / "threat-model.schema.json").read_text())
    errors = schema_errors(app_schema, load("templates/repo-contract/.security/application.yaml"), "application.yaml")
    errors += schema_errors(asvs_schema, load("templates/repo-contract/.security/asvs.yaml"), "asvs.yaml")
    tm_files = {"assets.yaml": "assetsFile", "threats.yaml": "threatsFile",
                "mitigations.yaml": "mitigationsFile", "residual-risk.yaml": "residualRiskFile"}
    for name, ref in tm_files.items():
        sub = {"$schema": tm_schema["$schema"], "$defs": tm_schema["$defs"], "$ref": f"#/$defs/{ref}"}
        errors += schema_errors(sub, load(f"templates/repo-contract/.security/threat-model/{name}"), name)
    return errors + check_threat_model_refs()


def check_threat_model_refs() -> list[str]:
    tm = "templates/repo-contract/.security/threat-model/"
    elements = load(tm + "assets.yaml")
    threats = load(tm + "threats.yaml")["threats"]
    assets = {a["id"] for a in elements["assets"]}
    flows = {f["id"] for f in elements.get("data_flows", [])}
    boundaries = {b["id"] for b in elements.get("trust_boundaries", [])}
    threat_ids = {t["id"] for t in threats}
    errors = []
    for f in elements.get("data_flows", []):
        errors += [f"assets.yaml {f['id']}: unknown asset {a}" for a in f["data"] if a not in assets]
        errors += [f"assets.yaml {f['id']}: unknown boundary {b}" for b in f.get("crosses", []) if b not in boundaries]
    for t in threats:
        errors += [f"threats.yaml {t['id']}: unknown asset {a}" for a in t.get("assets", []) if a not in assets]
        errors += [f"threats.yaml {t['id']}: unknown flow {d}" for d in t.get("flows", []) if d not in flows]
    for m in load(tm + "mitigations.yaml")["mitigations"]:
        if m["threat"] not in threat_ids:
            errors.append(f"mitigations.yaml: unknown threat {m['threat']}")
    for r in load(tm + "residual-risk.yaml")["residual_risks"]:
        if r["threat"] not in threat_ids:
            errors.append(f"residual-risk.yaml: unknown threat {r['threat']}")
    flow_text = (ROOT / tm / "data-flow.md").read_text()
    errors += [f"data-flow.md: flow {d} drawn but not defined in assets.yaml"
               for d in sorted(set(re.findall(r"\bDF-[0-9]{2,3}\b", flow_text))) if d not in flows]
    return errors


# ---------------------------------------------------------------- config cross-references

def evidence_types() -> set[str]:
    return set(load("config/evidence-types.yaml")["types"])


def samm_practices() -> set[str]:
    samm = load("catalogue/frameworks/samm.yaml")
    return {p["id"] for bf in samm["business_functions"] for p in bf["practices"]}


def check_trusted_producers() -> list[str]:
    tp = load("config/trusted-producers.yaml")
    known = evidence_types()
    errors = []
    for wf in tp["workflows"]:
        errors += [f"trusted-producers {wf['path']}: unknown evidence type {t}" for t in wf["evidence_types"] if t not in known]
    for c in tp["connectors"]:
        errors += [f"trusted-producers connector {c['id']}: unknown evidence type {t}" for t in c["evidence_types"] if t not in known]
    covered = {t for wf in tp["workflows"] for t in wf["evidence_types"]} | {t for c in tp["connectors"] for t in c["evidence_types"]}
    errors += [f"evidence type {t} has no trusted producer" for t in sorted(known - covered)]
    return errors


def check_samm_targets() -> list[str]:
    targets = load("config/samm-targets.yaml")
    practices = samm_practices()
    app_practices = {p for p in practices if not p.startswith("G-")}
    errors = []
    for tier, values in targets["application_targets"].items():
        if tier not in TIERS:
            errors.append(f"samm-targets: unknown tier {tier}")
        missing, unknown = app_practices - set(values), set(values) - app_practices
        errors += [f"samm-targets tier {tier}: missing practice {p}" for p in sorted(missing)]
        errors += [f"samm-targets tier {tier}: unknown practice {p}" for p in sorted(unknown)]
        errors += [f"samm-targets tier {tier} {p}: {v} outside 0..3" for p, v in values.items() if not 0 <= v <= 3]
    errors += check_tier_monotonic(targets["application_targets"])
    org = set(targets["organisation_targets"])
    errors += [f"samm-targets organisation: unknown practice {p}" for p in sorted(org - practices)]
    return errors


def check_tier_monotonic(targets: dict) -> list[str]:
    # A more critical tier must never have a lower target than a less critical one.
    errors = []
    for p in targets["1"]:
        values = [targets[t][p] for t in ("1", "2", "3", "4")]
        if values != sorted(values, reverse=True):
            errors.append(f"samm-targets {p}: targets not non-increasing from Tier 1 to Tier 4: {values}")
    return errors


def check_exception_policy() -> list[str]:
    ep = load("config/exception-policy.yaml")
    roles = set(ep["approver_roles"])
    errors = []
    if set(ep["approval_matrix"]) != PRIORITIES:
        errors.append("exception-policy: approval_matrix must cover P1..P4")
    for prio, row in ep["approval_matrix"].items():
        if set(row) != TIERS:
            errors.append(f"exception-policy {prio}: must cover tiers 1..4")
        errors += [f"exception-policy {prio}/T{t}: unknown role {r}" for t, r in row.items() if r not in roles]
        ranks = [ep["role_rank"][row[t]] for t in ("1", "2", "3", "4") if row.get(t) in ep["role_rank"]]
        if ranks != sorted(ranks, reverse=True):
            errors.append(f"exception-policy {prio}: approver seniority must not increase for less critical tiers")
    if set(ep["max_duration_days"]) != PRIORITIES:
        errors.append("exception-policy: max_duration_days must cover P1..P4")
    return errors


def check_siem_events() -> list[str]:
    ev = load("config/siem-events.yaml")
    types = [e["type"] for e in ev["events"]]
    errors = [f"siem-events: duplicate type {t}" for t in sorted({t for t in types if types.count(t) > 1})]
    allowed = {"informational", "low", "medium", "high"}
    errors += [f"siem-events {e['type']}: bad severity {e['severity']}" for e in ev["events"] if e["severity"] not in allowed]
    return errors


def check_classification() -> list[str]:
    errors: list[str] = []
    for path in sorted((ROOT / "config/profiles").glob("*/classification.yaml")):
        errors += [f"{path.parent.name}: {e}" for e in _check_one_classification(load(str(path.relative_to(ROOT))))]
    org = load("config/organization.yaml")
    levels = [lv.get("type") for lv in org.get("levels") or []]
    if not levels:
        errors.append("organization.yaml: at least one level is required")
    if len(set(levels)) != len(levels):
        errors.append("organization.yaml: level types must be unique")
    errors += [f"organization.yaml: level {t!r} must match ^[a-z][a-z0-9_]{{1,31}}$" for t in levels
               if not re.match(r"^[a-z][a-z0-9_]{1,31}$", str(t))]
    if not (ROOT / "config/profiles" / str(org.get("profile")) / "classification.yaml").exists():
        errors.append(f"organization.yaml: profile {org.get('profile')!r} has no config/profiles/<profile>/classification.yaml")
    return errors


def _check_one_classification(cl: dict) -> list[str]:
    dims = cl["dimensions"]
    errors = []
    for rule in cl["floor_rules"]:
        for dim, values in rule["when"].items():
            if dim not in dims:
                errors.append(f"classification {rule['id']}: unknown dimension {dim}")
                continue
            errors += [f"classification {rule['id']}: {dim} has no option {v}" for v in values if v not in dims[dim]["options"]]
    mins = [t["min_points"] for t in cl["points_thresholds"]]
    if mins != sorted(mins, reverse=True) or mins[-1] != 0:
        errors.append("classification: points_thresholds must be descending and end at 0")
    return errors


def check_risk_model() -> list[str]:
    rm = load("config/risk-model.yaml")
    errors = []
    mins = [b["min_score"] for b in rm["bands"]]
    if mins != sorted(mins, reverse=True) or mins[-1] != 1:
        errors.append("risk-model: bands must be descending and end at 1")
    for kind in ("triage", "remediate"):
        if set(rm["sla"][kind]) != PRIORITIES:
            errors.append(f"risk-model: sla.{kind} must cover P1..P4")
        days = [rm["sla"][kind][p] for p in ("P1", "P2", "P3", "P4")]
        if days != sorted(days):
            errors.append(f"risk-model: sla.{kind} must not shorten for lower priorities")
    if set(rm["impact"]["base"]["from_tier"]) != TIERS:
        errors.append("risk-model: impact.base.from_tier must cover tiers 1..4")
    return errors


def check_licence_policy() -> list[str]:
    lp = load("config/licence-policy.yaml")
    groups = {k: set(lp[k]) for k in ("allow", "review", "deny")}
    errors = []
    for a, b in (("allow", "review"), ("allow", "deny"), ("review", "deny")):
        errors += [f"licence-policy: {lic} in both {a} and {b}" for lic in sorted(groups[a] & groups[b])]
    return errors


def check_maturity_and_asvs() -> list[str]:
    mm = load("config/maturity-methodology.yaml")
    errors = []
    mins = [b["min_fraction"] for b in mm["answer_bands"]]
    if mins != sorted(mins, reverse=True) or mins[-1] != 0:
        errors.append("maturity-methodology: answer_bands must be descending and end at 0")
    chapters = [c["id"] for c in load("catalogue/frameworks/asvs-applicability.yaml")["chapters"]]
    if chapters != [f"V{i}" for i in range(1, 18)]:
        errors.append(f"asvs-applicability: expected V1..V17 in order, got {chapters}")
    methods = set(load("catalogue/frameworks/asvs-applicability.yaml")["default_methods"])
    errors += [f"asvs-applicability: no default method for {c}" for c in chapters if c not in methods]
    return errors


def check_openapi() -> list[str]:
    spec_path = ROOT / "schemas/api/openapi.yaml"
    if not spec_path.exists():
        return ["schemas/api/openapi.yaml missing"]
    spec = yaml.safe_load(spec_path.read_text())
    errors = check_operation_annotations(spec)
    try:
        from openapi_spec_validator import validate
    except ImportError:
        print("SKIP openapi structural validation (pip install --require-hashes -r tools/requirements.txt)")
        return errors
    try:
        validate(spec)
    except Exception as e:  # validator raises several exception types
        errors.append(f"openapi: {e}")
    return errors


def check_operation_annotations(spec: dict) -> list[str]:
    # ADR-013: every operation declares a permission; operationIds are unique (client generation).
    errors, seen = [], set()
    methods = {"get", "put", "post", "patch", "delete"}
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method not in methods:
                continue
            label = f"openapi {method.upper()} {path}"
            if not op.get("x-permission"):
                errors.append(f"{label}: missing x-permission")
            op_id = op.get("operationId")
            if not op_id:
                errors.append(f"{label}: missing operationId")
            elif op_id in seen:
                errors.append(f"{label}: duplicate operationId {op_id}")
            seen.add(op_id)
            if op.get("x-permission") == "public" and op.get("security") != []:
                errors.append(f"{label}: public operation must declare security: []")
    return errors


def main() -> int:
    checks = [check_schemas, check_templates, check_trusted_producers, check_samm_targets, check_exception_policy,
              check_siem_events, check_classification, check_risk_model, check_licence_policy,
              check_maturity_and_asvs, check_openapi]
    errors = [e for check in checks for e in check()]
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK {len(checks)} config/schema check groups passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
