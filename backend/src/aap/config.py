# SPDX-License-Identifier: Apache-2.0
"""Load the governed configuration (catalogue + config/) from the repository.

Configuration is content-addressed: every bundle carries the SHA-256 of its canonical form, and every derived
record (evaluation, risk assessment, classification) stores that digest so results are reproducible (ADR-016).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml

from aap.domain.expressions import Expression, compile_expression

RISK_ROOTS = frozenset({"app", "finding", "vuln", "component", "priority", "sla_breached"})


def repo_root() -> Path:
    """The design repository root: AAP_REPO_ROOT, else the nearest ancestor holding catalogue/ and config/."""
    env = os.environ.get("AAP_REPO_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "catalogue").is_dir() and (parent / "config").is_dir():
            return parent
    raise FileNotFoundError("cannot locate repository root (set AAP_REPO_ROOT)")


def _load_yaml(path: Path) -> Any:
    with path.open() as f:
        return yaml.safe_load(f)


def digest(content: Any) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def tier_key(value: Any) -> int:
    return int(value)


@dataclass(frozen=True)
class ConfigDocument:
    kind: str
    version: str
    content: dict[str, Any]
    sha256: str


@dataclass
class ConfigBundle:
    """All governed configuration, loaded once per process (and per config release)."""

    root: Path
    documents: dict[str, ConfigDocument] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path | None = None) -> ConfigBundle:
        root = root or repo_root()
        files = {
            "control_catalogue": "catalogue/controls/controls.yaml",
            "samm": "catalogue/frameworks/samm.yaml",
            "asvs_applicability": "catalogue/frameworks/asvs-applicability.yaml",
            "organization": "config/organization.yaml",
            "risk_model": "config/risk-model.yaml",
            "evidence_types": "config/evidence-types.yaml",
            "trusted_producers": "config/trusted-producers.yaml",
            "exception_policy": "config/exception-policy.yaml",
            "samm_targets": "config/samm-targets.yaml",
            "maturity_methodology": "config/maturity-methodology.yaml",
            "licence_policy": "config/licence-policy.yaml",
            "siem_events": "config/siem-events.yaml",
            "metrics": "config/metrics.yaml",
            "integrations": "config/integrations.yaml",
        }
        profile = str(_load_yaml(root / "config/organization.yaml").get("profile") or "generic")
        if not profile.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"invalid classification profile name {profile!r}")
        files["classification"] = f"config/profiles/{profile}/classification.yaml"
        bundle = cls(root=root)
        for kind, rel in files.items():
            content = _load_yaml(root / rel)
            version = str(content.get("catalogue_version") or content.get("version") or "0")
            bundle.documents[kind] = ConfigDocument(kind, version, content, digest(content))
        return bundle

    def doc(self, kind: str) -> dict[str, Any]:
        return self.documents[kind].content

    @property
    def org_levels(self) -> list[str]:
        """Organization tree levels, top (root) first, from config/organization.yaml."""
        return [str(level["type"]) for level in self.doc("organization")["levels"]]

    @property
    def profile(self) -> str:
        return str(self.doc("organization").get("profile") or "generic")

    @property
    def catalogue(self) -> dict[str, Any]:
        return self.doc("control_catalogue")

    @cached_property
    def controls(self) -> dict[str, dict[str, Any]]:
        return {c["id"]: c for c in self.catalogue["controls"]}

    @cached_property
    def evidence_types(self) -> dict[str, dict[str, Any]]:
        types: dict[str, dict[str, Any]] = self.doc("evidence_types")["types"]
        return types

    @cached_property
    def risk_expressions(self) -> dict[str, Expression]:
        """Every condition in the risk model, compiled once. Raises on any invalid expression."""
        model = self.doc("risk_model")
        compiled: dict[str, Expression] = {}
        for section in ("likelihood", "impact"):
            for m in model[section]["modifiers"]:
                compiled[m["when"]] = compile_expression(m["when"], RISK_ROOTS)
        for o in model["overrides"]:
            compiled[o["when"]] = compile_expression(o["when"], RISK_ROOTS)
        for s in model.get("soc_escalation", []):
            compiled[s["when"]] = compile_expression(s["when"], RISK_ROOTS)
        return compiled

    def samm_streams(self) -> dict[str, dict[str, str]]:
        out: dict[str, dict[str, str]] = {}
        for bf in self.doc("samm")["business_functions"]:
            for p in bf["practices"]:
                for s in p["streams"]:
                    out[s["id"]] = {
                        "practice": p["id"],
                        "practice_name": p["name"],
                        "function": bf["id"],
                        "function_name": bf["name"],
                        "name": s["name"],
                    }
        return out
