# SPDX-License-Identifier: Apache-2.0
"""Control applicability and state vocabulary (control framework §4–5)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

IAC_LANGUAGES = frozenset({"hcl", "terraform", "bicep", "dockerfile", "yaml"})


class ControlState(StrEnum):
    SATISFIED = "satisfied"
    PARTIAL = "partial"
    NOT_SATISFIED = "not_satisfied"
    STALE = "stale"
    NO_EVIDENCE = "no_evidence"
    EXCEPTED = "excepted"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass(frozen=True)
class EvidenceView:
    """An evidence record as an evaluator sees it: already freshness-evaluated by the engine."""

    id: str
    type: str
    confidence: str
    result: str
    state: str  # freshness state
    observed_at: datetime
    summary: Mapping[str, Any] = field(default_factory=dict)
    subject: Mapping[str, Any] = field(default_factory=dict)
    scope_ref: str = ""
    state_reason: str = ""


@dataclass(frozen=True)
class AppFacts:
    """Application profile facts used by applicability conditions and evaluators."""

    application_id: str
    tier: int
    facts: Mapping[str, bool]
    profile: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Applicability:
    requirement: str  # mandatory | recommended | n/a
    unknown_conditions: tuple[str, ...] = ()
    reason: str = ""


def applicability(control: Mapping[str, Any], app: AppFacts) -> Applicability:
    tiers = {int(k): v for k, v in control["applicability"]["tiers"].items()}
    level = tiers.get(app.tier, "n/a")
    if level == "n/a":
        return Applicability("n/a", reason=f"not required for Tier {app.tier}")
    unknown: list[str] = []
    for cond in control["applicability"].get("conditions", []):
        if cond not in app.facts:
            unknown.append(cond)  # fail safe: an unknown fact keeps the control applicable
        elif not app.facts[cond]:
            return Applicability("n/a", reason=f"condition '{cond}' is false for this application")
    return Applicability(level, tuple(unknown), f"{level} for Tier {app.tier}")


def required_confidence(control: Mapping[str, Any], tier: int) -> str:
    req = control["assessment"]["min_confidence"]
    if isinstance(req, Mapping):
        return str({int(k): v for k, v in req.items()}[tier])
    return str(req)


def derive_facts(profile: Mapping[str, Any], detected: Mapping[str, Any]) -> dict[str, bool]:
    """Applicability conditions from the declared profile + what discovery detected in the repositories.
    Only facts we can actually derive are returned; others stay unknown (and keep controls applicable)."""
    languages = detected.get("languages") or profile.get("languages") or []
    code_languages = [lang for lang in languages if lang not in IAC_LANGUAGES]
    ecosystems = detected.get("ecosystems") or []
    facts: dict[str, bool] = {
        "has_source_code": bool(code_languages),
        "uses_dependencies": bool(ecosystems) or bool(code_languages),
        "has_iac": bool(detected.get("iac")),
        "builds_or_deploys_containers": bool(detected.get("dockerfiles") or profile.get("container_images")),
        "has_api": bool(profile.get("has_api")),
        "has_web_ui_or_api": bool(profile.get("has_api") or profile.get("has_web_frontend")),
        "has_workflows": bool(detected.get("workflows", True)),
        "deployed": profile.get("lifecycle") in ("pilot", "production"),
        "lifecycle_retired": profile.get("lifecycle") == "retired",
        "has_cloud_scope": bool(profile.get("cloud_scopes")),
        "has_third_party_services": bool(profile.get("third_party_services")),
        "publishes_artifacts": bool(profile.get("container_images")),
        "deployed_via_github": bool(profile.get("github_environments")),
        "has_sbom_capable_stack": bool(code_languages) or bool(ecosystems),
    }
    return facts
