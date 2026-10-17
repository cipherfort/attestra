# SPDX-License-Identifier: Apache-2.0
"""Register organisations, people and applications through the real registry + classification code paths.

`connector_evidence` writes what the GitHub connector will observe (C1 configuration evidence) using the same
summary contract the evaluators read. In production these come from the GitHub App connector (E06-F02).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.domain.classification import classify
from aap.domain.evidence import TrustedWorkflows
from aap.store import evidence_store, registry


@dataclass
class RepoSpec:
    full_name: str
    github_id: int
    role: str
    head_sha: str
    detected: dict[str, Any] = field(default_factory=dict)
    visibility: str = "private"


@dataclass
class AppSpec:
    name: str
    description: str
    team_slug: str
    lifecycle: str
    classification: dict[str, Any]
    profile: dict[str, Any]
    repos: list[RepoSpec]
    owners: dict[str, str] = field(default_factory=dict)  # role → user id


def demo_trusted(bundle: ConfigBundle, sha: str) -> TrustedWorkflows:
    """DEMO/TEST ONLY: the real trusted-producer registry has no released SHAs yet (no security-workflows release),
    so everything is rejected (the correct production behaviour). The demo adds one clearly fake SHA in memory."""
    cfg = dict(bundle.doc("trusted_producers"))
    cfg["workflows"] = [{**wf, "approved_shas": [{"sha": sha, "release": "demo"}]} for wf in cfg["workflows"]]
    return TrustedWorkflows.from_config(cfg)


def register(
    conn: Connection, bundle: ConfigBundle, spec: AppSpec, org_unit_id: str, approver_id: str
) -> tuple[str, str]:
    result = classify(spec.classification, bundle.doc("classification"))
    profile = {**spec.profile, "classification": spec.classification}
    app_id, app_key = registry.create_application(
        conn,
        registry.NewApplication(
            name=spec.name,
            description=spec.description,
            org_unit_id=org_unit_id,
            lifecycle=spec.lifecycle,
            exposure=spec.classification["exposure"],
            data_classification=spec.classification["data_classification"],
            personal_data=spec.classification["personal_data"],
            profile=profile,
            business_owner_id=spec.owners.get("business"),
            technical_owner_id=spec.owners.get("technical"),
            champion_id=spec.owners.get("champion"),
        ),
    )
    decision = "approved" if result.tier <= 2 else "auto_approved"  # Tier 1/2 need AppSec approval (CLS-02)
    registry.record_classification(
        conn,
        app_id,
        bundle.documents["classification"].version,
        spec.classification,
        result,
        decision,
        approver_id if decision == "approved" else None,
    )
    for r in spec.repos:
        repo_id = registry.upsert_repository(
            conn, r.github_id, r.full_name, r.visibility, "main", r.head_sha, r.detected
        )
        registry.link_repository(conn, app_id, repo_id, r.role)
    _onboarding_evidence(conn, app_id, app_key, spec, result.tier, result.asvs_target, decision)
    return app_id, app_key


def _onboarding_evidence(
    conn: Connection, app_id: str, app_key: str, spec: AppSpec, tier: int, asvs_target: str, decision: str
) -> None:
    """What onboarding produces: the GitHub connector's read of application.yaml (C1) and the classification
    decision recorded by the workflow engine (M2 when AppSec approved it, M1 when auto-approved)."""
    names = {
        role: conn.execute(text("SELECT display_name FROM users WHERE id = :u"), {"u": uid}).scalar_one()
        for role, uid in spec.owners.items()
    }
    level = int(asvs_target[1]) if asvs_target[:1] == "L" else 1
    now = datetime.now(UTC)
    connector_evidence(
        conn,
        app_id,
        app_key,
        now,
        {
            "registry.application": {
                "schema_valid": True,
                "unlinked_repos": 0,
                "security_policy": True,
                "security_contact": True,
                "unresolved_owners": [f"{r}_owner" for r in ("business", "technical") if r not in spec.owners],
                "champion": names.get("champion"),
                "asvs_version": "5.0.0",
                "asvs_target_level": level,
                "asvs_required_level": level,
            }
        },
    )
    connector_evidence(
        conn,
        app_id,
        app_key,
        now,
        {"registry.classification": {"tier": tier, "decision": decision}},
        confidence="M2" if decision == "approved" else "M1",
    )


def connector_evidence(
    conn: Connection,
    application_id: str,
    scope_ref: str,
    observed_at: datetime,
    items: Mapping[str, Mapping[str, Any]],
    confidence: str = "C1",
    subject_extra: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """items: evidence_type → summary. Returns evidence_type → evidence id."""
    out = {}
    for etype, summary in items.items():
        app_scoped = etype.startswith(("registry.", "assessment.", "training.", "process.", "cloud.", "siem."))
        out[etype] = str(
            evidence_store.insert_evidence(
                conn,
                evidence_store.NewEvidence(
                    evidence_type=etype,
                    application_id=application_id,
                    scope_type="application" if app_scoped else "repository",
                    scope_ref=scope_ref,
                    subject={"setting": etype, **(subject_extra or {})},
                    producer_type="platform_connector",
                    producer_ref="connector:github@0.1.0" if confidence.startswith("C") else "platform:workflow-engine",
                    observed_at=observed_at,
                    result="observed" if confidence.startswith("C") else "pass",
                    confidence=confidence,
                    summary=dict(summary),
                    confidence_reasons=["authoritative_api"]
                    if confidence.startswith("C")
                    else ["reviewer_independent"],
                ),
            )
        )
    return out


def good_repo_settings(required_checks: Sequence[str] = ("aap / sast", "aap / sca", "aap / secrets")) -> dict[str, Any]:
    return {
        "repo.ruleset": {
            "requires_pr": True,
            "required_approvals": 2,
            "require_code_owner_review": True,
            "required_checks": list(required_checks),
            "blocks_force_push": True,
            "blocks_deletion": True,
        },
        "repo.security_settings": {
            "features": {
                "secret_scanning": True,
                "secret_scanning_push_protection": True,
                "secret_scanning_validity_checks": True,
            }
        },
        "repo.codeowners": {"errors": 0, "covered_paths": [".github/workflows/", ".security/"]},
        "repo.access": {"outside_writers": 0, "admin_users": 2, "visibility": "private"},
    }
