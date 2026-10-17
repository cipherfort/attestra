# SPDX-License-Identifier: Apache-2.0
"""Evaluate every catalogue control for an application (control framework section 5, evidence model section 5).

1. Refresh evidence freshness (latest-per-scope, commit/artifact/continuous/time/event policies) and move the
   projection, appending validity events on change.
2. For each control × scope: applicability → evaluator → ledger entry when the outcome changed.
3. Optionally raise control-gap findings for mandatory controls failing past the grace period.

Repository-scoped controls (all evidence types live in a repository) are evaluated per linked repository; the
others at application scope.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

import aap
from aap.config import ConfigBundle
from aap.domain import fingerprints
from aap.domain.controls import AppFacts, ControlState, EvidenceView, applicability, derive_facts
from aap.domain.freshness import EvidenceState, FreshnessFacts
from aap.domain.freshness import evaluate as freshness
from aap.evaluators import evaluate_control
from aap.evaluators.base import FindingView
from aap.store import config_store, control_store, evidence_store, findings_store, registry

REPO_SCOPED = frozenset(
    {
        "repo.ruleset",
        "repo.security_settings",
        "repo.codeowners",
        "repo.access",
        "repo.actions_policy",
        "repo.environments",
        "scan.workflow_hardening",
        "scan.sast",
        "scan.sca",
        "scan.secrets",
        "scan.iac",
        "scan.malicious_package",
        "test.security",
    }
)
GAP_STATES = frozenset({ControlState.NOT_SATISFIED, ControlState.STALE, ControlState.NO_EVIDENCE})
STATE_RANK = {
    "error": 0,
    "no_evidence": 1,
    "stale": 2,
    "not_satisfied": 3,
    "partial": 4,
    "excepted": 5,
    "satisfied": 6,
    "not_applicable": 7,
}

# compare(repo_full_name, base_sha, head_sha) → changed paths, or None when unknown (e.g. GitHub compare truncated)
CompareFn = Callable[[str, str, str], Sequence[str] | None]


@dataclass(frozen=True)
class ScopeResult:
    control_key: str
    scope_type: str
    scope_ref: str
    requirement: str
    state: str
    explanation: str
    changed: bool


def build_id() -> str:
    import os

    return os.environ.get("AAP_BUILD", f"aap-{aap.__version__}-dev")


def _views(
    conn: Connection, bundle: ConfigBundle, app: Mapping[str, Any], now: datetime, compare: CompareFn | None
) -> list[EvidenceView]:
    rows = evidence_store.evidence_for_application(conn, str(app["id"]))
    heads = {r["full_name"]: r["head_sha"] for r in app["repositories"] or []}
    newest: dict[tuple[str, str], datetime] = {}
    for r in rows:
        key = (r.evidence_type, r.scope_ref)
        newest[key] = max(newest.get(key, r.observed_at), r.observed_at)

    views: list[EvidenceView] = []
    for r in rows:
        policy = bundle.evidence_types[r.evidence_type]["freshness"]
        if r.observed_at < newest[(r.evidence_type, r.scope_ref)]:
            state, until, reason = EvidenceState.SUPERSEDED, r.valid_until, "superseded by newer evidence"
        elif policy["policy"] == "commit_bound" and r.subject.get("on_default_branch") is False:
            state, until, reason = EvidenceState.SUPERSEDED, r.valid_until, "not from the default branch"
        else:
            facts = _facts(r, policy, heads, now, compare)
            res = freshness(r.observed_at, policy, facts)
            state, until, reason = res.state, res.valid_until, res.reason
        evidence_store.update_projection(conn, r.evidence_id, state.value, until, reason)
        views.append(
            EvidenceView(
                id=str(r.evidence_id),
                type=r.evidence_type,
                confidence=r.confidence,
                result=r.result,
                state=state.value,
                observed_at=r.observed_at,
                summary=r.summary or {},
                subject=r.subject or {},
                scope_ref=r.scope_ref,
                state_reason=reason,
            )
        )
    return views


def _facts(
    r: Any, policy: Mapping[str, Any], heads: Mapping[str, str | None], now: datetime, compare: CompareFn | None
) -> FreshnessFacts:
    if policy["policy"] != "commit_bound":
        return FreshnessFacts(now=now, last_confirmed=r.last_confirmed)
    commit, head = r.subject.get("commit_sha"), heads.get(r.scope_ref)
    if commit is None or head is None or commit == head:  # unbound observations age by their ceiling
        return FreshnessFacts(now=now, changed_paths=())
    paths = compare(r.scope_ref, commit, head) if compare else None
    return FreshnessFacts(now=now, changed_paths=tuple(paths) if paths is not None else None)


def _findings(conn: Connection, application_id: str, now: datetime) -> list[FindingView]:
    out = []
    for f in findings_store.for_application(conn, application_id):
        triage_overdue = f["status"] == "new" and f["triage_due_at"] is not None and f["triage_due_at"] < now
        out.append(
            FindingView(
                str(f["id"]),
                f["finding_type"],
                f["status"],
                f["priority"],
                bool(f["sla_breached"]),
                source=str((f["location"] or {}).get("source", f["source_system"])),
                details={
                    "validity": (f["location"] or {}).get("validity", "unknown"),
                    "triage_overdue": triage_overdue,
                },
            )
        )
    return out


def _active_exceptions(conn: Connection, application_id: str, now: datetime) -> dict[str, str]:
    rows = conn.execute(
        text(
            "SELECT exception_key, target_ref FROM exceptions WHERE application_id = :a AND target_type = 'control' "
            "AND status = 'approved' AND starts_at <= :now AND expires_at > :now"
        ),
        {"a": application_id, "now": now},
    ).all()
    return {r.target_ref: r.exception_key for r in rows}


def evaluate_application(
    conn: Connection,
    bundle: ConfigBundle,
    application_id: str,
    now: datetime,
    compare: CompareFn | None = None,
    gap_grace: timedelta | None = timedelta(days=14),
) -> list[ScopeResult]:
    app = registry.application_context(conn, application_id)
    if app is None:
        raise LookupError(application_id)
    if app["tier_rank"] is None:
        raise ValueError(f"{app['app_key']} has no approved tier; classify it first")
    cfg = config_store.active(conn)
    evidence = _views(conn, bundle, app, now, compare)
    findings = _findings(conn, application_id, now)
    exceptions = _active_exceptions(conn, application_id, now)
    profile = dict(app["profile"] or {})
    profile["lifecycle"] = app["lifecycle"]
    repos = app["repositories"] or []

    results: list[ScopeResult] = []
    for key, control in bundle.controls.items():
        repo_scoped = set(control["assessment"]["evidence_types"]) <= REPO_SCOPED and repos
        scopes = (
            [("repository", r["full_name"], r.get("detected") or {}) for r in repos]
            if repo_scoped
            else [("application", str(app["app_key"]), _merged_detection(repos))]
        )
        for scope_type, scope_ref, detected in scopes:
            facts = AppFacts(application_id, int(app["tier_rank"]), derive_facts(profile, detected), profile)
            scoped = [e for e in evidence if scope_type == "application" or e.scope_ref == scope_ref]
            res = evaluate_control(control, facts, scoped, findings, now, exceptions.get(key))
            requirement = applicability(control, facts).requirement
            changed = control_store.record(
                conn,
                application_id=application_id,
                control_key=key,
                control_id=cfg.controls[key],
                scope_type=scope_type,
                scope_ref=scope_ref,
                requirement=requirement,
                state=res.state.value,
                explanation=res.explanation,
                evaluator=res.evaluator,
                evaluator_build=build_id(),
                catalogue_version_id=cfg.ids["control_catalogue"],
                evidence_ids=res.evidence_ids,
                details=dict(res.details),
            )
            results.append(
                ScopeResult(key, scope_type, scope_ref, requirement, res.state.value, res.explanation, changed)
            )

    if gap_grace is not None:
        raise_control_gaps(conn, application_id, results, now, gap_grace)
    return results


def _merged_detection(repos: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for r in repos:
        for k, v in (r.get("detected") or {}).items():
            if isinstance(v, list):
                merged[k] = sorted(set(merged.get(k, [])) | set(v))
            else:
                merged[k] = merged.get(k) or v
    return merged


def raise_control_gaps(
    conn: Connection, application_id: str, results: Sequence[ScopeResult], now: datetime, grace: timedelta
) -> int:
    """Mandatory controls failing longer than the grace period become `control_gap` findings (control framework section 5)."""
    since = {(r["control_key"], r["scope_ref"]): r["since"] for r in control_store.current_states(conn, application_id)}
    raised = 0
    for r in results:
        if r.requirement != "mandatory" or ControlState(r.state) not in GAP_STATES:
            continue
        if now - since.get((r.control_key, r.scope_ref), now) < grace:
            continue
        evidence_like = conn.execute(
            text(
                "SELECT last_evaluation_id FROM control_states WHERE application_id = :a AND control_key = :k "
                "AND scope_ref = :s"
            ),
            {"a": application_id, "k": r.control_key, "s": r.scope_ref},
        ).scalar_one()
        _, status = findings_store.observe(
            conn,
            findings_store.NewFinding(
                fingerprint=fingerprints.control_gap(application_id, r.control_key, r.scope_ref),
                application_id=application_id,
                repository_id=None,
                scope_type=r.scope_type,
                scope_ref=r.scope_ref,
                finding_type="control_gap",
                source_system="platform",
                title=f"{r.control_key}: {r.explanation}"[:300],
                description=r.explanation,
                control_key=r.control_key,
                tool_severity="medium",
                source_refs=[{"system": "control_evaluation", "id": str(evidence_like)}],
            ),
            None,
            now,
        )
        raised += status == "created"
    return raised
