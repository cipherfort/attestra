# SPDX-License-Identifier: Apache-2.0
"""Security exceptions (ADR-021, config/exception-policy.yaml): a time-bound, approved acceptance of a known gap.

    draft ──submit──▶ pending_approval ──approve──▶ approved ──(expires_at)──▶ expired
                                       └─reject──▶ rejected          └─revoke──▶ revoked
    renew: a new draft linked to the old one (renewal_of); beyond max_renewals it needs one approver level higher.

Rules (all from governed config, nothing hard-coded here):
* the approver's role must rank at least the role the matrix requires for residual priority × application tier;
* segregation of duties: the approver is not the requester, not the technical owner, and not a member of the
  owning unit chain; Tier 1/2 also need the business owner's co-signature first;
* the expiry is at most the policy's maximum for the priority AND the control's own `exception.max_days`;
  controls with `exception.allowed: false` cannot be excepted at all;
* every step is an append-only `exception_events` row; on expiry the target returns to its real state and an
  `exception_expired` finding is raised.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, time, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.domain import fingerprints
from aap.ids import uuid7
from aap.store import findings_store, jobs

DEFAULT_ROLE_MAP = {
    "appsec_engineer": "appsec_engineer",
    "unit_lead": "unit_security_lead",
    "security_leadership": "head_of_appsec",
}


class ExceptionError(ValueError):
    def __init__(self, problem: str, status: int = 422):
        super().__init__(problem)
        self.problem, self.status = problem, status


def _policy(bundle: ConfigBundle) -> Mapping[str, Any]:
    return bundle.doc("exception_policy")


def _event(conn: Connection, exception_id: str, event_type: str, actor: str | None, details: Mapping[str, Any]) -> None:
    conn.execute(
        text("""INSERT INTO exception_events (id, exception_id, event_type, actor_id, details)
                VALUES (:id, :e, :t, :a, CAST(:d AS jsonb))"""),
        {"id": uuid7(), "e": exception_id, "t": event_type, "a": actor, "d": json.dumps(dict(details), default=str)},
    )


def _load(conn: Connection, exception_id: str) -> Mapping[str, Any]:
    row = (
        conn.execute(
            text("""SELECT x.*, a.tier_rank, a.app_key, a.business_owner_id, a.technical_owner_id
                    FROM exceptions x JOIN applications a ON a.id = x.application_id
                    WHERE x.id::text = :x OR x.exception_key = :x"""),
            {"x": exception_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise ExceptionError("exception not found", 404)  # RLS: out of scope looks the same as missing
    return row


def required_role(bundle: ConfigBundle, priority: str, tier: int, renewal_count: int = 0) -> str:
    pol = _policy(bundle)
    role = pol["approval_matrix"][priority][tier]
    if renewal_count > int(pol["max_renewals"][priority]):  # renewal_escalation: one level up after max
        ranks = pol["role_rank"]
        higher = sorted((r for r in ranks if ranks[r] > ranks[role]), key=lambda r: ranks[r])
        role = higher[0] if higher else role
    return str(role)


def approver_rank(bundle: ConfigBundle, platform_roles: Sequence[str]) -> int:
    pol = _policy(bundle)
    mapping = {**DEFAULT_ROLE_MAP, **(pol.get("platform_roles") or {})}
    return max((int(pol["role_rank"][mapping[r]]) for r in platform_roles if r in mapping), default=0)


def max_expiry(bundle: ConfigBundle, target_type: str, target_ref: str, priority: str, tier: int) -> int:
    days = int(_policy(bundle)["max_duration_days"][priority])
    if target_type == "control":
        control = bundle.controls.get(target_ref)
        if control is None:
            raise ExceptionError(f"no control {target_ref!r} in the catalogue")
        default = (bundle.doc("control_catalogue").get("defaults") or {}).get("exception") or {}
        rule = {**default, **(control.get("exception") or {})}  # catalogue defaults, then the control's own
        if not rule.get("allowed", False):
            raise ExceptionError(f"{target_ref} cannot be excepted (catalogue: exception.allowed is false)")
        per_tier = {int(k): int(v) for k, v in (rule.get("max_days") or {}).items()}
        days = min(days, per_tier.get(tier, days))
    return days


def create(
    conn: Connection,
    bundle: ConfigBundle,
    *,
    application_id: str,
    target_type: str,
    target_ref: str,
    justification: str,
    risk_description: str,
    residual_priority: str,
    remediation_plan: str,
    requested_by: str,
    owner_id: str | None = None,
    compensating_controls: str | None = None,
    requested_expiry: Any = None,
    renewal_of: str | None = None,
    renewal_count: int = 0,
) -> str:
    app = conn.execute(text("SELECT id, tier_rank FROM applications WHERE id = :a"), {"a": application_id}).first()
    if app is None:
        raise ExceptionError("application not found", 404)
    if app.tier_rank is None:
        raise ExceptionError("the application has no approved tier yet")
    if target_type == "finding":
        f = conn.execute(
            text("SELECT status FROM findings WHERE id::text = :f AND application_id = :a"),
            {"f": target_ref, "a": application_id},
        ).first()
        if f is None:
            raise ExceptionError("finding not found in this application", 404)
        if f.status in ("closed", "false_positive"):
            raise ExceptionError(f"the finding is {f.status}; nothing to except")
    days = max_expiry(bundle, target_type, target_ref, residual_priority, int(app.tier_rank))
    if requested_expiry is not None and (requested_expiry - datetime.now().date()).days > days:
        raise ExceptionError(f"requested expiry is beyond the {days}-day maximum for {residual_priority}")
    row = conn.execute(
        text("""INSERT INTO exceptions (application_id, target_type, target_ref, justification, risk_description,
                  residual_priority, compensating_controls, remediation_plan, owner_id, requested_by, renewal_of,
                  renewal_count, review_at)
                VALUES (:a, :tt, :tr, :j, :r, :p, :c, :plan, :o, :by, :ren, :rc, CAST(:review AS timestamptz))
                RETURNING id"""),
        {
            "a": application_id,
            "tt": target_type,
            "tr": target_ref,
            "j": justification,
            "r": risk_description,
            "p": residual_priority,
            "c": compensating_controls,
            "plan": remediation_plan,
            "o": owner_id or requested_by,
            "by": requested_by,
            "ren": renewal_of,
            "rc": renewal_count,
            "review": datetime.combine(requested_expiry, time.min).isoformat() if requested_expiry else None,
        },
    ).first()
    _event(conn, str(row.id), "created", requested_by, {"renewal_of": renewal_of} if renewal_of else {})
    return str(row.id)


def submit(conn: Connection, bundle: ConfigBundle, exception_id: str, actor: str) -> None:
    x = _load(conn, exception_id)
    if x["status"] != "draft":
        raise ExceptionError(f"only drafts can be submitted (this one is {x['status']})", 409)
    if str(x["requested_by"]) != str(actor):
        raise ExceptionError("only the requester can submit their draft", 403)
    conn.execute(text("UPDATE exceptions SET status = 'pending_approval' WHERE id = :x"), {"x": x["id"]})
    role = required_role(bundle, x["residual_priority"], int(x["tier_rank"]), int(x["renewal_count"]))
    _event(conn, str(x["id"]), "submitted", actor, {"required_approver_role": role})


def cosign_required(bundle: ConfigBundle, tier: int) -> bool:
    return tier in [int(t) for t in _policy(bundle).get("business_owner_cosign_tiers") or []]


def _cosigned(conn: Connection, exception_id: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT 1 FROM exception_events WHERE exception_id = :x AND event_type = 'cosigned' LIMIT 1"),
            {"x": exception_id},
        ).first()
    )


def cosign(conn: Connection, exception_id: str, actor: str) -> None:
    x = _load(conn, exception_id)
    if x["status"] != "pending_approval":
        raise ExceptionError("only submitted exceptions can be co-signed", 409)
    if x["business_owner_id"] is None or str(x["business_owner_id"]) != str(actor):
        raise ExceptionError("only the application's business owner can co-sign", 403)
    if not _cosigned(conn, str(x["id"])):
        _event(conn, str(x["id"]), "cosigned", actor, {})


def sod_problem(conn: Connection, x: Mapping[str, Any], approver: str) -> str | None:
    from aap.services.onboarding import sod_problem as unit_chain_problem

    if str(x["requested_by"]) == str(approver):
        return "you requested this exception; another person must decide it"
    if x["technical_owner_id"] is not None and str(x["technical_owner_id"]) == str(approver):
        return "you are the application's technical owner"
    problem = unit_chain_problem(conn, str(x["application_id"]), None, approver)
    return problem


def decide(
    conn: Connection,
    bundle: ConfigBundle,
    exception_id: str,
    *,
    approver: str,
    approver_roles: Sequence[str],
    outcome: str,
    comment: str,
    expires_at: Any = None,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now().astimezone()
    x = _load(conn, exception_id)
    if x["status"] != "pending_approval":
        raise ExceptionError(f"nothing to decide (status {x['status']})", 409)
    if len(comment.strip()) < 5:
        raise ExceptionError("a decision needs a comment (at least 5 characters)")
    problem = sod_problem(conn, x, approver)
    if problem:
        raise ExceptionError(f"segregation of duties: {problem}", 403)
    role = required_role(bundle, x["residual_priority"], int(x["tier_rank"]), int(x["renewal_count"]))
    ranks = _policy(bundle)["role_rank"]
    if approver_rank(bundle, approver_roles) < int(ranks[role]):
        raise ExceptionError(f"this exception needs approval by {role} or above", 403)
    if outcome == "reject":
        conn.execute(text("UPDATE exceptions SET status = 'rejected' WHERE id = :x"), {"x": x["id"]})
        _event(conn, str(x["id"]), "rejected", approver, {"comment": comment})
        return
    if outcome != "approve":
        raise ExceptionError("outcome must be approve or reject")
    if cosign_required(bundle, int(x["tier_rank"])) and not _cosigned(conn, str(x["id"])):
        raise ExceptionError("Tier 1/2: the business owner must co-sign before approval", 409)
    days = max_expiry(bundle, x["target_type"], x["target_ref"], x["residual_priority"], int(x["tier_rank"]))
    latest = now + timedelta(days=days)
    expiry = latest if expires_at is None else datetime.combine(expires_at, time(23, 59), tzinfo=now.tzinfo)
    if expiry > latest + timedelta(days=1):
        raise ExceptionError(
            f"expiry beyond the {days}-day maximum for {x['residual_priority']} at Tier {x['tier_rank']}"
        )
    if expiry <= now:
        raise ExceptionError("expiry must be in the future")
    conn.execute(
        text("""UPDATE exceptions SET status = 'approved', approver_id = :ap, approved_at = :now, starts_at = :now,
                  expires_at = :exp WHERE id = :x"""),
        {"ap": approver, "now": now, "exp": expiry, "x": x["id"]},
    )
    _event(
        conn,
        str(x["id"]),
        "approved",
        approver,
        {"comment": comment, "expires_at": expiry.isoformat(), "required_role": role},
    )
    if x["renewal_of"] is not None:
        conn.execute(
            text("UPDATE exceptions SET status = 'closed' WHERE id = :o AND status = 'approved'"),
            {"o": x["renewal_of"]},
        )
        _event(conn, str(x["renewal_of"]), "renewed", approver, {"by": str(x["id"])})
    if x["target_type"] == "finding":
        _set_finding(conn, x["target_ref"], "excepted", f"exception {x['exception_key']} approved", approver)
    jobs.enqueue(
        conn, "evaluate", {"application_id": str(x["application_id"])}, dedup_key=f"evaluate:{x['application_id']}"
    )


def _set_finding(conn: Connection, finding_id: str, status: str, reason: str, actor: str | None) -> None:
    row = conn.execute(
        text("""UPDATE findings f SET status = CAST(:s AS finding_status), updated_at = now()
                FROM (SELECT id, status AS old FROM findings WHERE id::text = :f FOR UPDATE) o
                WHERE f.id = o.id AND o.old NOT IN ('closed', 'false_positive') RETURNING f.id, o.old"""),
        {"s": status, "f": finding_id},
    ).first()
    if row is not None:
        findings_store._event(
            conn, str(row.id), "status_changed", row.old, status, details={"reason": reason}, actor=actor or "platform"
        )


def revoke(
    conn: Connection, bundle: ConfigBundle, exception_id: str, actor: str, actor_roles: Sequence[str], reason: str
) -> None:
    x = _load(conn, exception_id)
    if x["status"] != "approved":
        raise ExceptionError("only approved exceptions can be revoked", 409)
    if approver_rank(bundle, actor_roles) < 1:
        raise ExceptionError("only an approver can revoke an exception", 403)
    conn.execute(text("UPDATE exceptions SET status = 'revoked' WHERE id = :x"), {"x": x["id"]})
    _event(conn, str(x["id"]), "revoked", actor, {"reason": reason})
    _after_end(conn, x, "revoked")


def renew(
    conn: Connection, bundle: ConfigBundle, exception_id: str, actor: str, justification: str, remediation_plan: str
) -> str:
    x = _load(conn, exception_id)
    if x["status"] not in ("approved", "expired"):
        raise ExceptionError("only approved or expired exceptions can be renewed", 409)
    return create(
        conn,
        bundle,
        application_id=str(x["application_id"]),
        target_type=x["target_type"],
        target_ref=x["target_ref"],
        justification=justification,
        risk_description=x["risk_description"],
        residual_priority=x["residual_priority"],
        remediation_plan=remediation_plan,
        requested_by=actor,
        owner_id=str(x["owner_id"]),
        compensating_controls=x["compensating_controls"],
        renewal_of=str(x["id"]),
        renewal_count=int(x["renewal_count"]) + 1,
    )


def _after_end(conn: Connection, x: Mapping[str, Any], how: str) -> None:
    if x["target_type"] == "finding":
        _set_finding(conn, x["target_ref"], "reopened", f"exception {x['exception_key']} {how}", None)
    jobs.enqueue(
        conn, "evaluate", {"application_id": str(x["application_id"])}, dedup_key=f"evaluate:{x['application_id']}"
    )


def expire_due(conn: Connection, bundle: ConfigBundle, now: datetime) -> int:
    """Scheduler: approved exceptions past expiry → expired, target back to its real state, a finding raised."""
    rows = conn.execute(
        text("""SELECT x.id FROM exceptions x WHERE x.status = 'approved' AND x.expires_at <= :now FOR UPDATE"""),
        {"now": now},
    ).all()
    pol = _policy(bundle).get("on_expiry") or {}
    for r in rows:
        x = _load(conn, str(r.id))
        conn.execute(text("UPDATE exceptions SET status = 'expired' WHERE id = :x"), {"x": x["id"]})
        _event(conn, str(x["id"]), "expired", None, {})
        if pol.get("create_finding_type") == "exception_expired":
            findings_store.observe(
                conn,
                findings_store.NewFinding(
                    fingerprint=fingerprints.exception_expired(str(x["exception_key"])),
                    application_id=str(x["application_id"]),
                    repository_id=None,
                    scope_type="application",
                    scope_ref=str(x["app_key"]),
                    finding_type="exception_expired",
                    source_system="platform",
                    title=f"Exception {x['exception_key']} expired: {x['target_type']} {x['target_ref']}"[:300],
                    description=f"The accepted risk is no longer covered. Remediation plan: {x['remediation_plan']}",
                    control_key=x["target_ref"] if x["target_type"] == "control" else None,
                    location={"exception": x["exception_key"], "residual_priority": x["residual_priority"]},
                    tool_severity={"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}[x["residual_priority"]],
                ),
                None,
                now,
            )
        if pol.get("reopen_target", True):
            _after_end(conn, x, "expired")
    return len(rows)


def view(
    conn: Connection,
    bundle: ConfigBundle,
    exception_id: str,
    viewer: str | None = None,
    viewer_roles: Sequence[str] = (),
) -> dict[str, Any]:
    x = _load(conn, exception_id)
    events = conn.execute(
        text("""SELECT e.event_type, e.at, e.details, u.display_name FROM exception_events e
                LEFT JOIN users u ON u.id = e.actor_id WHERE e.exception_id = :x ORDER BY e.at"""),
        {"x": x["id"]},
    ).all()
    names = {
        r.id: r.display_name
        for r in conn.execute(
            text("SELECT id, display_name FROM users WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(i) for i in (x["owner_id"], x["requested_by"], x["approver_id"]) if i]},
        )
    }
    tier = int(x["tier_rank"])
    role = required_role(bundle, x["residual_priority"], tier, int(x["renewal_count"]))
    can_decide = False
    if viewer and x["status"] == "pending_approval":
        can_decide = sod_problem(conn, x, viewer) is None and approver_rank(bundle, viewer_roles) >= int(
            _policy(bundle)["role_rank"][role]
        )
    return {
        "id": str(x["id"]),
        "exception_key": x["exception_key"],
        "application_id": str(x["application_id"]),
        "app_key": x["app_key"],
        "target_type": x["target_type"],
        "target_ref": x["target_ref"],
        "justification": x["justification"],
        "risk_description": x["risk_description"],
        "residual_priority": x["residual_priority"],
        "compensating_controls": x["compensating_controls"],
        "remediation_plan": x["remediation_plan"],
        "status": x["status"],
        "owner": names.get(x["owner_id"]),
        "requested_by": names.get(x["requested_by"]),
        "approver": names.get(x["approver_id"]),
        "required_approver_role": role,
        "business_owner_cosign_required": cosign_required(bundle, tier),
        "cosigned": _cosigned(conn, str(x["id"])),
        "can_decide": can_decide,
        "can_cosign": bool(
            viewer
            and x["business_owner_id"]
            and str(x["business_owner_id"]) == str(viewer)
            and x["status"] == "pending_approval"
        ),
        "max_days": max_expiry(bundle, x["target_type"], x["target_ref"], x["residual_priority"], tier),
        "created_at": x["created_at"],
        "approved_at": x["approved_at"],
        "expires_at": x["expires_at"],
        "renewal_count": x["renewal_count"],
        "events": [
            {"type": e.event_type, "actor": e.display_name or "platform", "at": e.at, "details": e.details}
            for e in events
        ],
    }
