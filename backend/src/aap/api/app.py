# SPDX-License-Identifier: Apache-2.0
"""HTTP API (ADR-023, schemas/api/openapi.yaml). Every route declares `x-permission`; data access runs as the
`aap_api` database role under the caller's row-level-security scope."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from aap.api.auth import auth_mode, authenticate, scope_for
from aap.api.policy import Principal
from aap.config import ConfigBundle
from aap.db import get_engine, transaction
from aap.services import maturity_service
from aap.services.evaluation import STATE_RANK
from aap.store import audit, control_store, findings_store, supply_chain

PROBLEM = "https://aap.internal.example/problems/"


# ------------------------------------------------------------------------------------------ plumbing


def _problem(
    status: int, title: str, kind: str, detail: str | None = None, request: Request | None = None
) -> JSONResponse:
    body = {"type": PROBLEM + kind, "title": title, "status": status}
    if detail:
        body["detail"] = detail
    if request is not None:
        body["request_id"] = request.state.request_id
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


KIND = {
    400: "bad-request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not-found",
    409: "conflict",
    412: "precondition-failed",
    422: "unprocessable",
    501: "not-configured",
}


def authorize(permission: str) -> Callable[[Request], Principal]:
    def dep(request: Request) -> Principal:
        p = authenticate(request)
        if not p.can(permission):
            raise HTTPException(403, f"permission {permission} required")
        request.state.principal = p
        return p

    dep.__name__ = f"authorize_{permission.replace('.', '_')}"
    return dep


class Router(APIRouter):
    def op(self, method: str, path: str, operation_id: str, permission: str, **kw: Any) -> Callable[[Any], Any]:
        def deco(fn: Any) -> Any:
            deps = [] if permission == "public" else [Depends(authorize(permission))]
            self.add_api_route(
                path,
                fn,
                methods=[method],
                operation_id=operation_id,
                dependencies=deps,
                openapi_extra={"x-permission": permission},
                **kw,
            )
            return fn

        return deco


def principal(request: Request) -> Principal:
    return request.state.principal  # type: ignore[no-any-return]


def db(request: Request) -> Engine:
    return request.app.state.engine  # type: ignore[no-any-return]


def bundle(request: Request) -> ConfigBundle:
    return request.app.state.bundle  # type: ignore[no-any-return]


def _app_id(conn: Connection, ref: str) -> str:
    """Accept a UUID or an APP-nnnnn key. Out-of-scope (RLS) and unknown look identical: 404."""
    col = "app_key" if ref.upper().startswith("APP-") else "id"
    if col == "id":
        try:
            ref = str(uuid.UUID(ref))  # canonical form: Python accepts spellings PostgreSQL rejects (found by fuzzing)
        except ValueError:
            raise HTTPException(404, "application not found") from None
    sql = (
        "SELECT id FROM applications WHERE app_key = :r"
        if col == "app_key"
        else "SELECT id FROM applications WHERE id = :r"
    )
    row = conn.execute(text(sql), {"r": ref.upper() if col == "app_key" else ref}).first()
    if row is None:
        raise HTTPException(404, "application not found")
    return str(row.id)


def _rows(result: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in result.mappings().all()]


def _etag(*parts: Any) -> str:
    return '"' + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16] + '"'


r = Router()


# ------------------------------------------------------------------------------------------ platform & identity


@r.op("GET", "/health/live", "getLiveness", "public")
def live() -> dict[str, str]:
    return {"status": "ok"}


@r.op("GET", "/health/ready", "getReadiness", "public")
def ready(request: Request) -> dict[str, Any]:
    with transaction(db(request), "aap_api") as conn:
        active = conn.execute(text("SELECT count(*) FROM config_versions WHERE active")).scalar_one()
    if active == 0:
        raise HTTPException(503, "no active configuration")
    return {"status": "ready", "config_versions_active": active}


@r.op("GET", "/users/me", "getCurrentUser", "authenticated")
def me(p: Principal = Depends(principal)) -> dict[str, Any]:
    return {
        "user": {"id": p.user_id, "display_name": p.display_name},
        "roles": [{"role": x} for x in p.roles],
        "org_wide": p.org_wide,
        "permissions": sorted(p.permissions),
        "csrf_token": p.extra.get("csrf"),  # session sign-in only: send as X-AAP-CSRF on unsafe requests
        "auth_mode": auth_mode(),
    }


@r.op("GET", "/integrations", "listIntegrations", "integration.read")
def integrations(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from dataclasses import asdict

    from aap.integrations import load_errors, status

    items = [asdict(s) for s in status(db(request), request.app.state.bundle, role="aap_api")]
    return {"items": items, "load_errors": load_errors()}


@r.op("GET", "/org-units", "listOrgUnits", "org_unit.read")
def org_units(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        rows = _rows(
            conn.execute(text("SELECT id, parent_id, unit_type AS type, name, slug FROM org_units ORDER BY name"))
        )
    if not p.org_wide:
        rows = [x for x in rows if str(x["id"]) in p.org_units]
    return {"items": rows, "page": {"next_cursor": None}}


# ------------------------------------------------------------------------------------------ applications

APP_SUMMARY = """
SELECT a.id, a.app_key, a.name, a.tier_rank AS tier, a.lifecycle, a.exposure, o.name AS org_unit, o.slug AS org_slug,
  (SELECT json_object_agg(state, n) FROM (SELECT state, count(*) n FROM (
     SELECT DISTINCT ON (cs.control_key) cs.control_key, cs.state FROM control_states cs
     WHERE cs.application_id = a.id AND cs.requirement = 'mandatory'
     ORDER BY cs.control_key, array_position(ARRAY['error','no_evidence','stale','not_satisfied','partial','excepted',
       'satisfied','not_applicable']::control_state[], cs.state)) worst GROUP BY state) s) AS mandatory_controls,
  (SELECT json_object_agg(coalesce(priority::text, 'unscored'), n) FROM (SELECT priority, count(*) n FROM findings f
     WHERE f.application_id = a.id AND f.status = ANY(:open) GROUP BY priority) s) AS open_findings,
  (SELECT count(*) FROM findings f WHERE f.application_id = a.id AND f.sla_breached AND f.status = ANY(:open)) AS sla_breaches
FROM applications a JOIN org_units o ON o.id = a.org_unit_id
"""


@r.op("GET", "/applications", "listApplications", "application.read")
def list_applications(request: Request, q: str | None = None, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        where = ""
        params: dict[str, Any] = {"open": list(findings_store.OPEN_STATUSES)}
        if q:
            where, params["q"] = " WHERE a.name ILIKE :q OR a.app_key ILIKE :q", f"%{q[:100]}%"
        rows = _rows(conn.execute(text(APP_SUMMARY + where + " ORDER BY a.tier_rank NULLS LAST, a.name"), params))
    return {"items": rows, "page": {"next_cursor": None}}


@r.op("GET", "/applications/{appId}", "getApplication", "application.read")
def get_application(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        row = (
            conn.execute(text(APP_SUMMARY + " WHERE a.id = :a"), {"a": aid, "open": list(findings_store.OPEN_STATUSES)})
            .mappings()
            .first()
        )
        detail = (
            conn.execute(
                text("""SELECT a.description, a.data_classification, a.personal_data, a.profile, a.updated_at,
               bo.display_name AS business_owner, tech.display_name AS technical_owner, ch.display_name AS champion
               FROM applications a LEFT JOIN users bo ON bo.id = a.business_owner_id
               LEFT JOIN users tech ON tech.id = a.technical_owner_id LEFT JOIN users ch ON ch.id = a.champion_id
               WHERE a.id = :a"""),
                {"a": aid},
            )
            .mappings()
            .first()
        )
    return {**dict(row or {}), **dict(detail or {})}


@r.op("GET", "/applications/{appId}/classification", "getClassification", "application.read")
def get_classification(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.domain.classification import classify
    from aap.services import onboarding

    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        row = (
            conn.execute(
                # the latest decision, which may still be pending AppSec approval (Tier 1/2)
                text("""SELECT c.*, u.display_name AS decided_by_name, q.display_name AS requested_by_name
               FROM application_classifications c LEFT JOIN users u ON u.id = c.decided_by
               LEFT JOIN users q ON q.id = c.requested_by
               WHERE c.application_id = :a
                 AND NOT EXISTS (SELECT 1 FROM application_classifications s WHERE s.supersedes_id = c.id)
               ORDER BY c.created_at DESC LIMIT 1"""),
                {"a": aid},
            )
            .mappings()
            .first()
        )
        can_decide = (
            row is not None
            and row["decision"] == "pending"
            and p.can("classification.decide")
            and onboarding.sod_problem(conn, aid, row["requested_by"], p.user_id) is None
        )
    if row is None:
        raise HTTPException(404, "application has no classification")
    explained = classify(row["inputs"], bundle(request).doc("classification"))
    return {
        "id": row["id"],
        "model_version": row["model_version"],
        "inputs": row["inputs"],
        "matched_floor_rules": row["matched_floor_rules"],
        "points": row["points"],
        "computed_tier": row["computed_tier"],
        "decision": row["decision"],
        "explanation": explained.explanation,
        "asvs_target": explained.asvs_target,
        "contributions": explained.contributions,
        "decided_by": row["decided_by_name"],
        "decided_at": row["decided_at"],
        "requested_by": row["requested_by_name"],
        # the requester may not decide their own request (segregation of duties); the UI hides the buttons
        "can_decide": can_decide,
    }


@r.op("GET", "/applications/{appId}/repositories", "listApplicationRepositories", "application.read")
def app_repos(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        rows = _rows(
            conn.execute(
                text("""SELECT r.id, r.provider, r.external_id, r.full_name, r.visibility, r.default_branch, ar.role,
               r.onboarding, r.head_sha, r.detected FROM application_repositories ar JOIN repositories r ON r.id = ar.repository_id
               WHERE ar.application_id = :a ORDER BY ar.role, r.full_name"""),
                {"a": aid},
            )
        )
    return {"items": rows}


# ------------------------------------------------------------------------------------------ controls & evidence


@r.op("GET", "/applications/{appId}/controls", "listControlStates", "application.read")
def control_states(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    b = bundle(request)
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        rows = control_store.current_states(conn, aid)
        computed = conn.execute(
            text("SELECT max(last_evaluated_at) FROM control_states WHERE application_id = :a"), {"a": aid}
        ).scalar()
    items = []
    for s in rows:
        c = b.controls.get(s["control_key"], {})
        items.append(
            {
                "control_key": s["control_key"],
                "title": c.get("title"),
                "domain": c.get("domain"),
                "objective_type": c.get("objective_type"),
                "mode": (c.get("assessment") or {}).get("mode"),
                "requirement": s["requirement"],
                "state": s["state"],
                "observe_mode": s["observe_mode"],
                "scope": {"type": s["scope_type"], "ref": s["scope_ref"]},
                "since": s["since"],
                "explanation": s["explanation"],
                "evidence_ids": s["evidence_ids"],
                "evaluator": s["evaluator"],
                "proof": c.get("proof"),
            }
        )
    items.sort(key=lambda i: (i["requirement"] != "mandatory", STATE_RANK.get(i["state"], 9), i["control_key"]))
    return {"items": items, "data_as_of": {"computed_at": computed, "stale_connectors": []}}


@r.op("GET", "/applications/{appId}/controls/{controlKey}/evaluations", "listControlEvaluations", "application.read")
def control_history(appId: str, controlKey: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        rows = control_store.history(conn, aid, controlKey)
    return {"items": [dict(x) for x in rows], "page": {"next_cursor": None}}


EVIDENCE_COLS = """e.evidence_id AS id, e.evidence_type AS type, e.confidence, e.confidence_reasons, e.result,
  e.observed_at, e.ingested_at, s.state, s.valid_until, e.producer_type, e.producer_ref, e.tool, e.tool_version,
  e.subject, e.summary, e.scope_ref"""


@r.op("GET", "/applications/{appId}/evidence", "listEvidence", "evidence.read")
def list_evidence(
    appId: str, request: Request, type: str | None = None, p: Principal = Depends(principal)
) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        sql = f"SELECT {EVIDENCE_COLS} FROM evidence e JOIN evidence_current_state s USING (evidence_id) WHERE e.application_id = :a"  # noqa: S608
        params: dict[str, Any] = {"a": aid}
        if type:
            sql += " AND e.evidence_type = :t"
            params["t"] = type
        rows = _rows(conn.execute(text(sql + " ORDER BY e.observed_at DESC LIMIT 200"), params))
    return {"items": rows, "page": {"next_cursor": None}}


@r.op("GET", "/evidence/{evidenceId}", "getEvidence", "evidence.read")
def get_evidence(evidenceId: uuid.UUID, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        row = (
            conn.execute(
                text(f"""SELECT {EVIDENCE_COLS}, e.application_id, e.run_ref, e.raw_location, e.attestation_ref,
               encode(e.record_hash, 'hex') AS record_hash, encode(e.prev_hash, 'hex') AS prev_hash,
               (SELECT array_agg(encode(h, 'hex')) FROM unnest(e.raw_sha256) h) AS raw_sha256
               FROM evidence e JOIN evidence_current_state s USING (evidence_id) WHERE e.evidence_id = :id"""),  # noqa: S608
                {"id": evidenceId},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise HTTPException(404, "evidence not found")
        events = _rows(
            conn.execute(
                text(
                    "SELECT state, reason, occurred_at AS at FROM evidence_validity_events "
                    "WHERE evidence_id = :id ORDER BY occurred_at"
                ),
                {"id": evidenceId},
            )
        )
        used = [
            str(x.id)
            for x in conn.execute(
                text(
                    "SELECT id FROM control_evaluations WHERE :id = ANY(evidence_ids) ORDER BY evaluated_at DESC LIMIT 20"
                ),
                {"id": evidenceId},
            )
        ]
    return {**dict(row), "validity_events": events, "used_by_evaluations": used}


# ------------------------------------------------------------------------------------------ findings

FINDING_COLS = """f.id, f.application_id, a.app_key, a.name AS application_name, f.finding_type AS type, f.source_system,
  f.title, f.cwe_id, v.vuln_key AS vulnerability, f.tool_severity, f.priority, f.risk_score, f.status, f.first_seen_at,
  f.last_seen_at, f.triage_due_at, f.sla_due_at, f.sla_breached, f.control_key, f.location, f.scope_ref, f.updated_at"""


@r.op("GET", "/findings", "listFindings", "finding.read")
def list_findings(
    request: Request,
    application: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    p: Principal = Depends(principal),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        if application:
            clauses.append("f.application_id = :a")
            params["a"] = _app_id(conn, application)
        if status == "open":
            clauses.append("f.status = ANY(:open)")
            params["open"] = list(findings_store.OPEN_STATUSES)
        elif status:
            clauses.append("f.status::text = :s")
            params["s"] = status
        if priority:
            clauses.append("f.priority::text = ANY(:p)")
            params["p"] = priority.split(",")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = _rows(
            conn.execute(
                text(
                    f"SELECT {FINDING_COLS} FROM findings f JOIN applications a ON a.id = f.application_id "  # noqa: S608
                    f"LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id{where} "
                    "ORDER BY f.priority NULLS LAST, f.sla_due_at NULLS LAST LIMIT 500"
                ),
                params,
            )
        )
    return {"items": rows, "page": {"next_cursor": None}}


def _finding(conn: Connection, fid: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"""SELECT {FINDING_COLS}, f.description, f.closure_evidence_id, f.last_seen_evidence_id,
           ra.likelihood, ra.impact, ra.explanation AS risk_explanation, ra.applied_rules, ra.computed_at AS risk_computed_at
           FROM findings f JOIN applications a ON a.id = f.application_id
           LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
           LEFT JOIN finding_risk_assessments ra ON ra.id = f.risk_assessment_id WHERE f.id = :id"""),  # noqa: S608
            {"id": fid},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(404, "finding not found")
    return dict(row)


@r.op("GET", "/findings/{findingId}", "getFinding", "finding.read")
def get_finding(findingId: uuid.UUID, request: Request, p: Principal = Depends(principal)) -> JSONResponse:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        f = _finding(conn, findingId)
    return JSONResponse(jsonable_encoder(f), headers={"ETag": _etag(f["status"], f["updated_at"])})


@r.op("GET", "/findings/{findingId}/events", "listFindingEvents", "finding.read")
def finding_events(findingId: uuid.UUID, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        _finding(conn, findingId)
        rows = _rows(
            conn.execute(
                text(
                    "SELECT at, event_type, from_status, to_status, actor_type, actor_id, evidence_id, "
                    "details FROM finding_events WHERE finding_id = :f ORDER BY at"
                ),
                {"f": findingId},
            )
        )
    return {"items": rows, "page": {"next_cursor": None}}


@r.op("GET", "/findings/{findingId}/risk-assessments", "listRiskAssessments", "finding.read")
def risk_assessments(findingId: uuid.UUID, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        _finding(conn, findingId)
        rows = _rows(
            conn.execute(
                text(
                    "SELECT id, model_version_id, inputs, likelihood, impact, score, priority, "
                    "applied_rules, explanation, manual_override, computed_at FROM finding_risk_assessments "
                    "WHERE finding_id = :f ORDER BY computed_at DESC"
                ),
                {"f": findingId},
            )
        )
    return {"items": rows}


class Transition(BaseModel):
    action: str = Field(pattern="^(triage|mark_false_positive|confirm_false_positive|reject_false_positive)$")
    comment: str | None = Field(default=None, max_length=4000)


FP_EVENTS = ("false_positive_requested", "confirm_false_positive", "reject_false_positive")


def _open_fp_request(conn: Connection, fid: uuid.UUID) -> str | None:
    """The requester's user id when a false-positive request is awaiting a second reviewer, else None."""
    last = conn.execute(
        text(
            "SELECT event_type, actor_id FROM finding_events WHERE finding_id = :f "
            "AND event_type = ANY(:e) ORDER BY at DESC LIMIT 1"
        ),
        {"f": fid, "e": list(FP_EVENTS)},
    ).first()
    return str(last.actor_id) if last and last.event_type == "false_positive_requested" else None


class SodViolation(Exception):
    def __init__(self, application_id: str, detail: str):
        super().__init__(detail)
        self.application_id, self.detail = application_id, detail


# ------------------------------------------------------------------------------------------ exceptions (ADR-021)


class ExceptionCreate(BaseModel):
    application: str = Field(max_length=64)
    target_type: str = Field(pattern="^(control|finding|requirement|sla)$")
    target_ref: str = Field(min_length=1, max_length=200)
    justification: str = Field(min_length=20, max_length=4000)
    risk_description: str = Field(min_length=20, max_length=4000)
    residual_priority: str = Field(pattern="^P[1-4]$")
    compensating_controls: str | None = Field(default=None, max_length=4000)
    remediation_plan: str = Field(min_length=20, max_length=4000)
    owner: str | None = None
    requested_expiry: date | None = None


class ExceptionDecision(BaseModel):
    outcome: str = Field(pattern="^(approve|reject)$")
    comment: str = Field(min_length=5, max_length=4000)
    expires_at: date | None = None


class ExceptionRenewal(BaseModel):
    justification: str = Field(min_length=20, max_length=4000)
    remediation_plan: str = Field(min_length=20, max_length=4000)


def _exception_call(request: Request, p: Principal, action: str, fn: Any, target: str | None = None) -> Any:
    """Run an exception operation under the caller's scope; audit successes and refusals (403) alike."""
    from aap.services.exceptions import ExceptionError

    try:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            out = fn(conn)
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action=action,
                outcome="success",
                target_type="exception",
                target_id=str(out if isinstance(out, str) else target),
                request_id=request.state.request_id,
            )
        return out
    except ExceptionError as e:
        if e.status == 403:
            with transaction(db(request), "aap_api", scope_for(p)) as conn:
                audit.write(
                    conn,
                    actor_type="user",
                    actor_id=p.user_id,
                    action=action,
                    outcome="denied",
                    target_type="exception",
                    target_id=target,
                    request_id=request.state.request_id,
                    details={"reason": e.problem[:200]},
                )
        raise HTTPException(e.status, e.problem) from None


@r.op("GET", "/exceptions", "listExceptions", "exception.read")
def list_exceptions(
    request: Request, application: str | None = None, status: str | None = None, p: Principal = Depends(principal)
) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, application) if application else None
        rows = _rows(
            conn.execute(
                text("""SELECT x.id, x.exception_key, x.target_type, x.target_ref, x.residual_priority, x.status,
                          x.expires_at, x.created_at, a.app_key, a.name AS application_name, u.display_name AS requested_by
                        FROM exceptions x JOIN applications a ON a.id = x.application_id
                        JOIN users u ON u.id = x.requested_by
                        WHERE (CAST(:a AS uuid) IS NULL OR x.application_id = CAST(:a AS uuid))
                          AND (CAST(:s AS text) IS NULL OR x.status::text = :s)
                        ORDER BY x.created_at DESC LIMIT 200"""),
                {"a": aid, "s": status},
            )
        )
    return {"items": rows}


@r.op("POST", "/exceptions", "createException", "exception.request", status_code=201)
def create_exception(body: ExceptionCreate, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import exceptions

    def fn(conn: Connection) -> str:
        aid = _app_id(conn, body.application)
        return exceptions.create(
            conn,
            bundle(request),
            application_id=aid,
            target_type=body.target_type,
            target_ref=body.target_ref,
            justification=body.justification,
            risk_description=body.risk_description,
            residual_priority=body.residual_priority,
            remediation_plan=body.remediation_plan,
            requested_by=p.user_id,
            owner_id=body.owner,
            compensating_controls=body.compensating_controls,
            requested_expiry=body.requested_expiry,
        )

    xid = _exception_call(request, p, "exception.create", fn)
    return _exception_view(request, p, xid)


def _exception_view(request: Request, p: Principal, xid: str) -> dict[str, Any]:
    from aap.services import exceptions

    try:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            return exceptions.view(conn, bundle(request), xid, p.user_id, p.roles)
    except exceptions.ExceptionError as e:
        raise HTTPException(e.status, e.problem) from None


@r.op("GET", "/exceptions/{exceptionId}", "getException", "exception.read")
def get_exception(exceptionId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    return _exception_view(request, p, exceptionId)


@r.op("POST", "/exceptions/{exceptionId}/submit", "submitException", "exception.request")
def submit_exception(exceptionId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import exceptions

    _exception_call(
        request,
        p,
        "exception.submit",
        lambda conn: exceptions.submit(conn, bundle(request), exceptionId, p.user_id),
        exceptionId,
    )
    return _exception_view(request, p, exceptionId)


# Who may co-sign is an identity fact (the application's recorded business owner), checked by the service; a role
# would be weaker. The permission only requires that the caller can see the exception.
@r.op("POST", "/exceptions/{exceptionId}/cosign", "cosignException", "exception.read")
def cosign_exception(exceptionId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import exceptions

    _exception_call(
        request, p, "exception.cosign", lambda conn: exceptions.cosign(conn, exceptionId, p.user_id), exceptionId
    )
    return _exception_view(request, p, exceptionId)


@r.op("POST", "/exceptions/{exceptionId}/decision", "decideException", "exception.decide")
def decide_exception(
    exceptionId: str, body: ExceptionDecision, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import exceptions

    _exception_call(
        request,
        p,
        f"exception.{body.outcome}",
        lambda conn: exceptions.decide(
            conn,
            bundle(request),
            exceptionId,
            approver=p.user_id,
            approver_roles=p.roles,
            outcome=body.outcome,
            comment=body.comment,
            expires_at=body.expires_at,
        ),
        exceptionId,
    )
    return _exception_view(request, p, exceptionId)


class ExceptionRevoke(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@r.op("POST", "/exceptions/{exceptionId}/revoke", "revokeException", "exception.decide")
def revoke_exception(
    exceptionId: str, body: ExceptionRevoke, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import exceptions

    _exception_call(
        request,
        p,
        "exception.revoke",
        lambda conn: exceptions.revoke(conn, bundle(request), exceptionId, p.user_id, p.roles, body.reason),
        exceptionId,
    )
    return _exception_view(request, p, exceptionId)


@r.op("POST", "/exceptions/{exceptionId}/renewals", "renewException", "exception.request", status_code=201)
def renew_exception(
    exceptionId: str, body: ExceptionRenewal, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import exceptions

    xid = _exception_call(
        request,
        p,
        "exception.renew",
        lambda conn: exceptions.renew(
            conn, bundle(request), exceptionId, p.user_id, body.justification, body.remediation_plan
        ),
        exceptionId,
    )
    return _exception_view(request, p, xid)


# ------------------------------------------------------------------------------------------ assessments (M1/M2)


class AssessmentCreate(BaseModel):
    type: str = Field(pattern="^(manual_control|samm_application|threat_model_review|architecture_review|pentest)$")
    application: str = Field(max_length=64)
    scope: dict[str, Any] = Field(default_factory=dict)
    due_at: date | None = None


class AssessmentDecision(BaseModel):
    outcome: str = Field(pattern="^(approve|reject)$")
    comment: str = Field(min_length=5, max_length=4000)


def _assessment_call(request: Request, p: Principal, action: str, fn: Any, target: str | None = None) -> Any:
    from aap.services.assessments import AssessmentError

    try:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            out = fn(conn)
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action=action,
                outcome="success",
                target_type="assessment",
                target_id=str(target or out),
                request_id=request.state.request_id,
            )
        return out
    except AssessmentError as e:
        if e.status == 403:
            with transaction(db(request), "aap_api", scope_for(p)) as conn:
                audit.write(
                    conn,
                    actor_type="user",
                    actor_id=p.user_id,
                    action=action,
                    outcome="denied",
                    target_type="assessment",
                    target_id=target,
                    request_id=request.state.request_id,
                    details={"reason": e.problem[:200]},
                )
        raise HTTPException(e.status, e.problem) from None


def _assessment_view(request: Request, p: Principal, sid: str) -> dict[str, Any]:
    from aap.services import assessments

    try:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            aid = conn.execute(text("SELECT application_id FROM assessments WHERE id::text = :s"), {"s": sid}).scalar()
            if (
                aid is None
                or conn.execute(text("SELECT 1 FROM applications WHERE id = :a"), {"a": aid}).first() is None
            ):
                raise HTTPException(404, "assessment not found")  # RLS: another unit's assessment looks missing
            return assessments.view(conn, sid, p.user_id, sorted(p.permissions))
    except assessments.AssessmentError as e:
        raise HTTPException(e.status, e.problem) from None


@r.op("GET", "/assessments", "listAssessments", "assessment.read")
def list_assessments(
    request: Request, application: str | None = None, p: Principal = Depends(principal)
) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, application) if application else None
        rows = _rows(
            conn.execute(
                text("""SELECT s.id, s.assessment_type AS type, s.status, s.due_at, s.approved_at, a.app_key,
                          a.name AS application_name, u.display_name AS lead_assessor,
                          (SELECT confidence FROM evidence e WHERE e.evidence_id = s.evidence_id) AS confidence
                        FROM assessments s JOIN applications a ON a.id = s.application_id
                        LEFT JOIN users u ON u.id = s.lead_assessor_id
                        WHERE CAST(:a AS uuid) IS NULL OR s.application_id = CAST(:a AS uuid)
                        ORDER BY s.submitted_at DESC NULLS FIRST LIMIT 200"""),
                {"a": aid},
            )
        )
    return {"items": rows}


@r.op("POST", "/assessments", "createAssessment", "assessment.create", status_code=201)
def create_assessment(body: AssessmentCreate, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import assessments

    def fn(conn: Connection) -> str:
        aid = _app_id(conn, body.application)
        return assessments.create(
            conn,
            bundle(request),
            kind=body.type,
            application_id=aid,
            lead_assessor=p.user_id,
            scope=body.scope,
            due_at=body.due_at,
        )

    sid = _assessment_call(request, p, "assessment.create", fn)
    return _assessment_view(request, p, sid)


@r.op("GET", "/assessments/{assessmentId}", "getAssessment", "assessment.read")
def get_assessment(assessmentId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    return _assessment_view(request, p, assessmentId)


@r.op("PUT", "/assessments/{assessmentId}/answers", "putAssessmentAnswers", "assessment.answer")
def put_assessment_answers(
    assessmentId: str, body: dict[str, Any], request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import assessments

    _assessment_view(request, p, assessmentId)  # scope check first
    _assessment_call(
        request,
        p,
        "assessment.record",
        lambda conn: assessments.record(conn, bundle(request), assessmentId, p.user_id, body),
        assessmentId,
    )
    return _assessment_view(request, p, assessmentId)


@r.op("POST", "/assessments/{assessmentId}/submit", "submitAssessment", "assessment.answer")
def submit_assessment(assessmentId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import assessments

    _assessment_view(request, p, assessmentId)
    _assessment_call(
        request,
        p,
        "assessment.submit",
        lambda conn: assessments.submit(conn, bundle(request), assessmentId, p.user_id),
        assessmentId,
    )
    return _assessment_view(request, p, assessmentId)


@r.op("POST", "/assessments/{assessmentId}/decision", "decideAssessment", "assessment.approve")
def decide_assessment(
    assessmentId: str, body: AssessmentDecision, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import assessments

    _assessment_view(request, p, assessmentId)
    _assessment_call(
        request,
        p,
        f"assessment.{body.outcome}",
        lambda conn: assessments.decide(
            conn, assessmentId, approver=p.user_id, outcome=body.outcome, comment=body.comment
        ),
        assessmentId,
    )
    return _assessment_view(request, p, assessmentId)


# ------------------------------------------------------------------------------------------ administration


class UnitCreate(BaseModel):
    slug: str = Field(max_length=64)
    name: str = Field(min_length=2, max_length=200)
    unit_type: str = Field(max_length=32)
    parent: str = Field(max_length=64)


class UnitUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    scm_group: str | None = Field(default=None, max_length=255)
    idp_group_id: str | None = Field(default=None, max_length=255)


class GrantCreate(BaseModel):
    principal_type: str = Field(default="user", pattern="^(user|idp_group)$")
    principal_id: str = Field(max_length=255)
    role: str = Field(max_length=40)
    org_unit: str | None = Field(default=None, max_length=64)
    expires_at: date | None = None


def _admin(request: Request, p: Principal, action: str, fn: Any, target: str = "") -> Any:
    from aap.services.admin import AdminError

    try:
        with transaction(db(request), "aap_admin") as conn:
            out = fn(conn)
            if action:
                audit.write(
                    conn,
                    actor_type="user",
                    actor_id=p.user_id,
                    action=action,
                    outcome="success",
                    target_type="admin",
                    target_id=target or (out if isinstance(out, str) else ""),
                    request_id=request.state.request_id,
                )
        return out
    except AdminError as e:
        if e.status == 403:
            with transaction(db(request), "aap_admin") as conn:
                audit.write(
                    conn,
                    actor_type="user",
                    actor_id=p.user_id,
                    action=action,
                    outcome="denied",
                    target_type="admin",
                    target_id=target,
                    request_id=request.state.request_id,
                    details={"reason": e.problem[:200]},
                )
        raise HTTPException(e.status, e.problem) from None


@r.op("GET", "/admin/org-units", "adminListOrgUnits", "org.admin")
def admin_units(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    return {"items": _admin(request, p, "", admin.tree), "levels": admin.levels(bundle(request))}


@r.op("POST", "/admin/org-units", "adminCreateOrgUnit", "org.admin", status_code=201)
def admin_create_unit(body: UnitCreate, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    uid = _admin(
        request,
        p,
        "org_unit.create",
        lambda conn: admin.create_unit(
            conn, bundle(request), slug=body.slug, name=body.name, unit_type=body.unit_type, parent=body.parent
        ),
    )
    return {"id": uid, "slug": body.slug}


@r.op("PATCH", "/admin/org-units/{slug}", "adminUpdateOrgUnit", "org.admin")
def admin_update_unit(
    slug: str, body: UnitUpdate, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import admin

    _admin(
        request,
        p,
        "org_unit.update",
        lambda conn: admin.update_unit(conn, slug, body.model_dump(exclude_none=True)),
        slug,
    )
    return {"slug": slug}


@r.op("GET", "/admin/org-units/{slug}/members", "adminListMembers", "org.admin")
def admin_members(slug: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    return {"items": _admin(request, p, "", lambda conn: admin.members(conn, slug))}


@r.op("PUT", "/admin/org-units/{slug}/members/{userId}", "adminAddMember", "org.admin")
def admin_add_member(slug: str, userId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    _admin(
        request, p, "org_unit.member.add", lambda conn: admin.set_member(conn, slug, userId, True), f"{slug}:{userId}"
    )
    return {"slug": slug, "user_id": userId, "member": True}


@r.op("DELETE", "/admin/org-units/{slug}/members/{userId}", "adminRemoveMember", "org.admin")
def admin_remove_member(slug: str, userId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    _admin(
        request,
        p,
        "org_unit.member.remove",
        lambda conn: admin.set_member(conn, slug, userId, False),
        f"{slug}:{userId}",
    )
    return {"slug": slug, "user_id": userId, "member": False}


@r.op("GET", "/admin/users", "adminListUsers", "org.admin")
def admin_users(request: Request, q: str = "", p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    return {"items": _admin(request, p, "", lambda conn: admin.users(conn, q[:100]))}


@r.op("GET", "/admin/role-assignments", "adminListGrants", "org.admin")
def admin_grants(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    return {"items": _admin(request, p, "", admin.grants)}


@r.op("POST", "/admin/role-assignments", "adminGrantRole", "org.admin", status_code=201)
def admin_grant(body: GrantCreate, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    gid = _admin(
        request,
        p,
        "role.grant",
        lambda conn: admin.grant(
            conn,
            actor=p.user_id,
            principal_type=body.principal_type,
            principal_id=body.principal_id,
            role=body.role,
            org_unit=body.org_unit,
            expires_at=body.expires_at,
        ),
        f"{body.role}:{body.principal_id}",
    )
    return {"id": gid}


@r.op("DELETE", "/admin/role-assignments/{grantId}", "adminRevokeRole", "org.admin")
def admin_revoke(grantId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    from aap.services import admin

    _admin(request, p, "role.revoke", lambda conn: admin.revoke(conn, actor=p.user_id, grant_id=grantId), grantId)
    return {"id": grantId, "revoked": True}


class RegisterApplication(BaseModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$", max_length=255)
    provider: str = Field(default="github", pattern="^(github|gitlab)$")
    # Offline registration (no SCM plugin configured, or a contract not yet merged): the files' text + the repo id
    repository_id: str | None = Field(default=None, max_length=64)
    application_yaml: str | None = Field(default=None, max_length=256 * 1024)
    asvs_yaml: str | None = Field(default=None, max_length=256 * 1024)


@r.op("POST", "/applications", "registerApplication", "application.register", status_code=201)
def register_application(
    body: RegisterApplication, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    import yaml

    from aap.services import onboarding

    try:
        if body.application_yaml is not None:
            if not body.repository_id:
                raise HTTPException(422, "repository_id is required with application_yaml")
            try:
                app_doc = yaml.safe_load(body.application_yaml)
                asvs_doc = yaml.safe_load(body.asvs_yaml) if body.asvs_yaml else None
            except yaml.YAMLError as e:
                raise HTTPException(422, f"not valid YAML: {str(e)[:200]}") from None
            repo = onboarding.RepoRef(body.provider, body.repository_id, body.repository)
        else:
            repo, app_doc, asvs_doc = (
                onboarding.fetch_contract_gitlab(onboarding.gitlab_api(), body.repository)
                if body.provider == "gitlab"
                else onboarding.fetch_contract(onboarding.github_api(body.repository), body.repository)
            )
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            reg = onboarding.register(
                conn, bundle(request), repo=repo, app_doc=app_doc, asvs_doc=asvs_doc, requested_by=p.user_id
            )
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action="application.register",
                outcome="success",
                target_type="application",
                target_id=reg.application_id,
                application_id=reg.application_id,
                request_id=request.state.request_id,
                details={"repository": repo.full_name, "tier": reg.tier, "decision": reg.decision},
            )
    except onboarding.OnboardingError as e:
        raise HTTPException(e.status, "; ".join(e.problems)) from None
    except DBAPIError as e:
        if "row-level security" in str(e.orig):
            raise HTTPException(403, "you can register applications only in units you belong to") from None
        raise
    return {
        "id": reg.application_id,
        "app_key": reg.app_key,
        "tier": reg.tier,
        "decision": reg.decision,
        "explanation": reg.explanation,
        "matched_floor_rules": reg.matched_floor_rules,
    }


class ClassificationDecision(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    reason: str = Field(default="", max_length=2000)


@r.op(
    "POST",
    "/applications/{appId}/classification/decisions",
    "decideClassification",
    "classification.decide",
    status_code=201,
)
def decide_classification(
    appId: str, body: ClassificationDecision, request: Request, p: Principal = Depends(principal)
) -> dict[str, Any]:
    from aap.services import onboarding

    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
    try:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            out = onboarding.decide(
                conn, bundle(request), aid, decision=body.decision, decided_by=p.user_id, reason=body.reason
            )
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action=f"classification.{body.decision}",
                outcome="success",
                target_type="application",
                target_id=aid,
                application_id=aid,
                request_id=request.state.request_id,
                details={"reason": body.reason, "tier": out["tier"]},
            )
        return out
    except onboarding.SodViolationError as e:
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action=f"classification.{body.decision}",
                outcome="denied",
                target_type="application",
                target_id=aid,
                application_id=aid,
                request_id=request.state.request_id,
                details={"reason": "SOD_VIOLATION"},
            )
        raise HTTPException(403, f"segregation of duties: {e.problems[0]}") from None
    except onboarding.OnboardingError as e:
        raise HTTPException(e.status, "; ".join(e.problems)) from None


@r.op("POST", "/findings/{findingId}/transitions", "transitionFinding", "finding.transition")
def transition(
    findingId: uuid.UUID,
    body: Transition,
    request: Request,
    if_match: str = Header(alias="If-Match"),
    p: Principal = Depends(principal),
) -> dict[str, Any]:
    try:
        return _transition(findingId, body, request, if_match, p)
    except SodViolation as e:
        # The refused request rolled back; the denial is audited in its own transaction so it is never lost.
        with transaction(db(request), "aap_api", scope_for(p)) as conn:
            audit.write(
                conn,
                actor_type="user",
                actor_id=p.user_id,
                action=f"finding.{body.action}",
                outcome="denied",
                target_type="finding",
                target_id=str(findingId),
                application_id=e.application_id,
                request_id=request.state.request_id,
                details={"reason": "SOD_VIOLATION"},
            )
        raise HTTPException(403, f"segregation of duties: {e.detail}") from None


def _transition(
    findingId: uuid.UUID, body: Transition, request: Request, if_match: str, p: Principal
) -> dict[str, Any]:
    """triage · mark_false_positive (request) · confirm/reject_false_positive (a second person, AppSec, SoD-enforced).
    Closing is not a transition: findings close only on verification evidence."""
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        f = _finding(conn, findingId)
        if if_match != _etag(f["status"], f["updated_at"]):
            raise HTTPException(412, "finding changed since it was read; re-read and retry")
        open_states = set(findings_store.OPEN_STATUSES)
        requester = _open_fp_request(conn, findingId)
        new_status = f["status"]
        if body.action == "triage":
            if f["status"] not in ("new", "reopened"):
                raise HTTPException(409, f"cannot triage a finding in state {f['status']}")
            new_status = "triaged"
        elif body.action == "mark_false_positive":
            if f["status"] not in open_states or requester:
                raise HTTPException(409, "finding is not open, or a false-positive request is already pending")
            if not body.comment:
                raise HTTPException(422, "a justification comment is required")
        else:
            if requester is None:
                raise HTTPException(409, "no false-positive request is pending")
            if not p.can("finding.fp.confirm"):
                raise HTTPException(403, "an AppSec engineer must review false positives")
            if requester == p.user_id:
                raise SodViolation(str(f["application_id"]), "you requested this false positive yourself")
            if body.action == "confirm_false_positive":
                new_status = "false_positive"
        if new_status != f["status"]:
            conn.execute(
                text("UPDATE findings SET status = :s, updated_at = now() WHERE id = :f"),
                {"s": new_status, "f": findingId},
            )
        event = "false_positive_requested" if body.action == "mark_false_positive" else body.action
        conn.execute(
            text("""INSERT INTO finding_events (id, finding_id, event_type, from_status, to_status, actor_type,
               actor_id, details) VALUES (:id, :f, :e, :fs, :ts, 'user', :u, CAST(:d AS jsonb))"""),
            {
                "id": uuid.uuid4(),
                "f": findingId,
                "e": event,
                "fs": f["status"],
                "ts": new_status,
                "u": p.user_id,
                "d": json.dumps({"comment": body.comment or ""}),
            },
        )
        audit.write(
            conn,
            actor_type="user",
            actor_id=p.user_id,
            action=f"finding.{body.action}",
            outcome="success",
            target_type="finding",
            target_id=str(findingId),
            application_id=str(f["application_id"]),
            request_id=request.state.request_id,
        )
        return _finding(conn, findingId)


# ------------------------------------------------------------------------------------------ supply chain


@r.op("GET", "/vulnerabilities/{vulnId}/affected-applications", "getAffectedApplications", "vulnerability.impact.read")
def affected(vulnId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        result = supply_chain.affected_applications(conn, vulnId)
    if result is None:
        raise HTTPException(404, "vulnerability not known to the platform")
    return result


@r.op("GET", "/components", "searchComponents", "component.read")
def components(
    request: Request, purl: str | None = None, name: str | None = None, p: Principal = Depends(principal)
) -> dict[str, Any]:
    if not purl and not name:
        raise HTTPException(400, "give purl or name")
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        rows = _rows(
            conn.execute(
                text("""SELECT c.purl, c.ecosystem, c.name, c.version, c.licence_expression AS licence,
               (SELECT count(DISTINCT s.application_id) FROM sbom_components sc JOIN sboms s ON s.id = sc.sbom_id AND s.is_current
                WHERE sc.component_id = c.id) AS application_count,
               (SELECT count(*) FROM component_vulnerabilities cv WHERE cv.component_id = c.id) AS known_vulnerabilities
               FROM components c WHERE (CAST(:purl AS text) IS NULL OR c.purl LIKE :purl || '@%')
                 AND (CAST(:name AS text) IS NULL OR c.name ILIKE :name) ORDER BY c.purl LIMIT 200"""),
                {"purl": purl, "name": name},
            )
        )
    return {"items": rows, "page": {"next_cursor": None}}


@r.op("GET", "/applications/{appId}/sboms", "listApplicationSboms", "application.read")
def sboms(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        rows = _rows(
            conn.execute(
                text(
                    "SELECT id, scope_key, commit_sha, format, spec_version, component_count, "
                    "purl_coverage_pct, is_current, evidence_id, generated_at FROM sboms "
                    "WHERE application_id = :a ORDER BY generated_at DESC"
                ),
                {"a": aid},
            )
        )
    for row in rows:  # numeric(5,2) → a JSON number, as the contract says
        if row.get("purl_coverage_pct") is not None:
            row["purl_coverage_pct"] = float(row["purl_coverage_pct"])
    return {"items": rows}


# ------------------------------------------------------------------------------------------ maturity & reporting


@r.op("GET", "/applications/{appId}/maturity", "getApplicationMaturity", "application.read")
def app_maturity(appId: str, request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    b = bundle(request)
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        aid = _app_id(conn, appId)
        report = maturity_service.application_maturity(conn, b, aid)
    return {
        "methodology_version": b.documents["maturity_methodology"].version,
        "catalogue_version": b.documents["control_catalogue"].version,
        "meets_tier_target": report.meets_target,
        "overall": report.overall,
        "practices": [
            {"item": k, "name": v.name, "score": v.score, "target": v.target, "provenance": v.provenance}
            for k, v in report.practices.items()
        ],
        "functions": [{"item": k, "name": v.name, "score": v.score} for k, v in report.functions.items()],
        "streams": [{"item": k, "name": v.name, "score": v.score} for k, v in report.streams.items()],
    }


EXPORTS = {
    "findings": (
        [
            "app_key",
            "application",
            "finding_id",
            "type",
            "title",
            "priority",
            "status",
            "cwe",
            "vulnerability",
            "first_seen",
            "sla_due",
            "sla_breached",
            "scope",
        ],
        """SELECT a.app_key, a.name, f.id, f.finding_type, f.title, f.priority, f.status, f.cwe_id, v.vuln_key,
                  f.first_seen_at, f.sla_due_at, f.sla_breached, f.scope_ref
           FROM findings f JOIN applications a ON a.id = f.application_id
           LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
           WHERE f.status NOT IN ('closed', 'false_positive') ORDER BY a.app_key, f.priority NULLS LAST, f.title""",
    ),
    "controls": (
        ["app_key", "application", "tier", "control", "requirement", "state", "scope", "since", "explanation"],
        """SELECT a.app_key, a.name, a.tier_rank, c.control_key, c.requirement, c.state, c.scope_ref, c.since,
                  e.explanation
           FROM control_states c JOIN applications a ON a.id = c.application_id
           LEFT JOIN control_evaluations e ON e.id = c.last_evaluation_id
           ORDER BY a.app_key, c.control_key, c.scope_ref""",
    ),
}


def csv_cell(value: Any) -> str:
    """Spreadsheet-safe text: formulas are neutralised (OWASP CSV injection), timestamps are ISO 8601."""
    if value is None:
        return ""
    text_value = value.isoformat() if hasattr(value, "isoformat") else str(value)
    return "'" + text_value if text_value[:1] in ("=", "+", "-", "@", "\t", "\r") else text_value


@r.op("GET", "/reports/{report}.csv", "exportReport", "report.export")
def export_report(report: str, request: Request, p: Principal = Depends(principal)) -> Response:
    import csv
    import io

    if report not in EXPORTS:
        raise HTTPException(404, f"no report {report!r} (available: {', '.join(EXPORTS)})")
    header, query = EXPORTS[report]
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        rows = conn.execute(text(query)).all()  # row-level security limits rows to the caller's scope
        audit.write(
            conn,
            actor_type="user",
            actor_id=p.user_id,
            action=f"export.{report}",
            outcome="success",
            target_type="report",
            target_id=report,
            request_id=request.state.request_id,
            details={"rows": len(rows)},
        )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow([csv_cell(v) for v in row])
    return Response(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="aap-{report}.csv"', "Cache-Control": "no-store"},
    )


@r.op("GET", "/reports/org-scorecard", "getOrgScorecard", "report.org.read")
def org_scorecard(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
    with transaction(db(request), "aap_api", scope_for(p)) as conn:
        open_ = list(findings_store.OPEN_STATUSES)
        stats = (
            conn.execute(
                text("""SELECT
            (SELECT count(*) FROM applications WHERE lifecycle <> 'retired') AS applications,
            (SELECT count(*) FROM control_states WHERE requirement = 'mandatory') AS mandatory_states,
            (SELECT count(*) FROM control_states WHERE requirement = 'mandatory' AND state = 'satisfied') AS satisfied,
            (SELECT count(*) FROM control_states WHERE requirement = 'mandatory' AND state IN ('no_evidence', 'stale')) AS missing_or_stale,
            (SELECT count(*) FROM findings WHERE priority = 'P1' AND status = ANY(:open)) AS p1_open,
            (SELECT count(*) FROM findings WHERE priority = 'P1' AND sla_breached AND status = ANY(:open)) AS p1_overdue,
            (SELECT count(*) FROM findings f JOIN vulnerabilities v ON v.id = f.vulnerability_id
               JOIN applications a ON a.id = f.application_id
               WHERE v.in_kev AND a.exposure IN ('internet_public', 'internet_authenticated') AND f.status = ANY(:open))
               AS kev_internet_exposed_open,
            (SELECT count(*) FROM evidence_rejections) AS evidence_rejections"""),
                {"open": open_},
            )
            .mappings()
            .first()
        )
    s = dict(stats or {})
    s["mandatory_control_coverage_pct"] = (
        round(100 * s["satisfied"] / s["mandatory_states"], 1) if s["mandatory_states"] else None
    )
    return s


@r.op("GET", "/catalogue/controls", "listCatalogueControls", "catalogue.read")
def catalogue(request: Request) -> dict[str, Any]:
    b = bundle(request)
    return {
        "catalogue_version": b.catalogue["catalogue_version"],
        "git_sha": "local",
        "items": [
            {
                "control_key": c["id"],
                "title": c["title"],
                "domain": c["domain"],
                "objective_type": c["objective_type"],
                "assessment_mode": c["assessment"]["mode"],
                "description": c["description"],
                "proof": c["proof"],
                "applicability": c["applicability"]["tiers"],
                "mappings": c["mappings"],
            }
            for c in b.catalogue["controls"]
        ],
    }


# ------------------------------------------------------------------------------------------ app factory


def create_app(engine: Engine | None = None, config: ConfigBundle | None = None) -> FastAPI:
    auth_mode()  # fail fast on a forbidden auth configuration
    app = FastAPI(
        title="Attestra API",
        version="1.0.0-draft",
        root_path="",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
    )
    app.state.engine = engine or get_engine()
    app.state.bundle = config or ConfigBundle.load()

    @app.middleware("http")
    async def request_id(request: Request, call_next: Any) -> Any:
        request.state.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        # PostgreSQL text cannot hold NUL: refuse it at the edge instead of failing inside a query (found by fuzzing)
        from urllib.parse import unquote

        if "\x00" in unquote(request.url.path) or "\x00" in unquote(request.url.query):
            response = _problem(400, "bad request", "bad-request", "NUL characters are not allowed", request)
            response.headers["X-Request-ID"] = request.state.request_id
            return response
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(HTTPException)
    async def http_problem(request: Request, exc: HTTPException) -> JSONResponse:
        return _problem(
            exc.status_code,
            KIND.get(exc.status_code, "error").replace("-", " "),
            KIND.get(exc.status_code, "error"),
            str(exc.detail),
            request,
        )

    @app.exception_handler(DBAPIError)
    async def db_error(request: Request, exc: DBAPIError) -> JSONResponse:
        if "cannot contain NUL" in str(exc.orig):  # a NUL inside a JSON body
            return _problem(400, "bad request", "bad-request", "NUL characters are not allowed", request)
        if "invalid input syntax for type uuid" in str(exc.orig):  # a malformed id names nothing: 404, like unknown
            return _problem(404, "not found", "not-found", "not found", request)
        return _problem(500, "internal error", "internal", None, request)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:  # never leak internals
        return _problem(500, "internal error", "internal", None, request)

    app.include_router(r, prefix="/api/v1")
    if auth_mode() == "oidc":
        from aap.api import bff

        app.include_router(bff.router)
    _mount_ui(app)
    return app


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def spa_static_files(directory: Any) -> Any:
    """Static files for the single-page UI: a path that is not a file and looks like a client route (no extension,
    not under api/ or auth/) gets index.html, so deep links and reloads work. Missing assets and unknown API paths
    stay 404."""
    from fastapi.staticfiles import StaticFiles
    from starlette.exceptions import HTTPException as StarletteHTTPException

    class SPAStaticFiles(StaticFiles):
        async def get_response(self, path: str, scope: Any) -> Any:
            try:
                return await super().get_response(path, scope)
            except StarletteHTTPException as e:
                client_route = (
                    e.status_code == 404
                    and not path.startswith(("api/", "auth/"))
                    and "." not in path.rsplit("/", 1)[-1]
                )
                if not client_route:
                    raise
                return await super().get_response("index.html", scope)

    return SPAStaticFiles(directory=directory, html=True)


def _mount_ui(app: FastAPI) -> None:
    """Serve the built SPA from the same origin (BFF pattern, ADR-014/023) with a strict CSP. Skipped when absent."""
    import os
    from pathlib import Path

    from aap.config import repo_root

    dist = Path(os.environ.get("AAP_STATIC_DIR") or repo_root() / "frontend" / "dist")
    if not (dist / "index.html").exists():
        return

    @app.middleware("http")
    async def csp(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        if not request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = CSP
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.mount("/", spa_static_files(dist), name="ui")
