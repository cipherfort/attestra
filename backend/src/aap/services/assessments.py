# SPDX-License-Identifier: Apache-2.0
"""Manual assessments: the evidence a person provides when no tool can (evidence model §3, M1/M2).

    planned ──record──▶ in_progress ──submit──▶ submitted ──approve──▶ approved ──(worker)──▶ assessment.* evidence
                                                          └─reject──▶ rejected

* The lead assessor records and submits; a different person decides (never the lead assessor).
* The approval yields **M2** (independent) when the approver is outside the owning unit chain, otherwise **M1**
  (self-assessment). The confidence is decided here, from who approved, not claimed by the form.
* The API never writes evidence (schema test T9): approval queues an `assessment` job and the worker writes the
  evidence record and links it back (`assessments.evidence_id`).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.store import evidence_store, jobs

EVIDENCE_TYPE = {
    "manual_control": "assessment.manual_control",
    "samm_application": "assessment.samm_interview",
    "threat_model_review": "assessment.threat_model",
    "architecture_review": "assessment.architecture_review",
    "pentest": "assessment.pentest",
}
OUTCOMES = {
    "manual_control": ("pass", "fail"),
    "threat_model_review": ("approved", "approved_with_conditions", "rejected"),
    "architecture_review": ("approved", "approved_with_conditions", "rejected"),
    "pentest": ("approved", "approved_with_conditions", "rejected"),
}
SAMM_VALUES = (0.0, 0.25, 0.5, 1.0)  # SAMM answer options
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ASVS_ID = re.compile(r"^V\d+\.\d+\.\d+$")


class AssessmentError(ValueError):
    def __init__(self, problem: str, status: int = 422):
        super().__init__(problem)
        self.problem, self.status = problem, status


def _load(conn: Connection, assessment_id: str) -> Mapping[str, Any]:
    row = (
        conn.execute(
            text("""SELECT s.*, a.app_key FROM assessments s LEFT JOIN applications a ON a.id = s.application_id
                    WHERE s.id::text = :s"""),
            {"s": assessment_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise AssessmentError("assessment not found", 404)
    return row


def validate_scope(bundle: ConfigBundle, kind: str, scope: Mapping[str, Any], final: bool) -> list[str]:
    """What is wrong with the recorded content. `final`: everything required for approval must be present."""
    problems: list[str] = []
    outcome = scope.get("outcome")
    if kind in OUTCOMES and (outcome is not None or final) and outcome not in OUTCOMES[kind]:
        problems.append(f"outcome must be one of {', '.join(OUTCOMES[kind])}")
    if kind == "manual_control":
        key = scope.get("control_key")
        control = bundle.controls.get(str(key)) if key else None
        if final and control is None:
            problems.append("control_key must name a catalogue control")
        elif control is not None and "assessment.manual_control" not in control["assessment"]["evidence_types"]:
            problems.append(f"{key} is not assessed manually (its evidence types do not include a manual attestation)")
        if final and not str(scope.get("method") or "").strip():
            problems.append("method is required (how the control was verified)")
        bad = [r for r in scope.get("asvs_verified") or [] if not ASVS_ID.match(str(r))]
        if bad:
            problems.append(f"not ASVS requirement ids: {', '.join(map(str, bad[:5]))}")
    elif kind == "threat_model_review":
        if final and not SHA1.match(str(scope.get("model_commit") or "")):
            problems.append("model_commit must be the 40-character commit SHA of the reviewed threat model")
    elif kind == "pentest":
        if final and not str(scope.get("tester") or "").strip():
            problems.append("tester is required")
        if final and not SHA256.match(str(scope.get("report_sha256") or "")):
            problems.append("report_sha256 must be the SHA-256 of the report")
    elif kind == "samm_application":
        streams = {
            s["id"] for bf in bundle.doc("samm")["business_functions"] for p in bf["practices"] for s in p["streams"]
        }
        answers = scope.get("answers") or {}
        for key, value in answers.items():
            stream, _, level = str(key).partition(":")
            if stream not in streams or level not in ("1", "2", "3"):
                problems.append(f"{key}: answers are keyed STREAM:LEVEL, e.g. D-TA-A:1")
            elif float(value) not in SAMM_VALUES:
                problems.append(f"{key}: SAMM answers are 0, 0.25, 0.5 or 1")
        if final and not answers:
            problems.append("no answers recorded")
    return problems


def create(
    conn: Connection,
    bundle: ConfigBundle,
    *,
    kind: str,
    application_id: str,
    lead_assessor: str,
    scope: Mapping[str, Any] | None = None,
    due_at: Any = None,
) -> str:
    if kind not in EVIDENCE_TYPE:
        raise AssessmentError(f"type must be one of {', '.join(EVIDENCE_TYPE)}")
    problems = validate_scope(bundle, kind, scope or {}, final=False)
    if problems:
        raise AssessmentError("; ".join(problems))
    import json

    row = conn.execute(
        text("""INSERT INTO assessments (assessment_type, application_id, scope, lead_assessor_id, due_at)
                VALUES (CAST(:t AS assessment_type), :a, CAST(:s AS jsonb), :l, :d) RETURNING id"""),
        {"t": kind, "a": application_id, "s": json.dumps(dict(scope or {})), "l": lead_assessor, "d": due_at},
    ).first()
    return str(row.id)


def record(conn: Connection, bundle: ConfigBundle, assessment_id: str, actor: str, scope: Mapping[str, Any]) -> None:
    import json

    s = _load(conn, assessment_id)
    if str(s["lead_assessor_id"]) != str(actor):
        raise AssessmentError("only the lead assessor records the assessment", 403)
    if s["status"] not in ("planned", "in_progress"):
        raise AssessmentError(f"the assessment is {s['status']}", 409)
    merged = {**(s["scope"] or {}), **dict(scope)}
    problems = validate_scope(bundle, s["assessment_type"], merged, final=False)
    if problems:
        raise AssessmentError("; ".join(problems))
    conn.execute(
        text("""UPDATE assessments SET scope = CAST(:s AS jsonb), status = 'in_progress',
                  started_at = COALESCE(started_at, now()) WHERE id = :id"""),
        {"s": json.dumps(merged), "id": s["id"]},
    )


def submit(conn: Connection, bundle: ConfigBundle, assessment_id: str, actor: str) -> None:
    s = _load(conn, assessment_id)
    if str(s["lead_assessor_id"]) != str(actor):
        raise AssessmentError("only the lead assessor submits the assessment", 403)
    if s["status"] not in ("planned", "in_progress"):
        raise AssessmentError(f"the assessment is {s['status']}", 409)
    problems = validate_scope(bundle, s["assessment_type"], s["scope"] or {}, final=True)
    if problems:
        raise AssessmentError("; ".join(problems))
    conn.execute(
        text("UPDATE assessments SET status = 'submitted', submitted_at = now() WHERE id = :id"), {"id": s["id"]}
    )


def independence(conn: Connection, application_id: str | None, approver: str) -> str:
    """M2 when the approver is outside the owning unit chain (independent), M1 otherwise."""
    from aap.services.onboarding import sod_problem

    if application_id is None:
        return "M1"
    return "M1" if sod_problem(conn, application_id, None, approver) else "M2"


def decide(conn: Connection, assessment_id: str, *, approver: str, outcome: str, comment: str) -> str | None:
    s = _load(conn, assessment_id)
    if s["status"] != "submitted":
        raise AssessmentError(f"nothing to decide (status {s['status']})", 409)
    if str(s["lead_assessor_id"]) == str(approver):
        raise AssessmentError("segregation of duties: the lead assessor cannot approve their own assessment", 403)
    if len(comment.strip()) < 5:
        raise AssessmentError("a decision needs a comment (at least 5 characters)")
    if outcome == "reject":
        conn.execute(
            text("UPDATE assessments SET status = 'rejected', approved_by = :a WHERE id = :id"),
            {"a": approver, "id": s["id"]},
        )
        return None
    if outcome != "approve":
        raise AssessmentError("outcome must be approve or reject")
    confidence = independence(conn, str(s["application_id"]) if s["application_id"] else None, approver)
    conn.execute(
        text("""UPDATE assessments SET status = 'approved', approved_by = :a, approved_at = now(),
                  scope = scope || jsonb_build_object('approval_comment', CAST(:c AS text),
                                                      'confidence', CAST(:conf AS text))
                WHERE id = :id"""),
        {"a": approver, "c": comment, "conf": confidence, "id": s["id"]},
    )
    jobs.enqueue(conn, "assessment", {"assessment_id": str(s["id"])}, dedup_key=f"assessment:{s['id']}")
    return confidence


def write_evidence(conn: Connection, assessment_id: str, now: datetime) -> str | None:
    """Worker: an approved assessment becomes its evidence record (once)."""
    s = _load(conn, assessment_id)
    if s["status"] != "approved" or s["evidence_id"] is not None or s["application_id"] is None:
        return None
    scope = dict(s["scope"] or {})
    names = {
        r.id: r.display_name
        for r in conn.execute(
            text("SELECT id, display_name FROM users WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(s["lead_assessor_id"]), str(s["approved_by"])]},
        )
    }
    kind = s["assessment_type"]
    lead, approver = names.get(s["lead_assessor_id"], "assessor"), names.get(s["approved_by"], "approver")
    summary: dict[str, Any] = {
        "reviewer": scope.get("tester") if kind == "pentest" else lead,
        "approved_by": approver,
        "assessment_id": str(s["id"]),
    }
    for k in ("outcome", "control_key", "method", "model_commit", "report_sha256", "asvs_verified", "findings_summary"):
        if k in scope:
            summary[k] = scope[k]
    if "answers" in scope:  # hashed records carry no floats (canonical JSON): answers as decimal strings
        summary["answers"] = {k: str(float(v)) for k, v in scope["answers"].items()}
    outcome = scope.get("outcome")
    result = "fail" if outcome in ("fail", "rejected") else "pass"
    eid = evidence_store.insert_evidence(
        conn,
        evidence_store.NewEvidence(
            evidence_type=EVIDENCE_TYPE[kind],
            application_id=str(s["application_id"]),
            scope_type="application",
            scope_ref=str(s["app_key"]),
            subject={
                "assessment_id": str(s["id"]),
                **({"control_key": scope["control_key"]} if scope.get("control_key") else {}),
            },
            producer_type="manual",
            producer_ref="platform:workflow-engine",
            observed_at=s["approved_at"] or now,
            result=result,
            confidence=str(scope.get("confidence") or "M1"),
            summary=summary,
            confidence_reasons=["reviewer_independent"] if scope.get("confidence") == "M2" else ["self_assessment"],
        ),
    )
    conn.execute(text("UPDATE assessments SET evidence_id = :e WHERE id = :id"), {"e": eid, "id": s["id"]})
    jobs.enqueue(
        conn, "evaluate", {"application_id": str(s["application_id"])}, dedup_key=f"evaluate:{s['application_id']}"
    )
    return str(eid)


def view(
    conn: Connection, assessment_id: str, viewer: str | None = None, viewer_permissions: Sequence[str] = ()
) -> dict[str, Any]:
    s = _load(conn, assessment_id)
    names = {
        r.id: r.display_name
        for r in conn.execute(
            text("SELECT id, display_name FROM users WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(i) for i in (s["lead_assessor_id"], s["approved_by"]) if i]},
        )
    }
    lead = viewer is not None and str(s["lead_assessor_id"]) == str(viewer)
    return {
        "id": str(s["id"]),
        "type": s["assessment_type"],
        "application_id": str(s["application_id"] or ""),
        "app_key": s["app_key"],
        "status": s["status"],
        "scope": s["scope"],
        "lead_assessor": names.get(s["lead_assessor_id"]),
        "approved_by": names.get(s["approved_by"]),
        "due_at": s["due_at"],
        "submitted_at": s["submitted_at"],
        "approved_at": s["approved_at"],
        "evidence_id": str(s["evidence_id"]) if s["evidence_id"] else None,
        "can_record": lead and s["status"] in ("planned", "in_progress"),
        "can_decide": (not lead) and s["status"] == "submitted" and "assessment.approve" in viewer_permissions,
    }


def manual_samm_answers(conn: Connection, application_id: str) -> dict[tuple[str, int], tuple[float, str]]:
    """Latest usable SAMM interview evidence → {(stream, level): (value, confidence)} for the maturity engine."""
    row = conn.execute(
        text("""SELECT e.summary, e.confidence FROM evidence e JOIN evidence_current_state s
                  ON s.evidence_id = e.evidence_id
                WHERE e.application_id = :a AND e.evidence_type = 'assessment.samm_interview'
                  AND s.state IN ('active', 'expiring') ORDER BY e.observed_at DESC LIMIT 1"""),
        {"a": application_id},
    ).first()
    out: dict[tuple[str, int], tuple[float, str]] = {}
    if row is None:
        return out
    for key, value in (row.summary.get("answers") or {}).items():
        stream, _, level = str(key).partition(":")
        if level in ("1", "2", "3"):
            out[(stream, int(level))] = (float(value), row.confidence)
    return out
