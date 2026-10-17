# SPDX-License-Identifier: Apache-2.0
"""Findings projection, lifecycle ledger and risk assessments (vulnerability management standard §2).

Rules enforced here and by the schema: one finding per fingerprint (dedup), closure only with verification
evidence (schema test T4), regression of a closed fingerprint reopens it, SLA due dates never extend.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.domain.risk import RiskResult
from aap.ids import uuid7

OPEN_STATUSES = ("new", "triaged", "ticketed", "fix_pending", "reopened")


@dataclass
class NewFinding:
    fingerprint: str
    application_id: str
    repository_id: str | None
    scope_type: str
    scope_ref: str
    finding_type: str
    source_system: str
    title: str
    description: str = ""
    cwe_id: int | None = None
    vulnerability_id: str | None = None
    component_id: str | None = None
    control_key: str | None = None
    location: dict[str, Any] = field(default_factory=dict)
    tool_severity: str | None = None
    source_refs: list[dict[str, Any]] = field(default_factory=list)


def _event(
    conn: Connection,
    finding_id: str,
    event_type: str,
    from_status: str | None,
    to_status: str | None,
    evidence_id: str | None = None,
    details: Mapping[str, Any] | None = None,
    actor: str = "platform",
) -> None:
    conn.execute(
        text("""INSERT INTO finding_events (id, finding_id, event_type, from_status, to_status, actor_type, actor_id,
                  evidence_id, details)
                VALUES (:id, :f, :t, :fs, :ts, :at, :actor, :ev, CAST(:d AS jsonb))"""),
        {
            "id": uuid7(),
            "f": finding_id,
            "t": event_type,
            "fs": from_status,
            "ts": to_status,
            "at": "system" if actor == "platform" else "user",
            "actor": actor,
            "ev": evidence_id,
            "d": json.dumps(dict(details or {}), default=str),
        },
    )


def observe(conn: Connection, f: NewFinding, evidence_id: str | None, seen_at: datetime) -> tuple[str, str]:
    """Record that a scan reported this finding. Returns (finding id, 'created' | 'seen' | 'reopened')."""
    row = conn.execute(text("SELECT id, status FROM findings WHERE fingerprint = :fp"), {"fp": f.fingerprint}).first()
    if row is None:
        fid = str(uuid7())
        conn.execute(
            text("""INSERT INTO findings (id, fingerprint, application_id, repository_id, scope_type, scope_ref,
                      finding_type, source_system, source_refs, title, description, cwe_id, vulnerability_id,
                      component_id, control_key, location, tool_severity, status, first_seen_at, last_seen_at,
                      last_seen_evidence_id)
                    VALUES (:id, :fp, :app, :repo, :st, :sr, :ft, :src, CAST(:refs AS jsonb), :title, :desc, :cwe, :vuln,
                      :comp, :ck, CAST(:loc AS jsonb), :sev, 'new', :seen, :seen, :ev)"""),
            {
                "id": fid,
                "fp": f.fingerprint,
                "app": f.application_id,
                "repo": f.repository_id,
                "st": f.scope_type,
                "sr": f.scope_ref,
                "ft": f.finding_type,
                "src": f.source_system,
                "refs": json.dumps(f.source_refs),
                "title": f.title[:500],
                "desc": f.description[:4000],
                "cwe": f.cwe_id,
                "vuln": f.vulnerability_id,
                "comp": f.component_id,
                "ck": f.control_key,
                "loc": json.dumps(f.location),
                "sev": f.tool_severity,
                "seen": seen_at,
                "ev": evidence_id,
            },
        )
        _event(conn, fid, "detected", None, "new", evidence_id)
        return fid, "created"

    fid, status = str(row.id), row.status
    if status == "closed":
        conn.execute(
            text(
                "UPDATE findings SET status = 'reopened', closed_at = NULL, closure_evidence_id = NULL, "
                "last_seen_at = :seen, last_seen_evidence_id = :ev WHERE id = :id"
            ),
            {"id": fid, "seen": seen_at, "ev": evidence_id},
        )
        _event(conn, fid, "reopened", "closed", "reopened", evidence_id, {"reason": "regression: detected again"})
        return fid, "reopened"
    conn.execute(
        text("UPDATE findings SET last_seen_at = :seen, last_seen_evidence_id = :ev WHERE id = :id"),
        {"id": fid, "seen": seen_at, "ev": evidence_id},
    )
    return fid, "seen"


def close_absent(
    conn: Connection, *, scope_ref: str, finding_type: str, source_system: str, seen: Iterable[str], evidence_id: str
) -> list[str]:
    """A re-scan of the same scope that no longer reports a finding verifies the fix and closes it.
    The closing scan is recorded as the closure evidence (schema test T4)."""
    rows = conn.execute(
        text("""UPDATE findings SET status = 'closed', closed_at = now(), closure_evidence_id = :ev
                WHERE scope_ref = :sr AND finding_type = :ft AND source_system = :src
                  AND status = ANY(:open) AND NOT (fingerprint = ANY(:seen))
                RETURNING id"""),
        {
            "ev": evidence_id,
            "sr": scope_ref,
            "ft": finding_type,
            "src": source_system,
            "open": list(OPEN_STATUSES),
            "seen": list(seen),
        },
    ).all()
    for r in rows:
        _event(conn, str(r.id), "verified", None, "closed", evidence_id, {"reason": "absent from re-scan"})
    return [str(r.id) for r in rows]


def record_risk(
    conn: Connection,
    finding_id: str,
    result: RiskResult,
    model_version_id: str,
    model: Mapping[str, Any],
    factor: float = 1.0,
) -> str:
    """Store the assessment and apply priority + SLA. Due dates are computed from first detection and never extend:
    a re-score that lowers priority keeps the earlier deadline (ADR-011)."""
    ra_id = str(uuid7())
    conn.execute(
        text("""INSERT INTO finding_risk_assessments (id, finding_id, model_version_id, inputs, likelihood, impact, score,
                  priority, applied_rules, explanation)
                VALUES (:id, :f, :mv, CAST(:inputs AS jsonb), :l, :i, :s, :p, :rules, :expl)"""),
        {
            "id": ra_id,
            "f": finding_id,
            "mv": model_version_id,
            "inputs": json.dumps(result.inputs, default=str),
            "l": result.likelihood,
            "i": result.impact,
            "s": result.score,
            "p": result.priority,
            "rules": list(result.applied_rules),
            "expl": result.explanation,
        },
    )
    first_seen = conn.execute(text("SELECT first_seen_at FROM findings WHERE id = :f"), {"f": finding_id}).scalar_one()
    conn.execute(
        text("""UPDATE findings SET priority = :p, risk_score = :s, risk_assessment_id = :ra,
                  triage_due_at = LEAST(COALESCE(triage_due_at, :td), :td),
                  sla_due_at = LEAST(COALESCE(sla_due_at, :rd), :rd)
                WHERE id = :f"""),
        {
            "p": result.priority,
            "s": result.score,
            "ra": ra_id,
            "f": finding_id,
            "td": result.triage_due(first_seen, model),
            "rd": result.remediation_due(first_seen, model, factor),
        },
    )
    return ra_id


def mark_sla_breaches(conn: Connection, now: datetime) -> int:
    return conn.execute(
        text(
            "UPDATE findings SET sla_breached = true WHERE NOT sla_breached AND sla_due_at < :now "
            "AND status = ANY(:open)"
        ),
        {"now": now, "open": list(OPEN_STATUSES)},
    ).rowcount


def for_application(conn: Connection, application_id: str) -> Sequence[Mapping[str, Any]]:
    return (
        conn.execute(
            text("""SELECT f.*, v.vuln_key FROM findings f LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
                WHERE f.application_id = :a"""),
            {"a": application_id},
        )
        .mappings()
        .all()
    )
