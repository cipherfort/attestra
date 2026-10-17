# SPDX-License-Identifier: Apache-2.0
"""Evidence ledger persistence (evidence model section 2, section 6; ADR-016).

Inserts are serialised per monthly chain with an advisory lock, so `prev_hash` always points at the chain's
previous record. Rows are never updated: freshness lives in `evidence_validity_events` (append-only) and the
`evidence_current_state` projection.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text

from aap.domain.evidence import record_hash, verify_chain
from aap.ids import uuid7


def normalise_summary(value: Any) -> Any:
    """Hashed records carry no floats (JCS divergence); floats become decimal strings, everywhere they are stored."""
    if isinstance(value, Mapping):
        return {str(k): normalise_summary(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [normalise_summary(v) for v in value]
    if isinstance(value, float):
        return format(value, "g")
    return value


@dataclass
class NewEvidence:
    evidence_type: str
    application_id: str | None
    scope_type: str
    scope_ref: str
    subject: dict[str, Any]
    producer_type: str
    producer_ref: str
    observed_at: datetime
    result: str
    confidence: str
    tool: str | None = None
    tool_version: str | None = None
    policy_ref: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    confidence_reasons: list[str] = field(default_factory=list)
    run_ref: dict[str, Any] | None = None
    raw_location: str | None = None
    raw_sha256: list[str] = field(default_factory=list)
    attestation_ref: str | None = None


def _utc(ts: datetime) -> str:
    """Hash timestamps in UTC: PostgreSQL returns timestamptz in the session time zone."""
    return ts.astimezone(UTC).isoformat()


def chain_name(ts: datetime) -> str:
    return f"evidence_{ts:%Y_%m}"


def _month_bounds(ts: datetime) -> tuple[datetime, datetime]:
    start = ts.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end


def hashed_fields(evidence_id: str, ingested_at: datetime, ev: NewEvidence) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "ingested_at": _utc(ingested_at),
        "evidence_type": ev.evidence_type,
        "application_id": ev.application_id,
        "scope_type": ev.scope_type,
        "scope_ref": ev.scope_ref,
        "subject": normalise_summary(ev.subject),
        "producer_type": ev.producer_type,
        "producer_ref": ev.producer_ref,
        "tool": ev.tool,
        "tool_version": ev.tool_version,
        "policy_ref": ev.policy_ref,
        "observed_at": _utc(ev.observed_at),
        "result": ev.result,
        "summary": normalise_summary(ev.summary),
        "confidence": ev.confidence,
        "confidence_reasons": list(ev.confidence_reasons),
        "run_ref": normalise_summary(ev.run_ref),
        "raw_location": ev.raw_location,
        "raw_sha256": list(ev.raw_sha256),
        "attestation_ref": ev.attestation_ref,
    }


def insert_evidence(conn: Connection, ev: NewEvidence, valid_until: datetime | None = None) -> UUID:
    now = datetime.now(UTC)
    chain = chain_name(now)
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:chain))"), {"chain": chain})
    start, end = _month_bounds(now)
    last = conn.execute(
        text(
            "SELECT record_hash, ingested_at FROM evidence WHERE ingested_at >= :s AND ingested_at < :e "
            "ORDER BY ingested_at DESC, evidence_id DESC LIMIT 1"
        ),
        {"s": start, "e": end},
    ).first()
    prev_hash: bytes | None = bytes(last.record_hash) if last else None
    ingested_at = max(now, last.ingested_at + timedelta(microseconds=1)) if last else now
    evidence_id = uuid7()
    fields = hashed_fields(str(evidence_id), ingested_at, ev)
    rhash = record_hash(prev_hash, fields)
    conn.execute(
        text("""
        INSERT INTO evidence (evidence_id, ingested_at, evidence_type, application_id, scope_type, scope_ref, subject,
          producer_type, producer_ref, tool, tool_version, policy_ref, observed_at, result, summary, confidence,
          confidence_reasons, run_ref, raw_location, raw_sha256, attestation_ref, prev_hash, record_hash)
        VALUES (:id, :ingested_at, :etype, :app, :scope_type, :scope_ref, CAST(:subject AS jsonb), :ptype, :pref,
          :tool, :tool_version, :policy_ref, :observed_at, :result, CAST(:summary AS jsonb), :confidence,
          :reasons, CAST(:run_ref AS jsonb), :raw_location, :raw_sha256, :attestation_ref, :prev_hash, :record_hash)
        """),
        {
            "id": evidence_id,
            "ingested_at": ingested_at,
            "etype": ev.evidence_type,
            "app": ev.application_id,
            "scope_type": ev.scope_type,
            "scope_ref": ev.scope_ref,
            "subject": json.dumps(fields["subject"]),
            "ptype": ev.producer_type,
            "pref": ev.producer_ref,
            "tool": ev.tool,
            "tool_version": ev.tool_version,
            "policy_ref": ev.policy_ref,
            "observed_at": ev.observed_at,
            "result": ev.result,
            "summary": json.dumps(fields["summary"]),
            "confidence": ev.confidence,
            "reasons": ev.confidence_reasons,
            "run_ref": json.dumps(fields["run_ref"]) if ev.run_ref is not None else None,
            "raw_location": ev.raw_location,
            "raw_sha256": [bytes.fromhex(h) for h in ev.raw_sha256],
            "attestation_ref": ev.attestation_ref,
            "prev_hash": prev_hash,
            "record_hash": rhash,
        },
    )
    conn.execute(
        text("""
        INSERT INTO evidence_current_state (evidence_id, application_id, evidence_type, scope_type, scope_ref, state,
          confidence, observed_at, valid_until)
        VALUES (:id, :app, :etype, :scope_type, :scope_ref, 'active', :confidence, :observed_at, :valid_until)
        """),
        {
            "id": evidence_id,
            "app": ev.application_id,
            "etype": ev.evidence_type,
            "scope_type": ev.scope_type,
            "scope_ref": ev.scope_ref,
            "confidence": ev.confidence,
            "observed_at": ev.observed_at,
            "valid_until": valid_until,
        },
    )
    record_validity(conn, evidence_id, "active", "ingested")
    return evidence_id


def record_validity(
    conn: Connection, evidence_id: UUID | str, state: str, reason: str, related_ref: str | None = None
) -> None:
    conn.execute(
        text(
            "INSERT INTO evidence_validity_events (id, evidence_id, state, reason, related_ref) "
            "VALUES (:id, :eid, :state, :reason, :ref)"
        ),
        {"id": uuid7(), "eid": evidence_id, "state": state, "reason": reason, "ref": related_ref},
    )


def update_projection(
    conn: Connection, evidence_id: UUID | str, state: str, valid_until: datetime | None, reason: str
) -> bool:
    """Move the current-state projection; returns True (and appends a validity event) only on a change."""
    changed = conn.execute(
        text(
            "UPDATE evidence_current_state SET state = :state, valid_until = :vu, updated_at = now() "
            "WHERE evidence_id = :id AND state IS DISTINCT FROM CAST(:state AS evidence_state) RETURNING evidence_id"
        ),
        {"id": evidence_id, "state": state, "vu": valid_until},
    ).first()
    if changed:
        record_validity(conn, evidence_id, state, reason)
    return changed is not None


def evidence_for_application(conn: Connection, application_id: str) -> Sequence[Any]:
    return conn.execute(
        text("""
        SELECT e.evidence_id, e.evidence_type, e.scope_type, e.scope_ref, e.subject, e.producer_type, e.producer_ref,
               e.tool, e.tool_version, e.observed_at, e.ingested_at, e.result, e.summary, e.confidence,
               e.confidence_reasons, e.run_ref, e.raw_location, e.attestation_ref, s.state, s.valid_until,
               (SELECT max(v.occurred_at) FROM evidence_validity_events v
                 WHERE v.evidence_id = e.evidence_id AND v.reason = 'reconfirmed') AS last_confirmed
        FROM evidence e JOIN evidence_current_state s ON s.evidence_id = e.evidence_id
        WHERE e.application_id = :app AND s.state <> 'revoked'
        ORDER BY e.observed_at DESC
        """),
        {"app": application_id},
    ).all()


def record_rejection(
    conn: Connection,
    provider: str | None,
    repository_external_id: int | str | None,
    run_id: int | None,
    reason: str,
    details: Mapping[str, Any],
) -> None:
    conn.execute(
        text(
            "INSERT INTO evidence_rejections (id, repository_provider, repository_external_id, run_id, reason_code, details) "
            "VALUES (:id, :prov, :repo, :run, :reason, CAST(:details AS jsonb))"
        ),
        {
            "id": uuid7(),
            "prov": provider,
            "repo": None if repository_external_id is None else str(repository_external_id),
            "run": run_id,
            "reason": reason,
            "details": json.dumps(normalise_summary(dict(details))),
        },
    )


def verify_month(conn: Connection, month: datetime) -> tuple[int, int | None]:
    """Recompute the chain for one month (daily integrity job). Returns (records checked, first broken index)."""
    start, end = _month_bounds(month)
    rows = (
        conn.execute(
            text(
                "SELECT * FROM evidence WHERE ingested_at >= :s AND ingested_at < :e ORDER BY ingested_at, evidence_id"
            ),
            {"s": start, "e": end},
        )
        .mappings()
        .all()
    )
    chain = []
    for r in rows:
        ev = NewEvidence(
            evidence_type=r["evidence_type"],
            application_id=str(r["application_id"]) if r["application_id"] else None,
            scope_type=r["scope_type"],
            scope_ref=r["scope_ref"],
            subject=r["subject"],
            producer_type=r["producer_type"],
            producer_ref=r["producer_ref"],
            observed_at=r["observed_at"],
            result=r["result"],
            confidence=r["confidence"],
            tool=r["tool"],
            tool_version=r["tool_version"],
            policy_ref=r["policy_ref"],
            summary=r["summary"],
            confidence_reasons=list(r["confidence_reasons"]),
            run_ref=r["run_ref"],
            raw_location=r["raw_location"],
            raw_sha256=[bytes(b).hex() for b in r["raw_sha256"]],
            attestation_ref=r["attestation_ref"],
        )
        fields = hashed_fields(str(r["evidence_id"]), r["ingested_at"], ev)
        chain.append((fields, bytes(r["record_hash"]), bytes(r["prev_hash"]) if r["prev_hash"] else None))
    return len(chain), verify_chain(chain)
