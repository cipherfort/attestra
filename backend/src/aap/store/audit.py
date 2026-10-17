# SPDX-License-Identifier: Apache-2.0
"""Audit events: append-only, hash-chained per month like evidence (ADR-016)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aap.domain.evidence import record_hash
from aap.ids import uuid7


def write(
    conn: Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    outcome: str,
    target_type: str | None = None,
    target_id: str | None = None,
    application_id: str | None = None,
    request_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    now = datetime.now(UTC)
    chain = f"audit_{now:%Y_%m}"
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:c))"), {"c": chain})
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last = conn.execute(
        text("SELECT record_hash, at FROM audit_events WHERE at >= :s ORDER BY at DESC, id DESC LIMIT 1"), {"s": start}
    ).first()
    at = max(now, last.at + timedelta(microseconds=1)) if last else now
    event_id = uuid7()
    fields = {
        "id": str(event_id),
        "at": at.astimezone(UTC).isoformat(),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "application_id": application_id,
        "outcome": outcome,
        "request_id": request_id,
        "details": json.loads(json.dumps(dict(details or {}), default=str)),
    }
    prev = bytes(last.record_hash) if last else None
    conn.execute(
        text("""INSERT INTO audit_events (id, at, actor_type, actor_id, action, target_type, target_id, application_id,
                  outcome, request_id, details, prev_hash, record_hash)
                VALUES (:id, :at, :atype, :actor, :action, :tt, :tid, :app, :outcome, :rid, CAST(:details AS jsonb),
                        :prev, :hash)"""),
        {
            "id": event_id,
            "at": at,
            "atype": actor_type,
            "actor": actor_id,
            "action": action,
            "tt": target_type,
            "tid": target_id,
            "app": application_id,
            "outcome": outcome,
            "rid": request_id,
            "details": json.dumps(fields["details"]),
            "prev": prev,
            "hash": record_hash(prev, fields),
        },
    )
