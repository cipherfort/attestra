# SPDX-License-Identifier: Apache-2.0
"""Control evaluation ledger + current-state projection (control framework section 5)."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, cast

from sqlalchemy import Connection, text

from aap.ids import uuid7


def record(
    conn: Connection,
    *,
    application_id: str,
    control_key: str,
    control_id: str,
    scope_type: str,
    scope_ref: str,
    requirement: str,
    state: str,
    explanation: str,
    evaluator: str,
    evaluator_build: str,
    catalogue_version_id: str,
    evidence_ids: Sequence[str],
    details: Mapping[str, Any],
    observe_mode: bool = False,
) -> bool:
    """Append to the ledger only when the outcome changed (state, explanation or evidence). Always refresh the
    projection's last_evaluated_at. Returns True when a new ledger entry was written."""
    current = conn.execute(
        text("""SELECT cs.state, cs.last_evaluation_id, ce.explanation, ce.evidence_ids
                FROM control_states cs
                LEFT JOIN control_evaluations ce ON ce.id = cs.last_evaluation_id
                WHERE cs.application_id = :a AND cs.control_key = :k AND cs.scope_type = :st AND cs.scope_ref = :sr"""),
        {"a": application_id, "k": control_key, "st": scope_type, "sr": scope_ref},
    ).first()
    unchanged = (
        current is not None
        and current.state == state
        and current.explanation == explanation
        and sorted(map(str, current.evidence_ids or [])) == sorted(map(str, evidence_ids))
    )
    if unchanged:
        conn.execute(
            text(
                "UPDATE control_states SET last_evaluated_at = now(), requirement = :req "
                "WHERE application_id = :a AND control_key = :k AND scope_type = :st AND scope_ref = :sr"
            ),
            {"a": application_id, "k": control_key, "st": scope_type, "sr": scope_ref, "req": requirement},
        )
        return False

    eval_id = uuid7()
    conn.execute(
        text("""INSERT INTO control_evaluations (id, application_id, control_key, control_id, scope_type, scope_ref, state,
                  previous_state, evaluator, evaluator_build, catalogue_version_id, evidence_ids, explanation, details,
                  observe_mode)
                VALUES (:id, :a, :k, :cid, :st, :sr, :state, :prev, :ev, :build, :cat, :eids, :expl,
                        CAST(:details AS jsonb), :obs)"""),
        {
            "id": eval_id,
            "a": application_id,
            "k": control_key,
            "cid": control_id,
            "st": scope_type,
            "sr": scope_ref,
            "state": state,
            "prev": current.state if current else None,
            "ev": evaluator,
            "build": evaluator_build,
            "cat": catalogue_version_id,
            "eids": list(evidence_ids),
            "expl": explanation,
            "details": json.dumps(dict(details), default=str),
            "obs": observe_mode,
        },
    )
    conn.execute(
        text("""INSERT INTO control_states (application_id, control_key, scope_type, scope_ref, requirement, state, since,
                  last_evaluation_id, last_evaluated_at, observe_mode)
                VALUES (:a, :k, :st, :sr, :req, :state, now(), :eid, now(), :obs)
                ON CONFLICT (application_id, control_key, scope_type, scope_ref) DO UPDATE SET
                  requirement = EXCLUDED.requirement,
                  since = CASE WHEN control_states.state = EXCLUDED.state THEN control_states.since ELSE now() END,
                  state = EXCLUDED.state, last_evaluation_id = EXCLUDED.last_evaluation_id,
                  last_evaluated_at = now(), observe_mode = EXCLUDED.observe_mode"""),
        {
            "a": application_id,
            "k": control_key,
            "st": scope_type,
            "sr": scope_ref,
            "req": requirement,
            "state": state,
            "eid": eval_id,
            "obs": observe_mode,
        },
    )
    return True


def current_states(conn: Connection, application_id: str) -> Sequence[Mapping[str, Any]]:
    rows = (
        conn.execute(
            text("""SELECT cs.control_key, cs.scope_type, cs.scope_ref, cs.requirement, cs.state, cs.since,
                       cs.last_evaluated_at, cs.observe_mode, ce.explanation, ce.evidence_ids, ce.evaluator, ce.details
                FROM control_states cs JOIN control_evaluations ce ON ce.id = cs.last_evaluation_id
                WHERE cs.application_id = :a ORDER BY cs.control_key, cs.scope_ref"""),
            {"a": application_id},
        )
        .mappings()
        .all()
    )
    return cast("Sequence[Mapping[str, Any]]", rows)  # text() rows are keyed by column name


def history(conn: Connection, application_id: str, control_key: str, limit: int = 50) -> Sequence[Mapping[str, Any]]:
    rows = (
        conn.execute(
            text("""SELECT id, evaluated_at, scope_type, scope_ref, state, previous_state, evaluator, evaluator_build,
                       catalogue_version_id, evidence_ids, explanation, details
                FROM control_evaluations WHERE application_id = :a AND control_key = :k
                ORDER BY evaluated_at DESC LIMIT :l"""),
            {"a": application_id, "k": control_key, "l": limit},
        )
        .mappings()
        .all()
    )
    return cast("Sequence[Mapping[str, Any]]", rows)  # text() rows are keyed by column name
