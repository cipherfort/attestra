# SPDX-License-Identifier: Apache-2.0
"""Application maturity from current control states (methodology section A.3)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection

from aap.config import ConfigBundle
from aap.domain.maturity import ManualAnswer, MaturityReport, StateInput, compute
from aap.services.assessments import manual_samm_answers
from aap.services.evaluation import STATE_RANK
from aap.store import control_store, registry


def app_states(conn: Connection, application_id: str) -> dict[str, StateInput]:
    """One state per control: the worst across its applicable scopes (a control is only as good as its weakest repo)."""
    per: dict[str, list[Mapping[str, Any]]] = {}
    for s in control_store.current_states(conn, application_id):
        per.setdefault(s["control_key"], []).append(s)
    out: dict[str, StateInput] = {}
    for key, scopes in per.items():
        applicable = [s for s in scopes if s["requirement"] != "n/a"] or scopes
        worst = min(applicable, key=lambda s: STATE_RANK[s["state"]])
        fraction = (worst["details"] or {}).get("fraction")
        out[key] = StateInput(
            key,
            worst["state"],
            worst["requirement"],
            bool(worst["observe_mode"]),
            float(fraction) if fraction is not None else None,
        )
    return out


def application_maturity(conn: Connection, bundle: ConfigBundle, application_id: str) -> MaturityReport:
    app = registry.application_context(conn, application_id)
    if app is None:
        raise LookupError(application_id)
    tier = int(app["tier_rank"] or 4)
    targets = bundle.doc("samm_targets")["application_targets"].get(tier) or bundle.doc("samm_targets")[
        "application_targets"
    ].get(str(tier))
    app_practices = {
        p["id"]
        for bf in bundle.doc("samm")["business_functions"]
        for p in bf["practices"]
        if not p["id"].startswith("G-")
    }
    return compute(
        app_states(conn, application_id),
        bundle.controls,
        bundle.doc("samm"),
        bundle.doc("maturity_methodology"),
        manual={k: ManualAnswer(v, c) for k, (v, c) in manual_samm_answers(conn, application_id).items()},
        targets=targets,
        practices_in_scope=app_practices,
    )
