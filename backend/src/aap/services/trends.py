# SPDX-License-Identifier: Apache-2.0
"""Read models for the dashboards: trends from the monthly snapshots, maturity roll-ups, the evidence and rejection
lists, and the activity feed. Everything runs as the caller (`aap_api`), so row-level security scopes it."""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle


def _function_keys(bundle: ConfigBundle) -> list[tuple[str, str]]:
    return [(bf["id"], bf["name"]) for bf in bundle.doc("samm")["business_functions"]]


def trend(
    conn: Connection, bundle: ConfigBundle, scope_type: str, scope_id: str, name: str, months: int
) -> dict[str, Any]:
    snaps = conn.execute(
        text("SELECT id, period, published FROM maturity_snapshots ORDER BY period DESC LIMIT :n"), {"n": months}
    ).all()[::-1]
    index = {str(s.id): i for i, s in enumerate(snaps)}
    ids = list(index)
    metrics: dict[str, list[float | None]] = {}
    for r in conn.execute(
        text("""SELECT snapshot_id, metric, value FROM posture_metrics
                WHERE scope_type = :t AND scope_id = :i AND snapshot_id = ANY(CAST(:ids AS uuid[]))"""),
        {"t": scope_type, "i": scope_id, "ids": ids},
    ):
        metrics.setdefault(r.metric, [None] * len(snaps))[index[str(r.snapshot_id)]] = float(r.value)
    functions = _function_keys(bundle)
    values: dict[str, list[float | None]] = {k: [None] * len(snaps) for k, _ in functions}
    for r in conn.execute(
        text("""SELECT ms.snapshot_id, fi.item_key, ms.score FROM maturity_scores ms
                JOIN framework_items fi ON fi.id = ms.framework_item_id
                WHERE ms.scope_type = CAST(:t AS scope_type) AND ms.scope_id = :i
                  AND ms.snapshot_id = ANY(CAST(:ids AS uuid[])) AND fi.item_key = ANY(:keys)"""),
        {"t": scope_type, "i": scope_id, "ids": ids, "keys": [k for k, _ in functions]},
    ):
        values[r.item_key][index[str(r.snapshot_id)]] = float(r.score)
    return {
        "scope": {"type": scope_type, "id": scope_id, "name": name},
        "periods": [f"{s.period:%Y-%m}" for s in snaps],
        "provisional": next((f"{s.period:%Y-%m}" for s in snaps if not s.published), None),
        "metrics": metrics,
        "samm_functions": [{"item": k, "name": n, "values": values[k]} for k, n in functions],
    }


def snapshots(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("""SELECT s.period, s.published, c.version AS catalogue, m.version AS methodology
                FROM maturity_snapshots s
                JOIN config_versions c ON c.id = s.catalogue_version_id
                JOIN config_versions m ON m.id = s.methodology_version_id
                ORDER BY s.period""")
    ).all()
    out, previous = [], None
    for r in rows:
        out.append(
            {
                "period": f"{r.period:%Y-%m}",
                "published": r.published,
                "catalogue_version": r.catalogue,
                "methodology_version": r.methodology,
                "methodology_changed": previous is not None and previous != r.methodology,
            }
        )
        previous = r.methodology
    return out


def _quantile(xs: Sequence[float], q: float) -> float:
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    pos = q * (len(s) - 1)
    lo = int(pos)
    return s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (pos - lo)


def rollup(
    conn: Connection, bundle: ConfigBundle, unit: Mapping[str, Any], period: str | None
) -> dict[str, Any] | None:
    """Distribution of application maturity in the unit's subtree (never a league table), the share of applications
    meeting their tier target, and the unit's own aggregate practice scores."""
    snap = conn.execute(
        text(
            "SELECT id, period FROM maturity_snapshots WHERE (CAST(:p AS text) IS NULL OR to_char(period, 'YYYY-MM') = CAST(:p AS text)) "
            "ORDER BY period DESC LIMIT 1"
        ),
        {"p": period},
    ).first()
    if snap is None:
        return None
    practices = {p["id"]: p["name"] for bf in bundle.doc("samm")["business_functions"] for p in bf["practices"]}
    rows = conn.execute(
        text("""WITH RECURSIVE sub AS (SELECT id FROM org_units WHERE id = :u
                  UNION ALL SELECT o.id FROM org_units o JOIN sub ON o.parent_id = sub.id)
                SELECT a.id AS app, a.tier_rank AS tier, fi.item_key, ms.score
                FROM applications a JOIN maturity_scores ms ON ms.scope_id = a.id AND ms.scope_type = 'application'
                JOIN framework_items fi ON fi.id = ms.framework_item_id
                WHERE a.org_unit_id IN (SELECT id FROM sub) AND ms.snapshot_id = :s AND fi.item_key = ANY(:keys)"""),
        {"u": unit["id"], "s": snap.id, "keys": list(practices)},
    ).all()
    by_practice: dict[str, list[float]] = {}
    per_app: dict[str, tuple[int, dict[str, float]]] = {}
    for r in rows:
        by_practice.setdefault(r.item_key, []).append(float(r.score))
        per_app.setdefault(str(r.app), (int(r.tier), {}))[1][r.item_key] = float(r.score)
    targets_doc = bundle.doc("samm_targets")["application_targets"]
    meeting: dict[str, list[bool]] = {}
    for tier, scores in per_app.values():
        targets = targets_doc.get(tier) or targets_doc.get(str(tier)) or {}
        meets = all(scores.get(k, 0) >= float(v) for k, v in targets.items())
        meeting.setdefault(str(tier), []).append(meets)
    own = conn.execute(
        text("""SELECT fi.item_key, ms.score, ms.automated_pct, ms.manual_independent_pct, ms.manual_self_pct, ms.unassessed_pct
                FROM maturity_scores ms JOIN framework_items fi ON fi.id = ms.framework_item_id
                WHERE ms.snapshot_id = :s AND ms.scope_type = 'organisation' AND ms.scope_id = :u AND fi.item_key = ANY(:keys)"""),
        {"s": snap.id, "u": unit["id"], "keys": list(practices)},
    ).all()
    return {
        "org_unit": dict(unit),
        "snapshot": f"{snap.period:%Y-%m}",
        "pct_apps_meeting_target_by_tier": {t: round(100 * sum(v) / len(v), 1) for t, v in sorted(meeting.items())},
        "distribution": [
            {
                "practice": k,
                "name": practices[k],
                "median": round(statistics.median(v), 2),
                "p25": round(_quantile(v, 0.25), 2),
                "p75": round(_quantile(v, 0.75), 2),
                "min": min(v),
                "max": max(v),
                "count": len(v),
            }
            for k, v in by_practice.items()
        ],
        "organisation_practices": [
            {
                "item": r.item_key,
                "name": practices.get(r.item_key, r.item_key),
                "level": "practice",
                "score": float(r.score),
                "provenance": {
                    "automated": float(r.automated_pct),
                    "manual_independent": float(r.manual_independent_pct),
                    "manual_self": float(r.manual_self_pct),
                    "unassessed": float(r.unassessed_pct),
                },
            }
            for r in own
        ],
    }


def evidence(
    conn: Connection, app_id: str | None, etype: str | None, confidence: str | None, limit: int
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("""SELECT e.evidence_id AS id, e.evidence_type AS type, e.confidence, e.result, e.observed_at,
                       coalesce(s.state::text, 'pending') AS state, e.tool, a.app_key, a.name AS application_name,
                       e.subject->>'repository' AS repository, e.subject->>'commit_sha' AS commit_sha
                FROM evidence e
                LEFT JOIN evidence_current_state s ON s.evidence_id = e.evidence_id
                LEFT JOIN applications a ON a.id = e.application_id
                WHERE (CAST(:a AS uuid) IS NULL OR e.application_id = CAST(:a AS uuid))
                  AND (CAST(:t AS text) IS NULL OR e.evidence_type = :t)
                  AND (CAST(:c AS text) IS NULL OR e.confidence::text = :c)
                ORDER BY e.observed_at DESC LIMIT :n"""),
        {"a": app_id, "t": etype, "c": confidence, "n": limit},
    )
    return [dict(r) for r in rows.mappings()]


def rejections(conn: Connection, app_id: str | None, org_wide: bool, limit: int) -> list[dict[str, Any]]:
    """Rejected submissions. Matched to an application through its repository, visible where the application is
    (the applications join is under row-level security); ones from unregistered repositories only to org-wide roles."""
    rows = conn.execute(
        text("""SELECT er.id, er.received_at, er.reason_code, er.run_id, er.details,
                       r.full_name AS repository, a.app_key, a.name AS application_name, a.id AS app_id
                FROM evidence_rejections er
                LEFT JOIN repositories r ON r.provider = er.repository_provider AND r.external_id = er.repository_external_id
                LEFT JOIN application_repositories ar ON ar.repository_id = r.id
                LEFT JOIN applications a ON a.id = ar.application_id
                WHERE (CAST(:a AS uuid) IS NULL OR a.id = CAST(:a AS uuid))
                ORDER BY er.received_at DESC LIMIT :n"""),
        {"a": app_id, "n": limit * 2},
    )
    out = []
    for r in rows.mappings():
        row = dict(r)
        if row.pop("app_id") is None and (not org_wide or app_id is not None):
            continue  # unregistered repository: org-wide roles only; or the application row is out of scope
        out.append(row)
    return out[:limit]


def activity(conn: Connection, app_id: str | None, limit: int) -> list[dict[str, Any]]:
    """Recent events across evidence, rejections, findings and exceptions, newest first. Never the audit log."""
    rows = conn.execute(
        text("""SELECT * FROM (
                  SELECT e.observed_at AS at, 'evidence_accepted' AS kind,
                         e.evidence_type || ' evidence (' || e.confidence || ')' AS title,
                         a.app_key, a.name AS application_name, e.evidence_id::text AS ref, a.id AS app_id
                  FROM evidence e JOIN applications a ON a.id = e.application_id
                  UNION ALL
                  SELECT fe.at, CASE WHEN fe.event_type = 'detected' THEN 'finding_opened' ELSE 'finding_closed' END,
                         f.title, a.app_key, a.name, f.id::text, a.id
                  FROM finding_events fe JOIN findings f ON f.id = fe.finding_id JOIN applications a ON a.id = f.application_id
                  WHERE fe.event_type = 'detected' OR fe.to_status = 'closed'
                  UNION ALL
                  SELECT xe.at, 'exception_' || xe.event_type, x.exception_key || ': ' || x.target_ref,
                         a.app_key, a.name, x.exception_key, a.id
                  FROM exception_events xe JOIN exceptions x ON x.id = xe.exception_id JOIN applications a ON a.id = x.application_id
                  WHERE xe.event_type IN ('approved', 'rejected', 'expired')
                  UNION ALL
                  SELECT er.received_at, 'evidence_rejected', 'Evidence rejected: ' || er.reason_code,
                         a.app_key, a.name, er.id::text, a.id
                  FROM evidence_rejections er
                  JOIN repositories r ON r.provider = er.repository_provider AND r.external_id = er.repository_external_id
                  JOIN application_repositories ar ON ar.repository_id = r.id
                  JOIN applications a ON a.id = ar.application_id
                ) feed
                WHERE CAST(:a AS uuid) IS NULL OR app_id = CAST(:a AS uuid)
                ORDER BY at DESC LIMIT :n"""),
        {"a": app_id, "n": limit},
    )
    return [{k: v for k, v in r.items() if k != "app_id"} for r in rows.mappings()]
