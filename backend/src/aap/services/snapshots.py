# SPDX-License-Identifier: Apache-2.0
"""Monthly posture snapshots for trend reporting (component C13; migration 0010).

One snapshot per month holds, for every classified application and every org unit above it:
* SAMM maturity per practice and business function (`maturity_scores`), with answer provenance;
* posture metrics (`posture_metrics`): mandatory controls and how many current evidence proves, open findings by
  priority and past their deadline, evidence accepted and rejected during the month, the SAMM overall score.

The current month is provisional: the scheduler refreshes it (at most every few hours) from the live control
states. Once the month is over it is published and never changes again (database trigger).

`backfill` computes earlier months *as of* each month end, with the real evaluator, using only the evidence and
findings that existed then (nothing is written to the evaluation ledger). That is how a new deployment, or the
demo, gets a history; it is never invented.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.domain.maturity import MaturityReport, StateInput
from aap.services import evaluation, maturity_service
from aap.services.evaluation import STATE_RANK, ScopeResult
from aap.store import config_store

PRIORITIES = ("P1", "P2", "P3", "P4")
REFRESH = timedelta(hours=6)
# org-unit aggregation: everything is summed except these, which are averaged over the unit's applications
AVERAGED = {"samm_overall"}


def month_start(d: date | datetime) -> date:
    return date(d.year, d.month, 1)


def add_months(period: date, n: int) -> date:
    y, m = divmod(period.month - 1 + n, 12)
    return date(period.year + y, m + 1, 1)


def month_end(period: date) -> datetime:
    """The last instant of the month (UTC)."""
    nxt = add_months(period, 1)
    return datetime(nxt.year, nxt.month, 1, tzinfo=UTC) - timedelta(microseconds=1)


@dataclass(frozen=True)
class SnapshotResult:
    period: date
    applications: int
    org_units: int
    published: bool


def states_from_results(results: Sequence[ScopeResult]) -> dict[str, StateInput]:
    """One state per control: the worst across its applicable scopes (same rule as maturity_service.app_states)."""
    per: dict[str, list[ScopeResult]] = defaultdict(list)
    for r in results:
        per[r.control_key].append(r)
    out: dict[str, StateInput] = {}
    for key, scopes in per.items():
        applicable = [s for s in scopes if s.requirement != "n/a"] or scopes
        worst = min(applicable, key=lambda s: STATE_RANK[s.state])
        fraction = worst.details.get("fraction")
        out[key] = StateInput(
            key, worst.state, worst.requirement, False, float(fraction) if fraction is not None else None
        )
    return out


def _app_metrics(
    conn: Connection, app_id: str, states: Mapping[str, StateInput], period: date, at: datetime
) -> dict[str, float]:
    mandatory = [s for s in states.values() if s.requirement == "mandatory"]
    m: dict[str, float] = {
        "mandatory_total": len(mandatory),
        "mandatory_satisfied": sum(1 for s in mandatory if s.state == "satisfied"),
    }
    open_rows = conn.execute(
        text("""SELECT priority::text AS p, count(*) AS n, count(*) FILTER (WHERE sla_due_at < :at) AS late
                FROM findings
                WHERE application_id = :a AND first_seen_at <= :at AND status <> 'false_positive'
                  AND (closed_at IS NULL OR closed_at > :at)
                GROUP BY priority"""),
        {"a": app_id, "at": at},
    ).all()
    for p in PRIORITIES:
        m[f"findings_open_{p.lower()}"] = 0
    m["findings_past_sla"] = 0
    for r in open_rows:
        if r.p in PRIORITIES:
            m[f"findings_open_{r.p.lower()}"] = int(r.n)
        m["findings_past_sla"] += int(r.late)
    start = datetime(period.year, period.month, 1, tzinfo=UTC)
    m["evidence_accepted"] = int(
        conn.execute(
            text(
                "SELECT count(*) FROM evidence WHERE application_id = :a AND observed_at >= :s AND observed_at <= :at"
            ),
            {"a": app_id, "s": start, "at": at},
        ).scalar_one()
    )
    m["evidence_rejected"] = int(
        conn.execute(
            text("""SELECT count(*) FROM evidence_rejections er
                    JOIN repositories r ON r.provider = er.repository_provider AND r.external_id = er.repository_external_id
                    JOIN application_repositories ar ON ar.repository_id = r.id
                    WHERE ar.application_id = :a AND er.received_at >= :s AND er.received_at <= :at"""),
            {"a": app_id, "s": start, "at": at},
        ).scalar_one()
    )
    return m


def _write_scores(
    conn: Connection,
    snapshot_id: str,
    scope_type: str,
    scope_id: str,
    items: Mapping[str, Any],
    samm_items: Mapping[str, str],
) -> None:
    for key, s in items.items():
        item_id = samm_items.get(key)
        if item_id is None:
            continue
        prov = s["provenance"]
        conn.execute(
            text("""INSERT INTO maturity_scores (snapshot_id, scope_type, scope_id, framework_item_id, score, automated_pct,
                      manual_independent_pct, manual_self_pct, unassessed_pct)
                    VALUES (:snap, CAST(:st AS scope_type), :sid, :item, :score, :a, :mi, :ms, :u)"""),
            {
                "snap": snapshot_id,
                "st": scope_type,
                "sid": scope_id,
                "item": item_id,
                "score": round(min(3.0, max(0.0, float(s["score"]))), 2),
                "a": round(float(prov.get("automated", 0)), 2),
                "mi": round(float(prov.get("manual_independent", 0)), 2),
                "ms": round(float(prov.get("manual_self", 0)), 2),
                "u": round(float(prov.get("unassessed", 0)), 2),
            },
        )


def _write_metrics(
    conn: Connection, snapshot_id: str, scope_type: str, scope_id: str, metrics: Mapping[str, float]
) -> None:
    for name, value in metrics.items():
        conn.execute(
            text(
                "INSERT INTO posture_metrics (snapshot_id, scope_type, scope_id, metric, value) VALUES (:s, :t, :i, :m, :v)"
            ),
            {"s": snapshot_id, "t": scope_type, "i": scope_id, "m": name, "v": value},
        )


def _report_items(report: MaturityReport) -> dict[str, dict[str, Any]]:
    return {
        k: {"score": v.score, "provenance": v.provenance} for k, v in {**report.practices, **report.functions}.items()
    }


def take(
    conn: Connection, bundle: ConfigBundle, period: date, at: datetime, *, history: bool, publish: bool
) -> SnapshotResult | None:
    """Compute (or recompute, while unpublished) the snapshot for `period` as of `at`. `history=True` evaluates as
    of `at` without writing to the ledger; otherwise the live control states are used. Returns None for a period
    that is already published."""
    period = month_start(period)
    cfg = config_store.active(conn)
    row = conn.execute(text("SELECT id, published FROM maturity_snapshots WHERE period = :p"), {"p": period}).first()
    if row is not None and row.published:
        return None
    if row is None:
        snap = str(
            conn.execute(
                text("""INSERT INTO maturity_snapshots (period, taken_at, catalogue_version_id, methodology_version_id)
                        VALUES (:p, :at, :cat, :meth) RETURNING id"""),
                {"p": period, "at": at, "cat": cfg.ids["control_catalogue"], "meth": cfg.ids["maturity_methodology"]},
            ).scalar_one()
        )
    else:
        snap = str(row.id)
        conn.execute(text("DELETE FROM maturity_scores WHERE snapshot_id = :s"), {"s": snap})
        conn.execute(text("DELETE FROM posture_metrics WHERE snapshot_id = :s"), {"s": snap})
        conn.execute(
            text(
                "UPDATE maturity_snapshots SET taken_at = :at, catalogue_version_id = :cat, methodology_version_id = :meth WHERE id = :s"
            ),
            {"s": snap, "at": at, "cat": cfg.ids["control_catalogue"], "meth": cfg.ids["maturity_methodology"]},
        )

    apps = conn.execute(
        text("""SELECT id, org_unit_id FROM applications
                WHERE tier_rank IS NOT NULL AND lifecycle <> 'retired' AND created_at <= :at"""),
        {"at": at},
    ).all()
    per_app_metrics: dict[str, dict[str, float]] = {}
    per_app_items: dict[str, dict[str, dict[str, Any]]] = {}
    for a in apps:
        app_id = str(a.id)
        if history:
            results = evaluation.evaluate_application(
                conn, bundle, app_id, at, gap_grace=None, record=False, as_of=True
            )
            states = states_from_results(results)
        else:
            states = maturity_service.app_states(conn, app_id)
        report = maturity_service.maturity_from_states(conn, bundle, app_id, states)
        items = _report_items(report)
        metrics = _app_metrics(conn, app_id, states, period, at)
        metrics["samm_overall"] = round(report.overall, 2)
        _write_scores(conn, snap, "application", app_id, items, cfg.samm_items)
        _write_metrics(conn, snap, "application", app_id, metrics)
        per_app_metrics[app_id] = metrics
        per_app_items[app_id] = items

    # roll up to every org unit: the applications in its subtree
    units = conn.execute(text("SELECT id, parent_id FROM org_units")).all()
    parent = {str(u.id): (str(u.parent_id) if u.parent_id else None) for u in units}
    members: dict[str, list[str]] = defaultdict(list)
    for a in apps:
        unit: str | None = str(a.org_unit_id)
        while unit is not None:
            members[unit].append(str(a.id))
            unit = parent.get(unit)
    for unit_id, app_ids in members.items():
        names = {k for i in app_ids for k in per_app_metrics[i]}
        rolled = {
            k: (
                round(statistics.fmean(per_app_metrics[i][k] for i in app_ids if k in per_app_metrics[i]), 2)
                if k in AVERAGED
                else sum(per_app_metrics[i].get(k, 0) for i in app_ids)
            )
            for k in names
        }
        rolled["applications"] = len(app_ids)
        _write_metrics(conn, snap, "organisation", unit_id, rolled)
        keys = {k for i in app_ids for k in per_app_items[i]}
        items = {
            k: {
                "score": statistics.fmean(per_app_items[i][k]["score"] for i in app_ids if k in per_app_items[i]),
                "provenance": {
                    p: statistics.fmean(
                        per_app_items[i][k]["provenance"].get(p, 0) for i in app_ids if k in per_app_items[i]
                    )
                    for p in ("automated", "manual_independent", "manual_self", "unassessed")
                },
            }
            for k in keys
        }
        _write_scores(conn, snap, "organisation", unit_id, items, cfg.samm_items)
    if publish:
        conn.execute(text("UPDATE maturity_snapshots SET published = true WHERE id = :s"), {"s": snap})
    return SnapshotResult(period, len(apps), len(members), publish)


def tick(conn: Connection, bundle: ConfigBundle, now: datetime) -> SnapshotResult | None:
    """Scheduler: publish finished months, refresh the current month if its snapshot is older than REFRESH."""
    current = month_start(now)
    conn.execute(
        text("UPDATE maturity_snapshots SET published = true WHERE period < :p AND NOT published"), {"p": current}
    )
    taken = conn.execute(text("SELECT taken_at FROM maturity_snapshots WHERE period = :p"), {"p": current}).scalar()
    if taken is not None and now - taken < REFRESH:
        return None
    return take(conn, bundle, current, now, history=False, publish=False)


def backfill(conn: Connection, bundle: ConfigBundle, months: int, now: datetime) -> list[SnapshotResult]:
    """Compute the `months - 1` finished months before the current one (as of each month end) and the current
    month from live states. Published months are left as they are."""
    current = month_start(now)
    done = []
    for i in range(months - 1, 0, -1):
        period = add_months(current, -i)
        r = take(conn, bundle, period, month_end(period), history=True, publish=True)
        if r is not None:
            done.append(r)
    r = take(conn, bundle, current, now, history=False, publish=False)
    if r is not None:
        done.append(r)
    return done
