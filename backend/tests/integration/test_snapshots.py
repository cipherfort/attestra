# SPDX-License-Identifier: Apache-2.0
"""Monthly posture snapshots (C13): history computed as of each month end, an org roll-up that adds up, published
months that cannot change, and row-level security on application rows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aap.db import Scope, transaction
from aap.services import snapshots

pytestmark = pytest.mark.db


def _metrics(conn, period, scope_type, scope_id):
    rows = conn.execute(
        text("""SELECT pm.metric, pm.value FROM posture_metrics pm JOIN maturity_snapshots s ON s.id = pm.snapshot_id
                WHERE s.period = :p AND pm.scope_type = :t AND pm.scope_id = :i"""),
        {"p": period, "t": scope_type, "i": scope_id},
    ).all()
    return {r.metric: float(r.value) for r in rows}


def test_the_demo_has_a_year_of_snapshots_with_only_the_current_month_provisional(engine, demo):
    current = snapshots.month_start(datetime.now(UTC))
    with transaction(engine, "aap_worker") as conn:
        rows = conn.execute(text("SELECT period, published FROM maturity_snapshots ORDER BY period")).all()
    periods = {r.period: r.published for r in rows}
    assert len([p for p in periods if p <= current]) >= 12
    assert periods[current] is False
    assert all(published for p, published in periods.items() if p < current)


def test_history_counts_only_applications_and_evidence_that_existed_then(engine, demo):
    current = snapshots.month_start(datetime.now(UTC))
    claims, wiki = demo.applications["Claims API"], demo.applications["Team Wiki Helper"]
    past = snapshots.add_months(current, -6)
    with transaction(engine, "aap_worker") as conn:
        assert _metrics(conn, snapshots.add_months(current, -10), "application", wiki) == {}  # onboarded 100 days ago
        then = _metrics(conn, past, "application", claims)
        observed = conn.execute(
            text("SELECT count(*) FROM evidence WHERE application_id = :a AND observed_at >= :s AND observed_at <= :e"),
            {"a": claims, "s": datetime(past.year, past.month, 1, tzinfo=UTC), "e": snapshots.month_end(past)},
        ).scalar_one()
        opened_later = conn.execute(
            text("SELECT count(*) FROM findings WHERE application_id = :a AND first_seen_at > :e"),
            {"a": claims, "e": snapshots.month_end(past)},
        ).scalar_one()
    # as of that month: exactly the evidence observed during it, and no finding first seen afterwards
    assert then["evidence_accepted"] == observed > 0
    assert opened_later > 0  # the demo has later findings, and none of them are counted then
    open_then = sum(then[f"findings_open_{p}"] for p in ("p1", "p2", "p3", "p4"))
    with transaction(engine, "aap_worker") as conn:
        recount = conn.execute(
            text("""SELECT count(*) FROM findings WHERE application_id = :a AND first_seen_at <= :e AND priority IS NOT NULL
                    AND status <> 'false_positive' AND (closed_at IS NULL OR closed_at > :e)"""),
            {"a": claims, "e": snapshots.month_end(past)},
        ).scalar_one()
    assert open_then == recount


def test_org_units_roll_up_their_applications(engine, demo):
    current = snapshots.month_start(datetime.now(UTC))
    with transaction(engine, "aap_worker") as conn:
        root = conn.execute(text("SELECT id FROM org_units WHERE parent_id IS NULL")).scalar_one()
        org = _metrics(conn, current, "organisation", root)
        apps = conn.execute(
            text("""SELECT pm.metric, sum(pm.value) AS v FROM posture_metrics pm JOIN maturity_snapshots s ON s.id = pm.snapshot_id
                    WHERE s.period = :p AND pm.scope_type = 'application' GROUP BY pm.metric"""),
            {"p": current},
        ).all()
    summed = {r.metric: float(r.v) for r in apps}
    for metric in ("mandatory_total", "mandatory_satisfied", "findings_open_p1", "evidence_accepted"):
        assert org[metric] == summed[metric], metric
    assert org["applications"] >= 4


def test_published_snapshots_cannot_change(engine, demo):
    past = snapshots.add_months(snapshots.month_start(datetime.now(UTC)), -2)
    with transaction(engine, "aap_worker") as conn:
        assert snapshots.take(conn, demo_bundle(), past, snapshots.month_end(past), history=True, publish=True) is None
    for sql in (
        "UPDATE posture_metrics SET value = 0 WHERE snapshot_id = (SELECT id FROM maturity_snapshots WHERE period = :p)",
        "DELETE FROM maturity_scores WHERE snapshot_id = (SELECT id FROM maturity_snapshots WHERE period = :p)",
        "UPDATE maturity_snapshots SET published = false WHERE period = :p",
    ):
        # refused either by the grants (no UPDATE on the score tables) or by the immutability trigger
        with pytest.raises(DBAPIError, match=r"immutable|permission denied"), transaction(engine, "aap_worker") as conn:
            conn.execute(text(sql), {"p": past})


def test_the_scheduler_refreshes_the_current_month_at_most_every_few_hours(engine, demo):
    with transaction(engine, "aap_worker") as conn:
        assert snapshots.tick(conn, demo_bundle(), datetime.now(UTC)) is None  # the demo just took it
        later = snapshots.tick(conn, demo_bundle(), datetime.now(UTC) + snapshots.REFRESH + timedelta(minutes=1))
    assert later is not None and later.published is False


def test_application_rows_follow_row_level_security(engine, demo):
    claims_team = None
    with transaction(engine, "aap_worker") as conn:
        claims_team = str(conn.execute(text("SELECT id FROM org_units WHERE slug = 'claims-team'")).scalar_one())
    with transaction(engine, "aap_api", Scope(False, (claims_team,))) as conn:
        visible = {
            str(r.scope_id)
            for r in conn.execute(
                text("SELECT DISTINCT scope_id FROM posture_metrics WHERE scope_type = 'application'")
            )
        }
        scores = {
            str(r.scope_id)
            for r in conn.execute(
                text("SELECT DISTINCT scope_id FROM maturity_scores WHERE scope_type = 'application'")
            )
        }
    # other modules add applications to the Claims team; what matters is that other teams' applications never show
    others = {demo.applications[n] for n in ("Payments Portal", "HR Leave Tracker", "Team Wiki Helper")}
    assert demo.applications["Claims API"] in visible and not visible & others
    assert visible == scores


def demo_bundle():
    from aap.config import ConfigBundle

    return ConfigBundle.load()
