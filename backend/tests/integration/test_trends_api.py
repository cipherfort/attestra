# SPDX-License-Identifier: Apache-2.0
"""Dashboard read models over the demo world: trends from the monthly snapshots, the maturity roll-up, global
evidence and rejection lists, and the activity feed. Each one is scoped like the rest of the API (404, not 403)."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.db import transaction

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def client(engine, bundle, demo):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    return TestClient(create_app(engine, bundle))


def get(client, path, login="cpatel"):
    return client.get(f"/api/v1{path}", headers={"X-AAP-Dev-User": login})


@pytest.fixture(scope="module")
def units(engine, demo):
    with transaction(engine, "aap_worker") as conn:
        return {r.slug: str(r.id) for r in conn.execute(text("SELECT id, slug FROM org_units"))}


def test_application_trend_has_a_year_with_the_current_month_provisional(client):
    r = get(client, "/applications/APP-00001/trend")
    assert r.status_code == 200, r.text
    t = r.json()
    current = f"{datetime.now(UTC):%Y-%m}"
    assert len(t["periods"]) == 12 and t["periods"][-1] == current and t["provisional"] == current
    proven = t["metrics"]["mandatory_satisfied"]
    assert proven[-1] is not None and proven[-1] > (proven[0] or 0)  # the evidence arrived during the year
    assert {f["item"] for f in t["samm_functions"]} >= {"G", "D", "I", "V", "O"}
    assert get(client, "/applications/APP-00001/trend?months=3").json()["periods"][-1] == current


def test_trends_are_scoped(client, units):
    assert get(client, "/applications/APP-00002/trend", "ajones").status_code == 404  # Payments: not her team
    root = units["example-org"]
    assert get(client, f"/org-units/{root}/trend", "fwong").status_code == 200  # executive: aggregates
    assert get(client, f"/org-units/{root}/trend", "dlee").status_code == 404  # Benefits lead: not the whole org
    benefits = get(client, f"/org-units/{units['benefits']}/trend", "dlee")
    assert benefits.status_code == 200 and benefits.json()["metrics"]["applications"][-1] >= 2  # other modules add more


def test_the_maturity_rollup_is_a_distribution_not_a_league_table(client, units):
    r = get(client, f"/org-units/{units['example-org']}/maturity", "fwong")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snapshot"] == f"{datetime.now(UTC):%Y-%m}"
    assert body["distribution"] and all(d["p25"] <= d["median"] <= d["p75"] for d in body["distribution"])
    assert "app_key" not in str(body)  # no per-application ranking
    assert get(client, f"/org-units/{units['example-org']}/maturity?snapshot=1999-01", "fwong").status_code == 404
    snaps = get(client, "/maturity/snapshots", "fwong").json()["items"]
    assert len(snaps) >= 12 and snaps[-1]["published"] is False and all(s["published"] for s in snaps[:-1])


def test_evidence_and_rejections_across_applications(client):
    items = get(client, "/evidence?limit=100").json()["items"]
    when = [datetime.fromisoformat(e["observed_at"]) for e in items]
    assert items and when == sorted(when, reverse=True)
    assert {"app_key", "confidence", "state"} <= set(items[0])
    sca = get(client, "/evidence?filter[type]=scan.sca").json()["items"]
    assert sca and all(e["type"] == "scan.sca" for e in sca)
    mine = get(client, "/evidence?limit=100", "ajones").json()["items"]
    # other modules add applications to the Claims team; other teams' evidence must never show
    assert mine and not {e["app_key"] for e in mine} & {"APP-00002", "APP-00003", "APP-00004"}
    rejected = get(client, "/evidence-rejections").json()["items"]
    assert any(x["reason_code"] == "UNTRUSTED_PRODUCER" for x in rejected)  # the demo's forged submission
    assert get(client, "/evidence?filter[confidence]=C9").status_code == 422


def test_the_activity_feed_is_newest_first_and_scoped(client):
    feed = get(client, "/activity?limit=50").json()["items"]
    when = [datetime.fromisoformat(x["at"]) for x in feed]
    assert feed and when == sorted(when, reverse=True)
    assert {"evidence_accepted", "finding_opened"} <= {x["kind"] for x in feed}
    theirs = get(client, "/activity?limit=50", "ekim").json()["items"]
    assert theirs and {x["app_key"] for x in theirs} == {"APP-00002"}
    assert all(x["app_key"] == "APP-00001" for x in get(client, "/activity?application=APP-00001").json()["items"])


def test_sbom_components_page_by_purl_with_matched_vulnerabilities(client):
    sboms = get(client, "/applications/APP-00001/sboms").json()["items"]
    current = next(s for s in sboms if s["is_current"])
    first = get(client, f"/sboms/{current['id']}/components?limit=2").json()
    assert len(first["items"]) == 2 and first["page"]["next_cursor"]
    rest = get(client, f"/sboms/{current['id']}/components?limit=200&cursor={first['page']['next_cursor']}").json()
    purls = [c["purl"] for c in first["items"] + rest["items"]]
    assert purls == sorted(purls) and len(purls) == current["component_count"] and rest["page"]["next_cursor"] is None
    assert any(c["vulnerabilities"] for c in first["items"] + rest["items"])  # the demo's vulnerable dependency
    assert get(client, f"/sboms/{current['id']}/components", "ekim").status_code == 404  # Payments team: not theirs
    assert get(client, f"/sboms/{current['id']}/components?cursor=%%%").status_code == 400


def test_sbom_list_says_whether_each_sbom_is_fresh_and_how_many_components_are_vulnerable(client):
    current = next(s for s in get(client, "/applications/APP-00001/sboms").json()["items"] if s["is_current"])
    assert current["freshness"] in {"active", "expiring", "expired", "superseded", "revoked"}
    assert current["vulnerable_components"] >= 1
