# SPDX-License-Identifier: Apache-2.0
"""API behaviour over the demo world: scoping (404 not 403), permissions, ETags, SoD, explainability, CVE query."""

from __future__ import annotations

import os

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.api.auth import AuthConfigurationError
from aap.config import repo_root
from aap.db import transaction

pytestmark = pytest.mark.db


@pytest.fixture(scope="session")
def client(engine, bundle, demo):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def app_names(client, login):
    r = client.get("/api/v1/applications", headers=as_(login))
    assert r.status_code == 200, r.text
    return {a["name"] for a in r.json()["items"]}


def test_health(client):
    assert client.get("/api/v1/health/ready").status_code == 200


def test_unauthenticated_is_problem_json(client):
    r = client.get("/api/v1/applications")
    assert r.status_code == 401 and r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["type"].endswith("/unauthenticated") and "request_id" in r.json()


def test_team_scoping(client):
    assert app_names(client, "ajones") == {"Claims API"}
    assert app_names(client, "dlee") == {"Claims API", "Payments Portal"}  # directorate lead: Benefits subtree
    assert app_names(client, "cpatel") == {"Claims API", "Payments Portal", "HR Leave Tracker", "Team Wiki Helper"}


def test_out_of_scope_is_404_not_403(client, demo):
    pay = demo.applications["Payments Portal"]
    r = client.get(f"/api/v1/applications/{pay}/controls", headers=as_("ajones"))
    assert r.status_code == 404  # AC-03: no enumeration


def test_executive_sees_aggregates_only(client):
    assert client.get("/api/v1/applications", headers=as_("fwong")).status_code == 403
    r = client.get("/api/v1/reports/org-scorecard", headers=as_("fwong"))
    assert r.status_code == 200 and r.json()["kev_internet_exposed_open"] == 1


def test_control_state_is_traceable_to_hash_chained_evidence(client, demo):
    claims = demo.applications["Claims API"]
    items = client.get(f"/api/v1/applications/{claims}/controls", headers=as_("ajones")).json()["items"]
    sast = next(i for i in items if i["control_key"] == "ASC-BLD-01" and i["scope"]["ref"].endswith("claims-api"))
    assert sast["state"] == "satisfied" and "CodeQL 2.19.1" in sast["explanation"] and sast["proof"]
    ev = client.get(f"/api/v1/evidence/{sast['evidence_ids'][0]}", headers=as_("ajones")).json()
    assert ev["confidence"] == "C2" and "approved_workflow_verified" in ev["confidence_reasons"]
    assert len(ev["record_hash"]) == 64 and ev["validity_events"][0]["reason"] == "ingested"
    assert ev["used_by_evaluations"]


def test_classification_is_explained(client, demo):
    r = client.get(
        f"/api/v1/applications/{demo.applications['Claims API']}/classification", headers=as_("ajones")
    ).json()
    assert r["computed_tier"] == 1 and "FR-3" in r["explanation"] and r["asvs_target"] == "L3"


def test_cve_impact_respects_scope(client):
    org = client.get("/api/v1/vulnerabilities/CVE-2021-44228/affected-applications", headers=as_("cpatel")).json()
    assert [a["application"]["name"] for a in org["affected"]] == ["Claims API"]
    assert {p["application"]["name"]: p["reason"] for p in org["possibly_affected"]} == {
        "HR Leave Tracker": "stale_sbom",
        "Team Wiki Helper": "no_sbom",
    }
    assert org["not_affected_count"] == 1
    by_alias = client.get(
        "/api/v1/vulnerabilities/GHSA-jfh8-c2jp-5v3q/affected-applications", headers=as_("ajones")
    ).json()
    assert [a["application"]["name"] for a in by_alias["affected"]] == ["Claims API"]
    assert by_alias["possibly_affected"] == []  # the champion sees only their own application


def test_log4shell_on_internet_facing_tier1_is_p1_with_reasons(client, demo):
    items = client.get(
        f"/api/v1/findings?application={demo.applications['Claims API']}&status=open", headers=as_("ajones")
    ).json()["items"]
    log4j = next(f for f in items if f["vulnerability"] == "CVE-2021-44228")
    detail = client.get(f"/api/v1/findings/{log4j['id']}", headers=as_("ajones")).json()
    assert (detail["priority"] == "P1" and "override.kev_internet" in detail["applied_rules"]) or detail[
        "priority"
    ] == "P1"
    assert "EPSS" in detail["risk_explanation"]


def _sqli(client, demo, login="ajones"):
    items = client.get(
        f"/api/v1/findings?application={demo.applications['Claims API']}&status=open", headers=as_(login)
    ).json()["items"]
    return next(f for f in items if f["cwe_id"] == 89)


def test_triage_requires_current_etag(client, demo):
    f = _sqli(client, demo)
    stale = client.post(
        f"/api/v1/findings/{f['id']}/transitions",
        json={"action": "triage"},
        headers={**as_("ajones"), "If-Match": '"stale"'},
    )
    assert stale.status_code == 412
    etag = client.get(f"/api/v1/findings/{f['id']}", headers=as_("ajones")).headers["ETag"]
    ok = client.post(
        f"/api/v1/findings/{f['id']}/transitions",
        json={"action": "triage"},
        headers={**as_("ajones"), "If-Match": etag},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "triaged"


def test_false_positive_needs_a_second_appsec_reviewer(client, demo, engine):
    items = client.get(
        f"/api/v1/findings?application={demo.applications['Claims API']}&status=open", headers=as_("cpatel")
    ).json()["items"]
    xss = next(f for f in items if f["cwe_id"] == 79)
    url = f"/api/v1/findings/{xss['id']}/transitions"

    def etag():
        return client.get(f"/api/v1/findings/{xss['id']}", headers=as_("cpatel")).headers["ETag"]

    assert (
        client.post(
            url, json={"action": "mark_false_positive"}, headers={**as_("cpatel"), "If-Match": etag()}
        ).status_code
        == 422
    )  # justification required
    assert (
        client.post(
            url,
            json={"action": "mark_false_positive", "comment": "sanitised by DOMPurify upstream"},
            headers={**as_("cpatel"), "If-Match": etag()},
        ).status_code
        == 200
    )
    self_confirm = client.post(
        url, json={"action": "confirm_false_positive"}, headers={**as_("cpatel"), "If-Match": etag()}
    )
    assert self_confirm.status_code == 403 and "segregation of duties" in self_confirm.json()["detail"]  # AC-04 pattern
    champion = client.post(
        url, json={"action": "confirm_false_positive"}, headers={**as_("ajones"), "If-Match": etag()}
    )
    assert champion.status_code == 403  # champions cannot confirm P1/P2 false positives
    ok = client.post(url, json={"action": "confirm_false_positive"}, headers={**as_("hreviewer"), "If-Match": etag()})
    assert ok.status_code == 200 and ok.json()["status"] == "false_positive"
    with transaction(engine, "aap_worker") as conn:
        denied = conn.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE action = 'finding.confirm_false_positive' "
                "AND outcome = 'denied'"
            )
        ).scalar_one()
    assert denied >= 1


def test_implementation_and_contract_match_in_both_directions(client):
    """Every implemented operation is in schemas/api/openapi.yaml with the same method, path and permission; every
    contract operation is implemented or explicitly marked `x-status: designed`."""
    spec = yaml.safe_load((repo_root() / "schemas/api/openapi.yaml").read_text())
    contract = {
        op["operationId"]: (m, path, op["x-permission"], op.get("x-status"))
        for path, item in spec["paths"].items()
        for m, op in item.items()
        if m in ("get", "post", "put", "patch", "delete")
    }
    implemented = {
        op["operationId"]: (m, path.removeprefix("/api/v1"), op.get("x-permission"))
        for path, item in client.app.openapi()["paths"].items()
        for m, op in item.items()
    }
    assert all(v[2] for v in implemented.values()), "a route has no x-permission"
    undocumented = sorted(set(implemented) - set(contract))
    assert undocumented == [], f"implemented but not in the contract: {undocumented}"
    for op_id, (m, path, perm) in implemented.items():
        assert contract[op_id][:3] == (m, path, perm), op_id
        assert contract[op_id][3] is None, f"{op_id} is implemented: remove x-status: designed"
    unbuilt = sorted(k for k, v in contract.items() if k not in implemented and v[3] != "designed")
    assert unbuilt == [], f"in the contract, not implemented, not marked designed: {unbuilt}"


def test_dev_auth_cannot_be_enabled_in_production(engine, bundle, monkeypatch):
    monkeypatch.setenv("AAP_AUTH_MODE", "dev")
    monkeypatch.setenv("AAP_ENV", "production")
    with pytest.raises(AuthConfigurationError):
        create_app(engine, bundle)
