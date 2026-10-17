# SPDX-License-Identifier: Apache-2.0
"""Security exceptions through the API: approval matrix, segregation of duties, business-owner co-signature, duration
limits, the effect on control and finding state, revocation and expiry."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.db import transaction
from aap.services import evaluation, exceptions
from aap.store import registry

pytestmark = pytest.mark.db

TEXT = "A long enough justification for the test case."


@pytest.fixture(scope="module")
def app_id(engine, fresh_app):
    from aap.store import findings_store

    aid = fresh_app("Exceptions Test App", "990001")
    with transaction(engine, "aap_worker") as conn:
        findings_store.observe(
            conn,
            findings_store.NewFinding(
                fingerprint="exceptions-test-finding",
                application_id=aid,
                repository_id=None,
                scope_type="repository",
                scope_ref="example-org/exceptions-test-app",
                finding_type="code",
                source_system="platform",
                title="Test finding for exceptions",
            ),
            None,
            datetime.now(UTC),
        )
    return aid


@pytest.fixture(scope="module")
def client(engine, bundle, demo, app_id):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    with transaction(engine, "aap_worker") as conn:
        lead = registry.upsert_user(conn, "AppSec lead", "hlead")
        registry.grant_role(conn, lead, "security_leadership")
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def new(client, login, app, priority="P3", target_type="control", target_ref="ASC-SRC-01", **extra):
    body = {
        "application": app,
        "target_type": target_type,
        "target_ref": target_ref,
        "justification": TEXT,
        "risk_description": TEXT,
        "residual_priority": priority,
        "remediation_plan": TEXT,
        **extra,
    }
    return client.post("/api/v1/exceptions", json=body, headers=as_(login))


def act(client, login, xid, action, **body):
    return client.post(f"/api/v1/exceptions/{xid}/{action}", json=body or None, headers=as_(login))


def test_tier1_control_exception_needs_the_right_role_and_a_cosign(client, app_id, engine, bundle):
    claims = app_id  # Tier 1; business owner dlee, technical owner bsmith
    r = new(client, "ajones", claims, "P3")
    assert r.status_code == 201, r.text
    x = r.json()
    assert x["status"] == "draft" and x["required_approver_role"] == "head_of_appsec"
    assert x["business_owner_cosign_required"] and x["max_days"] == 90  # catalogue Tier 1 limit beats P3's 180
    assert act(client, "ekim", x["id"], "submit").status_code in (403, 404)  # not the requester / out of scope
    assert act(client, "ajones", x["id"], "submit").json()["status"] == "pending_approval"

    decide = {"outcome": "approve", "comment": "accepted for one quarter"}
    weak = act(client, "cpatel", x["id"], "decision", **decide)
    assert weak.status_code == 403 and "head_of_appsec" in weak.json()["detail"]  # appsec_engineer ranks too low
    assert act(client, "hlead", x["id"], "decision", **decide).status_code == 409  # Tier 1: no co-sign yet
    assert act(client, "bsmith", x["id"], "cosign").status_code == 403  # only the business owner co-signs
    assert act(client, "dlee", x["id"], "cosign").json()["cosigned"]
    too_long = act(client, "hlead", x["id"], "decision", **decide, expires_at=str(date.today() + timedelta(days=200)))
    assert too_long.status_code == 422 and "90-day" in too_long.json()["detail"]
    ok = act(client, "hlead", x["id"], "decision", **decide)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "approved" and ok.json()["approver"] == "AppSec lead"
    assert [e["type"] for e in ok.json()["events"]] == ["created", "submitted", "cosigned", "approved"]

    with transaction(engine, "aap_worker") as conn:
        results = evaluation.evaluate_application(conn, bundle, claims, datetime.now(UTC), gap_grace=None)
        # applicability comes first: a repository the control does not apply to stays not_applicable
        assert {r.state for r in results if r.control_key == "ASC-SRC-01"} - {"not_applicable"} == {"excepted"}
        # expiry: the control returns to its real state and an exception_expired finding appears
        assert exceptions.expire_due(conn, bundle, datetime.now(UTC) + timedelta(days=91)) >= 1
        finding = conn.execute(
            text("SELECT finding_type, status FROM findings WHERE location->>'exception' = :k"),
            {"k": x["exception_key"]},
        ).one()
        assert finding.finding_type == "exception_expired"
        results = evaluation.evaluate_application(conn, bundle, claims, datetime.now(UTC), gap_grace=None)
        assert "excepted" not in {r.state for r in results if r.control_key == "ASC-SRC-01"}
    denied = client.get(f"/api/v1/exceptions/{x['id']}", headers=as_("ajones")).json()
    assert denied["status"] == "expired"


def test_segregation_of_duties_and_policy_limits(client, demo, engine, app_id):
    claims = app_id
    with transaction(engine, "aap_worker") as conn:  # the technical owner also holds approver authority
        unit = conn.execute(text("SELECT id FROM org_units WHERE slug = 'benefits'")).scalar_one()
        registry.grant_role(conn, demo.users["bsmith"], "unit_lead", str(unit))
    x = new(client, "ajones", claims, "P4").json()  # P4 at Tier 1 needs unit_security_lead
    assert x["required_approver_role"] == "unit_security_lead"
    act(client, "ajones", x["id"], "submit")
    act(client, "dlee", x["id"], "cosign")
    owner = act(client, "bsmith", x["id"], "decision", outcome="approve", comment="looks fine")
    assert owner.status_code == 403 and "technical owner" in owner.json()["detail"]
    assert client.get(f"/api/v1/exceptions/{x['id']}", headers=as_("bsmith")).json()["can_decide"] is False
    with transaction(engine, "aap_worker") as conn:
        denied = conn.execute(
            text("SELECT count(*) FROM audit_events WHERE action = 'exception.approve' AND outcome = 'denied'")
        ).scalar_one()
    assert denied >= 1
    assert client.get(f"/api/v1/exceptions/{x['id']}", headers=as_("dlee")).json()["can_decide"] is True
    assert act(client, "dlee", x["id"], "decision", outcome="approve", comment="unit lead approves").status_code == 200

    gov = new(client, "ajones", claims, target_ref="ASC-GOV-01")  # exception.allowed: false in the catalogue
    assert gov.status_code == 422 and "cannot be excepted" in gov.json()["detail"]
    long = new(client, "ajones", claims, requested_expiry=str(date.today() + timedelta(days=400)))
    assert long.status_code == 422
    unknown = new(client, "ajones", claims, target_ref="ASC-NOPE-01")
    assert unknown.status_code == 422
    assert new(client, "ekim", claims).status_code == 404  # out of ekim's scope: no enumeration


def test_finding_exception_excepts_then_reopens_on_revoke(client, demo, engine, app_id):
    claims = app_id
    items = client.get(f"/api/v1/findings?application={claims}&status=open", headers=as_("cpatel")).json()["items"]
    target = next(f for f in items if f["status"] not in ("excepted", "false_positive"))
    # residual priority is the requester's statement of the risk left after compensating controls
    x = new(client, "ajones", claims, "P4", target_type="finding", target_ref=target["id"]).json()
    act(client, "ajones", x["id"], "submit")
    act(client, "dlee", x["id"], "cosign")
    approver = "hlead"
    assert act(client, approver, x["id"], "decision", outcome="approve", comment="fix scheduled").status_code == 200
    assert client.get(f"/api/v1/findings/{target['id']}", headers=as_("cpatel")).json()["status"] == "excepted"
    revoked = act(client, "cpatel", x["id"], "revoke", reason="the compensating control was removed")
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert client.get(f"/api/v1/findings/{target['id']}", headers=as_("cpatel")).json()["status"] == "reopened"

    renewal = act(client, "ajones", x["id"], "renewals", justification=TEXT, remediation_plan=TEXT)
    assert renewal.status_code == 409  # revoked exceptions are not renewed: request a new one
    listing = client.get(f"/api/v1/exceptions?application={claims}", headers=as_("ajones")).json()["items"]
    assert any(i["exception_key"] == x["exception_key"] and i["status"] == "revoked" for i in listing)
