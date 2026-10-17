# SPDX-License-Identifier: Apache-2.0
"""Administration: the unit tree follows config/organization.yaml, nobody grants themselves a role, platform_admin
never comes from the platform, and the changes run as the narrow aap_admin role and are audited."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.db import transaction
from aap.store import registry

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def client(engine, bundle, demo):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    with transaction(engine, "aap_worker") as conn:
        admin = registry.upsert_user(conn, "Platform Admin", "padmin")
        registry.grant_role(conn, admin, "platform_admin")
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def test_unit_tree_follows_the_configured_levels(client):
    tree = client.get("/api/v1/admin/org-units", headers=as_("padmin")).json()
    assert tree["levels"] == ["organisation", "business_unit", "team"]
    assert {u["slug"] for u in tree["items"]} >= {"example-org", "benefits", "claims-team"}
    claims = next(u for u in tree["items"] if u["slug"] == "claims-team")
    assert claims["parent"] == "benefits" and claims["applications"] >= 1
    new = {"slug": "fraud-team", "name": "Fraud team", "unit_type": "team", "parent": "benefits"}
    assert client.post("/api/v1/admin/org-units", json=new, headers=as_("padmin")).status_code == 201
    assert client.post("/api/v1/admin/org-units", json=new, headers=as_("padmin")).status_code == 409
    nested = {"slug": "sub-team", "name": "Sub team", "unit_type": "team", "parent": "fraud-team"}
    r = client.post("/api/v1/admin/org-units", json=nested, headers=as_("padmin"))
    assert r.status_code == 422 and "directly under a business_unit" in r.json()["detail"]
    root = {"slug": "second-root", "name": "Another org", "unit_type": "organisation", "parent": "example-org"}
    assert client.post("/api/v1/admin/org-units", json=root, headers=as_("padmin")).status_code == 422
    assert (
        client.patch(
            "/api/v1/admin/org-units/fraud-team", json={"scm_group": "@example-org/fraud"}, headers=as_("padmin")
        ).status_code
        == 200
    )
    assert client.get("/api/v1/admin/org-units", headers=as_("cpatel")).status_code == 403  # AppSec is not admin


def test_membership_and_grants(client, demo, engine):
    ekim = demo.users["ekim"]
    assert client.put(f"/api/v1/admin/org-units/fraud-team/members/{ekim}", headers=as_("padmin")).status_code == 200
    members = client.get("/api/v1/admin/org-units/fraud-team/members", headers=as_("padmin")).json()["items"]
    assert [m["display_name"] for m in members] == ["Eun Kim"]
    found = client.get("/api/v1/admin/users?q=eun", headers=as_("padmin")).json()["items"]
    assert found and found[0]["id"] == str(ekim)

    g = {"principal_id": str(ekim), "role": "champion", "org_unit": "fraud-team"}
    r = client.post("/api/v1/admin/role-assignments", json=g, headers=as_("padmin"))
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    assert client.post("/api/v1/admin/role-assignments", json=g, headers=as_("padmin")).status_code == 409
    unscoped = client.post(
        "/api/v1/admin/role-assignments", json={"principal_id": str(ekim), "role": "champion"}, headers=as_("padmin")
    )
    assert unscoped.status_code == 422 and "scoped role" in unscoped.json()["detail"]
    wide = client.post(
        "/api/v1/admin/role-assignments",
        json={"principal_id": str(ekim), "role": "auditor", "org_unit": "fraud-team"},
        headers=as_("padmin"),
    )
    assert wide.status_code == 422 and "organization-wide" in wide.json()["detail"]
    pa = client.post(
        "/api/v1/admin/role-assignments",
        json={"principal_id": str(ekim), "role": "platform_admin"},
        headers=as_("padmin"),
    )
    assert pa.status_code == 422 and "identity provider" in pa.json()["detail"]
    with transaction(engine, "aap_worker") as conn:
        me = conn.execute(text("SELECT user_id FROM user_identities WHERE login = 'padmin'")).scalar_one()
    self_grant = client.post(
        "/api/v1/admin/role-assignments",
        json={"principal_id": str(me), "role": "appsec_engineer"},
        headers=as_("padmin"),
    )
    assert self_grant.status_code == 403 and "yourself" in self_grant.json()["detail"]
    grants = client.get("/api/v1/admin/role-assignments", headers=as_("padmin")).json()["items"]
    assert any(
        x["id"] == gid and x["principal_name"] == "Eun Kim" and x["granted_by"] == "Platform Admin" for x in grants
    )
    assert client.delete(f"/api/v1/admin/role-assignments/{gid}", headers=as_("padmin")).status_code == 200
    assert client.delete(f"/api/v1/admin/org-units/fraud-team/members/{ekim}", headers=as_("padmin")).status_code == 200
    with transaction(engine, "aap_worker") as conn:
        actions = dict(
            conn.execute(
                text("""SELECT action || ':' || outcome, count(*) FROM audit_events
                                            WHERE action LIKE 'role.%' OR action LIKE 'org_unit.%' GROUP BY 1""")
            ).all()
        )
    assert actions.get("role.grant:denied", 0) >= 1 and actions.get("role.grant:success", 0) >= 1
    assert actions.get("role.revoke:success", 0) >= 1 and actions.get("org_unit.create:success", 0) >= 1


def test_admin_role_cannot_touch_application_data(engine):
    with pytest.raises(Exception, match="permission denied"), transaction(engine, "aap_admin") as conn:
        conn.execute(text("UPDATE applications SET name = 'x'"))
    with pytest.raises(Exception, match="permission denied"), transaction(engine, "aap_admin") as conn:
        conn.execute(text("UPDATE org_units SET parent_id = NULL"))  # re-parenting stays a migration
