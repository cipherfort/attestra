# SPDX-License-Identifier: Apache-2.0
"""BFF sign-in end to end against PostgreSQL: login → IdP → callback → session cookie → API, CSRF, timeouts,
role sources, logout, service bearer tokens."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.api.auth import SESSION_COOKIE
from aap.api.oidc import OidcClient, OidcSettings
from aap.db import admin_connection, transaction
from aap.store import registry
from tests.oidc_idp import API_AUDIENCE, CLIENT_ID, CLIENT_SECRET, ISSUER, TENANT, FakeIdP

pytestmark = pytest.mark.db


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def web(engine, bundle, loaded, idp, monkeypatch):
    monkeypatch.setenv("AAP_AUTH_MODE", "oidc")
    monkeypatch.setenv("AAP_ENV", "development")
    app = create_app(engine, bundle)
    app.state.oidc = OidcClient(
        OidcSettings(
            ISSUER,
            CLIENT_ID,
            "https://testserver/auth/callback",
            API_AUDIENCE,
            TENANT,
            post_logout_redirect_uri="https://testserver/",
        ),
        client_secret=CLIENT_SECRET,
        http=idp.client(),
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def sign_in(web, idp, return_to="/"):
    r = web.get("/auth/login", params={"return_to": return_to})
    assert r.status_code == 302 and r.headers["location"].startswith("https://idp.test/authorize?")
    back = idp.authorize(r.headers["location"])
    r = web.get(back.replace("https://testserver", ""))
    assert r.status_code == 302, r.text
    return r


def test_full_sign_in_creates_user_and_session(web, idp, engine):
    idp.user_claims = {
        "oid": "aaaaaaaa-0000-0000-0000-000000000001",
        "name": "Ada Example",
        "roles": ["appsec_engineer", "champion"],
    }  # champion is scoped: must be ignored from a token
    r = sign_in(web, idp, return_to="/#/applications")
    assert r.headers["location"] == "/#/applications"
    cookie = r.headers["set-cookie"]
    assert SESSION_COOKIE in cookie and "HttpOnly" in cookie and "Secure" in cookie and "samesite=lax" in cookie.lower()
    me = web.get("/api/v1/users/me").json()
    assert me["user"]["display_name"] == "Ada Example"
    assert [x["role"] for x in me["roles"]] == ["appsec_engineer"] and me["org_wide"]
    assert me["csrf_token"] and me["auth_mode"] == "oidc"
    with transaction(engine, "aap_worker") as conn:
        stored = conn.execute(text("SELECT id_hash, csrf_token FROM web_sessions")).all()
    raw = web.cookies.get(SESSION_COOKIE)
    assert raw and all(row.id_hash != raw for row in stored)  # only the hash is stored


def test_state_is_single_use_and_bound(web, idp):
    r = web.get("/auth/login")
    back = idp.authorize(r.headers["location"]).replace("https://testserver", "")
    assert web.get(back).status_code == 302
    replay = web.get(back)
    assert replay.status_code == 401  # state consumed
    assert web.get("/auth/callback?code=x&state=forged").status_code == 401
    assert web.get("/auth/callback?error=access_denied").status_code == 401


def test_csrf_required_for_unsafe_methods(web, idp):
    sign_in(web, idp)
    assert web.post("/auth/logout").status_code == 403
    me = web.get("/api/v1/users/me").json()
    assert me["roles"] == [] and web.get("/api/v1/applications").status_code == 403  # no role → nothing else
    csrf = me["csrf_token"]
    r = web.post("/auth/logout", headers={"X-AAP-CSRF": csrf})
    assert r.status_code == 200 and r.json()["end_session_url"].startswith("https://idp.test/logout")
    assert "client_id=" in r.json()["end_session_url"]  # the provider ends its own session too (Keycloak requires it)
    assert web.get("/api/v1/users/me").status_code == 401  # session gone


def _age_sessions(engine, sql: str) -> None:
    with admin_connection(engine) as conn:
        conn.execute(text(sql))


def test_idle_and_absolute_timeouts(web, idp, engine):
    sign_in(web, idp)
    assert web.get("/api/v1/users/me").status_code == 200
    _age_sessions(engine, "UPDATE aap.web_sessions SET last_seen_at = now() - interval '31 minutes'")
    assert web.get("/api/v1/users/me").status_code == 401
    sign_in(web, idp)
    _age_sessions(engine, "UPDATE aap.web_sessions SET expires_at = now() - interval '1 second'")
    assert web.get("/api/v1/users/me").status_code == 401


def test_scoped_roles_come_from_platform_by_group(web, idp, engine):
    group = "bbbbbbbb-0000-0000-0000-00000000000g"
    with transaction(engine, "aap_worker") as conn:
        org = conn.execute(
            text("SELECT id FROM org_units WHERE parent_id IS NULL")
        ).scalar() or registry.upsert_org_unit(conn, "oidc-org", "OIDC Org", "organisation", None)
        ou = registry.upsert_org_unit(conn, "oidc-unit", "OIDC Business Unit", "business_unit", str(org))
        conn.execute(
            text("""INSERT INTO role_assignments (principal_type, principal_id, role, scope_org_unit_id)
                             VALUES ('idp_group', :g, 'unit_lead', :o)"""),
            {"g": group, "o": ou},
        )
    idp.user_claims = {"oid": "aaaaaaaa-0000-0000-0000-000000000002", "groups": [group], "roles": []}
    sign_in(web, idp)
    me = web.get("/api/v1/users/me").json()
    assert [x["role"] for x in me["roles"]] == ["unit_lead"] and not me["org_wide"]


def test_pre_registered_user_linked_by_email_in_pinned_tenant(web, idp, engine):
    with transaction(engine, "aap_worker") as conn:
        uid = registry.upsert_user(conn, "Registry Name", "reglogin", email="owner@example.org")
    idp.user_claims = {
        "oid": "aaaaaaaa-0000-0000-0000-000000000003",
        "preferred_username": "Owner@example.org",
        "name": "Owner From Entra",
    }
    sign_in(web, idp)
    assert web.get("/api/v1/users/me").json()["user"]["id"] == str(uid)


def test_deactivated_user_cannot_sign_in(web, idp, engine):
    oid = "aaaaaaaa-0000-0000-0000-000000000004"
    idp.user_claims = {"oid": oid}
    sign_in(web, idp)
    with transaction(engine, "aap_worker") as conn:
        conn.execute(
            text("""UPDATE users SET active = false WHERE id IN
                    (SELECT user_id FROM user_identities WHERE provider LIKE 'oidc:%' AND external_id = :o)"""),
            {"o": oid},
        )
    assert web.get("/api/v1/users/me").status_code == 401  # existing session ends
    r = web.get("/auth/login")
    assert web.get(idp.authorize(r.headers["location"]).replace("https://testserver", "")).status_code == 401


def test_service_bearer_token_gets_aggregates_only(web, idp):
    token = idp.access_token()
    h = {"Authorization": f"Bearer {token}"}
    me = web.get("/api/v1/users/me", headers=h).json()
    assert [x["role"] for x in me["roles"]] == ["reports_reader"]
    assert web.get("/api/v1/applications", headers=h).status_code == 403
    assert web.get("/api/v1/users/me", headers={"Authorization": f"Bearer {idp.id_token('n')}"}).status_code == 401
    delegated = idp.access_token(scp="user_impersonation")
    assert web.get("/api/v1/users/me", headers={"Authorization": f"Bearer {delegated}"}).status_code == 401


def test_no_session_is_401_problem(web):
    r = web.get("/api/v1/applications")
    assert r.status_code == 401 and r.json()["detail"] == "sign in required"
