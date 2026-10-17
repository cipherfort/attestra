# SPDX-License-Identifier: Apache-2.0
"""Per-process database logins (risk R-25): each login can switch only to its own roles, holds no privileges of its
own (NOINHERIT), and the API works end to end when connected as its login."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from aap.db import set_login_password, transaction

pytestmark = pytest.mark.db


def _engine_as(db_url: str, login: str, password: str):
    return create_engine(make_url(db_url).set(username=login, password=password))


def test_api_login_cannot_become_the_worker(db_url, engine, demo):
    set_login_password(engine, "aap_api_login", "api-test-pw")
    api = _engine_as(db_url, "aap_api_login", "api-test-pw")
    with api.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):  # NOINHERIT: nothing without switching role
            conn.execute(text("SELECT count(*) FROM aap.applications")).scalar_one()
    with pytest.raises(DBAPIError, match="permission denied to set role"):
        with transaction(api, "aap_worker") as conn:
            conn.execute(text("SELECT 1"))
    with transaction(api, "aap_auth") as conn:
        assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() > 0
    api.dispose()


def test_worker_and_hook_logins_are_confined(db_url, engine):
    set_login_password(engine, "aap_worker_login", "worker-test-pw")
    set_login_password(engine, "aap_hook_login", "hook-test-pw")
    worker = _engine_as(db_url, "aap_worker_login", "worker-test-pw")
    hook = _engine_as(db_url, "aap_hook_login", "hook-test-pw")
    with transaction(worker, "aap_worker") as conn:
        conn.execute(text("SELECT 1"))
    for target in ("aap_api", "aap_auth"):
        with pytest.raises(DBAPIError, match="permission denied to set role"):
            with transaction(worker, target) as conn:
                conn.execute(text("SELECT 1"))
    with pytest.raises(DBAPIError, match="permission denied to set role"):
        with transaction(hook, "aap_worker") as conn:
            conn.execute(text("SELECT 1"))
    worker.dispose()
    hook.dispose()


def test_the_api_runs_as_its_login(db_url, engine, bundle, demo, monkeypatch):
    from aap.api.app import create_app

    set_login_password(engine, "aap_api_login", "api-test-pw")
    api = _engine_as(db_url, "aap_api_login", "api-test-pw")
    monkeypatch.setenv("AAP_AUTH_MODE", "dev")
    monkeypatch.setenv("AAP_ENV", "development")
    client = TestClient(create_app(api, bundle))
    r = client.get("/api/v1/applications", headers={"X-AAP-Dev-User": "cpatel"})
    assert r.status_code == 200 and len(r.json()["items"]) >= 4  # the demo world (other tests may add more)
    assert client.get("/api/v1/integrations", headers={"X-AAP-Dev-User": "cpatel"}).status_code == 200
    api.dispose()


def test_unknown_login_refused(engine):
    with pytest.raises(ValueError):
        set_login_password(engine, "postgres", "x")
    assert os.environ.get("AAP_DATABASE_URL")
