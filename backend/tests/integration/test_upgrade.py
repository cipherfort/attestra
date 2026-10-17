# SPDX-License-Identifier: Apache-2.0
"""Upgrades: from every earlier migration revision, with data written at that revision, to the latest. The data
survives, row-level security still scopes it, and features added since work on it (classification evidence,
evaluation, exceptions). Each release upgrades from the previous minor; this checks every step in between.

Runs in its own throwaway PostgreSQL (one database per starting revision)."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from aap.db import transaction

pytestmark = pytest.mark.db
BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _cfg(url: str) -> Config:
    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _revisions() -> list[str]:
    script = ScriptDirectory.from_config(_cfg("postgresql://unused"))
    return [r.revision for r in reversed(list(script.walk_revisions()))]


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    from tests.integration.conftest import _start_container

    name, url = _start_container()
    try:
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


SEED = """
SET search_path = aap, public;
INSERT INTO org_units (id, slug, name, unit_type, parent_id)
  VALUES ('00000000-0000-7000-8000-000000000001', 'upgrade-org', 'Upgrade Org', 'organisation', NULL),
         ('00000000-0000-7000-8000-000000000002', 'upgrade-team', 'Upgrade team', 'team',
          '00000000-0000-7000-8000-000000000001');
INSERT INTO users (id, display_name, email, active)
  VALUES ('00000000-0000-7000-8000-000000000010', 'Ursula Upgrade', 'ursula@example.org', true);
INSERT INTO applications (id, name, description, org_unit_id, lifecycle, exposure, data_classification, personal_data,
                          profile)
  VALUES ('00000000-0000-7000-8000-000000000100', 'Upgrade App', 'written before the upgrade',
          '00000000-0000-7000-8000-000000000002', 'production', 'internal', 'internal', 'none', '{}');
"""


@pytest.mark.parametrize("start", _revisions()[:-1])
def test_upgrade_from_each_earlier_revision_keeps_data_and_gains_features(server, bundle, start, monkeypatch):
    base, _, _ = server.rpartition("/")
    admin = create_engine(f"{base}/postgres", isolation_level="AUTOCOMMIT")
    db = f"up_{start.split('_')[0]}"
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{db}"'))
        c.execute(text(f'CREATE DATABASE "{db}"'))
    url = f"{base}/{db}"
    monkeypatch.setenv("AAP_DATABASE_URL", url)  # migrations/env.py connects through it
    command.upgrade(_cfg(url), start)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.exec_driver_sql(SEED)

    command.upgrade(_cfg(url), "head")  # the upgrade under test

    from aap.services import onboarding
    from aap.store import config_store, registry

    with engine.begin() as conn:
        conn.exec_driver_sql("SET search_path = aap, public")
        assert conn.execute(text("SELECT name FROM applications")).scalar_one() == "Upgrade App"
        assert conn.execute(text("SELECT count(*) FROM org_units")).scalar_one() == 2
    with transaction(engine, "aap_worker") as conn:
        config_store.load(conn, bundle, git_sha="upgrade-test")
        app_id = "00000000-0000-7000-8000-000000000100"
        from aap.domain.classification import classify

        inputs = {
            "data_classification": "internal",
            "personal_data": "none",
            "exposure": "internal",
            "user_population": "team",
            "business_criticality": "minimal",
            "privileged_integration": "none",
            "regulatory": [],
        }
        registry.record_classification(
            conn,
            app_id,
            bundle.documents["classification"].version,
            inputs,
            classify(inputs, bundle.doc("classification")),
            "auto_approved",
            None,
        )
        assert onboarding.record_classification_evidence(conn, app_id, datetime.now(UTC)) is not None
        from aap.services import evaluation

        results = evaluation.evaluate_application(conn, bundle, app_id, datetime.now(UTC), gap_grace=None)
        assert any(r.control_key == "ASC-GOV-02" and r.state == "satisfied" for r in results)
    # row-level security still scopes the old row: invisible outside its unit, visible inside it
    from aap.db import Scope

    with transaction(engine, "aap_api", Scope(False, ())) as conn:
        assert conn.execute(text("SELECT count(*) FROM applications")).scalar_one() == 0
    with transaction(engine, "aap_api", Scope(False, ("00000000-0000-7000-8000-000000000002",))) as conn:
        assert conn.execute(text("SELECT count(*) FROM applications")).scalar_one() == 1
    engine.dispose()
    admin.dispose()
