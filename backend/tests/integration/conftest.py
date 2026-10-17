# SPDX-License-Identifier: Apache-2.0
"""Integration fixtures: a real PostgreSQL 16 (throwaway Docker container on tmpfs, or AAP_TEST_DATABASE_URL),
migrated with the production migrations and loaded with the real configuration."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text

from aap.blobstore import LocalBlobStore
from aap.config import ConfigBundle
from aap.db import admin_connection, transaction
from aap.store import config_store

HERE = os.path.dirname(__file__)
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))


def _start_container() -> tuple[str, str]:
    if not shutil.which("docker"):
        pytest.skip("docker not available and AAP_TEST_DATABASE_URL not set")
    name = f"aap-it-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--tmpfs",
            "/var/lib/postgresql/data:rw,size=512m",
            "-e",
            "POSTGRES_PASSWORD=test",
            "-e",
            "POSTGRES_DB=aap",
            "-p",
            "127.0.0.1::5432",
            "postgres:16-alpine",
        ],
        check=True,
        capture_output=True,
    )
    port = (
        subprocess.run(["docker", "port", name, "5432/tcp"], check=True, capture_output=True, text=True)
        .stdout.strip()
        .rsplit(":", 1)[-1]
    )
    url = f"postgresql+psycopg://postgres:test@127.0.0.1:{port}/aap"
    deadline = time.time() + 60
    while time.time() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        if (logs.stdout + logs.stderr).count("ready to accept connections") >= 2:
            try:
                create_engine(url).connect().close()
                return name, url
            except Exception:
                pass
        time.sleep(0.5)
    raise RuntimeError("postgres container did not become ready")


@pytest.fixture(scope="session")
def db_url() -> Iterator[str]:
    url = os.environ.get("AAP_TEST_DATABASE_URL")
    name = None
    if not url:
        name, url = _start_container()
    os.environ["AAP_DATABASE_URL"] = url
    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "migrations"))
    try:
        command.upgrade(cfg, "head")
        yield url
    finally:
        if name:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="session")
def engine(db_url: str) -> Engine:
    return create_engine(db_url)


@pytest.fixture(scope="session")
def loaded(engine: Engine, bundle: ConfigBundle) -> config_store.ActiveConfig:
    with transaction(engine, "aap_worker") as conn:
        return config_store.load(conn, bundle, git_sha="test")


@pytest.fixture
def blobs(tmp_path) -> LocalBlobStore:
    return LocalBlobStore(tmp_path / "blobs")


@pytest.fixture
def admin(engine: Engine):
    def run(sql: str, **params):
        with admin_connection(engine) as conn:
            return conn.execute(text(sql), params).all()

    return run


@pytest.fixture(scope="session")
def demo_blobs(tmp_path_factory) -> LocalBlobStore:
    return LocalBlobStore(tmp_path_factory.mktemp("demo-blobs"))


@pytest.fixture(scope="session")
def demo(engine: Engine, bundle: ConfigBundle, loaded: config_store.ActiveConfig, demo_blobs: LocalBlobStore):
    """The seeded demo world (four applications), shared by every integration module that needs it."""
    from aap.demo.scenario import seed
    from aap.store import registry

    with transaction(engine, "aap_worker") as conn:
        result = seed(conn, bundle, demo_blobs)
        second = registry.upsert_user(conn, "Second Reviewer", "hreviewer")
        registry.grant_role(conn, second, "appsec_engineer")
    return result


@pytest.fixture(scope="session")
def fresh_app(engine, bundle, demo):
    """Factory: a Tier 1 application of its own in the Claims team (business owner dlee, technical owner bsmith),
    so a test module can change state freely without touching the shared demo applications."""
    import copy

    import yaml
    from sqlalchemy import text

    from aap.config import repo_root
    from aap.db import transaction
    from aap.services import onboarding

    template = yaml.safe_load((repo_root() / "templates/repo-contract/.security/application.yaml").read_text())

    def make(name: str, repo_id: str) -> str:
        doc = copy.deepcopy(template)
        doc["application"]["name"] = name
        doc["application"]["owners"]["org_unit"] = "claims-team"
        with transaction(engine, "aap_worker") as conn:
            reg = onboarding.register(
                conn,
                bundle,
                repo=onboarding.RepoRef("github", repo_id, f"example-org/{name.lower().replace(' ', '-')}"),
                app_doc=doc,
                requested_by=demo.users["ajones"],
            )
            onboarding.decide(conn, bundle, reg.application_id, decision="approved", decided_by=demo.users["cpatel"])
            conn.execute(
                text("UPDATE applications SET business_owner_id = :b, technical_owner_id = :t WHERE id = :a"),
                {"b": demo.users["dlee"], "t": demo.users["bsmith"], "a": reg.application_id},
            )
        return reg.application_id

    return make
