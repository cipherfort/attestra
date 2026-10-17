# SPDX-License-Identifier: Apache-2.0
"""Webhook receiver (AC-06: forged HMAC, replay) and the worker loop end to end:
webhook → job → verified ingestion → evaluation job → control state."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.connectors.github import FakeGitHub, FakeRun
from aap.db import transaction
from aap.demo import bundles
from aap.demo.seed import AppSpec, RepoSpec, demo_trusted, register
from aap.domain.evidence import RunInfo
from aap.hook.app import create_app
from aap.store import control_store, registry
from aap.worker.runner import Worker

pytestmark = pytest.mark.db
SECRET = b"test-webhook-secret"


def sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def delivery(event: str, payload: dict, secret_ok: bool = True, delivery_id: str | None = None):
    body = json.dumps(payload).encode()
    return body, {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery_id or str(uuid.uuid4()),
        "X-Hub-Signature-256": sign(body) if secret_ok else "sha256=" + "0" * 64,
        "Content-Type": "application/json",
    }


def test_forged_signature_rejected_and_nothing_enqueued(engine):
    hook = TestClient(create_app(engine, SECRET))
    gid = 880000 + uuid.uuid4().int % 9999
    body, headers = delivery(
        "workflow_run",
        {"action": "completed", "repository": {"id": gid, "full_name": "o/r"}, "workflow_run": {"id": 1}},
        secret_ok=False,
    )
    assert hook.post("/github/webhook", content=body, headers=headers).status_code == 401
    with transaction(engine, "aap_worker") as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM jobs WHERE payload->>'repo_external_id' = :g"), {"g": str(gid)}
            ).scalar_one()
            == 0
        )


def test_replayed_delivery_is_ignored(engine):
    hook = TestClient(create_app(engine, SECRET))
    gid = 890000 + uuid.uuid4().int % 9999
    did = str(uuid.uuid4())
    body, headers = delivery(
        "workflow_run",
        {"action": "completed", "repository": {"id": gid, "full_name": "o/r"}, "workflow_run": {"id": 5}},
        delivery_id=did,
    )
    assert hook.post("/github/webhook", content=body, headers=headers).json()["jobs"] == 1
    assert hook.post("/github/webhook", content=body, headers=headers).json()["status"] == "duplicate delivery ignored"


def test_webhook_to_control_state_through_the_worker(engine, bundle, loaded, blobs):
    suffix = uuid.uuid4().hex[:6]
    gid = 900000 + uuid.uuid4().int % 99999
    repo = f"example-org/worker-e2e-{suffix}"
    head = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    with transaction(engine, "aap_worker") as conn:
        org = registry.upsert_org_unit(conn, f"o-{suffix}", "Org", "organisation", None)
        team = registry.upsert_org_unit(conn, f"t-{suffix}", "Team", "team", org)
        approver = registry.upsert_user(conn, "Approver", f"appr-{suffix}")
        app_id, _ = register(
            conn,
            bundle,
            AppSpec(
                name=f"Worker E2E {suffix}",
                description="end to end",
                team_slug="t",
                lifecycle="production",
                classification={
                    "data_classification": "internal",
                    "personal_data": "none",
                    "exposure": "internal",
                    "user_population": "organisation",
                    "business_criticality": "moderate",
                    "privileged_integration": "none",
                },
                profile={"languages": ["python"]},
                repos=[RepoSpec(repo, gid, "primary", head, {"languages": ["python"], "ecosystems": ["pypi"]})],
            ),
            team,
            approver,
        )

    run_id = 4242
    zipped = bundles.build(
        evidence_type="scan.sast",
        repo_full_name=repo,
        repo_id=gid,
        commit_sha=head,
        run_id=run_id,
        tool="CodeQL",
        tool_version="2.19.1",
        files={"results.sarif": bundles.sarif("CodeQL", "2.19.1", [])},
        summary={"languages": ["python"], "languages_detected": ["python"], "query_suite": "default"},
        result="pass",
    )
    gh = FakeGitHub()
    gh.add_run(
        repo,
        FakeRun(
            RunInfo(run_id, 1, gid, head, "push", "success", (bundles.workflow_ref("scan.sast"),)),
            {"aap-evidence-sast": zipped},
        ),
    )

    hook = TestClient(create_app(engine, SECRET))
    body, headers = delivery(
        "workflow_run",
        {"action": "completed", "repository": {"id": gid, "full_name": repo}, "workflow_run": {"id": run_id}},
    )
    assert hook.post("/github/webhook", content=body, headers=headers).status_code == 202

    worker = Worker(engine, bundle, github=gh, blobs=blobs, trusted=demo_trusted(bundle, bundles.DEMO_WORKFLOW_SHA))
    assert worker.drain() >= 2  # ingest job, then the evaluate job it enqueued
    with transaction(engine, "aap_worker") as conn:
        states = {s["control_key"]: s for s in control_store.current_states(conn, app_id)}
        assert states["ASC-BLD-01"]["state"] == "satisfied"
        posture = conn.execute(
            text("SELECT count(*) FROM evidence WHERE application_id = :a AND evidence_type = 'vuln.posture'"),
            {"a": app_id},
        ).scalar_one()
    assert posture == 1
    assert datetime.now(UTC)  # keep import used
