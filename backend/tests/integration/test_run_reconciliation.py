# SPDX-License-Identifier: Apache-2.0
"""Workflow runs whose webhook never arrived are picked up by the GitHub connector: unseen completed runs are queued
for ingestion exactly as the webhook would have queued them; runs that already left evidence or a rejection are not."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from aap.db import transaction
from aap.services.github_sync import reconcile_runs, registered_repositories

pytestmark = pytest.mark.db


class FakeRuns:
    def __init__(self, ids: list[int]):
        self.ids, self.calls = ids, []

    def pages(self, path, params=None, key=None):
        self.calls.append((path, dict(params or {}), key))
        yield from ({"id": i, "status": "completed"} for i in self.ids)


def test_unseen_runs_are_queued_once_and_seen_ones_skipped(engine, demo, admin):
    with transaction(engine, "aap_worker") as conn:
        repos = dict(registered_repositories(conn, "example-org"))
        seen_evidence = int(
            conn.execute(text("SELECT run_ref->>'run_id' FROM evidence WHERE run_ref ? 'run_id' LIMIT 1")).scalar()
        )
        seen_rejection = int(
            conn.execute(text("SELECT run_id FROM evidence_rejections WHERE run_id IS NOT NULL LIMIT 1")).scalar()
        )
    assert "example-org/claims-api" in repos
    repo, ext = "example-org/claims-api", repos["example-org/claims-api"]
    admin("DELETE FROM jobs WHERE queue = 'ingest' RETURNING id")
    api = FakeRuns([900000001, 900000002, seen_evidence, seen_rejection])
    since = datetime.now(UTC) - timedelta(days=400)
    with transaction(engine, "aap_worker") as conn:
        assert reconcile_runs(conn, api, repo, ext, since) == 2
    path, params, key = api.calls[0]
    assert path == f"/repos/{repo}/actions/runs" and key == "workflow_runs"
    assert params["status"] == "completed" and params["created"].startswith(">=")
    with transaction(engine, "aap_worker") as conn:
        queued = (
            conn.execute(text("SELECT payload FROM jobs WHERE queue = 'ingest' AND status = 'queued' ORDER BY id"))
            .scalars()
            .all()
        )
        assert [q["run_id"] for q in queued] == [900000001, 900000002]
        assert all(
            q["repo"] == repo and q["repo_external_id"] == int(ext) and q["provider"] == "github" for q in queued
        )
        assert reconcile_runs(conn, FakeRuns([900000001, 900000002]), repo, ext, since) == 0  # already queued
    admin("DELETE FROM jobs WHERE queue = 'ingest' RETURNING id")
