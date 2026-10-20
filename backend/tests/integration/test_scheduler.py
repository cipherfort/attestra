# SPDX-License-Identifier: Apache-2.0
"""The scheduler sweep keeps itself going: exactly one sweep job exists at a time, and finishing one queues the next
one interval later, however many workers run. Without this nothing periodic happens (connector syncs, deadline
breaches, exception expiry, re-evaluation, snapshots, chain verification)."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from aap.db import transaction
from aap.worker.runner import Worker, scheduler_interval

pytestmark = pytest.mark.db


def _sweeps(engine):
    with transaction(engine, "aap_worker") as conn:
        return conn.execute(
            text("""SELECT status, run_at > now() + interval '100 seconds' AS later FROM jobs
                    WHERE queue = 'scheduler' AND status IN ('queued', 'running') ORDER BY id"""),
        ).all()


def test_one_sweep_at_a_time_and_each_one_queues_the_next(engine, bundle, loaded, blobs, admin, monkeypatch):
    monkeypatch.setenv("AAP_SCHEDULER_INTERVAL", "120")
    admin("DELETE FROM jobs WHERE queue = 'scheduler' RETURNING id")
    first, second = Worker(engine, bundle, blobs=blobs), Worker(engine, bundle, blobs=blobs)
    first.ensure_scheduled()
    second.ensure_scheduled()  # another replica starting: still one sweep
    assert [s.status for s in _sweeps(engine)] == ["queued"]

    assert first.run_once(queues=("scheduler",))  # the sweep runs …
    after = _sweeps(engine)
    assert len(after) == 1 and after[0].status == "queued" and after[0].later  # … and queues the next, 120 s on

    second.ensure_scheduled()  # a replica's periodic check while the next sweep waits: no duplicate
    assert len(_sweeps(engine)) == 1
    assert not first.run_once(queues=("scheduler",))  # not due yet


def test_the_interval_has_a_floor_and_a_default(monkeypatch):
    monkeypatch.setenv("AAP_SCHEDULER_INTERVAL", "5")
    assert scheduler_interval().total_seconds() == 60
    monkeypatch.setenv("AAP_SCHEDULER_INTERVAL", "not a number")
    assert scheduler_interval().total_seconds() == 300
    monkeypatch.delenv("AAP_SCHEDULER_INTERVAL")
    assert scheduler_interval().total_seconds() == 300
