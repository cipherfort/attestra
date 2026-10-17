# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL job queue (ADR-024): at-least-once, `FOR UPDATE SKIP LOCKED`, exponential backoff, dead-lettering."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import Connection, text


@dataclass(frozen=True)
class Job:
    id: int
    queue: str
    payload: Mapping[str, Any]
    attempts: int
    max_attempts: int


def enqueue(
    conn: Connection,
    queue: str,
    payload: Mapping[str, Any],
    dedup_key: str | None = None,
    delay: timedelta | None = None,
) -> int | None:
    """Returns the job id, or None when an identical job (same queue + dedup key) is already queued/running."""
    row = conn.execute(
        text("""INSERT INTO jobs (queue, payload, dedup_key, run_at)
                VALUES (:q, CAST(:p AS jsonb), :d, now() + CAST(:delay AS interval))
                ON CONFLICT (queue, dedup_key) WHERE dedup_key IS NOT NULL AND status IN ('queued', 'running')
                DO NOTHING RETURNING id"""),
        {
            "q": queue,
            "p": json.dumps(dict(payload)),
            "d": dedup_key,
            "delay": f"{int((delay or timedelta()).total_seconds())} seconds",
        },
    ).first()
    return int(row.id) if row else None


def claim(conn: Connection, queues: Sequence[str], worker: str, lease: timedelta = timedelta(minutes=5)) -> Job | None:
    row = conn.execute(
        text("""UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_by = :w,
                  locked_until = now() + CAST(:lease AS interval)
                WHERE id = (SELECT id FROM jobs WHERE queue = ANY(:qs) AND status = 'queued' AND run_at <= now()
                            ORDER BY run_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
                RETURNING id, queue, payload, attempts, max_attempts"""),
        {"qs": list(queues), "w": worker, "lease": f"{int(lease.total_seconds())} seconds"},
    ).first()
    return Job(row.id, row.queue, row.payload, row.attempts, row.max_attempts) if row else None


def complete(conn: Connection, job_id: int) -> None:
    conn.execute(
        text("UPDATE jobs SET status = 'succeeded', finished_at = now(), locked_by = NULL WHERE id = :id"),
        {"id": job_id},
    )


def fail(conn: Connection, job: Job, error: str) -> str:
    """Retry with exponential backoff (30s · 2^n, max 1h) or dead-letter after max_attempts."""
    if job.attempts >= job.max_attempts:
        conn.execute(
            text("UPDATE jobs SET status = 'dead', last_error = :e, finished_at = now() WHERE id = :id"),
            {"id": job.id, "e": error[:2000]},
        )
        return "dead"
    backoff = min(3600, 30 * 2 ** (job.attempts - 1))
    conn.execute(
        text(
            "UPDATE jobs SET status = 'queued', last_error = :e, locked_by = NULL, "
            "run_at = now() + CAST(:b AS interval) WHERE id = :id"
        ),
        {"id": job.id, "e": error[:2000], "b": f"{backoff} seconds"},
    )
    return "retry"


def release_expired_leases(conn: Connection) -> int:
    """Jobs whose worker died mid-flight go back to the queue (idempotent handlers make this safe)."""
    return conn.execute(
        text("UPDATE jobs SET status = 'queued', locked_by = NULL WHERE status = 'running' AND locked_until < now()")
    ).rowcount
