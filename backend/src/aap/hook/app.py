# SPDX-License-Identifier: Apache-2.0
"""Webhook receiver (GitHub and GitLab): the only internet-facing component (ADR-025, threat T-04).

It authenticates the delivery (GitHub: HMAC-SHA256; GitLab: the secret token header; both compared in constant
time), drops replays (delivery ID), and enqueues a job
carrying identifiers only. It runs as the `aap_hook` database role, which can do nothing except insert into
`webhook_deliveries` and `jobs`. It has no read path to platform data and makes no outbound calls.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from aap.db import get_engine, transaction
from aap.store import jobs

MAX_BODY = 25 * 1024 * 1024  # GitHub's maximum payload size


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def jobs_for(event: str, payload: dict[str, Any]) -> list[tuple[str, dict[str, Any], str]]:
    """Map a webhook to (queue, identifiers-only payload, dedup key). The payload is a hint: workers re-fetch state."""
    repo = payload.get("repository") or {}
    rid, full = repo.get("id"), repo.get("full_name")
    if not isinstance(rid, int) or not isinstance(full, str):
        return []
    if event == "workflow_run" and payload.get("action") == "completed":
        run_id = (payload.get("workflow_run") or {}).get("id")
        if isinstance(run_id, int):
            return [
                (
                    "ingest",
                    {"provider": "github", "repo_external_id": rid, "repo": full, "run_id": run_id},
                    f"run:{rid}:{run_id}",
                )
            ]
    if event == "push":
        return [
            (
                "github-sync",
                {"provider": "github", "repo_external_id": rid, "repo": full, "kind": "push"},
                f"sync:{rid}",
            )
        ]
    if event in ("repository_ruleset", "branch_protection_rule", "security_and_analysis", "repository"):
        return [
            (
                "github-sync",
                {"provider": "github", "repo_external_id": rid, "repo": full, "kind": "settings"},
                f"settings:{rid}",
            )
        ]
    if event in ("code_scanning_alert", "secret_scanning_alert", "dependabot_alert"):
        return [
            (
                "github-sync",
                {"provider": "github", "repo_external_id": rid, "repo": full, "kind": "alerts"},
                f"alerts:{rid}",
            )
        ]
    return []


def gitlab_jobs_for(event: str, payload: dict[str, Any]) -> list[tuple[str, dict[str, Any], str]]:
    """GitLab: a finished job → ingest its evidence bundles; a push → refresh the project's settings evidence."""
    pid = payload.get("project_id") or (payload.get("project") or {}).get("id")
    if not isinstance(pid, int):
        return []
    if event == "Job Hook" and payload.get("build_status") in ("success", "failed"):
        job = payload.get("build_id")
        if isinstance(job, int):
            return [("gitlab-ingest", {"provider": "gitlab", "project_id": pid, "job_id": job}, f"glrun:{pid}:{job}")]
    if event in ("Push Hook", "Merge Request Hook"):
        return [("gitlab-sync", {"provider": "gitlab", "project_id": pid}, f"glsync:{pid}")]
    return []


def create_app(
    engine: Engine | None = None, secret: bytes | None = None, gitlab_secret: bytes | None = None
) -> FastAPI:
    app = FastAPI(title="aap-hook", docs_url=None, redoc_url=None, openapi_url=None)
    key = secret or os.environ.get("AAP_WEBHOOK_SECRET", "").encode()
    gl_key = gitlab_secret or b""
    if not key or (gitlab_secret is None and secret is None):
        from aap.secrets import SecretError, secret_store

        try:
            store = secret_store()
            key = key or (store.get("github-webhook-secret") or "").encode()  # `aap bootstrap github-app`
            gl_key = gl_key or (store.get("gitlab-webhook-secret") or "").encode()  # `aap bootstrap gitlab`
        except SecretError:
            pass
    if not key and not gl_key:
        raise RuntimeError("no webhook secret: run `aap bootstrap github-app` or `aap bootstrap gitlab`")
    eng = engine or get_engine()

    async def record(
        request: Request, delivery: str, event: str, queued: list[tuple[str, dict[str, Any], str]]
    ) -> dict[str, Any]:
        try:
            with transaction(eng, "aap_hook") as conn:
                conn.execute(
                    text("INSERT INTO webhook_deliveries (delivery_id, event) VALUES (:d, :e)"),
                    {"d": delivery[:200], "e": event[:64]},
                )
                ids = [jobs.enqueue(conn, q, p, dedup_key=d) for q, p, d in queued]
        except IntegrityError:
            return {"status": "duplicate delivery ignored"}
        except Exception:
            raise HTTPException(400, "invalid delivery") from None
        return {"status": "accepted", "jobs": len([j for j in ids if j])}

    @app.post("/gitlab/webhook", status_code=202)
    async def receive_gitlab(request: Request) -> dict[str, Any]:
        token = request.headers.get("X-Gitlab-Token", "").encode()
        if not gl_key or not hmac.compare_digest(token, gl_key):
            raise HTTPException(401, "invalid token")
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "payload too large")
        delivery = request.headers.get("X-Gitlab-Event-UUID") or request.headers.get("Idempotency-Key") or ""
        if not delivery:
            raise HTTPException(400, "missing delivery id")
        try:
            payload = json.loads(body)
        except ValueError:
            raise HTTPException(400, "body is not JSON") from None
        event = request.headers.get("X-Gitlab-Event", "")
        return await record(request, f"gitlab:{delivery}", event, gitlab_jobs_for(event, payload))

    @app.post("/github/webhook", status_code=202)
    async def receive(request: Request) -> dict[str, Any]:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "payload too large")
        if not key or not verify_signature(key, body, request.headers.get("X-Hub-Signature-256")):
            raise HTTPException(401, "invalid signature")
        delivery = request.headers.get("X-GitHub-Delivery", "")
        event = request.headers.get("X-GitHub-Event", "")
        try:
            payload = json.loads(body)
        except ValueError:
            raise HTTPException(400, "body is not JSON") from None
        try:
            with transaction(eng, "aap_hook") as conn:
                conn.execute(
                    text("INSERT INTO webhook_deliveries (delivery_id, event) VALUES (:d, :e)"),
                    {"d": delivery, "e": event[:64]},
                )
                queued = [jobs.enqueue(conn, q, p, dedup_key=d) for q, p, d in jobs_for(event, payload)]
        except IntegrityError:
            return {"status": "duplicate delivery ignored"}  # replay: already recorded
        except Exception:
            raise HTTPException(400, "invalid delivery") from None
        return {"status": "accepted", "jobs": len([j for j in queued if j])}

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    return app
