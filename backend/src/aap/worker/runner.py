# SPDX-License-Identifier: Apache-2.0
"""Background worker (ADR-024): claims jobs with SKIP LOCKED and runs idempotent handlers as `aap_worker`.

Queues:
  ingest      workflow_run.completed → verified evidence ingestion (needs a GitHub client)
  evaluate    re-evaluate an application's controls, re-score its findings, publish posture
  scheduler   periodic sweeps: freshness/evaluation for every application, SLA breaches, chain verification,
              and enqueueing every configured integration whose sync interval has elapsed
  connector   one integration sync (worker/connectors.py), recorded in connector_runs
  github-sync one repository's GitHub settings/alerts after a push or settings webhook
  assessment  an approved manual assessment becomes its evidence record (the API never writes evidence)
  onboarding  an application was registered or its classification decided: record the decision as evidence,
              read the source repository (when the GitHub plugin is configured), then evaluate
"""

from __future__ import annotations

import logging
import os
import socket
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, text

from aap.blobstore import EvidenceBlobStore, default_store
from aap.config import ConfigBundle
from aap.connectors.github import GitHubClient
from aap.db import transaction
from aap.domain.evidence import TrustedWorkflows
from aap.ingest.pipeline import ingest_workflow_run
from aap.services import evaluation, exceptions, risk_service, siem_export
from aap.store import evidence_store, findings_store, jobs

log = logging.getLogger("aap.worker")
Handler = Callable[[Mapping[str, Any]], None]


class Worker:
    def __init__(
        self,
        engine: Engine,
        bundle: ConfigBundle,
        github: GitHubClient | None = None,
        blobs: EvidenceBlobStore | None = None,
        trusted: TrustedWorkflows | None = None,
    ):
        self.engine, self.bundle, self.github = engine, bundle, github
        self.blobs = blobs or default_store()
        self.trusted = trusted or TrustedWorkflows.from_config(bundle.doc("trusted_producers"))
        self.name = f"{socket.gethostname()}:{os.getpid()}"
        self.handlers: dict[str, Handler] = {
            "ingest": self.ingest,
            "evaluate": self.evaluate,
            "scheduler": self.scheduler,
            "connector": self.connector,
            "onboarding": self.onboarding,
            "assessment": self.assessment,
            # push / settings / alert webhooks (hook/app.py): refresh that one repository's GitHub evidence
            "github-sync": lambda p: self.connector({"connector": "github", "repo": p["repo"], "target": p["repo"]}),
            # GitLab (ADR-033): a finished job's evidence bundles; a push refreshes that project's settings evidence
            "gitlab-ingest": self.gitlab_ingest,
            "gitlab-sync": lambda p: self.connector(
                {"connector": "gitlab", "project_id": p["project_id"], "target": str(p["project_id"])}
            ),
        }

    # ---------------------------------------------------------------------------------------- handlers

    def ingest(self, p: Mapping[str, Any]) -> None:
        if self.github is None:
            raise RuntimeError("no GitHub client: the GitHub App is not configured (aap bootstrap github-app)")
        with transaction(self.engine, "aap_worker") as conn:
            out = ingest_workflow_run(
                conn,
                github=self.github,
                blobs=self.blobs,
                bundle=self.bundle,
                trusted=self.trusted,
                repo_full_name=p["repo"],
                repo_external_id=p["repo_external_id"],
                provider=str(p.get("provider", "github")),
                run_id=int(p["run_id"]),
            )
        log.info("ingest %s run %s: accepted=%d rejected=%s", p["repo"], p["run_id"], len(out.accepted), out.rejected)
        if out.accepted and "defectdojo" not in self._unconfigured():
            with transaction(self.engine, "aap_worker") as conn:
                jobs.enqueue(conn, "connector", {"connector": "defectdojo", "evidence_ids": out.accepted})

    def evaluate(self, p: Mapping[str, Any]) -> None:
        app_id = str(p["application_id"])
        now = datetime.now(UTC)
        with transaction(self.engine, "aap_worker") as conn:
            risk_service.score_application(conn, self.bundle, app_id)
            risk_service.publish_posture(conn, app_id, now)
            evaluation.evaluate_application(conn, self.bundle, app_id, now)

    def gitlab_ingest(self, p: Mapping[str, Any]) -> None:
        from aap.ingest.pipeline import ingest_gitlab_job
        from aap.integrations import gitlab_client
        from aap.secrets import secret_store

        api = gitlab_client(secret_store())
        with transaction(self.engine, "aap_worker") as conn:
            out = ingest_gitlab_job(
                conn,
                gitlab=api,
                blobs=self.blobs,
                bundle=self.bundle,
                project_id=int(p["project_id"]),
                job_id=int(p["job_id"]),
            )
        log.info(
            "gitlab job %s/%s: accepted=%d rejected=%s skipped=%s",
            p["project_id"],
            p["job_id"],
            len(out.accepted),
            out.rejected,
            out.skipped,
        )

    def assessment(self, p: Mapping[str, Any]) -> None:
        from aap.services import assessments

        with transaction(self.engine, "aap_worker") as conn:
            assessments.write_evidence(conn, str(p["assessment_id"]), datetime.now(UTC))

    def onboarding(self, p: Mapping[str, Any]) -> None:
        from aap.services import onboarding

        app_id = str(p["application_id"])
        with transaction(self.engine, "aap_worker") as conn:
            onboarding.record_classification_evidence(conn, app_id, datetime.now(UTC))
            source = conn.execute(
                text("""SELECT r.full_name, r.provider, a.tier_rank FROM applications a
                        LEFT JOIN repositories r ON r.id = a.source_repo_id WHERE a.id = :a"""),
                {"a": app_id},
            ).first()
            if source is not None and source.provider == "github" and "github" not in self._unconfigured():
                jobs.enqueue(
                    conn, "github-sync", {"repo": source.full_name}, dedup_key=f"github-sync:{source.full_name}"
                )
            # controls are evaluated against an approved tier only; a pending Tier 1/2 waits for AppSec (fail closed)
            if source is not None and source.tier_rank is not None:
                jobs.enqueue(conn, "evaluate", {"application_id": app_id}, dedup_key=f"evaluate:{app_id}")

    def _unconfigured(self) -> set[str]:
        from aap.integrations import status

        return {s.key for s in status(self.engine, self.bundle) if not s.configured}

    def connector(self, p: Mapping[str, Any]) -> None:
        from aap.integrations import record_run
        from aap.plugins import RunContext, registry
        from aap.secrets import secret_store

        key = str(p["connector"])
        plugin = registry().get(key)
        if plugin.run is None:
            raise RuntimeError(f"plugin {key!r} has nothing to run")
        run = plugin.run
        ctx = RunContext(self.engine, self.bundle, secret_store(), self.blobs, p)
        result = record_run(self.engine, key, str(p.get("target", "")), lambda: run(ctx))
        log.info("connector %s: items=%d gaps=%d errors=%d", key, result.items, len(result.gaps), len(result.errors))

    def scheduler(self, p: Mapping[str, Any]) -> None:
        from aap.integrations import due
        from aap.secrets import SecretError, secret_store

        try:
            store = secret_store()
        except SecretError:
            store = None
        due_connectors = due(self.engine, self.bundle, store)
        with transaction(self.engine, "aap_worker") as conn:
            for key in due_connectors:
                jobs.enqueue(conn, "connector", {"connector": key}, dedup_key=f"connector:{key}")
            findings_store.mark_sla_breaches(conn, datetime.now(UTC))
            exceptions.expire_due(conn, self.bundle, datetime.now(UTC))
            jobs.release_expired_leases(conn)
            for row in conn.execute(
                text("SELECT id FROM applications WHERE tier_rank IS NOT NULL AND lifecycle <> 'retired'")
            ):
                jobs.enqueue(conn, "evaluate", {"application_id": str(row.id)}, dedup_key=f"evaluate:{row.id}")
            checked, broken = evidence_store.verify_month(conn, datetime.now(UTC))
            if broken is not None:
                # P1 platform incident + SIEM event `evidence.integrity_failure` (runbook: evidence-integrity-mismatch)
                siem_export.integrity_failure(conn, self.bundle.doc("siem_events"), datetime.now(UTC), broken, checked)
                log.critical("evidence hash chain broken at index %d of %d", broken, checked)

    # ---------------------------------------------------------------------------------------- loop

    def run_once(
        self,
        queues: tuple[str, ...] = (
            "ingest",
            "onboarding",
            "assessment",
            "evaluate",
            "scheduler",
            "connector",
            "github-sync",
        ),
    ) -> bool:
        with transaction(self.engine, "aap_worker") as conn:
            job = jobs.claim(conn, queues, self.name)
        if job is None:
            return False
        try:
            self.handlers[job.queue](job.payload)
        except Exception as e:  # handlers are idempotent: retry with backoff, then dead-letter
            with transaction(self.engine, "aap_worker") as conn:
                outcome = jobs.fail(conn, job, f"{type(e).__name__}: {e}")
            log.exception("job %s (%s) failed → %s", job.id, job.queue, outcome)
        else:
            with transaction(self.engine, "aap_worker") as conn:
                jobs.complete(conn, job.id)
        return True

    def drain(self, max_jobs: int = 1000) -> int:
        n = 0
        while n < max_jobs and self.run_once():
            n += 1
        return n

    def forever(self, idle_sleep: float = 2.0) -> None:  # pragma: no cover - process loop
        while True:
            if not self.run_once():
                time.sleep(idle_sleep)
