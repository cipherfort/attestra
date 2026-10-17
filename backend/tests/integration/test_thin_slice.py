# SPDX-License-Identifier: Apache-2.0
"""Phase 1 thin slice, end to end against PostgreSQL 16 (PID WP1.7):

    pipeline evidence bundle → verified ingestion → write-once storage + hash-chained ledger
    → findings from SARIF → control evaluation → explainable state → re-scan closes / regression reopens

plus the abuse cases AC-01 (forged producer), AC-02 (unapproved SHA) and digest tampering, and RLS scoping.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from aap.connectors.github import FakeGitHub, FakeRun
from aap.db import Scope, transaction
from aap.demo import bundles
from aap.demo.seed import AppSpec, RepoSpec, connector_evidence, demo_trusted, good_repo_settings, register
from aap.domain.evidence import RunInfo
from aap.ingest.pipeline import ingest_workflow_run
from aap.services import evaluation, risk_service
from aap.store import control_store, evidence_store, findings_store, registry

pytestmark = pytest.mark.db

CLAIMS = {
    "data_classification": "confidential",
    "personal_data": "customer_personal",
    "exposure": "internet_authenticated",
    "user_population": "public_large",
    "business_criticality": "major",
    "privileged_integration": "limited",
    "regulatory": ["GDPR"],
}
SQLI = {
    "rule": "java/sql-injection",
    "message": "Query built from user-controlled sources",
    "score": 8.8,
    "cwe": 89,
    "file": "src/main/java/ClaimsRepository.java",
    "line": 42,
    "fp": "a1b2c3",
}
XSS = {
    "rule": "js/reflected-xss",
    "message": "Reflected cross-site scripting",
    "score": 6.1,
    "cwe": 79,
    "file": "web/src/render.ts",
    "line": 7,
    "fp": "d4e5f6",
}


@pytest.fixture
def world(engine, bundle, loaded):
    """A team, an approver, and a Tier 1 application with one repository (unique per test)."""
    suffix = uuid.uuid4().hex[:6]
    gid = int(uuid.uuid4().int % 10**9)
    head = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    with transaction(engine, "aap_worker") as conn:
        org = registry.upsert_org_unit(conn, f"org-{suffix}", "Org", "organisation", None)
        team = registry.upsert_org_unit(conn, f"claims-{suffix}", "Claims team", "team", org)
        other = registry.upsert_org_unit(conn, f"payments-{suffix}", "Payments team", "team", org)
        appsec = registry.upsert_user(conn, "AppSec Reviewer", f"appsec-{suffix}")
        repo = f"example-org/claims-api-{suffix}"
        app_id, app_key = register(
            conn,
            bundle,
            AppSpec(
                name=f"Claims API {suffix}",
                description="Citizens submit benefit claims",
                team_slug="claims",
                lifecycle="production",
                classification=CLAIMS,
                profile={"languages": ["java", "javascript"], "has_api": True, "has_web_frontend": True},
                repos=[
                    RepoSpec(
                        repo,
                        gid,
                        "primary",
                        head,
                        {"languages": ["java", "javascript"], "ecosystems": ["maven", "npm"], "workflows": True},
                    )
                ],
            ),
            team,
            appsec,
        )
    return {"app_id": app_id, "app_key": app_key, "repo": repo, "gid": gid, "head": head, "team": team, "other": other}


def _ingest(engine, bundle, blobs, world, zipped, run_id, refs=None, conclusion="success", head=None):
    gh = FakeGitHub()
    gh.add_run(
        world["repo"],
        FakeRun(
            RunInfo(
                run_id,
                1,
                world["gid"],
                head or world["head"],
                "push",
                conclusion,
                tuple(refs or (bundles.workflow_ref("scan.sast"),)),
            ),
            {"aap-evidence-sast": zipped},
        ),
    )
    with transaction(engine, "aap_worker") as conn:
        return ingest_workflow_run(
            conn,
            github=gh,
            blobs=blobs,
            bundle=bundle,
            trusted=demo_trusted(bundle, bundles.DEMO_WORKFLOW_SHA),
            repo_full_name=world["repo"],
            repo_external_id=world["gid"],
            run_id=run_id,
        )


def _sast(world, results, run_id, commit=None, **kw):
    return bundles.build(
        evidence_type="scan.sast",
        repo_full_name=world["repo"],
        repo_id=world["gid"],
        commit_sha=commit or world["head"],
        run_id=run_id,
        tool="CodeQL",
        tool_version="2.19.1",
        files={"results.sarif": bundles.sarif("CodeQL", "2.19.1", results)},
        summary={
            "languages": ["java", "javascript"],
            "languages_detected": ["java", "javascript"],
            "query_suite": "security-extended",
        },
        **kw,
    )


def _state(engine, app_id, key):
    with transaction(engine, "aap_worker") as conn:
        return {s["scope_ref"]: s for s in control_store.current_states(conn, app_id) if s["control_key"] == key}


def _evaluate(engine, bundle, app_id):
    with transaction(engine, "aap_worker") as conn:
        return evaluation.evaluate_application(conn, bundle, app_id, datetime.now(UTC), gap_grace=None)


def test_classified_tier_1_and_sast_starts_with_no_evidence(engine, bundle, world):
    _evaluate(engine, bundle, world["app_id"])
    st = _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]
    assert st["state"] == "no_evidence" and st["requirement"] == "mandatory"


def test_verified_sast_evidence_satisfies_control_and_creates_findings(engine, bundle, blobs, world):
    out = _ingest(engine, bundle, blobs, world, _sast(world, [SQLI, XSS], 101), 101)
    assert len(out.accepted) == 1 and not out.rejected and out.findings_created == 2
    _evaluate(engine, bundle, world["app_id"])
    st = _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]
    assert st["state"] == "satisfied"
    assert "CodeQL 2.19.1" in st["explanation"] and world["head"][:7] in st["explanation"]
    assert [str(e) for e in st["evidence_ids"]] == out.accepted  # the state points at the exact evidence record


def test_ac01_forged_evidence_from_teams_own_workflow_is_rejected(engine, bundle, blobs, world):
    forged = f"{world['repo']}/.github/workflows/totally-real-sast.yml@{'e' * 40}"
    out = _ingest(engine, bundle, blobs, world, _sast(world, [], 102), 102, refs=[forged])
    assert out.rejected == [("aap-evidence-sast", "UNTRUSTED_PRODUCER")] and not out.accepted
    _evaluate(engine, bundle, world["app_id"])
    assert _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]["state"] == "no_evidence"


def test_ac02_and_tampering_rejected(engine, bundle, blobs, world):
    unapproved = bundles.workflow_ref("scan.sast", sha="f" * 40)
    assert (
        _ingest(engine, bundle, blobs, world, _sast(world, [], 103), 103, refs=[unapproved]).rejected[0][1]
        == "UNAPPROVED_WORKFLOW_REF"
    )
    assert (
        _ingest(engine, bundle, blobs, world, _sast(world, [], 104, tamper="digest"), 104).rejected[0][1]
        == "DIGEST_MISMATCH"
    )
    with transaction(engine, "aap_worker") as conn:
        reasons = {
            r.reason_code
            for r in conn.execute(
                text("SELECT reason_code FROM evidence_rejections WHERE repository_external_id = :g"),
                {"g": str(world["gid"])},
            )
        }
    assert reasons == {"UNAPPROVED_WORKFLOW_REF", "DIGEST_MISMATCH"}


def test_rescan_closes_fixed_finding_and_regression_reopens(engine, bundle, blobs, world):
    _ingest(engine, bundle, blobs, world, _sast(world, [SQLI, XSS], 201), 201)
    second = _ingest(engine, bundle, blobs, world, _sast(world, [XSS], 202), 202)  # SQLi fixed
    assert second.findings_closed == 1
    with transaction(engine, "aap_worker") as conn:
        rows = {r["cwe_id"]: r for r in findings_store.for_application(conn, world["app_id"])}
    assert rows[89]["status"] == "closed" and str(rows[89]["closure_evidence_id"]) == second.accepted[0]
    assert rows[79]["status"] == "new"
    third = _ingest(engine, bundle, blobs, world, _sast(world, [SQLI, XSS], 203), 203)  # regression
    assert third.findings_created == 0
    with transaction(engine, "aap_worker") as conn:
        assert {r["cwe_id"]: r["status"] for r in findings_store.for_application(conn, world["app_id"])}[
            89
        ] == "reopened"


def test_ten_identical_runs_create_no_duplicate_findings(engine, bundle, blobs, world):
    for run in range(300, 310):
        _ingest(engine, bundle, blobs, world, _sast(world, [SQLI, XSS], run), run)
    with transaction(engine, "aap_worker") as conn:
        assert len(findings_store.for_application(conn, world["app_id"])) == 2  # PS-6


def test_new_commit_touching_code_makes_evidence_stale(engine, bundle, blobs, world):
    _ingest(engine, bundle, blobs, world, _sast(world, [], 401), 401)
    new_head = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    with transaction(engine, "aap_worker") as conn:
        conn.execute(
            text("UPDATE repositories SET head_sha = :h WHERE provider = 'github' AND external_id = :g"),
            {"h": new_head, "g": str(world["gid"])},
        )
        evaluation.evaluate_application(
            conn,
            bundle,
            world["app_id"],
            datetime.now(UTC),
            gap_grace=None,
            compare=lambda repo, base, head: ["src/main/java/ClaimsService.java"],
        )
    st = _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]
    assert st["state"] == "stale" and "ClaimsService.java" in st["explanation"]


def test_configuration_controls_and_explanations(engine, bundle, world):
    with transaction(engine, "aap_worker") as conn:
        settings = good_repo_settings()
        settings["repo.ruleset"]["required_approvals"] = 1  # Tier 1 requires 2
        connector_evidence(conn, world["app_id"], world["repo"], datetime.now(UTC), settings)
    _evaluate(engine, bundle, world["app_id"])
    assert _state(engine, world["app_id"], "ASC-SRC-03")[world["repo"]]["state"] == "satisfied"
    bp = _state(engine, world["app_id"], "ASC-SRC-01")[world["repo"]]
    assert bp["state"] == "not_satisfied" and "≥2 approvals (has 1)" in bp["explanation"]


def test_risk_scoring_sets_priority_and_sla(engine, bundle, blobs, world):
    _ingest(engine, bundle, blobs, world, _sast(world, [SQLI], 501), 501)
    with transaction(engine, "aap_worker") as conn:
        assert risk_service.score_application(conn, bundle, world["app_id"]) == 1
        assert risk_service.score_application(conn, bundle, world["app_id"]) == 0  # unchanged → no new assessment
        f = findings_store.for_application(conn, world["app_id"])[0]
    # SAST high (base 3) on Tier 1 (impact 4): 12 → P2, 30-day SLA
    assert f["priority"] == "P2" and f["risk_score"] == 12
    assert (f["sla_due_at"] - f["first_seen_at"]).days == 30


def test_evidence_hash_chain_verifies(engine, bundle, blobs, world):
    _ingest(engine, bundle, blobs, world, _sast(world, [SQLI], 601), 601)
    with transaction(engine, "aap_worker") as conn:
        checked, broken = evidence_store.verify_month(conn, datetime.now(UTC))
    assert checked >= 1 and broken is None


def test_rls_other_team_cannot_see_application(engine, bundle, world):
    with transaction(engine, "aap_api", Scope(org_units=(world["other"],))) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM applications WHERE id = :a"), {"a": world["app_id"]}).scalar() == 0
        )
    with transaction(engine, "aap_api", Scope(org_units=(world["team"],))) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM applications WHERE id = :a"), {"a": world["app_id"]}).scalar() == 1
        )


def test_pr_evidence_does_not_satisfy_default_branch_control(engine, bundle, blobs, world):
    _ingest(engine, bundle, blobs, world, _sast(world, [], 701, ref="refs/pull/12/merge"), 701)
    _evaluate(engine, bundle, world["app_id"])
    st = _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]
    assert st["state"] == "stale" and "default branch" in st["explanation"]


def test_old_evidence_ages_out(engine, bundle, blobs, world):
    old = datetime.now(UTC) - timedelta(days=45)
    _ingest(engine, bundle, blobs, world, _sast(world, [], 801, produced_at=old), 801)
    _evaluate(engine, bundle, world["app_id"])
    st = _state(engine, world["app_id"], "ASC-BLD-01")[world["repo"]]
    assert st["state"] == "stale" and "ceiling" in st["explanation"]


def test_verified_bundle_with_malformed_sarif_is_rejected_cleanly(engine, bundle, blobs, world):
    """Found by fuzzing: a bundle that passes verification (approved workflow, digests) but whose SARIF is malformed
    is rejected as SCHEMA_INVALID, and nothing of it is written (savepoint), instead of failing the ingestion job."""
    malformed = json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"properties": {"security-severity": "high"}}]}],
        }
    )
    zipped = bundles.build(
        evidence_type="scan.sast",
        repo_full_name=world["repo"],
        repo_id=world["gid"],
        commit_sha=world["head"],
        run_id=9701,
        tool="CodeQL",
        tool_version="2.19.1",
        files={"results.sarif": malformed.encode()},
    )
    with transaction(engine, "aap_worker") as conn:
        before = conn.execute(text("SELECT count(*) FROM evidence")).scalar_one()
    out = _ingest(engine, bundle, blobs, world, zipped, 9701)
    assert out.accepted == [] and out.rejected == [("aap-evidence-sast", "SCHEMA_INVALID")]
    with transaction(engine, "aap_worker") as conn:
        assert conn.execute(text("SELECT count(*) FROM evidence")).scalar_one() == before
        reason = conn.execute(text("SELECT details FROM evidence_rejections WHERE run_id = 9701")).scalar_one()
    assert "malformed SARIF" in reason["detail"]
