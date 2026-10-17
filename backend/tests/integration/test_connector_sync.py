# SPDX-License-Identifier: Apache-2.0
"""Connector services over the demo world, with recorded API shapes: GitHub settings, cloud posture (Azure Resource
Graph via respx, AWS Security Hub via moto), SIEM derivation/dispatch, run bookkeeping and scheduling."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta

import boto3
import httpx
import pytest
import respx
import yaml
from moto import mock_aws
from sqlalchemy import text

from aap.config import repo_root
from aap.connectors.cloud import ARG_URL, DefenderClient, SecurityHubClient
from aap.connectors.github_settings import GitHubRest, collect_repository
from aap.connectors.sentinel import STREAM_COLUMNS, LogsIngestionClient, SentinelError
from aap.db import transaction
from aap.integrations import RunResult, due, record_run, status
from aap.services import cloud_sync, siem_export
from aap.services.github_sync import sync_repository

pytestmark = pytest.mark.db
GH = "https://api.github.com"
REPO = "example-org/claims-api"


def _q(engine, sql, **p):
    with transaction(engine, "aap_worker") as conn:
        return conn.execute(text(sql), p).all()


# ------------------------------------------------------------------------------------------ GitHub


def _mock_repo(gid: int, alerts: list[dict]) -> None:
    app_yaml = (repo_root() / "templates/repo-contract/.security/application.yaml").read_text()
    asvs_yaml = (repo_root() / "templates/repo-contract/.security/asvs.yaml").read_text()
    threats = (repo_root() / "templates/repo-contract/.security/threat-model/threats.yaml").read_text()
    mitig = (repo_root() / "templates/repo-contract/.security/threat-model/mitigations.yaml").read_text()
    files = {
        ".security/application.yaml": app_yaml,
        ".security/asvs.yaml": asvs_yaml,
        ".security/threat-model/threats.yaml": threats,
        ".security/threat-model/mitigations.yaml": mitig,
        ".github/CODEOWNERS": "* @example-org/claims\n/.github/workflows/ @example-org/platform\n",
        "SECURITY.md": "# Security",
    }
    respx.get(f"{GH}/repos/{REPO}").respond(
        200,
        json={
            "id": gid,
            "default_branch": "main",
            "visibility": "private",
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "secret_scanning_validity_checks": {"status": "disabled"},
            },
        },
    )
    respx.get(f"{GH}/repos/{REPO}/commits/main").respond(200, json={"sha": "a" * 40})
    respx.get(f"{GH}/repos/{REPO}/rules/branches/main").respond(
        200,
        json=[
            {
                "type": "pull_request",
                "ruleset_id": 7,
                "parameters": {"required_approving_review_count": 2, "require_code_owner_review": True},
            },
            {
                "type": "required_status_checks",
                "ruleset_id": 7,
                "parameters": {
                    "required_status_checks": [
                        {"context": "aap / sast"},
                        {"context": "aap / sca"},
                        {"context": "aap / secrets"},
                    ]
                },
            },
            {"type": "non_fast_forward", "ruleset_id": 7},
            {"type": "deletion", "ruleset_id": 7},
        ],
    )
    respx.get(f"{GH}/repos/{REPO}/branches/main/protection").respond(404)
    respx.get(url__regex=rf"{GH}/repos/{REPO}/contents/(?P<path>[^?]+)").mock(
        side_effect=lambda req, path: httpx.Response(200, text=files[path]) if path in files else httpx.Response(404)
    )
    respx.get(url__regex=rf"{GH}/repos/example-org/\.github/contents/.*").respond(404)
    respx.get(f"{GH}/repos/{REPO}/codeowners/errors").respond(200, json={"errors": []})
    respx.get(url__regex=rf"{GH}/repos/{REPO}/collaborators.*affiliation=outside.*").respond(200, json=[])
    respx.get(url__regex=rf"{GH}/repos/{REPO}/collaborators.*affiliation=direct.*").respond(200, json=[{"login": "a"}])
    respx.get(f"{GH}/repos/{REPO}/environments").respond(
        200,
        json={
            "environments": [
                {
                    "name": "production",
                    "deployment_branch_policy": {"protected_branches": True},
                    "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "Team"}]}],
                }
            ]
        },
    )
    respx.get(url__regex=rf"{GH}/repos/{REPO}/actions/secrets.*").respond(
        200, json={"secrets": [{"name": "NPM_TOKEN"}]}
    )
    respx.get(url__regex=rf"{GH}/repos/{REPO}/environments/production/secrets.*").respond(200, json={"secrets": []})
    respx.get(f"{GH}/repos/{REPO}/actions/permissions").respond(
        200, json={"enabled": True, "allowed_actions": "selected"}
    )
    respx.get(f"{GH}/repos/{REPO}/actions/permissions/workflow").respond(
        200, json={"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
    )
    respx.get(url__regex=rf"{GH}/repos/{REPO}/secret-scanning/alerts.*").respond(200, json=alerts)
    respx.get(url__regex=rf"{GH}/orgs/example-org/teams/.*").respond(200, json={"members_count": 3})


@respx.mock
def test_github_settings_become_evidence_and_alerts_become_findings(engine, bundle, demo):
    gid = int(_q(engine, "SELECT external_id FROM repositories WHERE full_name = :n", n=REPO)[0].external_id)
    alert = {
        "number": 41,
        "validity": "active",
        "secret_type_display_name": "Azure AD client secret",
        "first_location_detected": {"path": "config/app.yaml", "start_line": 3},
        "html_url": "https://x",
    }
    _mock_repo(gid, [alert])
    api = GitHubRest(lambda: "t")
    snap = collect_repository(api, REPO)
    with transaction(engine, "aap_worker") as conn:
        out = sync_repository(conn, bundle, snap, datetime.now(UTC), api)
    assert out.registered and not out.gaps
    assert {
        "repo.ruleset",
        "repo.security_settings",
        "repo.codeowners",
        "repo.access",
        "repo.environments",
        "repo.actions_policy",
        "scan.secrets",
        "repo.threat_model",
        "registry.application",
    } <= set(out.written)
    ev = {
        r.evidence_type: r
        for r in _q(
            engine,
            """SELECT DISTINCT ON (evidence_type) evidence_type, confidence, summary,
            producer_ref FROM evidence WHERE scope_ref IN (:r, 'APP-00001') AND producer_ref LIKE 'connector:github-settings%'
            ORDER BY evidence_type, ingested_at DESC""",
            r=REPO,
        )
    }
    assert ev["repo.ruleset"].summary["required_approvals"] == 2 and ev["repo.ruleset"].confidence == "C1"
    assert ev["scan.secrets"].confidence == "C3" and ev["scan.secrets"].summary["active"] == 1
    assert ev["repo.codeowners"].summary["covered_paths"] == [".github/workflows/", ".security/"]
    assert ev["repo.threat_model"].summary["schema_valid"], ev["repo.threat_model"].summary
    f = _q(engine, "SELECT status FROM findings WHERE fingerprint = :f", f=f"secret:github:{gid}:41")
    assert f and f[0].status == "new"

    # next sync: alert resolved → finding closed by the scan evidence
    respx.reset()
    _mock_repo(gid, [])
    snap = collect_repository(api, REPO)
    with transaction(engine, "aap_worker") as conn:
        out = sync_repository(conn, bundle, snap, datetime.now(UTC), api)
    assert out.findings_closed == 1
    assert (
        _q(engine, "SELECT status FROM findings WHERE fingerprint = :f", f=f"secret:github:{gid}:41")[0].status
        == "closed"
    )


@respx.mock
def test_unregistered_repository_gets_no_evidence(engine, bundle, demo):
    respx.get(f"{GH}/repos/acme/unknown").respond(
        200, json={"id": 999001, "default_branch": "main", "visibility": "public"}
    )
    respx.get(url__regex=rf"{GH}/.*").respond(404)
    snap = collect_repository(GitHubRest(lambda: "t"), "acme/unknown")
    with transaction(engine, "aap_worker") as conn:
        out = sync_repository(conn, bundle, snap, datetime.now(UTC))
    assert not out.registered and out.written == []
    assert _q(engine, "SELECT onboarding FROM repositories WHERE external_id = '999001'")


# ------------------------------------------------------------------------------------------ cloud


@pytest.fixture
def scopes(engine, demo):
    app = _q(engine, "SELECT id FROM applications WHERE name = 'Claims API'")[0].id
    with transaction(engine, "aap_worker") as conn:
        conn.execute(text("DELETE FROM cloud_scopes WHERE application_id = :a"), {"a": app})
        conn.execute(
            text("""INSERT INTO cloud_scopes (application_id, provider, scope_type, scope_ref) VALUES
            (:a, 'azure', 'resource_group', '/subscriptions/0000/resourceGroups/rg-claims-prod'),
            (:a, 'aws', 'account', '123456789012')"""),
            {"a": app},
        )
    return app


@respx.mock
def test_defender_paging_mapping_and_closure(engine, scopes):
    page1 = {
        "data": [
            {
                "id": "/subscriptions/0000/providers/microsoft.security/assessments/a1",
                "severity": "high",
                "resourceId": "/subscriptions/0000/resourcegroups/rg-claims-prod/providers/x/y",
                "title": "TLS",
                "subscriptionId": "0000",
            }
        ],
        "$skipToken": "next",
    }
    page2 = {
        "data": [
            {
                "id": "/subscriptions/0000/providers/microsoft.security/assessments/a2",
                "severity": "low",
                "resourceId": "/subscriptions/0000/resourcegroups/rg-other/providers/x/z",
                "title": "Other",
                "subscriptionId": "0000",
            }
        ]
    }
    route = respx.post(ARG_URL).mock(side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)])
    found = list(DefenderClient(lambda: "tok", http=httpx.Client()).unhealthy(["0000"]))
    assert len(found) == 2 and json.loads(route.calls[1].request.content)["options"]["$skipToken"] == "next"
    with transaction(engine, "aap_worker") as conn:
        rep = cloud_sync.sync(conn, "azure", "defender", found, datetime.now(UTC))
    assert rep.unmapped == 1 and rep.by_app == {"APP-00001": 1}
    post = _q(
        engine,
        """SELECT summary, confidence FROM evidence WHERE evidence_type = 'cloud.posture'
                         AND scope_ref = 'APP-00001' ORDER BY ingested_at DESC LIMIT 1""",
    )[0]
    assert post.summary["max_severity"] == "high" and post.confidence == "C3"
    with transaction(engine, "aap_worker") as conn:
        rep = cloud_sync.sync(conn, "azure", "defender", [], datetime.now(UTC))
    assert rep.closed == 1


def test_security_hub_via_moto(engine, scopes):
    with mock_aws():
        hub = boto3.client("securityhub", region_name="eu-west-2")
        hub.enable_security_hub()
        base = {
            "SchemaVersion": "2018-10-08",
            "ProductArn": "arn:aws:securityhub:eu-west-2:123456789012:product/123456789012/default",
            "GeneratorId": "fsbp",
            "Types": ["Software and Configuration Checks"],
            "CreatedAt": "2026-10-01T00:00:00Z",
            "UpdatedAt": "2026-10-01T00:00:00Z",
            "Description": "d",
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
        }
        hub.batch_import_findings(
            Findings=[
                {
                    **base,
                    "Id": "f-crit",
                    "AwsAccountId": "123456789012",
                    "Severity": {"Label": "CRITICAL"},
                    "Title": "Public S3",
                    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::claims"}],
                },
                {
                    **base,
                    "Id": "f-other",
                    "AwsAccountId": "999999999999",
                    "Severity": {"Label": "HIGH"},
                    "Title": "Elsewhere",
                    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::x"}],
                },
                {
                    **base,
                    "Id": "f-low",
                    "AwsAccountId": "123456789012",
                    "Severity": {"Label": "LOW"},
                    "Title": "Low",
                    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::y"}],
                },
            ]
        )
        found = list(
            SecurityHubClient(lambda: boto3.Session(region_name="eu-west-2"), ["eu-west-2"]).active(["123456789012"])
        )
    assert [f.id for f in found] == ["f-crit"]  # other account and LOW severity filtered at the API
    with transaction(engine, "aap_worker") as conn:
        rep = cloud_sync.sync(conn, "aws", "security_hub", found, datetime.now(UTC))
    assert rep.by_app == {"APP-00001": 1}
    assert (
        _q(engine, "SELECT source_system FROM findings WHERE fingerprint = 'cloud:aws:f-crit'")[0].source_system
        == "security_hub"
    )


# ------------------------------------------------------------------------------------------ SIEM


def test_siem_derive_dedup_and_dispatch(engine, bundle, demo):
    policy = bundle.doc("siem_events")
    now = datetime.now(UTC)
    with transaction(engine, "aap_worker") as conn:
        conn.execute(text("DELETE FROM outbox WHERE topic = 'siem'"))
        first = siem_export.derive(conn, policy, now, "https://aap.example.org")
        second = siem_export.derive(conn, policy, now + timedelta(minutes=5), "https://aap.example.org")
    types = {r.etype for r in _q(engine, "SELECT payload->>'EventType' etype FROM outbox WHERE topic = 'siem'")}
    assert first >= 3 and second == 0, (first, second)
    assert {"vuln.kev_internet_exposed", "secret.exposed_active", "checkpoint.daily"} <= types
    sent_bodies = []

    def ok(request):
        sent_bodies.append(json.loads(gzip.decompress(request.content)))
        return httpx.Response(204)

    client = LogsIngestionClient(
        "https://dce.example.ingest.monitor.azure.com",
        "dcr-123",
        lambda: "tok",
        http=httpx.Client(transport=httpx.MockTransport(ok)),
    )
    with transaction(engine, "aap_worker") as conn:
        sent, err = siem_export.dispatch(conn, client)
    assert sent == first and err is None
    assert all(set(row) <= set(STREAM_COLUMNS) for row in sent_bodies[0])
    assert _q(engine, "SELECT count(*) n FROM outbox WHERE topic = 'siem' AND dispatched_at IS NULL")[0].n == 0

    # a refused batch stays queued (at-least-once)
    with transaction(engine, "aap_worker") as conn:
        conn.execute(text("UPDATE outbox SET dispatched_at = NULL WHERE topic = 'siem'"))
    failing = LogsIngestionClient(
        "https://dce.example",
        "dcr",
        lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403))),
    )
    with transaction(engine, "aap_worker") as conn:
        sent, err = siem_export.dispatch(conn, failing)
    assert sent == 0 and "403" in err


def test_stream_columns_reject_unknown_fields():
    c = LogsIngestionClient(
        "https://dce.example",
        "d",
        lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(204))),
    )
    with pytest.raises(SentinelError, match="not in the DCR stream"):
        c.send([{"TimeGenerated": "x", "Secret": "y"}])


def test_terraform_dcr_stream_matches_code():
    tf = (repo_root() / "examples/terraform/azure/modules/sentinel/columns.auto.json").read_text()
    assert json.loads(tf) == [{"name": k, "type": v} for k, v in STREAM_COLUMNS.items()]


def test_every_derived_event_type_is_governed():
    governed = {e["type"] for e in yaml.safe_load((repo_root() / "config/siem-events.yaml").read_text())["events"]}
    assert set(siem_export.QUERIES) <= governed


# ------------------------------------------------------------------------------------------ registry / runs


def test_status_reports_missing_configuration(engine, bundle, monkeypatch, tmp_path):
    for v in ("AAP_JIRA_URL", "AAP_JIRA_EMAIL", "AAP_DT_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("AAP_SECRETS_DIR", str(tmp_path / "s"))
    st = {s.key: s for s in status(engine, bundle)}
    assert (
        not st["jira"].configured
        and "AAP_JIRA_URL" in st["jira"].missing
        and "secret:jira-api-token" in st["jira"].missing
    )
    monkeypatch.setenv("AAP_DT_URL", "http://dt")
    from aap.secrets import FileSecretStore

    FileSecretStore(tmp_path / "s").put("dependency-track-api-key", "odt_x")
    st = {s.key: s for s in status(engine, bundle)}
    assert st["dependency_track"].configured
    assert "dependency_track" in due(engine, bundle, FileSecretStore(tmp_path / "s"), datetime.now(UTC))


def test_record_run_states(engine):
    assert record_run(engine, "test-ok", "", lambda: RunResult(3)).items == 3
    record_run(engine, "test-partial", "", lambda: RunResult(1, {"repo": "403"}))
    with pytest.raises(RuntimeError):
        record_run(engine, "test-failed", "", lambda: (_ for _ in ()).throw(ValueError("boom")))
    rows = {
        r.connector: r
        for r in _q(engine, "SELECT connector, status, error FROM connector_runs WHERE connector LIKE 'test-%'")
    }
    assert rows["test-ok"].status == "ok" and rows["test-partial"].status == "partial"
    assert rows["test-failed"].status == "failed" and "boom" in rows["test-failed"].error


def test_worker_runs_a_third_party_plugin(engine, bundle, monkeypatch, tmp_path):
    """The worker dispatches through the registry: a plugin from another package runs like a built-in one."""
    import aap.plugins as plugins_mod
    from aap.plugins import Plugin, Registry
    from aap.plugins import RunResult as PRunResult
    from aap.worker.runner import Worker

    seen = {}

    def run(ctx):
        seen["payload"] = dict(ctx.payload)
        return PRunResult(7, {"one-repo": "403"})

    fake = Registry(
        {"acme_siem": Plugin(key="acme_siem", name="Acme SIEM", kind="siem", purpose="t", run=run, source="aap-acme")},
        {},
    )
    monkeypatch.setattr(plugins_mod, "registry", lambda: fake)
    monkeypatch.setenv("AAP_SECRETS_DIR", str(tmp_path / "s"))
    monkeypatch.setenv("AAP_BLOB_ROOT", str(tmp_path / "b"))
    Worker(engine, bundle).connector({"connector": "acme_siem", "target": "t1"})
    assert seen["payload"]["target"] == "t1"
    row = _q(
        engine,
        "SELECT status, items FROM connector_runs WHERE connector = 'acme_siem' ORDER BY started_at DESC LIMIT 1",
    )[0]
    assert row.status == "partial" and row.items == 7
