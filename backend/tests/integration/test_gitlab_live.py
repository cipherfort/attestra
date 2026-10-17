# SPDX-License-Identifier: Apache-2.0
"""GitLab end to end against a real GitLab (deploy/local/gitlab.compose.yaml), ADR-033:

publish the shipped components → approve their commit → a project includes them pinned → the pipeline runs on a real
runner → the platform, with only a read-only group token, ingests the evidence at C2 → a project that overrides the
component's job is rejected → settings evidence is collected.

Opt-in: AAP_TEST_SERVICES=1 AAP_TEST_GITLAB_URL=http://127.0.0.1:8929 AAP_TEST_GITLAB_HOST=gitlab.local.test:8929
        AAP_TEST_GITLAB_ADMIN_TOKEN_FILE=... AAP_TEST_GITLAB_RO_TOKEN_FILE=... (a runner must be registered)
"""

from __future__ import annotations

import copy
import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import yaml
from sqlalchemy import text

from aap import pipelines
from aap.config import repo_root
from aap.connectors.gitlab import GitLabComponents, GitLabRest
from aap.connectors.gitlab_settings import collect_project, group_exists
from aap.db import transaction
from aap.ingest.pipeline import ingest_gitlab_job
from aap.services import onboarding
from aap.services.github_sync import sync_repository

pytestmark = [pytest.mark.db, pytest.mark.service]
URL = os.environ.get("AAP_TEST_GITLAB_URL", "")
if not (os.environ.get("AAP_TEST_SERVICES") and URL):
    pytest.skip("live GitLab test: set AAP_TEST_SERVICES=1 and AAP_TEST_GITLAB_URL", allow_module_level=True)
HOST = os.environ["AAP_TEST_GITLAB_HOST"]
ADMIN = Path(os.environ["AAP_TEST_GITLAB_ADMIN_TOKEN_FILE"]).read_text().strip()
RO = Path(os.environ["AAP_TEST_GITLAB_RO_TOKEN_FILE"]).read_text().strip()
GROUP = "example-org"
COMPONENTS = f"{GROUP}/security-components"


def admin() -> httpx.Client:
    return httpx.Client(base_url=f"{URL}/api/v4", headers={"PRIVATE-TOKEN": ADMIN}, timeout=60)


def ok(r: httpx.Response) -> dict:
    assert r.status_code < 300, f"{r.request.method} {r.request.url}: {r.status_code} {r.text[:300]}"
    return r.json()


def project(gl: httpx.Client, name: str) -> dict:
    r = gl.get(f"/projects/{GROUP}%2F{name}")
    if r.status_code == 200:
        return r.json()
    gid = ok(gl.get(f"/groups/{GROUP}"))["id"]
    return ok(
        gl.post(
            "/projects",
            json={"name": name, "namespace_id": gid, "visibility": "internal", "initialize_with_readme": True},
        )
    )


def commit(gl: httpx.Client, pid: int, files: dict[str, str], message: str) -> str:
    actions = []
    for path, content in files.items():
        exists = gl.get(f"/projects/{pid}/repository/files/{path.replace('/', '%2F')}", params={"ref": "main"})
        actions.append(
            {"action": "update" if exists.status_code == 200 else "create", "file_path": path, "content": content}
        )
    return ok(
        gl.post(
            f"/projects/{pid}/repository/commits",
            json={"branch": "main", "commit_message": message, "actions": actions},
        )
    )["id"]


def run_pipeline(gl: httpx.Client, pid: int, timeout: int = 900) -> list[dict]:
    pipe = ok(gl.post(f"/projects/{pid}/pipeline", params={"ref": "main"}))
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = ok(gl.get(f"/projects/{pid}/pipelines/{pipe['id']}"))["status"]
        if status in ("success", "failed", "canceled"):
            return list(ok(gl.get(f"/projects/{pid}/pipelines/{pipe['id']}/jobs")))
        time.sleep(5)
    raise AssertionError("pipeline did not finish")


@pytest.fixture(scope="module")
def world(engine, bundle, demo, tmp_path_factory):
    gl = admin()
    comp = project(gl, "security-components")
    files = {f"templates/{n}.yml": pipelines.render_gitlab(n) for n in pipelines.GITLAB_SHIPPED}
    sha = commit(gl, comp["id"], files, "aap components")
    cfg_dir = tmp_path_factory.mktemp("cfg")
    shutil.copytree(repo_root() / "config", cfg_dir / "config")
    pipelines.approve_gitlab(sha, "v-test", COMPONENTS, path=cfg_dir / "config" / "trusted-producers.yaml")
    trusted_doc = yaml.safe_load((cfg_dir / "config" / "trusted-producers.yaml").read_text())
    live_bundle = copy.copy(bundle)
    real_doc = bundle.doc

    def doc(name: str):  # the test bundle trusts the commit just published, nothing else changes
        return trusted_doc if name == "trusted_producers" else real_doc(name)

    live_bundle.doc = doc  # type: ignore[method-assign]
    app = project(gl, "claims-portal")
    contract = yaml.safe_load((repo_root() / "templates/repo-contract/.security/application.yaml").read_text())
    contract["application"]["name"] = "GitLab Claims Portal"
    contract["application"]["owners"]["org_unit"] = "claims-team"
    commit(
        gl,
        app["id"],
        {
            ".gitlab-ci.yml": pipelines.gitlab_include(HOST, COMPONENTS, sha) + "stages: [test]\n",
            ".security/application.yaml": yaml.safe_dump(contract),
            "requirements.txt": "requests==2.19.0\n",  # a known-vulnerable pin, so SCA has something to report
            "CODEOWNERS": "[Security]\n.gitlab-ci.yml @root\n.security/ @root\n",
        },
        "onboard",
    )
    with transaction(engine, "aap_worker") as conn:
        reg = onboarding.register(
            conn,
            live_bundle,
            repo=onboarding.RepoRef("gitlab", str(app["id"]), app["path_with_namespace"], "internal", "main"),
            app_doc=contract,
        )
    jobs = run_pipeline(gl, app["id"])
    api = GitLabRest(lambda: RO, base_url=URL)
    return {
        "gl": gl,
        "api": api,
        "app": app,
        "jobs": jobs,
        "bundle": live_bundle,
        "sha": sha,
        "reg": reg,
        "trusted": GitLabComponents.from_config(trusted_doc),
    }


def test_component_evidence_is_accepted_at_c2(world, engine, blobs):
    by_name = {j["name"]: j for j in world["jobs"]}
    assert set(by_name) == {f"aap-{n}" for n in pipelines.GITLAB_SHIPPED}, by_name
    assert all(j["status"] == "success" for j in world["jobs"]), {j["name"]: j["status"] for j in world["jobs"]}
    accepted = []
    for job in world["jobs"]:
        with transaction(engine, "aap_worker") as conn:
            out = ingest_gitlab_job(
                conn,
                gitlab=world["api"],
                blobs=blobs,
                bundle=world["bundle"],
                project_id=world["app"]["id"],
                job_id=job["id"],
            )
        assert out.rejected == [], (job["name"], out.rejected)
        accepted += out.accepted
    assert len(accepted) == len(pipelines.GITLAB_SHIPPED)
    with transaction(engine, "aap_worker") as conn:  # webhook and polling may both deliver a job: ingested once
        again = ingest_gitlab_job(
            conn,
            gitlab=world["api"],
            blobs=blobs,
            bundle=world["bundle"],
            project_id=world["app"]["id"],
            job_id=world["jobs"][0]["id"],
        )
    assert again.accepted == [] and again.skipped == "job already ingested"
    with transaction(engine, "aap_worker") as conn:
        rows = conn.execute(
            text(
                "SELECT evidence_type, confidence, producer_ref FROM evidence WHERE evidence_id = ANY(CAST(:i AS uuid[]))"
            ),
            {"i": accepted},
        ).all()
    assert {r.confidence for r in rows} == {"C2"}  # ADR-033: GitLab is capped at C2
    assert all(r.producer_ref.startswith(f"{COMPONENTS}/") and r.producer_ref.endswith(world["sha"]) for r in rows)
    assert {r.evidence_type for r in rows} >= {"scan.sast", "scan.sca", "scan.secrets", "scan.iac", "sbom"}


def test_a_forged_scan_with_a_valid_manifest_is_rejected(world, engine, blobs):
    """The strongest forgery a project can make: keep the component's job, including the evidence tool, but replace the
    scan with a fabricated clean result. The manifest is valid and bound to the job; only the component check can
    catch it, and it must."""
    gl, app = world["gl"], world["app"]
    job = list(yaml.safe_load_all(pipelines.render_gitlab("secrets")))[1]["aap-secrets"]
    job["script"] = [
        line
        if "gitleaks dir" not in line
        else 'printf \'%s\' \'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","version":"8.30.1"}},'
        '"results":[]}]}\' > results/gitleaks.sarif'
        for line in job["script"]
    ]
    job["stage"] = "test"
    forged = (
        pipelines.gitlab_include(HOST, COMPONENTS, world["sha"])
        + "stages: [test]\n"
        + yaml.safe_dump({"aap-secrets": job}, sort_keys=False, width=1000)
    )
    commit(gl, app["id"], {".gitlab-ci.yml": forged}, "forge a clean secrets scan")
    jobs = run_pipeline(gl, app["id"])
    forged_job = next(j for j in jobs if j["name"] == "aap-secrets")
    assert forged_job["status"] == "success"  # the forgery runs and uploads a well-formed bundle
    with transaction(engine, "aap_worker") as conn:
        out = ingest_gitlab_job(
            conn,
            gitlab=world["api"],
            blobs=blobs,
            bundle=world["bundle"],
            project_id=app["id"],
            job_id=forged_job["id"],
        )
        rejection = conn.execute(
            text("SELECT reason_code, details FROM evidence_rejections WHERE run_id = :j"), {"j": forged_job["id"]}
        ).one()
    assert out.accepted == [] and out.rejected == [("aap-evidence-secrets", "UNAPPROVED_WORKFLOW_REF")]
    assert rejection.reason_code == "UNAPPROVED_WORKFLOW_REF"
    assert "script" in rejection.details["component_check"]
    commit(
        gl,
        app["id"],
        {".gitlab-ci.yml": pipelines.gitlab_include(HOST, COMPONENTS, world["sha"]) + "stages: [test]\n"},
        "restore",
    )


def test_settings_evidence_from_a_reporter_token(world, engine):
    snap = collect_project(world["api"], world["app"]["id"], world["trusted"])
    assert snap.provider == "gitlab" and snap.full_name == world["app"]["path_with_namespace"]
    assert snap.evidence["repo.codeowners"]["present"] is True
    assert ".security/" in snap.evidence["repo.codeowners"]["covered_paths"]
    assert "repo.environments" in snap.gaps and "Maintainer" in snap.gaps["repo.environments"]
    rules = snap.evidence["repo.ruleset"]
    assert rules["blocks_force_push"] is True  # main is protected by default on GitLab
    with transaction(engine, "aap_worker") as conn:
        out = sync_repository(conn, world["bundle"], snap, datetime.now(UTC), None, group_exists(world["api"]))
    assert out.registered and "registry.application" in out.written and "repo.ruleset" in out.written


def test_gitlab_issues_as_the_ticket_system(world, engine, demo):
    from aap.connectors.issues import GitLabIssues
    from aap.services import ticketing

    gl, app = world["gl"], world["app"]
    gid = ok(gl.get(f"/groups/{GROUP}"))["id"]
    token = ok(
        gl.post(
            f"/groups/{gid}/access_tokens",
            json={
                "name": "aap-issues-test",
                "scopes": ["api"],
                "access_level": 20,
                "expires_at": (datetime.now(UTC).date().replace(day=1))
                .replace(year=datetime.now(UTC).year + 1)
                .isoformat(),
            },
        )
    )
    client = GitLabIssues(lambda: token["token"], URL)
    for old in gl.get(f"/projects/{app['id']}/issues", params={"labels": "aap-managed", "per_page": 100}).json():
        gl.delete(f"/projects/{app['id']}/issues/{old['iid']}")  # earlier runs' issues (admin may delete)
    policy = {
        "ticket_priorities": ["P1"],
        "labels": ["appsec"],
        "default_project_by_org_unit": {},
        "default_project": app["path_with_namespace"],
    }
    with transaction(engine, "aap_worker") as conn:
        conn.execute(text("DELETE FROM finding_tickets"))  # this test owns the ticket state of the shared world
        rep = ticketing.sync(conn, client, policy, "https://aap.example.org", datetime.now(UTC))
    assert rep.created and not rep.errors, rep.errors
    key = rep.created[0]
    issue = client.get(key)
    assert issue.status_category == "new" and "aap-managed" in issue.labels
    with transaction(engine, "aap_worker") as conn:  # idempotent: a second sync creates nothing
        assert ticketing.sync(conn, client, policy, "https://aap.example.org", datetime.now(UTC)).created == []
    client.transition_to(key, "done")  # a developer closes the issue
    with transaction(engine, "aap_worker") as conn:
        rep3 = ticketing.sync(conn, client, policy, "https://aap.example.org", datetime.now(UTC))
        statuses = set(
            conn.execute(
                text("""SELECT f.status FROM findings f JOIN finding_tickets ft ON ft.finding_id = f.id
                                            JOIN tickets t ON t.id = ft.ticket_id WHERE t.ticket_key = :k"""),
                {"k": key},
            ).scalars()
        )
    assert not rep3.errors and statuses == {"fix_pending"}  # closing the issue never closes the finding
