# SPDX-License-Identifier: Apache-2.0
"""GitLab adapter against responses recorded from a real GitLab CE 19.5 (tests/fixtures/gitlab, ADR-033 spike):
the component check accepts the approved job and rejects every way a project can change it."""

from __future__ import annotations

import copy
import io
import json
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient

from aap.config import repo_root
from aap.connectors.gitlab import (
    GitLabComponents,
    bundles,
    owners_from_codeowners,
    render_component,
    required_component_checks,
    verify_component_job,
)
from aap.connectors.gitlab_settings import summarise_protection
from aap.hook.app import create_app, gitlab_jobs_for

FIX = repo_root() / "backend" / "tests" / "fixtures" / "gitlab"
SHA = (FIX / "component_sha.txt").read_text().strip()
APPROVED = json.loads((FIX / "lint_approved.json").read_text())
FORGED = json.loads((FIX / "lint_forged.json").read_text())
SOURCE = (FIX / "component_secrets.yml").read_text()
TRUSTED = GitLabComponents(
    "example-org/security-components",
    {"secrets": {"job": "aap-secrets", "types": {"scan.secrets"}, "shas": {SHA}}},
)


def files(project, path, ref):
    return SOURCE if path == "templates/secrets.yml" and ref == SHA else None


def check(lint, trusted=TRUSTED, job="aap-secrets", etype="scan.secrets"):
    return verify_component_job(lint, job, etype, trusted, files)


def test_the_approved_component_job_is_accepted():
    c = check(APPROVED)
    assert c.approved_ref == f"example-org/security-components/secrets@{SHA}", c.detail


def test_a_forged_script_is_caught_although_the_includes_look_clean():
    assert [i["location"] for i in FORGED["includes"]] == [i["location"] for i in APPROVED["includes"]]
    c = check(FORGED)
    assert c.approved_ref is None and c.known_component and "script" in c.detail


def test_unapproved_commit_wrong_type_and_unknown_job():
    other = GitLabComponents(TRUSTED.project, {"secrets": {**TRUSTED.components["secrets"], "shas": {"0" * 40}}})
    c = check(APPROVED, other)
    assert c.approved_ref is None and c.known_component and "not an approved commit" in c.detail
    assert check(APPROVED, etype="scan.sast").known_component is False
    assert check(APPROVED, job="aap-made-up").approved_ref is None


def merged_with(lint, mutate):
    out = copy.deepcopy(lint)
    merged = yaml.safe_load(out["merged_yaml"])
    mutate(merged)
    out["merged_yaml"] = yaml.safe_dump(merged)
    return out


def test_inheriting_project_defaults_or_variables_is_rejected():
    c = check(merged_with(APPROVED, lambda m: m["aap-secrets"].pop("inherit")))
    assert c.approved_ref is None and "inherits" in c.detail


def test_changing_the_image_or_artifacts_is_rejected_but_scheduling_is_not():
    img = check(merged_with(APPROVED, lambda m: m["aap-secrets"].__setitem__("image", "python:3.12")))
    assert img.approved_ref is None and "image" in img.detail
    sched = check(merged_with(APPROVED, lambda m: m["aap-secrets"].update(stage="security", tags=["linux"])))
    assert sched.approved_ref is not None


def test_includes_must_be_pinned():
    lint = copy.deepcopy(APPROVED)
    lint["includes"].append({"type": "project", "location": "templates/x.yml", "extra": {"ref": "main"}})
    c = check(lint)
    assert c.approved_ref is None and "not pinned" in c.detail
    lint["includes"][-1] = {"type": "remote", "location": "https://example.org/ci.yml", "extra": {}}
    assert "not pinned" in check(lint).detail
    lint = copy.deepcopy(APPROVED)
    lint["valid"], lint["errors"] = False, ["broken"]
    assert "not valid" in check(lint).detail


def test_render_component_uses_input_defaults():
    job = render_component(SOURCE, "aap-secrets")
    assert job["stage"] == "test" and job["inherit"] == {"default": False, "variables": False}
    with pytest.raises(ValueError):
        render_component("spec:\n  inputs:\n    s: {}\n---\nj:\n  stage: $[[ inputs.s ]]\n", "j")


def test_bundles_are_top_level_folders_only():
    found = bundles(
        {
            "aap-evidence-secrets/evidence-manifest.json": b"{}",
            "aap-evidence-secrets/g.sarif": b"x",
            "aap-evidence-secrets/nested/x": b"y",
            "results/other.sarif": b"z",
        }
    )
    assert found == {"aap-evidence-secrets": {"evidence-manifest.json": b"{}", "g.sarif": b"x"}}


def test_required_checks_and_branch_protection_summary():
    assert required_component_checks(APPROVED, TRUSTED) == ["aap / secrets"]
    protected = {
        "push_access_levels": [{"access_level": 0}],
        "allow_force_push": False,
        "code_owner_approval_required": False,
    }
    s = summarise_protection(protected, None, True, ["aap / secrets"])
    assert s["requires_pr"] and s["required_approvals"] == 0 and s["required_checks"] == ["aap / secrets"]
    assert "unavailable_on_tier" in s["notes"][0]  # GitLab Free: approvals cannot be required (a fact, not a gap)
    assert summarise_protection(protected, {"approvals_before_merge": 2}, False, ["x"])["required_checks"] == []
    unprotected = summarise_protection(None, None, True, [])
    assert not unprotected["requires_pr"] and not unprotected["blocks_force_push"]


def test_gitlab_codeowners_sections():
    rules = owners_from_codeowners("[Security] @sec-team\n.gitlab-ci.yml\n^[Docs][2] @docs\ndocs/ @alice\n# comment\n")
    assert rules == [(".gitlab-ci.yml", ["@sec-team"]), ("docs/", ["@alice"])]


def test_webhook_maps_jobs_and_checks_the_token():
    from sqlalchemy import create_engine

    engine = create_engine("postgresql+psycopg://unused@127.0.0.1:1/unused")  # refused before any query
    assert gitlab_jobs_for("Job Hook", {"project_id": 7, "build_id": 9, "build_status": "success"}) == [
        ("gitlab-ingest", {"provider": "gitlab", "project_id": 7, "job_id": 9}, "glrun:7:9")
    ]
    assert gitlab_jobs_for("Job Hook", {"project_id": 7, "build_id": 9, "build_status": "running"}) == []
    assert gitlab_jobs_for("Push Hook", {"project_id": 7})[0][0] == "gitlab-sync"
    app = TestClient(create_app(engine, secret=b"gh", gitlab_secret=b"s3cret"))
    body = json.dumps({"object_kind": "build", "project_id": 7, "build_id": 9, "build_status": "success"})
    bad = app.post(
        "/gitlab/webhook",
        content=body,
        headers={"X-Gitlab-Token": "nope", "X-Gitlab-Event": "Job Hook", "X-Gitlab-Event-UUID": "u1"},
    )
    assert bad.status_code == 401


def test_bundle_zip_round_trip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("aap-evidence-sbom/evidence-manifest.json", "{}")
        z.writestr("aap-evidence-sbom/sbom.cdx.json", "{}")
    from aap.ingest.parsers import safe_unzip

    assert set(bundles(safe_unzip(buf.getvalue()))["aap-evidence-sbom"]) == {"evidence-manifest.json", "sbom.cdx.json"}
