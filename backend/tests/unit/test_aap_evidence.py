# SPDX-License-Identifier: Apache-2.0
"""The pipeline-side manifest tool and the platform-side verifier agree: a manifest written by aap_evidence.py in a
(simulated) GitHub Actions job passes the schema and verify_bundle; tampering is caught on both sides."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from datetime import date
from pathlib import Path

import pytest
import yaml

from aap import pipelines
from aap.config import repo_root
from aap.domain.evidence import RejectReason, RunInfo, TrustedWorkflows, verify_bundle
from aap.ingest.pipeline import manifest_errors

TOOL = repo_root() / "pipelines" / "aap_evidence.py"
spec = importlib.util.spec_from_file_location("aap_evidence", TOOL)
assert spec and spec.loader
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

SHA = "c" * 40
WF_SHA = "d" * 40
SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.1"}},
            "results": [
                {"ruleId": "js/xss", "level": "error", "message": {"text": "x"}},
                {"ruleId": "js/sqli", "level": "warning", "message": {"text": "y"}},
                {"ruleId": "js/old", "level": "note", "message": {"text": "z"}, "suppressions": [{"kind": "inSource"}]},
            ],
        }
    ],
}


def gh_env(tmp_path: Path, event: dict | None = None) -> dict[str, str]:
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(event or {"repository": {"visibility": "private"}}))
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "example-org/claims-api",
        "GITHUB_REPOSITORY_ID": "4242",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "example-org/claims-api/.github/workflows/aap-security.yml@refs/heads/main",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_EVENT_PATH": str(ev),
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


def produce(tmp_path: Path, env: dict[str, str], *extra: str) -> Path:
    (tmp_path / "results.sarif").write_text(json.dumps(SARIF))
    out = tmp_path / "bundle"
    rc = tool.main(
        [
            "manifest",
            "--type",
            "scan.sast",
            "--tool-name",
            "codeql",
            "--policy-ref",
            "codeql/security-extended",
            "--out",
            str(out),
            *extra,
            str(tmp_path / "results.sarif"),
        ],
        env=env,
    )
    assert rc == 0
    return out


def run_info(**kw) -> RunInfo:
    base = dict(
        run_id=9001,
        run_attempt=2,
        repository_id=4242,
        head_sha=SHA,
        event="push",
        conclusion="success",
        referenced_workflows=(f"example-org/security-workflows/.github/workflows/sast.yml@{WF_SHA}",),
    )
    return RunInfo(**{**base, **kw})


TRUSTED = TrustedWorkflows(
    "example-org/security-workflows",
    {".github/workflows/sast.yml": {"shas": {WF_SHA}, "types": {"scan.sast"}}},
    {"github-hosted": "C3", "self-hosted": "C2"},
)


def bundle_files(out: Path) -> tuple[dict, dict[str, bytes]]:
    manifest = json.loads((out / "evidence-manifest.json").read_text())
    files = {p.name: p.read_bytes() for p in out.iterdir() if p.name != "evidence-manifest.json"}
    return manifest, files


def test_manifest_from_a_github_job_passes_the_platform_verifier(tmp_path):
    out = produce(tmp_path, gh_env(tmp_path))
    manifest, files = bundle_files(out)
    assert manifest_errors(manifest) == []
    assert manifest["tool"]["version"] == "2.20.1"  # read from the SARIF driver
    assert manifest["result"] == "findings" and manifest["summary"]["results"] == 2  # the suppressed one is excluded
    assert manifest["repository"] == {"full_name": "example-org/claims-api", "id": 4242, "visibility": "private"}
    verdict = verify_bundle(manifest, files, run_info(), None, TRUSTED)
    assert verdict.accepted and verdict.confidence == "C2" and verdict.producer_ref.endswith(f"sast.yml@{WF_SHA}")
    assert tool.verify(str(out)) == []


def test_pull_request_binds_to_the_head_commit_not_the_merge_commit(tmp_path):
    head = "e" * 40
    env = gh_env(tmp_path, {"pull_request": {"number": 7, "head": {"sha": head}}})
    env |= {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/7/merge"}
    manifest, files = bundle_files(produce(tmp_path, env))
    assert manifest["commit_sha"] == head and manifest["pull_request"] == 7
    assert verify_bundle(manifest, files, run_info(head_sha=head, event="pull_request"), None, TRUSTED).accepted


def test_tampering_after_the_manifest_is_caught_by_both_sides(tmp_path):
    out = produce(tmp_path, gh_env(tmp_path))
    (out / "results.sarif").write_text(json.dumps({**SARIF, "runs": []}))  # e.g. a later step "cleans" the results
    assert any("sha256 mismatch" in p for p in tool.verify(str(out)))
    manifest, files = bundle_files(out)
    assert verify_bundle(manifest, files, run_info(), None, TRUSTED).reason == RejectReason.DIGEST_MISMATCH


def test_manifest_from_another_repository_run_is_a_binding_mismatch(tmp_path):
    manifest, files = bundle_files(produce(tmp_path, gh_env(tmp_path)))
    assert verify_bundle(manifest, files, run_info(run_id=1), None, TRUSTED).reason == RejectReason.BINDING_MISMATCH


def test_refuses_outside_ci_and_bad_inputs(tmp_path, capsys):
    (tmp_path / "a.sarif").write_text(json.dumps(SARIF))
    args = [
        "manifest",
        "--type",
        "scan.sast",
        "--tool-name",
        "x",
        "--out",
        str(tmp_path / "o"),
        str(tmp_path / "a.sarif"),
    ]
    assert tool.main(args, env={}) == 2 and "not running in GitHub Actions" in capsys.readouterr().err
    (tmp_path / "bad name.sarif").write_text("{}")
    bad = [
        "manifest",
        "--type",
        "scan.sast",
        "--tool-name",
        "x",
        "--tool-version",
        "1",
        "--out",
        str(tmp_path / "p"),
        str(tmp_path / "bad name.sarif"),
    ]
    assert tool.main(bad, env=gh_env(tmp_path)) == 2
    digest = ["--artifact-digest", "latest"]
    assert tool.main([*args[:-1], *digest, args[-1]], env=gh_env(tmp_path)) == 2


def test_gitlab_job_context_is_capped_as_self_hosted(tmp_path):
    env = {
        "GITLAB_CI": "true",
        "CI_PROJECT_PATH": "group/sub/proj",
        "CI_PROJECT_ID": "77",
        "CI_COMMIT_SHA": SHA,
        "CI_COMMIT_REF_NAME": "main",
        "CI_JOB_ID": "555",
        "CI_PIPELINE_ID": "12",
        "CI_PIPELINE_SOURCE": "push",
        "CI_PROJECT_VISIBILITY": "internal",
    }
    manifest, _ = bundle_files(produce(tmp_path, env))
    assert manifest_errors(manifest) == []
    assert manifest["repository"]["full_name"] == "group/sub/proj" and manifest["run"]["id"] == 555
    assert manifest["run"]["runner_environment"] == "self-hosted"


# ------------------------------------------------------------------------------------------ export / approve


def _inlined_tool(rendered: str) -> str:
    doc = yaml.safe_load(rendered)
    steps = next(iter(doc["jobs"].values()))["steps"]
    script = next(s["run"] for s in steps if "aap-evidence tool" in s.get("name", ""))
    body = script.split("<<'AAP_EVIDENCE_EOF'\n", 1)[1].rsplit("AAP_EVIDENCE_EOF", 1)[0]
    return body


@pytest.mark.parametrize("name", sorted(pipelines.SHIPPED))
def test_rendered_workflow_inlines_the_exact_tool_and_pins_every_action(name):
    rendered = pipelines.render(name)
    assert hashlib.sha256(_inlined_tool(rendered).encode()).hexdigest() == hashlib.sha256(TOOL.read_bytes()).hexdigest()
    doc = yaml.safe_load(rendered)
    for job in doc["jobs"].values():
        assert job["permissions"]["contents"] == "read"
        for step in job["steps"]:
            if "uses" in step:
                ref = step["uses"].split("@", 1)[1]
                assert len(ref) == 40, f"{name}: {step['uses']} is not pinned to a commit"
    upload = next(s for j in doc["jobs"].values() for s in j["steps"] if "upload-artifact" in s.get("uses", ""))
    assert upload["with"]["name"].startswith("aap-evidence-")


def test_approve_appends_the_release_and_retires_the_previous_one(tmp_path):
    cfg = tmp_path / "trusted-producers.yaml"
    shutil.copy(repo_root() / "config" / "trusted-producers.yaml", cfg)
    first, second = "1" * 40, "2" * 40
    pipelines.approve(first, "v1.0.0", "acme/security-workflows", path=cfg, today=date(2027, 1, 1))
    pipelines.approve(second, "v1.1.0", path=cfg, today=date(2027, 3, 1))
    text = cfg.read_text()
    assert "# Trusted evidence producers" in text and "runner_policy:" in text  # the rest of the file is untouched
    doc = yaml.safe_load(text)
    assert doc["workflow_repository"] == "acme/security-workflows"
    sast = next(w for w in doc["workflows"] if w["path"] == ".github/workflows/sast.yml")
    assert [s["sha"] for s in sast["approved_shas"]] == [first, second]
    assert sast["approved_shas"][0]["retire_after"] == "2027-05-30" and sast["approved_shas"][1]["retire_after"] is None
    trusted = TrustedWorkflows.from_config(doc)
    assert trusted.approved_ref("scan.sast", [f"acme/security-workflows/.github/workflows/sast.yml@{second}"])
    dast = next(w for w in doc["workflows"] if w["path"] == ".github/workflows/dast.yml")
    assert dast["approved_shas"] == []  # not shipped: never approved by this command
    with pytest.raises(pipelines.PipelineError):
        pipelines.approve("v1.0.0", "v1.0.0", path=cfg)  # a tag is not a commit


def test_caller_renders_the_organizations_values():
    out = pipelines.caller("acme/security-workflows", "3" * 40, "v1.2.0")
    assert "example-org" not in out.split("# Container images")[0] and f"sast.yml@{'3' * 40} # v1.2.0" in out
    yaml.safe_load(out)


def test_summary_fields_and_environment(tmp_path):
    (tmp_path / "verify.json").write_text("[]")
    out = tmp_path / "b"
    rc = tool.main(
        [
            "manifest",
            "--type",
            "deploy.record",
            "--tool-name",
            "gh",
            "--tool-version",
            "2",
            "--result",
            "pass",
            "--artifact-digest",
            "sha256:" + "a" * 64,
            "--environment-name",
            "production",
            "--summary",
            "verified=true",
            "--summary",
            "image_created_at=2026-10-01T00:00:00Z",
            "--out",
            str(out),
            str(tmp_path / "verify.json"),
        ],
        env=gh_env(tmp_path),
    )
    assert rc == 0
    manifest, _ = bundle_files(out)
    assert manifest_errors(manifest) == []
    assert manifest["summary"] == {"verified": True, "image_created_at": "2026-10-01T00:00:00Z"}
    assert manifest["environment"] == {"name": "production"}
    assert (
        tool.main(
            [
                "manifest",
                "--type",
                "deploy.record",
                "--tool-name",
                "gh",
                "--tool-version",
                "2",
                "--summary",
                "Bad Key=1",
                "--out",
                str(tmp_path / "c"),
                str(tmp_path / "verify.json"),
            ],
            env=gh_env(tmp_path),
        )
        == 2
    )
