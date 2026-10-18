# SPDX-License-Identifier: Apache-2.0
"""Build evidence bundles exactly as the `security-workflows` `emit-evidence` action will (pipeline architecture section 5):
a zip holding `evidence-manifest.json` plus the declared raw files, each with its SHA-256 in the manifest."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

WORKFLOW_REPO = "example-org/security-workflows"
DEMO_WORKFLOW_SHA = hashlib.sha1(
    b"example-org/security-workflows@v1.0.0", usedforsecurity=False
).hexdigest()  # DEMO ONLY: registered as trusted by the demo's producer overlay, never in config/

MEDIA = {".sarif": "application/sarif+json", ".json": "application/vnd.cyclonedx+json"}
WORKFLOW_FOR = {
    "scan.sast": "sast",
    "scan.sca": "sca",
    "scan.iac": "iac",
    "sbom": "sbom",
    "scan.workflow_hardening": "workflow-lint",
    "test.security": "test-evidence",
    "scan.dast": "dast",
    "scan.container": "container",
    "scan.api": "api",
}


def workflow_ref(evidence_type: str, sha: str = DEMO_WORKFLOW_SHA) -> str:
    return f"{WORKFLOW_REPO}/.github/workflows/{WORKFLOW_FOR[evidence_type]}.yml@{sha}"


def build(
    *,
    evidence_type: str,
    repo_full_name: str,
    repo_id: int,
    commit_sha: str,
    run_id: int,
    tool: str,
    tool_version: str,
    files: Mapping[str, bytes],
    result: str = "findings",
    ref: str = "refs/heads/main",
    summary: Mapping[str, Any] | None = None,
    produced_at: datetime | None = None,
    runner: str = "github-hosted",
    policy_ref: str | None = None,
    artifact: Mapping[str, str] | None = None,
    tamper: str | None = None,
) -> bytes:
    """`tamper` simulates attacks for tests/demo: 'digest' alters a file after hashing."""
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "predicate_type": "https://cipherfort.github.io/attestra/attestation/evidence/v1",
        "evidence_type": evidence_type,
        "repository": {"full_name": repo_full_name, "id": repo_id, "visibility": "private"},
        "commit_sha": commit_sha,
        "ref": ref,
        "run": {
            "id": run_id,
            "attempt": 1,
            "workflow_ref": f"{repo_full_name}/.github/workflows/aap-security.yml@{ref}",
            "job_workflow_ref": workflow_ref(evidence_type),
            "event": "push",
            "runner_environment": runner,
        },
        "tool": {"name": tool, "version": tool_version, **({"policy_ref": policy_ref} if policy_ref else {})},
        "result": result,
        "files": [
            {
                "path": p,
                "sha256": hashlib.sha256(d).hexdigest(),
                "media_type": next((m for ext, m in MEDIA.items() if p.endswith(ext)), "application/json"),
                "size_bytes": len(d),
            }
            for p, d in files.items()
        ],
        "produced_at": (produced_at or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if summary:
        manifest["summary"] = dict(summary)
    if artifact:
        manifest["artifact"] = dict(artifact)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence-manifest.json", json.dumps(manifest, indent=2))
        for p, d in files.items():
            zf.writestr(p, d + (b" " if tamper == "digest" else b""))
    return buf.getvalue()


def sarif(tool: str, version: str, results: list[dict[str, Any]]) -> bytes:
    rules = {r["rule"]: r for r in results}
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "semanticVersion": version,
                        "rules": [
                            {
                                "id": rid,
                                "shortDescription": {"text": r["message"]},
                                "properties": {
                                    "security-severity": str(r["score"]),
                                    "tags": ["security", f"external/cwe/cwe-{r['cwe']:03d}"],
                                },
                            }
                            for rid, r in rules.items()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": r["rule"],
                        "level": "error",
                        "message": {"text": r["message"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": r["file"]},
                                    "region": {"startLine": r["line"]},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": r["fp"]},
                    }
                    for r in results
                ],
            }
        ],
    }
    return json.dumps(doc).encode()


def cyclonedx(components: list[tuple[str, str, str, str]]) -> bytes:
    """components: (name, version, purl, licence)"""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {"timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "tools": [{"name": "cdxgen"}]},
            "components": [
                {"type": "library", "name": n, "version": v, "purl": p, "licenses": [{"license": {"id": lic}}]}
                for n, v, p, lic in components
            ],
        }
    ).encode()
