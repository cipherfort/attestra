# SPDX-License-Identifier: Apache-2.0
"""Evidence verification (abuse cases AC-01, AC-02, AC-07; evidence model section 4) and hash-chain tamper detection."""

import hashlib

import pytest

from aap.domain.evidence import (
    AttestationCheck,
    CanonicalisationError,
    Limits,
    RejectReason,
    RunInfo,
    TrustedWorkflows,
    canonical_json,
    meets,
    record_hash,
    verify_bundle,
    verify_chain,
)

APPROVED = "a" * 40
REPO = "example-org/security-workflows"
SARIF = b'{"version":"2.1.0","runs":[]}'


def trusted(runner_caps=None):
    return TrustedWorkflows.from_config(
        {
            "workflow_repository": REPO,
            "workflows": [
                {
                    "path": ".github/workflows/sast.yml",
                    "evidence_types": ["scan.sast"],
                    "approved_shas": [{"sha": APPROVED, "release": "v1.0.0"}],
                }
            ],
            "runner_policy": runner_caps or {"github-hosted": "C3", "self-hosted": "C2"},
        }
    )


def manifest(**over):
    m = {
        "schema_version": "1.0",
        "predicate_type": "https://fortproof.dev/attestation/evidence/v1",
        "evidence_type": "scan.sast",
        "repository": {"full_name": "org/claims-api", "id": 42},
        "commit_sha": "3" * 40,
        "ref": "refs/heads/main",
        "run": {
            "id": 1001,
            "attempt": 1,
            "workflow_ref": "org/claims-api/.github/workflows/aap-security.yml@refs/heads/main",
            "job_workflow_ref": f"{REPO}/.github/workflows/sast.yml@{APPROVED}",
            "event": "push",
            "runner_environment": "github-hosted",
        },
        "tool": {"name": "codeql", "version": "2.19.1"},
        "result": "findings",
        "files": [
            {
                "path": "results.sarif",
                "sha256": hashlib.sha256(SARIF).hexdigest(),
                "media_type": "application/sarif+json",
            }
        ],
        "produced_at": "2026-10-07T10:00:00Z",
    }
    m.update(over)
    return m


def run(refs=(f"{REPO}/.github/workflows/sast.yml@{APPROVED}",), **over):
    base = dict(
        run_id=1001,
        run_attempt=1,
        repository_id=42,
        head_sha="3" * 40,
        event="push",
        conclusion="success",
        referenced_workflows=tuple(refs),
    )
    base.update(over)
    return RunInfo(**base)


def test_valid_bundle_with_attestation_is_c3():
    v = verify_bundle(
        manifest(),
        {"results.sarif": SARIF},
        run(),
        AttestationCheck(True, f"{REPO}/.github/workflows/sast.yml@{APPROVED}"),
        trusted(),
    )
    assert v.accepted and v.confidence == "C3"
    assert "attestation_verified" in v.confidence_reasons


def test_valid_bundle_without_attestation_is_c2():
    v = verify_bundle(manifest(), {"results.sarif": SARIF}, run(), None, trusted())
    assert v.accepted and v.confidence == "C2"


def test_ac01_handcrafted_manifest_from_own_workflow_rejected():
    v = verify_bundle(
        manifest(),
        {"results.sarif": SARIF},
        run(refs=("org/claims-api/.github/workflows/my-fake-scan.yml@" + "b" * 40,)),
        None,
        trusted(),
    )
    assert not v.accepted and v.reason is RejectReason.UNTRUSTED_PRODUCER


def test_ac02_approved_path_at_unapproved_sha_rejected():
    v = verify_bundle(
        manifest(),
        {"results.sarif": SARIF},
        run(refs=(f"{REPO}/.github/workflows/sast.yml@{'c' * 40}",)),
        None,
        trusted(),
    )
    assert not v.accepted and v.reason is RejectReason.UNAPPROVED_WORKFLOW_REF


def test_workflow_approved_for_another_evidence_type_is_untrusted():
    v = verify_bundle(manifest(evidence_type="sbom"), {"results.sarif": SARIF}, run(), None, trusted())
    assert v.reason is RejectReason.UNTRUSTED_PRODUCER


def test_tampered_file_rejected():
    v = verify_bundle(manifest(), {"results.sarif": SARIF + b" "}, run(), None, trusted())
    assert v.reason is RejectReason.DIGEST_MISMATCH


def test_undeclared_extra_file_rejected():
    v = verify_bundle(manifest(), {"results.sarif": SARIF, "extra.json": b"{}"}, run(), None, trusted())
    assert v.reason is RejectReason.DIGEST_MISMATCH


def test_manifest_for_a_different_commit_rejected():
    v = verify_bundle(manifest(commit_sha="4" * 40), {"results.sarif": SARIF}, run(), None, trusted())
    assert v.reason is RejectReason.BINDING_MISMATCH


def test_cancelled_run_rejected():
    v = verify_bundle(manifest(), {"results.sarif": SARIF}, run(conclusion="cancelled"), None, trusted())
    assert v.reason is RejectReason.BINDING_MISMATCH


def test_attestation_signed_by_other_workflow_rejected():
    v = verify_bundle(
        manifest(),
        {"results.sarif": SARIF},
        run(),
        AttestationCheck(True, "org/claims-api/.github/workflows/evil.yml@x"),
        trusted(),
    )
    assert v.reason is RejectReason.ATTESTATION_INVALID


def test_ac07_oversized_artifact_rejected_before_hashing():
    v = verify_bundle(
        manifest(), {"results.sarif": b"x" * 2048}, run(), None, trusted(), limits=Limits(max_file_bytes=1024)
    )
    assert v.reason is RejectReason.REJECTED_SIZE


def test_persistent_self_hosted_runner_caps_confidence():
    m = manifest()
    m["run"]["runner_environment"] = "self-hosted"
    v = verify_bundle(
        m,
        {"results.sarif": SARIF},
        run(),
        AttestationCheck(True, f"{REPO}/.github/workflows/sast.yml@{APPROVED}"),
        trusted(),
    )
    assert v.accepted and v.confidence == "C2" and "capped_C2_runner_self-hosted" in v.confidence_reasons


def test_schema_errors_reject():
    v = verify_bundle(manifest(), {"results.sarif": SARIF}, run(), None, trusted(), schema_errors=["missing tool"])
    assert v.reason is RejectReason.SCHEMA_INVALID


def test_no_released_workflows_means_everything_rejected(bundle):
    """The real config has no release SHAs yet, so no pipeline evidence can be accepted (correct behaviour)."""
    real = TrustedWorkflows.from_config(bundle.doc("trusted_producers"))
    v = verify_bundle(manifest(), {"results.sarif": SARIF}, run(), None, real)
    assert v.reason is RejectReason.UNAPPROVED_WORKFLOW_REF


def test_confidence_kinds_do_not_mix():
    assert meets("C3", "C2") and not meets("C1", "C2")
    assert meets("M2", "M1") and not meets("M2", "C1") and not meets("C3", "M1")


def test_hash_chain_detects_tampering():
    records = [{"evidence_id": f"e{i}", "result": "pass", "n": i} for i in range(5)]
    chain, prev = [], None
    for r in records:
        h = record_hash(prev, r)
        chain.append((r, h, prev))
        prev = h
    assert verify_chain(chain) is None
    tampered = [(dict(r), h, p) for r, h, p in chain]
    tampered[2][0]["result"] = "fail"  # a superuser rewrites one record
    assert verify_chain(tampered) == 2
    deleted = chain[:2] + chain[3:]  # or silently deletes one
    assert verify_chain(deleted) == 2


def test_canonical_json_is_order_independent_and_rejects_floats():
    assert (
        canonical_json({"b": 1, "a": [True, None]})
        == canonical_json({"a": [True, None], "b": 1})
        == b'{"a":[true,null],"b":1}'
    )
    with pytest.raises(CanonicalisationError):
        canonical_json({"score": 9.8})
