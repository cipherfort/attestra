# SPDX-License-Identifier: Apache-2.0
"""Sigstore verification against a real, public GitHub attestation (fixtures/attestations/README.md). Offline."""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from sigstore.models import Bundle

from aap.connectors.attestation import (
    AttestationVerifier,
    GhCliBackend,
    bundles_from_listing,
    decode_bundle,
    load_trusted_roots,
    predicate_type_of,
    signer_claims,
)
from aap.domain.evidence import AttestationCheck, Limits, RunInfo, TrustedWorkflows, verify_bundle

FIX = Path(__file__).parent.parent / "fixtures" / "attestations"
BUNDLE = (FIX / "gh-cli-v2.102.0-provenance.sigstore.json").read_bytes()
SUBJECT = "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386"  # gh_2.102.0_linux_amd64.tar.gz
SIGNER = "cli/cli/.github/workflows/deployment.yml@fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"


@pytest.fixture(scope="module")
def verifier() -> AttestationVerifier:
    return AttestationVerifier(load_trusted_roots(FIX / "trusted_root.jsonl"))


def test_real_bundle_verifies_and_yields_signer_runner_and_commit(verifier):
    check = verifier.verify(BUNDLE, SUBJECT, "cli/cli")
    assert check.verified, check.detail
    assert check.signer_workflow == SIGNER
    assert check.runner_environment == "github-hosted"
    assert check.source_digest == "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"


def test_wrong_source_repository_is_rejected(verifier):
    check = verifier.verify(BUNDLE, SUBJECT, "attacker/cli")
    assert not check.verified and "verification failed" in check.detail


def test_digest_not_in_subjects_is_rejected(verifier):
    check = verifier.verify(BUNDLE, "0" * 64, "cli/cli")
    assert not check.verified and "subject" in check.detail


def test_tampered_payload_fails_signature(verifier):
    b = json.loads(BUNDLE)
    stmt = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
    stmt["subject"].append({"name": "evil", "digest": {"sha256": "f" * 64}})
    b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
    check = verifier.verify(json.dumps(b).encode(), "f" * 64, "cli/cli")
    assert not check.verified


def test_github_instance_bundle_without_gh_backend_is_fail_closed(verifier):
    b = json.loads(BUNDLE)
    b["verificationMaterial"].pop("tlogEntries")
    check = verifier.verify(json.dumps(b).encode(), SUBJECT, "cli/cli")
    assert not check.verified and "no gh verifier" in check.detail


def test_gh_backend_parses_real_output_and_checks_subject_bytes():
    out = json.loads((FIX / "gh-attestation-verify-output.json").read_text())

    class StubGh(GhCliBackend):
        def verify(self, bundle_json, subject, source_repository):
            assert subject == b"manifest-bytes" and source_repository == "cli/cli"
            return out[0]["verificationResult"]["signature"]["certificate"]

    v = AttestationVerifier([], gh_backend=StubGh("gh", "root.jsonl"))
    b = json.loads(BUNDLE)
    b["verificationMaterial"]["tlogEntries"] = []
    digest = hashlib.sha256(b"manifest-bytes").hexdigest()
    check = v.verify(json.dumps(b).encode(), digest, "cli/cli", b"manifest-bytes")
    assert check.verified and check.signer_workflow == SIGNER and check.runner_environment == "github-hosted"
    wrong = v.verify(json.dumps(b).encode(), "0" * 64, "cli/cli", b"manifest-bytes")
    assert not wrong.verified and "do not match" in wrong.detail


@pytest.mark.skipif(
    not shutil.which("gh") or not os.environ.get("AAP_TEST_GH_ARTIFACT"),
    reason="set AAP_TEST_GH_ARTIFACT to gh_2.102.0_linux_amd64.tar.gz to run the real gh backend",
)
def test_gh_backend_real_binary_offline():
    artifact = Path(os.environ["AAP_TEST_GH_ARTIFACT"]).read_bytes()
    backend = GhCliBackend(shutil.which("gh"), str(FIX / "trusted_root.jsonl"))
    cert = backend.verify(
        BUNDLE, artifact, "cli/cli"
    )  # the untouched bundle: gh verifies it like a GitHub-instance one
    assert cert["buildSignerDigest"] == "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"
    with pytest.raises(ValueError):
        backend.verify(BUNDLE, artifact + b"x", "cli/cli")
    with pytest.raises(ValueError):
        backend.verify(BUNDLE, artifact, "attacker/cli")


def test_garbage_is_fail_closed(verifier):
    assert not verifier.verify(b"{not json", SUBJECT, "cli/cli").verified
    assert not verifier.verify(b'{"mediaType": "x"}', SUBJECT, "cli/cli").verified


def test_verify_any_semantics(verifier):
    assert verifier.verify_any([], SUBJECT, "cli/cli") is None  # no attestation → C2, not an error
    bad_then_good = verifier.verify_any([b"{}", BUNDLE], SUBJECT, "cli/cli")
    assert bad_then_good is not None and bad_then_good.verified
    only_bad = verifier.verify_any([b"{}"], SUBJECT, "cli/cli")
    assert only_bad is not None and not only_bad.verified


def test_snappy_bundle_url_is_decoded():
    raw = decode_bundle((FIX / "gh-cli-v2.102.0-release.sigstore.json.sn").read_bytes())
    assert json.loads(raw)["mediaType"].startswith("application/vnd.dev.sigstore.bundle")
    listing = {"attestations": [{"bundle": None, "bundle_url": "https://example.invalid/b.sn"}]}
    out = bundles_from_listing(listing, lambda url: (FIX / "gh-cli-v2.102.0-release.sigstore.json.sn").read_bytes())
    assert out == [raw]


def test_snappy_bomb_refused_before_decompression():
    # varint preamble declaring 100 MB
    with pytest.raises(ValueError, match="declares"):
        decode_bundle(bytes([0x80, 0x80, 0x80, 0x30]) + b"\x00" * 10)


def test_non_https_bundle_url_ignored():
    assert bundles_from_listing({"attestations": [{"bundle_url": "http://x/b"}]}, lambda u: b"") == []


def test_claims_from_certificate():
    claims = signer_claims(Bundle.from_json(BUNDLE).signing_certificate)
    assert claims.issuer == "https://token.actions.githubusercontent.com"
    assert claims.source_repository_uri == "https://github.com/cli/cli"


# ---------------------------------------------------------------- the attestation feeds verify_bundle (C3 rules)

TRUSTED = TrustedWorkflows(
    "cli/cli",
    {".github/workflows/deployment.yml": {"shas": {"fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"}, "types": {"sbom"}}},
    {"github-hosted": "C3", "self-hosted": "C2"},
)


def _manifest(runner: str = "github-hosted") -> tuple[dict, dict, RunInfo]:
    files = {"sbom.json": b"{}"}
    import hashlib

    manifest = {
        "evidence_type": "sbom",
        "commit_sha": "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd",
        "repository": {"id": 212613049},
        "run": {"id": 1, "attempt": 1, "runner_environment": runner},
        "files": [{"path": "sbom.json", "sha256": hashlib.sha256(b"{}").hexdigest()}],
    }
    run = RunInfo(1, 1, 212613049, "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd", "push", "success", (SIGNER,))
    return manifest, files, run


def test_c3_when_attested_by_approved_workflow(verifier):
    manifest, files, run = _manifest()
    check = verifier.verify(BUNDLE, SUBJECT, "cli/cli")
    v = verify_bundle(manifest, files, run, check, TRUSTED, (), Limits())
    assert v.accepted and v.confidence == "C3" and "attestation_verified" in v.confidence_reasons


def test_attested_commit_must_match_run():
    manifest, files, _ = _manifest()
    other = RunInfo(1, 1, 212613049, "a" * 40, "push", "success", (SIGNER,))
    manifest["commit_sha"] = "a" * 40
    check = AttestationCheck(True, SIGNER, "ok", "github-hosted", "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd")
    v = verify_bundle(manifest, files, other, check, TRUSTED, (), Limits())
    assert not v.accepted and v.reason.value == "ATTESTATION_INVALID"


def test_certificate_runner_overrides_manifest_claim():
    manifest, files, run = _manifest(runner="github-hosted")  # manifest lies
    check = AttestationCheck(True, SIGNER, "ok", "self-hosted", run.head_sha)
    v = verify_bundle(manifest, files, run, check, TRUSTED, (), Limits())
    assert v.accepted and v.confidence == "C2" and "capped_C2_runner_self-hosted" in v.confidence_reasons


# ---------------------------------------------------------------- the shipped workflows' own attestation (real run)

E2E = "cipherfort/fortproof-e2e-app"
E2E_BUNDLE = (FIX / "fortproof-e2e-sca-evidence.sigstore.json").read_bytes()
E2E_MANIFEST = (FIX / "fortproof-e2e-sca-evidence-manifest.json").read_bytes()
E2E_SIGNER = (
    "cipherfort/fortproof-security-workflows/.github/workflows/sca.yml@fdfe5ba2e5c28b9bed2de0801e85e23f0f80365f"
)


def test_shipped_workflow_evidence_attestation_verifies(verifier):
    """The shipped sca.yml signs the manifest with the FortProof evidence predicate; that must verify (it used to be
    refused as "not SLSA provenance", turning every signed bundle into a rejection)."""
    assert predicate_type_of(E2E_BUNDLE) == "https://fortproof.dev/attestation/evidence/v1"
    check = verifier.verify(E2E_BUNDLE, hashlib.sha256(E2E_MANIFEST).hexdigest(), E2E)
    assert check.verified, check.detail
    assert check.signer_workflow == E2E_SIGNER
    assert check.source_digest == json.loads(E2E_MANIFEST)["commit_sha"]


def test_shipped_workflow_evidence_reaches_c3(verifier):
    manifest = json.loads(E2E_MANIFEST)
    files = {"osv.sarif": (FIX / "fortproof-e2e-sca-osv.sarif").read_bytes()}
    run = RunInfo(
        manifest["run"]["id"], 1, manifest["repository"]["id"], manifest["commit_sha"], "push", "success", (E2E_SIGNER,)
    )
    trusted = TrustedWorkflows(
        "cipherfort/fortproof-security-workflows",
        {".github/workflows/sca.yml": {"shas": {"fdfe5ba2e5c28b9bed2de0801e85e23f0f80365f"}, "types": {"scan.sca"}}},
        {"github-hosted": "C3", "self-hosted": "C2"},
    )
    check = verifier.verify(E2E_BUNDLE, hashlib.sha256(E2E_MANIFEST).hexdigest(), E2E)
    v = verify_bundle(manifest, files, run, check, trusted, (), Limits())
    assert v.accepted and v.confidence == "C3" and "attestation_verified" in v.confidence_reasons, v
