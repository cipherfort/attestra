# SPDX-License-Identifier: Apache-2.0
"""Evidence verification and tamper-evident hashing (evidence model section 4 and section 6, ADR-016).

`verify_bundle` is the gate between a pipeline and the evidence ledger. Everything in a manifest is untrusted
until checked against what GitHub reports about the run and against the trusted-producer registry. A forged
manifest from a team's own workflow, an approved workflow at an unapproved commit, or files that do not match
their digests are all rejected with a reason code.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any

AUTOMATED_ORDER = ("C0", "C1", "C2", "C3")
MANUAL_ORDER = ("M1", "M2")


class RejectReason(StrEnum):
    UNTRUSTED_PRODUCER = "UNTRUSTED_PRODUCER"
    UNAPPROVED_WORKFLOW_REF = "UNAPPROVED_WORKFLOW_REF"
    ATTESTATION_INVALID = "ATTESTATION_INVALID"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    REJECTED_SIZE = "REJECTED_SIZE"
    SCHEMA_INVALID = "SCHEMA_INVALID"


# ---------------------------------------------------------------------------- canonical hashing


class CanonicalisationError(ValueError):
    pass


def _canonical_value(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {str(k): _canonical_value(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_canonical_value(x) for x in v]
    if isinstance(v, bool) or v is None or isinstance(v, int | str):
        return v
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, float):
        # JCS number serialisation differs from Python's for some floats; hashed records must not carry them.
        raise CanonicalisationError("floats are not allowed in hashed records; store them as strings")
    raise CanonicalisationError(f"cannot canonicalise {type(v).__name__}")


def canonical_json(record: Mapping[str, Any]) -> bytes:
    """RFC 8785 (JCS) for the value space hashed records use: no floats, keys compared as ASCII-safe strings."""
    return json.dumps(_canonical_value(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_hash(prev_hash: bytes | None, record: Mapping[str, Any]) -> bytes:
    """SHA-256(prev_hash ‖ JCS(record)). The first record in a chain uses 32 zero bytes as prev."""
    h = hashlib.sha256()
    h.update(prev_hash or b"\x00" * 32)
    h.update(canonical_json(record))
    return h.digest()


def verify_chain(records: Sequence[tuple[Mapping[str, Any], bytes, bytes | None]]) -> int | None:
    """Records as (hashed fields, stored record_hash, stored prev_hash) in chain order.
    Returns the index of the first broken link, or None if the chain is intact."""
    prev: bytes | None = None
    for i, (fields, stored, stored_prev) in enumerate(records):
        if stored_prev != prev or record_hash(prev, fields) != stored:
            return i
        prev = stored
    return None


# ---------------------------------------------------------------------------- confidence


def confidence_rank(level: str) -> tuple[str, int]:
    if level in AUTOMATED_ORDER:
        return "automated", AUTOMATED_ORDER.index(level)
    if level in MANUAL_ORDER:
        return "manual", MANUAL_ORDER.index(level)
    raise ValueError(f"unknown confidence {level!r}")


def meets(actual: str, required: str) -> bool:
    """C-levels satisfy only C requirements, M-levels only M requirements (manual ≠ automated)."""
    a_kind, a = confidence_rank(actual)
    r_kind, r = confidence_rank(required)
    return a_kind == r_kind and a >= r


def cap(level: str, ceiling: str) -> str:
    return level if confidence_rank(level)[1] <= confidence_rank(ceiling)[1] else ceiling


# ---------------------------------------------------------------------------- verification


@dataclass(frozen=True)
class RunInfo:
    """What GitHub (not the manifest) says about the workflow run. Fetched by the platform's GitHub App."""

    run_id: int
    run_attempt: int
    repository_id: int
    head_sha: str
    event: str
    conclusion: str | None
    referenced_workflows: tuple[str, ...]  # "owner/repo/.github/workflows/x.yml@<sha>"


@dataclass(frozen=True)
class AttestationCheck:
    """Result of verifying the Sigstore attestation over the manifest (done by the GitHub connector)."""

    verified: bool
    signer_workflow: str | None = None  # Build Signer URI: owner/repo/.github/workflows/x.yml@<sha>
    detail: str = ""
    runner_environment: str | None = None  # from the signing certificate: authoritative, unlike the manifest
    source_digest: str | None = None  # commit the attested run built


@dataclass(frozen=True)
class TrustedWorkflows:
    repository: str
    approved: dict[str, dict[str, set[str]]]  # path → {"shas": {...}, "types": {...}}
    runner_caps: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> TrustedWorkflows:
        approved: dict[str, dict[str, set[str]]] = {}
        for wf in cfg["workflows"]:
            shas = {
                (s["sha"] if isinstance(s, Mapping) else str(s))
                for s in wf.get("approved_shas") or []
                if not (isinstance(s, Mapping) and s.get("revoked_at"))
            }
            approved[wf["path"]] = {"shas": shas, "types": set(wf["evidence_types"])}
        return cls(cfg["workflow_repository"], approved, dict(cfg.get("runner_policy", {})))

    def approved_ref(self, evidence_type: str, refs: Sequence[str]) -> str | None:
        for ref in refs:
            path, _, sha = ref.partition("@")
            prefix = f"{self.repository}/"
            if not path.startswith(prefix):
                continue
            entry = self.approved.get(path[len(prefix) :])
            if entry and evidence_type in entry["types"] and sha in entry["shas"]:
                return ref
        return None

    def known_path(self, evidence_type: str, refs: Sequence[str]) -> bool:
        prefix = f"{self.repository}/"
        return any(
            ref.partition("@")[0].startswith(prefix)
            and evidence_type in self.approved.get(ref.partition("@")[0][len(prefix) :], {}).get("types", set())
            for ref in refs
        )


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 200 * 1024 * 1024
    max_total_bytes: int = 500 * 1024 * 1024
    max_files: int = 50


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: RejectReason | None
    confidence: str | None
    confidence_reasons: tuple[str, ...]
    detail: str
    producer_ref: str | None = None


def _reject(reason: RejectReason, detail: str) -> Verdict:
    return Verdict(False, reason, None, (), detail)


def verify_bundle(
    manifest: Mapping[str, Any],
    files: Mapping[str, bytes],
    run: RunInfo,
    attestation: AttestationCheck | None,
    trusted: TrustedWorkflows,
    schema_errors: Sequence[str] = (),
    limits: Limits | None = None,
) -> Verdict:
    """Steps 1–6 of evidence model section 4. `schema_errors` come from validating the manifest against its schema."""
    limits = limits or Limits()
    if schema_errors:
        return _reject(RejectReason.SCHEMA_INVALID, "; ".join(schema_errors[:5]))

    # limits first: never hash or parse oversized input
    sizes = [len(b) for b in files.values()]
    if (
        len(files) > limits.max_files
        or any(s > limits.max_file_bytes for s in sizes)
        or sum(sizes) > limits.max_total_bytes
    ):
        return _reject(RejectReason.REJECTED_SIZE, f"{len(files)} files, {sum(sizes)} bytes")

    etype = manifest["evidence_type"]
    # 1. the run must have completed (a failed scan step is still evidence; a cancelled run is not)
    if run.conclusion not in ("success", "failure"):
        return _reject(RejectReason.BINDING_MISMATCH, f"run conclusion {run.conclusion!r}")

    # 2. the caller must have used an approved reusable workflow at an approved commit
    approved = trusted.approved_ref(etype, run.referenced_workflows)
    if approved is None:
        if trusted.known_path(etype, run.referenced_workflows):
            return _reject(
                RejectReason.UNAPPROVED_WORKFLOW_REF, f"{etype} produced by an unapproved commit of the workflow"
            )
        return _reject(
            RejectReason.UNTRUSTED_PRODUCER, f"no approved producer for {etype} among {list(run.referenced_workflows)}"
        )

    # 5. binding: the manifest must describe this run, this repository, this commit
    if manifest["commit_sha"] != run.head_sha or manifest["repository"]["id"] != run.repository_id:
        return _reject(RejectReason.BINDING_MISMATCH, "manifest commit or repository differs from the workflow run")
    if manifest["run"]["id"] != run.run_id or manifest["run"]["attempt"] != run.run_attempt:
        return _reject(RejectReason.BINDING_MISMATCH, "manifest run id/attempt differs from the workflow run")

    # 4. integrity: every declared file present and hash-matched; nothing undeclared
    declared = {f["path"]: f["sha256"] for f in manifest["files"]}
    if set(declared) != set(files):
        return _reject(RejectReason.DIGEST_MISMATCH, "files present differ from files declared in the manifest")
    for path, expected in declared.items():
        if hashlib.sha256(files[path]).hexdigest() != expected:
            return _reject(RejectReason.DIGEST_MISMATCH, f"sha256 mismatch for {path}")

    # 3. attestation (when available on the org; assumption A-05)
    reasons = ["approved_workflow_verified"]
    confidence = "C2"
    if attestation is not None:
        if not attestation.verified or attestation.signer_workflow != approved:
            return _reject(
                RejectReason.ATTESTATION_INVALID, attestation.detail or "signer is not the approved workflow"
            )
        if attestation.source_digest is not None and attestation.source_digest != run.head_sha:
            return _reject(RejectReason.ATTESTATION_INVALID, "attested source commit differs from the workflow run")
        reasons.append("attestation_verified")
        confidence = "C3"

    # the certificate's runner claim outranks the manifest's self-declared one
    attested_runner = attestation.runner_environment if attestation else None
    runner = attested_runner or manifest["run"]["runner_environment"]
    ceiling = trusted.runner_caps.get(runner, "C2")
    if confidence_rank(confidence)[1] > confidence_rank(ceiling)[1]:
        reasons.append(f"capped_{ceiling}_runner_{runner}")
        confidence = cap(confidence, ceiling)
    else:
        reasons.append(f"runner_{runner}")
    return Verdict(True, None, confidence, tuple(reasons), "verified", producer_ref=approved)
