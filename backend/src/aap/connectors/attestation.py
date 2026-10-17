# SPDX-License-Identifier: Apache-2.0
"""Sigstore verification of GitHub artifact attestations (ADR-030, evidence model section 4 step 3).

A security-workflows release attests the evidence manifest with `actions/attest-build-provenance`. The platform:

1. lists attestations for the manifest's sha256 (`GET /repos/{repo}/attestations/sha256:{digest}`), reading an inline
   `bundle` or the snappy-compressed `bundle_url` GitHub now serves;
2. verifies each bundle against the trust roots from `gh attestation trusted-root`, requiring the GitHub Actions OIDC
   issuer and the application's own repository as the source:
   * Sigstore public-good bundles (public repositories; Rekor-logged) in-process with sigstore-python;
   * GitHub-instance bundles (private/internal repositories, GitHub Enterprise Cloud only; timestamp-only, which
     sigstore-python cannot model) with `gh attestation verify` offline (sigstore-go), see GhCliBackend;
3. checks the in-toto subject list contains the manifest digest; and
4. returns the signer workflow (`owner/repo/path@<signer digest>`), the runner environment and the source commit read
   from the Fulcio certificate. `verify_bundle` then requires that signer to be the approved workflow at an approved
   SHA and the source commit to be the run's commit.

Everything is fail-closed: any parsing or verification error yields `verified=False` with a reason, never C3.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cramjam
from cryptography import x509
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier, policy

from aap.domain.evidence import AttestationCheck

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
MAX_BUNDLE_BYTES = 256 * 1024  # a provenance bundle is ~5 KB; anything near this is hostile

# Fulcio certificate extensions (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
_OID = {
    "issuer": "1.3.6.1.4.1.57264.1.8",
    "signer_uri": "1.3.6.1.4.1.57264.1.9",
    "signer_digest": "1.3.6.1.4.1.57264.1.10",
    "runner_environment": "1.3.6.1.4.1.57264.1.11",
    "source_repository_uri": "1.3.6.1.4.1.57264.1.12",
    "source_digest": "1.3.6.1.4.1.57264.1.13",
    "source_ref": "1.3.6.1.4.1.57264.1.14",
    "run_invocation_uri": "1.3.6.1.4.1.57264.1.21",
}


@dataclass(frozen=True)
class SignerClaims:
    issuer: str | None
    signer_uri: str | None
    signer_digest: str | None
    runner_environment: str | None
    source_repository_uri: str | None
    source_digest: str | None
    source_ref: str | None
    run_invocation_uri: str | None

    def signer_workflow(self, host: str = "github.com") -> str | None:
        """`https://github.com/o/r/.github/workflows/x.yml@refs/tags/v1` + digest
        → `o/r/.github/workflows/x.yml@<digest>` (the form trusted-producers approves)."""
        if not self.signer_uri or not self.signer_digest:
            return None
        prefix = f"https://{host}/"
        if not self.signer_uri.startswith(prefix):
            return None
        path = self.signer_uri[len(prefix) :].partition("@")[0]
        return f"{path}@{self.signer_digest}"


def _der_utf8(raw: bytes) -> str:
    # v2 extensions are DER UTF8String (tag 0x0c + length); v1 extensions are raw bytes.
    if len(raw) >= 2 and raw[0] == 0x0C:
        n, i = raw[1], 2
        if n & 0x80:
            k = n & 0x7F
            n, i = int.from_bytes(raw[2 : 2 + k], "big"), 2 + k
        return raw[i : i + n].decode()
    return raw.decode()


def signer_claims(cert: x509.Certificate) -> SignerClaims:
    found: dict[str, str] = {}
    by_oid = {v: k for k, v in _OID.items()}
    for ext in cert.extensions:
        key = by_oid.get(ext.oid.dotted_string)
        if key is not None and isinstance(ext.value, x509.UnrecognizedExtension):
            found[key] = _der_utf8(ext.value.value)
    return SignerClaims(**{k: found.get(k) for k in _OID})


def load_trusted_roots(path: str | Path) -> list[TrustedRoot]:
    """Trust roots from a `gh attestation trusted-root` JSONL file that sigstore-python can use in-process.

    GitHub's own instance has no transparency logs; sigstore-python cannot model it, so it is skipped here and used by
    the `gh` backend from the same file (see GhCliBackend)."""
    roots: list[TrustedRoot] = []
    with tempfile.TemporaryDirectory() as d:  # TrustedRoot only loads from a path
        for i, line in enumerate(Path(path).read_text().splitlines()):
            if not line.strip():
                continue
            one = Path(d) / f"root{i}.json"
            one.write_text(line)
            try:
                roots.append(TrustedRoot.from_file(str(one)))
            except Exception:  # noqa: S112 - a root without tlogs (GitHub instance): the gh backend handles it
                continue
    return roots


@dataclass(frozen=True)
class GhCliBackend:
    """`gh attestation verify` (sigstore-go), offline: artifact file + bundle file + custom trusted root.

    Runs with an empty config directory and no token, so it cannot reach GitHub or use anyone's credentials.
    The binary is pinned in the container image (the Dockerfile) and its version recorded in the evidence."""

    gh: str
    trusted_root_file: str
    timeout: float = 30.0

    def verify(self, bundle_json: bytes, subject: bytes, source_repository: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as d:
            art, bun, cfg = Path(d) / "subject", Path(d) / "bundle.json", Path(d) / "gh"
            art.write_bytes(subject)
            bun.write_bytes(bundle_json)
            cfg.mkdir()
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, inputs are file paths we created
                [
                    self.gh,
                    "attestation",
                    "verify",
                    str(art),
                    "--bundle",
                    str(bun),
                    "--custom-trusted-root",
                    self.trusted_root_file,
                    "--repo",
                    source_repository,
                    "--predicate-type",
                    PROVENANCE_V1,
                    "--format",
                    "json",
                ],
                capture_output=True,
                timeout=self.timeout,
                env={
                    "PATH": "/usr/bin:/bin",
                    "GH_CONFIG_DIR": str(cfg),
                    "HOME": d,
                    "GH_PROMPT_DISABLED": "1",
                    "GH_NO_UPDATE_NOTIFIER": "1",
                },
                check=False,
            )
        if proc.returncode != 0:
            raise ValueError(proc.stderr.decode(errors="replace").strip()[-300:] or f"gh exited {proc.returncode}")
        results = json.loads(proc.stdout)
        return dict(results[0]["verificationResult"]["signature"]["certificate"])


def claims_from_gh(cert: dict[str, Any]) -> SignerClaims:
    return SignerClaims(
        issuer=cert.get("issuer"),
        signer_uri=cert.get("buildSignerURI"),
        signer_digest=cert.get("buildSignerDigest"),
        runner_environment=cert.get("runnerEnvironment"),
        source_repository_uri=cert.get("sourceRepositoryURI"),
        source_digest=cert.get("sourceRepositoryDigest"),
        source_ref=cert.get("sourceRepositoryRef"),
        run_invocation_uri=cert.get("runInvocationURI"),
    )


def decode_bundle(raw: bytes) -> bytes:
    """GitHub serves `bundle_url` as raw (block) snappy; inline bundles are plain JSON."""
    if raw[:1] == b"{":
        data = raw
    else:
        declared, shift, i = 0, 0, 0
        while i < len(raw) and i < 5:  # snappy preamble: uncompressed length as a varint
            b = raw[i]
            declared |= (b & 0x7F) << shift
            i += 1
            if not b & 0x80:
                break
            shift += 7
        if declared > MAX_BUNDLE_BYTES:
            raise ValueError(f"bundle declares {declared} bytes (limit {MAX_BUNDLE_BYTES})")
        data = bytes(cramjam.snappy.decompress_raw(raw))
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle too large")
    return data


class AttestationVerifier:
    def __init__(
        self,
        trusted_roots: Sequence[TrustedRoot],
        github_host: str = "github.com",
        gh_backend: GhCliBackend | None = None,
    ):
        if not trusted_roots and gh_backend is None:
            raise ValueError("at least one trusted root or the gh backend is required")
        self._verifiers = [Verifier(trusted_root=r) for r in trusted_roots]
        self._host = github_host
        self._gh = gh_backend

    @classmethod
    def from_trust_root_file(
        cls, path: str, gh: str | None = None, github_host: str = "github.com"
    ) -> AttestationVerifier:
        return cls(load_trusted_roots(path), github_host, GhCliBackend(gh, path) if gh else None)

    def verify(
        self, bundle_json: bytes, subject_sha256: str, source_repository: str, subject: bytes | None = None
    ) -> AttestationCheck:
        """Verify one bundle for `subject_sha256`, produced by a workflow run in `source_repository` (owner/name).
        `subject` (the attested bytes) is needed only for GitHub-instance bundles (gh backend)."""
        try:
            has_tlog = bool(json.loads(bundle_json)["verificationMaterial"].get("tlogEntries"))
        except (ValueError, KeyError, TypeError, AttributeError):
            return AttestationCheck(False, None, "bundle unparseable")
        if has_tlog:
            return self._verify_in_process(bundle_json, subject_sha256, source_repository)
        if self._gh is None or subject is None:
            return AttestationCheck(
                False, None, "timestamp-only (GitHub instance) bundle and no gh verifier configured"
            )
        if hashlib.sha256(subject).hexdigest() != subject_sha256:
            return AttestationCheck(False, None, "subject bytes do not match the digest")
        try:
            cert = self._gh.verify(bundle_json, subject, source_repository)
        except (ValueError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired) as e:
            return AttestationCheck(False, None, f"gh verification failed: {str(e)[:200]}")
        return self._result(claims_from_gh(cert), "gh attestation verified")

    def _result(self, claims: SignerClaims, detail: str) -> AttestationCheck:
        if claims.issuer != GITHUB_ACTIONS_ISSUER:
            return AttestationCheck(False, None, f"issuer {claims.issuer} is not GitHub Actions")
        return AttestationCheck(
            True,
            claims.signer_workflow(self._host),
            detail,
            runner_environment=claims.runner_environment,
            source_digest=claims.source_digest,
        )

    def _verify_in_process(self, bundle_json: bytes, subject_sha256: str, source_repository: str) -> AttestationCheck:
        try:
            bundle = Bundle.from_json(bundle_json)
        except Exception as e:  # malformed input from the network: fail closed
            return AttestationCheck(False, None, f"bundle unparseable: {type(e).__name__}")
        want_repo = f"https://{self._host}/{source_repository}"
        pol = policy.AllOf([policy.OIDCIssuerV2(GITHUB_ACTIONS_ISSUER), policy.OIDCSourceRepositoryURI(want_repo)])
        errors: list[str] = []
        for v in self._verifiers:
            try:
                ptype, payload = v.verify_dsse(bundle, pol)
                break
            except Exception as e:  # wrong root, bad signature, policy failure
                errors.append(str(e)[:200])
        else:
            return AttestationCheck(False, None, "signature or identity verification failed: " + " | ".join(errors))

        if ptype != "application/vnd.in-toto+json":
            return AttestationCheck(False, None, f"unexpected payload type {ptype}")
        try:
            statement = json.loads(payload)
            subjects = {s["digest"]["sha256"] for s in statement["subject"] if "sha256" in s.get("digest", {})}
        except (ValueError, KeyError, TypeError):
            return AttestationCheck(False, None, "in-toto statement unparseable")
        if statement.get("predicateType") != PROVENANCE_V1:
            return AttestationCheck(
                False, None, f"predicate {statement.get('predicateType')} is not SLSA provenance v1"
            )
        if subject_sha256 not in subjects:
            return AttestationCheck(False, None, "attestation subject does not include the manifest digest")
        return self._result(signer_claims(bundle.signing_certificate), "sigstore verified")

    def verify_any(
        self, bundles: Iterable[bytes], subject_sha256: str, source_repository: str, subject: bytes | None = None
    ) -> AttestationCheck | None:
        """First verified bundle wins. No bundles → None (C2, not an error). Bundles but none valid → invalid."""
        failures: list[str] = []
        for raw in bundles:
            check = self.verify(raw, subject_sha256, source_repository, subject)
            if check.verified:
                return check
            failures.append(check.detail)
        if not failures:
            return None
        return AttestationCheck(False, None, "; ".join(failures)[:500])


def bundles_from_listing(listing: dict[str, object], fetch: Callable[[str], bytes]) -> list[bytes]:
    """Turn the attestations API response into decoded bundle JSON. `fetch` downloads a bundle_url (size-limited)."""
    out: list[bytes] = []
    atts = listing.get("attestations")
    for att in atts if isinstance(atts, list) else []:
        if not isinstance(att, dict):
            continue
        if att.get("bundle"):
            out.append(json.dumps(att["bundle"]).encode())
        elif isinstance(att.get("bundle_url"), str) and att["bundle_url"].startswith("https://"):
            out.append(decode_bundle(fetch(att["bundle_url"])))
    return out


def subject_of(bundle_json: bytes) -> list[str]:
    """Subject digests of a bundle's in-toto statement (diagnostics only; not verified)."""
    env = json.loads(bundle_json)["dsseEnvelope"]
    statement = json.loads(base64.b64decode(env["payload"]))
    return [s["digest"].get("sha256", "") for s in statement.get("subject", [])]
