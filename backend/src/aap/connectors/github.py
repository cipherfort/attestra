# SPDX-License-Identifier: Apache-2.0
"""GitHub connector (ADR-005): a read-only GitHub App is the platform's source of truth for workflow runs.

`GitHubClient` is the interface ingestion depends on. `RestGitHubClient` implements it over the REST API with a token
provider (`github_app.GitHubAppAuth.token_provider`, installation tokens minted from the App key held in Key Vault)
and, when given an `AttestationVerifier`, Sigstore verification of the manifest attestation (→ C3). Without a
verifier, evidence is capped at C2: an unverified attestation is never trusted. `FakeGitHub` serves the demo and
tests with the same interface.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from aap.connectors.attestation import MAX_BUNDLE_BYTES, AttestationVerifier, bundles_from_listing
from aap.domain.evidence import AttestationCheck, RunInfo

API = "https://api.github.com"


@dataclass(frozen=True)
class ArtifactRef:
    id: int
    name: str
    size_in_bytes: int
    expired: bool = False


class GitHubClient(Protocol):
    def workflow_run(self, repo_full_name: str, run_id: int) -> RunInfo: ...

    def run_artifacts(self, repo_full_name: str, run_id: int) -> list[ArtifactRef]: ...

    def download_artifact(self, repo_full_name: str, artifact_id: int, max_bytes: int) -> bytes: ...

    def verify_attestation(
        self, repo_full_name: str, subject_sha256: str, subject: bytes | None = None
    ) -> AttestationCheck | None: ...


class RestGitHubClient:
    """REST implementation. Never sends or logs the token outside the Authorization header."""

    def __init__(
        self,
        token_provider: Callable[[], str],
        base_url: str = API,
        timeout: float = 30.0,
        attestation: AttestationVerifier | None = None,
        http: httpx.Client | None = None,
    ):
        self._token = token_provider
        self._http = http or httpx.Client(base_url=base_url, timeout=timeout, follow_redirects=False)
        self._attestation = attestation

    def _get(self, path: str) -> httpx.Response:
        r = self._http.get(
            path,
            headers={
                "Authorization": f"Bearer {self._token()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        r.raise_for_status()
        return r

    def workflow_run(self, repo_full_name: str, run_id: int) -> RunInfo:
        d = self._get(f"/repos/{repo_full_name}/actions/runs/{run_id}").json()
        refs = tuple(f"{w['path'].split('@')[0]}@{w['sha']}" for w in d.get("referenced_workflows") or [])
        return RunInfo(
            run_id=d["id"],
            run_attempt=d["run_attempt"],
            repository_id=d["repository"]["id"],
            head_sha=d["head_sha"],
            event=d["event"],
            conclusion=d.get("conclusion"),
            referenced_workflows=refs,
        )

    def run_artifacts(self, repo_full_name: str, run_id: int) -> list[ArtifactRef]:
        d = self._get(f"/repos/{repo_full_name}/actions/runs/{run_id}/artifacts?per_page=100").json()
        return [ArtifactRef(a["id"], a["name"], a["size_in_bytes"], a.get("expired", False)) for a in d["artifacts"]]

    def download_artifact(self, repo_full_name: str, artifact_id: int, max_bytes: int) -> bytes:
        # The API answers with a 302 to a short-lived storage URL; follow it once without forwarding our token.
        r = self._http.get(
            f"/repos/{repo_full_name}/actions/artifacts/{artifact_id}/zip",
            headers={"Authorization": f"Bearer {self._token()}"},
        )
        if r.status_code != 302:
            r.raise_for_status()
        location = r.headers["location"]
        if not location.startswith("https://"):
            raise ValueError("artifact redirect is not https")
        chunks, total = [], 0
        with httpx.stream("GET", location, timeout=60.0) as s:
            s.raise_for_status()
            for chunk in s.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"artifact larger than {max_bytes} bytes")
                chunks.append(chunk)
        return b"".join(chunks)

    def verify_attestation(
        self, repo_full_name: str, subject_sha256: str, subject: bytes | None = None
    ) -> AttestationCheck | None:
        if self._attestation is None:
            return None  # no trust root configured: C2 at most
        r = self._http.get(
            f"/repos/{repo_full_name}/attestations/sha256:{subject_sha256}",
            headers={
                "Authorization": f"Bearer {self._token()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        bundles = bundles_from_listing(r.json(), _fetch_bundle)
        return self._attestation.verify_any(bundles, subject_sha256, repo_full_name, subject)


def _fetch_bundle(url: str) -> bytes:
    """Bundle storage is a pre-signed URL: never send our token there."""
    with httpx.stream("GET", url, timeout=30.0, follow_redirects=False) as s:
        s.raise_for_status()
        data = b""
        for chunk in s.iter_bytes():
            data += chunk
            if len(data) > MAX_BUNDLE_BYTES:
                raise ValueError("attestation bundle too large")
        return data


@dataclass
class FakeRun:
    run: RunInfo
    artifacts: dict[str, bytes] = field(default_factory=dict)  # name → zip bytes
    attested_signer: str | None = None


class FakeGitHub:
    """In-memory GitHub for the demo and tests. Same interface, same failure modes."""

    def __init__(self) -> None:
        self.runs: dict[tuple[str, int], FakeRun] = {}

    def add_run(self, repo: str, run: FakeRun) -> None:
        self.runs[(repo, run.run.run_id)] = run

    def workflow_run(self, repo_full_name: str, run_id: int) -> RunInfo:
        return self.runs[(repo_full_name, run_id)].run

    def run_artifacts(self, repo_full_name: str, run_id: int) -> list[ArtifactRef]:
        fr = self.runs[(repo_full_name, run_id)]
        return [ArtifactRef(run_id * 1000 + i, name, len(data)) for i, (name, data) in enumerate(fr.artifacts.items())]

    def download_artifact(self, repo_full_name: str, artifact_id: int, max_bytes: int) -> bytes:
        run_id, index = divmod(artifact_id, 1000)
        items = list(self.runs[(repo_full_name, run_id)].artifacts.values())
        if index >= len(items):
            raise KeyError(artifact_id)
        if len(items[index]) > max_bytes:
            raise ValueError("artifact too large")
        return items[index]

    def verify_attestation(
        self, repo_full_name: str, subject_sha256: str, subject: bytes | None = None
    ) -> AttestationCheck | None:
        for (repo, _), fr in self.runs.items():
            if repo == repo_full_name and fr.attested_signer:
                return AttestationCheck(True, fr.attested_signer)
        return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
