# SPDX-License-Identifier: Apache-2.0
"""What the core expects from each kind of plugin's client. Structural (typing.Protocol): implement the methods,
no base class needed. The built-in implementations are named next to each interface."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from datetime import date
from typing import Any, Protocol

from aap.blobstore import EvidenceBlobStore  # evidence_store: LocalBlobStore, AzureBlobStore
from aap.connectors.github import GitHubClient  # scm: RestGitHubClient (GitLab in M3)
from aap.secrets import SecretStore  # secrets: FileSecretStore, KeyVaultSecretStore

ScmClient = GitHubClient


class TicketIssue(Protocol):
    key: str
    status: str
    status_category: str  # new | indeterminate | done
    url: str


class TicketError(Exception):
    """Any ticket-system failure; the sync records it and carries on with the next ticket."""


class TicketSystem(Protocol):
    """ticketing: connectors/jira.JiraClient, connectors/issues.GitHubIssues, GitLabIssues. Idempotency is the plugin's
    job: find_by_dedup (within the target project) before create. `system` is stored on the ticket record."""

    system: str

    def find_by_dedup(self, dedup_key: str, project: str | None = None) -> TicketIssue | None: ...

    def create(
        self,
        *,
        project: str,
        issue_type: str,
        summary: str,
        description: dict[str, Any],
        dedup_key: str,
        labels: Sequence[str],
        priority: str | None,
        due: date | None,
    ) -> TicketIssue: ...

    def get(self, key: str) -> TicketIssue: ...

    def comment(self, key: str, body: dict[str, Any]) -> None: ...

    def transition_to(self, key: str, category: str, prefer: Sequence[str] = ()) -> bool: ...


class CloudPosture(Protocol):
    """cloud_posture: connectors/cloud.DefenderClient, SecurityHubClient. Yields only findings in its scope."""

    def findings(self) -> Iterator[Any]: ...  # aap.connectors.cloud.CloudFinding


class SiemSink(Protocol):
    """siem: connectors/sentinel.LogsIngestionClient. Raises on a refused batch; rows stay queued (at-least-once)."""

    def send(self, rows: Sequence[dict[str, Any]]) -> int: ...


class VulnFeed(Protocol):
    """vuln_intel: advisories in the platform's shape (see store/supply_chain.upsert_vulnerability)."""

    def advisories(self, purls: Iterable[str]) -> Iterator[dict[str, Any]]: ...


__all__ = ["CloudPosture", "EvidenceBlobStore", "ScmClient", "SecretStore", "SiemSink", "TicketSystem", "VulnFeed"]
