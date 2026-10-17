# SPDX-License-Identifier: Apache-2.0
"""GitHub Issues and GitLab Issues as ticket systems (aap.plugins.interfaces.TicketSystem), for teams that track work
where their code lives instead of in Jira.

Same rules as the Jira client (ADR-018): the platform is the only writer of these issues; idempotency by a label
`aap-k-<sha256(dedup_key)[:24]>` looked up before create; content is a title, priority, due date, labels and a deep
link, never exploit detail or secret material. Closing an issue never closes a finding: the next scan does.

Credentials are write-capable and kept apart from the read-only connectors:
* GitHub: the platform's GitHub App with `issues: write` (opt-in: `aap bootstrap github-app --with-issues`).
* GitLab: a separate group access token, Reporter + `api` scope (`aap bootstrap gitlab --with-issues`).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import date
from typing import Any
from urllib.parse import quote

import httpx

from aap.connectors.jira import MANAGED_LABEL, Issue, dedup_label
from aap.plugins.interfaces import TicketError


class IssueError(TicketError):
    pass


def adf_to_markdown(doc: Mapping[str, Any]) -> str:
    """The neutral document (paragraphs + one link, see connectors.jira.adf) as plain Markdown."""
    out = []
    for para in doc.get("content") or []:
        parts = []
        for node in para.get("content") or []:
            text = str(node.get("text", "")).replace("<", "&lt;")
            link = next((m["attrs"]["href"] for m in node.get("marks") or [] if m.get("type") == "link"), None)
            parts.append(f"[{text}]({link})" if link else text)
        out.append("".join(parts))
    return "\n\n".join(out)


def _check(r: httpx.Response, what: str) -> Any:
    if r.status_code >= 300:
        raise IssueError(f"{what}: HTTP {r.status_code}")
    return r.json() if r.content else None


class GitHubIssues:
    """`project` is the repository (owner/name) that receives the issues."""

    system = "github"

    def __init__(
        self,
        token_provider: Callable[[str], str],
        api_url: str = "https://api.github.com",
        http: httpx.Client | None = None,
    ):
        self._token = token_provider  # owner → installation token
        self._http = http or httpx.Client(base_url=api_url, timeout=30.0, follow_redirects=False)

    def _h(self, repo: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token(repo.split('/')[0])}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @staticmethod
    def _issue(repo: str, i: Mapping[str, Any]) -> Issue:
        return Issue(
            f"{repo}#{i['number']}",
            i["state"],
            "done" if i["state"] == "closed" else "new",
            tuple(lbl["name"] for lbl in i.get("labels") or []),
            i.get("html_url", ""),
        )

    def _split(self, key: str) -> tuple[str, int]:
        repo, _, number = key.rpartition("#")
        return repo, int(number)

    def find_by_dedup(self, dedup_key: str, project: str | None = None) -> Issue | None:
        if project is None:
            return None  # GitHub searches per repository; sync() passes the target repository
        r = self._http.get(
            f"/repos/{project}/issues",
            params={"labels": dedup_label(dedup_key), "state": "all"},
            headers=self._h(project),
        )
        found = [i for i in _check(r, "search issues") if "pull_request" not in i]
        return self._issue(project, found[0]) if found else None

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
    ) -> Issue:
        body = adf_to_markdown(description) + (f"\n\nDue: {due.isoformat()} (SLA)" if due else "")
        payload = {
            "title": summary[:250],
            "body": body,
            "labels": sorted({MANAGED_LABEL, dedup_label(dedup_key), *labels}),
        }
        r = self._http.post(f"/repos/{project}/issues", json=payload, headers=self._h(project))
        return self._issue(project, _check(r, "create issue"))

    def get(self, key: str) -> Issue:
        repo, number = self._split(key)
        return self._issue(
            repo, _check(self._http.get(f"/repos/{repo}/issues/{number}", headers=self._h(repo)), "get issue")
        )

    def comment(self, key: str, body: dict[str, Any]) -> None:
        repo, number = self._split(key)
        _check(
            self._http.post(
                f"/repos/{repo}/issues/{number}/comments", json={"body": adf_to_markdown(body)}, headers=self._h(repo)
            ),
            "comment",
        )

    def transition_to(self, key: str, category: str, prefer: Sequence[str] = ()) -> bool:
        repo, number = self._split(key)
        state = {"done": "closed", "indeterminate": "open", "new": "open"}[category]
        r = self._http.patch(f"/repos/{repo}/issues/{number}", json={"state": state}, headers=self._h(repo))
        _check(r, "transition")
        return True


class GitLabIssues:
    """`project` is the GitLab project path (group/sub/project) that receives the issues."""

    system = "gitlab"

    def __init__(self, token_provider: Callable[[], str], base_url: str, http: httpx.Client | None = None):
        self._token = token_provider
        self._http = http or httpx.Client(
            base_url=f"{base_url.rstrip('/')}/api/v4", timeout=30.0, follow_redirects=False
        )

    def _h(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self._token()}

    @staticmethod
    def _issue(project: str, i: Mapping[str, Any]) -> Issue:
        return Issue(
            f"{project}#{i['iid']}",
            i["state"],
            "done" if i["state"] == "closed" else "new",
            tuple(i.get("labels") or []),
            i.get("web_url", ""),
        )

    def _split(self, key: str) -> tuple[str, int]:
        project, _, iid = key.rpartition("#")
        return project, int(iid)

    def find_by_dedup(self, dedup_key: str, project: str | None = None) -> Issue | None:
        if project is None:
            return None
        r = self._http.get(
            f"/projects/{quote(project, safe='')}/issues",
            params={"labels": dedup_label(dedup_key), "state": "all"},
            headers=self._h(),
        )
        found = _check(r, "search issues")
        return self._issue(project, found[0]) if found else None

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
    ) -> Issue:
        payload: dict[str, Any] = {
            "title": summary[:250],
            "description": adf_to_markdown(description),
            "labels": ",".join(sorted({MANAGED_LABEL, dedup_label(dedup_key), *labels})),
        }
        if due:
            payload["due_date"] = due.isoformat()
        r = self._http.post(f"/projects/{quote(project, safe='')}/issues", json=payload, headers=self._h())
        return self._issue(project, _check(r, "create issue"))

    def get(self, key: str) -> Issue:
        project, iid = self._split(key)
        r = self._http.get(f"/projects/{quote(project, safe='')}/issues/{iid}", headers=self._h())
        return self._issue(project, _check(r, "get issue"))

    def comment(self, key: str, body: dict[str, Any]) -> None:
        project, iid = self._split(key)
        _check(
            self._http.post(
                f"/projects/{quote(project, safe='')}/issues/{iid}/notes",
                json={"body": adf_to_markdown(body)},
                headers=self._h(),
            ),
            "comment",
        )

    def transition_to(self, key: str, category: str, prefer: Sequence[str] = ()) -> bool:
        project, iid = self._split(key)
        event = "close" if category == "done" else "reopen"
        _check(
            self._http.put(
                f"/projects/{quote(project, safe='')}/issues/{iid}", json={"state_event": event}, headers=self._h()
            ),
            "transition",
        )
        return True
