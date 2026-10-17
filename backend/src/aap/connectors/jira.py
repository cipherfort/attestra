# SPDX-License-Identifier: Apache-2.0
"""Jira Cloud REST v3 client (ADR-018). Data Center works with a PAT (bearer) and the same v2-compatible endpoints.

Idempotency without a Jira app: entity properties are not JQL-searchable for plain REST clients, so every
platform ticket carries a label `aap-k-<sha256(dedup_key)[:24]>`. Lookup by that label happens before create; the
full dedup key is also stored as the issue property `aap` for humans and reconciliation.

Content rule: title, priority, due date, labels, a deep link. Never exploit detail or secret material.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

import httpx

from aap.plugins.interfaces import TicketError

MANAGED_LABEL = "aap-managed"


class JiraError(TicketError):
    pass


def dedup_label(dedup_key: str) -> str:
    return "aap-k-" + hashlib.sha256(dedup_key.encode()).hexdigest()[:24]


def adf(*paragraphs: str, link: tuple[str, str] | None = None) -> dict[str, Any]:
    """Atlassian Document Format: plain paragraphs and one optional link. No markup from scanners is passed through."""
    content: list[dict[str, Any]] = [
        {"type": "paragraph", "content": [{"type": "text", "text": p[:2000]}]} for p in paragraphs if p
    ]
    if link:
        text, href = link
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text, "marks": [{"type": "link", "attrs": {"href": href}}]}],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


@dataclass(frozen=True)
class Issue:
    key: str
    status: str
    status_category: str  # new | indeterminate | done
    labels: tuple[str, ...]
    url: str


class JiraClient:
    system = "jira"

    def __init__(
        self,
        base_url: str,
        *,
        email: str | None = None,
        api_token: str | None = None,
        bearer: str | None = None,
        http: httpx.Client | None = None,
    ):
        if not base_url.startswith("https://") and not base_url.startswith("http://localhost"):
            raise JiraError("Jira base URL must be https")
        if bearer:
            auth = f"Bearer {bearer}"
        elif email and api_token:
            auth = "Basic " + base64.b64encode(f"{email}:{api_token}".encode()).decode()
        else:
            raise JiraError("Jira needs email + API token (Cloud) or a PAT (Data Center)")
        self.base = base_url.rstrip("/")
        self._h = {"Authorization": auth, "Accept": "application/json", "Content-Type": "application/json"}
        self._http = http or httpx.Client(timeout=30.0, follow_redirects=False)

    def _req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        r = self._http.request(method, self.base + path, headers=self._h, **kw)
        if r.status_code == 429:
            raise JiraError(f"rate limited (Retry-After {r.headers.get('Retry-After', '?')})")
        if r.status_code >= 400:
            raise JiraError(f"{method} {path.split('?')[0]} → {r.status_code}: {r.text[:300]}")
        return r

    # ---------------------------------------------------------------- reads
    def myself(self) -> dict[str, Any]:
        return dict(self._req("GET", "/rest/api/3/myself").json())

    def project(self, key: str) -> dict[str, Any]:
        return dict(self._req("GET", f"/rest/api/3/project/{key}").json())

    def search(self, jql: str, fields: Sequence[str] = ("status", "labels"), limit: int = 500) -> Iterator[Issue]:
        token: str | None = None
        seen = 0
        while seen < limit:
            body: dict[str, Any] = {"jql": jql, "fields": list(fields), "maxResults": 100}
            if token:
                body["nextPageToken"] = token
            d = self._req("POST", "/rest/api/3/search/jql", json=body).json()
            for i in d.get("issues", []):
                seen += 1
                yield self._issue(i)
            token = d.get("nextPageToken")
            if not token or d.get("isLast", True):
                return

    def _issue(self, i: Mapping[str, Any]) -> Issue:
        f = i.get("fields") or {}
        st = f.get("status") or {}
        return Issue(
            i["key"],
            st.get("name", ""),
            (st.get("statusCategory") or {}).get("key", "new"),
            tuple(f.get("labels") or []),
            f"{self.base}/browse/{i['key']}",
        )

    def get(self, key: str) -> Issue:
        return self._issue(self._req("GET", f"/rest/api/3/issue/{key}", params={"fields": "status,labels"}).json())

    def find_by_dedup(self, dedup_key: str, project: str | None = None) -> Issue | None:
        return next(iter(self.search(f'labels = "{dedup_label(dedup_key)}" ORDER BY created ASC', limit=1)), None)

    # ---------------------------------------------------------------- writes
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
        fields: dict[str, Any] = {
            "project": {"key": project},
            "issuetype": {"name": issue_type},
            "summary": summary[:250],
            "description": description,
            "labels": sorted({*labels, MANAGED_LABEL, dedup_label(dedup_key)}),
        }
        if priority:
            fields["priority"] = {"name": priority}
        if due:
            fields["duedate"] = due.isoformat()
        key = self._req("POST", "/rest/api/3/issue", json={"fields": fields}).json()["key"]
        self._req("PUT", f"/rest/api/3/issue/{key}/properties/aap", json={"dedup_key": dedup_key})
        return self.get(key)

    def comment(self, key: str, body: dict[str, Any]) -> None:
        self._req("POST", f"/rest/api/3/issue/{key}/comment", json={"body": body})

    def transition_to(self, key: str, category: str, prefer: Sequence[str] = ()) -> bool:
        """Move to a status in `category` (done | new | indeterminate). Workflows differ per project, so we pick the
        first available transition whose target is in that category, preferring names in `prefer`."""
        ts = self._req("GET", f"/rest/api/3/issue/{key}/transitions").json().get("transitions", [])
        cands = [t for t in ts if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == category]
        if not cands:
            return False
        cands.sort(key=lambda t: (t["to"].get("name") not in prefer, t["name"]))
        self._req("POST", f"/rest/api/3/issue/{key}/transitions", json={"transition": {"id": cands[0]["id"]}})
        return True

    # ---------------------------------------------------------------- admin (bootstrap only)
    def create_project(self, key: str, name: str, lead_account_id: str) -> dict[str, Any]:
        body = {
            "key": key,
            "name": name,
            "projectTypeKey": "software",
            "projectTemplateKey": "com.pyxis.greenhopper.jira:gh-simplified-kanban-classic",
            "leadAccountId": lead_account_id,
            "assigneeType": "UNASSIGNED",
        }
        return dict(self._req("POST", "/rest/api/3/project", json=body).json())
