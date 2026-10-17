# SPDX-License-Identifier: Apache-2.0
"""Contract fake of the Jira Cloud REST v3 subset the platform uses (no Jira emulator exists).

Shapes follow https://developer.atlassian.com/cloud/jira/platform/rest/v3/ (search/jql with nextPageToken, ADF
bodies, transitions with `to.statusCategory.key`). The optional live test (-m jira) checks the same calls against a
real site so this fake cannot drift unnoticed.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

STATUSES = {
    "To Do": "new",
    "In Progress": "indeterminate",
    "Done": "done",
}
TRANSITIONS = [  # (id, name, to)
    ("11", "Start", "In Progress"),
    ("21", "Done", "Done"),
    ("31", "Reopen", "In Progress"),
    ("41", "Back to To Do", "To Do"),
]


class FakeJira:
    base = "https://acme.atlassian.net"

    def __init__(self, projects: tuple[str, ...] = ("SEC",)):
        self.projects = set(projects)
        self.issues: dict[str, dict[str, Any]] = {}
        self.comments: dict[str, list[dict[str, Any]]] = {}
        self.properties: dict[str, dict[str, Any]] = {}
        self.seq = 0
        self.requests: list[tuple[str, str]] = []

    def set_status(self, key: str, status: str) -> None:
        self.issues[key]["status"] = status

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.requests.append((method, path))
        if not request.headers.get("authorization", "").startswith(("Basic ", "Bearer ")):
            return httpx.Response(401)
        if path == "/rest/api/3/myself":
            return httpx.Response(200, json={"accountId": "svc-1", "displayName": "AAP service"})
        if m := re.fullmatch(r"/rest/api/3/project/(\w+)", path):
            return httpx.Response(200 if m[1] in self.projects else 404, json={"key": m[1]})
        if path == "/rest/api/3/search/jql" and method == "POST":
            body = json.loads(request.content)
            m = re.search(r'labels = "?([\w-]+)"?', body["jql"])
            hits = [self._issue(k) for k, i in self.issues.items() if m and m[1] in i["labels"]]
            return httpx.Response(200, json={"issues": hits[: body.get("maxResults", 50)], "isLast": True})
        if path == "/rest/api/3/issue" and method == "POST":
            f = json.loads(request.content)["fields"]
            if f["project"]["key"] not in self.projects:
                return httpx.Response(400, json={"errors": {"project": "project is required"}})
            assert f["description"]["type"] == "doc"
            self.seq += 1
            key = f"{f['project']['key']}-{self.seq}"
            self.issues[key] = {"fields": f, "labels": list(f["labels"]), "status": "To Do"}
            return httpx.Response(201, json={"id": str(self.seq), "key": key})
        if m := re.fullmatch(r"/rest/api/3/issue/([\w-]+)/properties/(\w+)", path):
            self.properties.setdefault(m[1], {})[m[2]] = json.loads(request.content)
            return httpx.Response(200)
        if m := re.fullmatch(r"/rest/api/3/issue/([\w-]+)/comment", path):
            self.comments.setdefault(m[1], []).append(json.loads(request.content)["body"])
            return httpx.Response(201, json={"id": "c"})
        if m := re.fullmatch(r"/rest/api/3/issue/([\w-]+)/transitions", path):
            issue = self.issues.get(m[1])
            if issue is None:
                return httpx.Response(404)
            if method == "GET":
                ts = [
                    {"id": i, "name": n, "to": {"name": to, "statusCategory": {"key": STATUSES[to]}}}
                    for i, n, to in TRANSITIONS
                    if to != issue["status"]
                ]
                return httpx.Response(200, json={"transitions": ts})
            tid = json.loads(request.content)["transition"]["id"]
            issue["status"] = next(to for i, _, to in TRANSITIONS if i == tid)
            return httpx.Response(204)
        if m := re.fullmatch(r"/rest/api/3/issue/([\w-]+)", path):
            return httpx.Response(200, json=self._issue(m[1])) if m[1] in self.issues else httpx.Response(404)
        return httpx.Response(404, json={"path": path})

    def _issue(self, key: str) -> dict[str, Any]:
        i = self.issues[key]
        return {
            "key": key,
            "fields": {
                "labels": i["labels"],
                "status": {"name": i["status"], "statusCategory": {"key": STATUSES[i["status"]]}},
            },
        }

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))
