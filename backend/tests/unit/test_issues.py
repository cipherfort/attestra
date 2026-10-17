# SPDX-License-Identifier: Apache-2.0
"""GitHub Issues as a ticket system: idempotent by label, Markdown body without scanner markup, close/reopen."""

from __future__ import annotations

import json
from datetime import date

import httpx

from aap.connectors.issues import GitHubIssues, adf_to_markdown
from aap.connectors.jira import adf, dedup_label


def test_adf_renders_as_plain_markdown_and_escapes_html():
    doc = adf("Application: <script>x</script>", "second", link=("Open", "https://aap.example.org/#/findings/1"))
    assert (
        adf_to_markdown(doc)
        == "Application: &lt;script>x&lt;/script>\n\nsecond\n\n[Open](https://aap.example.org/#/findings/1)"
    )


def test_github_issues_lifecycle():
    issues: dict[int, dict] = {}
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, req.headers.get("Authorization")))
        path = req.url.path
        if req.method == "GET" and path == "/repos/acme/security/issues":
            label = req.url.params["labels"]
            found = [i for i in issues.values() if label in [lbl["name"] for lbl in i["labels"]]]
            return httpx.Response(
                200, json=[*found, {"number": 99, "pull_request": {}, "labels": [], "state": "open"}] if found else []
            )
        if req.method == "POST" and path == "/repos/acme/security/issues":
            body = json.loads(req.content)
            n = len(issues) + 1
            issues[n] = {
                "number": n,
                "state": "open",
                "html_url": f"https://github.test/acme/security/issues/{n}",
                "labels": [{"name": lbl} for lbl in body["labels"]],
                "body": body["body"],
            }
            return httpx.Response(201, json=issues[n])
        if req.method == "PATCH":
            n = int(path.rsplit("/", 1)[1])
            issues[n]["state"] = json.loads(req.content)["state"]
            return httpx.Response(200, json=issues[n])
        if req.method == "GET" and path.startswith("/repos/acme/security/issues/"):
            return httpx.Response(200, json=issues[int(path.rsplit("/", 1)[1])])
        if req.method == "POST" and path.endswith("/comments"):
            return httpx.Response(201, json={})
        return httpx.Response(404)

    gh = GitHubIssues(
        lambda owner: f"tok-{owner}",
        http=httpx.Client(base_url="https://api.github.test", transport=httpx.MockTransport(handler)),
    )
    assert gh.find_by_dedup("k1", "acme/security") is None
    issue = gh.create(
        project="acme/security",
        issue_type="Task",
        summary="[P1] Claims: SQLi",
        description=adf("x"),
        dedup_key="k1",
        labels=["aap-P1"],
        priority=None,
        due=date(2026, 11, 1),
    )
    assert issue.key == "acme/security#1" and dedup_label("k1") in issue.labels and "aap-managed" in issue.labels
    assert "Due: 2026-11-01" in issues[1]["body"]
    again = gh.find_by_dedup("k1", "acme/security")
    assert again is not None and again.key == "acme/security#1"  # pull requests in the result are ignored
    assert gh.transition_to(issue.key, "done") and gh.get(issue.key).status_category == "done"
    assert gh.transition_to(issue.key, "indeterminate") and gh.get(issue.key).status_category == "new"
    gh.comment(issue.key, adf("still detected"))
    assert all(auth == "Bearer tok-acme" for _, _, auth in calls)
