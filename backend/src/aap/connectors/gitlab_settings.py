# SPDX-License-Identifier: Apache-2.0
"""GitLab project settings → the same C1 evidence types (and summary shapes) the GitHub connector produces, so the
evaluators need no provider logic. ADR-033 decision 4: a feature the tier lacks is reported absent with the reason;
something the Reporter token cannot read is a gap (never guessed).

| Evidence type          | GitLab source                                                                        |
|------------------------|--------------------------------------------------------------------------------------|
| repo.ruleset           | protected default branch (push/merge levels, force push, code-owner approval),       |
|                        | approvals (Premium), "pipelines must succeed" + approved component jobs in the config |
| repo.security_settings | secret push protection (Ultimate)                                                    |
| repo.codeowners        | CODEOWNERS (root, .gitlab/, docs/), sections supported                               |
| repo.access            | direct members with Developer+ who are not group members; Maintainer+; visibility    |
| repo.environments      | gap: CI/CD variable names need Maintainer                                            |
| repo.actions_policy    | gap: no GitLab equivalent of GitHub Actions permissions                              |
| registry.application,  | .security/ files, as on GitHub                                                       |
| repo.threat_model      |                                                                                      |
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

import httpx
import yaml

from aap.connectors.github_settings import RepoSnapshot, Unavailable, codeowners_coverage
from aap.connectors.gitlab import GitLabComponents, GitLabRest, owners_from_codeowners, required_component_checks

VERSION = "0.1.0"
PRODUCER = f"connector:gitlab-settings@{VERSION}"
DEVELOPER, MAINTAINER = 30, 40
NO_ONE = 0


def summarise_protection(
    branch: dict[str, Any] | None, approvals: dict[str, Any] | None, pipeline_must_succeed: bool, checks: list[str]
) -> dict[str, Any]:
    if not branch:
        return {
            "requires_pr": False,
            "required_approvals": 0,
            "require_code_owner_review": False,
            "required_checks": [],
            "blocks_force_push": False,
            "blocks_deletion": False,
            "sources": [],
            "notes": ["default branch is not protected"],
        }
    push_levels = [lvl.get("access_level") for lvl in branch.get("push_access_levels") or []]
    notes = []
    if approvals is None:
        notes.append("merge request approvals: unavailable_on_tier (GitLab Free cannot require approvals)")
    return {
        "requires_pr": bool(push_levels) and all(level == NO_ONE for level in push_levels),
        "required_approvals": int((approvals or {}).get("approvals_before_merge") or 0),
        "require_code_owner_review": bool(branch.get("code_owner_approval_required")),
        "required_checks": checks if pipeline_must_succeed else [],
        "blocks_force_push": not bool(branch.get("allow_force_push")),
        "blocks_deletion": True,  # GitLab never deletes a protected branch
        "sources": ["protected_branch"],
        "notes": notes,
    }


def collect_project(
    api: GitLabRest,
    project: str | int,
    trusted: GitLabComponents,
    sensitive_paths: tuple[str, ...] = (".gitlab-ci.yml", ".gitlab/", ".security/"),
) -> RepoSnapshot:
    p = api.project(project)
    pid = int(p["id"])
    branch = p.get("default_branch") or "main"
    head = None
    with contextlib.suppress(Unavailable):  # an empty repository has no commits
        head = api.get(f"/projects/{pid}/repository/commits/{GitLabRest.pid(branch)}")["id"]
    snap = RepoSnapshot(
        p["path_with_namespace"],
        pid,
        branch,
        head,
        p.get("visibility", "private"),
        bool(p.get("archived")),
        provider="gitlab",
        producer=PRODUCER,
    )

    def attempt(etype: str, fn: Callable[[], dict[str, Any]]) -> None:
        try:
            snap.evidence[etype] = fn()
        except Unavailable as e:
            snap.gaps[etype] = str(e)
        except httpx.HTTPStatusError as e:
            snap.gaps[etype] = f"HTTP {e.response.status_code}"

    def ruleset() -> dict[str, Any]:
        try:
            protected = api.get(f"/projects/{pid}/protected_branches/{GitLabRest.pid(branch)}")
        except Unavailable:
            protected = None
        try:
            approvals = api.get(f"/projects/{pid}/approvals")
        except Unavailable:
            approvals = None
        checks = required_component_checks(api.lint(pid, head), trusted) if head else []
        return summarise_protection(protected, approvals, bool(p.get("only_allow_merge_if_pipeline_succeeds")), checks)

    def security() -> dict[str, Any]:
        flag = p.get("secret_push_protection_enabled", p.get("pre_receive_secret_detection_enabled"))
        features = {"secret_scanning_push_protection": bool(flag)}
        return {
            "features": features,
            "notes": [] if flag is not None else ["secret push protection: unavailable_on_tier"],
        }

    def codeowners() -> dict[str, Any]:
        content = None
        for path in ("CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"):
            content = api.file(pid, path, branch)
            if content is not None:
                break
        if content is None:
            return {"present": False, "errors": 0, "covered_paths": []}
        rules = owners_from_codeowners(content)
        return {
            "present": True,
            "errors": 0,
            "covered_paths": codeowners_coverage(rules, list(sensitive_paths)),
            "notes": ["GitLab exposes no CODEOWNERS syntax check through the API"],
        }

    def access() -> dict[str, Any]:
        direct = list(api.pages(f"/projects/{pid}/members"))
        group_members: set[int] = set()
        ns = p.get("namespace") or {}
        if ns.get("kind") == "group":
            group_members = {m["id"] for m in api.pages(f"/groups/{ns['id']}/members/all")}
        outside = [m for m in direct if m.get("access_level", 0) >= DEVELOPER and m["id"] not in group_members]
        admins = [m for m in api.pages(f"/projects/{pid}/members/all") if m.get("access_level", 0) >= MAINTAINER]
        return {
            "outside_writers": len(outside),
            "admin_users": len(admins),
            "visibility": snap.visibility,
            "archived": snap.archived,
        }

    def unreadable_environments() -> dict[str, Any]:
        raise Unavailable("CI/CD variable names need the Maintainer role; the platform's token is Reporter")

    def no_equivalent() -> dict[str, Any]:
        raise Unavailable("no GitLab equivalent of GitHub Actions permissions")

    attempt("repo.ruleset", ruleset)
    attempt("repo.security_settings", security)
    attempt("repo.codeowners", codeowners)
    attempt("repo.access", access)
    attempt("repo.environments", unreadable_environments)
    attempt("repo.actions_policy", no_equivalent)

    for name in (
        "application.yaml",
        "asvs.yaml",
        "threat-model/threats.yaml",
        "threat-model/mitigations.yaml",
        "threat-model/residual-risk.yaml",
    ):
        try:
            text = api.file(pid, f".security/{name}", branch)
            snap.documents[name] = None if text is None else yaml.safe_load(text)
        except (Unavailable, yaml.YAMLError) as e:
            snap.documents[name] = None
            snap.gaps[f".security/{name}"] = str(e)[:200]
    try:
        snap.documents["SECURITY.md"] = any(
            api.file(pid, path, branch) is not None
            for path in ("SECURITY.md", ".gitlab/SECURITY.md", "docs/SECURITY.md")
        )
    except Unavailable:
        snap.documents["SECURITY.md"] = False
    return snap


def group_exists(api: GitLabRest) -> Callable[[str], bool]:
    """Owner references `@group/subgroup` resolve when the group exists and has members."""

    def check(path: str) -> bool:
        try:
            return any(True for _ in api.pages(f"/groups/{GitLabRest.pid(path)}/members/all"))
        except Unavailable:
            return False

    return check
