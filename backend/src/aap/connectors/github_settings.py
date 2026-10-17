# SPDX-License-Identifier: Apache-2.0
"""GitHub repository settings connector (ADR-005): what GitHub *says* is configured, as C1 evidence.

Reads, per registered repository, with an installation token (read-only):

| Evidence type            | API                                                                              |
|--------------------------|----------------------------------------------------------------------------------|
| repo.ruleset             | GET /repos/{r}/rules/branches/{default} (effective org + repo rulesets) and, when |
|                          | readable, classic branch protection. The stronger of the two counts.             |
| repo.security_settings   | GET /repos/{r} → security_and_analysis                                           |
| repo.codeowners          | CODEOWNERS file + GET /repos/{r}/codeowners/errors; last-match-wins coverage     |
| repo.access              | outside collaborators with push+, direct admins, visibility                      |
| repo.environments        | environments + protection rules; Actions secret NAMES (never values)             |
| repo.actions_policy      | Actions permissions, default GITHUB_TOKEN permissions                            |
| repo.threat_model        | .security/threat-model/*.yaml (structure only; the review is M2 evidence)        |
| registry.application     | .security/application.yaml + asvs.yaml (schema, owners, SECURITY.md)             |
| scan.secrets (C3)        | secret-scanning alerts: GitHub ran the scan, so this is execution evidence       |

Fail-closed: a 403/404 on a read means that evidence type is NOT produced for this run (and the gap is reported), never
a default "ok". Summaries carry exactly the fields the evaluators read (aap/evaluators/library.py).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml

from aap.connectors.github_app import API, HEADERS

VERSION = "1.0.0"
PRODUCER = f"connector:github-settings@{VERSION}"
MAX_FILE_BYTES = 512 * 1024
MAX_PAGES = 20

# Names that indicate a long-lived cloud credential stored as an Actions secret (OIDC federation is the standard).
STATIC_CLOUD_SECRET = re.compile(
    r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET|AZURE_CREDENTIALS|"
    r"GOOGLE_CREDENTIALS|GCP_SA_KEY|GCP_CREDENTIALS|SERVICE_ACCOUNT_KEY)",
    re.IGNORECASE,
)
PRODUCTION_ENV = re.compile(r"^(prod|production|live)$", re.IGNORECASE)


class Unavailable(Exception):
    """The read was refused or the resource is absent: the evidence type is skipped, with this reason."""


class GitHubRest:
    def __init__(self, token_provider: Callable[[], str], base_url: str = API, http: httpx.Client | None = None):
        self._token = token_provider
        self._http = http or httpx.Client(base_url=base_url, timeout=30.0, follow_redirects=False)

    def _headers(self, accept: str | None = None) -> dict[str, str]:
        h = {**HEADERS, "Authorization": f"Bearer {self._token()}"}
        if accept:
            h["Accept"] = accept
        return h

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        r = self._http.get(path, params=params, headers=self._headers())
        if r.status_code in (403, 404):
            raise Unavailable(f"{r.status_code} on {path.split('?')[0]}")
        r.raise_for_status()
        return r.json()

    def pages(self, path: str, params: Mapping[str, Any] | None = None, key: str | None = None) -> Iterator[Any]:
        url: str | None = path
        query: dict[str, Any] | None = {"per_page": 100, **(params or {})}
        for _ in range(MAX_PAGES):
            if url is None:
                return
            r = self._http.get(url, params=query, headers=self._headers())
            if r.status_code in (403, 404):
                raise Unavailable(f"{r.status_code} on {path}")
            r.raise_for_status()
            body = r.json()
            yield from (body[key] if key else body)
            url, query = r.links.get("next", {}).get("url"), None
        raise Unavailable(f"more than {MAX_PAGES} pages on {path}")

    def file(self, repo: str, path: str, ref: str | None = None) -> str | None:
        r = self._http.get(
            f"/repos/{repo}/contents/{path}",
            params={"ref": ref} if ref else None,
            headers=self._headers("application/vnd.github.raw"),
        )
        if r.status_code == 404:
            return None
        if r.status_code == 403:
            raise Unavailable(f"403 reading {path}")
        r.raise_for_status()
        if len(r.content) > MAX_FILE_BYTES:
            raise Unavailable(f"{path} larger than {MAX_FILE_BYTES} bytes")
        return r.text


# ------------------------------------------------------------------------------------------ pure summarisers


def summarise_rules(branch_rules: Sequence[Mapping[str, Any]], classic: Mapping[str, Any] | None) -> dict[str, Any]:
    """Effective rules on the default branch. Rulesets (org + repo) and classic protection both bind; take the max."""
    s: dict[str, Any] = {
        "requires_pr": False,
        "required_approvals": 0,
        "require_code_owner_review": False,
        "required_checks": set(),
        "blocks_force_push": False,
        "blocks_deletion": False,
        "sources": set(),
    }
    for rule in branch_rules:
        t, p = rule.get("type"), rule.get("parameters") or {}
        s["sources"].add(f"ruleset:{rule.get('ruleset_id')}")
        if t == "pull_request":
            s["requires_pr"] = True
            s["required_approvals"] = max(s["required_approvals"], int(p.get("required_approving_review_count", 0)))
            s["require_code_owner_review"] |= bool(p.get("require_code_owner_review"))
        elif t == "required_status_checks":
            s["required_checks"] |= {c["context"] for c in p.get("required_status_checks", [])}
        elif t == "non_fast_forward":
            s["blocks_force_push"] = True
        elif t == "deletion":
            s["blocks_deletion"] = True
    if classic:
        s["sources"].add("branch_protection")
        reviews = classic.get("required_pull_request_reviews")
        if reviews:
            s["requires_pr"] = True
            s["required_approvals"] = max(
                s["required_approvals"], int(reviews.get("required_approving_review_count", 0))
            )
            s["require_code_owner_review"] |= bool(reviews.get("require_code_owner_reviews"))
        checks = classic.get("required_status_checks") or {}
        s["required_checks"] |= {c["context"] for c in checks.get("checks", [])} | set(checks.get("contexts", []))
        if not (classic.get("allow_force_pushes") or {}).get("enabled", False):
            s["blocks_force_push"] = True
        if not (classic.get("allow_deletions") or {}).get("enabled", False):
            s["blocks_deletion"] = True
    s["required_checks"] = sorted(s["required_checks"])
    s["sources"] = sorted(s["sources"])
    return s


def summarise_security(repo: Mapping[str, Any]) -> dict[str, Any]:
    sa = repo.get("security_and_analysis")
    if sa is None:
        # absent unless the token can administer the repo: unknown is not "disabled", and not "enabled"
        raise Unavailable("security_and_analysis not visible (administration:read missing)")
    return {"features": {k: (v or {}).get("status") == "enabled" for k, v in sa.items()}}


def parse_codeowners(content: str) -> list[tuple[str, list[str]]]:
    rules = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            rules.append((pattern, owners))
    return rules


def _co_match(pattern: str, path: str) -> bool:
    """CODEOWNERS (gitignore-style) matching, enough for directory and glob rules."""
    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")
    if pat in ("*", "**"):
        return True
    if pat.endswith("/"):
        pat += "**"
    if not anchored and "/" not in pat.rstrip("*"):
        return any(fnmatch.fnmatch(part, pat) for part in path.split("/")) or fnmatch.fnmatch(path, pat)
    return (
        fnmatch.fnmatch(path, pat)
        or fnmatch.fnmatch(path, pat.removesuffix("/**") + "/*")
        or path.startswith(pat.removesuffix("**"))
    )


def codeowners_coverage(rules: Sequence[tuple[str, list[str]]], paths: Sequence[str]) -> list[str]:
    """A path is covered when the LAST matching rule names at least one owner (GitHub semantics)."""
    covered = []
    for path in paths:
        probe = path if not path.endswith("/") else path + "probe"
        owners: list[str] | None = None
        for pattern, o in rules:
            if _co_match(pattern, probe):
                owners = o
        if owners:
            covered.append(path)
    return covered


def summarise_environments(
    envs: Sequence[Mapping[str, Any]], secret_names: Sequence[str], env_secret_names: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    prod: dict[str, Any] = {}
    for env in envs:
        if PRODUCTION_ENV.match(env.get("name", "")):
            reviewers = sum(
                len(r.get("reviewers") or [])
                for r in env.get("protection_rules") or []
                if r.get("type") == "required_reviewers"
            )
            prod = {
                "name": env["name"],
                "required_reviewers": reviewers,
                "branch_policy": env.get("deployment_branch_policy") is not None,
                "wait_timer": next(
                    (
                        r.get("wait_timer", 0)
                        for r in env.get("protection_rules") or []
                        if r.get("type") == "wait_timer"
                    ),
                    0,
                ),
            }
            break
    all_names = list(secret_names) + [n for names in env_secret_names.values() for n in names]
    return {
        "production": prod,
        "environments": sorted(e.get("name", "") for e in envs),
        "static_cloud_secret_names": sorted({n for n in all_names if STATIC_CLOUD_SECRET.search(n)}),
    }


def summarise_threat_model(
    threats: Mapping[str, Any] | None,
    mitigations: Mapping[str, Any] | None,
    residual: Mapping[str, Any] | None,
    schema_errors: Sequence[str],
) -> dict[str, Any]:
    t_list = (threats or {}).get("threats") or []
    mitigated = {
        m.get("threat")
        for m in (mitigations or {}).get("mitigations") or []
        if m.get("status") in ("implemented", "verified")
    }
    accepted = {r.get("threat") for r in (residual or {}).get("residual_risks") or [] if r.get("exception_id")}
    high = [t for t in t_list if t.get("rating") in ("high", "critical")]
    return {
        "schema_valid": not schema_errors and bool(t_list),
        "schema_errors": list(schema_errors)[:10],
        "threats": len(t_list),
        "high_threats": len(high),
        "high_threat_ids": sorted(str(t["id"]) for t in high if t.get("id")),
        "high_threats_unmitigated": sorted(
            t["id"] for t in high if t.get("id") not in mitigated and t.get("id") not in accepted
        ),
    }


@dataclass
class OwnerResolution:
    """Resolves owner references in application.yaml: `@login`, `@org/team`, or an email address."""

    user_logins: set[str] = field(default_factory=set)
    user_emails: set[str] = field(default_factory=set)
    team_slugs: set[str] = field(default_factory=set)  # org/team that exists and has members

    def resolves(self, ref: str | None) -> bool:
        if not ref:
            return False
        ref = ref.strip()
        if ref.startswith("@") and "/" in ref:
            return ref[1:].lower() in self.team_slugs
        if ref.startswith("@"):
            return ref[1:].lower() in self.user_logins
        return ref.lower() in self.user_emails


def summarise_application(
    app_doc: Mapping[str, Any] | None,
    asvs_doc: Mapping[str, Any] | None,
    schema_errors: Sequence[str],
    owners: OwnerResolution,
    security_policy: bool,
    linked_repos: set[str],
    tier_asvs_level: int | None,
) -> dict[str, Any]:
    app = (app_doc or {}).get("application") or {}
    own = app.get("owners") or {}
    unresolved = [k for k in ("business_owner", "technical_owner", "team") if not owners.resolves(own.get(k))]
    declared_repos = set(app.get("repositories") or [])
    level = (asvs_doc or {}).get("target_level")
    summary: dict[str, Any] = {
        "schema_valid": app_doc is not None and not schema_errors,
        "schema_errors": list(schema_errors)[:10],
        "name": app.get("name"),
        "unresolved_owners": unresolved,
        "unlinked_repos": len(declared_repos - linked_repos),
        "security_policy": security_policy,
        "security_contact": bool((app.get("security_contact") or {}).get("email")),
        "champion": own.get("security_champion") if owners.resolves(own.get("security_champion")) else None,
        "data_stores": sorted(str(d.get("name")) for d in app.get("data_stores") or [] if d.get("name")),
    }
    if asvs_doc is not None and level is not None:
        summary |= {"asvs_version": asvs_doc.get("asvs_version"), "asvs_target_level": int(level)}
        if tier_asvs_level is not None:
            summary["asvs_required_level"] = tier_asvs_level
    return summary


# ------------------------------------------------------------------------------------------ collection


@dataclass
class RepoSnapshot:
    full_name: str
    github_id: int
    default_branch: str
    head_sha: str | None
    visibility: str
    archived: bool = False
    provider: str = "github"
    producer: str = PRODUCER
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)  # type → summary
    gaps: dict[str, str] = field(default_factory=dict)  # type → why it was not produced
    secret_alerts: list[dict[str, Any]] = field(default_factory=list)
    documents: dict[str, Any] = field(default_factory=dict)  # parsed .security files (for onboarding)


def _yaml(text: str | None) -> Any:
    return None if text is None else yaml.safe_load(text)


def collect_repository(
    api: GitHubRest,
    full_name: str,
    sensitive_paths: Sequence[str] = (".github/workflows/", ".security/"),
) -> RepoSnapshot:
    repo = api.get(f"/repos/{full_name}")
    branch = repo["default_branch"]
    head = None
    try:
        head = api.get(f"/repos/{full_name}/commits/{branch}")["sha"]
    except Unavailable:
        pass
    except httpx.HTTPStatusError as e:  # 409: empty repository, no commits yet
        if e.response.status_code != 409:
            raise
    snap = RepoSnapshot(
        full_name, int(repo["id"]), branch, head, repo.get("visibility", "private"), bool(repo.get("archived"))
    )

    def attempt(etype: str, fn: Callable[[], dict[str, Any]]) -> None:
        try:
            snap.evidence[etype] = fn()
        except Unavailable as e:
            snap.gaps[etype] = str(e)

    def rules() -> dict[str, Any]:
        branch_rules = list(api.pages(f"/repos/{full_name}/rules/branches/{branch}"))
        try:
            classic = api.get(f"/repos/{full_name}/branches/{branch}/protection")
        except Unavailable:
            classic = None  # 404 = no classic protection; rulesets above still apply
        return summarise_rules(branch_rules, classic)

    def codeowners() -> dict[str, Any]:
        content = None
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            content = api.file(full_name, path, branch)
            if content is not None:
                break
        if content is None:
            return {"present": False, "errors": 0, "covered_paths": []}
        errors = api.get(f"/repos/{full_name}/codeowners/errors", {"ref": branch}).get("errors", [])
        return {
            "present": True,
            "errors": len(errors),
            "covered_paths": codeowners_coverage(parse_codeowners(content), sensitive_paths),
        }

    def access() -> dict[str, Any]:
        outside = list(api.pages(f"/repos/{full_name}/collaborators", {"affiliation": "outside", "permission": "push"}))
        admins = list(api.pages(f"/repos/{full_name}/collaborators", {"affiliation": "direct", "permission": "admin"}))
        return {
            "outside_writers": len(outside),
            "admin_users": len(admins),
            "visibility": snap.visibility,
            "archived": snap.archived,
        }

    def environments() -> dict[str, Any]:
        envs = api.get(f"/repos/{full_name}/environments").get("environments", [])
        names = [s["name"] for s in api.pages(f"/repos/{full_name}/actions/secrets", key="secrets")]
        env_names = {
            e["name"]: [
                s["name"] for s in api.pages(f"/repos/{full_name}/environments/{e['name']}/secrets", key="secrets")
            ]
            for e in envs
        }
        return summarise_environments(envs, names, env_names)

    def actions_policy() -> dict[str, Any]:
        perms = api.get(f"/repos/{full_name}/actions/permissions")
        wf = api.get(f"/repos/{full_name}/actions/permissions/workflow")
        return {
            "enabled": bool(perms.get("enabled")),
            "allowed_actions": perms.get("allowed_actions"),
            "sha_pinning_required": bool(perms.get("sha_pinning_required")),
            "default_workflow_permissions": wf.get("default_workflow_permissions"),
            "can_approve_pull_request_reviews": bool(wf.get("can_approve_pull_request_reviews")),
        }

    def secrets() -> dict[str, Any]:
        alerts = list(api.pages(f"/repos/{full_name}/secret-scanning/alerts", {"state": "open"}))
        snap.secret_alerts = alerts
        return {
            "open_alerts": len(alerts),
            "active": sum(1 for a in alerts if a.get("validity") == "active"),
            "push_protection_bypassed": sum(1 for a in alerts if a.get("push_protection_bypassed")),
        }

    attempt("repo.ruleset", rules)
    attempt("repo.security_settings", lambda: summarise_security(repo))
    attempt("repo.codeowners", codeowners)
    attempt("repo.access", access)
    attempt("repo.environments", environments)
    attempt("repo.actions_policy", actions_policy)
    attempt("scan.secrets", secrets)

    # repository contract files (parsed here; validated and summarised by the sync service, which knows the registry)
    for name in (
        "application.yaml",
        "asvs.yaml",
        "threat-model/threats.yaml",
        "threat-model/mitigations.yaml",
        "threat-model/residual-risk.yaml",
    ):
        try:
            snap.documents[name] = _yaml(api.file(full_name, f".security/{name}", branch))
        except (Unavailable, yaml.YAMLError) as e:
            snap.documents[name] = None
            snap.gaps[f".security/{name}"] = str(e)[:200]
    try:
        snap.documents["SECURITY.md"] = (
            any(
                api.file(full_name, p, branch) is not None
                for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
            )
            or api.file(f"{full_name.split('/')[0]}/.github", "SECURITY.md") is not None
        )
    except Unavailable:
        snap.documents["SECURITY.md"] = False
    return snap
