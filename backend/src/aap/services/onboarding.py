# SPDX-License-Identifier: Apache-2.0
"""Register an application from its repository contract (.security/application.yaml + asvs.yaml).

register(): validate the contract, resolve the owning unit and the owners, compute the tier with the active
            classification profile, create the application, link its primary repository, record the classification
            (Tier 1/2 → pending AppSec approval; Tier 3/4 → auto-approved, CLS-02) and queue the onboarding job.
decide():   approve or reject a pending classification. The ledger is append-only: a decision is a new row that
            supersedes the pending one. Segregation of duties: the decider is neither the requester nor a member of
            the owning unit, a unit below it, or a unit above it (other than the organization root).

Runs under the caller's database role: through the API that is `aap_api` with the caller's row-level-security
scope, so a team can only register applications into units it belongs to.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import jsonschema
from sqlalchemy import Connection, text

from aap.config import ConfigBundle, repo_root
from aap.domain.classification import ClassificationError, classify
from aap.store import jobs, registry

HUMAN_APPROVAL_TIERS = (1, 2)


class OnboardingError(ValueError):
    def __init__(self, problems: list[str], status: int = 422):
        super().__init__("; ".join(problems))
        self.problems, self.status = problems, status


class SodViolationError(OnboardingError):
    def __init__(self, detail: str):
        super().__init__([detail], 403)


@dataclass(frozen=True)
class RepoRef:
    provider: str
    external_id: str
    full_name: str
    visibility: str = "private"
    default_branch: str = "main"
    head_sha: str | None = None


@dataclass
class Registered:
    application_id: str
    app_key: str
    tier: int
    decision: str
    explanation: str
    matched_floor_rules: list[str] = field(default_factory=list)


def _schema_errors(doc: Any, name: str) -> list[str]:
    schema = json.loads((repo_root() / "schemas" / "repo-contract" / name).read_text())
    v = jsonschema.Draft202012Validator(schema)
    out = []
    for e in v.iter_errors(doc):
        leaves = [e]
        if e.context:  # oneOf/anyOf repeats the whole document: report the branch the author evidently meant
            branches: dict[Any, list[Any]] = {}
            for c in e.context:
                branches.setdefault(c.relative_schema_path[0], []).append(c)
            leaves = min(branches.values(), key=len)
        for leaf in leaves:
            where = "/".join(map(str, leaf.absolute_path)) or "(root)"
            out.append(f"{name.split('.')[0]}: {where}: {leaf.message}"[:240])
    return out


def _user_by_ref(conn: Connection, ref: str | None) -> str | None:
    """`@login` → an SCM identity; an email address → users.email. Teams (`@org/team`) are not people."""
    if not ref:
        return None
    ref = ref.strip()
    if ref.startswith("@") and "/" not in ref:
        row = conn.execute(
            text("""SELECT user_id FROM user_identities WHERE provider NOT LIKE 'oidc:%'
                    AND lower(login) = lower(:l) LIMIT 1"""),
            {"l": ref[1:]},
        ).first()
    elif "@" in ref and not ref.startswith("@"):
        row = conn.execute(
            text("SELECT id AS user_id FROM users WHERE lower(email) = lower(:e) AND active LIMIT 1"), {"e": ref}
        ).first()
    else:
        return None
    return str(row.user_id) if row else None


def register(
    conn: Connection,
    bundle: ConfigBundle,
    *,
    repo: RepoRef,
    app_doc: Any,
    asvs_doc: Any = None,
    requested_by: str | None = None,
) -> Registered:
    problems = _schema_errors(app_doc, "application.schema.json")
    if asvs_doc is not None:
        problems += _schema_errors(asvs_doc, "asvs.schema.json")
    if problems:
        raise OnboardingError(problems)
    app = app_doc["application"]
    unit_slug = (app.get("owners") or {}).get("org_unit")
    unit = conn.execute(text("SELECT id, unit_type FROM org_units WHERE slug = :s"), {"s": unit_slug}).first()
    if unit is None:
        raise OnboardingError([f"owners.org_unit {unit_slug!r} is not a unit in this organization"])
    existing = registry.application_by_repo(conn, repo.external_id, repo.provider)
    if existing is not None:
        key = conn.execute(
            text("SELECT app_key FROM applications WHERE id = :a"), {"a": existing["application_id"]}
        ).scalar()
        raise OnboardingError([f"{repo.full_name} is already registered as {key}"], 409)

    inputs = dict(app["classification"])
    try:
        result = classify(inputs, bundle.doc("classification"))
    except ClassificationError as e:
        raise OnboardingError([f"classification: {e}"]) from e
    owners = app.get("owners") or {}
    profile = {
        **(app.get("profile") or {}),
        "classification": inputs,
        "environments": app.get("environments") or [],
        "declared_repositories": app.get("repositories") or [],
        "asvs_target_level": (asvs_doc or {}).get("target_level"),
        "asvs_capabilities": (asvs_doc or {}).get("capabilities") or {},
    }
    app_id, app_key = registry.create_application(
        conn,
        registry.NewApplication(
            name=app["name"],
            description=app["description"],
            org_unit_id=str(unit.id),
            lifecycle=app["lifecycle"],
            exposure=inputs["exposure"],
            data_classification=inputs["data_classification"],
            personal_data=inputs["personal_data"],
            profile=profile,
            business_owner_id=_user_by_ref(conn, owners.get("business_owner")),
            technical_owner_id=_user_by_ref(conn, owners.get("technical_owner")),
            champion_id=_user_by_ref(conn, owners.get("security_champion")),
        ),
    )
    repo_id = registry.upsert_repository(
        conn,
        repo.external_id,
        repo.full_name,
        repo.visibility,
        repo.default_branch,
        repo.head_sha,
        provider=repo.provider,
    )
    registry.link_repository(conn, app_id, repo_id, "primary")
    decision = "pending" if result.tier in HUMAN_APPROVAL_TIERS else "auto_approved"
    registry.record_classification(
        conn,
        app_id,
        bundle.documents["classification"].version,
        inputs,
        result,
        decision,
        None,
        requested_by=requested_by,
    )
    jobs.enqueue(conn, "onboarding", {"application_id": app_id}, dedup_key=f"onboarding:{app_id}")
    return Registered(app_id, app_key, result.tier, decision, result.explanation, list(result.matched_floor_rules))


def sod_problem(conn: Connection, application_id: str, requested_by: Any, decider: str) -> str | None:
    """Why `decider` may not decide this application's classification (segregation of duties), or None."""
    if requested_by is not None and str(requested_by) == str(decider):
        return "you requested this classification yourself; another person must decide it"
    owning_team_member = conn.execute(
        # the owning unit, every unit below it, and every unit above it except the organization root
        text("""WITH RECURSIVE owning AS (SELECT a.org_unit_id AS id FROM applications a WHERE a.id = :a),
                below AS (SELECT id FROM owning UNION SELECT o.id FROM org_units o JOIN below b ON o.parent_id = b.id),
                above AS (SELECT o.id, o.parent_id FROM org_units o JOIN owning w ON o.id = w.id
                          UNION SELECT o.id, o.parent_id FROM org_units o JOIN above x ON o.id = x.parent_id),
                units AS (SELECT id FROM below UNION SELECT id FROM above WHERE parent_id IS NOT NULL)
                SELECT 1 FROM org_unit_members m JOIN units u ON u.id = m.org_unit_id WHERE m.user_id = :u LIMIT 1"""),
        {"a": application_id, "u": decider},
    ).first()
    if owning_team_member:
        return "you are a member of the team that owns this application; AppSec must decide it"
    return None


def decide(
    conn: Connection, bundle: ConfigBundle, application_id: str, *, decision: str, decided_by: str, reason: str = ""
) -> dict[str, Any]:
    if decision not in ("approved", "rejected"):
        raise OnboardingError(["decision must be approved or rejected"])
    pending = (
        conn.execute(
            text("""SELECT c.* FROM application_classifications c WHERE c.application_id = :a
                AND NOT EXISTS (SELECT 1 FROM application_classifications s WHERE s.supersedes_id = c.id)
                ORDER BY c.created_at DESC LIMIT 1"""),
            {"a": application_id},
        )
        .mappings()
        .first()
    )
    if pending is None or pending["decision"] != "pending":
        raise OnboardingError(["no classification is waiting for a decision"], 409)
    problem = sod_problem(conn, application_id, pending["requested_by"], decided_by)
    if problem:
        raise SodViolationError(problem)
    result = classify(pending["inputs"], bundle.doc("classification"))
    new_id = registry.record_classification(
        conn,
        application_id,
        pending["model_version"],
        pending["inputs"],
        result,
        decision,
        decided_by,
        supersedes_id=str(pending["id"]),
        requested_by=str(pending["requested_by"]) if pending["requested_by"] else None,
    )
    jobs.enqueue(conn, "onboarding", {"application_id": application_id}, dedup_key=f"onboarding:{application_id}")
    return {"classification_id": new_id, "decision": decision, "tier": result.tier}


def github_api(full_name: str) -> Any:
    """A read-only GitHub client for the repository's owner (the GitHub plugin), or a 422 telling the caller how to
    register without one."""
    import os

    from aap.connectors.github_settings import GitHubRest
    from aap.integrations import github_auth
    from aap.secrets import secret_store

    if not os.environ.get("AAP_GITHUB_APP_CLIENT_ID"):
        raise OnboardingError(
            ["the GitHub plugin is not configured: provide the contract files and the repository id instead"]
        )
    auth = github_auth(secret_store())
    return GitHubRest(
        auth.token_provider(full_name.split("/")[0]),
        base_url=os.environ.get("AAP_GITHUB_API", "https://api.github.com"),
    )


def fetch_contract(api: Any, full_name: str) -> tuple[RepoRef, Any, Any]:
    """Read the repository's identity and its contract files through the SCM plugin (read-only GitHub App)."""
    import httpx
    import yaml

    from aap.connectors.github_settings import Unavailable

    try:
        repo = api.get(f"/repos/{full_name}")
    except Unavailable as e:
        raise OnboardingError([f"{full_name}: not visible to the GitHub App ({e}); install the App on it"], 404) from e
    branch = repo["default_branch"]
    head = None
    try:
        head = api.get(f"/repos/{full_name}/commits/{branch}")["sha"]
    except Unavailable:
        pass
    except httpx.HTTPStatusError as e:  # 409 "Git Repository is empty": no commits yet, nothing to bind to
        if e.response.status_code != 409:
            raise
    raw_app = api.file(full_name, ".security/application.yaml", branch)
    if raw_app is None:
        raise OnboardingError([f"{full_name} has no .security/application.yaml on {branch} (templates/repo-contract)"])
    raw_asvs = api.file(full_name, ".security/asvs.yaml", branch)
    try:
        app_doc = yaml.safe_load(raw_app)
        asvs_doc = yaml.safe_load(raw_asvs) if raw_asvs else None
    except yaml.YAMLError as e:
        raise OnboardingError([f"contract files are not valid YAML: {str(e)[:200]}"]) from e
    ref = RepoRef("github", str(repo["id"]), repo["full_name"], repo.get("visibility", "private"), branch, head)
    return ref, app_doc, asvs_doc


def record_classification_evidence(conn: Connection, application_id: str, now: datetime) -> str | None:
    """Worker side of onboarding: the current classification decision becomes `registry.classification` evidence
    (producer platform:workflow-engine). M2 when a person decided it (independent of the requester), M1 when the
    profile auto-approved it; a pending or rejected classification is recorded too, so the control shows why it
    is not satisfied instead of 'no evidence'. Returns the evidence id, or None if there is no classification."""
    from aap.store import evidence_store

    row = conn.execute(
        text("""SELECT c.id, c.computed_tier, c.decision, c.model_version, c.decided_by, a.app_key
                FROM application_classifications c JOIN applications a ON a.id = c.application_id
                WHERE c.application_id = :a
                  AND NOT EXISTS (SELECT 1 FROM application_classifications s WHERE s.supersedes_id = c.id)
                ORDER BY c.created_at DESC LIMIT 1"""),
        {"a": application_id},
    ).first()
    if row is None:
        return None
    human = row.decision in ("approved", "rejected")
    eid = evidence_store.insert_evidence(
        conn,
        evidence_store.NewEvidence(
            evidence_type="registry.classification",
            application_id=application_id,
            scope_type="application",
            scope_ref=row.app_key,
            subject={"classification_id": str(row.id), "model_version": row.model_version},
            producer_type="platform_connector",
            producer_ref="platform:workflow-engine",
            observed_at=now,
            result={"approved": "pass", "auto_approved": "pass", "rejected": "fail"}.get(row.decision, "inconclusive"),
            confidence="M2" if human else "M1",
            summary={"tier": row.computed_tier, "decision": row.decision},
            confidence_reasons=["reviewer_independent"] if human else ["rule_based"],
        ),
    )
    return str(eid)


def gitlab_api() -> Any:
    import os

    from aap.integrations import gitlab_client
    from aap.secrets import secret_store

    if not os.environ.get("AAP_GITLAB_URL"):
        raise OnboardingError(
            ["the GitLab plugin is not configured: provide the contract files and the project id instead"]
        )
    return gitlab_client(secret_store())


def fetch_contract_gitlab(api: Any, path: str) -> tuple[RepoRef, Any, Any]:
    """GitLab: the project (by path), its default branch head, and the contract files on that branch."""
    import yaml

    from aap.connectors.github_settings import Unavailable

    try:
        project = api.project(path)
    except Unavailable as e:
        raise OnboardingError([f"{path}: not visible to the platform's GitLab token ({e})"], 404) from e
    branch = project.get("default_branch") or "main"
    head = None
    with contextlib.suppress(Unavailable):
        head = api.get(f"/projects/{project['id']}/repository/commits/{api.pid(branch)}")["id"]
    raw_app = api.file(project["id"], ".security/application.yaml", branch)
    if raw_app is None:
        raise OnboardingError([f"{path} has no .security/application.yaml on {branch} (templates/repo-contract)"])
    raw_asvs = api.file(project["id"], ".security/asvs.yaml", branch)
    try:
        app_doc = yaml.safe_load(raw_app)
        asvs_doc = yaml.safe_load(raw_asvs) if raw_asvs else None
    except yaml.YAMLError as e:
        raise OnboardingError([f"contract files are not valid YAML: {str(e)[:200]}"]) from e
    ref = RepoRef(
        "gitlab", str(project["id"]), project["path_with_namespace"], project.get("visibility", "private"), branch, head
    )
    return ref, app_doc, asvs_doc
