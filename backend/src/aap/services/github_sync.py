# SPDX-License-Identifier: Apache-2.0
"""Write a GitHub repository snapshot into the evidence ledger (E06-F03, E08-F01-S02).

Unregistered repositories are recorded as discovered (no evidence about applications that do not exist yet).
Registered ones get one evidence record per produced type; gaps are returned so the connector run can report them.
Open secret-scanning alerts become findings (`ghas` / `secret`); an alert no longer open is closed by the same scan
evidence (closure requires evidence, schema test T4).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import jsonschema
from sqlalchemy import Connection, text

from aap.config import ConfigBundle, repo_root
from aap.connectors.github_settings import (
    GitHubRest,
    OwnerResolution,
    RepoSnapshot,
    Unavailable,
    summarise_application,
    summarise_threat_model,
)
from aap.store import evidence_store, findings_store, jobs, registry

C3_TYPES = {"scan.secrets"}  # GitHub executed these scans itself: execution evidence, not configuration


@dataclass
class SyncResult:
    repository: str
    registered: bool
    written: list[str] = field(default_factory=list)
    gaps: dict[str, str] = field(default_factory=dict)
    findings_opened: int = 0
    findings_closed: int = 0


def _schema(name: str) -> dict[str, Any]:
    return dict(json.loads((repo_root() / "schemas" / "repo-contract" / name).read_text()))


def _errors(doc: Any, schema: dict[str, Any]) -> list[str]:
    if doc is None:
        return ["file missing"]
    v = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"[:200] for e in v.iter_errors(doc)]


def _tier_asvs_level(bundle: ConfigBundle, tier_rank: int | None) -> int | None:
    if tier_rank is None:
        return None
    for t in bundle.doc("classification")["tiers"]:
        if t["rank"] == tier_rank:
            return int(str(t["asvs_target"])[1])
    return None


def owner_resolution(
    conn: Connection,
    api: GitHubRest | None,
    refs: list[str],
    provider: str = "github",
    team_exists: Callable[[str], bool] | None = None,
) -> OwnerResolution:
    """`@login` → an identity of this provider; `@group/team` → `team_exists` (GitLab) or the GitHub teams API."""
    res = OwnerResolution()
    logins = conn.execute(
        text("""SELECT lower(i.login) l FROM user_identities i JOIN users u ON u.id = i.user_id
                WHERE u.active AND i.provider = :p AND i.login IS NOT NULL"""),
        {"p": provider},
    ).all()
    emails = conn.execute(text("SELECT lower(email) e FROM users WHERE active AND email IS NOT NULL")).all()
    res.user_logins = {r.l for r in logins}
    res.user_emails = {r.e for r in emails}
    for ref in refs:
        if ref and ref.startswith("@") and "/" in ref and team_exists is not None:
            if team_exists(ref[1:]):
                res.team_slugs.add(ref[1:].lower())
        elif ref and ref.startswith("@") and "/" in ref and api is not None:
            org, slug = ref[1:].split("/", 1)
            try:
                team = api.get(f"/orgs/{org}/teams/{slug}")
                if int(team.get("members_count", 0)) > 0:
                    res.team_slugs.add(ref[1:].lower())
            except Unavailable:
                pass
    return res


def sync_repository(
    conn: Connection,
    bundle: ConfigBundle,
    snap: RepoSnapshot,
    now: datetime,
    api: GitHubRest | None = None,
    team_exists: Callable[[str], bool] | None = None,
) -> SyncResult:
    """Provider-neutral: GitHub and GitLab snapshots (snap.provider) are written the same way."""
    target = registry.application_by_repo(conn, snap.github_id, snap.provider)
    registry.upsert_repository(
        conn,
        snap.github_id,
        snap.full_name,
        snap.visibility,
        snap.default_branch,
        snap.head_sha,
        detected={"security_files": sorted(k for k, v in snap.documents.items() if v)},
        provider=snap.provider,
    )
    result = SyncResult(snap.full_name, target is not None, gaps=dict(snap.gaps))
    if target is None:
        return result
    app_id = str(target["application_id"])
    subject = {
        "repository": snap.full_name,
        "provider": snap.provider,
        "external_id": snap.github_id,
        "commit_sha": snap.head_sha,
    }

    def write(
        etype: str,
        summary: dict[str, Any],
        scope_type: str = "repository",
        scope_ref: str | None = None,
        subj: dict[str, Any] | None = None,
    ) -> str:
        confidence = "C3" if etype in C3_TYPES else "C1"
        ev_id = evidence_store.insert_evidence(
            conn,
            evidence_store.NewEvidence(
                evidence_type=etype,
                application_id=app_id,
                scope_type=scope_type,
                scope_ref=scope_ref or snap.full_name,
                subject=subj or subject,
                producer_type="platform_connector",
                producer_ref=snap.producer,
                observed_at=now,
                result="observed",
                confidence=confidence,
                tool="github" if etype in C3_TYPES else None,
                summary=summary,
                confidence_reasons=["authoritative_api"] + (["platform_executed"] if etype in C3_TYPES else []),
            ),
        )
        result.written.append(etype)
        return str(ev_id)

    for etype, summary in snap.evidence.items():
        ev_id = write(etype, summary)
        if etype == "scan.secrets":
            seen = []
            for alert in snap.secret_alerts:
                fp = f"secret:github:{snap.github_id}:{alert['number']}"
                seen.append(fp)
                loc = alert.get("first_location_detected") or {}
                _, outcome = findings_store.observe(
                    conn,
                    findings_store.NewFinding(
                        fingerprint=fp,
                        application_id=app_id,
                        repository_id=str(target["repository_id"]),
                        scope_type="repository",
                        scope_ref=snap.full_name,
                        finding_type="secret",
                        source_system="ghas",
                        title=f"{alert.get('secret_type_display_name') or alert.get('secret_type')} exposed",
                        description="GitHub secret scanning. Rotate the credential, then resolve the alert as revoked.",
                        location={
                            "uri": loc.get("path"),
                            "line": loc.get("start_line"),
                            "validity": alert.get("validity"),
                        },
                        tool_severity="critical" if alert.get("validity") in ("active", "unknown", None) else "high",
                        source_refs=[
                            {
                                "system": "ghas",
                                "id": f"secret-scanning-alert-{alert['number']}",
                                "url": alert.get("html_url"),
                            }
                        ],
                    ),
                    ev_id,
                    now,
                )
                result.findings_opened += outcome in ("created", "reopened")
            result.findings_closed += len(
                findings_store.close_absent(
                    conn,
                    scope_ref=snap.full_name,
                    finding_type="secret",
                    source_system="ghas",
                    seen=seen,
                    evidence_id=ev_id,
                )
            )

    # threat model structure (commit-bound to the threat-model files)
    docs = snap.documents
    if docs.get("threat-model/threats.yaml") is not None:
        tm_schema = _schema("threat-model.schema.json")
        errs = []
        for name, part in (
            ("threats.yaml", "threatsFile"),
            ("mitigations.yaml", "mitigationsFile"),
            ("residual-risk.yaml", "residualRiskFile"),
        ):
            doc = docs.get(f"threat-model/{name}")
            if doc is not None:
                sub = {"$schema": tm_schema.get("$schema"), "$defs": tm_schema["$defs"], "$ref": f"#/$defs/{part}"}
                errs += [f"{name}: {e}" for e in _errors(doc, sub)]
        write(
            "repo.threat_model",
            summarise_threat_model(
                docs.get("threat-model/threats.yaml"),
                docs.get("threat-model/mitigations.yaml"),
                docs.get("threat-model/residual-risk.yaml"),
                errs,
            ),
        )

    # application.yaml is authoritative only in the application's source repository
    app = conn.execute(
        text(
            """SELECT a.app_key, a.tier_rank, a.source_repo_id,
                 (SELECT array_agg(r.full_name) FROM application_repositories ar
                  JOIN repositories r ON r.id = ar.repository_id WHERE ar.application_id = a.id) repos
               FROM applications a WHERE a.id = :a"""
        ),
        {"a": app_id},
    ).first()
    if app is not None and str(app.source_repo_id) == str(target["repository_id"]):
        app_doc, asvs_doc = docs.get("application.yaml"), docs.get("asvs.yaml")
        errs = _errors(app_doc, _schema("application.schema.json"))
        if asvs_doc is not None:
            errs += [f"asvs.yaml: {e}" for e in _errors(asvs_doc, _schema("asvs.schema.json"))]
        owners = ((app_doc or {}).get("application") or {}).get("owners") or {}
        res = owner_resolution(conn, api, [str(v) for v in owners.values() if v], snap.provider, team_exists)
        write(
            "registry.application",
            summarise_application(
                app_doc,
                asvs_doc,
                errs,
                res,
                bool(docs.get("SECURITY.md")),
                {r for r in (app.repos or []) if r != snap.full_name},
                _tier_asvs_level(bundle, app.tier_rank),
            ),
            scope_type="application",
            scope_ref=app.app_key,
            subj={**subject, "files": [".security/application.yaml", ".security/asvs.yaml"]},
        )
    return result


def registered_repositories(conn: Connection, org: str) -> list[tuple[str, str]]:
    """(full name, external id) of the organization's GitHub repositories linked to an application."""
    rows = conn.execute(
        text("""SELECT DISTINCT r.full_name, r.external_id FROM repositories r
                JOIN application_repositories ar ON ar.repository_id = r.id
                WHERE r.provider = 'github' AND NOT r.archived AND r.full_name LIKE :o ORDER BY r.full_name"""),
        {"o": f"{org}/%"},
    )
    return [(str(r.full_name), str(r.external_id)) for r in rows]


def reconcile_runs(
    conn: Connection, api: Any, repo_full_name: str, repo_external_id: str, since: datetime, limit: int = 100
) -> int:
    """Queue ingestion for completed workflow runs since `since` that left neither evidence nor a rejection: what a
    missed `workflow_run` webhook would have queued (receiver down, delivery failed, or no public endpoint). Ingestion
    is idempotent, so a run that legitimately produced nothing is only looked at again while it is inside the window.
    Returns the number of runs queued."""
    queued = 0
    params = {"status": "completed", "created": f">={since:%Y-%m-%dT%H:%M:%SZ}"}
    for run in api.pages(f"/repos/{repo_full_name}/actions/runs", params, key="workflow_runs"):
        run_id = int(run["id"])
        seen = conn.execute(
            text("""SELECT EXISTS (SELECT 1 FROM evidence WHERE ingested_at >= :floor AND run_ref->>'run_id' = :r)
                        OR EXISTS (SELECT 1 FROM evidence_rejections WHERE run_id = :n)"""),
            {"floor": since - timedelta(days=1), "r": str(run_id), "n": run_id},
        ).scalar()
        if seen:
            continue
        payload = {
            "provider": "github",
            "repo_external_id": int(repo_external_id),
            "repo": repo_full_name,
            "run_id": run_id,
        }
        if jobs.enqueue(conn, "ingest", payload, dedup_key=f"run:{repo_external_id}:{run_id}") is not None:
            queued += 1
        if queued >= limit:
            break
    return queued
