# SPDX-License-Identifier: Apache-2.0
"""Pull-based evidence ingestion (ADR-005, evidence model §4). Triggered by a `workflow_run.completed` webhook.

    run metadata from GitHub  →  download aap-evidence-* artifacts (size-limited)  →  safe unzip
    →  manifest schema check  →  verify_bundle (approved workflow @ approved SHA, binding, digests, attestation)
    →  reject: evidence_rejections + audit trail
    →  accept: raw files to write-once store → evidence ledger → findings (SARIF) / inventory (SBOM)
              → close findings a default-branch re-scan no longer reports → enqueue control re-evaluation

Nothing from the webhook payload is trusted beyond the repository and run identifiers.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import jsonschema
from sqlalchemy import Connection, text

from aap.blobstore import EvidenceBlobStore
from aap.config import ConfigBundle, repo_root
from aap.connectors.github import GitHubClient, sha256_hex
from aap.domain import fingerprints
from aap.domain.evidence import Limits, TrustedWorkflows, Verdict, verify_bundle
from aap.ingest.parsers import BundleError, load_json, parse_junit, parse_sarif, safe_unzip, sbom_summary
from aap.store import evidence_store, findings_store, jobs, registry, supply_chain

MANIFEST = "evidence-manifest.json"
ARTIFACT_PREFIX = "aap-evidence-"
FINDING_TYPES = {"scan.sast": "code", "scan.iac": "iac", "scan.container": "container"}


@dataclass
class IngestOutcome:
    accepted: list[str] = field(default_factory=list)  # evidence ids
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (artifact, reason)
    findings_created: int = 0
    findings_closed: int = 0
    skipped: str | None = None


@lru_cache(maxsize=1)
def _manifest_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads((repo_root() / "schemas/evidence/evidence-manifest.schema.json").read_text())
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def manifest_errors(manifest: Any) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in _manifest_validator().iter_errors(manifest)
    ][:10]


def ingest_workflow_run(
    conn: Connection,
    *,
    github: GitHubClient,
    blobs: EvidenceBlobStore,
    bundle: ConfigBundle,
    trusted: TrustedWorkflows,
    repo_full_name: str,
    repo_external_id: int | str,
    provider: str = "github",
    run_id: int,
    limits: Limits | None = None,
) -> IngestOutcome:
    limits = limits or Limits()
    out = IngestOutcome()
    target = registry.application_by_repo(conn, repo_external_id, provider)
    if target is None:
        out.skipped = "repository is not linked to a registered application (discovery will raise it)"
        return out

    run = github.workflow_run(repo_full_name, run_id)
    if str(run.repository_id) != str(repo_external_id):
        evidence_store.record_rejection(
            conn,
            provider,
            repo_external_id,
            run_id,
            "BINDING_MISMATCH",
            {"detail": "run belongs to another repository"},
        )
        out.rejected.append(("*", "BINDING_MISMATCH"))
        return out

    for art in github.run_artifacts(repo_full_name, run_id):
        if not art.name.startswith(ARTIFACT_PREFIX) or art.expired:
            continue
        if art.size_in_bytes > limits.max_total_bytes:
            evidence_store.record_rejection(
                conn,
                provider,
                repo_external_id,
                run_id,
                "REJECTED_SIZE",
                {"artifact": art.name, "size": art.size_in_bytes},
            )
            out.rejected.append((art.name, "REJECTED_SIZE"))
            continue
        try:
            files = safe_unzip(
                github.download_artifact(repo_full_name, art.id, limits.max_total_bytes), max_files=limits.max_files + 1
            )
            raw_manifest = files.pop(MANIFEST)
            manifest = load_json(raw_manifest)
        except (BundleError, KeyError, ValueError) as e:
            evidence_store.record_rejection(
                conn,
                provider,
                repo_external_id,
                run_id,
                "SCHEMA_INVALID",
                {"artifact": art.name, "detail": str(e)[:300]},
            )
            out.rejected.append((art.name, "SCHEMA_INVALID"))
            continue

        errors = manifest_errors(manifest)
        attestation = (
            None if errors else github.verify_attestation(repo_full_name, sha256_hex(raw_manifest), raw_manifest)
        )
        verdict = verify_bundle(manifest, files, run, attestation, trusted, errors, limits)
        if not verdict.accepted:
            assert verdict.reason is not None
            evidence_store.record_rejection(
                conn,
                provider,
                repo_external_id,
                run_id,
                verdict.reason.value,
                {
                    "artifact": art.name,
                    "detail": verdict.detail,
                    "referenced_workflows": list(run.referenced_workflows),
                },
            )
            out.rejected.append((art.name, verdict.reason.value))
            continue
        evidence_id = _accept_or_reject(
            conn,
            blobs,
            bundle,
            target,
            manifest,
            raw_manifest,
            files,
            verdict,
            run.run_id,
            out,
            provider,
            repo_external_id,
            art.name,
        )
        if evidence_id:
            out.accepted.append(evidence_id)

    if out.accepted:
        jobs.enqueue(
            conn,
            "evaluate",
            {"application_id": str(target["application_id"])},
            dedup_key=f"evaluate:{target['application_id']}",
        )
    return out


def _accept_or_reject(
    conn: Connection,
    blobs: EvidenceBlobStore,
    bundle: ConfigBundle,
    target: Mapping[str, Any],
    manifest: Mapping[str, Any],
    raw_manifest: bytes,
    files: Mapping[str, bytes],
    verdict: Verdict,
    run_id: int,
    out: IngestOutcome,
    provider: str,
    repo_external_id: int | str,
    artifact: str,
) -> str | None:
    """Accept in a savepoint: content that verified but cannot be parsed (malformed SARIF/SBOM/JUnit) is rejected as
    SCHEMA_INVALID with nothing half-written, instead of failing the whole ingestion job."""
    try:
        with conn.begin_nested():
            return _accept(conn, blobs, bundle, target, manifest, raw_manifest, files, verdict, run_id, out)
    except BundleError as e:
        evidence_store.record_rejection(
            conn, provider, repo_external_id, run_id, "SCHEMA_INVALID", {"artifact": artifact, "detail": str(e)[:300]}
        )
        out.rejected.append((artifact, "SCHEMA_INVALID"))
        return None


def _accept(
    conn: Connection,
    blobs: EvidenceBlobStore,
    bundle: ConfigBundle,
    target: Mapping[str, Any],
    manifest: Mapping[str, Any],
    raw_manifest: bytes,
    files: Mapping[str, bytes],
    verdict: Verdict,
    run_id: int,
    out: IngestOutcome,
) -> str:
    etype = manifest["evidence_type"]
    manifest_uri = blobs.put(raw_manifest)
    for data in files.values():
        blobs.put(data)
    on_default = manifest["ref"] == f"refs/heads/{target['default_branch']}"
    summary: dict[str, Any] = dict(manifest.get("summary") or {})
    summary.update(
        {
            "tool": manifest["tool"]["name"],
            "tool_version": manifest["tool"]["version"],
            "query_suite": summary.get("query_suite") or manifest["tool"].get("policy_ref"),
        }
    )
    sarif = None
    for path, data in files.items():
        if path.endswith(".sarif"):
            parsed, sarif_results = parse_sarif(load_json(data))
            summary.update({k: v for k, v in parsed.items() if k not in ("tool", "tool_version")})
            sarif = sarif_results
        elif etype == "sbom" and path.endswith(".json"):
            bom = load_json(data)
            summary.update(sbom_summary(bom))
        elif etype == "test.security" and path.endswith(".xml"):
            junit = parse_junit(data)
            for k in ("tests", "failures", "skipped"):
                summary[k] = summary.get(k, 0) + junit[k] if isinstance(summary.get(k), int) else junit[k]
            for k in ("asvs", "threats"):
                merged = dict(summary.get(k) or {}) if isinstance(summary.get(k), dict) else {}
                for ref, outcome in junit[k].items():
                    merged[ref] = "fail" if outcome == "fail" or merged.get(ref) == "fail" else "pass"
                summary[k] = merged

    result = manifest["result"]
    if etype == "sbom" and summary.get("quality_problems"):
        result = "inconclusive"  # SBOM Standard SBM-04: below quality threshold never satisfies ASC-BLD-03
    subject = {
        "repo": manifest["repository"]["full_name"],
        "ref": manifest["ref"],
        "commit_sha": manifest["commit_sha"],
        "on_default_branch": on_default,
    }
    if manifest.get("artifact"):
        subject["artifact_digest"] = manifest["artifact"]["digest"]
        subject["artifact_name"] = manifest["artifact"].get("name")
    if manifest.get("environment", {}).get("name"):
        subject["environment"] = manifest["environment"]["name"]
    observed = datetime.fromisoformat(manifest["produced_at"].replace("Z", "+00:00")).astimezone(UTC)
    evidence_id = str(
        evidence_store.insert_evidence(
            conn,
            evidence_store.NewEvidence(
                evidence_type=etype,
                application_id=str(target["application_id"]),
                scope_type="repository",
                scope_ref=manifest["repository"]["full_name"],
                subject=subject,
                producer_type="approved_workflow",
                producer_ref=verdict.producer_ref or "",
                observed_at=min(observed, datetime.now(UTC)),
                result=result,
                confidence=verdict.confidence or "C2",
                tool=manifest["tool"]["name"],
                tool_version=manifest["tool"]["version"],
                policy_ref=manifest["tool"].get("policy_ref"),
                summary=summary,
                confidence_reasons=list(verdict.confidence_reasons),
                run_ref={
                    "run_id": run_id,
                    "attempt": manifest["run"]["attempt"],
                    "event": manifest["run"]["event"],
                    "runner_environment": manifest["run"]["runner_environment"],
                },
                raw_location=manifest_uri,
                raw_sha256=[f["sha256"] for f in manifest["files"]],
            ),
        )
    )

    if sarif is not None and etype in FINDING_TYPES and on_default:
        _apply_sarif(conn, target, manifest, sarif, evidence_id, observed, FINDING_TYPES[etype], out)
    if etype == "sbom" and on_default:
        for path, data in files.items():
            if path.endswith(".json"):
                _licence_evidence(conn, bundle, target, manifest, load_json(data), evidence_id, verdict, observed)
                supply_chain.ingest_cyclonedx(
                    conn,
                    application_id=str(target["application_id"]),
                    repository_id=str(target["repository_id"]),
                    scope_key=f"repo:{manifest['repository']['id']}"
                    if not manifest.get("artifact")
                    else f"artifact:{manifest['artifact'].get('name')}",
                    commit_sha=manifest["commit_sha"],
                    bom=load_json(data),
                    evidence_id=evidence_id,
                    generated_at=observed,
                )
    return evidence_id


def _licence_evidence(
    conn: Connection,
    bundle: ConfigBundle,
    target: Mapping[str, Any],
    manifest: Mapping[str, Any],
    bom: Mapping[str, Any],
    sbom_evidence_id: str,
    verdict: Verdict,
    observed: datetime,
) -> None:
    """Evaluate the SBOM's licences against the central policy; the result is platform-derived evidence whose
    confidence cannot exceed the SBOM it was computed from."""
    from aap.domain import licences
    from aap.domain.sbom import walk_components
    from aap.store.supply_chain import licence_of

    policy = bundle.doc("licence_policy")
    result = licences.evaluate(
        ((c.get("purl", c.get("name", "?")), licence_of(c)) for c in walk_components(bom.get("components") or [])),
        policy,
    )
    evidence_store.insert_evidence(
        conn,
        evidence_store.NewEvidence(
            evidence_type="scan.licence",
            application_id=str(target["application_id"]),
            scope_type="repository",
            scope_ref=manifest["repository"]["full_name"],
            subject={
                "repo": manifest["repository"]["full_name"],
                "commit_sha": manifest["commit_sha"],
                "sbom_evidence_id": sbom_evidence_id,
                "on_default_branch": True,
            },
            producer_type="platform_connector",
            producer_ref="platform:licence-evaluator",
            observed_at=observed,
            result="pass" if result.passes(float(policy["unknown_handling"]["max_unknown_pct"])) else "findings",
            confidence=verdict.confidence or "C2",
            tool="licence-policy",
            tool_version=str(policy["version"]),
            summary={
                "components": result.components,
                "denied": list(result.denied),
                "review": list(result.review),
                "unknown_pct": result.unknown_pct,
            },
            confidence_reasons=["derived_from_sbom"],
        ),
    )


def _apply_sarif(
    conn: Connection,
    target: Mapping[str, Any],
    manifest: Mapping[str, Any],
    results: list[Any],
    evidence_id: str,
    seen_at: datetime,
    finding_type: str,
    out: IngestOutcome,
) -> None:
    repo_id = int(manifest["repository"]["id"])
    tool = manifest["tool"]["name"]
    seen = []
    for r in results:
        fp = (
            fingerprints.code(repo_id, tool, r.rule_id, r.source_key)
            if finding_type == "code"
            else fingerprints.iac(repo_id, r.rule_id, f"{r.uri}:{r.source_key}")
        )
        seen.append(fp)
        _, status = findings_store.observe(
            conn,
            findings_store.NewFinding(
                fingerprint=fp,
                application_id=str(target["application_id"]),
                repository_id=str(target["repository_id"]),
                scope_type="repository",
                scope_ref=manifest["repository"]["full_name"],
                finding_type=finding_type,
                source_system="platform",
                title=f"{r.rule_id}: {r.message}"[:300],
                description=r.message,
                cwe_id=r.cwe,
                location={"uri": r.uri, "line": r.line, "tool": tool},
                tool_severity=r.severity,
                source_refs=[{"system": tool, "id": r.source_key}],
            ),
            evidence_id,
            seen_at,
        )
        out.findings_created += status == "created"
    closed = findings_store.close_absent(
        conn,
        scope_ref=manifest["repository"]["full_name"],
        finding_type=finding_type,
        source_system="platform",
        seen=seen,
        evidence_id=evidence_id,
    )
    out.findings_closed += len(closed)


def ingest_gitlab_job(
    conn: Connection,
    *,
    gitlab: Any,
    blobs: EvidenceBlobStore,
    bundle: ConfigBundle,
    project_id: int,
    job_id: int,
    limits: Limits | None = None,
) -> IngestOutcome:
    """GitLab: one job's artifacts archive may hold several `aap-evidence-<name>/` bundles (ADR-033). Each bundle is
    verified against the job (binding) and the job against the approved component (merged-configuration check)."""
    from aap.connectors.github_settings import Unavailable
    from aap.connectors.gitlab import GitLabComponents, bundles, run_info, trusted_workflows, verify_component_job

    limits = limits or Limits()
    out = IngestOutcome()
    provider = "gitlab"
    target = registry.application_by_repo(conn, project_id, provider)
    if target is None:
        out.skipped = "project is not linked to a registered application (discovery will raise it)"
        return out
    already = conn.execute(
        text("""SELECT 1 FROM evidence WHERE application_id = :a AND producer_type = 'approved_workflow'
                AND run_ref->>'run_id' = :j AND subject->>'repo' IS NOT NULL LIMIT 1"""),
        {"a": target["application_id"], "j": str(job_id)},
    ).first()
    if already:  # polling and webhooks may both deliver a job: ingest it once
        out.skipped = "job already ingested"
        return out
    trusted = GitLabComponents.from_config(bundle.doc("trusted_producers"))
    try:
        job = gitlab.job(project_id, job_id)
        archive = gitlab.artifacts(project_id, job_id, limits.max_total_bytes)
    except Unavailable as e:
        out.skipped = f"job not readable: {e}"
        return out
    try:
        found = bundles(safe_unzip(archive, max_files=limits.max_files * 4))
    except BundleError as e:
        evidence_store.record_rejection(conn, provider, project_id, job_id, "SCHEMA_INVALID", {"detail": str(e)[:300]})
        out.rejected.append(("*", "SCHEMA_INVALID"))
        return out
    if not found:
        out.skipped = "no aap-evidence-* bundle in the job's artifacts"
        return out
    sha = str((job.get("commit") or {}).get("id") or "")
    lint = gitlab.lint(project_id, sha)
    for name, files in found.items():
        try:
            raw_manifest = files.pop(MANIFEST)
            manifest = load_json(raw_manifest)
        except (KeyError, ValueError, BundleError) as e:
            evidence_store.record_rejection(
                conn, provider, project_id, job_id, "SCHEMA_INVALID", {"artifact": name, "detail": str(e)[:300]}
            )
            out.rejected.append((name, "SCHEMA_INVALID"))
            continue
        errors = manifest_errors(manifest)
        check = verify_component_job(
            lint,
            str(job.get("name")),
            str(manifest.get("evidence_type")),
            trusted,
            lambda project, path, ref: gitlab.file(project, path, ref),
        )
        if check.approved_ref is None and not errors:
            # a modified approved component is UNAPPROVED (someone changed it), anything else UNTRUSTED (ADR-033)
            reason = "UNAPPROVED_WORKFLOW_REF" if check.known_component else "UNTRUSTED_PRODUCER"
            evidence_store.record_rejection(
                conn,
                provider,
                project_id,
                job_id,
                reason,
                {"artifact": name, "detail": check.detail, "component_check": check.detail},
            )
            out.rejected.append((name, reason))
            continue
        run = run_info(job, project_id, check)
        verdict = verify_bundle(manifest, files, run, None, trusted_workflows(trusted), errors, limits)
        if not verdict.accepted:
            assert verdict.reason is not None
            evidence_store.record_rejection(
                conn,
                provider,
                project_id,
                job_id,
                verdict.reason.value,
                {"artifact": name, "detail": verdict.detail, "component_check": check.detail},
            )
            out.rejected.append((name, verdict.reason.value))
            continue
        evidence_id = _accept_or_reject(
            conn, blobs, bundle, target, manifest, raw_manifest, files, verdict, job_id, out, provider, project_id, name
        )
        if evidence_id:
            out.accepted.append(evidence_id)
    if out.accepted:
        jobs.enqueue(
            conn,
            "evaluate",
            {"application_id": str(target["application_id"])},
            dedup_key=f"evaluate:{target['application_id']}",
        )
    return out
