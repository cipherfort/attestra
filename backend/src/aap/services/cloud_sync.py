# SPDX-License-Identifier: Apache-2.0
"""Cloud findings → applications (ADR-019, control ASC-OPS-03).

A cloud finding belongs to an application when its resource sits inside one of the app's `cloud_scopes`
(subscription, resource group, AWS account, or tag `k=v`). Each sync writes, per application and provider:
* `cloud.posture` evidence (C3: the cloud provider evaluated the resources), with `max_severity` and counts;
* one finding per open high/critical/medium issue (`cloud`, source defender | security_hub), with risk scoring
  and SLA from the platform risk model;
* closure of findings the provider no longer reports, with the same evidence as proof.
Findings in no mapped scope are counted as `unmapped` in the connector run (a coverage gap, never dropped silently).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.connectors.cloud import SEVERITIES, CloudFinding
from aap.store import evidence_store, findings_store

PRODUCER = {"defender": "connector:defender@1.0.0", "security_hub": "connector:securityhub@1.0.0"}


@dataclass
class CloudReport:
    applications: int = 0
    findings: int = 0
    unmapped: int = 0
    closed: int = 0
    by_app: dict[str, int] = field(default_factory=dict)


def _matches(f: CloudFinding, scope_type: str, scope_ref: str) -> bool:
    ref = scope_ref.lower()
    if scope_type in ("subscription", "resource_group", "management_group") and f.provider == "azure":
        rid = f.resource_id.lower()
        return rid == ref or rid.startswith(ref.rstrip("/") + "/")
    if scope_type == "account" and f.provider == "aws":
        return f.account == scope_ref
    if scope_type == "tag":
        k, _, v = scope_ref.partition("=")
        return (k, v) in f.tags
    return False


def sync(conn: Connection, provider: str, source: str, findings: Iterable[CloudFinding], now: datetime) -> CloudReport:
    rep = CloudReport()
    scopes = conn.execute(
        text("""SELECT cs.application_id, cs.scope_type::text AS scope_type, cs.scope_ref, a.app_key
                FROM cloud_scopes cs JOIN applications a ON a.id = cs.application_id
                WHERE cs.provider::text = :p AND a.lifecycle <> 'retired'"""),
        {"p": provider},
    ).all()
    per_app: dict[str, list[CloudFinding]] = defaultdict(list)
    keys: dict[str, str] = {}
    for f in findings:
        rep.findings += 1
        owners = {str(s.application_id) for s in scopes if _matches(f, s.scope_type, s.scope_ref)}
        if not owners:
            rep.unmapped += 1
        for app in owners:
            per_app[app].append(f)
    for s in scopes:
        keys[str(s.application_id)] = s.app_key
        per_app.setdefault(str(s.application_id), [])  # mapped app with zero findings still gets clean evidence

    for app_id, fs in per_app.items():
        rep.applications += 1
        rep.by_app[keys[app_id]] = len(fs)
        worst = max((SEVERITIES.index(f.severity) for f in fs), default=-1)
        scope_ref = f"{keys[app_id]}:{provider}"
        ev_id = str(
            evidence_store.insert_evidence(
                conn,
                evidence_store.NewEvidence(
                    evidence_type="cloud.posture",
                    application_id=app_id,
                    scope_type="application",
                    scope_ref=keys[app_id],
                    subject={
                        "provider": provider,
                        "scopes": sorted({s.scope_ref for s in scopes if str(s.application_id) == app_id}),
                    },
                    producer_type="platform_connector",
                    producer_ref=PRODUCER[source],
                    observed_at=now,
                    result="pass" if worst < SEVERITIES.index("high") else "fail",
                    confidence="C3",
                    tool=source,
                    summary={
                        "provider": provider,
                        "max_severity": SEVERITIES[worst] if worst >= 0 else "info",
                        "open": len(fs),
                        "by_severity": {sev: sum(1 for f in fs if f.severity == sev) for sev in SEVERITIES},
                    },
                    confidence_reasons=["authoritative_api", "provider_evaluated"],
                ),
            )
        )
        seen = []
        for f in fs:
            fp = f"cloud:{provider}:{f.id}"
            seen.append(fp)
            findings_store.observe(
                conn,
                findings_store.NewFinding(
                    fingerprint=fp,
                    application_id=app_id,
                    repository_id=None,
                    scope_type="application",
                    scope_ref=scope_ref,
                    finding_type="cloud",
                    source_system=source,
                    title=f.title[:300] or "Cloud posture finding",
                    description=f"{source} reports {f.severity} on {f.resource_id}",
                    location={"resource_id": f.resource_id, "account": f.account},
                    tool_severity=f.severity,
                    source_refs=[{"system": source, "id": f.id}],
                ),
                ev_id,
                now,
            )
        rep.closed += len(
            findings_store.close_absent(
                conn, scope_ref=scope_ref, finding_type="cloud", source_system=source, seen=seen, evidence_id=ev_id
            )
        )
    return rep


def unmapped_summary(rep: CloudReport) -> dict[str, Any]:
    return {"unmapped_findings": rep.unmapped} if rep.unmapped else {}
