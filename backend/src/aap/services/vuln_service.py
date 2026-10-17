# SPDX-License-Identifier: Apache-2.0
"""Turn component ↔ advisory matches into dependency findings (one per vulnerable package per SBOM scope)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Connection, text

from aap.domain import fingerprints
from aap.store import findings_store


def raise_dependency_findings(conn: Connection, vulnerability_id: str, now: datetime) -> int:
    rows = (
        conn.execute(
            text("""SELECT s.application_id, s.repository_id, s.scope_key, s.evidence_id, c.id AS component_id, c.purl,
                       sc.scope, v.vuln_key, v.aliases, v.title, v.cwe_ids, v.cvss_v3_score, cv.fixed_versions,
                       cv.source
                FROM component_vulnerabilities cv
                JOIN vulnerabilities v ON v.id = cv.vulnerability_id
                JOIN components c ON c.id = cv.component_id
                JOIN sbom_components sc ON sc.component_id = c.id
                JOIN sboms s ON s.id = sc.sbom_id AND s.is_current
                WHERE cv.vulnerability_id = :v"""),
            {"v": vulnerability_id},
        )
        .mappings()
        .all()
    )
    created = 0
    for r in rows:
        ids = [r["vuln_key"], *r["aliases"]]
        severity = (
            "critical" if (r["cvss_v3_score"] or 0) >= 9 else "high" if (r["cvss_v3_score"] or 0) >= 7 else "medium"
        )
        fixed = ", ".join(r["fixed_versions"]) or "none published"
        _, status = findings_store.observe(
            conn,
            findings_store.NewFinding(
                fingerprint=fingerprints.dependency(r["scope_key"], r["purl"], ids),
                application_id=str(r["application_id"]),
                repository_id=str(r["repository_id"]) if r["repository_id"] else None,
                scope_type="repository",
                scope_ref=r["scope_key"],
                finding_type="dependency",
                source_system=r["source"] if r["source"] in ("osv", "dependency_track") else "platform",
                title=f"{r['vuln_key']} in {fingerprints.purl_without_version(r['purl'])}: {r['title'] or ''}"[:300],
                description=f"{r['purl']} is affected by {r['vuln_key']}. Fixed in: {fixed}.",
                cwe_id=(r["cwe_ids"] or [None])[0],
                vulnerability_id=vulnerability_id,
                component_id=str(r["component_id"]),
                location={
                    "purl": r["purl"],
                    "component_scope": r["scope"],
                    "fixed_versions": list(r["fixed_versions"]),
                },
                tool_severity=severity,
                source_refs=[{"system": r["source"], "id": r["vuln_key"]}],
            ),
            str(r["evidence_id"]),
            now,
        )
        created += status == "created"
    return created
