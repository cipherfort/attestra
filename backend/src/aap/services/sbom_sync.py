# SPDX-License-Identifier: Apache-2.0
"""Current SBOMs ↔ Dependency-Track (ADR-009).

upload: every current SBOM not yet in DT is uploaded (project `<app_key>/<repo>`, version = branch) and its DT
        project UUID recorded on the sbom row.
pull:   DT findings for those projects become platform vulnerabilities (CISA KEV and EPSS from the authoritative
        feeds are preserved), exact-version component matches, and dependency findings with contextual priority.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import Connection, text

from aap.blobstore import EvidenceBlobStore
from aap.connectors.dependency_track import DependencyTrackClient, DependencyTrackError, to_advisory
from aap.services import vuln_service
from aap.store import supply_chain


@dataclass
class DtReport:
    uploaded: int = 0
    findings: int = 0
    vulnerabilities: int = 0
    findings_raised: int = 0
    errors: list[str] = field(default_factory=list)


def _sbom_bytes(conn: Connection, blobs: EvidenceBlobStore, evidence_id: Any) -> bytes | None:
    loc = conn.execute(text("SELECT raw_location FROM evidence WHERE evidence_id = :e"), {"e": evidence_id}).scalar()
    if not loc:
        return None
    manifest = json.loads(blobs.get(loc))
    for f in manifest.get("files", []):
        if f.get("media_type") == "application/vnd.cyclonedx+json" or (
            f.get("media_type") == "application/json" and f["path"].endswith((".cdx.json", "sbom.json", "bom.json"))
        ):
            return blobs.get(f"blob://sha256/{f['sha256']}")
    return None


def upload_current(conn: Connection, dt: DependencyTrackClient, blobs: EvidenceBlobStore, report: DtReport) -> None:
    rows = conn.execute(
        text("""SELECT s.id, s.evidence_id, a.app_key, r.full_name, r.default_branch
                FROM sboms s JOIN applications a ON a.id = s.application_id
                LEFT JOIN repositories r ON r.id = s.repository_id
                WHERE s.is_current AND s.dtrack_project_uuid IS NULL AND r.id IS NOT NULL"""),
    ).all()
    for s in rows:
        name, version = f"{s.app_key}/{s.full_name}", s.default_branch
        try:
            bom = _sbom_bytes(conn, blobs, s.evidence_id)
            if bom is None:
                report.errors.append(f"{name}: SBOM bytes not found in evidence store")
                continue
            dt.wait(dt.upload_bom(name, version, bom))
            project = dt.project(name, version)
            if project is None:
                report.errors.append(f"{name}: project not visible after upload")
                continue
            conn.execute(
                text("UPDATE sboms SET dtrack_project_uuid = CAST(:p AS uuid) WHERE id = :id"),
                {"p": project["uuid"], "id": s.id},
            )
            report.uploaded += 1
        except (DependencyTrackError, httpx.HTTPError) as e:
            report.errors.append(f"{name}: {e}")


def _resolve_key(conn: Connection, adv: dict[str, Any]) -> dict[str, Any]:
    """Reuse an existing vulnerability record that shares any identifier (no CVE/GHSA duplicates)."""
    ids = [adv["id"], *adv["aliases"]]
    row = conn.execute(
        text("SELECT vuln_key, aliases FROM vulnerabilities WHERE vuln_key = ANY(:ids) OR aliases && :ids LIMIT 1"),
        {"ids": ids},
    ).first()
    if row is None or row.vuln_key == adv["id"]:
        return adv
    return {**adv, "id": row.vuln_key, "aliases": sorted((set(ids) | set(row.aliases)) - {row.vuln_key})}


def pull_findings(conn: Connection, dt: DependencyTrackClient, now: datetime, report: DtReport) -> None:
    projects = conn.execute(
        text("SELECT DISTINCT dtrack_project_uuid AS p FROM sboms WHERE is_current AND dtrack_project_uuid IS NOT NULL")
    ).all()
    touched: set[str] = set()
    for p in projects:
        try:
            findings = dt.findings(str(p.p))
        except (DependencyTrackError, httpx.HTTPError) as e:  # one project failing must not stop the rest
            report.errors.append(f"project {p.p}: {e}")
            continue
        report.findings += len(findings)
        for f in findings:
            adv = {**_resolve_key(conn, to_advisory(f)), "source": "dependency_track"}  # who matched it
            vid = supply_chain.upsert_vulnerability(conn, adv)
            supply_chain.match_advisory(conn, adv, vid)
            touched.add(vid)
    report.vulnerabilities = len(touched)
    for vid in touched:
        report.findings_raised += vuln_service.raise_dependency_findings(conn, vid, now)
