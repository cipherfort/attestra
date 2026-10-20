# SPDX-License-Identifier: Apache-2.0
"""A dependency finding closes when a new current SBOM no longer lists the vulnerable component (upgraded or removed),
with that SBOM as the closure evidence. An empty or broken SBOM proves nothing and closes nothing."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from aap.db import transaction
from aap.services import vuln_service
from aap.store import supply_chain

pytestmark = pytest.mark.db

ADVISORY = {
    "id": "CVE-2020-14343",
    "aliases": ["GHSA-8q59-q68h-6hv4"],
    "source": "osv",
    "title": "Improper Input Validation in PyYAML",
    "cwe": [20],
    "cvss_v3_score": 9.8,
    "affected": [{"purl": "pkg:pypi/pyyaml", "ranges": [{"introduced": "0", "fixed": "5.4"}]}],
}


def _bom(*purls: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": p.split("/")[-1].split("@")[0], "version": p.split("@")[-1], "purl": p}
            for p in purls
        ],
    }


def _sbom(conn, app_id: str, scope: str, bom: dict) -> str:
    ev = str(uuid.uuid4())
    repo = conn.execute(
        text("""SELECT r.id FROM repositories r JOIN application_repositories ar ON ar.repository_id = r.id
                WHERE ar.application_id = :a LIMIT 1"""),
        {"a": app_id},
    ).scalar_one()
    supply_chain.ingest_cyclonedx(
        conn,
        application_id=app_id,
        repository_id=str(repo),
        scope_key=scope,
        commit_sha=None,
        bom=bom,
        evidence_id=ev,
        generated_at=datetime.now(UTC),
    )
    return ev


def _finding(conn, scope: str):
    return conn.execute(
        text(
            "SELECT id, status, closure_evidence_id FROM findings WHERE scope_ref = :s AND finding_type = 'dependency'"
        ),
        {"s": scope},
    ).one()


def test_an_upgrade_in_the_next_sbom_closes_the_finding(engine, fresh_app):
    app_id, scope = fresh_app("Dependency Closure", "990301"), f"repo:test-{uuid.uuid4().hex[:8]}"
    with transaction(engine, "aap_worker") as conn:
        _sbom(conn, app_id, scope, _bom("pkg:pypi/pyyaml@5.3", "pkg:pypi/requests@2.32.3"))
        vid = supply_chain.upsert_vulnerability(conn, ADVISORY)
        supply_chain.match_advisory(conn, ADVISORY, vid)
        vuln_service.raise_dependency_findings(conn, vid, datetime.now(UTC))
        assert _finding(conn, scope).status == "new"
    with transaction(engine, "aap_worker") as conn:
        fixed = _sbom(conn, app_id, scope, _bom("pkg:pypi/pyyaml@6.0.2", "pkg:pypi/requests@2.32.3"))
        f = _finding(conn, scope)
        assert f.status == "closed" and str(f.closure_evidence_id) == fixed
        event = conn.execute(
            text(
                "SELECT event_type, details->>'reason' AS reason FROM finding_events WHERE finding_id = :f ORDER BY at DESC LIMIT 1"
            ),
            {"f": f.id},
        ).one()
        assert event.event_type == "verified" and "absent from the current SBOM" in event.reason


def test_an_empty_sbom_closes_nothing(engine, fresh_app):
    app_id, scope = fresh_app("Dependency Empty Sbom", "990302"), f"repo:test-{uuid.uuid4().hex[:8]}"
    with transaction(engine, "aap_worker") as conn:
        _sbom(conn, app_id, scope, _bom("pkg:pypi/pyyaml@5.3"))
        vid = supply_chain.upsert_vulnerability(conn, ADVISORY)
        supply_chain.match_advisory(conn, ADVISORY, vid)
        vuln_service.raise_dependency_findings(conn, vid, datetime.now(UTC))
        _sbom(conn, app_id, scope, _bom())  # a scan that saw nothing is not proof of a fix
        assert _finding(conn, scope).status == "new"
