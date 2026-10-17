# SPDX-License-Identifier: Apache-2.0
"""Built-in feeds against the demo inventory: an OSV match raises an 'osv' dependency finding; KEV and EPSS update
the advisory and queue the application for re-scoring; a withdrawn advisory's link is removed."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
from sqlalchemy import text

from aap.connectors.vuln_feeds import EpssScore, KevEntry
from aap.db import transaction
from aap.services import vuln_feeds

pytestmark = pytest.mark.db

ADVISORY = "GHSA-test-osv-feed"
CVE = "CVE-2099-0001"


class FakeOsv:
    def __init__(self, target: str, withdrawn: bool = False):
        self.target, self.withdrawn, self.fetched = target, withdrawn, []

    def querybatch(self, purls):
        return {p: ({} if self.withdrawn or p != self.target else {ADVISORY: "2026-10-01T00:00:00Z"}) for p in purls}

    def vuln(self, vid):
        self.fetched.append(vid)
        name = self.target.split("@")[0]
        return {
            "id": vid,
            "aliases": [CVE],
            "summary": "Test advisory",
            "modified": "2026-10-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {"package": {"purl": name}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}
            ],
        }


class FakeKev:
    def __init__(self, cves):
        self.cves = cves

    def catalogue(self):
        return "test", [KevEntry(c, date(2026, 10, 2), False) for c in self.cves]


class FakeEpss:
    def scores(self, cves):
        return [EpssScore(c, Decimal("0.91"), Decimal("0.99"), date(2026, 10, 14)) for c in cves if c == CVE]


def test_feeds_raise_and_rescore_dependency_findings(engine, demo):
    with transaction(engine, "aap_worker") as conn:
        target = conn.execute(
            text("""SELECT c.purl FROM components c JOIN sbom_components sc ON sc.component_id = c.id
                    JOIN sboms s ON s.id = sc.sbom_id AND s.is_current ORDER BY c.purl LIMIT 1""")
        ).scalar_one()
        osv = FakeOsv(target)
        rep = vuln_feeds.osv_sync(conn, osv, datetime.now(UTC))
    assert rep.links_added >= 1 and rep.findings_raised >= 1 and osv.fetched == [ADVISORY]

    with transaction(engine, "aap_worker") as conn:
        vuln = conn.execute(text("SELECT * FROM vulnerabilities WHERE vuln_key = :k"), {"k": CVE}).mappings().one()
        assert vuln["cvss_v3_score"] == Decimal("9.8") and ADVISORY in vuln["aliases"]
        finding = conn.execute(
            text("SELECT source_system, location FROM findings WHERE vulnerability_id = :v"), {"v": vuln["id"]}
        ).first()
        assert finding.source_system == "osv" and finding.location["fixed_versions"] == ["99.0.0"]
        # a second run with nothing new fetches nothing
        again = FakeOsv(target)
        assert vuln_feeds.osv_sync(conn, again, datetime.now(UTC)).links_added == 0 and again.fetched == []

        already = list(conn.execute(text("SELECT vuln_key FROM vulnerabilities WHERE in_kev")).scalars())
        kev = vuln_feeds.kev_sync(conn, FakeKev([CVE, "CVE-1999-0001", *already]))
        assert kev.changed >= 1  # ours, plus any demo advisory whose KEV date differs
        epss = vuln_feeds.epss_sync(conn, FakeEpss())
        assert epss.changed == 1
        row = conn.execute(
            text("SELECT in_kev, kev_added_at, epss_score FROM vulnerabilities WHERE vuln_key = :k"), {"k": CVE}
        ).one()
        assert row.in_kev and row.kev_added_at == date(2026, 10, 2) and row.epss_score == Decimal("0.91")
        queued = conn.execute(text("SELECT count(*) FROM jobs WHERE queue = 'evaluate' AND status = 'queued'")).scalar()
        assert queued >= 1  # the affected application is re-scored with the new exploit data

        # dropped from KEV → flag cleared; withdrawn from OSV → component link removed
        assert vuln_feeds.kev_sync(conn, FakeKev(["CVE-1999-0001", *already])).changed == 1
        assert not conn.execute(text("SELECT in_kev FROM vulnerabilities WHERE vuln_key = :k"), {"k": CVE}).scalar()
        assert vuln_feeds.osv_sync(conn, FakeOsv(target, withdrawn=True), datetime.now(UTC)).links_removed == 1


class FakeEol:
    def cycles(self, product):
        from aap.connectors.eol import Cycle

        return [Cycle(str(major), date(2020, 1, 1), False) for major in range(100)]  # every major is past EOL


def test_eol_check_writes_derived_evidence_no_stronger_than_its_sbom(engine, demo):
    from aap.domain.fingerprints import purl_without_version
    from aap.services import eol

    with transaction(engine, "aap_worker") as conn:
        purl = conn.execute(
            text("""SELECT c.purl FROM components c JOIN sbom_components sc ON sc.component_id = c.id
                    JOIN sboms s ON s.id = sc.sbom_id AND s.is_current ORDER BY c.purl LIMIT 1""")
        ).scalar_one()
        out = eol.eol_sync(
            conn, FakeEol(), {"products": {purl_without_version(purl): "testproduct"}}, datetime.now(UTC)
        )
        assert out["applications"] >= 1 and out["errors"] == []
        rows = conn.execute(
            text("""SELECT e.confidence, e.summary, s.confidence AS sbom_confidence FROM evidence e
                    JOIN sboms sb ON sb.application_id = e.application_id AND sb.is_current
                    JOIN evidence s ON s.evidence_id = sb.evidence_id
                    WHERE e.evidence_type = 'sbom.eol'""")
        ).all()
    assert rows and all(r.confidence <= r.sbom_confidence for r in rows)
    flagged = [r for r in rows if r.summary["eol"]]
    assert flagged and flagged[0].summary["eol"][0]["product"] == "testproduct"
    assert all(r.summary["checked"] >= 0 and r.summary["snapshot"] for r in rows)
