# SPDX-License-Identifier: Apache-2.0
"""Built-in feeds: CVSS scoring from vectors, and the OSV/KEV/EPSS clients against recorded API shapes."""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal

import httpx
import pytest

from aap.connectors.vuln_feeds import EpssClient, FeedError, KevClient, OsvClient
from aap.domain.cvss import CvssError, base_score
from aap.services.vuln_feeds import fixed_versions, osv_to_advisory


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "10.0"),  # CVE-2021-44228 (Log4Shell)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"),  # CVE-2014-0160 (Heartbleed)
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.8"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"),  # typical reflected XSS
        ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "2.0"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0"),
    ],
)
def test_cvss_base_score_matches_the_specification(vector, score):
    assert base_score(vector) == Decimal(score)


def test_cvss_rejects_malformed_vectors():
    for bad in ("AV:N/AC:L", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"):
        with pytest.raises(CvssError):
            base_score(bad)


LOG4J = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "summary": "Remote code injection in Log4j",
    "modified": "2026-01-02T00:00:00Z",
    "published": "2021-12-10T00:00:00Z",
    "database_specific": {"cwe_ids": ["CWE-502", "CWE-917"]},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            },
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.16.0"}]},
            ],
        }
    ],
}


def test_osv_advisory_keys_on_the_cve_and_scores_the_vector():
    adv = osv_to_advisory(LOG4J)
    assert adv["id"] == "CVE-2021-44228" and adv["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert adv["cvss_v3_score"] == Decimal("10.0") and adv["cwe"] == [502, 917] and not adv["is_malicious"]
    assert osv_to_advisory({"id": "MAL-2026-1", "summary": "malicious"})["is_malicious"]
    assert fixed_versions(LOG4J, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == ["2.15.0", "2.16.0"]


def transport(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_osv_querybatch_follows_page_tokens_per_package():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        calls.append(body)
        out = []
        for q in body["queries"]:
            if q["package"]["purl"].startswith("pkg:npm/lodash") and "page_token" not in q:
                out.append({"vulns": [{"id": "GHSA-1", "modified": "m1"}], "next_page_token": "t2"})
            elif q.get("page_token") == "t2":
                out.append({"vulns": [{"id": "GHSA-2", "modified": "m2"}]})
            else:
                out.append({})
        return httpx.Response(200, json={"results": out})

    res = OsvClient(transport(handler), "https://osv.test").querybatch(["pkg:npm/lodash@4.17.20", "pkg:npm/x@1"])
    assert res == {"pkg:npm/lodash@4.17.20": {"GHSA-1": "m1", "GHSA-2": "m2"}, "pkg:npm/x@1": {}}
    assert len(calls) == 2 and calls[1]["queries"] == [
        {"package": {"purl": "pkg:npm/lodash@4.17.20"}, "page_token": "t2"}
    ]


def test_osv_errors_are_raised_not_swallowed():
    with pytest.raises(FeedError, match="HTTP 503"):
        OsvClient(transport(lambda r: httpx.Response(503)), "https://osv.test").querybatch(["pkg:npm/a@1"])
    with pytest.raises(FeedError, match="result count"):
        OsvClient(transport(lambda r: httpx.Response(200, json={"results": []})), "https://osv.test").querybatch(
            ["pkg:npm/a@1"]
        )


def kev_body(n: int, count: int | None = None) -> dict:
    vulns = [
        {"cveID": f"CVE-2020-{i:05d}", "dateAdded": "2022-01-10", "knownRansomwareCampaignUse": "Unknown"}
        for i in range(n)
    ]
    return {"catalogVersion": "2026.10.14", "count": n if count is None else count, "vulnerabilities": vulns}


def test_kev_refuses_a_truncated_catalogue():
    ok = KevClient(transport(lambda r: httpx.Response(200, json=kev_body(1500))), "https://kev.test").catalogue()
    assert ok[0] == "2026.10.14" and len(ok[1]) == 1500 and ok[1][0].added == date(2022, 1, 10)
    with pytest.raises(FeedError, match="implausible"):
        KevClient(transport(lambda r: httpx.Response(200, json=kev_body(12))), "https://kev.test").catalogue()
    with pytest.raises(FeedError, match="implausible"):
        KevClient(transport(lambda r: httpx.Response(200, json=kev_body(1500, 1600))), "https://kev.test").catalogue()


def test_epss_batches_cve_ids():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        cves = req.url.params["cve"].split(",")
        seen.append(len(cves))
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "data": [{"cve": c, "epss": "0.97", "percentile": "0.999", "date": "2026-10-14"} for c in cves],
            },
        )

    scores = EpssClient(transport(handler), "https://epss.test").scores(f"CVE-2021-{i:05d}" for i in range(250))
    assert seen == [100, 100, 50] and len(scores) == 250 and scores[0].epss == Decimal("0.97")
