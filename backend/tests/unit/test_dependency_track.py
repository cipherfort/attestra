# SPDX-License-Identifier: Apache-2.0
"""Mapping of real Dependency-Track 4.14.5 findings (fixtures/dependency-track-4.14.5-findings.json) and the client."""

import json
from pathlib import Path

import httpx
import pytest

from aap.connectors.dependency_track import DependencyTrackClient, DependencyTrackError, to_advisory

FINDINGS = json.loads((Path(__file__).parent.parent / "fixtures" / "dependency-track-4.14.5-findings.json").read_text())


def by_vuln(vuln_id):
    return next(f for f in FINDINGS if f["vulnerability"]["vulnId"] == vuln_id)


def test_log4shell_keyed_by_its_single_cve_with_ghsa_alias():
    adv = to_advisory(by_vuln("GHSA-jfh8-c2jp-5v3q"))
    assert adv["id"] == "CVE-2021-44228" and "GHSA-jfh8-c2jp-5v3q" in adv["aliases"]
    assert adv["affected"] == [{"purl": "pkg:maven/org.apache.logging.log4j/log4j-core", "versions": ["2.14.1"]}]
    assert 502 in adv["cwe"] and adv["cvss_v3_vector"].startswith("CVSS:3.1/")
    assert "in_kev" not in adv and "epss_score" not in adv  # never asserted by DT: preserved from authoritative feeds


def test_every_real_finding_maps():
    advs = [to_advisory(f) for f in FINDINGS]
    assert len(advs) == 7 and all(a["affected"] and a["id"] for a in advs)
    assert all(a["source"] == "dependency-track" for a in advs)


def test_multiple_cves_keep_the_dt_id():
    f = json.loads(json.dumps(by_vuln("GHSA-jfh8-c2jp-5v3q")))
    f["vulnerability"]["references"] += " CVE-2021-45046"
    adv = to_advisory(f)
    assert adv["id"] == "GHSA-jfh8-c2jp-5v3q" and {"CVE-2021-44228", "CVE-2021-45046"} <= set(adv["aliases"])


def test_permission_error_is_explicit():
    c = DependencyTrackClient(
        "https://dt.test", "k", http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    )
    with pytest.raises(DependencyTrackError, match="permissions"):
        c.findings("p")


def test_wait_times_out():
    c = DependencyTrackClient(
        "https://dt.test",
        "k",
        http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"processing": True}))),
    )
    with pytest.raises(DependencyTrackError, match="did not finish"):
        c.wait("t", timeout=0.05, poll=0.01, sleep=lambda s: None)
