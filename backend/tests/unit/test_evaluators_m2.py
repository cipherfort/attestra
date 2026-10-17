# SPDX-License-Identifier: Apache-2.0
"""The nine evaluators added in M2, their parsers and helpers. Each must say NO_EVIDENCE (never guess) when the
producer it relies on has not supplied the field it needs."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from aap.connectors.eol import Cycle, match_cycle
from aap.domain.controls import AppFacts, ControlState, EvidenceView
from aap.evaluators.base import EvaluationInput, registry
from aap.evaluators.library import asvs_chapter_applies, asvs_requirements
from aap.ingest.parsers import BundleError, parse_junit

S = ControlState
NOW = datetime(2026, 10, 15, tzinfo=UTC)


def ev(etype, summary=None, subject=None, days_ago=1, scope="APP-1", eid=None):
    return EvidenceView(
        eid or f"{etype}-{days_ago}-{scope}",
        etype,
        "C2",
        "pass",
        "active",
        NOW - timedelta(days=days_ago),
        summary or {},
        subject or {},
        scope,
    )


def run(name, evidence, params=None, profile=None, facts=None, tier=1):
    app = AppFacts("a", tier, facts or {}, profile or {})
    i = EvaluationInput({}, app, evidence, [], NOW, params or {}, "C2")
    return registry[name](i)


def test_all_catalogue_evaluators_are_implemented():
    import yaml

    from aap.config import repo_root

    doc = yaml.safe_load((repo_root() / "catalogue/controls/controls.yaml").read_text())
    missing = [c["id"] for c in doc["controls"] if c["assessment"].get("evaluator") not in registry]
    assert missing == []


def test_team_training_coverage():
    assert run("team_training_coverage@1", [ev("training.completion", {"courses": ["x"]})]).state == S.NO_EVIDENCE
    ok = run(
        "team_training_coverage@1",
        [ev("training.completion", {"engineers": 10, "completed": 9})],
        {"threshold_pct": 90},
    )
    assert ok.state == S.SATISFIED and "9/10" in ok.explanation
    part = run(
        "team_training_coverage@1",
        [ev("training.completion", {"engineers": 10, "completed": 5})],
        {"threshold_pct": 90},
    )
    assert part.state == S.PARTIAL and part.details["fraction"] == 0.5


def test_asvs_index_and_chapter_rules():
    reqs = asvs_requirements()
    assert len(reqs) == 345 and all(lvl in (1, 2, 3) for _, _, lvl in reqs)
    caps = {"web_frontend": False, "authentication": "none", "oauth_oidc": []}
    assert asvs_chapter_applies("always", caps)
    assert not asvs_chapter_applies("capabilities.web_frontend", caps)
    assert not asvs_chapter_applies("capabilities.authentication != 'none'", caps)
    assert not asvs_chapter_applies("size(capabilities.oauth_oidc) > 0", caps)
    assert asvs_chapter_applies("capabilities.unknown_flag", caps)  # unknown keeps the chapter in scope


def test_asvs_coverage_counts_only_applicable_passing_requirements():
    level1 = [rid for rid, _, lvl in asvs_requirements() if lvl == 1]
    profile = {"asvs_target_level": 1, "asvs_capabilities": {}}
    assert run("asvs_coverage@1", [], profile={}).state == S.NO_EVIDENCE
    assert run("asvs_coverage@1", [], profile=profile).state == S.NO_EVIDENCE
    tests = ev("test.security", {"asvs": {r: "pass" for r in level1[:10]} | {level1[10]: "fail"}})
    manual = ev("assessment.manual_control", {"asvs_verified": level1[11:20]})
    res = run("asvs_coverage@1", [tests, manual], {"verified_pct": 80}, profile)
    assert res.state == S.PARTIAL and "19 of" in res.explanation and "1 failing" in res.explanation
    everything = ev("test.security", {"asvs": {r: "pass" for r in level1}})
    assert run("asvs_coverage@1", [everything], {"verified_pct": 80}, profile).state == S.SATISFIED


def test_eol_components():
    assert run("eol_components@1", [ev("sbom")]).state == S.NO_EVIDENCE
    clean = run(
        "eol_components@1", [ev("sbom.eol", {"snapshot": "2026-10-15", "checked": 4, "eol": [], "eol_soon": [{}]})]
    )
    assert clean.state == S.SATISFIED and "within 180 days" in clean.explanation
    bad = run(
        "eol_components@1", [ev("sbom.eol", {"eol": [{"product": "django", "cycle": "3.2", "eol": "2024-04-01"}]})]
    )
    assert bad.state == S.NOT_SATISFIED and "django 3.2" in bad.explanation


D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def test_artifact_scanned_prefers_deployed_digests():
    deploy = ev("deploy.record", {"verified": True}, {"artifact_digest": D1, "environment": "prod"})
    assert run("artifact_scanned@1", []).state == S.NO_EVIDENCE
    assert run("artifact_scanned@1", [deploy]).state == S.NOT_SATISFIED
    scan = ev("scan.container", subject={"artifact_digest": D1})
    assert run("artifact_scanned@1", [deploy, scan]).state == S.SATISFIED
    build_only = ev("sbom", subject={"artifact_digest": D2})
    res = run("artifact_scanned@1", [build_only, scan])
    assert res.state == S.NOT_SATISFIED and "latest build" in res.explanation


def test_deploy_verification_and_image_age():
    prod = ev(
        "deploy.record",
        {"verified": True, "image_created_at": "2026-10-01T00:00:00Z"},
        {"artifact_digest": D1, "environment": "prod"},
    )
    test = ev(
        "deploy.record",
        {"verified": False, "image_created_at": "2026-06-01T00:00:00Z"},
        {"artifact_digest": D2, "environment": "test"},
        scope="t",
    )
    assert run("deploy_verification_executed@1", [prod]).state == S.SATISFIED
    res = run("deploy_verification_executed@1", [prod, test])
    assert res.state == S.NOT_SATISFIED and "test" in res.explanation
    assert run("image_patch_age@1", [prod], {"max_age_days": 30}).state == S.SATISFIED
    old = run("image_patch_age@1", [prod, test], {"max_age_days": 30})
    assert old.state == S.NOT_SATISFIED and "test 136d" in old.explanation
    no_time = ev("deploy.record", {"verified": True}, {"environment": "prod"})
    assert run("image_patch_age@1", [no_time]).state == S.NO_EVIDENCE


def test_threat_test_linkage():
    tm_old = ev("repo.threat_model", {"high_threats": 2})
    assert run("threat_test_linkage@1", [tm_old]).state == S.NO_EVIDENCE  # producer predates threat ids
    tm = ev("repo.threat_model", {"high_threat_ids": ["TM-01", "TM-02", "TM-03"]})
    tests = ev("test.security", {"threats": {"TM-01": "pass", "TM-02": "fail"}})
    res = run("threat_test_linkage@1", [tm, tests], {"min_pct_high_threats_tested": 60})
    assert res.state == S.PARTIAL and "1 of 3" in res.explanation and "TM-02" in res.explanation
    tests2 = ev("test.security", {"threats": {"TM-01": "pass", "TM-02": "pass"}}, days_ago=0)
    assert run("threat_test_linkage@1", [tm, tests2], {"min_pct_high_threats_tested": 60}).state == S.SATISFIED


def test_data_store_baseline_is_honest_about_the_missing_inventory():
    reg = ev("registry.application", {"data_stores": ["claims-db"]})
    res = run("data_store_baseline@1", [reg, ev("cloud.posture", {"open": 0})])
    assert res.state == S.NO_EVIDENCE and "PROPOSED" in res.explanation
    inv = ev(
        "cloud.posture",
        {
            "data_stores": [
                {"name": "claims-db", "encrypted": True, "backup": True},
                {"name": "shadow", "encrypted": False},
            ]
        },
    )
    bad = run("data_store_baseline@1", [reg, inv])
    assert (
        bad.state == S.NOT_SATISFIED and "shadow undeclared" in bad.explanation and "not encrypted" in bad.explanation
    )


def test_decommission_complete():
    live = ev("repo.access", {"archived": False}, scope="org/a")
    done = ev("repo.access", {"archived": True}, scope="org/a", days_ago=0)
    assert run("decommission_complete@1", [ev("repo.access", {"outside_writers": 0})]).state == S.NO_EVIDENCE
    assert run("decommission_complete@1", [live]).state == S.NOT_SATISFIED
    assert run("decommission_complete@1", [live, done]).state == S.SATISFIED  # latest per repository wins
    assert run("decommission_complete@1", [done], facts={"has_cloud_scope": True}).state == S.PARTIAL


JUNIT = b"""<?xml version="1.0"?>
<testsuites><testsuite name="authz">
  <testcase name="a"><properties><property name="asvs" value="V8.2.1, V8.2.2"/><property name="threat" value="TM-07"/></properties></testcase>
  <testcase name="b"><properties><property name="asvs" value="V8.2.2"/></properties><failure message="x"/></testcase>
  <testcase name="c"><properties><property name="threat" value="TM-09"/></properties><skipped/></testcase>
  <testcase name="d"><properties><property name="owner" value="team"/></properties></testcase>
</testsuite></testsuites>"""


def test_parse_junit_links_and_failures():
    out = parse_junit(JUNIT)
    assert (out["tests"], out["failures"], out["skipped"]) == (4, 1, 1)
    assert out["asvs"] == {"V8.2.1": "pass", "V8.2.2": "fail"}  # a failing linked test wins
    assert out["threats"] == {"TM-07": "pass"}  # skipped tests verify nothing


def test_parse_junit_refuses_entity_declarations():
    bomb = b'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aaaa">]><testsuite><testcase name="&a;"/></testsuite>'
    with pytest.raises(BundleError, match="DOCTYPE"):
        parse_junit(bomb)
    with pytest.raises(BundleError):
        parse_junit(b"<testsuite>")


def test_eol_cycle_matching_is_most_specific():
    cycles = [Cycle("3.2", date(2024, 4, 1), False), Cycle("3", None, False), Cycle("4.2", date(2026, 4, 1), False)]
    assert match_cycle("3.2.25", cycles).cycle == "3.2"
    assert match_cycle("3.1.0", cycles).cycle == "3"
    assert match_cycle("v4.2.1", cycles).cycle == "4.2"
    assert match_cycle("5.0", cycles) is None
