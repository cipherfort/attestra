# SPDX-License-Identifier: Apache-2.0
"""Evaluator behaviour against the real catalogue. The key invariant (ADR-004): configuration presence never
satisfies an activity control."""

from datetime import timedelta

import pytest

from aap.domain.controls import AppFacts, ControlState, EvidenceView
from aap.evaluators import evaluate_control
from aap.evaluators.base import FindingView

FACTS = {
    "has_source_code": True,
    "uses_dependencies": True,
    "has_iac": True,
    "has_workflows": True,
    "builds_or_deploys_containers": True,
    "deployed": True,
    "has_api": True,
    "has_web_ui_or_api": True,
}
APP1 = AppFacts("app-1", 1, FACTS)


def ev(now, etype, confidence="C3", result="findings", state="active", age_days=1, **summary):
    return EvidenceView(
        id=f"{etype}-{confidence}-{age_days}",
        type=etype,
        confidence=confidence,
        result=result,
        state=state,
        observed_at=now - timedelta(days=age_days),
        summary=summary,
        subject={"commit_sha": "3f2a9c" + "0" * 34},
        state_reason="meaningful change since evidence",
    )


def control(bundle, key):
    return bundle.controls[key]


def test_sast_satisfied_by_executed_scan_covering_all_languages(bundle, now):
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"),
        APP1,
        [
            ev(
                now,
                "scan.sast",
                tool="codeql",
                tool_version="2.19.1",
                languages=["java", "javascript"],
                languages_detected=["java", "javascript"],
                query_suite="security-extended",
            )
        ],
        [],
        now,
    )
    assert r.state is ControlState.SATISFIED
    assert "codeql 2.19.1" in r.explanation and "3f2a9c0" in r.explanation


def test_workflow_file_present_but_never_ran_is_no_evidence(bundle, now):
    """C1 'configured' evidence (e.g. code scanning enabled / workflow file present) must not satisfy SAST."""
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"), APP1, [ev(now, "scan.sast", confidence="C1", result="observed")], [], now
    )
    assert r.state is ControlState.NO_EVIDENCE
    assert "configuration alone does not prove the control operates" in r.explanation


def test_superseded_scan_reports_stale_with_reason(bundle, now):
    r = evaluate_control(control(bundle, "ASC-BLD-01"), APP1, [ev(now, "scan.sast", state="superseded")], [], now)
    assert r.state is ControlState.STALE and "meaningful change" in r.explanation


def test_missing_language_is_partial(bundle, now):
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"),
        APP1,
        [
            ev(
                now,
                "scan.sast",
                tool="codeql",
                languages=["java"],
                languages_detected=["java", "go"],
                query_suite="security-extended",
            )
        ],
        [],
        now,
    )
    assert r.state is ControlState.PARTIAL and "go" in r.explanation and r.details["fraction"] == 0.5


def test_weaker_query_suite_than_tier_requires_is_partial(bundle, now):
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"),
        APP1,
        [ev(now, "scan.sast", tool="codeql", languages=["java"], languages_detected=["java"], query_suite="default")],
        [],
        now,
    )
    assert r.state is ControlState.PARTIAL and "weaker" in r.explanation


def test_tier_4_query_suite_default_is_enough(bundle, now):
    app4 = AppFacts("app-4", 4, FACTS)
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"),
        app4,
        [ev(now, "scan.sast", tool="codeql", languages=["java"], languages_detected=["java"], query_suite="default")],
        [],
        now,
    )
    assert r.state is ControlState.SATISFIED


def test_failed_run_is_not_satisfied(bundle, now):
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"), APP1, [ev(now, "scan.sast", result="error", tool="codeql")], [], now
    )
    assert r.state is ControlState.NOT_SATISFIED


def test_findings_do_not_make_an_activity_control_fail(bundle, now):
    """Detection is never penalised: 40 findings + a scan that ran = control satisfied."""
    findings = [FindingView(f"f{i}", "code", "ticketed", "P2", False) for i in range(40)]
    r = evaluate_control(
        control(bundle, "ASC-BLD-01"),
        APP1,
        [
            ev(
                now,
                "scan.sast",
                tool="codeql",
                languages=["java"],
                languages_detected=["java"],
                query_suite="security-extended",
            )
        ],
        findings,
        now,
    )
    assert r.state is ControlState.SATISFIED


def test_not_applicable_by_tier(bundle, now):
    r = evaluate_control(control(bundle, "ASC-TM-01"), AppFacts("a", 4, FACTS), [], [], now)
    assert r.state is ControlState.NOT_APPLICABLE and "Tier 4" in r.explanation


def test_not_applicable_by_condition(bundle, now):
    r = evaluate_control(control(bundle, "ASC-BLD-04"), AppFacts("a", 1, {**FACTS, "has_iac": False}), [], [], now)
    assert r.state is ControlState.NOT_APPLICABLE and "has_iac" in r.explanation


def test_unknown_condition_keeps_control_applicable(bundle, now):
    r = evaluate_control(control(bundle, "ASC-BLD-04"), AppFacts("a", 1, {}), [], [], now)
    assert r.state is ControlState.NO_EVIDENCE


def test_exception_wins(bundle, now):
    r = evaluate_control(control(bundle, "ASC-TST-01"), APP1, [], [], now, active_exception="EX-000123")
    assert r.state is ControlState.EXCEPTED and "EX-000123" in r.explanation


def test_threat_model_tier1_needs_independent_review(bundle, now):
    c = control(bundle, "ASC-TM-01")
    structure = ev(now, "repo.threat_model", confidence="C1", result="observed", schema_valid=True)
    self_review = ev(now, "assessment.threat_model", confidence="M1", result="pass", reviewer="champion")
    r = evaluate_control(c, APP1, [structure, self_review], [], now)
    assert r.state is ControlState.PARTIAL  # structure alone; M1 is below the Tier 1 M2 requirement
    indep = ev(now, "assessment.threat_model", confidence="M2", result="pass", reviewer="AppSec")
    assert evaluate_control(c, APP1, [structure, indep], [], now).state is ControlState.SATISFIED


def test_no_active_secrets_outcome(bundle, now):
    c = control(bundle, "ASC-SRC-04")
    posture = ev(now, "scan.secrets", confidence="C3", result="observed")
    open_secret = FindingView("s1", "secret", "new", "P1", False, details={"validity": "active"})
    assert evaluate_control(c, APP1, [posture], [open_secret], now).state is ControlState.NOT_SATISFIED
    revoked = FindingView("s1", "secret", "closed", "P1", False, details={"validity": "active"})
    assert evaluate_control(c, APP1, [posture], [revoked], now).state is ControlState.SATISFIED


def test_unimplemented_evaluator_reports_error_not_a_guess(bundle, now):
    # every catalogue control has an evaluator now; the guarantee still holds for a control added without one
    c = dict(control(bundle, "ASC-ARC-02"))
    c["assessment"] = {**c["assessment"], "evaluator": "not_written_yet@1"}
    r = evaluate_control(c, APP1, [], [], now)
    assert r.state is ControlState.ERROR and "not implemented" in r.explanation


@pytest.mark.parametrize(
    "key",
    [
        c
        for c in [
            "ASC-BLD-01",
            "ASC-BLD-02",
            "ASC-BLD-03",
            "ASC-BLD-04",
            "ASC-BLD-05",
            "ASC-TST-01",
            "ASC-TST-02",
            "ASC-TST-05",
        ]
    ],
)
def test_every_activity_control_rejects_c1_evidence(bundle, now, key):
    c = control(bundle, key)
    weak = [ev(now, t, confidence="C1", result="observed") for t in c["assessment"]["evidence_types"]]
    r = evaluate_control(c, APP1, weak, [], now)
    assert r.state in (ControlState.NO_EVIDENCE, ControlState.ERROR), (key, r)
