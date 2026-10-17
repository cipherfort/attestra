# SPDX-License-Identifier: Apache-2.0
from aap.domain import fingerprints as fp
from aap.domain.maturity import ManualAnswer, StateInput, compute


def states(**kv):
    return {k: StateInput(k, v, "mandatory") for k, v in kv.items()}


def run(bundle, st, manual=None, targets=None):
    return compute(st, bundle.controls, bundle.doc("samm"), bundle.doc("maturity_methodology"), manual, targets)


def test_secure_build_from_control_states(bundle):
    # I-SB-A L2 maps ASC-BLD-01, -04, ASC-SRC-01, -02, -06: 4 of 5 satisfied → 0.8 → answer 1.0
    st = states(
        **{
            "ASC-BLD-01": "satisfied",
            "ASC-BLD-04": "satisfied",
            "ASC-SRC-01": "satisfied",
            "ASC-SRC-02": "satisfied",
            "ASC-SRC-06": "no_evidence",
        }
    )
    r = run(bundle, st)
    a = next(a for a in r.answers if (a.stream, a.level) == ("I-SB-A", 2))
    assert a.automated_fraction == 0.8 and a.value == 1.0 and a.provenance == "automated"


def test_excepted_counts_zero_and_not_applicable_is_excluded(bundle):
    st = {
        "ASC-TST-01": StateInput("ASC-TST-01", "excepted", "mandatory"),
        "ASC-TST-02": StateInput("ASC-TST-02", "not_applicable", "n/a"),
    }
    a = next(a for a in run(bundle, st).answers if (a.stream, a.level) == ("V-ST-A", 2))
    assert a.automated_fraction == 0.0 and a.value == 0.0


def test_manual_answer_capped_by_contrary_evidence(bundle):
    st = states(**{"ASC-VUL-04": "no_evidence"})  # I-DM-B L2
    r = run(bundle, st, manual={("I-DM-B", 2): ManualAnswer(1.0, "M2")})
    a = next(a for a in r.answers if (a.stream, a.level) == ("I-DM-B", 2))
    assert a.capped and a.value == 0.25


def test_manual_only_activity_keeps_manual_provenance(bundle):
    r = run(bundle, {}, manual={("G-SM-A", 1): ManualAnswer(1.0, "M2")})
    a = next(a for a in r.answers if (a.stream, a.level) == ("G-SM-A", 1))
    assert a.provenance == "manual_independent" and a.value == 1.0
    assert r.practices["G-SM"].provenance["unassessed"] > 0


def test_scores_stay_within_samm_scale(bundle):
    all_sat = {k: StateInput(k, "satisfied", "mandatory") for k in bundle.controls}
    r = run(bundle, all_sat)
    assert all(0 <= p.score <= 3 for p in r.practices.values())
    assert r.practices["I-SB"].score > 2.5


def test_fingerprints_are_stable_across_versions_and_aliases():
    a = fp.dependency(
        "repo:42", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"]
    )
    b = fp.dependency("repo:42", "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0", ["CVE-2021-44228"])
    assert a == b  # upgrading to a still-vulnerable version is the same finding; aliases resolve to the CVE
    assert fp.canonical_vuln_id(["MAL-2026-1", "GHSA-x"]) == "GHSA-x"
    assert fp.purl_without_version("pkg:npm/%40scope/pkg@1.0.0?arch=x") == "pkg:npm/%40scope/pkg"
