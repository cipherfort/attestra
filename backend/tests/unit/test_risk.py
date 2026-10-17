# SPDX-License-Identifier: Apache-2.0
from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from aap.domain.risk import PRIORITY_ORDER, RiskModel


def model(bundle):
    return RiskModel(bundle.doc("risk_model"))


def test_kev_on_internet_facing_tier1_is_p1(bundle):
    # docs/standards/risk-model.md worked example 1
    r = model(bundle).score(
        {
            "app": {"tier": 1, "exposure": "internet_public", "personal_data": "special_category"},
            "vuln": {"in_cisa_kev": True, "epss_percentile": 0.97},
            "finding": {"type": "dependency"},
        }
    )
    assert (r.likelihood, r.impact, r.score, r.priority) == (5, 5, 25, "P1")
    assert "likelihood.kev" in r.applied_rules
    assert "EPSS percentile 0.97" in r.explanation


def test_same_cve_in_dev_dependency_of_internal_tier3_is_p3(bundle):
    r = model(bundle).score(
        {
            "app": {"tier": 3, "exposure": "internal"},
            "vuln": {"in_cisa_kev": True, "epss_percentile": 0.97},
            "finding": {"type": "dependency"},
            "component": {"scope": "development"},
        }
    )
    assert r.priority == "P3" and r.score == 10


def test_unconfirmed_sast_high_then_dast_confirmed(bundle):
    ctx = {
        "app": {"tier": 2, "exposure": "internet_authenticated"},
        "finding": {"type": "code", "tool_severity": "high"},
    }
    assert model(bundle).score(ctx).priority == "P3"
    ctx["finding"]["confirmed_dynamically"] = True
    r = model(bundle).score(ctx)
    assert r.priority == "P2" and r.score == 12


def test_active_secret_is_forced_to_p1(bundle):
    r = model(bundle).score(
        {
            "app": {"tier": 3, "exposure": "internal"},
            "finding": {"type": "secret", "tool_severity": "critical", "secret_validity": "active"},
        }
    )
    assert r.score == 12 and r.priority == "P1"
    assert "override.active_secret" in r.applied_rules
    assert "raised to P1" in r.explanation


def test_sla_due_dates(bundle):
    r = model(bundle).score({"app": {"tier": 4}, "finding": {"tool_severity": "medium"}})
    detected = datetime(2026, 10, 1, tzinfo=UTC)
    assert (r.remediation_due(detected, bundle.doc("risk_model")) - detected).days == 180
    assert (r.remediation_due(detected, bundle.doc("risk_model"), factor=0.5) - detected).days == 90


@given(
    tier=st.sampled_from([1, 2, 3, 4]),
    epss=st.floats(min_value=0, max_value=1),
    kev=st.booleans(),
)
def test_more_exposure_never_lowers_priority(bundle, tier, epss, kev):
    m = model(bundle)
    base = {"vuln": {"in_cisa_kev": kev, "epss_percentile": epss}, "finding": {"type": "dependency"}}
    internal = m.score({**base, "app": {"tier": tier, "exposure": "internal"}})
    public = m.score({**base, "app": {"tier": tier, "exposure": "internet_public"}})
    assert PRIORITY_ORDER.index(public.priority) <= PRIORITY_ORDER.index(internal.priority)


@given(epss=st.floats(min_value=0, max_value=1))
def test_more_critical_tier_never_lowers_priority(bundle, epss):
    m = model(bundle)
    prios = [
        m.score({"app": {"tier": t, "exposure": "internal"}, "vuln": {"epss_percentile": epss}}).priority
        for t in (1, 2, 3, 4)
    ]
    idx = [PRIORITY_ORDER.index(p) for p in prios]
    assert idx == sorted(idx)
