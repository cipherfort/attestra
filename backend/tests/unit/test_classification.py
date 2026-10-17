# SPDX-License-Identifier: Apache-2.0
import itertools

import pytest

from aap.domain.classification import ClassificationError, classify

BASE = {
    "data_classification": "internal",
    "personal_data": "none",
    "exposure": "internal",
    "user_population": "organisation",
    "business_criticality": "moderate",
    "privileged_integration": "none",
}


def test_claims_api_template_is_tier_1_by_floor_rule(bundle):
    # templates/repo-contract/.security/application.yaml
    inputs = {
        "data_classification": "confidential",
        "personal_data": "customer_personal",
        "exposure": "internet_authenticated",
        "user_population": "public_large",
        "business_criticality": "major",
        "privileged_integration": "limited",
        "regulatory": ["GDPR"],
    }
    r = classify(inputs, bundle.doc("classification"))
    assert r.tier == 1
    assert "FR-3" in r.matched_floor_rules and "FR-4" in r.matched_floor_rules
    assert r.asvs_target == "L3"
    assert "FR-3" in r.explanation


def test_low_risk_internal_tool_is_tier_4(bundle):
    r = classify(
        {**BASE, "data_classification": "public", "user_population": "team", "business_criticality": "minimal"},
        bundle.doc("classification"),
    )
    assert r.tier == 4 and r.points == 1


def test_points_alone_can_reach_tier_2(bundle):
    r = classify(
        {
            **BASE,
            "data_classification": "confidential",
            "personal_data": "limited",
            "exposure": "partner",
            "business_criticality": "major",
        },
        bundle.doc("classification"),
    )
    assert r.floor_tier is None and r.tier == 2


def test_unknown_label_rejected(bundle):
    with pytest.raises(ClassificationError, match="labels not defined"):
        classify({**BASE, "exposure": "the internet"}, bundle.doc("classification"))


def test_missing_input_rejected(bundle):
    with pytest.raises(ClassificationError, match="missing"):
        classify({k: v for k, v in BASE.items() if k != "exposure"}, bundle.doc("classification"))


def test_more_exposure_never_lowers_the_tier(bundle):
    """Property: making any single dimension more severe can only keep or raise criticality (lower rank)."""
    model = bundle.doc("classification")
    dims = model["dimensions"]
    for dim, spec in dims.items():
        if dim == "regulatory":
            continue
        ordered = sorted(spec["options"], key=spec["options"].get)
        for lo, hi in itertools.pairwise(ordered):
            assert classify({**BASE, dim: hi}, model).tier <= classify({**BASE, dim: lo}, model).tier, (dim, lo, hi)
