# SPDX-License-Identifier: Apache-2.0
"""Application tiering per config/profiles/<profile>/classification.yaml (Application Classification Standard).

Two steps, both explained to the owner: floor rules set a minimum tier, points map to a tier; the final tier
is the more critical (lower rank) of the two.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

DIMENSIONS_REQUIRED = (
    "data_classification",
    "personal_data",
    "exposure",
    "user_population",
    "business_criticality",
    "privileged_integration",
)


class ClassificationError(ValueError):
    pass


@dataclass(frozen=True)
class ClassificationResult:
    tier: int
    tier_label: str
    asvs_target: str
    points: int
    points_tier: int
    floor_tier: int | None
    matched_floor_rules: tuple[str, ...]
    contributions: tuple[tuple[str, str, int], ...]
    explanation: str


def normalise_inputs(raw: Mapping[str, Any]) -> dict[str, str]:
    """`regulatory` is a list in application.yaml; the model scores it as none/some."""
    inputs = {k: str(v) for k, v in raw.items() if k != "regulatory" and v is not None}
    regulatory = raw.get("regulatory")
    inputs["regulatory"] = "some" if regulatory else "none"
    return inputs


def classify(raw_inputs: Mapping[str, Any], model: Mapping[str, Any]) -> ClassificationResult:
    inputs = normalise_inputs(raw_inputs)
    dims = model["dimensions"]
    missing = [d for d in DIMENSIONS_REQUIRED if d not in inputs]
    if missing:
        raise ClassificationError(f"missing classification inputs: {missing}")
    unknown = [f"{d}={inputs[d]}" for d in dims if d in inputs and inputs[d] not in dims[d]["options"]]
    if unknown:
        raise ClassificationError(f"labels not defined by the classification model: {unknown}")

    contributions = tuple((d, inputs[d], int(dims[d]["options"][inputs[d]])) for d in dims if d in inputs)
    points = sum(c[2] for c in contributions)
    points_tier = next(t["tier"] for t in model["points_thresholds"] if points >= t["min_points"])

    matched = [r for r in model["floor_rules"] if all(inputs.get(d) in vals for d, vals in r["when"].items())]
    floor_tier = min((r["min_tier"] for r in matched), default=None)
    tier = min(points_tier, floor_tier) if floor_tier is not None else points_tier

    tiers = {t["rank"]: t for t in model["tiers"]}
    reasons = [f"{r['id']} ({r['description']}) sets at least Tier {r['min_tier']}" for r in matched]
    reasons.append(f"{points} points → Tier {points_tier}")
    explanation = f"Tier {tier} ({tiers[tier]['label']}): " + "; ".join(reasons) + "."
    return ClassificationResult(
        tier=tier,
        tier_label=tiers[tier]["label"],
        asvs_target=str(tiers[tier]["asvs_target"]),
        points=points,
        points_tier=points_tier,
        floor_tier=floor_tier,
        matched_floor_rules=tuple(r["id"] for r in matched),
        contributions=contributions,
        explanation=explanation,
    )
