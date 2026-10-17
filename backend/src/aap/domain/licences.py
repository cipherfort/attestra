# SPDX-License-Identifier: Apache-2.0
"""Licence policy evaluation (ADR-029, config/licence-policy.yaml) over SBOM components.

SPDX expressions are evaluated conservatively: `A OR B` passes if either side is acceptable, `A AND B` needs
both, `WITH` exceptions are treated as the base licence. Missing / NOASSERTION licences count as unknown.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

UNKNOWN = frozenset({"", "NOASSERTION", "NONE", "UNKNOWN"})


@dataclass(frozen=True)
class LicenceResult:
    components: int
    denied: tuple[str, ...]  # "purl (licence)"
    review: tuple[str, ...]
    unknown: int

    @property
    def unknown_pct(self) -> float:
        return round(100.0 * self.unknown / self.components, 1) if self.components else 0.0

    def passes(self, max_unknown_pct: float) -> bool:
        return not self.denied and self.unknown_pct <= max_unknown_pct


def _classify(licence: str, policy: Mapping[str, Any]) -> str:
    lic = re.sub(r"\s+WITH\s+\S+", "", licence.strip().strip("()"))
    if lic in policy["allow"]:
        return "allow"
    if lic in policy["review"]:
        return "review"
    if lic in policy["deny"]:
        return "deny"
    return "unknown"


def classify_expression(expr: str | None, policy: Mapping[str, Any]) -> str:
    if expr is None or expr.strip().upper() in UNKNOWN:
        return "unknown"
    order = ("allow", "review", "unknown", "deny")
    best_or = []
    for alt in re.split(r"\s+OR\s+", expr):
        parts = [_classify(p, policy) for p in re.split(r"\s+AND\s+", alt)]
        best_or.append(max(parts, key=order.index))  # AND → the worst part
    return min(best_or, key=order.index)  # OR → the best alternative


def evaluate(components: Iterable[tuple[str, str | None]], policy: Mapping[str, Any]) -> LicenceResult:
    denied, review, unknown, n = [], [], 0, 0
    for purl, expr in components:
        n += 1
        verdict = classify_expression(expr, policy)
        if verdict == "deny":
            denied.append(f"{purl} ({expr})")
        elif verdict == "review":
            review.append(f"{purl} ({expr})")
        elif verdict == "unknown":
            unknown += 1
    return LicenceResult(n, tuple(denied), tuple(review), unknown)
