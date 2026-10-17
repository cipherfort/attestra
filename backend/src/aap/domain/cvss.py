# SPDX-License-Identifier: Apache-2.0
"""CVSS v3.0/v3.1 base score from a vector string (FIRST CVSS v3.1 specification section 7.1 and Appendix A).

OSV advisories carry the vector, not the score. Scores are computed here rather than trusted from a third field.
"""

from __future__ import annotations

import math
from decimal import Decimal

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    pass


def roundup(x: float) -> float:
    """Appendix A: the smallest number, to one decimal place, that is >= x (avoids float artefacts)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> Decimal:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise CvssError(f"not a CVSS v3 vector: {vector[:60]!r}")
    metrics: dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        metrics[k] = v
    if any(k not in metrics for k in REQUIRED):
        raise CvssError(f"vector misses base metrics: {vector[:60]!r}")
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            raise KeyError("S")
        iss = 1 - (1 - _W["C"][metrics["C"]]) * (1 - _W["I"][metrics["I"]]) * (1 - _W["A"][metrics["A"]])
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = (
            8.22
            * _W["AV"][metrics["AV"]]
            * _W["AC"][metrics["AC"]]
            * _PR[scope][metrics["PR"]]
            * _W["UI"][metrics["UI"]]
        )
    except KeyError as e:
        raise CvssError(f"invalid metric value in {vector[:60]!r}") from e
    if impact <= 0:
        return Decimal("0.0")
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return Decimal(str(roundup(min(raw, 10))))
