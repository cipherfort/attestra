# SPDX-License-Identifier: Apache-2.0
"""SAMM maturity derived from control states (SAMM/ASVS methodology section A.3, config/maturity-methodology.yaml).

Per (stream, level) answer:
    automated_fraction = Σ weight(state) / count(mandatory mapped controls that apply)
    automated_answer   = band(automated_fraction) onto the official answer scale
    both automated and manual  → min(manual, automated + tolerance)     provenance: automated (capped manual)
    only automated             → automated_answer                       provenance: automated
    only manual                → manual answer                          provenance: manual_independent / manual_self
    neither                    → 0                                      provenance: unassessed
stream = Σ level answers (0–3) · practice = mean(streams) · function = mean(practices) · overall = mean(functions)
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from statistics import mean
from typing import Any

PROVENANCE = ("automated", "manual_independent", "manual_self", "unassessed")


@dataclass(frozen=True)
class StateInput:
    control_key: str
    state: str
    requirement: str
    observe_mode: bool = False
    fraction: float | None = None  # for PARTIAL states


@dataclass(frozen=True)
class ManualAnswer:
    value: float
    confidence: str  # M1 | M2


@dataclass(frozen=True)
class Answer:
    stream: str
    level: int
    value: float
    provenance: str
    automated_fraction: float | None
    controls: tuple[str, ...]
    capped: bool = False


@dataclass
class MaturityScore:
    item: str
    name: str
    score: float
    provenance: dict[str, float] = field(default_factory=dict)
    target: float | None = None


@dataclass
class MaturityReport:
    answers: list[Answer]
    streams: dict[str, MaturityScore]
    practices: dict[str, MaturityScore]
    functions: dict[str, MaturityScore]
    overall: float
    meets_target: bool | None


def _weight(s: StateInput, weights: Mapping[str, Any]) -> float | None:
    rule = weights.get(s.state, 0.0)
    if rule == "exclude":
        return None
    if rule == "prorata":
        return 0.5 if s.fraction is None else max(0.0, min(1.0, s.fraction))
    if rule == "last_known":
        return 0.0  # the engine substitutes the last known state before calling; an unresolved error counts 0
    return float(rule)


def _band(fraction: float, bands: Iterable[Mapping[str, Any]]) -> float:
    return float(next(b["answer"] for b in bands if fraction >= b["min_fraction"]))


def stream_level_mappings(controls: Mapping[str, Mapping[str, Any]]) -> dict[tuple[str, int], list[str]]:
    out: dict[tuple[str, int], list[str]] = defaultdict(list)
    for key, c in controls.items():
        for m in c["mappings"].get("samm", []):
            out[(m["stream"], int(m["level"]))].append(key)
    return out


def compute(
    states: Mapping[str, StateInput],
    controls: Mapping[str, Mapping[str, Any]],
    samm: Mapping[str, Any],
    methodology: Mapping[str, Any],
    manual: Mapping[tuple[str, int], ManualAnswer] | None = None,
    targets: Mapping[str, float] | None = None,
    practices_in_scope: set[str] | None = None,
) -> MaturityReport:
    manual = manual or {}
    mappings = stream_level_mappings(controls)
    weights = methodology["control_state_weights"]
    tolerance = float(methodology["manual_cap_tolerance"])
    exclude_observe = methodology.get("observe_mode_controls") == "exclude"

    answers: list[Answer] = []
    streams: dict[str, MaturityScore] = {}
    practices: dict[str, MaturityScore] = {}
    functions: dict[str, MaturityScore] = {}

    for bf in samm["business_functions"]:
        practice_scores: list[float] = []
        for p in bf["practices"]:
            if practices_in_scope is not None and p["id"] not in practices_in_scope:
                continue
            stream_scores: list[float] = []
            provenance_counts: defaultdict[str, int] = defaultdict(int)
            for s in p["streams"]:
                total = 0.0
                for level in (1, 2, 3):
                    a = _answer(
                        s["id"],
                        level,
                        mappings.get((s["id"], level), []),
                        states,
                        weights,
                        methodology["answer_bands"],
                        manual.get((s["id"], level)),
                        tolerance,
                        exclude_observe,
                    )
                    answers.append(a)
                    total += a.value
                    provenance_counts[a.provenance] += 1
                streams[s["id"]] = MaturityScore(s["id"], s["name"], round(total, 2))
                stream_scores.append(total)
            n = sum(provenance_counts.values())
            score = round(mean(stream_scores), 2)
            practices[p["id"]] = MaturityScore(
                p["id"],
                p["name"],
                score,
                {k: round(100 * provenance_counts[k] / n, 1) for k in PROVENANCE},
                (targets or {}).get(p["id"]),
            )
            practice_scores.append(score)
        if practice_scores:
            functions[bf["id"]] = MaturityScore(bf["id"], bf["name"], round(mean(practice_scores), 2))

    overall = round(mean(f.score for f in functions.values()), 2) if functions else 0.0
    meets = None
    if targets:
        meets = all(practices[k].score >= v for k, v in targets.items() if k in practices)
    return MaturityReport(answers, streams, practices, functions, overall, meets)


def _answer(
    stream: str,
    level: int,
    mapped: list[str],
    states: Mapping[str, StateInput],
    weights: Mapping[str, Any],
    bands: Iterable[Mapping[str, Any]],
    manual: ManualAnswer | None,
    tolerance: float,
    exclude_observe: bool,
) -> Answer:
    counted: list[tuple[str, float]] = []
    for key in mapped:
        st = states.get(key)
        if st is None or st.requirement != "mandatory" or (exclude_observe and st.observe_mode):
            continue
        w = _weight(st, weights)
        if w is not None:
            counted.append((key, w))

    automated = None
    if counted:
        fraction = sum(w for _, w in counted) / len(counted)
        automated = _band(fraction, bands)
        keys = tuple(k for k, _ in counted)
        if manual is not None:
            capped = manual.value > automated + tolerance
            value = min(manual.value, automated + tolerance)
            return Answer(stream, level, value, "automated", round(fraction, 3), keys, capped)
        return Answer(stream, level, automated, "automated", round(fraction, 3), keys)
    if manual is not None:
        prov = "manual_independent" if manual.confidence == "M2" else "manual_self"
        return Answer(stream, level, manual.value, prov, None, ())
    return Answer(stream, level, 0.0, "unassessed", None, ())
