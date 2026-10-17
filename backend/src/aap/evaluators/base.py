# SPDX-License-Identifier: Apache-2.0
"""Evaluator framework.

`evaluate_control` wraps every evaluator with the rules that must hold for ALL controls:
  * applicability (tier × conditions) → NOT_APPLICABLE
  * an active approved exception → EXCEPTED
  * only fresh evidence at ≥ the required confidence is offered to the evaluator; when the only evidence is
    stale or below confidence, the state says so explicitly (STALE / NO_EVIDENCE) instead of the evaluator
    ever seeing it. This is how "a configuration file present" (C1) can never satisfy an activity control (C2+).
  * evaluators not implemented yet report ERROR, never a guessed state
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aap.domain.controls import AppFacts, ControlState, EvidenceView, applicability, required_confidence
from aap.domain.evidence import confidence_rank, meets
from aap.domain.freshness import USABLE


@dataclass(frozen=True)
class FindingView:
    id: str
    finding_type: str
    status: str
    priority: str | None
    sla_breached: bool
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationInput:
    control: Mapping[str, Any]
    app: AppFacts
    evidence: Sequence[EvidenceView]  # usable evidence of the control's types at ≥ required confidence
    findings: Sequence[FindingView]
    now: datetime
    params: Mapping[str, Any]
    required_confidence: str


@dataclass(frozen=True)
class EvaluationResult:
    state: ControlState
    explanation: str
    evidence_ids: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)
    evaluator: str = ""


Evaluator = Callable[[EvaluationInput], EvaluationResult]
registry: dict[str, Evaluator] = {}


def evaluator(name: str) -> Callable[[Evaluator], Evaluator]:
    def register(fn: Evaluator) -> Evaluator:
        registry[name] = fn
        return fn

    return register


def _tier_param(value: Any, tier: int) -> Any:
    if isinstance(value, Mapping) and value and all(str(k).isdigit() for k in value):
        return {int(k): v for k, v in value.items()}.get(tier)
    return value


def evaluate_control(
    control: Mapping[str, Any],
    app: AppFacts,
    evidence: Sequence[EvidenceView],
    findings: Sequence[FindingView],
    now: datetime,
    active_exception: str | None = None,
) -> EvaluationResult:
    name = control["assessment"]["evaluator"]
    appl = applicability(control, app)
    if appl.requirement == "n/a":
        return EvaluationResult(ControlState.NOT_APPLICABLE, appl.reason, evaluator=name)
    if active_exception:
        return EvaluationResult(
            ControlState.EXCEPTED, f"covered by approved exception {active_exception}", evaluator=name
        )

    required = required_confidence(control, app.tier)
    types = set(control["assessment"]["evidence_types"])
    relevant = [e for e in evidence if e.type in types]
    # The minimum applies to evidence of the same kind as the requirement (automated C* vs manual M*).
    # Hybrid controls also receive the other kind as *supporting* evidence (e.g. a threat model's C1 structure
    # check alongside its M2 review); evaluators decide what each kind may prove.
    usable = [
        e
        for e in relevant
        if e.state in USABLE
        and (meets(e.confidence, required) or confidence_rank(e.confidence)[0] != confidence_rank(required)[0])
    ]

    fn = registry.get(name)
    if fn is None:
        return EvaluationResult(ControlState.ERROR, f"evaluator {name} is not implemented yet", evaluator=name)

    params = {k: _tier_param(v, app.tier) for k, v in (control["assessment"].get("params") or {}).items()}
    result = fn(EvaluationInput(control, app, usable, findings, now, params, required))

    if result.state is ControlState.NO_EVIDENCE and relevant:
        explained = _explain_unusable(relevant, required, name)
        if explained is not None:
            return explained
    return EvaluationResult(result.state, result.explanation, result.evidence_ids, result.details, name)


def _explain_unusable(relevant: Sequence[EvidenceView], required: str, name: str) -> EvaluationResult | None:
    """Say *why* nothing was usable, so a team knows whether to run, re-run or raise confidence."""
    stale = [e for e in relevant if e.state not in USABLE]
    weak = [e for e in relevant if e.state in USABLE and not meets(e.confidence, required)]
    if weak:
        best = max(weak, key=lambda e: e.observed_at)
        note = " — configuration alone does not prove the control operates" if best.confidence == "C1" else ""
        return EvaluationResult(
            ControlState.NO_EVIDENCE,
            f"only {best.confidence} evidence ({best.type}) present; {required} required{note}",
            (best.id,),
            evaluator=name,
        )
    if stale:
        last = max(stale, key=lambda e: e.observed_at)
        return EvaluationResult(
            ControlState.STALE, f"latest evidence {last.state}: {last.state_reason}", (last.id,), evaluator=name
        )
    return None


def latest(evidence: Sequence[EvidenceView], etype: str | None = None) -> EvidenceView | None:
    pool = [e for e in evidence if etype is None or e.type == etype]
    return max(pool, key=lambda e: e.observed_at) if pool else None
