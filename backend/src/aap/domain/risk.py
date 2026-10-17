# SPDX-License-Identifier: Apache-2.0
"""Contextual finding prioritisation per config/risk-model.yaml (ADR-011, ADR-012).

A prioritisation model, not an objective truth: every result carries its inputs, the rules that fired and a
human-readable explanation ("Why P1?").
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from aap.domain.expressions import Expression, compile_expression

PRIORITY_ORDER = ("P1", "P2", "P3", "P4")
ROOTS = frozenset({"app", "finding", "vuln", "component", "priority", "sla_breached"})


def _clamp(v: int) -> int:
    return max(1, min(5, v))


def more_urgent(a: str, b: str) -> str:
    return a if PRIORITY_ORDER.index(a) <= PRIORITY_ORDER.index(b) else b


@dataclass(frozen=True)
class RiskResult:
    likelihood: int
    impact: int
    score: int
    priority: str
    applied_rules: tuple[str, ...]
    explanation: str
    inputs: dict[str, Any] = field(hash=False)

    def triage_due(self, detected: datetime, model: Mapping[str, Any]) -> datetime:
        return detected + timedelta(days=int(model["sla"]["triage"][self.priority]))

    def remediation_due(self, detected: datetime, model: Mapping[str, Any], factor: float = 1.0) -> datetime:
        return detected + timedelta(days=int(model["sla"]["remediate"][self.priority]) * factor)


class RiskModel:
    def __init__(self, model: Mapping[str, Any]):
        self.model = model
        self._compiled: dict[str, Expression] = {}

    def _expr(self, source: str) -> Expression:
        if source not in self._compiled:
            self._compiled[source] = compile_expression(source, ROOTS)
        return self._compiled[source]

    def _base_likelihood(self, ctx: Mapping[str, Any]) -> tuple[int, str]:
        vuln = ctx.get("vuln") or {}
        finding = ctx.get("finding") or {}
        for source in self.model["likelihood"]["base"]["sources"]:
            ((name, spec),) = source.items()
            if name == "epss_percentile" and vuln.get("epss_percentile") is not None:
                pct = float(vuln["epss_percentile"])
                band = next(b for b in spec["bands"] if pct >= b["gte"])
                return int(band["value"]), f"EPSS percentile {pct:.3f} → {band['value']}"
            if name == "cvss_exploitability" and finding.get("cvss_exploitability") in spec["map"]:
                label = finding["cvss_exploitability"]
                return int(spec["map"][label]), f"CVSS exploitability {label} → {spec['map'][label]}"
            if name == "tool_severity" and finding.get("tool_severity") in spec["map"]:
                sev = finding["tool_severity"]
                return int(spec["map"][sev]), f"tool severity {sev} → {spec['map'][sev]}"
        return 2, "no exploitability signal → default 2"

    def _apply(self, section: str, base: int, ctx: Mapping[str, Any], fired: list[str], why: list[str]) -> int:
        value = base
        for m in self.model[section]["modifiers"]:
            if self._expr(m["when"]).test(ctx):
                value += int(m["delta"])
                fired.append(f"{section}.{m['id']}")
                why.append(f"{m['id']} {int(m['delta']):+d}")
        return _clamp(value)

    def score(self, ctx: Mapping[str, Any]) -> RiskResult:
        fired: list[str] = []
        l_why: list[str] = []
        i_why: list[str] = []
        base_l, base_l_why = self._base_likelihood(ctx)
        likelihood = self._apply("likelihood", base_l, ctx, fired, l_why)

        tier = int((ctx.get("app") or {}).get("tier") or 4)
        base_i = int(self.model["impact"]["base"]["from_tier"][tier])
        impact = self._apply("impact", base_i, ctx, fired, i_why)

        score = likelihood * impact
        priority = next(b["priority"] for b in self.model["bands"] if score >= b["min_score"])
        banded = priority
        for o in self.model["overrides"]:
            if self._expr(o["when"]).test(ctx):
                raised = more_urgent(priority, o["min_priority"])
                if raised != priority:
                    fired.append(f"override.{o['id']}")
                priority = raised

        parts = [
            f"likelihood {likelihood} ({base_l_why}" + (", " + ", ".join(l_why) if l_why else "") + ")",
            f"impact {impact} (Tier {tier} base {base_i}" + (", " + ", ".join(i_why) if i_why else "") + ")",
            f"score {score} → {banded}",
        ]
        if priority != banded:
            parts.append(f"raised to {priority} by " + ", ".join(r for r in fired if r.startswith("override.")))
        return RiskResult(
            likelihood=likelihood,
            impact=impact,
            score=score,
            priority=priority,
            applied_rules=tuple(fired),
            explanation="; ".join(parts) + ".",
            inputs={k: v for k, v in ctx.items() if k in ROOTS},
        )

    def soc_escalation(self, ctx: Mapping[str, Any]) -> bool:
        return any(self._expr(s["when"]).test(ctx) for s in self.model.get("soc_escalation", []))
