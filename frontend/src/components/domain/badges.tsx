// SPDX-License-Identifier: Apache-2.0
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  CircleOff,
  Clock3,
  MinusCircle,
  ShieldCheck,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import type { ControlStateValue, Priority } from "../../api";

const pill = "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink";

/** Control states. Status colours are reserved for state and always ship with an icon and a label. */
export const STATES: Record<ControlStateValue, { label: string; color: string; icon: LucideIcon; order: number; hint: string }> = {
  not_satisfied: { label: "Not satisfied", color: "var(--critical)", icon: XCircle, order: 0, hint: "Current evidence shows the control is not met" },
  no_evidence: { label: "No evidence", color: "var(--neutral)", icon: CircleOff, order: 1, hint: "No current evidence was received for this control" },
  stale: { label: "Stale", color: "var(--serious)", icon: Clock3, order: 2, hint: "The evidence is older than its freshness window" },
  error: { label: "Not evaluated", color: "var(--unevaluated)", icon: AlertTriangle, order: 3, hint: "The evaluator could not reach a verdict" },
  partial: { label: "Partial", color: "var(--warning)", icon: CircleDashed, order: 4, hint: "Met in some scopes or for some requirements" },
  excepted: { label: "Excepted", color: "var(--series-1)", icon: ShieldCheck, order: 5, hint: "An approved, time-bound exception covers it" },
  satisfied: { label: "Satisfied", color: "var(--good)", icon: CheckCircle2, order: 6, hint: "Current, verified evidence shows the control is met" },
  not_applicable: { label: "Not applicable", color: "var(--axis)", icon: MinusCircle, order: 7, hint: "Does not apply at this application's tier" },
};

export function StateBadge({ state }: { state: ControlStateValue }) {
  const s = STATES[state];
  return (
    <span className={pill} title={s.hint}>
      <s.icon className="size-3.5" strokeWidth={2} aria-hidden="true" style={{ color: s.color }} />
      {s.label}
    </span>
  );
}

export const PRIORITY: Record<Priority, { color: string; days: number }> = {
  P1: { color: "var(--critical)", days: 7 },
  P2: { color: "var(--serious)", days: 30 },
  P3: { color: "var(--warning)", days: 90 },
  P4: { color: "var(--neutral)", days: 180 },
};

/** Contextual priority with its SLA; `due` adds a countdown ("3 days left" / "5 days overdue"). */
export function PriorityChip({ p, count, due }: { p: Priority | null; count?: number; due?: string | null }) {
  if (!p) return <span className={pill}>Unscored{count !== undefined ? ` ×${count}` : ""}</span>;
  let sla = "";
  if (due) {
    const days = Math.ceil((new Date(due).getTime() - Date.now()) / 86_400_000);
    sla = days < 0 ? `${-days}d overdue` : `${days}d left`;
  }
  return (
    <span className={pill} title={`${p}: fix within ${PRIORITY[p].days} days`}>
      <span aria-hidden="true" className="size-2 rounded-full" style={{ background: PRIORITY[p].color }} />
      {p}
      {count !== undefined && <span className="text-ink-2">×{count}</span>}
      {sla && <span className={`font-normal ${sla.includes("overdue") ? "text-critical-ink" : "text-muted"}`}>· {sla}</span>}
    </span>
  );
}

const TIERS: Record<number, string> = { 1: "Critical", 2: "High", 3: "Moderate", 4: "Low" };

export function TierBadge({ tier }: { tier: number | null }) {
  return (
    <span className={`${pill} font-semibold`} title={tier ? `Risk tier ${tier} (${TIERS[tier] ?? ""}): 1 = critical … 4 = low` : "Not classified yet"}>
      {tier ? `Tier ${tier}` : "Unclassified"}
    </span>
  );
}

/** Evidence confidence (docs/security/security-model.md): how strongly the platform can stand behind the evidence. */
export const CONFIDENCE: Record<string, { label: string; meaning: string; level: number; manual?: boolean }> = {
  C0: { label: "Declared", meaning: "A claim only; never satisfies a control", level: 0 },
  C1: { label: "Configured", meaning: "A setting read from the system of record's API", level: 1 },
  C2: { label: "Executed", meaning: "An approved pipeline ran on this exact commit", level: 2 },
  C3: { label: "Attested", meaning: "Executed and signed by the approved workflow's identity, or read from the system of record", level: 3 },
  M1: { label: "Self-assessed", meaning: "Manual, recorded by the owning team", level: 1, manual: true },
  M2: { label: "Independent", meaning: "Manual, reviewed by someone independent of the owning team", level: 2, manual: true },
};

export function ConfidenceBadge({ level }: { level: string }) {
  const c = CONFIDENCE[level] ?? { label: level, meaning: "", level: 0 };
  return (
    <span className={pill} title={`${level} ${c.label}: ${c.meaning}`}>
      <span aria-hidden="true" className="flex items-end gap-px">
        {[1, 2, 3].map((i) => (
          <span
            key={i}
            className={`w-1 rounded-sm ${i <= c.level ? (c.manual ? "border border-accent" : "bg-accent") : "bg-surface-3"}`}
            style={{ height: 4 + i * 3 }}
          />
        ))}
      </span>
      <span className="font-mono">{level}</span>
      <span className="text-ink-2">{c.label}</span>
    </span>
  );
}
