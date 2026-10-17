// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState, type ReactNode } from "react";
import type { ControlStateValue, Priority } from "../api";
import { ApiError } from "../api";

// Status colours are reserved for state and always ship with an icon + label (never colour alone).
export const STATE: Record<ControlStateValue, { label: string; color: string; icon: string; order: number }> = {
  not_satisfied: { label: "Not satisfied", color: "var(--critical)", icon: "✕", order: 0 },
  no_evidence: { label: "No evidence", color: "var(--neutral)", icon: "○", order: 1 },
  stale: { label: "Stale", color: "var(--serious)", icon: "↻", order: 2 },
  error: { label: "Not evaluated", color: "var(--unevaluated)", icon: "!", order: 3 },
  partial: { label: "Partial", color: "var(--warning)", icon: "◐", order: 4 },
  excepted: { label: "Excepted", color: "var(--series-1)", icon: "E", order: 5 },
  satisfied: { label: "Satisfied", color: "var(--good)", icon: "✓", order: 6 },
  not_applicable: { label: "Not applicable", color: "var(--axis)", icon: "–", order: 7 },
};

export function StateBadge({ state }: { state: ControlStateValue }) {
  const s = STATE[state];
  return (
    <span className="badge" title={s.label}>
      <span aria-hidden="true" style={{ color: s.color }} className="icon">{s.icon}</span>
      {s.label}
    </span>
  );
}

const PRIORITY: Record<Priority, { color: string; hint: string }> = {
  P1: { color: "var(--critical)", hint: "fix within 7 days" },
  P2: { color: "var(--serious)", hint: "fix within 30 days" },
  P3: { color: "var(--warning)", hint: "fix within 90 days" },
  P4: { color: "var(--neutral)", hint: "fix within 180 days" },
};

export function PriorityChip({ p, count }: { p: Priority | null; count?: number }) {
  if (!p) return <span className="badge">Unscored{count !== undefined ? ` ×${count}` : ""}</span>;
  return (
    <span className="badge" title={PRIORITY[p].hint}>
      <span className="dot" aria-hidden="true" style={{ background: PRIORITY[p].color }} />
      {p}{count !== undefined ? ` ×${count}` : ""}
    </span>
  );
}

export function Tier({ tier }: { tier: number | null }) {
  return <span className="tier" title="Risk tier: 1 = critical … 4 = low">{tier ? `Tier ${tier}` : "Unclassified"}</span>;
}

export function date(s: string | null | undefined, withTime = false): string {
  if (!s) return "—";
  const d = new Date(s);
  return withTime
    ? d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : d.toLocaleDateString(undefined, { dateStyle: "medium" });
}

export function useLoad<T>(load: () => Promise<T>, deps: unknown[]): { data?: T; error?: ApiError | Error; reload: () => void } {
  const [state, setState] = useState<{ data?: T; error?: ApiError | Error }>({});
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setState({});
    load().then((data) => live && setState({ data }), (error) => live && setState({ error }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

export function Loadable<T>({ state, children }: { state: { data?: T; error?: Error }; children: (d: T) => ReactNode }) {
  if (state.error) {
    const e = state.error;
    if (e instanceof ApiError && e.status === 404)
      return <div className="notice">Not found, or not visible to you. Out-of-scope items look the same as missing ones (no enumeration).</div>;
    if (e instanceof ApiError && e.status === 403)
      return <div className="notice">Your role doesn't include this view ({e.detail}).</div>;
    return <div className="notice error">Couldn't load: {e.message}</div>;
  }
  if (state.data === undefined) return <div className="muted">Loading…</div>;
  return <>{children(state.data)}</>;
}
