// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Sparkline } from "../charts/LineChart";

/** Stat tile: label · value (semibold, auto-compact) · optional context line · optional 12-point trend. */
export function Kpi({ label, value, sub, trend, tone }: { label: string; value: ReactNode; sub?: ReactNode; trend?: number[]; tone?: "critical" | "good" }) {
  return (
    <div className="rounded-xl border border-line bg-surface px-5 py-4">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className="mt-1.5 flex items-end justify-between gap-3">
        <div className={`text-[28px] font-semibold leading-none tracking-tight ${tone === "critical" ? "text-critical-ink" : tone === "good" ? "text-good-ink" : "text-ink"}`}>
          {value}
        </div>
        {trend && <Sparkline values={trend} label={`${label} trend`} />}
      </div>
      {sub && <div className="mt-2 text-xs text-ink-2">{sub}</div>}
    </div>
  );
}

export function compact(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}
