// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import type { ControlStateValue } from "../../api";
import { ChartTooltip, type Tip } from "../charts/Frame";
import { STATES } from "./badges";

export const COVERAGE_ORDER: ControlStateValue[] = ["satisfied", "partial", "excepted", "stale", "not_satisfied", "no_evidence", "error"];

export function coverageRatio(counts: Partial<Record<ControlStateValue, number>> | null | undefined): number | null {
  const total = COVERAGE_ORDER.reduce((s, k) => s + (counts?.[k] ?? 0), 0);
  return total ? (counts?.satisfied ?? 0) / total : null;
}

/** Mandatory controls by state: one stacked bar, 2px surface gaps between segments, rounded only at the ends, a
 *  tooltip on every segment, and the proven count beside it in ink. */
export function CoverageBar({ counts, width = 180 }: { counts: Partial<Record<ControlStateValue, number>> | null | undefined; width?: number }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const total = COVERAGE_ORDER.reduce((s, k) => s + (counts?.[k] ?? 0), 0);
  if (!total) return <span className="text-xs text-muted">Not evaluated yet</span>;
  const present = COVERAGE_ORDER.filter((k) => counts?.[k]);
  const sat = counts?.satisfied ?? 0;
  return (
    <span className="inline-flex items-center gap-3">
      <span
        role="img"
        aria-label={`${sat} of ${total} mandatory controls satisfied`}
        className="flex h-2 gap-0.5 overflow-hidden rounded-full"
        style={{ width }}
        onPointerLeave={() => setTip(null)}
      >
        {present.map((k) => (
          <span
            key={k}
            className="h-full first:rounded-l-full last:rounded-r-full"
            style={{ flexGrow: counts?.[k] ?? 0, flexBasis: 0, background: STATES[k].color }}
            onPointerMove={(e) => setTip({ x: e.clientX, y: e.clientY, title: STATES[k].label, rows: [{ value: `${counts?.[k]} of ${total}`, key: "mandatory controls" }] })}
          />
        ))}
      </span>
      <span className="text-xs tabular-nums text-ink-2"><span className="font-semibold text-ink">{sat}</span>/{total}</span>
      <ChartTooltip tip={tip} />
    </span>
  );
}

export function CoverageLegend() {
  return (
    <ul className="plain m-0 flex flex-wrap gap-x-4 gap-y-1 p-0 text-xs text-ink-2">
      {COVERAGE_ORDER.map((k) => {
        const S = STATES[k];
        return (
          <li key={k} className="flex items-center gap-1.5">
            <span aria-hidden="true" className="size-2.5 rounded-sm" style={{ background: S.color }} />
            <S.icon aria-hidden="true" className="size-3" strokeWidth={2} />
            {S.label}
          </li>
        );
      })}
    </ul>
  );
}
