// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ChartFrame, ChartTooltip, Legend, type Tip } from "./Frame";

export interface Range { key: string; label: string; min: number; p25: number; median: number; p75: number; max: number; count: number }

/** How scores spread across applications, one row per item: the full range as a thin line, the middle half
 *  (p25–p75) as a bar in slot 1, the median as an ink tick. A distribution, never a ranking of applications. */
export function RangeBars({ label, items, max = 3 }: { label: string; items: Range[]; max?: number }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const W = 720, labelW = 210, valueW = 64, rowH = 30, top = 4;
  const plotW = W - labelW - valueW;
  const H = top + items.length * rowH + 22;
  const sx = (v: number) => labelW + (Math.min(Math.max(v, 0), max) / max) * plotW;
  const f = (v: number) => v.toFixed(2);
  const table = {
    columns: ["Practice", "Lowest", "25th percentile", "Median", "75th percentile", "Highest", "Applications"],
    rows: items.map((r) => [r.label, f(r.min), f(r.p25), f(r.median), f(r.p75), f(r.max), r.count]),
  };
  const rows = (r: Range) => [
    { value: f(r.median), key: "median" },
    { value: `${f(r.p25)} – ${f(r.p75)}`, key: "middle half" },
    { value: `${f(r.min)} – ${f(r.max)}`, key: `range over ${r.count} application${r.count === 1 ? "" : "s"}` },
  ];
  return (
    <ChartFrame label={label} table={table}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="group" aria-label={label} onPointerLeave={() => setTip(null)} className="block max-w-[880px]">
        {Array.from({ length: max + 1 }, (_, t) => (
          <g key={t}>
            <line x1={sx(t)} x2={sx(t)} y1={top} y2={H - 20} stroke="var(--grid)" strokeWidth={1} />
            <text x={sx(t)} y={H - 4} textAnchor="middle" fontSize={11} fill="var(--muted)">{t}</text>
          </g>
        ))}
        {items.map((r, i) => {
          const yy = top + i * rowH, mid = yy + rowH / 2, barH = 12;
          const x0 = sx(r.p25), w = Math.max(sx(r.p75) - x0, 4);
          return (
            <g
              key={r.key}
              tabIndex={0}
              role="img"
              aria-label={`${r.label}: median ${f(r.median)}, middle half ${f(r.p25)} to ${f(r.p75)}, range ${f(r.min)} to ${f(r.max)}`}
              onPointerMove={(e) => setTip({ x: e.clientX, y: e.clientY, title: r.label, rows: rows(r) })}
              onFocus={(e) => { const b = (e.currentTarget as SVGGElement).getBoundingClientRect(); setTip({ x: b.left + b.width / 2, y: b.top, title: r.label, rows: rows(r) }); }}
              onBlur={() => setTip(null)}
              className="outline-none focus-visible:[&>rect:first-child]:fill-[var(--accent-soft)]"
            >
              <rect x={0} y={yy} width={W} height={rowH} fill="transparent" />
              <text x={labelW - 10} y={mid + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)">{r.label}</text>
              <line x1={sx(r.min)} x2={sx(r.max)} y1={mid} y2={mid} stroke="var(--axis)" strokeWidth={2} strokeLinecap="round" />
              <rect x={w === 4 ? x0 - 2 : x0} y={mid - barH / 2} width={w} height={barH} rx={4} fill="var(--series-1)" stroke="var(--surface)" strokeWidth={2} />
              <line x1={sx(r.median)} x2={sx(r.median)} y1={yy + 4} y2={yy + rowH - 4} stroke="var(--ink)" strokeWidth={2} />
              <text x={W - 4} y={mid + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)" className="tabular-nums">{f(r.median)}</text>
            </g>
          );
        })}
        <line x1={labelW} x2={labelW} y1={top} y2={H - 20} stroke="var(--axis)" strokeWidth={1} />
      </svg>
      <Legend
        items={[
          { label: "Middle half of applications", color: "var(--series-1)", shape: "square" },
          { label: "Median (value on the right)", color: "var(--ink)", shape: "tick" },
          { label: "Lowest to highest", color: "var(--axis)", shape: "line" },
        ]}
      />
      <ChartTooltip tip={tip} />
    </ChartFrame>
  );
}
