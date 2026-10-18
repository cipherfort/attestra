// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ChartFrame, ChartTooltip, Legend, type Tip } from "./Frame";

export interface Bullet { key: string; label: string; value: number; target: number | null; detail?: string[] }

/** Scores against a target on a fixed scale (SAMM 0–3): one series (slot 1), the target as an ink tick, the value
 *  at the bar's tip. Bars are at most 24px thick with a 4px rounded data end. */
export function BulletBars({ label, items, max = 3, valueLabel = "Score" }: { label: string; items: Bullet[]; max?: number; valueLabel?: string }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const W = 720, labelW = 210, valueW = 84, rowH = 30, top = 4;
  const plotW = W - labelW - valueW;
  const H = top + items.length * rowH + 22;
  const sx = (v: number) => labelW + (Math.min(v, max) / max) * plotW;
  const table = { columns: [label.split(" ")[0] ?? "Item", valueLabel, "Target"], rows: items.map((b) => [b.label, b.value.toFixed(2), b.target ?? "–"]) };
  return (
    <ChartFrame label={label} table={table}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="group" aria-label={label} onPointerLeave={() => setTip(null)} className="block">
        {Array.from({ length: max + 1 }, (_, t) => (
          <g key={t}>
            <line x1={sx(t)} x2={sx(t)} y1={top} y2={H - 20} stroke="var(--grid)" strokeWidth={1} />
            <text x={sx(t)} y={H - 4} textAnchor="middle" fontSize={11} fill="var(--muted)">{t}</text>
          </g>
        ))}
        {items.map((b, i) => {
          const yy = top + i * rowH;
          const barH = Math.min(14, rowH - 12);
          const w = Math.max(sx(b.value) - labelW, 3);
          const below = b.target !== null && b.value < b.target;
          return (
            <g
              key={b.key}
              tabIndex={0}
              role="img"
              aria-label={`${b.label}: ${b.value.toFixed(2)}${b.target !== null ? ` of target ${b.target}` : ""}`}
              onPointerMove={(e) => setTip({ x: e.clientX, y: e.clientY, title: b.label, rows: [{ value: `${b.value.toFixed(2)} / ${max}`, key: b.target !== null ? `target ${b.target}` : undefined }, ...(b.detail ?? []).map((d) => ({ value: d }))] })}
              onFocus={(e) => { const r = (e.currentTarget as SVGGElement).getBoundingClientRect(); setTip({ x: r.left + r.width / 2, y: r.top, title: b.label, rows: [{ value: `${b.value.toFixed(2)} / ${max}` }] }); }}
              onBlur={() => setTip(null)}
              className="outline-none focus-visible:[&>rect:first-child]:fill-[var(--accent-soft)]"
            >
              <rect x={0} y={yy} width={W} height={rowH} fill="transparent" />
              <text x={labelW - 10} y={yy + rowH / 2 + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)">{b.label}</text>
              <path
                d={`M${labelW},${yy + (rowH - barH) / 2} h${Math.max(w - 4, 0)} a4,4 0 0 1 4,4 v${barH - 8} a4,4 0 0 1 -4,4 h${-Math.max(w - 4, 0)} z`}
                fill="var(--series-1)"
              />
              {b.target !== null && <line x1={sx(b.target)} x2={sx(b.target)} y1={yy + 5} y2={yy + rowH - 5} stroke="var(--ink)" strokeWidth={2} />}
              <text x={W - 4} y={yy + rowH / 2 + 4} textAnchor="end" fontSize={12} fill={below ? "var(--critical-ink)" : "var(--ink-2)"} className="tabular-nums">
                {b.value.toFixed(2)}{b.target !== null ? ` / ${b.target}` : ""}
              </text>
            </g>
          );
        })}
        <line x1={labelW} x2={labelW} y1={top} y2={H - 20} stroke="var(--axis)" strokeWidth={1} />
      </svg>
      <Legend items={[{ label: valueLabel, color: "var(--series-1)", shape: "square" }, ...(items.some((b) => b.target !== null) ? [{ label: "Target", color: "var(--ink)", shape: "tick" as const }] : [])]} />
      <ChartTooltip tip={tip} />
    </ChartFrame>
  );
}
