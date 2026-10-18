// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ChartFrame, ChartTooltip, type Tip } from "./Frame";

/** Rows × columns of a 0–1 magnitude on the one-hue sequential ramp (5 steps). Each cell is a focusable button
 *  with its own tooltip; empty cells (no applicable controls) stay on the surface. */
export function Heatmap({
  label,
  rows,
  columns,
  value,
  detail,
  onCell,
}: {
  label: string;
  rows: { key: string; label: string }[];
  columns: { key: string; label: string; title?: string }[];
  value: (row: string, col: string) => number | null;
  detail?: (row: string, col: string) => string;
  onCell?: (row: string, col: string) => void;
}) {
  const [tip, setTip] = useState<Tip | null>(null);
  const step = (v: number) => `var(--seq-${Math.min(5, Math.max(1, Math.ceil(v * 5) || 1))})`;
  const pct = (v: number | null) => (v === null ? "n/a" : `${Math.round(v * 100)}%`);
  const table = { columns: ["", ...columns.map((c) => c.label)], rows: rows.map((r) => [r.label, ...columns.map((c) => pct(value(r.key, c.key)))]) };
  return (
    <ChartFrame label={label} table={table}>
      <div role="group" aria-label={label} className="overflow-x-auto" onPointerLeave={() => setTip(null)}>
        <div className="grid gap-0.5" style={{ gridTemplateColumns: `minmax(140px, 200px) repeat(${columns.length}, minmax(36px, 1fr))` }}>
          <div />
          {columns.map((c) => (
            <div key={c.key} title={c.title} className="pb-1 text-center text-[11px] font-medium text-muted">{c.label}</div>
          ))}
          {rows.map((r) => (
            <div key={r.key} className="contents">
              <div className="truncate pr-3 text-xs leading-8 text-ink-2">{r.label}</div>
              {columns.map((c) => {
                const v = value(r.key, c.key);
                const text = `${r.label} · ${c.title ?? c.label}: ${pct(v)}${detail ? ` (${detail(r.key, c.key)})` : ""}`;
                const show = (x: number, y: number) => setTip({ x, y, title: `${r.label} · ${c.title ?? c.label}`, rows: [{ value: pct(v), key: detail?.(r.key, c.key) }] });
                return (
                  <button
                    key={c.key}
                    type="button"
                    aria-label={text}
                    disabled={v === null}
                    onClick={() => onCell?.(r.key, c.key)}
                    onPointerMove={(e) => show(e.clientX, e.clientY)}
                    onFocus={(e) => { const b = e.currentTarget.getBoundingClientRect(); show(b.right, b.top); }}
                    onBlur={() => setTip(null)}
                    className="h-8 rounded-sm border-0 p-0 transition-[filter] hover:brightness-125 focus-visible:outline-2 disabled:bg-surface-2"
                    style={v === null ? undefined : { background: step(v) }}
                  />
                );
              })}
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center gap-2 text-xs text-muted" aria-hidden="true">
          <span>0%</span>
          {[1, 2, 3, 4, 5].map((s) => <span key={s} className="h-2.5 w-6 rounded-sm" style={{ background: `var(--seq-${s})` }} />)}
          <span>100%</span>
          <span className="ml-3 inline-block h-2.5 w-6 rounded-sm bg-surface-2" /> <span>not applicable</span>
        </div>
      </div>
      <ChartTooltip tip={tip} />
    </ChartFrame>
  );
}
