// SPDX-License-Identifier: Apache-2.0
import { Table2, LineChart as LineIcon } from "lucide-react";
import { useState, type ReactNode } from "react";

export interface TableView { columns: string[]; rows: (string | number)[][] }

export interface Tip { x: number; y: number; title: string; rows: { key?: string; color?: string; dash?: boolean; value: string }[] }

/** Hover/focus readout: the value leads, the series name follows; series keyed by a short line, not a box. */
export function ChartTooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  const left = Math.min(tip.x + 14, window.innerWidth - 260);
  return (
    <div
      role="status"
      className="pointer-events-none fixed z-50 min-w-36 max-w-64 rounded-lg border border-line bg-surface-3 px-3 py-2 text-xs shadow-card"
      style={{ left, top: tip.y + 14 }}
    >
      <div className="mb-1 text-muted">{tip.title}</div>
      {tip.rows.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          {r.color && <span aria-hidden="true" className="h-0.5 w-3 rounded" style={{ background: r.color }} />}
          <span className="font-semibold text-ink">{r.value}</span>
          {r.key && <span className="text-ink-2">{r.key}</span>}
        </div>
      ))}
    </div>
  );
}

/** Legend keys mirror the mark: a line for lines, a square for areas/bars. */
export function Legend({ items }: { items: { label: string; color: string; shape?: "line" | "square" | "tick" }[] }) {
  return (
    <ul className="plain m-0 mt-3 flex flex-wrap gap-x-4 gap-y-1 p-0 text-xs text-ink-2">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          {i.shape === "square" ? (
            <span aria-hidden="true" className="size-2.5 rounded-sm" style={{ background: i.color }} />
          ) : i.shape === "tick" ? (
            <span aria-hidden="true" className="h-3 w-0.5 rounded" style={{ background: i.color }} />
          ) : (
            <span aria-hidden="true" className="h-0.5 w-3.5 rounded" style={{ background: i.color }} />
          )}
          {i.label}
        </li>
      ))}
    </ul>
  );
}

/** A chart with its table view: every value a chart shows is also readable without hovering or seeing colour. */
export function ChartFrame({ label, table, children }: { label: string; table: TableView; children: ReactNode }) {
  const [asTable, setAsTable] = useState(false);
  return (
    <figure className="m-0">
      <div className="mb-2 flex justify-end">
        <div role="group" aria-label={`${label}: view`} className="inline-flex rounded-md border border-line p-0.5">
          {([[false, "Chart", LineIcon], [true, "Table", Table2]] as const).map(([v, name, Icon]) => (
            <button
              key={name}
              type="button"
              aria-pressed={asTable === v}
              onClick={() => setAsTable(v)}
              className={`flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium ${asTable === v ? "bg-surface-3 text-ink" : "bg-transparent text-muted hover:text-ink"}`}
            >
              <Icon className="size-3" aria-hidden="true" />
              {name}
            </button>
          ))}
        </div>
      </div>
      {asTable ? (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <caption className="sr-only">{label}</caption>
            <thead>
              <tr>{table.columns.map((c, i) => <th key={c} className={`border-b border-line px-3 py-2 text-xs font-medium text-muted ${i ? "text-right" : "text-left"}`}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {table.rows.map((r, i) => (
                <tr key={i} className="border-b border-line last:border-0">
                  {r.map((v, j) => <td key={j} className={`px-3 py-2 ${j ? "text-right tabular-nums" : ""}`}>{v}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        children
      )}
    </figure>
  );
}
