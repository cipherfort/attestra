// SPDX-License-Identifier: Apache-2.0
import { scaleLinear, scaleTime } from "d3-scale";
import { area, curveMonotoneX, line } from "d3-shape";
import { useMemo, useRef, useState } from "react";
import { ChartFrame, ChartTooltip, Legend, type Tip } from "./Frame";

export interface Series { key: string; label: string; color: string; values: (number | null)[] }

const fmtMonth = (d: Date) => d.toLocaleDateString(undefined, { month: "short", year: "2-digit" });

/** Time series on one axis (never two): 2px lines, a ~10% area wash for a single series, a crosshair that snaps to
 *  the nearest date and lists every series, a legend for two or more series, end-dots with a surface ring. */
export function LineChart({
  label,
  dates,
  series,
  yMax,
  format = (v) => String(v),
  height = 220,
}: {
  label: string;
  dates: string[];
  series: Series[];
  yMax?: number;
  format?: (v: number) => string;
  height?: number;
}) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  const W = 720, H = height, m = { top: 12, right: 16, bottom: 26, left: 44 };
  const xs = useMemo(() => dates.map((d) => new Date(d)), [dates]);
  const max = yMax ?? Math.max(1, ...series.flatMap((s) => s.values.filter((v): v is number => v !== null))) * 1.1;
  const x = scaleTime().domain([xs[0] ?? new Date(), xs[xs.length - 1] ?? new Date()]).range([m.left, W - m.right]);
  const y = scaleLinear().domain([0, max]).nice(4).range([H - m.bottom, m.top]);
  const path = (vals: (number | null)[]) =>
    line<number | null>().defined((v) => v !== null).x((_, i) => x(xs[i]!)).y((v) => y(v ?? 0)).curve(curveMonotoneX)(vals) ?? "";
  const wash = (vals: (number | null)[]) =>
    area<number | null>().defined((v) => v !== null).x((_, i) => x(xs[i]!)).y0(y(0)).y1((v) => y(v ?? 0)).curve(curveMonotoneX)(vals) ?? "";
  const nearest = (clientX: number) => {
    const box = ref.current?.getBoundingClientRect();
    if (!box || !xs.length) return null;
    const px = ((clientX - box.left) / box.width) * W;
    let best = 0;
    xs.forEach((d, i) => { if (Math.abs(x(d) - px) < Math.abs(x(xs[best]!) - px)) best = i; });
    return best;
  };
  const show = (i: number, cx: number, cy: number) => {
    setHover(i);
    setTip({
      x: cx, y: cy, title: fmtMonth(xs[i]!),
      rows: series.map((s) => ({ key: s.label, color: s.color, value: s.values[i] === null ? "–" : format(s.values[i]!) })),
    });
  };
  const ticks = y.ticks(4);
  const xTicks = xs.filter((_, i) => i % Math.max(1, Math.ceil(xs.length / 6)) === 0 || i === xs.length - 1);
  const table = { columns: ["Month", ...series.map((s) => s.label)], rows: xs.map((d, i) => [fmtMonth(d), ...series.map((s) => (s.values[i] === null ? "–" : format(s.values[i]!)))]) };
  return (
    <ChartFrame label={label} table={table}>
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        role="img"
        aria-label={`${label}: ${series.map((s) => `${s.label} latest ${s.values.at(-1) === null || s.values.at(-1) === undefined ? "none" : format(s.values.at(-1)!)}`).join("; ")}`}
        tabIndex={0}
        onPointerMove={(e) => { const i = nearest(e.clientX); if (i !== null) show(i, e.clientX, e.clientY); }}
        onPointerLeave={() => { setHover(null); setTip(null); }}
        onBlur={() => { setHover(null); setTip(null); }}
        onKeyDown={(e) => {
          if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
          e.preventDefault();
          const i = Math.min(xs.length - 1, Math.max(0, (hover ?? xs.length - 1) + (e.key === "ArrowRight" ? 1 : -1)));
          const box = ref.current!.getBoundingClientRect();
          show(i, box.left + (x(xs[i]!) / W) * box.width, box.top + 20);
        }}
        className="block overflow-visible focus-visible:outline-2"
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={m.left} x2={W - m.right} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth={1} />
            <text x={m.left - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--muted)" className="tabular-nums">{format(t)}</text>
          </g>
        ))}
        <line x1={m.left} x2={W - m.right} y1={y(0)} y2={y(0)} stroke="var(--axis)" strokeWidth={1} />
        {xTicks.map((d) => (
          <text key={d.toISOString()} x={x(d)} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--muted)">{fmtMonth(d)}</text>
        ))}
        {series.length === 1 && <path d={wash(series[0]!.values)} fill={series[0]!.color} opacity={0.1} />}
        {series.map((s) => (
          <path key={s.key} d={path(s.values)} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        ))}
        {hover !== null && <line x1={x(xs[hover]!)} x2={x(xs[hover]!)} y1={m.top} y2={H - m.bottom} stroke="var(--axis)" strokeWidth={1} />}
        {series.map((s) => {
          const i = hover ?? s.values.length - 1;
          const v = s.values[i];
          if (v === null || v === undefined || !xs[i]) return null;
          return <circle key={s.key} cx={x(xs[i]!)} cy={y(v)} r={4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />;
        })}
      </svg>
      {series.length > 1 && <Legend items={series.map((s) => ({ label: s.label, color: s.color }))} />}
      <ChartTooltip tip={tip} />
    </ChartFrame>
  );
}

/** A 12-point trend for a stat tile: the de-emphasis hue, with the current period in the accent. */
export function Sparkline({ values, label, width = 96, height = 28 }: { values: number[]; label: string; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const lo = Math.min(...values), hi = Math.max(...values);
  const x = scaleLinear().domain([0, values.length - 1]).range([2, width - 4]);
  const y = scaleLinear().domain(lo === hi ? [lo - 1, hi + 1] : [lo, hi]).range([height - 4, 4]);
  const d = line<number>().x((_, i) => x(i)).y((v) => y(v)).curve(curveMonotoneX)(values) ?? "";
  const last = values.length - 1;
  return (
    <svg width={width} height={height} role="img" aria-label={label} className="block overflow-visible">
      <path d={d} fill="none" stroke="var(--muted)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={x(last)} cy={y(values[last]!)} r={3} fill="var(--accent)" stroke="var(--surface)" strokeWidth={1.5} />
    </svg>
  );
}
