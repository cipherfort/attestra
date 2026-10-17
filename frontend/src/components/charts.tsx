// SPDX-License-Identifier: Apache-2.0
import { useState, type MouseEvent } from "react";
import type { ControlStateValue, MaturityPractice } from "../api";
import { STATE } from "./ui";

// Charts follow the reference data-viz method: thin marks, 2px surface gaps between segments, recessive grid,
// status colours only for state (each with a text label/legend), a hover tooltip on every mark, and a table view.

interface Tip { x: number; y: number; lines: string[] }

function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div className="tooltip" style={{ left: tip.x + 14, top: tip.y + 14 }} role="status">
      {tip.lines.map((l, i) => <div key={i} className={i === 0 ? "" : "muted"}>{i === 0 ? <strong>{l}</strong> : l}</div>)}
    </div>
  );
}

const ORDER: ControlStateValue[] = ["satisfied", "partial", "excepted", "stale", "not_satisfied", "no_evidence", "error"];

/** Mandatory controls by state for one application: a single stacked bar with a legend. */
export function CoverageBar({ counts, width = 260 }: { counts: Partial<Record<ControlStateValue, number>>; width?: number }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const total = ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0);
  if (!total) return <span className="muted small">not evaluated yet</span>;
  const h = 12, gap = 2;
  let x = 0;
  const segs = ORDER.filter((k) => counts[k]).map((k) => {
    const w = ((counts[k] ?? 0) / total) * width;
    const seg = { k, x, w: Math.max(w - gap, 1) };
    x += w;
    return seg;
  });
  const sat = counts.satisfied ?? 0;
  return (
    <span className="row">
      <svg className="viz" width={width} height={h} role="img"
        aria-label={`${sat} of ${total} mandatory controls satisfied`} onMouseLeave={() => setTip(null)}>
        {segs.map((s, i) => (
          <rect key={s.k} x={s.x} y={0} width={s.w} height={h} rx={i === 0 || i === segs.length - 1 ? 3 : 0}
            style={{ fill: STATE[s.k].color }}
            onMouseMove={(e: MouseEvent) => setTip({ x: e.clientX, y: e.clientY,
              lines: [STATE[s.k].label, `${counts[s.k]} of ${total} mandatory controls`] })} />
        ))}
      </svg>
      <span className="small"><strong>{sat}</strong>/{total}</span>
      <Tooltip tip={tip} />
    </span>
  );
}

export function CoverageLegend() {
  return (
    <div className="legend" aria-label="Control state legend">
      {ORDER.map((k) => (
        <span key={k}><span className="dot" style={{ background: STATE[k].color }} />{STATE[k].icon} {STATE[k].label}</span>
      ))}
    </div>
  );
}

/** SAMM practice scores (0–3) against the tier target: horizontal bars, one series, target as an ink tick. */
export function MaturityChart({ practices }: { practices: MaturityPractice[] }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const W = 700, labelW = 190, rowH = 26, top = 8, valueW = 96, plotW = W - labelW - valueW - 16;
  const H = top + practices.length * rowH + 28;
  const sx = (v: number) => labelW + (v / 3) * plotW;
  return (
    <div>
      <svg className="viz chart" viewBox={`0 0 ${W} ${H}`} width="100%" role="img"
        aria-label="SAMM maturity by practice compared with tier target" onMouseLeave={() => setTip(null)}>
        {[0, 1, 2, 3].map((t) => (
          <g key={t}>
            <line className="grid" x1={sx(t)} x2={sx(t)} y1={top} y2={H - 22} />
            <text x={sx(t)} y={H - 6} textAnchor="middle">{t}</text>
          </g>
        ))}
        {practices.map((p, i) => {
          const y = top + i * rowH;
          const below = p.target !== null && p.score < p.target;
          return (
            <g key={p.item}
              onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, lines: [
                `${p.name}: ${p.score.toFixed(2)}${p.target !== null ? ` (target ${p.target})` : ""}`,
                `automated ${p.provenance.automated}% · independent ${p.provenance.manual_independent}%`,
                `self-assessed ${p.provenance.manual_self}% · unassessed ${p.provenance.unassessed}%`] })}>
              <rect x={0} y={y} width={W} height={rowH} fill="transparent" />
              <text className="label" x={labelW - 8} y={y + rowH / 2 + 4} textAnchor="end">{p.name}</text>
              <rect x={labelW} y={y + 7} width={Math.max(sx(p.score) - labelW, 2)} height={rowH - 14} rx={4}
                style={{ fill: "var(--series-1)" }} />
              {p.target !== null && (
                <line className="target" x1={sx(p.target)} x2={sx(p.target)} y1={y + 3} y2={y + rowH - 3} />
              )}
              <text className="label" x={W - 4} y={y + rowH / 2 + 4} textAnchor="end"
                style={{ fill: below ? "var(--critical-ink)" : "var(--ink-2)" }}>
                {p.score.toFixed(2)}{p.target !== null ? ` / ${p.target}` : ""}
              </text>
            </g>
          );
        })}
        <line className="axis" x1={labelW} x2={labelW} y1={top} y2={H - 22} />
      </svg>
      <div className="legend">
        <span><span className="dot" style={{ background: "var(--series-1)" }} />Score (0–3, from evidence)</span>
        <span>Right column: score / target (red when below target)</span>
        <span><svg className="viz" width="10" height="14" aria-hidden="true"><line x1="5" x2="5" y1="1" y2="13" className="target" /></svg>
          Tier target</span>
      </div>
      <Tooltip tip={tip} />
    </div>
  );
}
