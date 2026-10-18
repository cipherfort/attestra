// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { Download, Printer } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { api, type PostureTrend } from "../api";
import { LineChart } from "../components/charts/LineChart";
import { RangeBars } from "../components/charts/RangeBars";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { LoadError, Notice, errorText } from "../components/ui/Form";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";
import { topUnit } from "./Overview";

const month = (p: string) => `${p}-01T00:00:00Z`;
const last = (xs: (number | null)[] | undefined) => [...(xs ?? [])].reverse().find((v) => v !== null) ?? null;
const spark = (xs: (number | null)[] | undefined) => (xs ?? []).filter((v): v is number => v !== null);

function coverage(t: PostureTrend): (number | null)[] {
  const sat = t.metrics.mandatory_satisfied ?? [], tot = t.metrics.mandatory_total ?? [];
  return tot.map((n, i) => (n ? ((sat[i] ?? 0) / n) * 100 : null));
}

/** Organisation-wide aggregates for leadership: no finding-level detail is needed or shown. */
export function Leadership() {
  const me = useMe();
  const perms = new Set(me.data?.permissions ?? []);
  const s = useQuery({ queryKey: ["scorecard"], queryFn: api.scorecard });
  const canTrend = perms.has("maturity.rollup.read");
  const units = useQuery({ queryKey: ["units"], queryFn: api.visibleUnits, enabled: canTrend });
  const unit = units.data ? topUnit(units.data) : undefined;
  const trend = useQuery({ queryKey: ["trend", unit?.id], queryFn: () => api.unitTrend(unit!.id), enabled: !!unit });
  const rollup = useQuery({ queryKey: ["unit-maturity", unit?.id, undefined], queryFn: () => api.unitMaturity(unit!.id), enabled: !!unit });
  const t = trend.data;
  const cov = t ? coverage(t) : [];
  const dates = (t?.periods ?? []).map(month);
  const x = s.data;

  return (
    <>
      <PageHeader
        title="Leadership report"
        description={`Organisation-wide aggregates${unit ? ` for ${unit.name}` : ""}, from verified evidence. Monthly figures are published at month end and never change afterwards; the current month is in progress.`}
        actions={<ExportButtons />}
      />
      {s.isPending ? <Skeleton className="mb-6 h-28 w-full" /> : s.isError ? <div className="mb-6"><LoadError error={s.error} /></div> : x && (
        <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
          <Kpi label="Mandatory controls proven" value={x.mandatory_control_coverage_pct === null ? "–" : `${Math.round(x.mandatory_control_coverage_pct)}%`} trend={spark(cov)} sub={`${x.satisfied} of ${x.mandatory_states} across ${x.applications} applications`} />
          <Kpi label="Known-exploited vulnerabilities on internet-facing apps" value={x.kev_internet_exposed_open} tone={x.kev_internet_exposed_open ? "critical" : "good"} sub="Risk indicator: escalate if above 0 for 7 days" />
          <Kpi label="P1 findings open" value={x.p1_open} tone={x.p1_open ? "critical" : undefined} trend={spark(t?.metrics.findings_open_p1)} sub={`${x.p1_overdue} past their deadline`} />
          <Kpi label="Evidence submissions rejected" value={x.evidence_rejections} trend={spark(t?.metrics.evidence_rejected)} sub="Forged, unapproved or tampered" />
        </div>
      )}

      {canTrend && (
        <div className="mb-6 grid gap-4 xl:grid-cols-2">
          <Card title="Mandatory controls proven" description="Share proven by current, verified evidence, by month">
            {t ? <LineChart label="Mandatory controls proven by month" dates={dates} yMax={100} format={(v) => `${Math.round(v)}%`} series={[{ key: "cov", label: "Controls proven", color: "var(--series-1)", values: cov }]} /> : <SkeletonRows rows={6} />}
          </Card>
          <Card title="Findings past their deadline" description="Open findings beyond their remediation deadline at each month end">
            {t ? <LineChart label="Findings past their deadline by month" dates={dates} integer format={(v) => String(Math.round(v))} series={[{ key: "late", label: "Past deadline", color: "var(--series-1)", values: t.metrics.findings_past_sla ?? [] }]} /> : <SkeletonRows rows={6} />}
          </Card>
          <Card title="SAMM maturity" description={`Overall score, 0–3; now ${last(t?.metrics.samm_overall)?.toFixed(2) ?? "–"}`}>
            {t ? <LineChart label="SAMM overall by month" dates={dates} yMax={3} format={(v) => v.toFixed(2)} series={[{ key: "samm", label: "SAMM overall", color: "var(--series-1)", values: t.metrics.samm_overall ?? [] }]} /> : <SkeletonRows rows={6} />}
          </Card>
          <Card title="Applications meeting their maturity target" description="Share of applications at or above every practice target for their tier" bodyClassName="px-5 py-2">
            {rollup.data ? (
              <ul className="plain m-0 p-0">
                {Object.entries(rollup.data.pct_apps_meeting_target_by_tier ?? {}).map(([tier, v]) => (
                  <li key={tier} className="flex items-center gap-4 border-b border-line py-3 last:border-b-0">
                    <span className="w-14 text-[13px] font-medium text-ink">Tier {tier}</span>
                    <span className="h-2 flex-1 overflow-hidden rounded-full bg-surface-3" aria-hidden="true">
                      <span className="block h-full rounded-full bg-series-1" style={{ width: `${Math.max(v, v ? 2 : 0)}%` }} />
                    </span>
                    <span className="w-12 text-right text-[13px] font-semibold tabular-nums text-ink">{Math.round(v)}%</span>
                  </li>
                ))}
              </ul>
            ) : <SkeletonRows rows={4} />}
          </Card>
        </div>
      )}

      {canTrend && rollup.data && rollup.data.distribution.length > 0 && (
        <Card title="How SAMM practices spread across applications" description={<>The middle half and median for each practice. <Link to="/maturity">Explore by unit and month</Link></>}>
          <RangeBars
            label="SAMM practice scores across applications"
            items={rollup.data.distribution.map((d) => ({ key: d.practice ?? "", label: d.name ?? d.practice ?? "", min: d.min ?? 0, p25: d.p25 ?? 0, median: d.median ?? 0, p75: d.p75 ?? 0, max: d.max ?? 0, count: d.count ?? 0 }))}
          />
        </Card>
      )}
    </>
  );
}

/** CSV exports, scoped to what the caller may see and audited (permission report.export). */
function ExportButtons() {
  const me = useMe();
  const [msg, setMsg] = useState<string | null>(null);
  const can = me.data?.permissions.includes("report.export");
  const get = (r: "findings" | "controls") => api.download(r).catch((e: unknown) => setMsg(errorText(e)));
  return (
    <div className="flex flex-wrap items-center gap-2 print:hidden">
      {can && <Button onClick={() => void get("findings")}><Download className="size-4" aria-hidden="true" />Open findings (CSV)</Button>}
      {can && <Button onClick={() => void get("controls")}><Download className="size-4" aria-hidden="true" />Control states (CSV)</Button>}
      <Button onClick={() => window.print()}><Printer className="size-4" aria-hidden="true" />Print or save as PDF</Button>
      {msg && <Notice tone="error">{msg}</Notice>}
    </div>
  );
}
