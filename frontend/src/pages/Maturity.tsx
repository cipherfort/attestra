// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { Gauge } from "lucide-react";
import { useSearchParams } from "react-router";
import { ApiError, api, type OrgUnitRow } from "../api";
import { Sparkline, LineChart } from "../components/charts/LineChart";
import { RangeBars } from "../components/charts/RangeBars";
import { Card } from "../components/ui/Card";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, Skeleton, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";

const month = (p: string) => new Date(`${p}-01T00:00:00Z`).toLocaleDateString(undefined, { month: "long", year: "numeric", timeZone: "UTC" });
const last = (xs: (number | null)[]) => [...xs].reverse().find((v) => v !== null) ?? null;
const first = (xs: (number | null)[]) => xs.find((v) => v !== null) ?? null;

/** Units listed parent first, indented by depth, so the picker reads like the org chart. */
function ordered(units: OrgUnitRow[]): { unit: OrgUnitRow; depth: number }[] {
  const ids = new Set(units.map((u) => u.id));
  const kids = (id: string | null) => units.filter((u) => (id === null ? !u.parent_id || !ids.has(u.parent_id) : u.parent_id === id));
  const out: { unit: OrgUnitRow; depth: number }[] = [];
  const walk = (id: string | null, depth: number) => {
    for (const u of kids(id).sort((a, b) => a.name.localeCompare(b.name))) { out.push({ unit: u, depth }); walk(u.id, depth + 1); }
  };
  walk(null, 0);
  return out;
}

const select = "h-8 rounded-md border border-line bg-surface-2 px-2 text-[13px] text-ink";

export function Maturity() {
  const [params, setParams] = useSearchParams();
  const me = useMe();
  const allowed = (me.data?.permissions ?? []).includes("maturity.rollup.read");
  const units = useQuery({ queryKey: ["units"], queryFn: api.visibleUnits, enabled: allowed });
  const snaps = useQuery({ queryKey: ["snapshots"], queryFn: api.snapshots, enabled: allowed });
  const tree = ordered(units.data ?? []);
  const unit = tree.find((t) => t.unit.id === params.get("unit"))?.unit ?? tree[0]?.unit;
  const periods = [...(snaps.data ?? [])].reverse();
  const period = periods.find((s) => s.period === params.get("month"))?.period;
  const trend = useQuery({ queryKey: ["trend", unit?.id], queryFn: () => api.unitTrend(unit!.id), enabled: !!unit });
  const rollup = useQuery({ queryKey: ["unit-maturity", unit?.id, period], queryFn: () => api.unitMaturity(unit!.id, period), enabled: !!unit });
  const set = (k: string, v: string | undefined) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };

  if (me.isPending) return <Skeleton className="h-96 w-full" />;
  if (!allowed) {
    return (
      <>
        <PageHeader title="Maturity" />
        <EmptyState icon={Gauge} title="Roll-ups are for leads and governance roles">
          Your role sees maturity per application: open an application and choose its Maturity tab.
        </EmptyState>
      </>
    );
  }
  if (units.isPending) return <Skeleton className="h-96 w-full" />;
  if (!unit) return <EmptyState icon={Gauge} title="No organisation units in your scope">Maturity is reported per organisation unit.</EmptyState>;

  const t = trend.data;
  const r = rollup.data;
  const overall = t?.metrics.samm_overall ?? [];
  const shown = r?.snapshot ?? t?.provisional ?? "";
  const snap = snaps.data?.find((s) => s.period === shown);
  const tiers = Object.entries(r?.pct_apps_meeting_target_by_tier ?? {});

  return (
    <>
      <PageHeader
        title="Maturity"
        description="OWASP SAMM scores (0–3) computed from verified evidence and recorded assessments. Shown as a spread across applications, never as a league table."
        actions={
          <>
            <label className="sr-only" htmlFor="m-unit">Organisation unit</label>
            <select id="m-unit" className={select} value={unit.id} onChange={(e) => set("unit", e.target.value)}>
              {tree.map(({ unit: u, depth }) => <option key={u.id} value={u.id}>{" ".repeat(depth)}{u.name}</option>)}
            </select>
            <label className="sr-only" htmlFor="m-month">Snapshot month</label>
            <select id="m-month" className={select} value={period ?? ""} onChange={(e) => set("month", e.target.value || undefined)}>
              <option value="">Latest</option>
              {periods.map((s) => <option key={s.period} value={s.period}>{month(s.period)}{s.published ? "" : " (in progress)"}</option>)}
            </select>
          </>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-5">
        <Kpi
          label="SAMM overall"
          value={last(overall)?.toFixed(2) ?? "–"}
          trend={overall.filter((v): v is number => v !== null)}
          sub={first(overall) !== null && last(overall) !== null ? `${(last(overall)! - first(overall)!) >= 0 ? "+" : ""}${(last(overall)! - first(overall)!).toFixed(2)} over ${t?.periods.length ?? 0} months` : "Average over the applications in scope"}
        />
        {tiers.map(([tier, v]) => (
          <Kpi key={tier} label={`Tier ${tier} meeting target`} value={`${Math.round(v)}%`} sub="Applications at or above every practice target" />
        ))}
      </div>

      <div className="mb-6 grid items-start gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3" title="SAMM overall by month" description={t?.provisional ? `${month(t.provisional)} is in progress and updates as evidence arrives; earlier months are published and fixed.` : undefined}>
          {t ? (
            <LineChart label="SAMM overall by month" dates={t.periods.map((p) => `${p}-01T00:00:00Z`)} yMax={3} format={(v) => v.toFixed(2)} series={[{ key: "samm", label: "SAMM overall", color: "var(--series-1)", values: overall }]} />
          ) : <SkeletonRows rows={6} />}
        </Card>
        <Card className="xl:col-span-2" title="By business function" description="Current score and the last 12 months" bodyClassName="px-5 py-2">
          {t ? (
            <ul className="plain m-0 p-0">
              {t.samm_functions.map((f) => {
                const now = last(f.values), then = first(f.values);
                const delta = now !== null && then !== null ? now - then : null;
                return (
                  <li key={f.item} className="flex items-center gap-3 border-b border-line py-2.5 last:border-b-0">
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] font-medium text-ink">{f.name ?? f.item}</div>
                      <div className="text-xs text-muted">{now === null ? "Not scored yet" : delta === null ? "No history" : `${delta >= 0 ? "+" : ""}${delta.toFixed(2)} in 12 months`}</div>
                    </div>
                    <Sparkline values={f.values.filter((v): v is number => v !== null)} label={`${f.name ?? f.item} over 12 months`} />
                    <div className="w-12 text-right text-sm font-semibold tabular-nums text-ink">{now?.toFixed(2) ?? "–"}</div>
                  </li>
                );
              })}
            </ul>
          ) : <SkeletonRows rows={5} />}
        </Card>
      </div>

      <Card
        title="How practices spread across applications"
        description={r ? `${month(r.snapshot ?? shown)}${snap && !snap.published ? " (in progress)" : ""} · ${unit.name} · methodology ${snap?.methodology_version ?? ""}` : undefined}
      >
        {rollup.isPending ? <SkeletonRows rows={10} /> : rollup.isError ? (
          <EmptyState title="No snapshot for this month">
            {rollup.error instanceof ApiError && rollup.error.status === 404 ? "There is no maturity snapshot for that month yet." : String(rollup.error)}
          </EmptyState>
        ) : r && r.distribution.length ? (
          <>
            {snap?.methodology_changed && (
              <p className="m-0 mb-3 rounded-md border border-warning/40 bg-surface-2 px-3 py-2 text-xs text-ink-2">
                The scoring method changed this month, so scores aren't directly comparable with earlier months.
              </p>
            )}
            <RangeBars
              label="SAMM practice scores across applications"
              items={r.distribution.map((d) => ({
                key: d.practice ?? "", label: d.name ?? d.practice ?? "", min: d.min ?? 0, p25: d.p25 ?? 0, median: d.median ?? 0, p75: d.p75 ?? 0, max: d.max ?? 0, count: d.count ?? 0,
              }))}
            />
          </>
        ) : (
          <EmptyState icon={Gauge} title="No applications scored yet">Scores appear once applications in this unit are classified and evidence arrives.</EmptyState>
        )}
      </Card>
    </>
  );
}
