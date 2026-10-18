// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Boxes, Plus } from "lucide-react";
import { Link } from "react-router";
import { api, type AppSummary, type Priority } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { PriorityChip, TierBadge } from "../components/domain/badges";
import { CoverageBar, CoverageLegend, coverageRatio } from "../components/domain/Coverage";
import { ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";

const PRIORITIES: Priority[] = ["P1", "P2", "P3", "P4"];

const columns: ColumnDef<AppSummary, unknown>[] = [
  {
    id: "name",
    header: "Application",
    accessorFn: (a) => `${a.name} ${a.app_key}`,
    sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
    cell: ({ row: { original: a } }) => (
      <div>
        <Link to={`/apps/${a.app_key}`} className="font-medium text-ink hover:text-accent-ink">{a.name}</Link>
        <div className="mt-0.5 font-mono text-[11px] text-muted">{a.app_key} · {a.lifecycle}</div>
      </div>
    ),
  },
  {
    id: "tier",
    header: "Tier",
    accessorFn: (a) => (a.tier === null ? "" : String(a.tier)),
    filterFn: inSet<AppSummary>(),
    sortingFn: (a, b) => (a.original.tier ?? 9) - (b.original.tier ?? 9),
    cell: ({ row }) => <TierBadge tier={row.original.tier} />,
  },
  { id: "unit", header: "Owned by", accessorKey: "org_unit", filterFn: inSet<AppSummary>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
  {
    id: "coverage",
    header: "Mandatory controls proven",
    accessorFn: (a) => coverageRatio(a.mandatory_controls) ?? -1,
    cell: ({ row }) => <CoverageBar counts={row.original.mandatory_controls} />,
  },
  {
    id: "findings",
    header: "Open findings",
    accessorFn: (a) => PRIORITIES.reduce((s, p, i) => s + (a.open_findings?.[p] ?? 0) * 10 ** (3 - i), 0),
    cell: ({ row: { original: a } }) => {
      const present = PRIORITIES.filter((p) => a.open_findings?.[p]);
      return present.length ? (
        <div className="flex flex-wrap gap-1.5">{present.map((p) => <PriorityChip key={p} p={p} count={a.open_findings?.[p]} />)}</div>
      ) : (
        <span className="text-xs text-muted">None</span>
      );
    },
  },
  {
    id: "sla",
    header: "Past SLA",
    accessorKey: "sla_breaches",
    meta: { align: "right" },
    cell: ({ getValue }) => {
      const n = Number(getValue());
      return <span className={n ? "font-semibold text-critical-ink" : "text-muted"}>{n}</span>;
    },
  },
  { id: "lifecycle", accessorKey: "lifecycle", filterFn: inSet<AppSummary>(), header: "Lifecycle" },
];

export function Portfolio() {
  const apps = useQuery({ queryKey: ["applications"], queryFn: api.applications });
  const me = useMe();
  const items = apps.data ?? [];
  const totals = items.reduce(
    (t, a) => {
      const c = a.mandatory_controls ?? {};
      const total = Object.values(c).reduce((s, n) => s + (n ?? 0), 0);
      return { sat: t.sat + (c.satisfied ?? 0), total: t.total + total, p1: t.p1 + (a.open_findings?.P1 ?? 0), sla: t.sla + a.sla_breaches };
    },
    { sat: 0, total: 0, p1: 0, sla: 0 },
  );
  const canRegister = me.data?.permissions.includes("application.register");
  return (
    <>
      <PageHeader
        title="Applications"
        description="Every application you can see: its risk tier, how many of its mandatory controls current evidence proves, and its open findings by contextual priority."
        actions={canRegister && <ButtonLink to="/register" variant="primary"><Plus className="size-4" aria-hidden="true" /> Register an application</ButtonLink>}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi label="Applications" value={apps.data ? items.length : "–"} sub={`${items.filter((a) => a.tier === 1 || a.tier === 2).length} at Tier 1 or 2`} />
        <Kpi
          label="Mandatory controls proven"
          value={totals.total ? `${Math.round((totals.sat / totals.total) * 100)}%` : "–"}
          sub={`${totals.sat} of ${totals.total} across the portfolio`}
        />
        <Kpi label="Open P1 findings" value={totals.p1} tone={totals.p1 ? "critical" : undefined} sub="Fix within 7 days" />
        <Kpi label="Findings past SLA" value={totals.sla} tone={totals.sla ? "critical" : "good"} sub={totals.sla ? "Needs escalation" : "All within their deadline"} />
      </div>
      <Card bodyClassName="">
        {apps.isPending ? (
          <SkeletonRows rows={6} />
        ) : apps.isError ? (
          <EmptyState title="Couldn't load the applications">{String(apps.error)}</EmptyState>
        ) : items.length === 0 ? (
          <EmptyState icon={Boxes} title="No applications in your scope yet" action={canRegister && <ButtonLink to="/register" variant="primary">Register the first application</ButtonLink>}>
            Applications appear here once they are registered and you belong to their owning unit.
          </EmptyState>
        ) : (
          <>
            <DataTable
              data={items}
              columns={columns}
              hidden={["lifecycle"]}
              label="applications"
              searchPlaceholder="Search name or key…"
              facets={[
                { column: "tier", title: "Tier", label: (v) => (v ? `Tier ${v}` : "Unclassified") },
                { column: "unit", title: "Unit" },
                { column: "lifecycle", title: "Lifecycle" },
              ]}
              initialSort={[{ id: "tier", desc: false }]}
              rowHref={(a) => `/apps/${a.app_key}`}
              csv={{
                filename: "applications.csv",
                row: (a) => ({
                  app_key: a.app_key, name: a.name, tier: a.tier ?? "", unit: a.org_unit, lifecycle: a.lifecycle,
                  controls_satisfied: a.mandatory_controls?.satisfied ?? 0,
                  controls_mandatory: Object.values(a.mandatory_controls ?? {}).reduce((s, n) => s + (n ?? 0), 0),
                  p1: a.open_findings?.P1 ?? 0, p2: a.open_findings?.P2 ?? 0, p3: a.open_findings?.P3 ?? 0, p4: a.open_findings?.P4 ?? 0,
                  past_sla: a.sla_breaches,
                }),
              }}
            />
            <div className="border-t border-line px-4 py-3"><CoverageLegend /></div>
          </>
        )}
      </Card>
    </>
  );
}
