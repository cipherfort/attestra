// SPDX-License-Identifier: Apache-2.0
import { useQueries, useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { ListChecks } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { api, type CatalogueControl, type ControlItem } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { STATES, StateBadge } from "../components/domain/badges";
import { Card } from "../components/ui/Card";
import { Dialog } from "../components/ui/Dialog";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";
import { DOMAINS } from "./Overview";

const MODE: Record<string, string> = { automated: "Automated", hybrid: "Automated + review", manual: "Assessment" };
const OBJECTIVE: Record<string, string> = { configuration: "Configuration", activity: "Activity", process: "Process", outcome: "Outcome" };

/** "Tiers 1–3", "Tier 1", "Tiers 1, 3" or "–": where a control is mandatory. */
export function tiersWhere(c: CatalogueControl, level = "mandatory"): string {
  const ts = Object.entries(c.applicability).filter(([, v]) => v === level).map(([t]) => Number(t)).sort();
  if (!ts.length) return "–";
  if (ts.length === 1) return `Tier ${ts[0]}`;
  const run = ts.every((t, i) => i === 0 || t === (ts[i - 1] ?? 0) + 1);
  return `Tiers ${run ? `${ts[0]}–${ts[ts.length - 1]}` : ts.join(", ")}`;
}

interface Mappings { samm?: { stream: string; level: number }[]; asvs?: string[]; ssdf?: string[]; csf?: string[]; other?: unknown[] }

function chips(m: Mappings): string[] {
  return [
    ...(m.samm ?? []).map((s) => `SAMM ${s.stream} L${s.level}`),
    ...(m.ssdf ?? []).map((s) => `SSDF ${s}`),
    ...((m.asvs ?? []).length ? [`ASVS ${(m.asvs ?? []).length > 3 ? `${(m.asvs ?? []).length} chapters` : (m.asvs ?? []).join(", ")}`] : []),
  ];
}

function Chip({ children }: { children: string }) {
  return <span className="inline-flex rounded border border-line bg-surface-2 px-1.5 py-px font-mono text-[11px] text-ink-2">{children}</span>;
}

/** Per control: in how many applications that must have it is it currently proven? (Worst state over its scopes.) */
function usePortfolio(enabled: boolean) {
  const apps = useQuery({ queryKey: ["applications"], queryFn: api.applications, enabled });
  const classified = (apps.data ?? []).filter((a) => a.tier !== null);
  const controls = useQueries({
    queries: classified.map((a) => ({ queryKey: ["controls", a.app_key], queryFn: () => api.controls(a.app_key), staleTime: 60_000, enabled })),
  });
  const byControl = new Map<string, { app: string; name: string; items: ControlItem[] }[]>();
  classified.forEach((a, i) => {
    for (const c of controls[i]?.data?.items ?? []) {
      if (c.requirement === "n/a") continue;
      const list = byControl.get(c.control_key) ?? [];
      let entry = list.find((e) => e.app === a.app_key);
      if (!entry) { entry = { app: a.app_key, name: a.name, items: [] }; list.push(entry); }
      entry.items.push(c);
      byControl.set(c.control_key, list);
    }
  });
  const ready = enabled && !apps.isPending && controls.every((q) => !q.isPending);
  return { byControl, ready };
}

export function Controls({ id }: { id?: string }) {
  const navigate = useNavigate();
  const me = useMe();
  const canApps = (me.data?.permissions ?? []).includes("application.read");
  const cat = useQuery({ queryKey: ["catalogue"], queryFn: api.catalogue, staleTime: 5 * 60_000 });
  const { byControl, ready } = usePortfolio(canApps);
  const proven = (key: string) => {
    const list = (byControl.get(key) ?? []).filter((e) => e.items.some((c) => c.requirement === "mandatory"));
    return { yes: list.filter((e) => e.items.every((c) => c.state === "satisfied")).length, of: list.length };
  };
  const cols: ColumnDef<CatalogueControl, unknown>[] = [
    { id: "control", header: "Control", accessorFn: (c) => `${c.control_key} ${c.title}`, cell: ({ row: { original: c } }) => (
      <div><Link to={`/controls/${c.control_key}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{c.title}</Link>
        <div className="font-mono text-[11px] text-muted">{c.control_key}</div></div>
    ) },
    { id: "domain", header: "Domain", accessorKey: "domain", filterFn: inSet<CatalogueControl>(), cell: ({ getValue }) => <span className="text-ink-2">{DOMAINS[String(getValue())] ?? String(getValue())}</span> },
    { id: "mode", header: "Assessed by", accessorKey: "assessment_mode", filterFn: inSet<CatalogueControl>(), cell: ({ getValue }) => <span className="text-ink-2">{MODE[String(getValue())] ?? String(getValue())}</span> },
    { id: "mandatory", header: "Mandatory for", accessorFn: (c) => tiersWhere(c), filterFn: inSet<CatalogueControl>(), cell: ({ getValue }) => <span className="whitespace-nowrap text-ink-2">{String(getValue())}</span> },
    { id: "maps", header: "Maps to", accessorFn: (c) => chips(c.mappings as Mappings).join(" "), enableSorting: false, cell: ({ row: { original: c } }) => (
      <div className="flex max-w-80 flex-wrap gap-1">{chips(c.mappings as Mappings).slice(0, 3).map((x) => <Chip key={x}>{x}</Chip>)}</div>
    ) },
    ...(canApps ? [{
      id: "proven", header: "Proven in", accessorFn: (c: CatalogueControl) => { const p = proven(c.control_key); return p.of ? p.yes / p.of : -1; },
      cell: ({ row: { original: c } }: { row: { original: CatalogueControl } }) => {
        if (!ready) return <span className="text-muted">…</span>;
        const p = proven(c.control_key);
        return p.of ? <span className="whitespace-nowrap tabular-nums text-ink-2">{p.yes} of {p.of} app{p.of === 1 ? "" : "s"}</span> : <span className="text-muted">Not required</span>;
      },
    } as ColumnDef<CatalogueControl, unknown>] : []),
  ];
  const open = cat.data?.items.find((c) => c.control_key === id);
  const where = open ? byControl.get(open.control_key) ?? [] : [];
  return (
    <>
      <PageHeader
        title="Controls"
        description={<>The control catalogue every application is evaluated against{cat.data ? <>, version <span className="font-mono">{cat.data.catalogue_version}</span></> : null}. Each control says what counts as proof; changes are made by pull request, never through the platform.</>}
      />
      <Card bodyClassName="">
        {cat.isPending ? <SkeletonRows rows={10} /> : (
          <DataTable
            data={cat.data?.items ?? []}
            columns={cols}
            label="controls"
            searchPlaceholder="Search controls…"
            facets={[
              { column: "domain", title: "Domain", label: (v) => DOMAINS[v] ?? v },
              { column: "mode", title: "Assessed by", label: (v) => MODE[v] ?? v },
              { column: "mandatory", title: "Mandatory for" },
            ]}
            initialSort={[]}
            pageSize={50}
            rowHref={(c) => `/controls/${c.control_key}`}
            csv={{ filename: "controls.csv", row: (c) => ({ control: c.control_key, title: c.title, domain: c.domain, assessed_by: c.assessment_mode, mandatory_for: tiersWhere(c), mappings: chips(c.mappings as Mappings).join("; ") }) }}
            empty={<EmptyState icon={ListChecks} title="No controls">The catalogue is empty.</EmptyState>}
          />
        )}
      </Card>
      <Dialog open={!!open} onClose={() => void navigate("/controls", { replace: true })} title={open ? `${open.control_key} · ${open.title}` : ""} variant="drawer">
        {open && (
          <div className="flex flex-col gap-5 text-[13px]">
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
              <span>{DOMAINS[open.domain] ?? open.domain}</span>
              <span>{OBJECTIVE[open.objective_type] ?? open.objective_type}</span>
              <span>{MODE[open.assessment_mode] ?? open.assessment_mode}</span>
            </div>
            <section>
              <h3 className="m-0 mb-1 text-xs font-semibold uppercase tracking-wide text-muted">What it requires</h3>
              <p className="m-0 whitespace-pre-line text-ink-2">{open.description}</p>
            </section>
            <section>
              <h3 className="m-0 mb-1 text-xs font-semibold uppercase tracking-wide text-muted">What counts as proof</h3>
              <p className="m-0 whitespace-pre-line text-ink-2">{open.proof}</p>
            </section>
            <section>
              <h3 className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-muted">By tier</h3>
              <dl className="m-0 grid grid-cols-4 gap-2">
                {Object.entries(open.applicability).sort().map(([t, v]) => (
                  <div key={t} className="rounded-md border border-line bg-surface-2 px-2.5 py-1.5">
                    <dt className="text-[11px] text-muted">Tier {t}</dt>
                    <dd className="m-0 text-ink">{v === "n/a" ? "Not applicable" : v === "mandatory" ? "Mandatory" : "Recommended"}</dd>
                  </div>
                ))}
              </dl>
            </section>
            <section>
              <h3 className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Maps to</h3>
              <Mapped m={open.mappings as Mappings} />
            </section>
            {canApps && (
              <section>
                <h3 className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Across your applications</h3>
                {!ready ? <SkeletonRows rows={3} /> : where.length ? (
                  <ul className="plain m-0 p-0">
                    {where.map((e) => {
                      const worst = e.items.reduce((a, b) => (STATES[b.state].order < STATES[a.state].order ? b : a));
                      return (
                        <li key={e.app} className="flex items-center gap-3 border-b border-line py-2 last:border-b-0">
                          <Link to={`/apps/${e.app}/controls`} className="min-w-0 flex-1 truncate text-ink hover:text-accent-ink">{e.name}</Link>
                          <span className="text-xs text-muted">{e.items[0]?.requirement === "mandatory" ? "Mandatory" : "Recommended"}</span>
                          <StateBadge state={worst.state} />
                        </li>
                      );
                    })}
                  </ul>
                ) : <p className="m-0 text-xs text-muted">No application you can see is evaluated against this control.</p>}
              </section>
            )}
          </div>
        )}
      </Dialog>
    </>
  );
}

function Mapped({ m }: { m: Mappings }) {
  const rows: [string, string[]][] = [
    ["OWASP SAMM", (m.samm ?? []).map((s) => `${s.stream} level ${s.level}`)],
    ["OWASP ASVS 5.0", m.asvs ?? []],
    ["NIST SSDF", m.ssdf ?? []],
    ["NIST CSF 2.0", m.csf ?? []],
  ];
  const shown = rows.filter(([, v]) => v.length);
  if (!shown.length) return <p className="m-0 text-xs text-muted">No framework mappings.</p>;
  return (
    <dl className="m-0 space-y-2">
      {shown.map(([k, v]) => (
        <div key={k} className="flex gap-3">
          <dt className="w-28 shrink-0 text-xs text-muted">{k}</dt>
          <dd className="m-0 flex flex-wrap gap-1">{v.map((x) => <Chip key={x}>{x}</Chip>)}</dd>
        </div>
      ))}
    </dl>
  );
}
