// SPDX-License-Identifier: Apache-2.0
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, ClipboardCheck, FileCheck2, ShieldOff } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ApiError, api, type Classification, type ControlItem, type ControlStateValue, type EvidenceListItem, type Finding } from "../api";
import { BulletBars } from "../components/charts/BulletBars";
import { LineChart } from "../components/charts/LineChart";
import { DataTable, inSet } from "../components/data/DataTable";
import { ConfidenceBadge, PriorityChip, STATES, StateBadge, TierBadge } from "../components/domain/badges";
import { CoverageBar, CoverageLegend } from "../components/domain/Coverage";
import { evidenceLabel } from "../components/domain/evidence";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Dialog } from "../components/ui/Dialog";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { TabPanel, Tabs } from "../components/ui/Tabs";
import { useMe } from "../hooks/useMe";
import { DOMAINS } from "./Overview";
import { SbomPanel } from "./SupplyChain";

/** One row per control: the worst state across its scopes (a control is only as good as its weakest repository). */
function perControl(items: ControlItem[]): { worst: ControlItem; scopes: ControlItem[] }[] {
  const by = new Map<string, ControlItem[]>();
  for (const i of items) by.set(i.control_key, [...(by.get(i.control_key) ?? []), i]);
  return [...by.values()].map((scopes) => {
    const applicable = scopes.filter((s) => s.requirement !== "n/a");
    const pool = applicable.length ? applicable : scopes;
    const worst = pool.reduce((a, b) => (STATES[b.state].order < STATES[a.state].order ? b : a));
    return { worst, scopes };
  });
}

const DECISION: Record<Classification["decision"], string> = {
  pending: "waiting for AppSec approval", approved: "approved", auto_approved: "auto-approved (Tier 3/4)", rejected: "rejected",
};

const date = (s: string | null | undefined, time = false) =>
  !s ? "–" : new Date(s).toLocaleString(undefined, time ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" });

const TABS = ["overview", "controls", "findings", "evidence", "supply-chain", "maturity", "activity"] as const;
type Tab = (typeof TABS)[number];

export function Application({ id }: { id: string }) {
  const params = useParams();
  const navigate = useNavigate();
  const tab: Tab = (TABS as readonly string[]).includes(params.tab ?? "") ? (params.tab as Tab) : "overview";
  const me = useMe();
  const app = useQuery({ queryKey: ["app", id], queryFn: () => api.application(id) });
  const controls = useQuery({ queryKey: ["controls", id], queryFn: () => api.controls(id) });
  const findings = useQuery({ queryKey: ["findings", id], queryFn: () => api.findings(id) });
  const maturity = useQuery({ queryKey: ["maturity", id], queryFn: () => api.maturity(id) });
  const trend = useQuery({ queryKey: ["app-trend", id], queryFn: () => api.appTrend(id) });

  if (app.isPending) return <SkeletonRows rows={10} />;
  if (app.isError) {
    const e = app.error;
    return (
      <EmptyState title={e instanceof ApiError && e.status === 404 ? "Application not found" : "Couldn't load the application"}>
        {e instanceof ApiError && e.status === 404 ? "It doesn't exist, or it isn't in your scope (the two look the same on purpose)." : String(e)}
      </EmptyState>
    );
  }
  const a = app.data;
  const rows = perControl(controls.data?.items ?? []);
  const mandatory = rows.filter((r) => r.worst.requirement === "mandatory");
  const counts = mandatory.reduce<Partial<Record<ControlStateValue, number>>>((acc, r) => ({ ...acc, [r.worst.state]: (acc[r.worst.state] ?? 0) + 1 }), {});
  const sat = counts.satisfied ?? 0;
  const t = trend.data;
  const cov = (t?.metrics.mandatory_total ?? []).map((n, i) => (n ? ((t?.metrics.mandatory_satisfied?.[i] ?? 0) / n) * 100 : null));
  const open = findings.data ?? [];
  const perms = new Set(me.data?.permissions ?? []);

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Applications", to: "/apps" }, { label: a.name }]}
        title={<span className="inline-flex items-center gap-3">{a.name}<TierBadge tier={a.tier} /></span>}
        meta={<><span className="font-mono text-xs text-muted">{a.app_key}</span><span>·</span><span>{a.org_unit}</span><span>·</span><span>{a.lifecycle}</span>{a.exposure && <><span>·</span><span>{a.exposure.replaceAll("_", " ")}</span></>}</>}
        description={a.description}
        actions={
          <>
            {perms.has("exception.request") && <ButtonLink to={`/exceptions/new?app=${a.app_key}`}><ShieldOff className="size-4" aria-hidden="true" /> Request exception</ButtonLink>}
            {perms.has("assessment.create") && <ButtonLink to={`/assessments/new?app=${a.app_key}`}><ClipboardCheck className="size-4" aria-hidden="true" /> Start assessment</ButtonLink>}
          </>
        }
      />
      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Kpi label="Mandatory controls proven" value={controls.data ? `${sat} / ${mandatory.length}` : "–"} trend={cov.filter((v): v is number => v !== null)} sub={controls.data ? `Evaluated ${date(controls.data.data_as_of.computed_at, true)}` : undefined} />
        <Kpi label="Open findings" value={findings.data ? open.length : "–"} tone={open.some((f) => f.priority === "P1") ? "critical" : undefined} sub={`${open.filter((f) => f.priority === "P1").length} P1 · ${open.filter((f) => f.sla_breached).length} past deadline`} />
        <Kpi label="SAMM maturity" value={maturity.data ? maturity.data.overall.toFixed(2) : "–"} sub={maturity.data && a.tier ? `${maturity.data.meets_tier_target ? "Meets" : "Below"} its Tier ${a.tier} target (0–3)` : "0–3 scale"} />
        <Kpi label="Evidence this month" value={t ? (t.metrics.evidence_accepted?.at(-1) ?? 0) : "–"} trend={(t?.metrics.evidence_accepted ?? []).filter((v): v is number => v !== null)} sub={`${t?.metrics.evidence_rejected?.at(-1) ?? 0} rejected`} />
      </div>

      <Tabs
        label="Application sections"
        value={tab}
        onValueChange={(v) => void navigate(v === "overview" ? `/apps/${a.app_key}` : `/apps/${a.app_key}/${v}`, { replace: true })}
        tabs={[
          { value: "overview", label: "Overview" },
          { value: "controls", label: "Controls", count: rows.length || undefined },
          { value: "findings", label: "Findings", count: open.length || undefined },
          { value: "evidence", label: "Evidence" },
          { value: "supply-chain", label: "Supply chain" },
          { value: "maturity", label: "Maturity" },
          { value: "activity", label: "Activity" },
        ]}
      >
        <TabPanel value="overview" className="space-y-4">
          <OverviewTab app={a} counts={counts} rows={rows} cov={cov} dates={t?.periods ?? []} />
        </TabPanel>
        <TabPanel value="controls"><ControlsTab rows={rows} loading={controls.isPending} /></TabPanel>
        <TabPanel value="findings"><FindingsTab items={open} loading={findings.isPending} /></TabPanel>
        <TabPanel value="evidence"><EvidenceTab appKey={a.app_key} /></TabPanel>
        <TabPanel value="supply-chain"><SbomPanel appKey={a.app_key} /></TabPanel>
        <TabPanel value="maturity" className="space-y-4">
          <Card title={a.tier ? `SAMM practices against the Tier ${a.tier} target` : "SAMM practices"} description="From control states and assessments (OWASP SAMM 0–3). Hover a bar for how much rests on automated evidence, independent review or self-assessment.">
            {maturity.data ? (
              <BulletBars
                label="SAMM maturity by practice"
                items={maturity.data.practices.map((p) => ({
                  key: p.item, label: p.name, value: p.score, target: p.target,
                  detail: [`automated ${p.provenance.automated}% · independent ${p.provenance.manual_independent}%`, `self-assessed ${p.provenance.manual_self}% · unassessed ${p.provenance.unassessed}%`],
                }))}
              />
            ) : <SkeletonRows rows={6} />}
          </Card>
          {t && (
            <Card title="SAMM maturity over time" description="Overall score, monthly">
              <LineChart label="SAMM maturity over time" dates={t.periods.map((p) => `${p}-01T00:00:00Z`)} yMax={3} format={(v) => v.toFixed(1)} series={[{ key: "samm", label: "SAMM overall", color: "var(--series-1)", values: t.metrics.samm_overall ?? [] }]} />
            </Card>
          )}
        </TabPanel>
        <TabPanel value="activity"><ActivityTab appKey={a.app_key} /></TabPanel>
      </Tabs>
    </>
  );
}

function OverviewTab({ app: a, counts, rows, cov, dates }: { app: Awaited<ReturnType<typeof api.application>>; counts: Partial<Record<ControlStateValue, number>>; rows: ReturnType<typeof perControl>; cov: (number | null)[]; dates: string[] }) {
  const qc = useQueryClient();
  const cls = useQuery({ queryKey: ["classification", a.app_key], queryFn: () => api.classification(a.app_key) });
  const attention = rows
    .filter((r) => r.worst.requirement === "mandatory" && !["satisfied", "excepted", "not_applicable", "error"].includes(r.worst.state))
    .sort((x, y) => STATES[x.worst.state].order - STATES[y.worst.state].order);
  return (
    <>
      {cls.data?.decision === "pending" && (
        <ClassificationDecision appId={a.id} c={cls.data} onDone={() => { void qc.invalidateQueries({ queryKey: ["app", a.app_key] }); void cls.refetch(); }} />
      )}
      <div className="grid items-start gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3" title="Needs attention" description="Mandatory controls that current evidence doesn't prove" actions={<CoverageBar counts={counts} width={220} />} bodyClassName="px-2 py-1">
          {attention.length === 0 ? (
            <EmptyState icon={CheckCircle2} title="Every evaluated mandatory control is proven">Current, verified evidence satisfies all of them.</EmptyState>
          ) : (
            <ul className="plain m-0 p-0">
              {attention.map(({ worst: r }) => (
                <li key={r.control_key} className="flex items-start gap-3 rounded-md px-3 py-2.5 hover:bg-surface-2">
                  <StateBadge state={r.state} />
                  <div className="min-w-0 flex-1">
                    <Link to={`/apps/${a.app_key}/controls?control=${r.control_key}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{r.title}</Link>
                    <div className="text-xs text-muted"><span className="font-mono">{r.control_key}</span>{r.scope.type === "repository" ? ` · ${r.scope.ref.split("/").pop()}` : ""} · {r.explanation}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <div className="border-t border-line px-3 py-3"><CoverageLegend /></div>
        </Card>
        <div className="space-y-4 xl:col-span-2">
          <Card title={a.tier ? `Why Tier ${a.tier}?` : "Classification"}>
            {cls.data ? (
              <>
                {cls.data.decision === "rejected" && (
                  <p className="m-0 mb-3 rounded-md border border-line bg-surface-2 p-3 text-xs text-critical-ink">
                    The computed Tier {cls.data.computed_tier} was rejected by {cls.data.decided_by}. Correct the classification in <code>.security/application.yaml</code> and register again, or ask AppSec.
                  </p>
                )}
                <p className="m-0 text-[13px] text-ink-2">{cls.data.explanation}</p>
                <p className="m-0 mt-2 text-xs text-muted">
                  ASVS target {cls.data.asvs_target} · {DECISION[cls.data.decision]}{cls.data.decided_by ? ` by ${cls.data.decided_by}` : ""}
                </p>
                <table className="mt-3 w-full text-xs">
                  <tbody>
                    {cls.data.contributions.map(([dim, val, pts]) => (
                      <tr key={dim} className="border-t border-line">
                        <td className="py-1.5 text-muted">{dim.replaceAll("_", " ")}</td>
                        <td className="py-1.5 text-ink-2">{val.replaceAll("_", " ")}</td>
                        <td className="py-1.5 text-right tabular-nums text-ink-2">{pts} pts</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : <SkeletonRows rows={3} />}
          </Card>
          <Card title="Ownership">
            <dl className="m-0 grid grid-cols-[130px_1fr] gap-x-3 gap-y-2 text-[13px]">
              <dt className="text-muted">Business owner</dt><dd className="m-0">{a.business_owner ?? <span className="text-critical-ink">Not resolved</span>}</dd>
              <dt className="text-muted">Technical owner</dt><dd className="m-0">{a.technical_owner ?? <span className="text-critical-ink">Not resolved</span>}</dd>
              <dt className="text-muted">Security champion</dt><dd className="m-0">{a.champion ?? <span className="text-muted">None named</span>}</dd>
              <dt className="text-muted">Data</dt><dd className="m-0">{a.data_classification} · personal data: {a.personal_data?.replaceAll("_", " ")}</dd>
              <dt className="text-muted">Exposure</dt><dd className="m-0">{a.exposure?.replaceAll("_", " ")}</dd>
            </dl>
          </Card>
          <OpenWork appKey={a.app_key} />
        </div>
      </div>
      {cov.some((v) => v !== null) && (
        <Card title="Mandatory controls proven over time">
          <LineChart label="Mandatory controls proven over time" dates={dates.map((p) => `${p}-01T00:00:00Z`)} yMax={100} format={(v) => `${Math.round(v)}%`} series={[{ key: "cov", label: "Controls proven", color: "var(--series-1)", values: cov }]} />
        </Card>
      )}
    </>
  );
}

/** Tier 1/2: an AppSec engineer outside the owning team approves or rejects; the API enforces the same rule. */
function ClassificationDecision({ appId, c, onDone }: { appId: string; c: Classification; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const decide = async (decision: "approved" | "rejected") => {
    try {
      await api.decideClassification(appId, decision, reason);
      onDone();
    } catch (e) {
      setMsg(e instanceof ApiError ? `${e.title}: ${e.detail ?? ""}` : String(e));
    }
  };
  return (
    <div className="rounded-xl border border-warning/40 bg-surface p-4">
      <div className="text-sm font-semibold text-ink">Tier {c.computed_tier} is waiting for AppSec approval</div>
      <p className="m-0 mt-1 text-[13px] text-ink-2">Controls are evaluated once the tier is approved.</p>
      {c.can_decide ? (
        <>
          <label className="mt-3 block text-xs text-muted" htmlFor="decision-reason">Reason (recorded in the audit log)</label>
          <textarea id="decision-reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} className="mt-1 w-full rounded-md border border-line bg-page p-2 text-[13px] text-ink" />
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void decide("approved")}>Approve Tier {c.computed_tier}</Button>
            <Button onClick={() => void decide("rejected")}>Reject</Button>
          </div>
          {msg && <p className="m-0 mt-2 text-xs text-critical-ink">{msg}</p>}
        </>
      ) : (
        <p className="m-0 mt-2 text-xs text-muted">An AppSec engineer who is not the requester and not in the owning team decides it.</p>
      )}
    </div>
  );
}

/** Exceptions and assessments for this application. */
function OpenWork({ appKey }: { appKey: string }) {
  const exceptions = useQuery({ queryKey: ["exceptions", appKey], queryFn: () => api.exceptions(appKey) });
  const assessments = useQuery({ queryKey: ["assessments", appKey], queryFn: () => api.assessments(appKey) });
  return (
    <Card title="Exceptions and assessments" bodyClassName="px-5 py-3">
      <div className="text-xs font-medium text-muted">Exceptions</div>
      {exceptions.data?.length ? (
        <ul className="plain m-0 mb-3 mt-1 p-0 text-[13px]">
          {exceptions.data.slice(0, 5).map((x) => (
            <li key={x.id} className="py-0.5"><Link to={`/exceptions/${x.exception_key}`} className="font-mono text-xs">{x.exception_key}</Link> <span className="text-ink-2">· {x.status.replaceAll("_", " ")}{x.expires_at ? ` · expires ${date(x.expires_at)}` : ""}</span></li>
          ))}
        </ul>
      ) : <p className="m-0 mb-3 mt-1 text-xs text-muted">None.</p>}
      <div className="text-xs font-medium text-muted">Assessments</div>
      {assessments.data?.length ? (
        <ul className="plain m-0 mt-1 p-0 text-[13px]">
          {assessments.data.slice(0, 5).map((x) => (
            <li key={x.id} className="py-0.5"><Link to={`/assessments/${x.id}`}>{x.type.replaceAll("_", " ")}</Link> <span className="text-ink-2">· {x.status.replaceAll("_", " ")}{x.confidence ? ` · ${x.confidence}` : ""}</span></li>
          ))}
        </ul>
      ) : <p className="m-0 mt-1 text-xs text-muted">None.</p>}
    </Card>
  );
}

type ControlRow = ReturnType<typeof perControl>[number];

function ControlsTab({ rows, loading }: { rows: ControlRow[]; loading: boolean }) {
  const [open, setOpen] = useState<ControlRow | null>(() => {
    const key = new URLSearchParams(window.location.search).get("control");
    return key ? rows.find((r) => r.worst.control_key === key) ?? null : null;
  });
  const columns: ColumnDef<ControlRow, unknown>[] = [
    { id: "key", header: "Control", accessorFn: (r) => `${r.worst.control_key} ${r.worst.title}`, sortingFn: (x, y) => x.original.worst.control_key.localeCompare(y.original.worst.control_key),
      cell: ({ row: { original: r } }) => (
        <button type="button" onClick={() => setOpen(r)} className="block bg-transparent p-0 text-left">
          <span className="block text-[13px] font-medium text-ink hover:text-accent-ink">{r.worst.title}</span>
          <span className="font-mono text-[11px] text-muted">{r.worst.control_key}</span>
        </button>
      ) },
    { id: "state", header: "State", accessorFn: (r) => r.worst.state, filterFn: inSet<ControlRow>(), sortingFn: (x, y) => STATES[x.original.worst.state].order - STATES[y.original.worst.state].order, cell: ({ row }) => <StateBadge state={row.original.worst.state} /> },
    { id: "domain", header: "Domain", accessorFn: (r) => r.worst.control_key.split("-")[1] ?? "", filterFn: inSet<ControlRow>(), cell: ({ getValue }) => <span className="text-ink-2">{DOMAINS[String(getValue())] ?? String(getValue())}</span> },
    { id: "requirement", header: "Requirement", accessorFn: (r) => r.worst.requirement, filterFn: inSet<ControlRow>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "why", header: "Why", accessorFn: (r) => r.worst.explanation, enableSorting: false, cell: ({ getValue }) => <span className="line-clamp-2 text-xs text-ink-2">{String(getValue())}</span> },
  ];
  return (
    <Card bodyClassName="">
      {loading ? <SkeletonRows rows={8} /> : (
        <DataTable
          data={rows}
          columns={columns}
          label="controls"
          searchPlaceholder="Search controls…"
          facets={[
            { column: "state", title: "State", label: (v) => STATES[v as ControlStateValue]?.label ?? v },
            { column: "domain", title: "Domain", label: (v) => DOMAINS[v] ?? v },
            { column: "requirement", title: "Requirement" },
          ]}
          initialSort={[{ id: "state", desc: false }]}
          pageSize={50}
        />
      )}
      <Dialog open={!!open} onClose={() => setOpen(null)} title={open ? `${open.worst.control_key} · ${open.worst.title}` : ""} variant="drawer">
        {open && (
          <div className="flex flex-col gap-4 text-[13px]">
            <div className="flex flex-wrap items-center gap-2"><StateBadge state={open.worst.state} /><span className="text-xs text-muted">{open.worst.requirement} · {open.worst.mode} · since {date(open.worst.since, true)}</span></div>
            <p className="m-0 text-ink-2">{open.worst.explanation}</p>
            <div><div className="mb-1 text-xs font-medium text-muted">How it is proven</div><p className="m-0 text-ink-2">{open.worst.proof}</p></div>
            <div>
              <div className="mb-1 text-xs font-medium text-muted">Scopes</div>
              <ul className="plain m-0 space-y-2 p-0">
                {open.scopes.map((s) => (
                  <li key={s.scope.ref} className="rounded-md border border-line p-3">
                    <div className="flex items-center gap-2"><StateBadge state={s.state} /><span className="font-mono text-xs text-ink-2">{s.scope.ref}</span></div>
                    <p className="m-0 mt-1.5 text-xs text-ink-2">{s.explanation}</p>
                    {s.evidence_ids.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {s.evidence_ids.map((e) => <Link key={e} to={`/evidence/${e}`} className="inline-flex items-center gap-1 font-mono text-xs"><FileCheck2 className="size-3" aria-hidden="true" />EV-{e.replaceAll("-", "").slice(-8).toUpperCase()}</Link>)}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
            <p className="m-0 text-xs text-muted">Evaluator <code>{open.worst.evaluator}</code></p>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

function FindingsTab({ items, loading }: { items: Finding[]; loading: boolean }) {
  const order = { P1: 0, P2: 1, P3: 2, P4: 3 } as const;
  const columns: ColumnDef<Finding, unknown>[] = [
    { id: "priority", header: "Priority", accessorFn: (f) => f.priority ?? "", filterFn: inSet<Finding>(), sortingFn: (a, b) => (order[a.original.priority ?? "P4"] ?? 9) - (order[b.original.priority ?? "P4"] ?? 9), cell: ({ row }) => <PriorityChip p={row.original.priority} due={row.original.sla_due_at} /> },
    { id: "title", header: "Finding", accessorKey: "title", cell: ({ row: { original: f } }) => (
      <div><Link to={`/findings/${f.id}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{f.title}</Link>
        <div className="text-xs text-muted">{f.type} · {String(f.location?.uri ?? f.location?.purl ?? f.scope_ref)}</div></div>
    ) },
    { id: "status", header: "Status", accessorKey: "status", filterFn: inSet<Finding>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue()).replaceAll("_", " ")}</span> },
    { id: "due", header: "Fix by", accessorFn: (f) => f.sla_due_at ?? "", cell: ({ row: { original: f } }) => <span className={f.sla_breached ? "text-critical-ink" : "text-ink-2"}>{date(f.sla_due_at)}{f.sla_breached ? " (past deadline)" : ""}</span> },
  ];
  return (
    <Card bodyClassName="">
      {loading ? <SkeletonRows rows={6} /> : (
        <DataTable data={items} columns={columns} label="open findings" facets={[{ column: "priority", title: "Priority" }, { column: "status", title: "Status" }]} initialSort={[{ id: "priority", desc: false }]} rowHref={(f) => `/findings/${f.id}`}
          empty={<EmptyState icon={CheckCircle2} title="No open findings">Nothing to fix for this application right now.</EmptyState>} />
      )}
    </Card>
  );
}

function EvidenceTab({ appKey }: { appKey: string }) {
  const ev = useQuery({ queryKey: ["evidence", appKey], queryFn: () => api.allEvidence({ application: appKey, limit: 200 }) });
  const columns: ColumnDef<EvidenceListItem, unknown>[] = [
    { id: "type", header: "Evidence", accessorFn: (e) => evidenceLabel(e.type), cell: ({ row: { original: e } }) => (
      <div><Link to={`/evidence/${e.id}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{evidenceLabel(e.type)}</Link>
        <div className="font-mono text-[11px] text-muted">{e.type}{e.repository ? ` · ${e.repository}` : ""}</div></div>
    ) },
    { id: "confidence", header: "Confidence", accessorKey: "confidence", filterFn: inSet<EvidenceListItem>(), cell: ({ getValue }) => <ConfidenceBadge level={String(getValue())} /> },
    { id: "state", header: "State", accessorKey: "state", filterFn: inSet<EvidenceListItem>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "result", header: "Result", accessorKey: "result", cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "observed", header: "Observed", accessorKey: "observed_at", cell: ({ getValue }) => <span className="text-ink-2">{date(String(getValue()), true)}</span> },
  ];
  return (
    <Card bodyClassName="">
      {ev.isPending ? <SkeletonRows rows={8} /> : (
        <DataTable data={ev.data ?? []} columns={columns} label="evidence records" searchPlaceholder="Search evidence…" facets={[{ column: "confidence", title: "Confidence" }, { column: "state", title: "State" }]} initialSort={[{ id: "observed", desc: true }]} rowHref={(e) => `/evidence/${e.id}`} />
      )}
    </Card>
  );
}

function ActivityTab({ appKey }: { appKey: string }) {
  const feed = useQuery({ queryKey: ["activity", appKey], queryFn: () => api.activity(appKey, 50) });
  return (
    <Card bodyClassName="px-2 py-1">
      {feed.isPending ? <SkeletonRows rows={6} /> : feed.data?.length ? (
        <ul className="plain m-0 p-0">
          {feed.data.map((x, i) => (
            <li key={`${x.ref}-${i}`} className="flex items-start gap-3 rounded-md px-3 py-2 hover:bg-surface-2">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-[13px] text-ink">{x.kind === "evidence_accepted" ? evidenceLabel(x.evidence_type) : x.title}{x.confidence && <ConfidenceBadge level={x.confidence} />}</div>
                <div className="text-xs text-muted">{x.kind.replaceAll("_", " ")}</div>
              </div>
              <time dateTime={x.at} className="shrink-0 text-xs text-muted">{date(x.at, true)}</time>
            </li>
          ))}
        </ul>
      ) : <EmptyState title="No activity yet" />}
    </Card>
  );
}
