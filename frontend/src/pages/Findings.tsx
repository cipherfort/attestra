// SPDX-License-Identifier: Apache-2.0
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, ShieldOff } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { ApiError, api, type Finding, type FindingDetail } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { PriorityChip } from "../components/domain/badges";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";

const day = (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "–");
const when = (s: string | null | undefined) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "–");
const ORDER = { P1: 0, P2: 1, P3: 2, P4: 3 } as const;

export function FindingsList() {
  const [openOnly, setOpenOnly] = useState(true);
  const q = useQuery({ queryKey: ["findings-all", openOnly], queryFn: () => api.findingsAll(openOnly) });
  const columns: ColumnDef<Finding, unknown>[] = [
    { id: "priority", header: "Priority", accessorFn: (f) => f.priority ?? "", filterFn: inSet<Finding>(), sortingFn: (a, b) => (ORDER[a.original.priority ?? "P4"] ?? 9) - (ORDER[b.original.priority ?? "P4"] ?? 9), cell: ({ row }) => <PriorityChip p={row.original.priority} due={["closed", "false_positive"].includes(row.original.status) ? null : row.original.sla_due_at} /> },
    { id: "title", header: "Finding", accessorKey: "title", cell: ({ row: { original: f } }) => (
      <div><Link to={`/findings/${f.id}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{f.title}</Link>
        <div className="text-xs text-muted">{f.type.replaceAll("_", " ")} · {String(f.location?.uri ?? f.location?.purl ?? f.scope_ref)}</div></div>
    ) },
    { id: "app", header: "Application", accessorKey: "application_name", filterFn: inSet<Finding>(), cell: ({ row: { original: f } }) => <Link to={`/apps/${f.app_key}`} className="text-ink-2 hover:text-accent-ink">{f.application_name}</Link> },
    { id: "type", header: "Type", accessorKey: "type", filterFn: inSet<Finding>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue()).replaceAll("_", " ")}</span> },
    { id: "status", header: "Status", accessorKey: "status", filterFn: inSet<Finding>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue()).replaceAll("_", " ")}</span> },
    { id: "due", header: "Fix by", accessorFn: (f) => f.sla_due_at ?? "9999", cell: ({ row: { original: f } }) => <span className={f.sla_breached ? "font-medium text-critical-ink" : "text-ink-2"}>{day(f.sla_due_at)}</span> },
  ];
  return (
    <>
      <PageHeader title="Findings" description="Security findings across the applications you can see, prioritised by context (exploitation, exposure, tier, data), not only by tool severity. A finding closes when a re-scan no longer reports it." />
      <Card bodyClassName="">
        {q.isPending ? <SkeletonRows rows={8} /> : (
          <DataTable
            data={q.data ?? []}
            columns={columns}
            label={openOnly ? "open findings" : "findings"}
            searchPlaceholder="Search findings…"
            facets={[{ column: "priority", title: "Priority" }, { column: "app", title: "Application" }, { column: "type", title: "Type", label: (v) => v.replaceAll("_", " ") }, { column: "status", title: "Status", label: (v) => v.replaceAll("_", " ") }]}
            initialSort={[{ id: "priority", desc: false }]}
            rowHref={(f) => `/findings/${f.id}`}
            toolbar={
              <label className="flex items-center gap-2 text-xs text-ink-2">
                <input type="checkbox" checked={!openOnly} onChange={(e) => setOpenOnly(!e.target.checked)} className="size-3.5 accent-[var(--accent)]" />
                Include closed
              </label>
            }
            csv={{ filename: "findings.csv", row: (f) => ({ priority: f.priority ?? "", title: f.title, application: f.application_name, type: f.type, status: f.status, fix_by: f.sla_due_at ?? "", past_deadline: f.sla_breached }) }}
            empty={<EmptyState icon={CheckCircle2} title="No findings">Nothing open across the applications you can see.</EmptyState>}
          />
        )}
      </Card>
    </>
  );
}

export function FindingPage({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.finding(id) });
  const events = useQuery({ queryKey: ["finding-events", id], queryFn: () => api.findingEvents(id) });
  const qc = useQueryClient();
  if (q.isPending) return <SkeletonRows rows={8} />;
  if (q.isError) {
    return <EmptyState title="Finding not found">{q.error instanceof ApiError && q.error.status === 404 ? "It doesn't exist, or it belongs to an application outside your scope." : String(q.error)}</EmptyState>;
  }
  const { data: f, etag } = q.data;
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["finding", id] }); void qc.invalidateQueries({ queryKey: ["finding-events", id] }); };
  const open = !["closed", "false_positive", "excepted"].includes(f.status);
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Findings", to: "/findings" }, { label: f.application_name, to: `/apps/${f.app_key}` }, { label: "Finding" }]}
        title={f.title}
        meta={<><PriorityChip p={f.priority} due={open ? f.sla_due_at : null} /><span>{f.type.replaceAll("_", " ")}</span><span>·</span><span>{f.status.replaceAll("_", " ")}</span><span>·</span><span>first seen {day(f.first_seen_at)}</span></>}
        actions={open && <ButtonLink to={`/exceptions/new?app=${f.app_key}&type=finding&ref=${f.id}`}><ShieldOff className="size-4" aria-hidden="true" /> Request exception</ButtonLink>}
      />
      <div className="grid items-start gap-4 xl:grid-cols-5">
        <div className="space-y-4 xl:col-span-3">
          <Card title={`Why ${f.priority ?? "unscored"}?`} description="A prioritisation model, not an objective truth: the weights are governed configuration (config/risk-model.yaml)">
            <p className="m-0 text-[13px] text-ink-2">{f.risk_explanation ?? "Not scored yet."}</p>
            {f.likelihood !== null && (
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <span className="rounded-md bg-surface-2 px-2 py-1 text-ink-2">Likelihood <b className="text-ink">{f.likelihood}</b></span>
                <span className="rounded-md bg-surface-2 px-2 py-1 text-ink-2">× Impact <b className="text-ink">{f.impact}</b></span>
                <span className="rounded-md bg-surface-2 px-2 py-1 text-ink-2">= Score <b className="text-ink">{f.risk_score}</b></span>
                {(f.applied_rules ?? []).map((r) => <span key={r} className="rounded-md border border-line px-2 py-1 font-mono text-ink-2">{r}</span>)}
              </div>
            )}
          </Card>
          <Card title="Details">
            <p className="m-0 text-[13px] text-ink-2">{f.description}</p>
            <dl className="m-0 mt-3 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-xs">
              {Object.entries(f.location ?? {}).map(([k, v]) => (
                <div key={k} className="contents"><dt className="text-muted">{k}</dt><dd className="m-0 break-all font-mono text-ink-2">{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>
              ))}
              {f.last_seen_evidence_id && <><dt className="text-muted">last seen in</dt><dd className="m-0"><Link to={`/evidence/${f.last_seen_evidence_id}`} className="font-mono">EV-{f.last_seen_evidence_id.replaceAll("-", "").slice(-8).toUpperCase()}</Link></dd></>}
              {f.closure_evidence_id && <><dt className="text-muted">closed by</dt><dd className="m-0"><Link to={`/evidence/${f.closure_evidence_id}`} className="font-mono">EV-{f.closure_evidence_id.replaceAll("-", "").slice(-8).toUpperCase()}</Link></dd></>}
            </dl>
          </Card>
        </div>
        <div className="space-y-4 xl:col-span-2">
          <Card title="Actions">
            <Actions f={f} etag={etag ?? ""} onDone={refresh} />
            <p className="m-0 mt-3 text-xs text-muted">Closing is not an action: a finding closes only when a re-scan of the same scope no longer reports it. A ticket marked Done is not enough.</p>
          </Card>
          <Card title="History">
            {events.data?.length ? (
              <ol className="plain m-0 space-y-2.5 p-0">
                {events.data.map((e, i) => (
                  <li key={i} className="text-[13px]">
                    <span className="font-medium text-ink">{e.event_type.replaceAll("_", " ")}</span>{e.to_status && <span className="text-ink-2"> → {e.to_status.replaceAll("_", " ")}</span>}
                    <div className="text-xs text-muted">{e.actor_type === "system" ? "platform" : "person"} · {when(e.at)}</div>
                    {typeof e.details?.comment === "string" && e.details.comment && <div className="mt-0.5 text-xs text-ink-2">“{e.details.comment}”</div>}
                  </li>
                ))}
              </ol>
            ) : <p className="m-0 text-xs text-muted">No events.</p>}
          </Card>
        </div>
      </div>
    </>
  );
}

function Actions({ f, etag, onDone }: { f: FindingDetail; etag: string; onDone: () => void }) {
  const me = useMe();
  const canConfirm = me.data?.permissions.includes("finding.fp.confirm") ?? false;
  const [comment, setComment] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const run = async (action: string) => {
    try {
      await api.transition(f.id, etag, action, comment || undefined);
      setMsg({ ok: true, text: `${action.replaceAll("_", " ")}: done` });
      setComment("");
      onDone();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? `${e.title}: ${e.detail ?? ""}` : String(e) });
    }
  };
  if (["closed", "false_positive"].includes(f.status)) return <p className="m-0 text-[13px] text-muted">No actions: this finding is {f.status.replaceAll("_", " ")}.</p>;
  return (
    <div>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => void run("triage")} disabled={!["new", "reopened"].includes(f.status)}>Triage</Button>
        <Button onClick={() => void run("mark_false_positive")}>Request false positive</Button>
        {canConfirm && <>
          <Button onClick={() => void run("confirm_false_positive")}>Confirm false positive</Button>
          <Button onClick={() => void run("reject_false_positive")}>Reject false positive</Button>
        </>}
      </div>
      <label htmlFor="finding-comment" className="mt-3 block text-xs text-muted">Justification (required to request a false positive)</label>
      <textarea id="finding-comment" rows={2} value={comment} onChange={(e) => setComment(e.target.value)} className="mt-1 w-full rounded-md border border-line bg-page p-2 text-[13px] text-ink" />
      {msg && <p className={`m-0 mt-2 text-xs ${msg.ok ? "text-good-ink" : "text-critical-ink"}`}>{msg.text}</p>}
      <p className="m-0 mt-2 text-xs text-muted">A false positive needs two people: anyone in the team can request it, and a different AppSec engineer confirms it. Self-confirmation is refused and audited.</p>
    </div>
  );
}
