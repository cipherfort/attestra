// SPDX-License-Identifier: Apache-2.0
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, CircleDashed, Clock3, FilePen, Hourglass, Plus, ShieldOff, XCircle, type LucideIcon } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, type ExceptionCreate, type ExceptionRow, type Priority, type SecurityException } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { PriorityChip } from "../components/domain/badges";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Facts, Field, LoadError, Notice, errorText, inputClass, selectClass, textareaClass } from "../components/ui/Form";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";

export const EXCEPTION_STATUS: Record<string, { label: string; icon: LucideIcon; tone: string }> = {
  draft: { label: "Draft", icon: FilePen, tone: "text-muted" },
  pending_approval: { label: "Waiting for a decision", icon: Hourglass, tone: "text-warning" },
  approved: { label: "Approved", icon: CheckCircle2, tone: "text-good" },
  rejected: { label: "Rejected", icon: XCircle, tone: "text-critical" },
  expired: { label: "Expired", icon: Clock3, tone: "text-serious" },
  revoked: { label: "Revoked", icon: XCircle, tone: "text-muted" },
  closed: { label: "Replaced by a renewal", icon: CircleDashed, tone: "text-muted" },
};
const OPEN = new Set(["draft", "pending_approval", "approved"]);
const TARGET: Record<string, string> = { control: "Control", finding: "Finding", requirement: "Requirement", sla: "Deadline" };
/** Approver levels in the exception policy (config/exception-policy.yaml), in words. */
const APPROVER: Record<string, string> = {
  ciso: "CISO", head_of_appsec: "Head of AppSec", unit_security_lead: "Unit security lead", appsec_engineer: "AppSec engineer",
};
const approver = (r: string) => APPROVER[r] ?? r.replaceAll("_", " ");

export function ExceptionStatus({ status }: { status: string }) {
  const s = EXCEPTION_STATUS[status] ?? { label: status, icon: CircleDashed, tone: "text-muted" };
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink">
      <s.icon className={`size-3.5 ${s.tone}`} aria-hidden="true" />{s.label}
    </span>
  );
}

const day = (s: string | null | undefined, time = false) =>
  s ? new Date(s).toLocaleString(undefined, time ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" }) : "–";
const daysLeft = (s: string | null | undefined) => (s ? Math.ceil((new Date(s).getTime() - Date.now()) / 86_400_000) : null);

export function Exceptions({ id }: { id?: string }) {
  if (id === "new") return <NewException />;
  if (id) return <ExceptionDetail key={id} id={id} />;
  return <ExceptionList />;
}

function ExceptionList() {
  const me = useMe();
  const canRequest = (me.data?.permissions ?? []).includes("exception.request");
  const [all, setAll] = useState(false);
  const rows = useQuery({ queryKey: ["exceptions"], queryFn: () => api.exceptions() });
  const data = (rows.data ?? []).filter((r) => all || OPEN.has(r.status));
  const items = rows.data ?? [];
  const soon = items.filter((r) => r.status === "approved" && (daysLeft(r.expires_at) ?? 99) <= 30).length;
  const cols: ColumnDef<ExceptionRow, unknown>[] = [
    { id: "key", header: "Exception", accessorFn: (r) => `${r.exception_key} ${r.target_ref}`, cell: ({ row: { original: r } }) => (
      <div><Link to={`/exceptions/${r.exception_key}`} className="font-mono text-[13px] font-medium text-ink hover:text-accent-ink">{r.exception_key}</Link>
        <div className="text-xs text-muted">{TARGET[r.target_type] ?? r.target_type} <span className="font-mono">{r.target_ref.slice(0, 24)}</span></div></div>
    ) },
    { id: "app", header: "Application", accessorKey: "application_name", filterFn: inSet<ExceptionRow>(), cell: ({ row: { original: r } }) => <Link to={`/apps/${r.app_key}`} className="text-ink-2 hover:text-accent-ink">{r.application_name}</Link> },
    { id: "priority", header: "Residual risk", accessorKey: "residual_priority", filterFn: inSet<ExceptionRow>(), cell: ({ getValue }) => <PriorityChip p={getValue() as Priority} /> },
    { id: "status", header: "Status", accessorKey: "status", filterFn: inSet<ExceptionRow>(), cell: ({ getValue }) => <ExceptionStatus status={String(getValue())} /> },
    { id: "by", header: "Requested by", accessorKey: "requested_by", cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "expires", header: "Expires", accessorFn: (r) => r.expires_at ?? "", cell: ({ row: { original: r } }) => {
      const d = daysLeft(r.expires_at);
      return r.expires_at ? (
        <div className="whitespace-nowrap"><span className="text-ink-2">{day(r.expires_at)}</span>
          {r.status === "approved" && d !== null && <div className={`text-xs ${d < 0 ? "text-critical-ink" : d <= 30 ? "font-medium text-ink" : "text-muted"}`}>{d < 0 ? "overdue" : `in ${d} day${d === 1 ? "" : "s"}`}</div>}</div>
      ) : <span className="text-muted">–</span>;
    } },
  ];
  return (
    <>
      <PageHeader
        title="Exceptions"
        description="Time-bound, approved acceptance of a known gap. Who must approve depends on the residual risk and the application's tier; the requester, the technical owner and the owning team can never approve their own."
        actions={canRequest && <ButtonLink to="/exceptions/new" variant="primary"><Plus className="size-4" aria-hidden="true" />Request an exception</ButtonLink>}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Kpi label="Waiting for a decision" value={rows.isPending ? "–" : items.filter((r) => r.status === "pending_approval").length} sub="Submitted, not yet decided" />
        <Kpi label="Active" value={rows.isPending ? "–" : items.filter((r) => r.status === "approved").length} sub="Approved and not expired" />
        <Kpi label="Expiring within 30 days" value={rows.isPending ? "–" : soon} tone={soon ? "critical" : undefined} sub="Renew with a plan, or close the gap" />
        <Kpi label="Drafts" value={rows.isPending ? "–" : items.filter((r) => r.status === "draft").length} sub="Not yet submitted" />
      </div>
      <Card bodyClassName="">
        {rows.isPending ? <SkeletonRows rows={6} /> : rows.isError ? <div className="p-4"><LoadError error={rows.error} /></div> : (
          <DataTable
            data={data}
            columns={cols}
            label="exceptions"
            searchPlaceholder="Search exceptions…"
            facets={[
              { column: "status", title: "Status", label: (v) => EXCEPTION_STATUS[v]?.label ?? v },
              { column: "priority", title: "Residual risk" },
              { column: "app", title: "Application" },
            ]}
            initialSort={[{ id: "expires", desc: false }]}
            rowHref={(r) => `/exceptions/${r.exception_key}`}
            toolbar={
              <label className="flex items-center gap-1.5 text-xs text-ink-2">
                <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} className="size-3.5 accent-[var(--accent)]" />
                Include closed
              </label>
            }
            csv={{ filename: "exceptions.csv", row: (r) => ({ exception: r.exception_key, application: r.app_key, target_type: r.target_type, target: r.target_ref, residual_priority: r.residual_priority, status: r.status, expires_at: r.expires_at ?? "" }) }}
            empty={<EmptyState icon={ShieldOff} title={all ? "No exceptions" : "No open exceptions"}>Every gap is either closed or still being worked on.</EmptyState>}
          />
        )}
      </Card>
    </>
  );
}

function NewException() {
  const [q] = useSearchParams();
  const navigate = useNavigate();
  const [form, setForm] = useState<ExceptionCreate>({
    application: q.get("app") ?? "", target_type: (q.get("type") as ExceptionCreate["target_type"]) ?? "control",
    target_ref: q.get("ref") ?? "", justification: "", risk_description: "", residual_priority: "P3",
    compensating_controls: "", remediation_plan: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof ExceptionCreate) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      const x = await api.createException({ ...form, compensating_controls: form.compensating_controls || undefined, requested_expiry: form.requested_expiry || undefined });
      void navigate(`/exceptions/${x.exception_key}`);
    } catch (err) { setError(errorText(err)); } finally { setBusy(false); }
  };
  const area = (k: keyof ExceptionCreate, label: string, hint: string, optional = false) => (
    <Field id={k} label={label} hint={hint} optional={optional}>
      <textarea id={k} rows={3} required={!optional} minLength={optional ? 0 : 20} value={String(form[k] ?? "")} onChange={set(k)} className={textareaClass} />
    </Field>
  );
  return (
    <>
      <PageHeader crumbs={[{ label: "Exceptions", to: "/exceptions" }, { label: "Request" }]} title="Request an exception" description="You create a draft first and can review it before submitting it for a decision." />
      <form onSubmit={submit} className="grid items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="The gap and the risk">
          <div className="grid gap-4">
            <div className="grid gap-4 md:grid-cols-3">
              <Field id="app" label="Application"><input id="app" required value={form.application} onChange={set("application")} placeholder="APP-00001" className={inputClass} /></Field>
              <Field id="target_type" label="It covers">
                <select id="target_type" value={form.target_type} onChange={set("target_type")} className={selectClass}>
                  <option value="control">A control</option><option value="finding">A finding</option>
                  <option value="requirement">A requirement</option><option value="sla">A remediation deadline</option>
                </select>
              </Field>
              <Field id="target_ref" label="Which one"><input id="target_ref" required value={form.target_ref} onChange={set("target_ref")} placeholder="ASC-SRC-01 or a finding id" className={inputClass} /></Field>
            </div>
            {area("justification", "Justification", "Why the gap can't be closed now (at least 20 characters)")}
            {area("risk_description", "Risk", "What could happen while the exception is open")}
            {area("compensating_controls", "Compensating controls", "What reduces the risk in the meantime", true)}
            {area("remediation_plan", "Remediation plan", "How and when the gap will be closed")}
          </div>
        </Card>
        <Card title="Decision">
          <div className="grid gap-4">
            <Field id="prio" label="Residual risk" hint="The risk left after compensating controls. It decides who must approve and for how long.">
              <select id="prio" value={form.residual_priority} onChange={set("residual_priority")} className={selectClass}>
                {(["P1", "P2", "P3", "P4"] as Priority[]).map((p) => <option key={p}>{p}</option>)}
              </select>
            </Field>
            <Field id="exp" label="Requested expiry" optional hint="The approver sets the final date, within the policy maximum.">
              <input id="exp" type="date" value={form.requested_expiry ?? ""} onChange={set("requested_expiry")} className={inputClass} />
            </Field>
            {error && <Notice tone="error" title="Not created">{error}</Notice>}
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : "Create draft"}</Button>
          </div>
        </Card>
      </form>
    </>
  );
}

/** Draft → submitted → (business owner co-sign) → decision → expiry, with where this exception is now. */
function Progress({ e }: { e: SecurityException }) {
  const done = (s: string) => e.events.some((ev) => ev.type === s);
  const steps: { label: string; state: "done" | "now" | "todo" | "stop"; note?: string }[] = [
    { label: "Drafted", state: "done", note: e.requested_by ?? undefined },
    { label: "Submitted", state: e.status === "draft" ? "now" : "done" },
  ];
  if (e.business_owner_cosign_required) steps.push({ label: "Business owner co-signs", state: e.cosigned ? "done" : e.status === "pending_approval" ? "now" : "todo" });
  const decided = ["approved", "rejected", "expired", "revoked", "closed"].includes(e.status);
  steps.push({
    label: e.status === "rejected" ? "Rejected" : "Approved",
    state: e.status === "rejected" ? "stop" : decided ? "done" : e.status === "pending_approval" && (!e.business_owner_cosign_required || e.cosigned) ? "now" : "todo",
    note: e.approver ? `${e.approver} · ${day(e.approved_at)}` : `${approver(e.required_approver_role)} or above`,
  });
  if (e.status !== "rejected") {
    steps.push({
      label: e.status === "revoked" ? "Revoked" : e.status === "expired" || done("expired") ? "Expired" : "Expires",
      state: e.status === "revoked" ? "stop" : ["expired", "closed"].includes(e.status) ? "done" : "todo",
      note: e.expires_at ? day(e.expires_at) : `at most ${e.max_days} days after approval`,
    });
  }
  return (
    <ol className="plain m-0 p-0" aria-label="Approval progress">
      {steps.map((s, i) => (
        <li key={s.label} className="relative flex gap-3 pb-4 last:pb-0">
          {i < steps.length - 1 && <span aria-hidden="true" className="absolute left-[9px] top-6 h-[calc(100%-1.5rem)] w-px bg-line" />}
          <span className={`mt-0.5 flex size-[19px] shrink-0 items-center justify-center rounded-full border ${s.state === "done" ? "border-good/50 text-good" : s.state === "now" ? "border-accent text-accent" : s.state === "stop" ? "border-critical/50 text-critical" : "border-line text-muted"}`}>
            {s.state === "done" ? <CheckCircle2 className="size-3" aria-label="done" /> : s.state === "stop" ? <XCircle className="size-3" aria-label="stopped" /> : s.state === "now" ? <Hourglass className="size-3" aria-label="current step" /> : <span role="img" className="size-1.5 rounded-full bg-current" aria-label="not yet" />}
          </span>
          <div className="min-w-0">
            <div className={`text-[13px] ${s.state === "todo" ? "text-ink-2" : "font-medium text-ink"}`}>{s.label}</div>
            {s.note && <div className="text-xs text-muted">{s.note}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

function ExceptionDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const x = useQuery({ queryKey: ["exception", id], queryFn: () => api.exception(id) });
  if (x.isPending) return <SkeletonRows rows={8} />;
  if (x.isError) return <><PageHeader crumbs={[{ label: "Exceptions", to: "/exceptions" }, { label: id }]} title={id} /><LoadError error={x.error} /></>;
  const e = x.data;
  const d = daysLeft(e.expires_at);
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["exception", id] }); void qc.invalidateQueries({ queryKey: ["exceptions"] }); };
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Exceptions", to: "/exceptions" }, { label: e.exception_key }]}
        title={<span className="font-mono">{e.exception_key}</span>}
        meta={<><ExceptionStatus status={e.status} /><PriorityChip p={e.residual_priority} /><span>·</span><Link to={`/apps/${e.app_key}`}>{e.app_key}</Link>
          {e.status === "approved" && d !== null && <><span>·</span><span>{d < 0 ? "past its expiry" : `expires in ${d} day${d === 1 ? "" : "s"}`}</span></>}</>}
      />
      <div className="grid items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="What is accepted">
          <Facts items={[
            ["Covers", e.target_type === "finding"
              ? <Link to={`/findings/${e.target_ref}`}>Finding {e.target_ref.slice(0, 8)}…</Link>
              : e.target_type === "control" ? <Link to={`/controls/${e.target_ref}`} className="font-mono">{e.target_ref}</Link>
                : <>{TARGET[e.target_type] ?? e.target_type} <span className="font-mono">{e.target_ref}</span></>],
            ["Justification", e.justification],
            ["Risk", e.risk_description],
            ["Compensating controls", e.compensating_controls ?? <span className="text-muted">None</span>],
            ["Remediation plan", e.remediation_plan],
            ["Maximum duration", `${e.max_days} days`],
          ]} />
        </Card>
        <div className="space-y-4">
          <Card title="Approval"><Progress e={e} /></Card>
          <Card title="Actions"><ExceptionActions e={e} onDone={refresh} /></Card>
          <Card title="History">
            <ol className="plain m-0 space-y-2.5 p-0">
              {e.events.map((ev, i) => (
                <li key={i} className="text-[13px]">
                  <span className="font-medium text-ink">{ev.type.replaceAll("_", " ")}</span>
                  <div className="text-xs text-muted">{ev.actor} · {day(ev.at, true)}</div>
                  {typeof ev.details?.comment === "string" && ev.details.comment && <div className="mt-0.5 text-xs text-ink-2">“{ev.details.comment}”</div>}
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>
    </>
  );
}

function ExceptionActions({ e, onDone }: { e: SecurityException; onDone: () => void }) {
  const navigate = useNavigate();
  const [comment, setComment] = useState("");
  const [expiry, setExpiry] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const run = async (action: "submit" | "cosign" | "decision" | "revoke" | "renewals", body?: unknown, ok = "Done") => {
    setMsg(null);
    try {
      const out = await api.exceptionAction(e.id, action, body);
      setComment("");
      if (action === "renewals") { void navigate(`/exceptions/${out.exception_key}`); return; }
      setMsg({ ok: true, text: ok });
      onDone();
    } catch (err) { setMsg({ ok: false, text: errorText(err) }); }
  };
  const feedback = msg && <p className={`m-0 mt-2 text-xs ${msg.ok ? "text-good-ink" : "text-critical-ink"}`} role={msg.ok ? "status" : "alert"}>{msg.text}</p>;
  if (e.status === "draft") {
    return <><Button variant="primary" onClick={() => void run("submit", undefined, "Submitted for a decision")}>Submit for approval</Button>
      <p className="m-0 mt-2 text-xs text-muted">Only the requester can submit. After that, nobody can edit it.</p>{feedback}</>;
  }
  if (e.status === "approved") {
    return (
      <div className="space-y-3">
        <Button onClick={() => void run("renewals", { justification: e.justification, remediation_plan: e.remediation_plan })}>Draft a renewal</Button>
        <Field id="revoke-reason" label="Reason to revoke"><input id="revoke-reason" value={comment} onChange={(ev) => setComment(ev.target.value)} className={inputClass} /></Field>
        <Button variant="danger" disabled={!comment.trim()} onClick={() => void run("revoke", { reason: comment }, "Revoked")}>Revoke</Button>
        {feedback}
      </div>
    );
  }
  if (e.status === "pending_approval" && (e.can_cosign || e.can_decide)) {
    return (
      <div className="space-y-3">
        {e.can_cosign && !e.cosigned && <Button variant="primary" onClick={() => void run("cosign", undefined, "Co-signed")}>Co-sign as business owner</Button>}
        {e.can_decide && (
          <>
            <Field id="decision-comment" label="Decision comment" hint="Recorded with the decision"><textarea id="decision-comment" rows={2} value={comment} onChange={(ev) => setComment(ev.target.value)} className={textareaClass} /></Field>
            <Field id="decision-expiry" label="Expires" optional hint={`At most ${e.max_days} days`}><input id="decision-expiry" type="date" value={expiry} onChange={(ev) => setExpiry(ev.target.value)} className={inputClass} /></Field>
            <div className="flex gap-2">
              <Button variant="primary" onClick={() => void run("decision", { outcome: "approve", comment, expires_at: expiry || undefined }, "Approved")}>Approve</Button>
              <Button onClick={() => void run("decision", { outcome: "reject", comment }, "Rejected")}>Reject</Button>
            </div>
          </>
        )}
        {feedback}
      </div>
    );
  }
  return <p className="m-0 text-[13px] text-muted">Nothing for you to do on this exception.</p>;
}
