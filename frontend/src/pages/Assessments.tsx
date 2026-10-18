// SPDX-License-Identifier: Apache-2.0
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, CircleDashed, ClipboardCheck, Hourglass, Plus, XCircle, type LucideIcon } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, type Assessment, type AssessmentRow } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { ConfidenceBadge } from "../components/domain/badges";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Facts, Field, LoadError, Notice, errorText, inputClass, selectClass, textareaClass } from "../components/ui/Form";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { useMe } from "../hooks/useMe";

type Input = { key: string; label: string; hint?: string; type: "text" | "outcome" | "pass" | "list" | "long" | "answers"; optional?: boolean };
const REVIEW: Input = { key: "outcome", label: "Outcome", type: "outcome" };

export const KINDS: Record<string, { label: string; about: string; fields: Input[] }> = {
  manual_control: {
    label: "Manual control attestation",
    about: "A person verifies a control that no tool can check.",
    fields: [
      { key: "control_key", label: "Control", hint: "For example ASC-REQ-03", type: "text" },
      { key: "outcome", label: "Outcome", type: "pass" },
      { key: "method", label: "How it was verified", type: "long" },
      { key: "asvs_verified", label: "ASVS requirements verified", hint: "Comma-separated ids", type: "list", optional: true },
    ],
  },
  threat_model_review: {
    label: "Threat model review",
    about: "Review of the threat model kept in the repository, pinned to a commit.",
    fields: [{ key: "model_commit", label: "Commit of the reviewed threat model", hint: "Full SHA", type: "text" }, REVIEW],
  },
  architecture_review: {
    label: "Architecture review",
    about: "Security review of the design.",
    fields: [REVIEW, { key: "findings_summary", label: "Conditions or findings", type: "long", optional: true }],
  },
  pentest: {
    label: "Penetration test",
    about: "An external or internal test; the report is pinned by its hash.",
    fields: [
      { key: "tester", label: "Tester or company", type: "text" },
      { key: "report_sha256", label: "SHA-256 of the report", type: "text" },
      REVIEW,
      { key: "findings_summary", label: "Summary", type: "long", optional: true },
    ],
  },
  samm_application: {
    label: "SAMM interview",
    about: "OWASP SAMM questions answered for the application.",
    fields: [{ key: "answers", label: "Answers", hint: "One per line: STREAM:LEVEL = 0, 0.25, 0.5 or 1 (for example D-TA-A:1 = 0.5)", type: "answers" }],
  },
};

const STATUS: Record<string, { label: string; icon: LucideIcon; tone: string }> = {
  planned: { label: "Planned", icon: CircleDashed, tone: "text-muted" },
  in_progress: { label: "In progress", icon: CircleDashed, tone: "text-accent" },
  submitted: { label: "Waiting for review", icon: Hourglass, tone: "text-warning" },
  approved: { label: "Approved", icon: CheckCircle2, tone: "text-good" },
  rejected: { label: "Rejected", icon: XCircle, tone: "text-critical" },
  cancelled: { label: "Cancelled", icon: XCircle, tone: "text-muted" },
};

function Status({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, icon: CircleDashed, tone: "text-muted" };
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink">
      <s.icon className={`size-3.5 ${s.tone}`} aria-hidden="true" />{s.label}
    </span>
  );
}

const day = (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "–");

function toScope(values: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(values)) {
    if (!v.trim()) continue;
    if (k === "asvs_verified") out[k] = v.split(",").map((x) => x.trim()).filter(Boolean);
    else if (k === "answers") {
      out[k] = Object.fromEntries(v.split("\n").map((l) => l.split("=").map((x) => x.trim()))
        .filter((p) => p.length === 2 && p[0]).map(([key, val]) => [key, Number(val)]));
    } else out[k] = v.trim();
  }
  return out;
}

function fromScope(scope: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(scope ?? {})) {
    if (k === "answers" && v && typeof v === "object") out[k] = Object.entries(v).map(([a, b]) => `${a} = ${b}`).join("\n");
    else if (Array.isArray(v)) out[k] = v.join(", ");
    else if (typeof v === "string") out[k] = v;
  }
  return out;
}

export function Assessments({ id }: { id?: string }) {
  if (id === "new") return <NewAssessment />;
  if (id) return <AssessmentDetail key={id} id={id} />;
  return <AssessmentList />;
}

function AssessmentList() {
  const me = useMe();
  const canCreate = (me.data?.permissions ?? []).includes("assessment.create");
  const rows = useQuery({ queryKey: ["assessments"], queryFn: () => api.assessments() });
  const items = rows.data ?? [];
  const count = (s: string) => (rows.isPending ? "–" : items.filter((r) => r.status === s).length);
  const cols: ColumnDef<AssessmentRow, unknown>[] = [
    { id: "type", header: "Assessment", accessorFn: (r) => KINDS[r.type]?.label ?? r.type, filterFn: inSet<AssessmentRow>(), cell: ({ row: { original: r } }) => (
      <Link to={`/assessments/${r.id}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{KINDS[r.type]?.label ?? r.type}</Link>
    ) },
    { id: "app", header: "Application", accessorKey: "application_name", filterFn: inSet<AssessmentRow>(), cell: ({ row: { original: r } }) => <Link to={`/apps/${r.app_key}`} className="text-ink-2 hover:text-accent-ink">{r.application_name}</Link> },
    { id: "lead", header: "Lead assessor", accessorFn: (r) => r.lead_assessor ?? "", cell: ({ getValue }) => <span className="text-ink-2">{String(getValue()) || "–"}</span> },
    { id: "status", header: "Status", accessorKey: "status", filterFn: inSet<AssessmentRow>(), cell: ({ getValue }) => <Status status={String(getValue())} /> },
    { id: "confidence", header: "Counts as", accessorFn: (r) => r.confidence ?? "", cell: ({ getValue }) => (getValue() ? <ConfidenceBadge level={String(getValue())} /> : <span className="text-muted">–</span>) },
    { id: "approved", header: "Approved", accessorFn: (r) => r.approved_at ?? "", cell: ({ row: { original: r } }) => <span className="text-ink-2">{day(r.approved_at)}</span> },
  ];
  return (
    <>
      <PageHeader
        title="Assessments"
        description="What a person verified when no tool can. A review by someone outside the owning team counts as M2 (independent); otherwise M1."
        actions={canCreate && <ButtonLink to="/assessments/new" variant="primary"><Plus className="size-4" aria-hidden="true" />Start an assessment</ButtonLink>}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Kpi label="In progress" value={count("in_progress")} sub="Being recorded by the lead assessor" />
        <Kpi label="Waiting for review" value={count("submitted")} sub="Someone else must approve it" />
        <Kpi label="Approved" value={count("approved")} sub="Recorded as evidence" />
        <Kpi label="Independent (M2)" value={rows.isPending ? "–" : items.filter((r) => r.confidence === "M2").length} sub="Reviewed outside the owning team" />
      </div>
      <Card bodyClassName="">
        {rows.isPending ? <SkeletonRows rows={6} /> : rows.isError ? <div className="p-4"><LoadError error={rows.error} /></div> : (
          <DataTable
            data={items}
            columns={cols}
            label="assessments"
            searchPlaceholder="Search assessments…"
            facets={[{ column: "type", title: "Type" }, { column: "status", title: "Status", label: (v) => STATUS[v]?.label ?? v }, { column: "app", title: "Application" }]}
            initialSort={[{ id: "approved", desc: true }]}
            rowHref={(r) => `/assessments/${r.id}`}
            empty={<EmptyState icon={ClipboardCheck} title="No assessments yet">Start one from an application page, or with the button above.</EmptyState>}
          />
        )}
      </Card>
    </>
  );
}

function NewAssessment() {
  const [q] = useSearchParams();
  const navigate = useNavigate();
  const [kind, setKind] = useState(q.get("type") ?? "manual_control");
  const [app, setApp] = useState(q.get("app") ?? "");
  const [error, setError] = useState<string | null>(null);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const a = await api.createAssessment({ type: kind, application: app });
      void navigate(`/assessments/${a.id}`);
    } catch (err) { setError(errorText(err)); }
  };
  return (
    <>
      <PageHeader crumbs={[{ label: "Assessments", to: "/assessments" }, { label: "Start" }]} title="Start an assessment" description="You become the lead assessor. Someone else reviews it before it counts as evidence." />
      <Card className="max-w-2xl">
        <form onSubmit={create} className="grid gap-4">
          <Field id="app" label="Application"><input id="app" required value={app} onChange={(e) => setApp(e.target.value)} placeholder="APP-00001" className={inputClass} /></Field>
          <fieldset className="m-0 border-0 p-0">
            <legend className="mb-2 text-xs font-medium text-ink-2">Type</legend>
            <div className="grid gap-2 md:grid-cols-2">
              {Object.entries(KINDS).map(([k, v]) => (
                <label key={k} className={`flex cursor-pointer gap-2.5 rounded-lg border p-3 text-[13px] ${kind === k ? "border-accent bg-accent-soft" : "border-line bg-surface-2 hover:border-line-strong"}`}>
                  <input type="radio" name="kind" value={k} checked={kind === k} onChange={() => setKind(k)} className="mt-0.5 accent-[var(--accent)]" />
                  <span><span className="block font-medium text-ink">{v.label}</span><span className={`text-xs ${kind === k ? "text-ink-2" : "text-muted"}`}>{v.about}</span></span>
                </label>
              ))}
            </div>
          </fieldset>
          {error && <Notice tone="error" title="Not started">{error}</Notice>}
          <div><Button type="submit" variant="primary">Start</Button></div>
        </form>
      </Card>
    </>
  );
}

function AssessmentDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const a = useQuery({ queryKey: ["assessment", id], queryFn: () => api.assessment(id) });
  if (a.isPending) return <SkeletonRows rows={8} />;
  if (a.isError) return <><PageHeader crumbs={[{ label: "Assessments", to: "/assessments" }, { label: "Assessment" }]} title="Assessment" /><LoadError error={a.error} /></>;
  return <AssessmentBody s={a.data} onDone={() => { void qc.invalidateQueries({ queryKey: ["assessment", id] }); void qc.invalidateQueries({ queryKey: ["assessments"] }); }} />;
}

const CHOICES: Record<string, string> = {
  pass: "Pass", fail: "Fail", approved: "Approved", approved_with_conditions: "Approved with conditions", rejected: "Rejected",
};
const mono = (f: Input) => f.key.includes("sha") || f.key.includes("commit") || f.type === "answers";

function Control({ f, value, onChange, disabled }: { f: Input; value: string; onChange: (v: string) => void; disabled: boolean }) {
  const common = { id: `f-${f.key}`, value, disabled, onChange: (e: { target: { value: string } }) => onChange(e.target.value) };
  if (f.type === "outcome" || f.type === "pass") {
    const opts = f.type === "pass" ? [["pass", "Pass"], ["fail", "Fail"]] : [["approved", "Approved"], ["approved_with_conditions", "Approved with conditions"], ["rejected", "Rejected"]];
    return <select {...common} className={selectClass}><option value="">Choose…</option>{opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>;
  }
  if (f.type === "long" || f.type === "answers") return <textarea {...common} rows={f.type === "answers" ? 10 : 3} spellCheck={f.type !== "answers"} className={`${textareaClass} ${f.type === "answers" ? "font-mono" : ""}`} />;
  return <input {...common} spellCheck={false} className={`${inputClass} ${mono(f) ? "font-mono" : ""}`} />;
}

function AssessmentBody({ s, onDone }: { s: Assessment; onDone: () => void }) {
  const [values, setValues] = useState<Record<string, string>>(fromScope(s.scope));
  const [comment, setComment] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const kind = KINDS[s.type];
  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg(null);
    try { await fn(); setMsg({ ok: true, text: ok }); onDone(); } catch (err) { setMsg({ ok: false, text: errorText(err) }); }
  };
  const confidence = typeof s.scope?.confidence === "string" ? s.scope.confidence : null;
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Assessments", to: "/assessments" }, { label: kind?.label ?? s.type }]}
        title={kind?.label ?? s.type}
        meta={<><Status status={s.status} /><span>·</span><Link to={`/apps/${s.app_key}`}>{s.app_key}</Link><span>·</span><span>lead {s.lead_assessor ?? "–"}</span></>}
      />
      <div className="grid items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title={s.can_record ? "Record what was verified" : "What was verified"} description={kind?.about}>
          <div className="grid gap-4">
            {kind?.fields.map((f) => (
              <Field key={f.key} id={`f-${f.key}`} label={f.label} hint={s.can_record ? f.hint : undefined} optional={f.optional}>
                {s.can_record
                  ? <Control f={f} value={values[f.key] ?? ""} onChange={(v) => setValues({ ...values, [f.key]: v })} disabled={false} />
                  : <div id={`f-${f.key}`} className={`whitespace-pre-line break-all text-[13px] text-ink ${mono(f) ? "font-mono text-xs" : ""}`}>{values[f.key] ? CHOICES[values[f.key]!] ?? values[f.key] : <span className="text-muted">–</span>}</div>}
              </Field>
            ))}
            {s.can_record && (
              <div className="flex gap-2">
                <Button onClick={() => void run(() => api.recordAssessment(s.id, toScope(values)), "Saved")}>Save</Button>
                <Button variant="primary" onClick={() => void run(async () => { await api.recordAssessment(s.id, toScope(values)); await api.assessmentAction(s.id, "submit"); }, "Submitted for review")}>Submit for review</Button>
              </div>
            )}
          </div>
        </Card>
        <div className="space-y-4">
          <Card title="Review">
            <Facts items={[
              ["Status", <Status key="s" status={s.status} />],
              ["Reviewed by", s.approved_by ? `${s.approved_by} · ${day(s.approved_at)}` : <span className="text-muted">Not yet</span>],
              ["Counts as", confidence ? <span className="inline-flex items-center gap-2"><ConfidenceBadge level={confidence} />{confidence === "M2" ? "independent" : "owning team"}</span> : <span className="text-muted">Decided at approval</span>],
              ...(s.evidence_id ? [["Evidence", <Link key="e" to={`/evidence/${s.evidence_id}`}>View the evidence record</Link>] as [string, React.ReactNode]] : []),
            ]} />
          </Card>
          {s.can_decide && (
            <Card title="Decide">
              <div className="grid gap-3">
                <Field id="review-comment" label="Review comment" hint="Recorded with the decision"><textarea id="review-comment" rows={3} value={comment} onChange={(e) => setComment(e.target.value)} className={textareaClass} /></Field>
                <div className="flex gap-2">
                  <Button variant="primary" onClick={() => void run(() => api.assessmentAction(s.id, "decision", { outcome: "approve", comment }), "Approved")}>Approve</Button>
                  <Button onClick={() => void run(() => api.assessmentAction(s.id, "decision", { outcome: "reject", comment }), "Rejected")}>Reject</Button>
                </div>
              </div>
            </Card>
          )}
          {msg && <Notice tone={msg.ok ? "success" : "error"}>{msg.text}</Notice>}
        </div>
      </div>
    </>
  );
}
