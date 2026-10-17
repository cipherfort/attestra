// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ApiError, api, type Assessment } from "../api";
import { date, Loadable, useLoad } from "../components/ui";
import { hashQuery } from "./Exceptions";

export const KINDS: Record<string, { label: string; fields: [string, string][] }> = {
  manual_control: { label: "Manual control attestation", fields: [["control_key", "Control (e.g. ASC-REQ-03)"],
    ["outcome", "Outcome: pass or fail"], ["method", "How it was verified"], ["asvs_verified", "ASVS ids verified (comma-separated, optional)"]] },
  threat_model_review: { label: "Threat model review", fields: [["model_commit", "Commit SHA of the reviewed threat model"],
    ["outcome", "approved, approved_with_conditions or rejected"]] },
  architecture_review: { label: "Architecture review", fields: [["outcome", "approved, approved_with_conditions or rejected"],
    ["findings_summary", "Conditions or findings (optional)"]] },
  pentest: { label: "Penetration test", fields: [["tester", "Tester or company"], ["report_sha256", "SHA-256 of the report"],
    ["outcome", "approved, approved_with_conditions or rejected"], ["findings_summary", "Summary (optional)"]] },
  samm_application: { label: "SAMM interview", fields: [["answers", "One per line: STREAM:LEVEL = 0 | 0.25 | 0.5 | 1 (e.g. D-TA-A:1 = 0.5)"]] },
};

const STATUS: Record<string, string> = {
  planned: "Planned", in_progress: "In progress", submitted: "Waiting for review", approved: "Approved",
  rejected: "Rejected", cancelled: "Cancelled",
};

function message(e: unknown): string {
  return e instanceof ApiError ? `${e.title}: ${e.detail ?? ""}` : String(e);
}

function toScope(kind: string, values: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(values)) {
    if (!v.trim()) continue;
    if (k === "asvs_verified") out[k] = v.split(",").map((x) => x.trim()).filter(Boolean);
    else if (k === "answers") out[k] = Object.fromEntries(v.split("\n").map((l) => l.split("=").map((x) => x.trim()))
      .filter((p) => p.length === 2 && p[0]).map(([key, val]) => [key, Number(val)]));
    else out[k] = v.trim();
  }
  return kind ? out : {};
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
  if (id?.startsWith("new")) return <NewAssessment />;
  if (id) return <AssessmentDetail id={id} />;
  return <AssessmentList />;
}

function AssessmentList() {
  const items = useLoad(() => api.assessments(), []);
  return (
    <>
      <h1>Assessments</h1>
      <p className="muted">Manual evidence: what a person verified when no tool can. A review by someone outside the owning team counts as M2 (independent); otherwise M1.</p>
      <div className="card">
        <Loadable state={items}>
          {(rows) => rows.length === 0 ? <div className="muted">No assessments yet. Start one from an application page.</div> : (
            <table>
              <thead><tr><th>Assessment</th><th>Application</th><th>Lead</th><th>Status</th><th>Confidence</th></tr></thead>
              <tbody>{rows.map((r) => (
                <tr key={r.id} className="clickable" onClick={() => { window.location.hash = `#/assessments/${r.id}`; }}>
                  <td><a href={`#/assessments/${r.id}`}>{KINDS[r.type]?.label ?? r.type}</a></td>
                  <td className="small">{r.app_key} · {r.application_name}</td><td className="small">{r.lead_assessor}</td>
                  <td className="small">{STATUS[r.status] ?? r.status}</td><td className="small">{r.confidence ?? "—"}</td>
                </tr>))}
              </tbody>
            </table>
          )}
        </Loadable>
      </div>
    </>
  );
}

function NewAssessment() {
  const q = hashQuery();
  const [kind, setKind] = useState(q.get("type") ?? "manual_control");
  const [app, setApp] = useState(q.get("app") ?? "");
  const [error, setError] = useState<string | null>(null);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const a = await api.createAssessment({ type: kind, application: app });
      window.location.hash = `#/assessments/${a.id}`;
    } catch (err) { setError(message(err)); }
  };
  return (
    <>
      <p className="small"><a href="#/assessments">← Assessments</a></p>
      <h1>Start an assessment</h1>
      <form className="card" onSubmit={create}>
        <dl className="kv">
          <dt>Application</dt><dd><input required value={app} onChange={(e) => setApp(e.target.value)} placeholder="APP-00001" /></dd>
          <dt>Type</dt><dd><select value={kind} onChange={(e) => setKind(e.target.value)}>
            {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select></dd>
        </dl>
        {error && <p className="notice error">{error}</p>}
        <p><button type="submit">Start</button> <span className="small muted">You become the lead assessor; someone else reviews it.</span></p>
      </form>
    </>
  );
}

function AssessmentDetail({ id }: { id: string }) {
  const [tick, setTick] = useState(0);
  const a = useLoad(() => api.assessment(id), [id, tick]);
  return (
    <Loadable state={a}>
      {(s) => <AssessmentBody s={s} onDone={() => setTick((t) => t + 1)} />}
    </Loadable>
  );
}

function AssessmentBody({ s, onDone }: { s: Assessment; onDone: () => void }) {
  const [values, setValues] = useState<Record<string, string>>(fromScope(s.scope));
  const [comment, setComment] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const kind = KINDS[s.type];
  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg(null);
    try { await fn(); setMsg({ ok: true, text: ok }); onDone(); } catch (err) { setMsg({ ok: false, text: message(err) }); }
  };
  return (
    <>
      <p className="small"><a href="#/assessments">← Assessments</a></p>
      <div className="row"><h1>{kind?.label ?? s.type}</h1>
        <span className="muted">{STATUS[s.status] ?? s.status} · <a href={`#/apps/${s.app_key}`}>{s.app_key}</a> · lead {s.lead_assessor}</span></div>
      <div className="card">
        <dl className="kv">
          {kind?.fields.map(([k, label]) => (
            <span key={k} style={{ display: "contents" }}>
              <dt><label htmlFor={k}>{label}</label></dt>
              <dd>{s.can_record
                ? <textarea id={k} rows={k === "answers" ? 8 : 2} value={values[k] ?? ""} spellCheck={false}
                    onChange={(e) => setValues({ ...values, [k]: e.target.value })} style={{ width: "100%" }} />
                : <span>{values[k] || <span className="muted">—</span>}</span>}</dd>
            </span>
          ))}
          {s.approved_by && <><dt>Reviewed by</dt><dd>{s.approved_by} · {date(s.approved_at)}
            {typeof s.scope?.confidence === "string" && <> · {s.scope.confidence === "M2" ? "M2 (independent)" : "M1 (owning team)"}</>}</dd></>}
          {s.evidence_id && <><dt>Evidence</dt><dd><a href={`#/evidence/${s.evidence_id}`}>view the evidence record</a></dd></>}
        </dl>
        {s.can_record && (
          <p className="row">
            <button className="secondary" onClick={() => void run(() => api.recordAssessment(s.id, toScope(s.type, values)), "saved")}>Save</button>
            <button onClick={() => void run(async () => {
              await api.recordAssessment(s.id, toScope(s.type, values));
              await api.assessmentAction(s.id, "submit");
            }, "submitted for review")}>Submit for review</button>
          </p>
        )}
        {s.can_decide && (
          <>
            <p><textarea rows={2} placeholder="Review comment (recorded)" value={comment} onChange={(e) => setComment(e.target.value)} style={{ width: "100%" }} /></p>
            <p className="row">
              <button onClick={() => void run(() => api.assessmentAction(s.id, "decision", { outcome: "approve", comment }), "approved")}>Approve</button>
              <button className="secondary" onClick={() => void run(() => api.assessmentAction(s.id, "decision", { outcome: "reject", comment }), "rejected")}>Reject</button>
            </p>
          </>
        )}
        {msg && <p className={msg.ok ? "ok" : "error"}>{msg.text}</p>}
      </div>
    </>
  );
}
