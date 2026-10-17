// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ApiError, api, type ExceptionCreate, type Priority, type SecurityException } from "../api";
import { date, Loadable, PriorityChip, useLoad } from "../components/ui";

const STATUS: Record<string, string> = {
  draft: "Draft", pending_approval: "Waiting for a decision", approved: "Approved", rejected: "Rejected",
  expired: "Expired", revoked: "Revoked", closed: "Replaced by a renewal",
};

/** Query string after the hash route, e.g. #/exceptions/new?app=APP-00001&type=control&ref=ASC-SRC-01 */
export function hashQuery(): URLSearchParams {
  const q = window.location.hash.split("?")[1] ?? "";
  return new URLSearchParams(q);
}

function message(e: unknown): string {
  return e instanceof ApiError ? `${e.title}: ${e.detail ?? ""}` : String(e);
}

export function Exceptions({ id }: { id?: string }) {
  if (id?.startsWith("new")) return <NewException />;
  if (id) return <ExceptionDetail id={id} />;
  return <ExceptionList />;
}

function ExceptionList() {
  const items = useLoad(() => api.exceptions(), []);
  const [filter, setFilter] = useState("open");
  return (
    <>
      <h1>Exceptions</h1>
      <p className="muted">
        A time-bound, approved acceptance of a known gap. The approver role depends on the residual priority and the
        application's tier; the requester, the technical owner and the owning team can never approve their own.
      </p>
      <div className="row small">
        <label>Show <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="open">Open (draft, waiting, approved)</option><option value="all">All</option>
        </select></label>
      </div>
      <div className="card">
        <Loadable state={items}>
          {(rows) => {
            const shown = rows.filter((r) => filter === "all" || ["draft", "pending_approval", "approved"].includes(r.status));
            return shown.length === 0 ? <div className="muted">No exceptions.</div> : (
              <table>
                <thead><tr><th>Exception</th><th>Application</th><th>Target</th><th>Residual</th><th>Status</th><th>Expires</th></tr></thead>
                <tbody>
                  {shown.map((r) => (
                    <tr key={r.id} className="clickable" onClick={() => { window.location.hash = `#/exceptions/${r.exception_key}`; }}>
                      <td><a href={`#/exceptions/${r.exception_key}`}>{r.exception_key}</a><div className="muted small">by {r.requested_by}</div></td>
                      <td className="small">{r.app_key} · {r.application_name}</td>
                      <td className="small">{r.target_type} <span className="mono">{r.target_ref.slice(0, 18)}</span></td>
                      <td><PriorityChip p={r.residual_priority} /></td>
                      <td className="small">{STATUS[r.status] ?? r.status}</td>
                      <td className="small">{date(r.expires_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            );
          }}
        </Loadable>
      </div>
    </>
  );
}

function NewException() {
  const q = hashQuery();
  const [form, setForm] = useState<ExceptionCreate>({
    application: q.get("app") ?? "", target_type: (q.get("type") as ExceptionCreate["target_type"]) ?? "control",
    target_ref: q.get("ref") ?? "", justification: "", risk_description: "", residual_priority: "P3",
    compensating_controls: "", remediation_plan: "",
  });
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof ExceptionCreate) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const x = await api.createException({ ...form, compensating_controls: form.compensating_controls || undefined,
        requested_expiry: form.requested_expiry || undefined });
      window.location.hash = `#/exceptions/${x.exception_key}`;
    } catch (err) { setError(message(err)); }
  };
  const area = (k: keyof ExceptionCreate, label: string, hint: string) => (
    <>
      <dt><label htmlFor={k}>{label}</label></dt>
      <dd><textarea id={k} rows={3} required={k !== "compensating_controls"} minLength={k === "compensating_controls" ? 0 : 20}
        value={String(form[k] ?? "")} onChange={set(k)} style={{ width: "100%" }} /><div className="small muted">{hint}</div></dd>
    </>
  );
  return (
    <>
      <p className="small"><a href="#/exceptions">← Exceptions</a></p>
      <h1>Request an exception</h1>
      <form className="card" onSubmit={submit}>
        <dl className="kv">
          <dt><label htmlFor="app">Application</label></dt>
          <dd><input id="app" required value={form.application} onChange={set("application")} placeholder="APP-00001" /></dd>
          <dt>What it covers</dt>
          <dd className="row">
            <select value={form.target_type} onChange={set("target_type")}>
              <option value="control">a control</option><option value="finding">a finding</option>
              <option value="requirement">a requirement</option><option value="sla">a remediation deadline</option>
            </select>
            <input required value={form.target_ref} onChange={set("target_ref")} placeholder="ASC-SRC-01 or a finding id" />
          </dd>
          <dt><label htmlFor="prio">Residual priority</label></dt>
          <dd><select id="prio" value={form.residual_priority} onChange={set("residual_priority")}>
            {(["P1", "P2", "P3", "P4"] as Priority[]).map((p) => <option key={p}>{p}</option>)}
          </select> <span className="small muted">the risk left after compensating controls; it decides who must approve and for how long</span></dd>
          {area("justification", "Justification", "Why the gap cannot be closed now")}
          {area("risk_description", "Risk", "What could happen while the exception is open")}
          {area("compensating_controls", "Compensating controls", "Optional: what reduces the risk meanwhile")}
          {area("remediation_plan", "Remediation plan", "How and when the gap will be closed")}
          <dt><label htmlFor="exp">Requested expiry</label></dt>
          <dd><input id="exp" type="date" value={form.requested_expiry ?? ""} onChange={set("requested_expiry")} />
            <span className="small muted"> optional; the approver sets the final date within the policy maximum</span></dd>
        </dl>
        {error && <p className="notice error" role="alert">{error}</p>}
        <p><button type="submit">Create draft</button> <span className="small muted">You can review the draft before submitting it.</span></p>
      </form>
    </>
  );
}

function ExceptionDetail({ id }: { id: string }) {
  const [tick, setTick] = useState(0);
  const x = useLoad(() => api.exception(id), [id, tick]);
  return (
    <Loadable state={x}>
      {(e) => (
        <>
          <p className="small"><a href="#/exceptions">← Exceptions</a></p>
          <div className="row"><h1>{e.exception_key}</h1><PriorityChip p={e.residual_priority} />
            <span className="muted">{STATUS[e.status] ?? e.status} · <a href={`#/apps/${e.app_key}`}>{e.app_key}</a></span></div>
          <div className="grid two">
            <div className="card">
              <h2>What is accepted</h2>
              <dl className="kv">
                <dt>Covers</dt><dd>{e.target_type} <span className="mono">{e.target_ref}</span></dd>
                <dt>Justification</dt><dd>{e.justification}</dd>
                <dt>Risk</dt><dd>{e.risk_description}</dd>
                <dt>Compensating controls</dt><dd>{e.compensating_controls ?? <span className="muted">none</span>}</dd>
                <dt>Remediation plan</dt><dd>{e.remediation_plan}</dd>
                <dt>Requested by</dt><dd>{e.requested_by}</dd>
                <dt>Approver needed</dt><dd>{e.required_approver_role.replaceAll("_", " ")} or above
                  {e.business_owner_cosign_required && <> · business owner co-sign {e.cosigned ? "✓ given" : "required"}</>}</dd>
                <dt>Maximum duration</dt><dd>{e.max_days} days</dd>
                {e.approver && <><dt>Approved by</dt><dd>{e.approver} · {date(e.approved_at)} · expires {date(e.expires_at)}</dd></>}
              </dl>
            </div>
            <div className="card">
              <h2>Actions</h2>
              <ExceptionActions e={e} onDone={() => setTick((t) => t + 1)} />
              <h3>History</h3>
              <ul className="timeline">
                {e.events.map((ev, i) => (
                  <li key={i}><strong>{ev.type}</strong><span className="muted small"> · {ev.actor} · {date(ev.at, true)}</span>
                    {typeof ev.details?.comment === "string" && <div className="small">“{ev.details.comment}”</div>}</li>
                ))}
              </ul>
            </div>
          </div>
        </>
      )}
    </Loadable>
  );
}

function ExceptionActions({ e, onDone }: { e: SecurityException; onDone: () => void }) {
  const [comment, setComment] = useState("");
  const [expiry, setExpiry] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const run = async (action: "submit" | "cosign" | "decision" | "revoke" | "renewals", body?: unknown) => {
    setMsg(null);
    try {
      const out = await api.exceptionAction(e.id, action, body);
      if (action === "renewals") window.location.hash = `#/exceptions/${out.exception_key}`;
      setComment(""); onDone();
    } catch (err) { setMsg(message(err)); }
  };
  const none = <p className="muted small">Nothing for you to do on this exception.</p>;
  return (
    <div>
      {e.status === "draft" && <p><button onClick={() => void run("submit")}>Submit for approval</button>
        <span className="small muted"> (requester only)</span></p>}
      {e.can_cosign && !e.cosigned && <p><button onClick={() => void run("cosign")}>Co-sign as business owner</button></p>}
      {e.can_decide && (
        <>
          <p><textarea rows={2} placeholder="Decision comment (recorded)" value={comment} onChange={(ev) => setComment(ev.target.value)} style={{ width: "100%" }} /></p>
          <p className="row">
            <label className="small">Expires <input type="date" value={expiry} onChange={(ev) => setExpiry(ev.target.value)} /></label>
            <button onClick={() => void run("decision", { outcome: "approve", comment, expires_at: expiry || undefined })}>Approve</button>
            <button className="secondary" onClick={() => void run("decision", { outcome: "reject", comment })}>Reject</button>
          </p>
        </>
      )}
      {e.status === "pending_approval" && !e.can_decide && !e.can_cosign && none}
      {e.status === "approved" && (
        <p className="row">
          <button className="secondary" onClick={() => void run("renewals", { justification: e.justification, remediation_plan: e.remediation_plan })}>Draft a renewal</button>
          <input placeholder="Reason to revoke" value={comment} onChange={(ev) => setComment(ev.target.value)} />
          <button className="secondary" onClick={() => void run("revoke", { reason: comment })}>Revoke</button>
        </p>
      )}
      {msg && <p className="error">{msg}</p>}
    </div>
  );
}
