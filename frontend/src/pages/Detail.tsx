// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api, ApiError, type FindingDetail } from "../api";
import { date, Loadable, PriorityChip, useLoad } from "../components/ui";

const CONFIDENCE: Record<string, string> = {
  C0: "Declared — a claim only; never satisfies a control",
  C1: "Configured — a setting observed through an authoritative API",
  C2: "Executed — an approved workflow ran on this exact commit",
  C3: "Attested — executed and signed, or read from the system of record",
  M1: "Manual — recorded by the owning team",
  M2: "Manual — recorded by an independent reviewer",
};

export function EvidencePage({ id }: { id: string }) {
  const ev = useLoad(() => api.evidence(id), [id]);
  return (
    <Loadable state={ev}>
      {(e) => (
        <>
          <p className="small"><button className="secondary" onClick={() => history.back()}>← Back</button></p>
          <h1>Evidence <span className="mono">EV-{e.id.replaceAll("-", "").slice(-8).toUpperCase()}</span></h1>
          <p className="muted">{e.type} · {e.state} · observed {date(e.observed_at, true)}</p>
          <div className="grid two">
            <div className="card">
              <h2>What was observed</h2>
              <dl className="kv">
                <dt>Confidence</dt><dd><strong>{e.confidence}</strong> — {CONFIDENCE[e.confidence] ?? ""}</dd>
                <dt>Why that confidence</dt><dd>{e.confidence_reasons.join(", ").replaceAll("_", " ")}</dd>
                <dt>Producer</dt><dd className="mono">{e.producer_ref}</dd>
                <dt>Tool</dt><dd>{e.tool ?? "—"} {e.tool_version ?? ""}</dd>
                <dt>Subject</dt><dd className="mono">{Object.entries(e.subject).map(([k, v]) => `${k}: ${String(v)}`).join(" · ")}</dd>
                <dt>Result</dt><dd>{e.result}</dd>
                <dt>Valid until</dt><dd>{date(e.valid_until, true)}</dd>
              </dl>
            </div>
            <div className="card">
              <h2>Tamper evidence</h2>
              <dl className="kv">
                <dt>Record hash</dt><dd className="mono">{e.record_hash}</dd>
                <dt>Previous in chain</dt><dd className="mono">{e.prev_hash ?? "(first in chain)"}</dd>
                <dt>Raw files (SHA-256)</dt><dd className="mono">{(e.raw_sha256 ?? []).join("\n") || "—"}</dd>
              </dl>
              <p className="small muted">Records are append-only and hash-chained; a daily checkpoint is anchored outside the platform (Sentinel), so silent edits are detectable.</p>
            </div>
          </div>
          <div className="grid two">
            <div className="card">
              <h2>Freshness history</h2>
              <ul className="timeline">
                {(e.validity_events ?? []).map((v, i) => <li key={i}><strong>{v.state}</strong> — {v.reason} <span className="muted small">{date(v.at, true)}</span></li>)}
              </ul>
            </div>
            <div className="card">
              <h2>Summary from the tool</h2>
              <pre className="mono small">{JSON.stringify(e.summary, null, 2)}</pre>
              <p className="small muted">Used by {e.used_by_evaluations?.length ?? 0} control evaluation(s).</p>
            </div>
          </div>
        </>
      )}
    </Loadable>
  );
}

export function FindingPage({ id }: { id: string }) {
  const [version, setVersion] = useState(0);
  const finding = useLoad(() => api.finding(id), [id, version]);
  const events = useLoad(() => api.findingEvents(id), [id, version]);
  return (
    <Loadable state={finding}>
      {({ data: f, etag }) => (
        <>
          <p className="small"><a href={`/apps/${f.app_key}`}>← {f.application_name}</a></p>
          <div className="row"><PriorityChip p={f.priority} /><h1>{f.title}</h1></div>
          <p className="muted">{f.type} · {f.status.replaceAll("_", " ")} · first seen {date(f.first_seen_at)} · fix by {date(f.sla_due_at)}{f.sla_breached ? " (past SLA)" : ""}</p>
          <div className="grid two">
            <div className="card">
              <h2>Why {f.priority ?? "unscored"}?</h2>
              <p>{f.risk_explanation ?? "Not yet scored."}</p>
              {f.likelihood && <p className="small muted">Likelihood {f.likelihood} × impact {f.impact} = {f.risk_score}. Rules applied: {(f.applied_rules ?? []).join(", ") || "none"}.</p>}
              <p className="small muted">This is a prioritisation model, not an objective truth. The weights are governed configuration (config/risk-model.yaml).</p>
              <h3>Details</h3>
              <p className="small">{f.description}</p>
              <p className="small mono">{Object.entries(f.location ?? {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join(" · ")}</p>
            </div>
            <div className="card">
              <h2>Actions</h2>
              <Actions f={f} etag={etag ?? ""} onDone={() => setVersion((v) => v + 1)} />
              {!["closed", "false_positive", "excepted"].includes(f.status) && (
                <p className="small"><a href={`/exceptions/new?app=${f.app_key}&type=finding&ref=${f.id}`}>Request an exception for this finding</a></p>
              )}
              <p className="small muted">Closing is not an action: a finding closes only when a re-scan of the same scope no longer reports it. A ticket marked Done is not enough.</p>
              <h3>History</h3>
              <Loadable state={events}>
                {(ev) => (
                  <ul className="timeline">
                    {ev.map((e, i) => (
                      <li key={i}><strong>{e.event_type.replaceAll("_", " ")}</strong>{e.to_status ? ` → ${e.to_status}` : ""}
                        <span className="muted small"> · {e.actor_type === "system" ? "platform" : "person"} · {date(e.at, true)}</span>
                        {typeof e.details?.comment === "string" && e.details.comment && <div className="small">“{e.details.comment}”</div>}
                      </li>
                    ))}
                  </ul>
                )}
              </Loadable>
            </div>
          </div>
        </>
      )}
    </Loadable>
  );
}

function Actions({ f, etag, onDone }: { f: FindingDetail; etag: string; onDone: () => void }) {
  const me = useLoad(api.me, []);
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
  if (["closed", "false_positive"].includes(f.status)) return <p className="muted">No actions: this finding is {f.status.replaceAll("_", " ")}.</p>;
  return (
    <div>
      <div className="row">
        <button onClick={() => run("triage")} disabled={!["new", "reopened"].includes(f.status)}>Triage</button>
        <button className="secondary" onClick={() => run("mark_false_positive")}>Request false positive</button>
        {canConfirm && <>
          <button className="secondary" onClick={() => run("confirm_false_positive")}>Confirm false positive</button>
          <button className="secondary" onClick={() => run("reject_false_positive")}>Reject false positive</button>
        </>}
      </div>
      <p><textarea rows={2} placeholder="Justification (required to request a false positive)" value={comment}
        onChange={(e) => setComment(e.target.value)} style={{ width: "100%" }} /></p>
      {msg && <p className={msg.ok ? "ok" : "error"}>{msg.text}</p>}
      <p className="small muted">A false positive needs two people: anyone in the team can request it, and a different AppSec engineer confirms it. Self-confirmation is refused and audited.</p>
    </div>
  );
}
