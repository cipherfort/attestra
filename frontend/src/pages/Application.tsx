// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ApiError, api, type Classification, type ControlItem, type ControlStateValue, type Finding } from "../api";
import { CoverageBar, CoverageLegend, MaturityChart } from "../components/charts";
import { date, Loadable, PriorityChip, STATE, StateBadge, Tier, useLoad } from "../components/ui";

const DOMAINS: Record<string, string> = {
  GOV: "Governance & registration", REQ: "Security requirements", TM: "Threat modelling", ARC: "Architecture",
  SRC: "Source & repository", BLD: "Build & supply chain", DEP: "Deployment", TST: "Security testing",
  VUL: "Vulnerability management", OPS: "Operations",
};

/** One row per control: the worst state across its scopes (a control is only as good as its weakest repository). */
function perControl(items: ControlItem[]): { worst: ControlItem; scopes: ControlItem[] }[] {
  const by = new Map<string, ControlItem[]>();
  for (const i of items) by.set(i.control_key, [...(by.get(i.control_key) ?? []), i]);
  return [...by.values()].map((scopes) => {
    const applicable = scopes.filter((s) => s.requirement !== "n/a");
    const pool = applicable.length ? applicable : scopes;
    const worst = pool.reduce((a, b) => (STATE[b.state].order < STATE[a.state].order ? b : a));
    return { worst, scopes };
  });
}

const DECISION: Record<Classification["decision"], string> = {
  pending: "waiting for AppSec approval", approved: "approved", auto_approved: "auto-approved (Tier 3/4)",
  rejected: "rejected",
};

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
    <div className="notice" style={{ marginBottom: 12 }}>
      <strong>Tier {c.computed_tier} is waiting for AppSec approval.</strong>{" "}
      Controls are evaluated once the tier is approved.
      {c.can_decide ? (
        <>
          <p><textarea rows={2} placeholder="Reason (recorded in the audit log)" value={reason}
            onChange={(e) => setReason(e.target.value)} style={{ width: "100%" }} /></p>
          <div className="row">
            <button onClick={() => void decide("approved")}>Approve Tier {c.computed_tier}</button>
            <button className="secondary" onClick={() => void decide("rejected")}>Reject</button>
          </div>
          {msg && <p className="error">{msg}</p>}
        </>
      ) : (
        <p className="small muted">
          An AppSec engineer who is not the requester and not in the owning team decides it.
        </p>
      )}
    </div>
  );
}

export function Application({ id }: { id: string }) {
  const app = useLoad(() => api.application(id), [id]);
  const cls = useLoad(() => api.classification(id), [id]);
  const controls = useLoad(() => api.controls(id), [id]);
  const findings = useLoad(() => api.findings(id), [id]);
  const maturity = useLoad(() => api.maturity(id), [id]);

  return (
    <Loadable state={app}>
      {(a) => (
        <>
          <p className="small"><a href="#/apps">← Applications</a></p>
          <div className="row">
            <h1>{a.name}</h1><Tier tier={a.tier} /><span className="muted">{a.app_key} · {a.org_unit} · {a.lifecycle}</span>
          </div>
          <p className="muted">{a.description}</p>

          <div className="grid tiles">
            <Loadable state={controls}>
              {(c) => {
                const rows = perControl(c.items).filter((r) => r.worst.requirement === "mandatory");
                const sat = rows.filter((r) => r.worst.state === "satisfied").length;
                return (
                  <div className="card tile">
                    <div className="label">Mandatory controls proven</div>
                    <div className="value">{sat}<span className="muted small"> / {rows.length}</span></div>
                    <div className="sub">evaluated {date(c.data_as_of.computed_at, true)}</div>
                  </div>
                );
              }}
            </Loadable>
            <Loadable state={findings}>
              {(f) => (
                <div className="card tile">
                  <div className="label">Open findings</div>
                  <div className="value">{f.length}</div>
                  <div className="sub">{f.filter((x) => x.priority === "P1").length} P1 · {f.filter((x) => x.sla_breached).length} past SLA</div>
                </div>
              )}
            </Loadable>
            <Loadable state={maturity}>
              {(m) => (
                <div className="card tile">
                  <div className="label">SAMM maturity (application practices)</div>
                  <div className="value">{m.overall.toFixed(2)}<span className="muted small"> / 3</span></div>
                  <div className="sub">{a.tier ? `${m.meets_tier_target ? "meets" : "below"} its Tier ${a.tier} target` : "no approved tier yet"}</div>
                </div>
              )}
            </Loadable>
          </div>

          <div className="grid two">
            <div className="card">
              <h2>{a.tier ? `Why Tier ${a.tier}?` : "Classification"}</h2>
              <Loadable state={cls}>
                {(c) => (
                  <>
                    {c.decision === "pending" && <ClassificationDecision appId={a.id} c={c} onDone={() => { app.reload(); cls.reload(); }} />}
                    {c.decision === "rejected" && (
                      <p className="notice error">
                        The computed Tier {c.computed_tier} was rejected by {c.decided_by}. Correct the classification in
                        <code> .security/application.yaml</code> and register again, or ask AppSec.
                      </p>
                    )}
                    <p>{c.explanation}</p>
                    <p className="small muted">
                      ASVS target {c.asvs_target} · {DECISION[c.decision]}{c.decided_by ? ` by ${c.decided_by}` : ""}
                      {c.requested_by ? ` · requested by ${c.requested_by}` : ""}
                    </p>
                    <table>
                      <tbody>
                        {c.contributions.map(([dim, val, pts]) => (
                          <tr key={dim}><td className="small">{dim.replaceAll("_", " ")}</td><td className="small">{val.replaceAll("_", " ")}</td>
                            <td className="num small">{pts} pts</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </Loadable>
            </div>
            <div className="card">
              <h2>Ownership</h2>
              <dl className="kv">
                <dt>Business owner</dt><dd>{a.business_owner ?? <span className="error">not resolved</span>}</dd>
                <dt>Technical owner</dt><dd>{a.technical_owner ?? <span className="error">not resolved</span>}</dd>
                <dt>Security champion</dt><dd>{a.champion ?? <span className="muted">none named</span>}</dd>
                <dt>Data</dt><dd>{a.data_classification} · personal data: {a.personal_data?.replaceAll("_", " ")}</dd>
                <dt>Exposure</dt><dd>{a.exposure?.replaceAll("_", " ")}</dd>
              </dl>
            </div>
          </div>

          <Loadable state={controls}>{(c) => <Attention items={c.items} appKey={a.app_key} />}</Loadable>
          <OpenWork appKey={a.app_key} />
          <div className="card">
            <h2>{a.tier ? `Maturity against the Tier ${a.tier} target` : "Maturity"}</h2>
            <p className="small muted">
              Derived from control states (official OWASP SAMM scale 0–3). Hover a bar for how much of the score rests on
              automated evidence, independent review or self-assessment.
            </p>
            <Loadable state={maturity}>{(m) => <MaturityChart practices={m.practices} />}</Loadable>
          </div>
          <Loadable state={findings}>{(f) => <Findings items={f} />}</Loadable>
          <Loadable state={controls}>{(c) => <Controls items={c.items} />}</Loadable>
        </>
      )}
    </Loadable>
  );
}

function Attention({ items, appKey }: { items: ControlItem[]; appKey: string }) {
  const rows = perControl(items)
    .filter((r) => r.worst.requirement === "mandatory" && !["satisfied", "excepted", "not_applicable", "error"].includes(r.worst.state))
    .sort((a, b) => STATE[a.worst.state].order - STATE[b.worst.state].order);
  const counts = perControl(items).filter((r) => r.worst.requirement === "mandatory")
    .reduce<Partial<Record<ControlStateValue, number>>>((acc, r) => ({ ...acc, [r.worst.state]: (acc[r.worst.state] ?? 0) + 1 }), {});
  return (
    <div className="card">
      <div className="row"><h2>Needs attention</h2><span className="spacer" /><CoverageBar counts={counts} width={320} /></div>
      {rows.length === 0 ? <p className="ok">Every evaluated mandatory control is proven by current evidence.</p> : (
        <table>
          <tbody>
            {rows.map(({ worst: r }) => (
              <tr key={r.control_key}>
                <td><StateBadge state={r.state} /></td>
                <td><strong>{r.title}</strong><div className="muted small">{r.control_key}{r.scope.type === "repository" ? ` · ${r.scope.ref.split("/").pop()}` : ""}</div></td>
                <td className="small">{r.explanation}</td>
                <td className="small"><a href={`#/exceptions/new?app=${appKey}&type=control&ref=${r.control_key}`}>Request exception</a></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <CoverageLegend />
    </div>
  );
}

/** Exceptions and assessments for this application, with the links to start new ones. */
function OpenWork({ appKey }: { appKey: string }) {
  const exceptions = useLoad(() => api.exceptions(appKey), [appKey]);
  const assessments = useLoad(() => api.assessments(appKey), [appKey]);
  return (
    <div className="grid two">
      <div className="card">
        <div className="row"><h2>Exceptions</h2><span className="spacer" />
          <a href={`#/exceptions/new?app=${appKey}`}>Request an exception</a></div>
        <Loadable state={exceptions}>
          {(xs) => xs.length === 0 ? <p className="muted small">None.</p> : (
            <ul className="plain small">{xs.slice(0, 8).map((x) => (
              <li key={x.id}><a href={`#/exceptions/${x.exception_key}`}>{x.exception_key}</a> · {x.target_type} {x.target_ref.slice(0, 14)} ·{" "}
                {x.status.replaceAll("_", " ")}{x.expires_at ? ` · expires ${date(x.expires_at)}` : ""}</li>))}</ul>
          )}
        </Loadable>
      </div>
      <div className="card">
        <div className="row"><h2>Assessments</h2><span className="spacer" />
          <a href={`#/assessments/new?app=${appKey}`}>Start an assessment</a></div>
        <Loadable state={assessments}>
          {(xs) => xs.length === 0 ? <p className="muted small">None.</p> : (
            <ul className="plain small">{xs.slice(0, 8).map((x) => (
              <li key={x.id}><a href={`#/assessments/${x.id}`}>{x.type.replaceAll("_", " ")}</a> · {x.status.replaceAll("_", " ")}
                {x.confidence ? ` · ${x.confidence}` : ""}</li>))}</ul>
          )}
        </Loadable>
      </div>
    </div>
  );
}

function Findings({ items }: { items: Finding[] }) {
  const order = { P1: 0, P2: 1, P3: 2, P4: 3 } as const;
  const sorted = [...items].sort((a, b) => (order[a.priority ?? "P4"] ?? 9) - (order[b.priority ?? "P4"] ?? 9));
  return (
    <div className="card">
      <h2>Open findings</h2>
      {sorted.length === 0 ? <p className="muted">No open findings.</p> : (
        <table>
          <thead><tr><th>Priority</th><th>Finding</th><th>Status</th><th>Fix by</th></tr></thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id} className="clickable" onClick={() => { window.location.hash = `#/findings/${f.id}`; }}>
                <td><PriorityChip p={f.priority} /></td>
                <td><a href={`#/findings/${f.id}`}>{f.title}</a>
                  <div className="muted small">{f.type} · {String(f.location?.uri ?? f.location?.purl ?? f.scope_ref)}</div></td>
                <td className="small">{f.status.replaceAll("_", " ")}</td>
                <td className={`small ${f.sla_breached ? "error" : ""}`}>{date(f.sla_due_at)}{f.sla_breached ? " (past SLA)" : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Controls({ items }: { items: ControlItem[] }) {
  const rows = perControl(items);
  const domains = Object.keys(DOMAINS).filter((d) => rows.some((r) => r.worst.domain === d));
  return (
    <div className="card">
      <h2>All controls</h2>
      <p className="small muted">Open a control to see how its operation is proven, every scope it was evaluated in, and the evidence behind it.</p>
      {domains.map((d) => (
        <div className="domain" key={d}>
          <h3>{DOMAINS[d]}</h3>
          {rows.filter((r) => r.worst.domain === d).sort((a, b) => a.worst.control_key.localeCompare(b.worst.control_key)).map(({ worst, scopes }) => (
            <details className="ctl" key={worst.control_key}>
              <summary>
                <span className="mono">{worst.control_key}</span>
                <StateBadge state={worst.state} />
                <span>{worst.title}</span>
                <span className="muted small">{worst.requirement} · {worst.mode}</span>
              </summary>
              <div className="expl">{worst.explanation}</div>
              <div className="more">
                <p><strong>How it is proven:</strong> {worst.proof}</p>
                <table>
                  <thead><tr><th>Scope</th><th>State</th><th>Explanation</th><th>Evidence</th></tr></thead>
                  <tbody>
                    {scopes.map((s) => (
                      <tr key={s.scope.ref}>
                        <td className="small">{s.scope.ref}</td>
                        <td><StateBadge state={s.state} /></td>
                        <td className="small">{s.explanation}</td>
                        <td className="small">{s.evidence_ids.length ? s.evidence_ids.map((e) => (
                          <div key={e}><a href={`#/evidence/${e}`} className="mono">EV-{e.replaceAll("-", "").slice(-8).toUpperCase()}</a></div>
                        )) : <span className="muted">none</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="small muted">Evaluator <code>{worst.evaluator}</code> · state since {date(worst.since, true)}</p>
              </div>
            </details>
          ))}
        </div>
      ))}
    </div>
  );
}
