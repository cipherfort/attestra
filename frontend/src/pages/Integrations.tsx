// SPDX-License-Identifier: Apache-2.0
import { api, type Integration } from "../api";
import { Loadable, useLoad } from "../components/ui";

// Status follows the reserved status colours, always with an icon and a text label (never colour alone).
const RUN: Record<string, { label: string; color: string; icon: string } | undefined> = {
  ok: { label: "OK", color: "var(--good)", icon: "✓" },
  partial: { label: "Partial", color: "var(--warning)", icon: "◐" },
  failed: { label: "Failed", color: "var(--critical)", icon: "✕" },
  running: { label: "Running", color: "var(--neutral)", icon: "…" },
};

const KIND: Record<string, string | undefined> = {
  scm: "source control", identity: "sign-in", ticketing: "ticketing", vuln_intel: "vulnerability data",
  workbench: "finding workbench", cloud_posture: "cloud posture", siem: "SIEM", evidence_store: "evidence storage",
  secrets: "secrets",
};

function Configured({ i }: { i: Integration }) {
  return i.configured
    ? <span className="badge"><span aria-hidden="true" className="icon" style={{ color: "var(--good)" }}>✓</span>Configured</span>
    : <span className="badge"><span aria-hidden="true" className="icon" style={{ color: "var(--neutral)" }}>○</span>Not configured</span>;
}

function LastRun({ i }: { i: Integration }) {
  if (!i.last_run) return <span className="muted">{i.configured && i.interval ? "Not run yet" : "—"}</span>;
  const r = RUN[i.last_run.status] ?? RUN.running!;
  const gaps = Object.keys(i.last_run.gaps).filter((k) => k !== "duration_s");
  return (
    <span>
      <span className="badge"><span aria-hidden="true" className="icon" style={{ color: r.color }}>{r.icon}</span>{r.label}</span>{" "}
      <span className="small muted">{new Date(i.last_run.started_at).toLocaleString()} · {i.last_run.items} item(s)</span>
      {gaps.length > 0 && <div className="small muted">Could not read: {gaps.slice(0, 4).join(", ")}{gaps.length > 4 ? "…" : ""}</div>}
      {i.last_run.error && <div className="small error">{i.last_run.error}</div>}
    </span>
  );
}

export function Integrations() {
  const state = useLoad(() => api.integrations(), []);
  return (
    <>
      <h1>Integrations</h1>
      <p className="muted">
        Every integration is a plugin, and every one starts unconfigured. Nothing is assumed: until an integration is
        set up, the controls that depend on it show <strong>No evidence</strong>, never a pass. Missing items are
        names only, never values.
      </p>
      <Loadable state={state}>
        {({ items, load_errors: errors }) => (
          <>
            {Object.keys(errors).length > 0 && (
              <div className="notice error">
                {Object.keys(errors).length} installed plugin(s) failed to load and are not running:{" "}
                {Object.entries(errors).map(([k, v]) => <div key={k} className="small"><code>{k}</code>: {v}</div>)}
              </div>
            )}
            <div className="grid tiles">
              <div className="card tile"><div className="label">Configured</div><div className="value">{items.filter((i) => i.configured).length} / {items.length}</div></div>
              <div className="card tile"><div className="label">Last run failed</div><div className="value">{items.filter((i) => i.last_run?.status === "failed").length}</div></div>
              <div className="card tile"><div className="label">Last run partial</div><div className="value">{items.filter((i) => i.last_run?.status === "partial").length}</div></div>
            </div>
            <div className="card">
              <table>
                <thead><tr><th>Integration</th><th>Status</th><th>Last run</th><th>What's missing</th><th>How to set it up</th></tr></thead>
                <tbody>
                  {items.map((i) => (
                    <tr key={i.key}>
                      <td><strong>{i.name}</strong> <span className="small muted">· {KIND[i.kind] ?? i.kind}{i.source !== "builtin" ? ` · plugin: ${i.source}` : ""}</span>
                        <div className="small muted">{i.purpose}</div>
                        {i.evidence.length > 0 && <div className="small muted">Evidence: {i.evidence.join(", ")}</div>}</td>
                      <td><Configured i={i} />{i.interval && <div className="small muted">every {i.interval}</div>}</td>
                      <td><LastRun i={i} /></td>
                      <td className="small">{i.missing.length ? i.missing.map((m) => <div key={m}><code>{m}</code></div>) : <span className="muted">Nothing</span>}</td>
                      <td className="small"><code>{i.bootstrap}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="small muted">Runbook: docs/operations/integration-bootstrap.md · CLI: <code>aap integrations status</code></p>
          </>
        )}
      </Loadable>
    </>
  );
}
