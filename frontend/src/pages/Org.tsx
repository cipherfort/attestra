// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api } from "../api";
import { Loadable, useLoad } from "../components/ui";

export function Leadership() {
  const s = useLoad(api.scorecard, []);
  return (
    <>
      <div className="row"><h1>Leadership view</h1><span className="spacer" /><ExportButtons /></div>
      <p className="muted">Organisation-wide aggregates. No finding-level detail is needed or shown here.</p>
      <Loadable state={s}>
        {(x) => (
          <div className="grid tiles">
            <div className="card tile"><div className="label">Applications</div><div className="value">{x.applications}</div></div>
            <div className="card tile"><div className="label">Mandatory controls proven</div>
              <div className="value">{x.mandatory_control_coverage_pct ?? "—"}%</div><div className="sub">{x.satisfied} of {x.mandatory_states}</div></div>
            <div className="card tile"><div className="label">Known-exploited vulns on internet-facing apps</div>
              <div className={`value ${x.kev_internet_exposed_open ? "error" : "ok"}`}>{x.kev_internet_exposed_open}</div><div className="sub">KRI: escalate if &gt; 0 for 7 days</div></div>
            <div className="card tile"><div className="label">P1 findings open</div><div className="value">{x.p1_open}</div><div className="sub">{x.p1_overdue} past SLA</div></div>
            <div className="card tile"><div className="label">Controls missing or stale evidence</div><div className="value">{x.missing_or_stale}</div></div>
            <div className="card tile"><div className="label">Rejected evidence submissions</div><div className="value">{x.evidence_rejections}</div><div className="sub">forged, unapproved or tampered</div></div>
          </div>
        )}
      </Loadable>
    </>
  );
}

/** CSV exports, scoped to what the caller may see and audited (permission report.export). */
function ExportButtons() {
  const me = useLoad(api.me, []);
  const [msg, setMsg] = useState<string | null>(null);
  if (!me.data?.permissions.includes("report.export")) return null;
  const get = (r: "findings" | "controls") => api.download(r).catch((e) => setMsg(String(e)));
  return (
    <span className="row small">
      <button className="secondary" onClick={() => void get("findings")}>Export open findings (CSV)</button>
      <button className="secondary" onClick={() => void get("controls")}>Export control states (CSV)</button>
      <button className="secondary" onClick={() => window.print()}>Print / save as PDF</button>
      {msg && <span className="error">{msg}</span>}
    </span>
  );
}
