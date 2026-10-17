// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api } from "../api";
import { Loadable, Tier, useLoad } from "../components/ui";

export function CvePage({ initial }: { initial?: string }) {
  const [query, setQuery] = useState(initial ?? "CVE-2021-44228");
  const [submitted, setSubmitted] = useState(initial ?? "CVE-2021-44228");
  const impact = useLoad(() => api.impact(submitted), [submitted]);
  return (
    <>
      <h1>Are we affected?</h1>
      <p className="muted">
        Searches every application's current SBOM. Applications with no SBOM, or a stale one, are listed as
        <strong> possibly affected</strong> — never as unaffected. You only see applications in your scope.
      </p>
      <form className="row card" onSubmit={(e) => { e.preventDefault(); setSubmitted(query.trim()); window.location.hash = `#/cve/${query.trim()}`; }}>
        <label className="small muted" htmlFor="vuln">CVE / GHSA / OSV id</label>
        <input id="vuln" value={query} onChange={(e) => setQuery(e.target.value)} size={28} />
        <button type="submit">Check</button>
      </form>
      <Loadable state={impact}>
        {(r) => (
          <>
            <div className="card">
              <h2>{r.vulnerability.vuln_key} {r.vulnerability.in_kev && <span className="badge"><span className="dot" style={{ background: "var(--critical)" }} />Known exploited (CISA KEV)</span>}</h2>
              <p>{r.vulnerability.title}</p>
              <p className="small muted">Aliases: {r.vulnerability.aliases.join(", ") || "none"} · CVSS {String(r.vulnerability.cvss_v3_score ?? "—")} · EPSS percentile {String(r.vulnerability.epss_percentile ?? "—")}</p>
            </div>
            <div className="grid tiles">
              <div className="card tile"><div className="label">Affected</div><div className="value error">{r.affected.length}</div></div>
              <div className="card tile"><div className="label">Possibly affected (no / stale SBOM)</div><div className="value">{r.possibly_affected.length}</div></div>
              <div className="card tile"><div className="label">Not affected (current SBOM, no match)</div><div className="value ok">{r.not_affected_count}</div></div>
            </div>
            {r.affected.length > 0 && (
              <div className="card">
                <h2>Affected</h2>
                <table>
                  <thead><tr><th>Application</th><th>Tier</th><th>Exposure</th><th>Component</th><th>Fixed in</th></tr></thead>
                  <tbody>
                    {r.affected.map((x) => x.components.map((c) => (
                      <tr key={x.application.id + c.purl}>
                        <td><a href={`#/apps/${x.application.app_key}`}>{x.application.name}</a></td>
                        <td><Tier tier={x.application.tier} /></td>
                        <td className="small">{x.application.exposure?.replaceAll("_", " ")}</td>
                        <td className="mono">{c.purl}</td>
                        <td className="small">{c.fixed_versions.join(", ") || "no fix published"}</td>
                      </tr>
                    )))}
                  </tbody>
                </table>
              </div>
            )}
            {r.possibly_affected.length > 0 && (
              <div className="card">
                <h2>Possibly affected — generate an SBOM to find out</h2>
                <table>
                  <tbody>
                    {r.possibly_affected.map((x) => (
                      <tr key={x.application.id}>
                        <td><a href={`#/apps/${x.application.app_key}`}>{x.application.name}</a></td>
                        <td><Tier tier={x.application.tier} /></td>
                        <td className="small">{x.reason === "no_sbom" ? "No SBOM has ever been ingested" : x.reason === "stale_sbom" ? "SBOM is older than its freshness ceiling" : x.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Loadable>
    </>
  );
}

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
