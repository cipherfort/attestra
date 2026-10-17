// SPDX-License-Identifier: Apache-2.0
import { api, type Priority } from "../api";
import { CoverageBar, CoverageLegend } from "../components/charts";
import { Loadable, PriorityChip, Tier, useLoad } from "../components/ui";

const PRIORITIES: Priority[] = ["P1", "P2", "P3", "P4"];

export function Portfolio() {
  const apps = useLoad(api.applications, []);
  const me = useLoad(api.me, []);
  return (
    <>
      <div className="row">
        <h1>Applications</h1>
        <span className="spacer" />
        {me.data?.permissions.includes("application.register") && (
          <button type="button" onClick={() => { window.location.hash = "#/register"; }}>Register an application</button>
        )}
      </div>
      <p className="muted">
        Every application you can see, its risk tier, how many of its mandatory security controls are proven by current
        evidence, and its open findings by contextual priority.
      </p>
      <div className="card">
        <Loadable state={apps}>
          {(items) => items.length === 0 ? <div className="muted">No applications in your scope.</div> : (
            <>
              <table>
                <thead>
                  <tr>
                    <th>Application</th><th>Tier</th><th>Owned by</th><th>Mandatory controls proven</th>
                    <th>Open findings</th><th className="num">Past SLA</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => { window.location.hash = `#/apps/${a.app_key}`; }}>
                      <td><a href={`#/apps/${a.app_key}`}>{a.name}</a><div className="muted small">{a.app_key} · {a.lifecycle}</div></td>
                      <td><Tier tier={a.tier} /></td>
                      <td className="small">{a.org_unit}</td>
                      <td><CoverageBar counts={a.mandatory_controls ?? {}} /></td>
                      <td>
                        <div className="chips">
                          {PRIORITIES.filter((p) => a.open_findings?.[p]).map((p) => (
                            <PriorityChip key={p} p={p} count={a.open_findings?.[p]} />
                          ))}
                          {!a.open_findings && <span className="muted small">none</span>}
                        </div>
                      </td>
                      <td className={`num ${a.sla_breaches ? "error" : ""}`}>{a.sla_breaches}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <CoverageLegend />
            </>
          )}
        </Loadable>
      </div>
    </>
  );
}
