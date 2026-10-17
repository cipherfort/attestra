// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ApiError, api, type Registered } from "../api";
import { Tier } from "../components/ui";

type Mode = "repository" | "paste";

/** Register an application from its repository contract (.security/application.yaml + asvs.yaml). */
export function Register() {
  const [mode, setMode] = useState<Mode>("repository");
  const [provider, setProvider] = useState<"github" | "gitlab">("github");
  const [repository, setRepository] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [appYaml, setAppYaml] = useState("");
  const [asvsYaml, setAsvsYaml] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string[] | null>(null);
  const [done, setDone] = useState<Registered | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      setDone(await api.register(mode === "repository" ? { repository, provider } : {
        repository, provider, repository_id: repositoryId, application_yaml: appYaml, asvs_yaml: asvsYaml || undefined,
      }));
    } catch (err) {
      const detail = err instanceof ApiError ? err.detail ?? err.title : String(err);
      setError(detail.split("; "));
    } finally {
      setBusy(false);
    }
  };

  if (done) return (
    <>
      <h1>Registered {done.app_key}</h1>
      <div className="card">
        <div className="row"><Tier tier={done.tier} /><span>{done.explanation}</span></div>
        {done.decision === "pending" ? (
          <p className="notice">
            Tier {done.tier} classifications need an AppSec engineer's approval before controls are evaluated. Someone
            outside your team decides it; you can't approve your own request.
          </p>
        ) : (
          <p className="ok">Classification auto-approved (Tier 3 and 4 don't need a person). Controls are being evaluated.</p>
        )}
        <p className="small muted">
          Next: add the shared security pipeline to the repository so scans produce evidence
          (<code>templates/repo-contract/.github/workflows/</code>).
        </p>
        <p><a href={`#/apps/${done.app_key}`}>Open {done.app_key} →</a></p>
      </div>
    </>
  );

  return (
    <>
      <p className="small"><a href="#/apps">← Applications</a></p>
      <h1>Register an application</h1>
      <p className="muted">
        The platform reads the application's contract, <code>.security/application.yaml</code> (and optionally
        <code> asvs.yaml</code>), works out its risk tier, and links the repository. You can register only into units
        you belong to. Start from <code>templates/repo-contract/</code> if the repository has no contract yet.
      </p>
      <form className="card" onSubmit={submit}>
        <fieldset className="row" style={{ border: 0, padding: 0, margin: "0 0 12px" }}>
          <legend className="small muted" style={{ marginBottom: 6 }}>Where should the contract come from?</legend>
          <label className="row"><input type="radio" checked={mode === "repository"} onChange={() => setMode("repository")} />
            Read it from the repository (GitHub or GitLab plugin)</label>
          <label className="row"><input type="radio" checked={mode === "paste"} onChange={() => setMode("paste")} />
            Paste the files (no GitHub plugin, or not merged yet)</label>
        </fieldset>
        <dl className="kv">
          <dt><label htmlFor="prov">Source control</label></dt>
          <dd><select id="prov" value={provider} onChange={(e) => setProvider(e.target.value as "github" | "gitlab")}>
            <option value="github">GitHub</option><option value="gitlab">GitLab</option></select></dd>
          <dt><label htmlFor="repo">Repository</label></dt>
          <dd><input id="repo" required placeholder={provider === "gitlab" ? "group/subgroup/project" : "owner/name"} pattern="[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)+"
            value={repository} onChange={(e) => setRepository(e.target.value.trim())} style={{ width: "100%" }} /></dd>
          {mode === "paste" && <>
            <dt><label htmlFor="rid">Repository id</label></dt>
            <dd><input id="rid" required inputMode="numeric" placeholder="the provider's numeric id"
              value={repositoryId} onChange={(e) => setRepositoryId(e.target.value.trim())} />
              <div className="small muted">GitHub: <code>gh api repos/OWNER/NAME --jq .id</code> · GitLab: the project ID on its overview page</div></dd>
            <dt><label htmlFor="app">application.yaml</label></dt>
            <dd><textarea id="app" required rows={14} spellCheck={false} value={appYaml}
              onChange={(e) => setAppYaml(e.target.value)} style={{ width: "100%", fontFamily: "monospace" }} /></dd>
            <dt><label htmlFor="asvs">asvs.yaml (optional)</label></dt>
            <dd><textarea id="asvs" rows={6} spellCheck={false} value={asvsYaml}
              onChange={(e) => setAsvsYaml(e.target.value)} style={{ width: "100%", fontFamily: "monospace" }} /></dd>
          </>}
        </dl>
        {error && (
          <div className="notice error" role="alert" style={{ marginTop: 12 }}>
            <strong>Not registered.</strong>
            <ul>{error.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
        )}
        <p><button type="submit" disabled={busy}>{busy ? "Registering…" : "Register"}</button></p>
      </form>
    </>
  );
}
