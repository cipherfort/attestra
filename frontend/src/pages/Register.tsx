// SPDX-License-Identifier: Apache-2.0
import { CheckCircle2, Hourglass } from "lucide-react";
import { useState } from "react";
import { ApiError, api, type Registered } from "../api";
import { TierBadge } from "../components/domain/badges";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field, Notice, inputClass, selectClass, textareaClass } from "../components/ui/Form";
import { PageHeader } from "../components/ui/PageHeader";

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

  if (done) {
    const pending = done.decision === "pending";
    return (
      <>
        <PageHeader crumbs={[{ label: "Applications", to: "/apps" }, { label: done.app_key }]} title={`Registered ${done.app_key}`} />
        <Card className="max-w-3xl">
          <div className="flex items-start gap-3">
            {pending ? <Hourglass className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden="true" /> : <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-good" aria-hidden="true" />}
            <div className="min-w-0 flex-1 text-[13px]">
              <div className="flex flex-wrap items-center gap-2"><TierBadge tier={done.tier} /><span className="text-ink">{done.explanation}</span></div>
              <p className="m-0 mt-2 text-ink-2">
                {pending
                  ? `Tier ${done.tier} classifications need an AppSec engineer's approval before controls are evaluated. Someone outside your team decides; you can't approve your own request.`
                  : "Classification auto-approved: Tier 3 and 4 don't need a person. Controls are being evaluated."}
              </p>
            </div>
          </div>
          <h2 className="m-0 mt-5 text-sm font-semibold text-ink">Next</h2>
          <ol className="m-0 mt-2 space-y-1.5 text-[13px] text-ink-2">
            <li>Add the shared security pipelines to the repository so scans produce evidence (<code>templates/repo-contract/</code>).</li>
            <li>Open the application to see which controls still need evidence.</li>
          </ol>
          <div className="mt-5"><ButtonLink to={`/apps/${done.app_key}`} variant="primary">Open {done.app_key}</ButtonLink></div>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Applications", to: "/apps" }, { label: "Register" }]}
        title="Register an application"
        description={<>The platform reads the application's contract, <code>.security/application.yaml</code> (and optionally <code>asvs.yaml</code>), works out its risk tier and links the repository. You can only register into units you belong to.</>}
      />
      <Card className="max-w-3xl">
        <form onSubmit={submit} className="grid gap-5">
          <fieldset className="m-0 border-0 p-0">
            <legend className="mb-2 text-xs font-medium text-ink-2">Where should the contract come from?</legend>
            <div className="grid gap-2 md:grid-cols-2">
              {([["repository", "Read it from the repository", "Uses the GitHub or GitLab integration"], ["paste", "Paste the files", "No integration yet, or the contract isn't merged"]] as const).map(([v, t, d]) => (
                <label key={v} className={`flex cursor-pointer gap-2.5 rounded-lg border p-3 text-[13px] ${mode === v ? "border-accent bg-accent-soft" : "border-line bg-surface-2 hover:border-line-strong"}`}>
                  <input type="radio" name="mode" checked={mode === v} onChange={() => setMode(v)} className="mt-0.5 accent-[var(--accent)]" />
                  <span><span className="block font-medium text-ink">{t}</span><span className={`text-xs ${mode === v ? "text-ink-2" : "text-muted"}`}>{d}</span></span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-4 md:grid-cols-3">
            <Field id="prov" label="Source control">
              <select id="prov" value={provider} onChange={(e) => setProvider(e.target.value as "github" | "gitlab")} className={selectClass}>
                <option value="github">GitHub</option><option value="gitlab">GitLab</option>
              </select>
            </Field>
            <div className="md:col-span-2">
              <Field id="repo" label="Repository">
                <input id="repo" required placeholder={provider === "gitlab" ? "group/subgroup/project" : "owner/name"} pattern="[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)+"
                  value={repository} onChange={(e) => setRepository(e.target.value.trim())} className={`${inputClass} font-mono`} />
              </Field>
            </div>
          </div>
          {mode === "paste" && (
            <>
              <Field id="rid" label="Repository id" hint={<>GitHub: <code>gh api repos/OWNER/NAME --jq .id</code> · GitLab: the project ID on its overview page</>}>
                <input id="rid" required inputMode="numeric" value={repositoryId} onChange={(e) => setRepositoryId(e.target.value.trim())} className={`${inputClass} font-mono md:w-60`} />
              </Field>
              <Field id="app-yaml" label="application.yaml"><textarea id="app-yaml" required rows={14} spellCheck={false} value={appYaml} onChange={(e) => setAppYaml(e.target.value)} className={`${textareaClass} font-mono text-xs`} /></Field>
              <Field id="asvs-yaml" label="asvs.yaml" optional><textarea id="asvs-yaml" rows={6} spellCheck={false} value={asvsYaml} onChange={(e) => setAsvsYaml(e.target.value)} className={`${textareaClass} font-mono text-xs`} /></Field>
            </>
          )}
          {error && (
            <Notice tone="error" title="Not registered">
              <ul className="m-0 mt-1 pl-5">{error.map((x) => <li key={x}>{x}</li>)}</ul>
            </Notice>
          )}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Registering…" : "Register"}</Button>
            <span className="text-xs text-muted">No contract yet? Start from <code>templates/repo-contract/</code>.</span>
          </div>
        </form>
      </Card>
    </>
  );
}
