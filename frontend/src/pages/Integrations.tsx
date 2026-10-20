// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, Archive, Bell, Bug, Check, CheckCircle2, CircleDashed, CircleOff, Cloud, Copy, GitBranch, KeyRound, Lock, Plug,
  RefreshCw, ScrollText, Ticket, Wrench, XCircle, type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { api, type Integration } from "../api";
import { Button } from "../components/ui/Button";
import { Dialog } from "../components/ui/Dialog";
import { LoadError, Notice } from "../components/ui/Form";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/States";

const KIND: Record<string, { label: string; icon: LucideIcon }> = {
  scm: { label: "Source control", icon: GitBranch },
  identity: { label: "Sign-in", icon: KeyRound },
  ticketing: { label: "Ticketing", icon: Ticket },
  vuln_intel: { label: "Vulnerability data", icon: Bug },
  workbench: { label: "Finding workbench", icon: Wrench },
  cloud_posture: { label: "Cloud posture", icon: Cloud },
  siem: { label: "SIEM", icon: ScrollText },
  evidence_store: { label: "Evidence storage", icon: Archive },
  secrets: { label: "Secrets", icon: Lock },
  notification: { label: "Notifications", icon: Bell },
};

type Health = "unconfigured" | "waiting" | "ok" | "partial" | "failed" | "running";
const HEALTH: Record<Health, { label: string; icon: LucideIcon; tone: string }> = {
  unconfigured: { label: "Not configured", icon: CircleOff, tone: "text-muted" },
  waiting: { label: "Configured, not run yet", icon: CircleDashed, tone: "text-accent" },
  ok: { label: "Healthy", icon: CheckCircle2, tone: "text-good" },
  partial: { label: "Partly working", icon: AlertTriangle, tone: "text-warning" },
  failed: { label: "Last run failed", icon: XCircle, tone: "text-critical" },
  running: { label: "Running", icon: RefreshCw, tone: "text-accent" },
};

function health(i: Integration): Health {
  if (!i.configured) return "unconfigured";
  return i.last_run ? i.last_run.status : "waiting";
}

function HealthBadge({ h }: { h: Health }) {
  const s = HEALTH[h];
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink">
      <s.icon className={`size-3.5 ${s.tone}`} aria-hidden="true" />{s.label}
    </span>
  );
}

const when = (s: string) => new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const gapsOf = (i: Integration) => Object.keys(i.last_run?.gaps ?? {}).filter((k) => k !== "duration_s");

export function Integrations() {
  const params = useParams();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["integrations"], queryFn: api.integrations });
  const items = q.data?.items ?? [];
  const errors = Object.entries(q.data?.load_errors ?? {});
  const open = items.find((i) => i.key === params.key);
  const by = (h: Health[]) => items.filter((i) => h.includes(health(i))).length;
  const kinds = [...new Set(items.map((i) => i.kind))].sort((a, b) => (KIND[a]?.label ?? a).localeCompare(KIND[b]?.label ?? b));
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Every integration is a plugin, and each one starts unconfigured. Until one is set up, the controls that depend on it show No evidence, never a pass."
        actions={<Button onClick={() => void q.refetch()} disabled={q.isFetching}><RefreshCw className={`size-4 ${q.isFetching ? "animate-spin" : ""}`} aria-hidden="true" />Refresh</Button>}
      />
      {q.isPending ? <Skeleton className="h-96 w-full" /> : q.isError ? <LoadError error={q.error} /> : (
        <>
          <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
            <Kpi label="Configured" value={`${items.filter((i) => i.configured).length} of ${items.length}`} sub="Settings present in the deployment" />
            <Kpi label="Healthy" value={by(["ok"])} tone={by(["ok"]) ? "good" : undefined} sub="Last run succeeded" />
            <Kpi label="Need attention" value={by(["failed", "partial"])} tone={by(["failed", "partial"]) ? "critical" : undefined} sub="Last run failed or read only part" />
            <Kpi label="Not configured" value={by(["unconfigured"])} sub="Their controls show No evidence" />
          </div>
          {errors.length > 0 && (
            <div className="mb-6">
              <Notice tone="error" title={`${errors.length} installed plugin${errors.length === 1 ? "" : "s"} failed to load and ${errors.length === 1 ? "isn't" : "aren't"} running`}>
                <ul className="plain m-0 mt-1 p-0">{errors.map(([k, v]) => <li key={k} className="text-xs"><code>{k}</code>: {v}</li>)}</ul>
              </Notice>
            </div>
          )}
          <div className="space-y-6">
            {kinds.map((k) => {
              const K = KIND[k] ?? { label: k, icon: Plug };
              return (
                <section key={k} aria-labelledby={`kind-${k}`}>
                  <h2 id={`kind-${k}`} className="m-0 mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted">
                    <K.icon className="size-3.5" aria-hidden="true" />{K.label}
                  </h2>
                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {items.filter((i) => i.kind === k).map((i) => <IntegrationCard key={i.key} i={i} onOpen={() => void navigate(`/integrations/${i.key}`)} />)}
                  </div>
                </section>
              );
            })}
          </div>
          <p className="mt-6 text-xs text-muted">From the command line: <code>aap integrations status</code>. Set-up guide: fortproof.dev/guide/connect-your-organization.</p>
        </>
      )}
      <Dialog open={!!open} onClose={() => void navigate("/integrations", { replace: true })} title={open ? `Set up ${open.name}` : ""} variant="drawer">
        {open && <Setup i={open} refresh={() => void q.refetch()} checking={q.isFetching} />}
      </Dialog>
    </>
  );
}

function IntegrationCard({ i, onOpen }: { i: Integration; onOpen: () => void }) {
  const h = health(i);
  const K = KIND[i.kind] ?? { label: i.kind, icon: Plug };
  return (
    <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
      <div className="flex items-start gap-3">
        <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 text-ink-2"><K.icon className="size-4" aria-hidden="true" /></span>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-ink">{i.name}</div>
          <div className="text-xs text-muted">{i.source === "builtin" ? "Built in" : `Plugin: ${i.source}`}{i.interval ? ` · every ${i.interval}` : ""}</div>
        </div>
        <HealthBadge h={h} />
      </div>
      <p className="m-0 mt-3 flex-1 text-xs text-ink-2">{i.purpose}</p>
      {i.last_run && (
        <p className="m-0 mt-2 text-xs text-muted">
          Last run {when(i.last_run.started_at)} · {i.last_run.items} item{i.last_run.items === 1 ? "" : "s"}
          {gapsOf(i).length > 0 && ` · couldn't read ${gapsOf(i).length}`}
        </p>
      )}
      <div className="mt-3 flex items-center justify-between gap-2 border-t border-line pt-3">
        <span className="text-xs text-muted">{i.missing.length ? `${i.missing.length} setting${i.missing.length === 1 ? "" : "s"} missing` : "All settings present"}</span>
        <Button size="sm" variant={i.configured ? "secondary" : "primary"} onClick={onOpen} aria-label={`${i.configured ? "Details" : "Set up"}: ${i.name}`}>{i.configured ? "Details" : "Set up"}</Button>
      </div>
    </div>
  );
}

function Step({ n, title, done, children }: { n: number; title: string; done: boolean; children: React.ReactNode }) {
  return (
    <li className="relative flex gap-3 pb-6 last:pb-0">
      <span aria-hidden="true" className="absolute left-[13px] top-8 h-[calc(100%-2rem)] w-px bg-line [li:last-child>&]:hidden" />
      <span className={`flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${done ? "border-good/50 text-good" : "border-accent text-accent-ink"}`}>
        {done ? <Check className="size-3.5" aria-label="done" /> : n}
      </span>
      <div className="min-w-0 flex-1 pt-0.5">
        <h3 className="m-0 text-[13px] font-semibold text-ink">{title}</h3>
        <div className="mt-1.5 text-[13px] text-ink-2">{children}</div>
      </div>
    </li>
  );
}

function Setup({ i, refresh, checking }: { i: Integration; refresh: () => void; checking: boolean }) {
  const [copied, setCopied] = useState(false);
  const h = health(i);
  const copy = () => {
    void navigator.clipboard?.writeText(i.bootstrap).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  };
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-3">
        <p className="m-0 text-[13px] text-ink-2">{i.purpose}</p>
        <HealthBadge h={h} />
      </div>
      {i.evidence.length > 0 && (
        <div>
          <div className="mb-1 text-xs text-muted">Evidence it produces</div>
          <div className="flex flex-wrap gap-1">{i.evidence.map((e) => <span key={e} className="rounded border border-line bg-surface-2 px-1.5 py-px font-mono text-[11px] text-ink-2">{e}</span>)}</div>
        </div>
      )}
      <ol className="plain m-0 p-0" aria-label="Setup steps">
        <Step n={1} title="Provide the settings" done={i.missing.length === 0}>
          {i.missing.length ? (
            <>
              These are missing from the deployment (names only; values are never shown here):
              <ul className="plain m-0 mt-2 space-y-1 p-0">{i.missing.map((m) => <li key={m}><code className="text-xs">{m}</code></li>)}</ul>
            </>
          ) : "Every setting it needs is present."}
        </Step>
        <Step n={2} title="Set it up" done={i.configured}>
          {i.bootstrap.startsWith("aap ") ? "Run this where the platform is deployed:" : "What it needs from you:"}
          <div className="mt-2 flex items-start gap-2 rounded-md border border-line bg-page p-2.5">
            <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-ink">{i.bootstrap}</code>
            <Button size="sm" variant="ghost" onClick={copy} aria-label="Copy the command">{copied ? <Check className="size-3.5" aria-hidden="true" /> : <Copy className="size-3.5" aria-hidden="true" />}{copied ? "Copied" : "Copy"}</Button>
          </div>
        </Step>
        <Step n={3} title="Check it works" done={h === "ok"}>
          {h === "unconfigured" ? "Once the settings are in place and the platform has restarted, the first scheduled run shows here."
            : h === "waiting" ? `Configured. The first run happens on its schedule${i.interval ? ` (every ${i.interval})` : ""}.`
              : i.last_run && (
                <>
                  Last run {when(i.last_run.started_at)}: {HEALTH[h].label.toLowerCase()}, {i.last_run.items} item{i.last_run.items === 1 ? "" : "s"}.
                  {gapsOf(i).length > 0 && <div className="mt-1 text-xs">Couldn't read: {gapsOf(i).join(", ")}</div>}
                  {i.last_run.error && <div className="mt-1 text-xs text-critical-ink">{i.last_run.error}</div>}
                </>
              )}
          <div className="mt-2"><Button size="sm" onClick={refresh} disabled={checking}><RefreshCw className={`size-3.5 ${checking ? "animate-spin" : ""}`} aria-hidden="true" />Check again</Button></div>
        </Step>
      </ol>
      <Notice>Settings and secrets are never entered in this screen. They live in the deployment's environment or secret store, so the platform never holds a credential it doesn't need.</Notice>
    </div>
  );
}
