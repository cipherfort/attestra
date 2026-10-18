// SPDX-License-Identifier: Apache-2.0
import { Check, CircleDashed, GitCommitHorizontal, Link2, ListChecks, ScrollText, ShieldCheck, X } from "lucide-react";
import type { ReactNode } from "react";
import type { Evidence } from "../../api";
import { CONFIDENCE, ConfidenceBadge } from "./badges";

/** What each confidence reason means, in words. */
const REASONS: Record<string, string> = {
  approved_workflow_verified: "Produced by an approved workflow at an approved commit",
  attestation_verified: "Signature verified (Sigstore attestation by the workflow's identity)",
  authoritative_api: "Read from the system of record's API",
  reviewer_independent: "Recorded by a reviewer independent of the owning team",
  reviewer_self: "Recorded by the owning team",
  platform_derived: "Derived by the platform from evidence it already verified",
};

function reason(code: string): { text: string; ok: boolean } {
  if (REASONS[code]) return { text: REASONS[code], ok: true };
  const capped = /^capped_(C\d)_runner_(.+)$/.exec(code);
  if (capped) return { text: `Confidence capped at ${capped[1]}: ran on a ${(capped[2] ?? "").replaceAll("-", " ")} runner`, ok: false };
  const runner = /^runner_(.+)$/.exec(code);
  if (runner?.[1] === "github-hosted") return { text: "Ran on a GitHub-hosted runner", ok: true };
  if (runner) return { text: `Ran on a ${(runner[1] ?? "").replaceAll("-", " ")} runner`, ok: true };
  return { text: code.replaceAll("_", " "), ok: true };
}

const short = (h: string | null | undefined, n = 12) => (h ? `${h.slice(0, n)}…` : "–");

function Step({ icon: Icon, title, done = true, last = false, children }: { icon: typeof Check; title: string; done?: boolean; last?: boolean; children: ReactNode }) {
  return (
    <li className={`relative flex gap-4 ${last ? "" : "pb-6"}`}>
      {!last && <span aria-hidden="true" className="absolute left-[15px] top-8 h-[calc(100%-2rem)] w-px bg-line" />}
      <span className={`flex size-8 shrink-0 items-center justify-center rounded-full border ${done ? "border-accent/40 bg-accent-soft text-accent-ink" : "border-line bg-surface-2 text-muted"}`}>
        <Icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1 pt-1">
        <div className="text-[13px] font-semibold text-ink">{title}</div>
        <div className="mt-1 text-[13px] text-ink-2">{children}</div>
      </div>
    </li>
  );
}

/** Source → manifest and files → verification → ledger → outcome. Each step shows what the platform checked. */
export function EvidenceChain({ e }: { e: Evidence }) {
  const s = e.subject as Record<string, unknown>;
  const run = (e.run_ref ?? {}) as Record<string, unknown>;
  const repo = String(s.repo ?? s.repository ?? run.repository ?? "");
  const commit = String(s.commit_sha ?? run.head_sha ?? "");
  const source =
    e.producer_type === "approved_workflow" ? "Pipeline run"
      : e.producer_type === "platform_connector" ? "Platform connector"
        : e.producer_type === "manual" ? "Manual record" : "External system";
  const level = CONFIDENCE[e.confidence];
  return (
    <ol className="plain m-0 p-0" aria-label="How this evidence was verified">
      <Step icon={GitCommitHorizontal} title={source}>
        {e.producer_type === "approved_workflow" ? (
          <>
            {repo && <span className="font-mono text-xs">{repo}</span>}
            {commit && <> at <span className="font-mono text-xs">{short(commit, 10)}</span></>}
            {run.run_id !== undefined && <> · run <span className="font-mono text-xs">{String(run.run_id)}</span></>}
            {s.on_default_branch === true && <> · default branch</>}
            <div className="mt-0.5 break-all font-mono text-[11px] text-muted">{e.producer_ref}</div>
          </>
        ) : (
          <span className="font-mono text-xs">{e.producer_ref}</span>
        )}
      </Step>
      <Step icon={ScrollText} title="Manifest and files" done={(e.raw_sha256?.length ?? 0) > 0 || e.producer_type !== "approved_workflow"}>
        {e.tool ? <>{e.tool} {e.tool_version}</> : "No tool output"} · observed {new Date(e.observed_at).toLocaleString()}
        {(e.raw_sha256?.length ?? 0) > 0 && (
          <ul className="plain m-0 mt-1 p-0">
            {e.raw_sha256!.map((h) => <li key={h} className="font-mono text-[11px] text-muted">sha256:{short(h, 24)}</li>)}
          </ul>
        )}
      </Step>
      <Step icon={ShieldCheck} title="Verification">
        <ul className="plain m-0 p-0">
          {e.confidence_reasons.map((c) => {
            const r = reason(c);
            return (
              <li key={c} className="flex items-start gap-2 py-0.5">
                {r.ok ? <Check className="mt-0.5 size-3.5 shrink-0 text-good" aria-label="passed" /> : <CircleDashed className="mt-0.5 size-3.5 shrink-0 text-warning" aria-label="limited" />}
                {r.text}
              </li>
            );
          })}
          {e.producer_type === "approved_workflow" && !e.confidence_reasons.includes("attestation_verified") && (
            <li className="flex items-start gap-2 py-0.5 text-muted">
              <X className="mt-0.5 size-3.5 shrink-0" aria-label="not present" />
              Not signed: without a verified attestation the evidence stays at C2 (for example, private repositories without GitHub Enterprise Cloud cannot attest)
            </li>
          )}
        </ul>
      </Step>
      <Step icon={Link2} title="Append-only ledger">
        Record <span className="font-mono text-xs">{short(e.record_hash, 16)}</span>
        {" "}follows <span className="font-mono text-xs">{e.prev_hash ? short(e.prev_hash, 16) : "(first in chain)"}</span>
        <div className="mt-0.5 text-xs text-muted">Hash-chained and checkpointed daily outside the platform, so a silent edit is detectable.</div>
      </Step>
      <Step icon={ListChecks} title="Outcome" last>
        <span className="inline-flex flex-wrap items-center gap-2">
          <ConfidenceBadge level={e.confidence} />
          <span>{level?.meaning ?? ""}</span>
        </span>
        <div className="mt-1 text-xs text-muted">
          State {e.state}{e.valid_until ? ` until ${new Date(e.valid_until).toLocaleDateString()}` : ""} · used by {e.used_by_evaluations?.length ?? 0} control evaluation(s)
        </div>
      </Step>
    </ol>
  );
}
