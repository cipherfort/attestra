// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { FileCheck2, ShieldAlert, ShieldX } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";
import { ApiError, api, type EvidenceListItem, type EvidenceRejection } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { ConfidenceBadge } from "../components/domain/badges";
import { EvidenceChain } from "../components/domain/EvidenceChain";
import { evidenceLabel } from "../components/domain/evidence";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { TabPanel, Tabs } from "../components/ui/Tabs";

const when = (s: string | null | undefined) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "–");

/** Why a submission was refused, in words (evidence model section 4). */
export const REJECTIONS: Record<string, { title: string; meaning: string }> = {
  UNTRUSTED_PRODUCER: { title: "Untrusted producer", meaning: "Not produced by an approved security workflow, for example a copy of it kept in the application's own repository." },
  UNAPPROVED_WORKFLOW_REF: { title: "Unapproved workflow version", meaning: "An approved workflow, but at a commit that was never approved or has been revoked." },
  ATTESTATION_INVALID: { title: "Signature failed", meaning: "The signature did not verify against the approved workflow's identity." },
  DIGEST_MISMATCH: { title: "Tampered files", meaning: "A file's hash differs from the one in the signed manifest." },
  BINDING_MISMATCH: { title: "Wrong binding", meaning: "The manifest names a different repository, commit or run than the one it came from." },
  REJECTED_SIZE: { title: "Too large", meaning: "Over the size limit for an evidence bundle." },
  SCHEMA_INVALID: { title: "Invalid manifest", meaning: "The manifest doesn't match the evidence manifest schema." },
  OTHER: { title: "Refused", meaning: "Refused for another reason; see the details." },
};

export function EvidenceExplorer() {
  const params = useParams();
  const navigate = useNavigate();
  const tab = params.tab === "rejected" ? "rejected" : "accepted";
  const accepted = useQuery({ queryKey: ["all-evidence"], queryFn: () => api.allEvidence({ limit: 200 }) });
  const rejected = useQuery({ queryKey: ["rejections"], queryFn: () => api.rejections(undefined, 200) });
  const acceptedCols: ColumnDef<EvidenceListItem, unknown>[] = [
    { id: "type", header: "Evidence", accessorFn: (e) => evidenceLabel(e.type), filterFn: inSet<EvidenceListItem>(), cell: ({ row: { original: e } }) => (
      <div><Link to={`/evidence/${e.id}`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{evidenceLabel(e.type)}</Link>
        <div className="font-mono text-[11px] text-muted">{e.type}{e.repository ? ` · ${e.repository}` : ""}</div></div>
    ) },
    { id: "app", header: "Application", accessorFn: (e) => e.application_name ?? "", filterFn: inSet<EvidenceListItem>(), cell: ({ row: { original: e } }) => (e.app_key ? <Link to={`/apps/${e.app_key}`} className="text-ink-2 hover:text-accent-ink">{e.application_name}</Link> : <span className="text-muted">Unregistered</span>) },
    { id: "confidence", header: "Confidence", accessorKey: "confidence", filterFn: inSet<EvidenceListItem>(), cell: ({ getValue }) => <ConfidenceBadge level={String(getValue())} /> },
    { id: "state", header: "State", accessorKey: "state", filterFn: inSet<EvidenceListItem>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "observed", header: "Observed", accessorKey: "observed_at", cell: ({ getValue }) => <span className="text-ink-2">{when(String(getValue()))}</span> },
  ];
  const rejectedCols: ColumnDef<EvidenceRejection, unknown>[] = [
    { id: "reason", header: "Why it was refused", accessorKey: "reason_code", filterFn: inSet<EvidenceRejection>(), cell: ({ row: { original: r } }) => (
      <div className="flex items-start gap-2.5">
        <ShieldX className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden="true" />
        <div><div className="text-[13px] font-medium text-ink">{REJECTIONS[r.reason_code]?.title ?? r.reason_code}</div>
          <div className="text-xs text-muted">{REJECTIONS[r.reason_code]?.meaning}</div></div>
      </div>
    ) },
    { id: "where", header: "From", accessorFn: (r) => r.repository ?? "", cell: ({ row: { original: r } }) => (
      <div><span className="font-mono text-xs text-ink-2">{r.repository ?? "unknown repository"}</span>{r.run_id ? <div className="text-xs text-muted">run {r.run_id}</div> : null}</div>
    ) },
    { id: "app", header: "Application", accessorFn: (r) => r.application_name ?? "", filterFn: inSet<EvidenceRejection>(), cell: ({ row: { original: r } }) => (r.app_key ? <Link to={`/apps/${r.app_key}`} className="text-ink-2 hover:text-accent-ink">{r.application_name}</Link> : <span className="text-muted">–</span>) },
    { id: "received", header: "Received", accessorKey: "received_at", cell: ({ getValue }) => <span className="text-ink-2">{when(String(getValue()))}</span> },
  ];
  const nRejected = rejected.data?.length ?? 0;
  return (
    <>
      <PageHeader
        title="Evidence"
        description="Everything the platform received. Accepted evidence was verified (who produced it, which commit, whether it was signed) before it could count; rejected submissions were refused with a reason."
      />
      <Tabs
        label="Evidence"
        value={tab}
        onValueChange={(v) => void navigate(v === "accepted" ? "/evidence" : "/evidence/view/rejected", { replace: true })}
        tabs={[
          // the lists hold the newest 200; "+" says there may be more
          { value: "accepted", label: "Accepted", count: accepted.data?.length, more: accepted.data?.length === 200 },
          { value: "rejected", label: "Rejected", count: rejected.data?.length, more: rejected.data?.length === 200 },
        ]}
      >
        <TabPanel value="accepted">
          <Card bodyClassName="">
            {accepted.isPending ? <SkeletonRows rows={8} /> : (
              <DataTable
                data={accepted.data ?? []}
                columns={acceptedCols}
                label="evidence records"
                searchPlaceholder="Search evidence…"
                facets={[{ column: "confidence", title: "Confidence" }, { column: "type", title: "Type" }, { column: "app", title: "Application" }, { column: "state", title: "State" }]}
                initialSort={[{ id: "observed", desc: true }]}
                rowHref={(e) => `/evidence/${e.id}`}
                empty={<EmptyState icon={FileCheck2} title="No evidence yet">Evidence appears when the shipped pipelines run, connectors sync, or assessments are recorded.</EmptyState>}
              />
            )}
          </Card>
        </TabPanel>
        <TabPanel value="rejected" className="space-y-4">
          {nRejected > 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-critical/40 bg-surface p-4">
              <ShieldAlert className="mt-0.5 size-5 shrink-0 text-critical" aria-hidden="true" />
              <div className="text-[13px] text-ink-2">
                <div className="font-semibold text-ink">{nRejected} submission{nRejected === 1 ? " was" : "s were"} refused</div>
                Nothing here counts towards any control. A submission is accepted only when it comes from an approved
                workflow at an approved commit, matches its manifest and, where available, carries a valid signature. A
                refused submission can mean a misconfigured pipeline, or someone trying to pass off results the platform
                did not see produced.
              </div>
            </div>
          )}
          <Card bodyClassName="">
            {rejected.isPending ? <SkeletonRows rows={4} /> : (
              <DataTable
                data={rejected.data ?? []}
                columns={rejectedCols}
                label="rejected submissions"
                facets={[{ column: "reason", title: "Reason", label: (v) => REJECTIONS[v]?.title ?? v }, { column: "app", title: "Application" }]}
                initialSort={[{ id: "received", desc: true }]}
                empty={<EmptyState icon={ShieldX} title="Nothing rejected">Every submission so far came from an approved producer and verified.</EmptyState>}
              />
            )}
          </Card>
        </TabPanel>
      </Tabs>
    </>
  );
}

export function EvidencePage({ id }: { id: string }) {
  const ev = useQuery({ queryKey: ["evidence-detail", id], queryFn: () => api.evidence(id) });
  if (ev.isPending) return <SkeletonRows rows={8} />;
  if (ev.isError) {
    return (
      <EmptyState title="Evidence not found">
        {ev.error instanceof ApiError && ev.error.status === 404 ? "It doesn't exist, or it belongs to an application outside your scope." : String(ev.error)}
      </EmptyState>
    );
  }
  const e = ev.data;
  const code = `EV-${e.id.replaceAll("-", "").slice(-8).toUpperCase()}`;
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Evidence", to: "/evidence" }, { label: code }]}
        title={evidenceLabel(e.type)}
        meta={<><span className="font-mono text-xs text-muted">{code}</span><span>·</span><span className="font-mono text-xs">{e.type}</span><span>·</span><ConfidenceBadge level={e.confidence} /><span>·</span><span>{e.state}</span></>}
      />
      <div className="grid items-start gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3" title="How this evidence was verified" description="From the run that produced it to the record in the ledger">
          <EvidenceChain e={e} />
        </Card>
        <div className="space-y-4 xl:col-span-2">
          <Card title="Freshness history">
            {(e.validity_events ?? []).length ? (
              <ol className="plain m-0 space-y-2 p-0">
                {(e.validity_events ?? []).map((v, i) => (
                  <li key={i} className="text-[13px]"><span className="font-medium text-ink">{v.state}</span> <span className="text-ink-2">· {v.reason}</span><div className="text-xs text-muted">{when(v.at)}</div></li>
                ))}
              </ol>
            ) : <p className="m-0 text-xs text-muted">No changes since it was recorded.</p>}
          </Card>
          <Card title="Summary from the tool">
            <pre className="m-0 max-h-80 overflow-auto rounded-md bg-page p-3 font-mono text-[11px] text-ink-2">{JSON.stringify(e.summary, null, 2)}</pre>
          </Card>
        </div>
      </div>
    </>
  );
}
