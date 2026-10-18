// SPDX-License-Identifier: Apache-2.0
import { useQueries, useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Boxes, PackageSearch, Radar, Search, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ApiError, api, type AppSummary, type ComponentHit, type Sbom, type SbomComponent } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { TierBadge } from "../components/domain/badges";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { TabPanel, Tabs } from "../components/ui/Tabs";

const day = (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "–");
const fresh = (s: Sbom | undefined) => !!s && (s.freshness === "active" || s.freshness === "expiring") && s.component_count > 0;
const input = "h-9 w-full rounded-md border border-line bg-surface-2 pl-8 pr-3 text-[13px] text-ink placeholder:text-muted";

/** "pkg:npm/%40scope/name@1.2.3" → { name: "@scope/name", version: "1.2.3", eco: "npm" } */
export function purlParts(purl: string): { eco: string; name: string; version: string } {
  const m = /^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:[?#].*)?$/.exec(purl);
  if (!m) return { eco: "", name: purl, version: "" };
  return { eco: m[1] ?? "", name: decodeURIComponent(m[2] ?? ""), version: decodeURIComponent(m[3] ?? "") };
}

function Freshness({ s }: { s: Sbom | undefined }) {
  if (!s) return <span className="inline-flex items-center gap-1.5 text-xs text-ink-2"><ShieldQuestion className="size-3.5 text-muted" aria-hidden="true" />No SBOM</span>;
  if (fresh(s)) return <span className="inline-flex items-center gap-1.5 text-xs text-ink-2"><ShieldCheck className="size-3.5 text-good" aria-hidden="true" />Current</span>;
  return <span className="inline-flex items-center gap-1.5 text-xs text-ink-2"><ShieldQuestion className="size-3.5 text-serious" aria-hidden="true" />{s.component_count === 0 ? "Empty" : "Stale"}</span>;
}

interface Row { app: AppSummary; sbom: Sbom | undefined }

export function SupplyChain() {
  const params = useParams();
  const navigate = useNavigate();
  const tab = params.tab === "components" ? "components" : "sboms";
  const apps = useQuery({ queryKey: ["applications"], queryFn: api.applications });
  const sboms = useQueries({
    queries: (apps.data ?? []).map((a) => ({ queryKey: ["sboms", a.app_key], queryFn: () => api.sboms(a.app_key), staleTime: 60_000 })),
  });
  const rows: Row[] = (apps.data ?? []).map((a, i) => ({ app: a, sbom: sboms[i]?.data?.find((s) => s.is_current) }));
  const loading = apps.isPending || sboms.some((q) => q.isPending);
  const covered = rows.filter((r) => fresh(r.sbom)).length;
  const vulnerable = rows.reduce((n, r) => n + (r.sbom?.vulnerable_components ?? 0), 0);
  const cols: ColumnDef<Row, unknown>[] = [
    { id: "app", header: "Application", accessorFn: (r) => r.app.name, cell: ({ row: { original: r } }) => (
      <div><Link to={`/apps/${r.app.app_key}/supply-chain`} className="text-[13px] font-medium text-ink hover:text-accent-ink">{r.app.name}</Link>
        <div className="font-mono text-[11px] text-muted">{r.app.app_key}</div></div>
    ) },
    { id: "tier", header: "Tier", accessorFn: (r) => (r.app.tier === null ? "Unclassified" : `Tier ${r.app.tier}`), filterFn: inSet<Row>(), cell: ({ row: { original: r } }) => <TierBadge tier={r.app.tier} /> },
    { id: "state", header: "SBOM", accessorFn: (r) => (!r.sbom ? "No SBOM" : fresh(r.sbom) ? "Current" : "Stale"), filterFn: inSet<Row>(), cell: ({ row: { original: r } }) => <Freshness s={r.sbom} /> },
    { id: "components", header: "Components", accessorFn: (r) => r.sbom?.component_count ?? -1, cell: ({ row: { original: r } }) => <span className="tabular-nums text-ink-2">{r.sbom ? r.sbom.component_count : "–"}</span> },
    { id: "vulnerable", header: "With known vulnerabilities", accessorFn: (r) => r.sbom?.vulnerable_components ?? -1, cell: ({ row: { original: r } }) => {
      const n = r.sbom?.vulnerable_components;
      return n === undefined ? <span className="text-muted">–</span> : <span className={`tabular-nums ${n ? "font-semibold text-critical-ink" : "text-ink-2"}`}>{n}</span>;
    } },
    { id: "purl", header: "Identified (purl)", accessorFn: (r) => r.sbom?.purl_coverage_pct ?? -1, cell: ({ row: { original: r } }) => <span className="tabular-nums text-ink-2">{r.sbom?.purl_coverage_pct != null ? `${Math.round(r.sbom.purl_coverage_pct)}%` : "–"}</span> },
    { id: "generated", header: "Generated", accessorFn: (r) => r.sbom?.generated_at ?? "", cell: ({ row: { original: r } }) => <span className="text-ink-2">{day(r.sbom?.generated_at)}</span> },
  ];
  return (
    <>
      <PageHeader
        title="Supply chain"
        description="What every application is built from, according to its current SBOM. An application without a current SBOM is never reported as unaffected."
        actions={<Link to="/cve" className="inline-flex items-center gap-1.5 text-[13px] text-accent-ink hover:underline"><Radar className="size-4" aria-hidden="true" />Are we affected by a vulnerability?</Link>}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-3">
        <Kpi label="Applications with a current SBOM" value={loading ? "–" : `${covered} of ${rows.length}`} tone={!loading && covered < rows.length ? "critical" : undefined} sub="Others can only be reported as possibly affected" />
        <Kpi label="Components with known vulnerabilities" value={loading ? "–" : vulnerable} tone={vulnerable ? "critical" : undefined} sub="Across current SBOMs, matched against the vulnerability feeds" />
        <Kpi label="Components tracked" value={loading ? "–" : rows.reduce((n, r) => n + (r.sbom?.component_count ?? 0), 0)} sub="Summed over current SBOMs" />
      </div>
      <Tabs
        label="Supply chain"
        value={tab}
        onValueChange={(v) => void navigate(v === "sboms" ? "/supply-chain" : `/supply-chain/${v}`, { replace: true })}
        tabs={[{ value: "sboms", label: "SBOMs by application" }, { value: "components", label: "Find a component" }]}
      >
        <TabPanel value="sboms">
          <Card bodyClassName="">
            {loading ? <SkeletonRows rows={6} /> : (
              <DataTable
                data={rows}
                columns={cols}
                label="applications and their SBOMs"
                searchPlaceholder="Search applications…"
                facets={[{ column: "state", title: "SBOM" }, { column: "tier", title: "Tier" }]}
                initialSort={[{ id: "vulnerable", desc: true }]}
                rowHref={(r) => `/apps/${r.app.app_key}/supply-chain`}
                empty={<EmptyState icon={Boxes} title="No applications">Register an application and run the SBOM pipeline.</EmptyState>}
              />
            )}
          </Card>
        </TabPanel>
        <TabPanel value="components"><ComponentSearch /></TabPanel>
      </Tabs>
    </>
  );
}

function ComponentSearch() {
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const hits = useQuery({ queryKey: ["components", term], queryFn: () => api.components(`%${term}%`), enabled: term.length >= 2 });
  const cols: ColumnDef<ComponentHit, unknown>[] = [
    { id: "name", header: "Component", accessorFn: (c) => purlParts(c.purl).name, cell: ({ row: { original: c } }) => (
      <div><div className="text-[13px] font-medium text-ink">{purlParts(c.purl).name}</div><div className="break-all font-mono text-[11px] text-muted">{c.purl}</div></div>
    ) },
    { id: "version", header: "Version", accessorKey: "version", cell: ({ getValue }) => <span className="font-mono text-xs text-ink-2">{String(getValue())}</span> },
    { id: "eco", header: "Ecosystem", accessorKey: "ecosystem", filterFn: inSet<ComponentHit>() },
    { id: "apps", header: "Used by", accessorKey: "application_count", cell: ({ getValue }) => <span className="tabular-nums text-ink-2">{Number(getValue())} app{Number(getValue()) === 1 ? "" : "s"}</span> },
    { id: "vulns", header: "Known vulnerabilities", accessorKey: "known_vulnerabilities", cell: ({ getValue }) => {
      const n = Number(getValue());
      return <span className={`tabular-nums ${n ? "font-semibold text-critical-ink" : "text-ink-2"}`}>{n}</span>;
    } },
    { id: "licence", header: "Licence", accessorFn: (c) => c.licence ?? "", cell: ({ getValue }) => <span className="font-mono text-xs text-ink-2">{String(getValue()) || "–"}</span> },
  ];
  return (
    <Card bodyClassName="">
      <form className="flex gap-2 border-b border-line p-4" onSubmit={(e) => { e.preventDefault(); setTerm(q.trim()); }}>
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden="true" />
          <label htmlFor="component-q" className="sr-only">Component name</label>
          <input id="component-q" className={input} placeholder="Component name, for example log4j or pyyaml" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Button type="submit" variant="primary" disabled={q.trim().length < 2}>Search</Button>
      </form>
      {!term ? (
        <EmptyState icon={PackageSearch} title="Search every current SBOM">Find which versions of a library are in use, by how many applications, and whether any has a known vulnerability.</EmptyState>
      ) : hits.isPending ? <SkeletonRows rows={4} /> : hits.isError ? (
        <EmptyState title="Search failed">{String(hits.error)}</EmptyState>
      ) : (
        <DataTable
          data={hits.data ?? []}
          columns={cols}
          label="matching components"
          searchPlaceholder="Filter results…"
          facets={[{ column: "eco", title: "Ecosystem" }]}
          initialSort={[{ id: "vulns", desc: true }]}
          empty={<EmptyState icon={PackageSearch} title={`Nothing matches “${term}”`}>No current SBOM lists a component with that name.</EmptyState>}
        />
      )}
    </Card>
  );
}

/** The application's current SBOM, component by component (Application → Supply chain tab). */
export function SbomPanel({ appKey }: { appKey: string }) {
  const sboms = useQuery({ queryKey: ["sboms", appKey], queryFn: () => api.sboms(appKey), staleTime: 60_000 });
  const current = sboms.data?.filter((s) => s.is_current) ?? [];
  const comps = useQueries({ queries: current.map((s) => ({ queryKey: ["sbom-components", s.id], queryFn: () => api.sbomComponents(s.id), staleTime: 60_000 })) });
  const items: (SbomComponent & { sbom: string })[] = current.flatMap((s, i) => (comps[i]?.data ?? []).map((c) => ({ ...c, sbom: s.scope_key })));
  const cols: ColumnDef<SbomComponent & { sbom: string }, unknown>[] = [
    { id: "name", header: "Component", accessorFn: (c) => purlParts(c.purl).name, cell: ({ row: { original: c } }) => (
      <div><div className="text-[13px] font-medium text-ink">{purlParts(c.purl).name}</div><div className="break-all font-mono text-[11px] text-muted">{c.purl}</div></div>
    ) },
    { id: "version", header: "Version", accessorFn: (c) => purlParts(c.purl).version, cell: ({ getValue }) => <span className="font-mono text-xs text-ink-2">{String(getValue()) || "–"}</span> },
    { id: "eco", header: "Ecosystem", accessorFn: (c) => purlParts(c.purl).eco, filterFn: inSet<SbomComponent & { sbom: string }>() },
    { id: "direct", header: "Dependency", accessorFn: (c) => (c.direct === true ? "Direct" : c.direct === false ? "Transitive" : "Unknown"), filterFn: inSet<SbomComponent & { sbom: string }>() },
    { id: "vulns", header: "Known vulnerabilities", accessorFn: (c) => (c.vulnerabilities ?? []).length, cell: ({ row: { original: c } }) => (
      (c.vulnerabilities ?? []).length ? (
        <div className="flex flex-wrap gap-1">{(c.vulnerabilities ?? []).map((v) => (
          <Link key={v} to={`/cve/${v}`} className="inline-flex items-center gap-1 rounded border border-critical/40 bg-surface-2 px-1.5 py-px font-mono text-[11px] text-critical-ink hover:underline">
            <ShieldAlert className="size-3" aria-hidden="true" />{v}
          </Link>
        ))}</div>
      ) : <span className="text-muted">None known</span>
    ) },
    { id: "licence", header: "Licence", accessorFn: (c) => c.licence ?? "", cell: ({ getValue }) => <span className="font-mono text-xs text-ink-2">{String(getValue()) || "–"}</span> },
  ];
  if (sboms.isPending || comps.some((q) => q.isPending)) return <Card><SkeletonRows rows={6} /></Card>;
  if (sboms.isError) return <Card><EmptyState title="Couldn't load SBOMs">{sboms.error instanceof ApiError ? sboms.error.title : String(sboms.error)}</EmptyState></Card>;
  if (!current.length) {
    return (
      <Card>
        <EmptyState icon={ShieldQuestion} title="No current SBOM">
          Until the SBOM pipeline runs for this application, "Are we affected?" can only report it as possibly affected.
        </EmptyState>
      </Card>
    );
  }
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {current.map((s) => (
          <div key={s.id} className="rounded-xl border border-line bg-surface px-5 py-4 text-[13px]">
            <div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-xs text-ink-2">{s.scope_key}</span><Freshness s={s} /></div>
            <div className="mt-2 text-ink">{s.format === "cyclonedx" ? "CycloneDX" : "SPDX"} {s.spec_version} · {s.component_count} components</div>
            <div className="mt-1 text-xs text-muted">
              Generated {day(s.generated_at)}{s.commit_sha ? <> at <span className="font-mono">{s.commit_sha.slice(0, 10)}</span></> : null}
              {s.purl_coverage_pct != null ? ` · ${Math.round(s.purl_coverage_pct)}% identified by purl` : ""}
            </div>
            <Link to={`/evidence/${s.evidence_id}`} className="mt-2 inline-block text-xs text-accent-ink hover:underline">How this SBOM was verified</Link>
          </div>
        ))}
      </div>
      <Card bodyClassName="">
        <DataTable
          data={items}
          columns={cols}
          label="SBOM components"
          searchPlaceholder="Search components…"
          facets={[{ column: "eco", title: "Ecosystem" }, { column: "direct", title: "Dependency" }]}
          initialSort={[{ id: "vulns", desc: true }]}
          csv={{ filename: `${appKey}-components.csv`, row: (c) => ({ purl: c.purl, direct: c.direct, scope: c.scope, licence: c.licence, vulnerabilities: (c.vulnerabilities ?? []).join(" ") }) }}
        />
      </Card>
    </div>
  );
}

const REASON: Record<string, string> = {
  no_sbom: "No SBOM has ever been received",
  stale_sbom: "Its SBOM is older than its freshness window",
};

/** "Are we affected?": one vulnerability against every current SBOM in scope. Unknown is never reported as safe. */
export function CvePage({ initial }: { initial?: string }) {
  const navigate = useNavigate();
  const id = initial ?? "CVE-2021-44228";
  const [q, setQ] = useState(id);
  const impact = useQuery({ queryKey: ["impact", id], queryFn: () => api.impact(id), retry: false });
  const r = impact.data;
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Supply chain", to: "/supply-chain" }, { label: "Are we affected?" }]}
        title="Are we affected?"
        description="Checks a vulnerability against every application's current SBOM. Applications with no SBOM, or a stale one, are listed as possibly affected, never as unaffected. You only see applications in your scope."
      />
      <Card className="mb-4" bodyClassName="p-4">
        <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); if (q.trim()) void navigate(`/cve/${encodeURIComponent(q.trim())}`); }}>
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden="true" />
            <label htmlFor="vuln" className="sr-only">CVE, GHSA or OSV id</label>
            <input id="vuln" className={input} placeholder="CVE, GHSA or OSV id" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <Button type="submit" variant="primary">Check</Button>
        </form>
      </Card>
      {impact.isPending ? <SkeletonRows rows={6} /> : impact.isError ? (
        <Card>
          <EmptyState icon={ShieldQuestion} title={`${id} isn't known to the platform`}>
            {impact.error instanceof ApiError && impact.error.status === 404
              ? "It isn't in the vulnerability feeds the platform has synced. Check the id, or wait for the next feed sync."
              : String(impact.error)}
          </EmptyState>
        </Card>
      ) : r && (
        <div className="space-y-4">
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="m-0 font-mono text-base font-semibold text-ink">{r.vulnerability.vuln_key}</h2>
              {r.vulnerability.in_kev && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-critical/50 bg-surface-2 px-2 py-0.5 text-xs font-medium text-critical-ink">
                  <ShieldAlert className="size-3.5" aria-hidden="true" />Known exploited (CISA KEV)
                </span>
              )}
            </div>
            {r.vulnerability.title && <p className="m-0 mt-2 text-[13px] text-ink-2">{r.vulnerability.title}</p>}
            <dl className="m-0 mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs">
              <div className="flex gap-1.5"><dt className="text-muted">CVSS</dt><dd className="m-0 text-ink">{String(r.vulnerability.cvss_v3_score ?? "–")}</dd></div>
              <div className="flex gap-1.5"><dt className="text-muted">EPSS percentile</dt><dd className="m-0 text-ink">{r.vulnerability.epss_percentile == null ? "–" : `${Math.round(Number(r.vulnerability.epss_percentile) * 100)}%`}</dd></div>
              <div className="flex gap-1.5"><dt className="text-muted">Aliases</dt><dd className="m-0 font-mono text-ink">{r.vulnerability.aliases.join(", ") || "none"}</dd></div>
            </dl>
          </Card>
          <div className="grid gap-4 md:grid-cols-3">
            <Kpi label="Affected" value={r.affected.length} tone={r.affected.length ? "critical" : undefined} sub="A current SBOM lists a vulnerable version" />
            <Kpi label="Possibly affected" value={r.possibly_affected.length} sub="No SBOM, or a stale one: unknown" />
            <Kpi label="Not affected" value={r.not_affected_count} tone="good" sub="A current SBOM, and no match" />
          </div>
          {r.affected.length > 0 && (
            <Card title="Affected" description="Upgrade to a fixed version, or record an exception with a plan" bodyClassName="">
              <div className="overflow-x-auto">
                <table className="w-full text-[13px]">
                  <thead><tr className="border-b border-line text-left text-xs text-muted">
                    <th className="px-5 py-2 font-medium">Application</th><th className="px-3 py-2 font-medium">Tier</th><th className="px-3 py-2 font-medium">Exposure</th>
                    <th className="px-3 py-2 font-medium">Component</th><th className="px-5 py-2 font-medium">Fixed in</th>
                  </tr></thead>
                  <tbody>
                    {r.affected.flatMap((x) => x.components.map((c) => (
                      <tr key={x.application.id + c.purl} className="border-b border-line last:border-b-0">
                        <td className="px-5 py-2.5"><Link to={`/apps/${x.application.app_key}/supply-chain`} className="font-medium text-ink hover:text-accent-ink">{x.application.name}</Link></td>
                        <td className="px-3 py-2.5"><TierBadge tier={x.application.tier} /></td>
                        <td className="px-3 py-2.5 text-ink-2">{x.application.exposure?.replaceAll("_", " ")}</td>
                        <td className="break-all px-3 py-2.5 font-mono text-xs text-ink-2">{c.purl}</td>
                        <td className="px-5 py-2.5 text-ink-2">{c.fixed_versions.join(", ") || "No fix published"}</td>
                      </tr>
                    )))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
          {r.possibly_affected.length > 0 && (
            <Card title="Possibly affected" description="Run the SBOM pipeline for these applications to find out" bodyClassName="px-5 py-1">
              <ul className="plain m-0 p-0">
                {r.possibly_affected.map((x) => (
                  <li key={x.application.id} className="flex items-center gap-3 border-b border-line py-2.5 text-[13px] last:border-b-0">
                    <ShieldQuestion className="size-4 shrink-0 text-serious" aria-hidden="true" />
                    <Link to={`/apps/${x.application.app_key}/supply-chain`} className="min-w-0 flex-1 truncate font-medium text-ink hover:text-accent-ink">{x.application.name}</Link>
                    <TierBadge tier={x.application.tier} />
                    <span className="w-72 text-xs text-ink-2">{REASON[x.reason] ?? x.reason}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
