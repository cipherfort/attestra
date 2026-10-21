// SPDX-License-Identifier: Apache-2.0
import { useQueries, useQuery } from "@tanstack/react-query";
import { Activity, Boxes, FileCheck2, FileX2, ShieldAlert, ShieldCheck, Users, XCircle } from "lucide-react";
import { Link } from "react-router";
import { api, type ActivityItem, type ControlItem, type OrgUnitRow, type PostureTrend } from "../api";
import { BulletBars } from "../components/charts/BulletBars";
import { Heatmap } from "../components/charts/Heatmap";
import { LineChart } from "../components/charts/LineChart";
import { ConfidenceBadge, PriorityChip } from "../components/domain/badges";
import { evidenceLabel } from "../components/domain/evidence";
import { ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Kpi } from "../components/ui/Kpi";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, Skeleton } from "../components/ui/States";
import { GettingStarted } from "../components/domain/GettingStarted";
import { useMe } from "../hooks/useMe";

export const DOMAINS: Record<string, string> = {
  GOV: "Governance & registration", REQ: "Security requirements", TM: "Threat modelling", ARC: "Architecture",
  SRC: "Source & repository", BLD: "Build & supply chain", DEP: "Deployment", TST: "Security testing",
  VUL: "Vulnerability management", OPS: "Operations",
};

const pct = (n: number) => `${Math.round(n)}%`;
const month = (p: string) => new Date(`${p}-01T00:00:00Z`).toISOString();

/** The unit an aggregate view starts from: the organisation for org-wide roles, otherwise the highest unit in scope. */
export function topUnit(units: OrgUnitRow[]): OrgUnitRow | undefined {
  const ids = new Set(units.map((u) => u.id));
  return units.find((u) => !u.parent_id) ?? units.find((u) => !u.parent_id || !ids.has(u.parent_id));
}

function series(t: PostureTrend | undefined, metric: string): (number | null)[] {
  return t?.metrics[metric] ?? [];
}

function coverage(t: PostureTrend | undefined): (number | null)[] {
  const sat = series(t, "mandatory_satisfied"), tot = series(t, "mandatory_total");
  return tot.map((n, i) => (n ? ((sat[i] ?? 0) / n) * 100 : null));
}

const last = (xs: (number | null)[]) => [...xs].reverse().find((v) => v !== null) ?? null;
const spark = (xs: (number | null)[]) => xs.filter((v): v is number => v !== null).slice(-12);

const KIND: Record<ActivityItem["kind"], { icon: typeof Activity; tone: string; label: string }> = {
  evidence_accepted: { icon: FileCheck2, tone: "text-good", label: "Evidence accepted" },
  evidence_rejected: { icon: FileX2, tone: "text-critical", label: "Evidence rejected" },
  finding_opened: { icon: ShieldAlert, tone: "text-serious", label: "Finding opened" },
  finding_closed: { icon: ShieldCheck, tone: "text-good", label: "Finding closed" },
  exception_approved: { icon: ShieldCheck, tone: "text-accent", label: "Exception approved" },
  exception_rejected: { icon: XCircle, tone: "text-muted", label: "Exception rejected" },
  exception_expired: { icon: XCircle, tone: "text-serious", label: "Exception expired" },
};

function when(at: string): string {
  const mins = Math.round((Date.now() - new Date(at).getTime()) / 60_000);
  if (mins < 60) return `${Math.max(mins, 1)}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return new Date(at).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function Overview() {
  const me = useMe();
  const perms = new Set(me.data?.permissions ?? []);
  const canApps = perms.has("application.read");
  const canRollup = perms.has("maturity.rollup.read");
  const units = useQuery({ queryKey: ["units"], queryFn: api.visibleUnits, enabled: canRollup });
  const unit = units.data ? topUnit(units.data) : undefined;
  const trend = useQuery({ queryKey: ["trend", unit?.id], queryFn: () => api.unitTrend(unit!.id), enabled: !!unit });
  const apps = useQuery({ queryKey: ["applications"], queryFn: api.applications, enabled: canApps });
  const risks = useQuery({ queryKey: ["risks"], queryFn: () => api.openFindings("P1,P2"), enabled: canApps });
  const feed = useQuery({ queryKey: ["activity"], queryFn: () => api.activity(undefined, 8), enabled: canApps });
  const classified = (apps.data ?? []).filter((a) => a.tier !== null).slice(0, 12);
  const controls = useQueries({
    queries: classified.map((a) => ({ queryKey: ["controls", a.app_key], queryFn: () => api.controls(a.app_key), staleTime: 60_000 })),
  });

  if (me.isPending) return <Skeleton className="h-96 w-full" />;
  if (canApps && apps.data && apps.data.length === 0) {
    // The set-up checklist is for the people who set the platform up; anyone else simply has no applications in
    // their scope yet (usually: not in a team), and needs to know who can change that.
    if (!perms.has("integration.read")) {
      return (
        <>
          <PageHeader title="Overview" />
          <Card>
            <EmptyState
              icon={Users}
              title="No applications to show you yet"
              action={perms.has("application.register") && <ButtonLink to="/register" size="sm">Register an application</ButtonLink>}
            >
              You see the applications of the teams you belong to. Ask a platform administrator to add you to your team
              {perms.has("application.register") ? ", or register your team's application." : "."}
            </EmptyState>
          </Card>
        </>
      );
    }
    return (
      <>
        <PageHeader title="Overview" />
        <GettingStarted perms={perms} apps={0} />
      </>
    );
  }

  if (!canApps && !canRollup && perms.has("org.admin")) {
    return (
      <>
        <PageHeader title="Overview" description="As a platform administrator you manage sign-in, integrations and the organisation; application data is visible only to the roles that work with it." />
        <GettingStarted perms={perms} apps={null} />
      </>
    );
  }

  const t = trend.data;
  const cov = coverage(t);
  const p1 = series(t, "findings_open_p1");
  const late = series(t, "findings_past_sla");
  const rejected = series(t, "evidence_rejected");
  const fromApps = (apps.data ?? []).reduce(
    (s, a) => ({ sat: s.sat + (a.mandatory_controls?.satisfied ?? 0), tot: s.tot + Object.values(a.mandatory_controls ?? {}).reduce((x, n) => x + (n ?? 0), 0), p1: s.p1 + (a.open_findings?.P1 ?? 0), sla: s.sla + a.sla_breaches }),
    { sat: 0, tot: 0, p1: 0, sla: 0 },
  );
  const coverageNow = last(cov) ?? (fromApps.tot ? (fromApps.sat / fromApps.tot) * 100 : null);
  const dates = (t?.periods ?? []).map(month);

  const domainCell = (appKey: string, domain: string): number | null => {
    const i = classified.findIndex((a) => a.app_key === appKey);
    const items: ControlItem[] = controls[i]?.data?.items ?? [];
    const mand = items.filter((c) => c.requirement === "mandatory" && c.control_key.split("-")[1] === domain);
    if (!mand.length) return null;
    return mand.filter((c) => c.state === "satisfied").length / mand.length;
  };
  const domainDetail = (appKey: string, domain: string): string => {
    const i = classified.findIndex((a) => a.app_key === appKey);
    const items = (controls[i]?.data?.items ?? []).filter((c) => c.requirement === "mandatory" && c.control_key.split("-")[1] === domain);
    return `${items.filter((c) => c.state === "satisfied").length} of ${items.length} mandatory controls proven`;
  };

  return (
    <>
      <PageHeader
        title="Overview"
        description={unit ? `Security posture for ${unit.name}, from verified evidence. Trends are monthly; the current month updates as evidence arrives.` : "Security posture from verified evidence."}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Kpi label="Mandatory controls proven" value={coverageNow === null ? "–" : pct(coverageNow)} trend={spark(cov)} sub={t ? "Across every classified application" : `${fromApps.sat} of ${fromApps.tot}`} />
        <Kpi label="Open P1 findings" value={last(p1) ?? fromApps.p1} tone={(last(p1) ?? fromApps.p1) ? "critical" : undefined} trend={spark(p1)} sub="Fix within 7 days" />
        <Kpi label="Findings past their deadline" value={last(late) ?? fromApps.sla} tone={(last(late) ?? fromApps.sla) ? "critical" : "good"} trend={spark(late)} sub="Need escalation" />
        <Kpi label="Evidence rejected this month" value={last(rejected) ?? "–"} trend={spark(rejected)} sub="Forged, unapproved or tampered" />
      </div>

      {t && (
        <div className="mb-6 grid gap-4 xl:grid-cols-2">
          <Card title="Mandatory controls proven" description="Share of mandatory controls that current, verified evidence satisfies">
            <LineChart label="Mandatory controls proven by month" dates={dates} yMax={100} format={(v) => pct(v)} series={[{ key: "cov", label: "Controls proven", color: "var(--series-1)", values: cov }]} />
          </Card>
          <Card title="Open findings by priority" description="At each month end">
            <LineChart
              label="Open findings by priority by month"
              dates={dates}
              format={(v) => String(Math.round(v))}
              integer
              series={[
                // validated categorical slots (status colours fail the separation check as lines); labels carry identity
                { key: "p1", label: "P1", color: "var(--series-1)", values: p1 },
                { key: "p2", label: "P2", color: "var(--series-2)", values: series(t, "findings_open_p2") },
                { key: "p3", label: "P3", color: "var(--series-3)", values: series(t, "findings_open_p3") },
              ]}
            />
          </Card>
        </div>
      )}

      <div className="mb-6 grid items-start gap-4 xl:grid-cols-5">
        {t && (
          <Card className="xl:col-span-3" title="SAMM maturity by business function" description="Average over the applications in scope, 0–3, computed from evidence and assessments">
            <BulletBars
              label="SAMM maturity by business function"
              valueLabel="Maturity (0–3)"
              items={t.samm_functions.map((f) => ({ key: f.item, label: f.name ?? f.item, value: last(f.values) ?? 0, target: null }))}
            />
          </Card>
        )}
        {canApps && (
          <Card className={t ? "xl:col-span-2" : "xl:col-span-5"} title="Recent activity" bodyClassName="px-2 py-1">
            {feed.data?.length ? (
              <ul className="plain m-0 p-0">
                {feed.data.map((x, i) => {
                  const k = KIND[x.kind];
                  const href = x.kind.startsWith("evidence_accepted") && x.ref ? `/evidence/${x.ref}` : x.kind.startsWith("finding") && x.ref ? `/findings/${x.ref}` : x.app_key ? `/apps/${x.app_key}` : undefined;
                  return (
                    <li key={`${x.ref}-${i}`} className="flex items-start gap-3 rounded-md px-3 py-2 hover:bg-surface-2">
                      <k.icon className={`mt-0.5 size-4 shrink-0 ${k.tone}`} strokeWidth={1.75} aria-label={k.label} />
                      <div className="min-w-0 flex-1">
                        {(() => {
                          const title = x.kind === "evidence_accepted" ? evidenceLabel(x.evidence_type) : x.title;
                          return (
                            <div className="flex items-center gap-2">
                              <span className="truncate text-[13px] text-ink">{href ? <Link to={href} className="text-ink hover:text-accent-ink">{title}</Link> : title}</span>
                              {x.confidence && <ConfidenceBadge level={x.confidence} />}
                            </div>
                          );
                        })()}
                        <div className="text-xs text-muted">{k.label}{x.application_name ? ` · ${x.application_name}` : ""}</div>
                      </div>
                      <time dateTime={x.at} className="shrink-0 text-xs text-muted">{when(x.at)}</time>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <EmptyState icon={Activity} title="Nothing yet">Evidence, findings and exception decisions appear here as they happen.</EmptyState>
            )}
          </Card>
        )}
      </div>

      {canApps && classified.length > 0 && (
        <div className="grid items-start gap-4 xl:grid-cols-5">
          <Card className="xl:col-span-3" title="Coverage by control domain" description="Mandatory controls proven per application and domain. Select a cell to open the application.">
            <Heatmap
              label="Mandatory controls proven by application and control domain"
              rows={classified.map((a) => ({ key: a.app_key, label: a.name }))}
              columns={Object.entries(DOMAINS).map(([k, v]) => ({ key: k, label: k, title: v }))}
              value={domainCell}
              detail={domainDetail}
              onCell={(app) => { window.location.assign(`/apps/${app}`); }}
            />
          </Card>
          <Card className="xl:col-span-2" title="Top risks" description="Open P1 and P2 findings, nearest deadline first" bodyClassName="px-2 py-1">
            {risks.data?.length ? (
              <ul className="plain m-0 p-0">
                {[...risks.data].sort((a, b) => String(a.sla_due_at ?? "").localeCompare(String(b.sla_due_at ?? ""))).slice(0, 8).map((f) => (
                  <li key={f.id} className="flex items-start gap-3 rounded-md px-3 py-2 hover:bg-surface-2">
                    <PriorityChip p={f.priority} due={f.sla_due_at} />
                    <div className="min-w-0 flex-1">
                      <Link to={`/findings/${f.id}`} className="block truncate text-[13px] text-ink hover:text-accent-ink">{f.title}</Link>
                      <div className="text-xs text-muted">{f.application_name}</div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState icon={Boxes} title="No open P1 or P2 findings">Nothing urgent across the applications you can see.</EmptyState>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
