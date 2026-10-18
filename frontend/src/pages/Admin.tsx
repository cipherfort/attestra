// SPDX-License-Identifier: Apache-2.0
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Building2, ChevronRight, Search, UserMinus, UserPlus, UsersRound } from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { api, type AdminUser, type Grant, type OrgUnit } from "../api";
import { DataTable, inSet } from "../components/data/DataTable";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field, LoadError, Notice, errorText, inputClass, selectClass } from "../components/ui/Form";
import { PageHeader } from "../components/ui/PageHeader";
import { EmptyState, SkeletonRows } from "../components/ui/States";
import { TabPanel, Tabs } from "../components/ui/Tabs";

const ROLES: Record<string, string> = {
  engineer: "Engineer", champion: "Security champion", app_owner: "Application owner", unit_lead: "Unit lead",
  appsec_engineer: "AppSec engineer", security_leadership: "Security leadership", governance_analyst: "Governance analyst",
  auditor: "Auditor", executive: "Executive", platform_admin: "Platform administrator",
};
const SCOPED = new Set(["champion", "engineer", "unit_lead", "app_owner"]);
const label = (s: string) => s.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
const day = (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "–");

/** Organisation structure and access. Platform administrators are assigned in the identity provider, never here. */
export function Admin() {
  const params = useParams();
  const navigate = useNavigate();
  const tab = params.tab === "roles" ? "roles" : "organisation";
  const units = useQuery({ queryKey: ["admin-units"], queryFn: api.orgUnits });
  return (
    <>
      <PageHeader
        title="Administration"
        description="Units and membership decide what each person can see. Every change is audited. You can't change your own roles, and platform administrators are assigned in the identity provider."
      />
      <Tabs
        label="Administration"
        value={tab}
        onValueChange={(v) => void navigate(v === "roles" ? "/admin/roles" : "/admin", { replace: true })}
        tabs={[{ value: "organisation", label: "Organisation", count: units.data?.items.length }, { value: "roles", label: "Role grants" }]}
      >
        <TabPanel value="organisation">
          {units.isPending ? <SkeletonRows rows={8} /> : units.isError ? <LoadError error={units.error} /> : <Organisation units={units.data.items} levels={units.data.levels} />}
        </TabPanel>
        <TabPanel value="roles"><Grants units={units.data?.items ?? []} /></TabPanel>
      </Tabs>
    </>
  );
}

function Organisation({ units, levels }: { units: OrgUnit[]; levels: string[] }) {
  const [selected, setSelected] = useState<string | null>(units.find((u) => !u.parent)?.slug ?? null);
  const children = (parent: string | null) => units.filter((u) => u.parent === parent).sort((a, b) => a.name.localeCompare(b.name));
  const render = (u: OrgUnit, depth: number): React.ReactNode => (
    <li key={u.slug}>
      <button
        type="button"
        onClick={() => setSelected(u.slug)}
        aria-current={selected === u.slug ? "true" : undefined}
        className={`flex w-full items-center gap-2 rounded-md py-1.5 pr-2 text-left text-[13px] ${selected === u.slug ? "bg-accent-soft text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"}`}
        style={{ paddingLeft: `${0.5 + depth * 1.1}rem` }}
      >
        {depth > 0 && <ChevronRight className="size-3 shrink-0 text-muted" aria-hidden="true" />}
        <span className="min-w-0 flex-1 truncate font-medium">{u.name}</span>
        <span className={`shrink-0 text-xs ${selected === u.slug ? "text-ink-2" : "text-muted"}`}>{label(u.unit_type)} · {u.members} {u.members === 1 ? "person" : "people"} · {u.applications} app{u.applications === 1 ? "" : "s"}</span>
      </button>
      {children(u.slug).length > 0 && <ul className="plain m-0 p-0">{children(u.slug).map((c) => render(c, depth + 1))}</ul>}
    </li>
  );
  const unit = units.find((u) => u.slug === selected);
  return (
    <div className="grid items-start gap-4 xl:grid-cols-5">
      <div className="space-y-4 xl:col-span-3">
        <Card title="Units" description="Moving a unit under another parent is a database migration, because it changes the scope of every application below it." bodyClassName="p-2">
          <ul className="plain m-0 p-0" aria-label="Organisation units">{children(null).map((u) => render(u, 0))}</ul>
        </Card>
        <NewUnit units={units} levels={levels} />
      </div>
      <div className="xl:col-span-2">
        {unit ? <Members unit={unit} /> : <Card><EmptyState icon={Building2} title="Choose a unit">Its members appear here.</EmptyState></Card>}
      </div>
    </div>
  );
}

function NewUnit({ units, levels }: { units: OrgUnit[]; levels: string[] }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ slug: "", name: "", unit_type: levels[1] ?? "", parent: "" });
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const parentType = levels[levels.indexOf(form.unit_type) - 1];
  const parents = units.filter((u) => u.unit_type === parentType);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createOrgUnit(form);
      setMsg({ ok: true, text: `Added ${form.name}` });
      setForm({ ...form, slug: "", name: "" });
      void qc.invalidateQueries({ queryKey: ["admin-units"] });
    } catch (err) { setMsg({ ok: false, text: errorText(err) }); }
  };
  return (
    <Card title="Add a unit">
      <form onSubmit={create} className="grid gap-4 md:grid-cols-2">
        <Field id="unit-type" label="Kind of unit">
          <select id="unit-type" value={form.unit_type} onChange={(e) => setForm({ ...form, unit_type: e.target.value, parent: "" })} className={selectClass}>
            {levels.slice(1).map((l) => <option key={l} value={l}>{label(l)}</option>)}
          </select>
        </Field>
        <Field id="unit-parent" label="Inside">
          <select id="unit-parent" required value={form.parent} onChange={(e) => setForm({ ...form, parent: e.target.value })} className={selectClass}>
            <option value="">Choose…</option>{parents.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
          </select>
        </Field>
        <Field id="unit-name" label="Name"><input id="unit-name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} /></Field>
        <Field id="unit-slug" label="Slug" hint="Used in application.yaml; lowercase letters, digits and hyphens">
          <input id="unit-slug" required pattern="[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} className={`${inputClass} font-mono`} />
        </Field>
        <div className="md:col-span-2 flex items-center gap-3">
          <Button type="submit" variant="primary">Add unit</Button>
          {msg && <span className={`text-xs ${msg.ok ? "text-good-ink" : "text-critical-ink"}`} role={msg.ok ? "status" : "alert"}>{msg.text}</span>}
        </div>
      </form>
    </Card>
  );
}

function UserPicker({ onPick, id, label: text }: { onPick: (u: AdminUser) => void; id: string; label: string }) {
  const [q, setQ] = useState("");
  const [found, setFound] = useState<AdminUser[] | null>(null);
  const search = () => void api.users(q).then(setFound);
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-ink-2">{text}</label>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input id={id} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); search(); } }} placeholder="Name, email or login" className={`${inputClass} pl-8`} />
        </div>
        <Button onClick={search} disabled={!q.trim()}>Find</Button>
      </div>
      {found && (
        found.length ? (
          <ul className="plain m-0 mt-2 rounded-md border border-line p-1">
            {found.map((u) => (
              <li key={u.id}>
                <button type="button" onClick={() => { onPick(u); setFound(null); setQ(""); }} className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-[13px] hover:bg-surface-2">
                  <span className="text-ink">{u.display_name}</span><span className="truncate text-xs text-muted">{u.email ?? u.logins.join(", ")}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : <p className="m-0 mt-2 text-xs text-muted">Nobody matches.</p>
      )}
    </div>
  );
}

function Members({ unit }: { unit: OrgUnit }) {
  const qc = useQueryClient();
  const members = useQuery({ queryKey: ["members", unit.slug], queryFn: () => api.members(unit.slug) });
  const [msg, setMsg] = useState<string | null>(null);
  const change = async (userId: string, present: boolean) => {
    try {
      await api.setMember(unit.slug, userId, present);
      setMsg(null);
      void qc.invalidateQueries({ queryKey: ["members", unit.slug] });
      void qc.invalidateQueries({ queryKey: ["admin-units"] });
    } catch (err) { setMsg(errorText(err)); }
  };
  return (
    <Card title={`Members of ${unit.name}`} description={unit.idp_group_id || unit.scm_group ? `Also synced from ${[unit.idp_group_id && "the identity provider group", unit.scm_group && `the ${unit.scm_group} team`].filter(Boolean).join(" and ")}` : "Membership is managed here"}>
      {members.isPending ? <SkeletonRows rows={4} /> : members.isError ? <LoadError error={members.error} /> : members.data.length ? (
        <ul className="plain m-0 mb-4 p-0">
          {members.data.map((m) => (
            <li key={m.user_id} className="flex items-center gap-3 border-b border-line py-2 last:border-b-0">
              <span className="flex size-7 items-center justify-center rounded-full bg-surface-3 text-[11px] font-semibold text-ink-2" aria-hidden="true">{m.display_name.split(" ").map((p) => p[0]).slice(0, 2).join("")}</span>
              <span className="min-w-0 flex-1 truncate text-[13px] text-ink">{m.display_name}</span>
              <span className="text-xs text-muted">{m.source}</span>
              <Button size="sm" variant="ghost" onClick={() => void change(m.user_id, false)} aria-label={`Remove ${m.display_name}`}><UserMinus className="size-3.5" aria-hidden="true" /></Button>
            </li>
          ))}
        </ul>
      ) : <div className="mb-4"><EmptyState icon={UsersRound} title="No members yet" /></div>}
      <UserPicker id="add-member" label="Add a member" onPick={(u) => void change(u.id, true)} />
      {msg && <div className="mt-3"><Notice tone="error">{msg}</Notice></div>}
    </Card>
  );
}

function Grants({ units }: { units: OrgUnit[] }) {
  const qc = useQueryClient();
  const grants = useQuery({ queryKey: ["grants"], queryFn: api.grants });
  const [who, setWho] = useState<AdminUser | null>(null);
  const [role, setRole] = useState("champion");
  const [unit, setUnit] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["grants"] });
  const grant = async () => {
    if (!who) return;
    try {
      await api.grant({ principal_type: "user", principal_id: who.id, role, org_unit: SCOPED.has(role) ? unit : undefined });
      setMsg({ ok: true, text: `${ROLES[role] ?? role} granted to ${who.display_name}` }); setWho(null); refresh();
    } catch (err) { setMsg({ ok: false, text: errorText(err) }); }
  };
  const revoke = (g: Grant) => void api.revokeGrant(g.id).then(refresh, (e: unknown) => setMsg({ ok: false, text: errorText(e) }));
  const unitName = (slug: string | null) => (slug ? units.find((u) => u.slug === slug)?.name ?? slug : "Organisation-wide");
  const cols: ColumnDef<Grant, unknown>[] = [
    { id: "who", header: "Who", accessorFn: (g) => g.principal_name ?? `${g.principal_type} ${g.principal_id}`, cell: ({ getValue }) => <span className="text-[13px] font-medium text-ink">{String(getValue())}</span> },
    { id: "role", header: "Role", accessorFn: (g) => ROLES[g.role] ?? g.role, filterFn: inSet<Grant>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "scope", header: "Scope", accessorFn: (g) => unitName(g.org_unit), filterFn: inSet<Grant>(), cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span> },
    { id: "granted", header: "Granted", accessorKey: "granted_at", cell: ({ row: { original: g } }) => <span className="text-ink-2">{day(g.granted_at)}{g.granted_by ? ` by ${g.granted_by}` : ""}</span> },
    { id: "actions", header: "", enableSorting: false, cell: ({ row: { original: g } }) => g.role === "platform_admin"
      ? <span className="text-xs text-muted">Set in the identity provider</span>
      : <Button size="sm" variant="ghost" onClick={() => revoke(g)} aria-label={`Revoke ${ROLES[g.role] ?? g.role} from ${g.principal_name ?? g.principal_id}`}>Revoke</Button> },
  ];
  return (
    <div className="grid items-start gap-4 xl:grid-cols-3">
      <Card className="xl:col-span-2" bodyClassName="">
        {grants.isPending ? <SkeletonRows rows={6} /> : grants.isError ? <div className="p-4"><LoadError error={grants.error} /></div> : (
          <DataTable data={grants.data} columns={cols} label="role grants" searchPlaceholder="Search people…" facets={[{ column: "role", title: "Role" }, { column: "scope", title: "Scope" }]} initialSort={[{ id: "who", desc: false }]} />
        )}
      </Card>
      <Card title="Grant a role">
        <div className="grid gap-4">
          {who ? (
            <div className="flex items-center justify-between rounded-md border border-line bg-surface-2 px-3 py-2 text-[13px]">
              <span className="text-ink">{who.display_name}</span><Button size="sm" variant="ghost" onClick={() => setWho(null)}>Change</Button>
            </div>
          ) : <UserPicker id="grant-who" label="Person" onPick={setWho} />}
          <Field id="grant-role" label="Role">
            <select id="grant-role" value={role} onChange={(e) => setRole(e.target.value)} className={selectClass}>
              {Object.entries(ROLES).filter(([k]) => k !== "platform_admin").map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          {SCOPED.has(role) && (
            <Field id="grant-unit" label="In unit" hint="This role only sees applications in that unit and below">
              <select id="grant-unit" value={unit} onChange={(e) => setUnit(e.target.value)} className={selectClass}>
                <option value="">Choose…</option>{units.filter((u) => u.parent).map((u) => <option key={u.slug} value={u.slug}>{u.name}</option>)}
              </select>
            </Field>
          )}
          <Button variant="primary" disabled={!who || (SCOPED.has(role) && !unit)} onClick={() => void grant()}><UserPlus className="size-4" aria-hidden="true" />Grant</Button>
          {msg && <Notice tone={msg.ok ? "success" : "error"}>{msg.text}</Notice>}
        </div>
      </Card>
    </div>
  );
}
