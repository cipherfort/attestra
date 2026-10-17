// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { ApiError, api, type AdminUser, type OrgUnit } from "../api";
import { date, Loadable, useLoad } from "../components/ui";

const ROLES = ["champion", "engineer", "unit_lead", "app_owner", "appsec_engineer", "security_leadership",
  "governance_analyst", "auditor", "executive"];
const SCOPED = new Set(["champion", "engineer", "unit_lead", "app_owner"]);

function message(e: unknown): string {
  return e instanceof ApiError ? `${e.title}: ${e.detail ?? ""}` : String(e);
}

/** Organization structure and access. platform_admin itself is assigned in the identity provider, never here. */
export function Admin() {
  const [tick, setTick] = useState(0);
  const units = useLoad(api.orgUnits, [tick]);
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <>
      <h1>Administration</h1>
      <p className="muted">
        Units and membership decide what each person can see. Every change is audited. You cannot change your own roles,
        and platform administrators are assigned in the identity provider. Moving a unit under another parent is a
        database migration, because it changes the scope of every application below it.
      </p>
      <Loadable state={units}>
        {(u) => (
          <div className="grid two">
            <div className="card">
              <h2>Organization</h2>
              <UnitTree units={u.items} selected={selected} onSelect={setSelected} />
              <NewUnit units={u.items} levels={u.levels} onDone={() => setTick((t) => t + 1)} />
            </div>
            <div className="card">
              {selected ? <Members slug={selected} onDone={() => setTick((t) => t + 1)} />
                : <p className="muted">Choose a unit to see and change its members.</p>}
            </div>
          </div>
        )}
      </Loadable>
      <Grants units={units.data?.items ?? []} />
    </>
  );
}

function UnitTree({ units, selected, onSelect }: { units: OrgUnit[]; selected: string | null; onSelect: (s: string) => void }) {
  const children = (parent: string | null): OrgUnit[] => units.filter((u) => u.parent === parent);
  const render = (u: OrgUnit, depth: number): React.ReactNode => (
    <li key={u.slug} style={{ marginLeft: depth * 16 }}>
      <button className={selected === u.slug ? "" : "secondary"} onClick={() => onSelect(u.slug)}>{u.name}</button>
      <span className="small muted"> {u.unit_type.replaceAll("_", " ")} · {u.members} members · {u.applications} apps
        {u.scm_group ? ` · ${u.scm_group}` : ""}</span>
      <ul className="plain">{children(u.slug).map((c) => render(c, depth + 1))}</ul>
    </li>
  );
  return <ul className="plain">{children(null).map((u) => render(u, 0))}</ul>;
}

function NewUnit({ units, levels, onDone }: { units: OrgUnit[]; levels: string[]; onDone: () => void }) {
  const [form, setForm] = useState({ slug: "", name: "", unit_type: levels[1] ?? "", parent: "" });
  const [msg, setMsg] = useState<string | null>(null);
  const parentType = levels[levels.indexOf(form.unit_type) - 1];
  const parents = units.filter((u) => u.unit_type === parentType);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api.createOrgUnit(form); setMsg(null); setForm({ ...form, slug: "", name: "" }); onDone(); }
    catch (err) { setMsg(message(err)); }
  };
  return (
    <form onSubmit={create}>
      <h3>Add a unit</h3>
      <p className="row small">
        <select value={form.unit_type} onChange={(e) => setForm({ ...form, unit_type: e.target.value, parent: "" })}>
          {levels.slice(1).map((l) => <option key={l} value={l}>{l.replaceAll("_", " ")}</option>)}
        </select>
        under <select required value={form.parent} onChange={(e) => setForm({ ...form, parent: e.target.value })}>
          <option value="">choose…</option>{parents.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
        </select>
      </p>
      <p className="row small">
        <input required placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input required placeholder="slug (used in application.yaml)" pattern="[a-z0-9][a-z0-9-]{1,62}[a-z0-9]"
          value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
        <button type="submit">Add</button>
      </p>
      {msg && <p className="error small">{msg}</p>}
    </form>
  );
}

function UserPicker({ onPick }: { onPick: (u: AdminUser) => void }) {
  const [q, setQ] = useState("");
  const [found, setFound] = useState<AdminUser[]>([]);
  return (
    <div>
      <p className="row small">
        <input placeholder="Find a person (name, email, login)" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="secondary" type="button" onClick={() => void api.users(q).then(setFound)}>Search</button>
      </p>
      {found.length > 0 && <ul className="plain small">{found.map((u) => (
        <li key={u.id}><button type="button" className="secondary" onClick={() => { onPick(u); setFound([]); setQ(""); }}>
          {u.display_name}</button> <span className="muted">{u.email ?? u.logins.join(", ")}</span></li>))}</ul>}
    </div>
  );
}

function Members({ slug, onDone }: { slug: string; onDone: () => void }) {
  const [tick, setTick] = useState(0);
  const members = useLoad(() => api.members(slug), [slug, tick]);
  const [msg, setMsg] = useState<string | null>(null);
  const change = async (userId: string, present: boolean) => {
    try { await api.setMember(slug, userId, present); setMsg(null); setTick((t) => t + 1); onDone(); }
    catch (err) { setMsg(message(err)); }
  };
  return (
    <>
      <h2>Members of {slug}</h2>
      <Loadable state={members}>
        {(m) => m.length === 0 ? <p className="muted small">No members.</p> : (
          <ul className="plain">{m.map((x) => (
            <li key={x.user_id} className="small">{x.display_name} <span className="muted">({x.source})</span>{" "}
              <button className="secondary" onClick={() => void change(x.user_id, false)}>Remove</button></li>))}</ul>
        )}
      </Loadable>
      <h3>Add a member</h3>
      <UserPicker onPick={(u) => void change(u.id, true)} />
      {msg && <p className="error small">{msg}</p>}
    </>
  );
}

function Grants({ units }: { units: OrgUnit[] }) {
  const [tick, setTick] = useState(0);
  const grants = useLoad(api.grants, [tick]);
  const [who, setWho] = useState<AdminUser | null>(null);
  const [role, setRole] = useState("champion");
  const [unit, setUnit] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const grant = async () => {
    if (!who) return;
    try {
      await api.grant({ principal_type: "user", principal_id: who.id, role, org_unit: SCOPED.has(role) ? unit : undefined });
      setMsg(null); setWho(null); setTick((t) => t + 1);
    } catch (err) { setMsg(message(err)); }
  };
  return (
    <div className="card">
      <h2>Role grants</h2>
      <Loadable state={grants}>
        {(g) => (
          <table>
            <thead><tr><th>Who</th><th>Role</th><th>Scope</th><th>Granted</th><th /></tr></thead>
            <tbody>{g.map((x) => (
              <tr key={x.id}>
                <td className="small">{x.principal_name ?? `${x.principal_type} ${x.principal_id}`}</td>
                <td className="small">{x.role.replaceAll("_", " ")}</td>
                <td className="small">{x.org_unit ?? "organization-wide"}</td>
                <td className="small">{date(x.granted_at)}{x.granted_by ? ` by ${x.granted_by}` : ""}</td>
                <td>{x.role !== "platform_admin" && <button className="secondary" onClick={() =>
                  void api.revokeGrant(x.id).then(() => setTick((t) => t + 1), (e) => setMsg(message(e)))}>Revoke</button>}</td>
              </tr>))}
            </tbody>
          </table>
        )}
      </Loadable>
      <h3>Grant a role</h3>
      {who ? <p className="small">To <strong>{who.display_name}</strong> <button className="secondary" onClick={() => setWho(null)}>change</button></p>
        : <UserPicker onPick={setWho} />}
      <p className="row small">
        <select value={role} onChange={(e) => setRole(e.target.value)}>{ROLES.map((r) => <option key={r} value={r}>{r.replaceAll("_", " ")}</option>)}</select>
        {SCOPED.has(role) && <select value={unit} onChange={(e) => setUnit(e.target.value)}>
          <option value="">in unit…</option>{units.filter((u) => u.parent).map((u) => <option key={u.slug} value={u.slug}>{u.name}</option>)}</select>}
        <button disabled={!who || (SCOPED.has(role) && !unit)} onClick={() => void grant()}>Grant</button>
      </p>
      {msg && <p className="error small">{msg}</p>}
    </div>
  );
}
