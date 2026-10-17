// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState, type ReactNode } from "react";
import { api, getPersona, setPersona, signOut, type Me } from "../api";
import { Logo } from "./shell/Logo";

// Demo personas (seeded by `aap demo seed`). Dev authentication only: in production people sign in through your OIDC identity provider.
export const PERSONAS = [
  { login: "ajones", label: "Amira Jones — security champion, Claims team" },
  { login: "ekim", label: "Eun Kim — engineer, Payments team" },
  { login: "dlee", label: "Dana Lee — security lead, Benefits business unit" },
  { login: "cpatel", label: "Chandra Patel — AppSec engineer (organisation-wide)" },
  { login: "fwong", label: "Farah Wong — executive (aggregates only)" },
  { login: "padmin", label: "Pat Admin — platform administrator (structure and access, no application data)" },
];

// Dev convenience: `?as=<login>` selects a demo persona (for links and screenshots). Only known personas are accepted.
const asParam = new URLSearchParams(window.location.search).get("as");
if (asParam && PERSONAS.some((p) => p.login === asParam)) setPersona(asParam);

export function useRoute(): string[] {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
}

export function Layout({ children, route }: { children: ReactNode; route: string[] }) {
  const persona = getPersona();
  const section = route[0] ?? "apps";
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => { api.me().then(setMe, () => setMe(null)); }, [persona]);
  const dev = !me || me.auth_mode === "dev";
  const link = (href: string, name: string, key: string) => (
    <a href={href} className={section === key ? "active" : ""}>{name}</a>
  );
  return (
    <>
      <header className="topbar">
        <a href="#/apps" className="text-ink hover:no-underline"><Logo /></a>
        <nav className="nav">
          {link("#/apps", "Applications", "apps")}
          {link("#/cve", "Are we affected?", "cve")}
          {link("#/leadership", "Leadership", "leadership")}
          {me?.permissions.includes("exception.read") && link("#/exceptions", "Exceptions", "exceptions")}
          {me?.permissions.includes("assessment.read") && link("#/assessments", "Assessments", "assessments")}
          {me?.permissions.includes("integration.read") && link("#/integrations", "Integrations", "integrations")}
          {me?.permissions.includes("org.admin") && link("#/admin", "Admin", "admin")}
        </nav>
        {dev ? (
          <label className="persona small">
            <span className="muted">Viewing as</span>
            <select value={persona} onChange={(e) => { setPersona(e.target.value); window.location.hash = "#/apps"; window.location.reload(); }}>
              {PERSONAS.map((p) => <option key={p.login} value={p.login}>{p.label}</option>)}
            </select>
          </label>
        ) : (
          <span className="persona small row">
            <span>{me?.user.display_name}</span>
            <button type="button" onClick={() => void signOut()}>Sign out</button>
          </span>
        )}
      </header>
      {dev && (
        <div className="devbanner">
          Demo data · development sign-in (persona switcher). In production you sign in through your identity provider and see only what your role allows, exactly as here.
        </div>
      )}
      <main>{children}</main>
    </>
  );
}
