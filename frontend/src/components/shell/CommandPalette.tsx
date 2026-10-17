// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { Boxes, Moon, Plus, Radar, Sun, UserRound } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api, setPersona, type Me } from "../../api";
import { PERSONAS } from "../../personas";
import { applyTheme, themePref } from "../../theme";
import { NAV, visible } from "./nav";

const VULN_ID = /^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3})$/i;

/** ⌘K: jump to a page or application, check exposure to a CVE, switch theme or demo person. A native <dialog> (focus
 *  trap, Esc and an inert page behind it, with no injected styles, which the CSP would block). */
export function CommandPalette({ open, onClose, me }: { open: boolean; onClose: () => void; me: Me | undefined }) {
  const ref = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const apps = useQuery({ queryKey: ["applications"], queryFn: api.applications, enabled: open, staleTime: 60_000 });
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      setQuery("");
      d.showModal();
      input.current?.focus(); // React's autoFocus runs at mount, while the dialog is still closed
    } else if (!open && d.open) d.close();
  }, [open]);
  const run = (fn: () => void) => () => {
    onClose();
    fn();
  };
  const dev = !me || me.auth_mode === "dev";
  const vuln = query.trim().toUpperCase();
  const group = "px-2 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-muted [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1";
  const row = "flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-ink-2 data-[selected=true]:bg-surface-3 data-[selected=true]:text-ink";
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}
      aria-label="Command palette"
      className="mx-auto mt-[12vh] w-[640px] max-w-[92vw] rounded-xl border border-line bg-surface p-0 text-ink shadow-card backdrop:bg-black/60"
    >
      <Command label="Command palette" loop>
        <Command.Input
          ref={input}
          value={query}
          onValueChange={setQuery}
          placeholder="Search applications and pages, or paste a CVE…"
          className="w-full border-0 border-b border-line bg-transparent px-4 py-3.5 text-sm text-ink outline-none placeholder:text-muted"
        />
        <Command.List className="max-h-[52vh] overflow-y-auto p-2">
          <Command.Empty className="px-3 py-6 text-center text-sm text-muted">No matches.</Command.Empty>
          {VULN_ID.test(vuln) && (
            <Command.Group heading="Vulnerability" className={group}>
              <Command.Item value={`check ${vuln}`} onSelect={run(() => navigate(`/cve/${vuln}`))} className={row}>
                <Radar className="size-4" strokeWidth={1.75} aria-hidden="true" />
                Are we affected by {vuln}?
              </Command.Item>
            </Command.Group>
          )}
          <Command.Group heading="Go to" className={group}>
            {NAV.flatMap((g) => visible(g.items, me?.permissions)).map((i) => (
              <Command.Item key={i.to} value={`go ${i.label}`} onSelect={run(() => navigate(i.to))} className={row}>
                <i.icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
                {i.label}
              </Command.Item>
            ))}
          </Command.Group>
          {(apps.data?.length ?? 0) > 0 && (
            <Command.Group heading="Applications" className={group}>
              {apps.data!.map((a) => (
                <Command.Item key={a.id} value={`${a.name} ${a.app_key}`} onSelect={run(() => navigate(`/apps/${a.app_key}`))} className={row}>
                  <Boxes className="size-4" strokeWidth={1.75} aria-hidden="true" />
                  <span className="flex-1">{a.name}</span>
                  <span className="font-mono text-xs text-muted">{a.app_key}</span>
                </Command.Item>
              ))}
            </Command.Group>
          )}
          <Command.Group heading="Actions" className={group}>
            {me?.permissions.includes("application.register") && (
              <Command.Item value="register an application" onSelect={run(() => navigate("/register"))} className={row}>
                <Plus className="size-4" strokeWidth={1.75} aria-hidden="true" />
                Register an application
              </Command.Item>
            )}
            <Command.Item
              value="switch theme dark light"
              onSelect={run(() => applyTheme(themePref() === "light" ? "dark" : "light"))}
              className={row}
            >
              {themePref() === "light" ? <Moon className="size-4" strokeWidth={1.75} /> : <Sun className="size-4" strokeWidth={1.75} />}
              Switch to {themePref() === "light" ? "dark" : "light"} theme
            </Command.Item>
            {dev && PERSONAS.map((p) => (
              <Command.Item
                key={p.login}
                value={`view as ${p.name}`}  // by name only: role text would match application searches
                onSelect={run(() => { setPersona(p.login); window.location.assign("/"); })}
                className={row}
              >
                <UserRound className="size-4" strokeWidth={1.75} aria-hidden="true" />
                <span className="flex-1">View as {p.name}</span>
                <span className="text-xs text-muted">{p.role}</span>
              </Command.Item>
            ))}
          </Command.Group>
        </Command.List>
      </Command>
    </dialog>
  );
}
