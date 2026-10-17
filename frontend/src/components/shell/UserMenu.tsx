// SPDX-License-Identifier: Apache-2.0
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Check, LogOut, Monitor, Moon, Sun } from "lucide-react";
import { useState } from "react";
import { getPersona, setPersona, signOut, type Me } from "../../api";
import { PERSONAS } from "../../personas";
import { applyTheme, themePref, type ThemePref } from "../../theme";

function initials(name: string): string {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]?.toUpperCase() ?? "").join("") || "?";
}

const item = "flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-[13px] text-ink-2 outline-none data-[highlighted]:bg-surface-3 data-[highlighted]:text-ink";

export function UserMenu({ me }: { me: Me | undefined }) {
  const [theme, setTheme] = useState<ThemePref>(themePref);
  const dev = !me || me.auth_mode === "dev";
  const persona = getPersona();
  const name = me?.user.display_name ?? "Signed out";
  const pickTheme = (t: ThemePref) => { applyTheme(t); setTheme(t); };
  return (
    <Menu.Root modal={false}>
      <Menu.Trigger
        aria-label={`Account: ${name}`}
        className="flex size-8 items-center justify-center rounded-full border border-line-strong bg-surface-2 p-0 text-xs font-semibold text-ink hover:bg-surface-3"
      >
        {initials(name)}
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content align="end" sideOffset={8} className="z-50 w-80 rounded-lg border border-line bg-surface p-1.5 shadow-card">
          <div className="px-2 py-1.5">
            <div className="text-sm font-semibold text-ink">{name}</div>
            <div className="text-xs text-muted">{(me?.roles ?? []).map((r) => r.role.replaceAll("_", " ")).join(", ") || "no roles"}</div>
          </div>
          <Menu.Separator className="my-1 h-px bg-line" />
          <Menu.Label className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted">Theme</Menu.Label>
          {([["dark", "Dark", Moon], ["light", "Light", Sun], ["system", "Match system", Monitor]] as const).map(([t, label, Icon]) => (
            <Menu.Item key={t} className={item} onSelect={() => pickTheme(t)}>
              <Icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
              <span className="flex-1">{label}</span>
              {theme === t && <Check className="size-4 text-accent" aria-label="selected" />}
            </Menu.Item>
          ))}
          {dev && (
            <>
              <Menu.Separator className="my-1 h-px bg-line" />
              <Menu.Label className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted">Viewing as (demo)</Menu.Label>
              {PERSONAS.map((p) => (
                <Menu.Item
                  key={p.login}
                  className={item}
                  onSelect={() => { setPersona(p.login); window.location.assign("/"); }}
                >
                  <span className="flex-1">
                    <span className="block text-ink">{p.name}</span>
                    <span className="block text-xs text-muted">{p.role}</span>
                  </span>
                  {persona === p.login && <Check className="size-4 text-accent" aria-label="current" />}
                </Menu.Item>
              ))}
            </>
          )}
          {!dev && (
            <>
              <Menu.Separator className="my-1 h-px bg-line" />
              <Menu.Item className={item} onSelect={() => void signOut()}>
                <LogOut className="size-4" strokeWidth={1.75} aria-hidden="true" />
                Sign out
              </Menu.Item>
            </>
          )}
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  );
}
