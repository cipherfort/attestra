// SPDX-License-Identifier: Apache-2.0
import * as Tooltip from "@radix-ui/react-tooltip";
import { Suspense, useEffect, useState, type MouseEvent } from "react";
import { Outlet, useNavigate } from "react-router";
import { useMe } from "../../hooks/useMe";
import { SkeletonRows } from "../ui/States";
import { CommandPalette } from "./CommandPalette";
import { DevBanner } from "./DevBanner";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AppShell() {
  const me = useMe();
  const navigate = useNavigate();
  const [palette, setPalette] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // Plain <a href="/…"> links inside pages navigate without a reload.
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = (e.target as HTMLElement).closest("a");
    const href = a?.getAttribute("href");
    if (!a || !href || a.target || a.hasAttribute("download")) return;
    if (!href.startsWith("/") || href.startsWith("//") || href.startsWith("/api/") || href.startsWith("/auth/")) return;
    e.preventDefault();
    void navigate(href);
  };
  return (
    <Tooltip.Provider delayDuration={300}>
      <div className="flex min-h-screen bg-page text-ink" onClick={onClick}>
        <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-accent-solid focus:px-3 focus:py-2 focus:text-white">
          Skip to content
        </a>
        <Sidebar me={me.data} />
        <div className="flex min-w-0 flex-1 flex-col">
          <DevBanner me={me.data} />
          <TopBar me={me.data} onSearch={() => setPalette(true)} />
          <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1400px] px-8 py-6 outline-none">
            <Suspense fallback={<SkeletonRows rows={8} />}>
              <Outlet />
            </Suspense>
          </main>
        </div>
        <CommandPalette open={palette} onClose={() => setPalette(false)} me={me.data} />
      </div>
    </Tooltip.Provider>
  );
}
