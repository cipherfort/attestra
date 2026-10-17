// SPDX-License-Identifier: Apache-2.0
import { Search } from "lucide-react";
import type { Me } from "../../api";
import { UserMenu } from "./UserMenu";

const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

export function TopBar({ me, onSearch }: { me: Me | undefined; onSearch: () => void }) {
  return (
    <header className="sticky top-0 z-20 flex h-12 items-center gap-3 border-b border-line bg-page/85 px-6 backdrop-blur">
      <button
        type="button"
        onClick={onSearch}
        className="flex h-8 w-full max-w-md items-center gap-2 rounded-md border border-line bg-surface px-2.5 text-left text-[13px] text-muted hover:border-line-strong hover:text-ink-2"
      >
        <Search className="size-4" strokeWidth={1.75} aria-hidden="true" />
        <span className="flex-1">Search applications, pages, CVEs…</span>
        <kbd className="rounded border border-line bg-surface-2 px-1.5 font-mono text-[11px] text-muted">{mac ? "⌘K" : "Ctrl K"}</kbd>
      </button>
      <span className="flex-1" />
      <UserMenu me={me} />
    </header>
  );
}
