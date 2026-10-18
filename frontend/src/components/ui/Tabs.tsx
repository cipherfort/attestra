// SPDX-License-Identifier: Apache-2.0
import * as RTabs from "@radix-ui/react-tabs";
import type { ReactNode } from "react";

export interface TabDef { value: string; label: ReactNode; count?: number; more?: boolean }

/** Underlined tabs. Controlled by the caller so the active tab can live in the URL. */
export function Tabs({
  tabs,
  value,
  onValueChange,
  children,
  label,
}: {
  tabs: TabDef[];
  value: string;
  onValueChange: (v: string) => void;
  children: ReactNode;
  label: string;
}) {
  return (
    <RTabs.Root value={value} onValueChange={onValueChange}>
      <RTabs.List aria-label={label} className="mb-5 flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((t) => (
          <RTabs.Trigger
            key={t.value}
            value={t.value}
            className="-mb-px flex items-center gap-1.5 whitespace-nowrap rounded-none border-0 border-b-2 border-transparent bg-transparent px-3 py-2 text-[13px] font-medium text-ink-2 hover:text-ink data-[state=active]:border-accent data-[state=active]:text-ink"
          >
            {t.label}
            {t.count !== undefined && (
              <span className="rounded-full bg-surface-3 px-1.5 text-[11px] font-semibold text-ink-2">{t.count}{t.more ? "+" : ""}</span>
            )}
          </RTabs.Trigger>
        ))}
      </RTabs.List>
      {children}
    </RTabs.Root>
  );
}

export const TabPanel = RTabs.Content;
