// SPDX-License-Identifier: Apache-2.0
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

/** What to do when there is nothing here yet: an icon, a sentence and, ideally, the next step. */
export function EmptyState({ icon: Icon, title, children, action }: { icon?: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      {Icon && (
        <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-surface-2 text-muted">
          <Icon className="size-5" strokeWidth={1.75} aria-hidden="true" />
        </div>
      )}
      <div className="text-sm font-semibold text-ink">{title}</div>
      {children && <div className="mt-1 max-w-md text-[13px] text-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** A loading placeholder in the shape of the content. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-md bg-surface-2 motion-reduce:animate-none ${className}`} />;
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3 p-5" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className="h-5 w-full" />)}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-line bg-surface-2 px-1.5 font-mono text-[11px] text-muted">{children}</kbd>;
}
