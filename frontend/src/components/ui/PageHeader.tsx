// SPDX-License-Identifier: Apache-2.0
import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";

export interface Crumb { label: string; to?: string }

/** Page title with breadcrumbs, a one-line description and actions on the right. */
export function PageHeader({
  title,
  description,
  crumbs,
  actions,
  meta,
}: {
  title: ReactNode;
  description?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <div className="mb-6">
      {crumbs && crumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="mb-2">
          <ol className="plain m-0 flex flex-wrap items-center gap-1 p-0 text-xs text-muted">
            {crumbs.map((c, i) => (
              <li key={`${c.label}-${i}`} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="size-3" aria-hidden="true" />}
                {c.to ? <Link to={c.to} className="text-muted hover:text-ink">{c.label}</Link> : <span aria-current="page">{c.label}</span>}
              </li>
            ))}
          </ol>
        </nav>
      )}
      <div className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="m-0 text-2xl font-semibold tracking-tight text-ink">{title}</h1>
          {meta && <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[13px] text-ink-2">{meta}</div>}
          {description && <p className="m-0 mt-2 max-w-3xl text-sm text-ink-2">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}
