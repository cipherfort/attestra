// SPDX-License-Identifier: Apache-2.0
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "../../api";

const base = "w-full rounded-md border border-line bg-page px-2.5 text-[13px] text-ink placeholder:text-muted focus:border-accent";
export const inputClass = `${base} h-9`;
export const selectClass = `${base} h-9 pr-8`;
export const textareaClass = `${base} py-2 leading-relaxed`;

/** A labelled control with an optional hint under it. `id` ties the label to the control. */
export function Field({ id, label, hint, children, optional }: { id: string; label: ReactNode; hint?: ReactNode; children: ReactNode; optional?: boolean }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-ink-2">
        {label}{optional && <span className="font-normal text-muted"> (optional)</span>}
      </label>
      {children}
      {hint && <p className="m-0 mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

/** A callout: what went wrong, what succeeded, or something worth knowing. Icon + text, never colour alone. */
export function Notice({ tone = "info", title, children }: { tone?: "info" | "error" | "success"; title?: ReactNode; children?: ReactNode }) {
  const Icon = tone === "error" ? AlertTriangle : tone === "success" ? CheckCircle2 : Info;
  const border = tone === "error" ? "border-critical/40" : tone === "success" ? "border-good/40" : "border-line";
  const color = tone === "error" ? "text-critical" : tone === "success" ? "text-good" : "text-accent";
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`flex items-start gap-3 rounded-lg border ${border} bg-surface-2 px-4 py-3 text-[13px]`}>
      <Icon className={`mt-0.5 size-4 shrink-0 ${color}`} aria-hidden="true" />
      <div className="min-w-0 flex-1 text-ink-2">
        {title && <div className="font-semibold text-ink">{title}</div>}
        {children}
      </div>
    </div>
  );
}

export function errorText(e: unknown): string {
  return e instanceof ApiError ? `${e.title}${e.detail ? `: ${e.detail}` : ""}` : String(e);
}

/** The standard load-failure state: 404 and 403 explained, without revealing whether something out of scope exists. */
export function LoadError({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.status === 404) {
    return <Notice title="Not found">It doesn't exist, or it's outside your scope. The two look the same on purpose.</Notice>;
  }
  if (error instanceof ApiError && error.status === 403) {
    return <Notice title="Not part of your role">{error.detail}</Notice>;
  }
  return <Notice tone="error" title="Couldn't load">{errorText(error)}</Notice>;
}

/** Definition list in two columns: a label and its value. */
export function Facts({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="m-0 grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-6 gap-y-3 text-[13px]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="m-0 whitespace-pre-line text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
