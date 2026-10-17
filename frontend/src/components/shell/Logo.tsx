// SPDX-License-Identifier: Apache-2.0
import { BRAND } from "../../brand";

/** The mark: a shield with a check (evidence-backed assurance). Inline so it takes the accent colour in both themes. */
export function LogoMark({ size = 22, className = "" }: { size?: number; className?: string }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden="true" className={`text-accent ${className}`}>
      <path fill="currentColor" d="M16 2.5 27 6.6v8.2c0 7.1-4.7 12.6-11 14.7C9.7 27.4 5 21.9 5 14.8V6.6z" />
      <path
        fill="none"
        stroke="#fff"
        strokeWidth={2.8}
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m10.6 16.2 3.8 3.8 7-7.6"
      />
    </svg>
  );
}

export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 font-semibold tracking-tight ${className}`}>
      <LogoMark />
      <span>{BRAND.name}</span>
    </span>
  );
}
