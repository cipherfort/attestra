// SPDX-License-Identifier: Apache-2.0
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Link } from "react-router";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const base = "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:cursor-default disabled:opacity-50 no-underline hover:no-underline";
const variants: Record<Variant, string> = {
  primary: "border border-transparent bg-accent-solid text-white hover:brightness-110",
  secondary: "border border-line-strong bg-surface-2 text-ink hover:bg-surface-3",
  ghost: "border border-transparent bg-transparent text-ink-2 hover:bg-surface-2 hover:text-ink",
  danger: "border border-transparent bg-critical text-white hover:brightness-110",
};
const sizes: Record<Size, string> = { sm: "h-7 px-2.5 text-xs", md: "h-8 px-3 text-[13px]" };

export function buttonClass(variant: Variant = "secondary", size: Size = "md", extra = ""): string {
  return `${base} ${variants[variant]} ${sizes[size]} ${extra}`;
}

export function Button({
  variant = "secondary",
  size = "md",
  className = "",
  type = "button",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size }) {
  return <button type={type} className={buttonClass(variant, size, className)} {...rest} />;
}

export function ButtonLink({
  to,
  variant = "secondary",
  size = "md",
  className = "",
  children,
}: { to: string; variant?: Variant; size?: Size; className?: string; children: ReactNode }) {
  return <Link to={to} className={buttonClass(variant, size, className)}>{children}</Link>;
}
