// SPDX-License-Identifier: Apache-2.0
import {
  BarChart3,
  Boxes,
  LayoutDashboard,
  ClipboardCheck,
  Plug,
  Radar,
  ShieldOff,
  UsersRound,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** shown only when the person has this permission */
  perm?: string;
  /** other paths that belong to this item (for the active state) */
  also?: string[];
  /** active only on this exact path */
  exact?: boolean;
}

export const NAV: { label: string; items: NavItem[] }[] = [
  {
    label: "Posture",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, exact: true },
      { to: "/apps", label: "Applications", icon: Boxes, also: ["/register", "/findings", "/evidence"] },
      { to: "/cve", label: "Are we affected?", icon: Radar },
    ],
  },
  {
    label: "Governance",
    items: [
      { to: "/exceptions", label: "Exceptions", icon: ShieldOff, perm: "exception.read" },
      { to: "/assessments", label: "Assessments", icon: ClipboardCheck, perm: "assessment.read" },
    ],
  },
  { label: "Reports", items: [{ to: "/leadership", label: "Leadership", icon: BarChart3 }] },
  {
    label: "Settings",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug, perm: "integration.read" },
      { to: "/admin", label: "Admin", icon: UsersRound, perm: "org.admin" },
    ],
  },
];

export function visible(items: NavItem[], permissions: string[] | undefined): NavItem[] {
  return items.filter((i) => !i.perm || (permissions ?? []).includes(i.perm));
}

export function isActive(item: NavItem, pathname: string): boolean {
  if (item.exact) return pathname === item.to;
  return [item.to, ...(item.also ?? [])].some((p) => pathname === p || pathname.startsWith(`${p}/`));
}
