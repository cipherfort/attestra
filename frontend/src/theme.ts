// SPDX-License-Identifier: Apache-2.0
// Theme preference: "dark" (default), "light" or "system". public/theme-init.js applies it before first paint.
export type ThemePref = "dark" | "light" | "system";

export function themePref(): ThemePref {
  try {
    const v = window.localStorage.getItem("theme");
    return v === "light" || v === "system" ? v : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(pref: ThemePref): void {
  try {
    window.localStorage.setItem("theme", pref);
  } catch {
    /* storage unavailable: the choice lasts for this page only */
  }
  const light = pref === "light" || (pref === "system" && window.matchMedia("(prefers-color-scheme: light)").matches);
  document.documentElement.setAttribute("data-theme", light ? "light" : "dark");
}
