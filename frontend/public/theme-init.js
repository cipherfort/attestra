// SPDX-License-Identifier: Apache-2.0
// Runs before first paint (external file: the CSP allows no inline script). Dark is the default; "system" follows
// the operating system; the choice is a per-browser convenience in localStorage.
(function () {
  var pref = null;
  try { pref = window.localStorage.getItem("theme"); } catch (e) { pref = null; }
  var theme = pref === "light" || pref === "dark" ? pref : "dark";
  if (pref === "system" && window.matchMedia) {
    theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
