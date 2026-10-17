// SPDX-License-Identifier: Apache-2.0
import { test as base, expect, type Page } from "@playwright/test";

/** Every test fails on a console error, an uncaught exception or a Content-Security-Policy violation. */
export const test = base.extend<{ problems: string[] }>({
  problems: async ({ page }, use) => {
    const problems: string[] = [];
    page.on("console", (m) => { if (m.type() === "error") problems.push(m.text()); });
    page.on("pageerror", (e) => problems.push(String(e)));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => {
        console.error(`CSP violation: ${e.violatedDirective} blocked ${e.blockedURI || "inline"}`);
      });
    });
    await use(problems);
    expect(problems, "console errors, exceptions or CSP violations").toEqual([]);
  },
});
export { expect };

export async function visit(page: Page, path: string, as = "cpatel"): Promise<void> {
  const sep = path.includes("?") ? "&" : "?";
  await page.goto(`${path}${sep}as=${as}`);
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
}
