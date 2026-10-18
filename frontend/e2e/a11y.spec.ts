// SPDX-License-Identifier: Apache-2.0
import AxeBuilder from "@axe-core/playwright";
import { expect, test, visit } from "./fixtures";

// WCAG 2.2 AA on the redesigned pages, in both themes. Pages still on the pre-redesign styles join as they move.
const PAGES = ["/", "/apps", "/apps/APP-00001", "/apps/APP-00001/controls", "/apps/APP-00001/evidence", "/evidence", "/evidence/view/rejected", "/findings"];

for (const theme of ["dark", "light"] as const) {
  for (const path of PAGES) {
    test(`${path} meets WCAG 2.2 AA (${theme})`, async ({ page, problems }) => {
      void problems;
      await page.addInitScript((t) => window.localStorage.setItem("theme", t), theme);
      await visit(page, path);
      await expect(page.locator("main h1")).toBeVisible();
      await page.waitForLoadState("networkidle");
      const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
      const summary = results.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} × ${v.nodes[0]?.target.join(" ")}`);
      expect(summary).toEqual([]);
    });
  }
}
