// SPDX-License-Identifier: Apache-2.0
// Launch assets, regenerated from the demo world after any UI change: `npm run screenshots` (needs the API with the
// demo seed, like the other browser tests). PNG screenshots (both themes, 1440×900 at 2×) go to launch-assets/screenshots/;
// `npm run screenshots:webp` converts them, losslessly, into docs/assets/screenshots/ for the README and the docs site;
// the walkthrough videos are in docs-video.spec.ts.
import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { expect, open, test } from "./fixtures";

const OUT = new URL("../launch-assets/screenshots/", import.meta.url).pathname;

const SCENES: { name: string; path: string; as?: string; prepare?: (page: Page) => Promise<void> }[] = [
  { name: "overview", path: "/" },
  { name: "application", path: "/apps/APP-00001" },
  { name: "evidence-rejected", path: "/evidence/view/rejected" },
  {
    name: "evidence-chain",
    path: "/evidence",
    prepare: async (page) => {
      await page.getByRole("link", { name: "Static analysis" }).first().click();
      await expect(page.getByRole("list", { name: "How this evidence was verified" })).toBeVisible();
    },
  },
  { name: "are-we-affected", path: "/cve/CVE-2021-44228" },
  { name: "maturity", path: "/maturity" },
  { name: "control-drawer", path: "/controls/ASC-BLD-02" },
  { name: "exception-approval", path: "/exceptions/EX-000002" },
];

test.describe("@docs screenshots", () => {
  test.beforeAll(() => mkdirSync(OUT, { recursive: true }));
  for (const theme of ["dark", "light"] as const) {
    for (const s of SCENES) {
      test(`${s.name} (${theme})`, async ({ page, problems }) => {
        void problems;
        await page.addInitScript((t) => window.localStorage.setItem("theme", t), theme);
        await open(page, s.path, s.as);
        if (s.prepare) { await s.prepare(page); await page.waitForTimeout(400); }
        await page.mouse.move(0, 0);
        await page.screenshot({ path: `${OUT}${s.name}-${theme}.png` });
      });
    }
  }
});
