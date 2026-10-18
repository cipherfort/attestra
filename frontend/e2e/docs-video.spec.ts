// SPDX-License-Identifier: Apache-2.0
// Silent walkthrough videos for the launch (npm run screenshots): written to launch-assets/, not committed. Add a voice-over
// and attach them to a release or upload them.
import { copyFileSync, mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { open, test } from "./fixtures";

const VIDEO = new URL("../launch-assets/", import.meta.url).pathname;
test.use({ video: { mode: "on", size: { width: 1440, height: 900 } } });

const pause = (page: Page, ms = 1600) => page.waitForTimeout(ms);
const keep = async (page: Page, name: string) => {
  const video = page.video();
  await page.close();
  mkdirSync(VIDEO, { recursive: true });
  if (video) copyFileSync(await video.path(), `${VIDEO}${name}.webm`);
};

test("forged evidence is rejected", async ({ page, problems }) => {
  void problems;
  await open(page, "/");
  await pause(page);
  await page.getByRole("link", { name: "Evidence", exact: true }).click();
  await pause(page);
  await page.getByRole("tab", { name: /Rejected/ }).click();
  await pause(page, 3000);
  await page.getByRole("tab", { name: /Accepted/ }).click();
  await pause(page);
  await page.getByRole("link", { name: "Static analysis" }).first().click();
  await pause(page, 3500);
  await keep(page, "forged-evidence-rejected");
});

test("Log4Shell: are we affected?", async ({ page, problems }) => {
  void problems;
  await open(page, "/supply-chain");
  await pause(page);
  await page.getByRole("link", { name: "Are we affected?", exact: true }).click();
  await pause(page, 3000);
  await page.getByRole("link", { name: "Claims API" }).first().click();
  await pause(page, 2500);
  await page.getByRole("link", { name: "CVE-2021-44228" }).click();
  await pause(page, 2000);
  await keep(page, "log4shell-are-we-affected");
});
