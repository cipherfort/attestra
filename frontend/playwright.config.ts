// SPDX-License-Identifier: Apache-2.0
// Browser tests against a running API that serves the built UI with the real CSP, in development sign-in mode with
// the demo world (`aap demo seed`): E2E_BASE_URL (default http://127.0.0.1:8766). Run: npx playwright test
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:8766",
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
});
