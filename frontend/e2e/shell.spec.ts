// SPDX-License-Identifier: Apache-2.0
import { expect, test, visit } from "./fixtures";

const PAGES: [string, string][] = [
  ["/", "Overview"],
  ["/apps", "Applications"],
  ["/apps/APP-00001", "Claims API"],
  ["/findings", "Findings"],
  ["/evidence", "Evidence"],
  ["/cve", "Are we affected?"],
  ["/leadership", "Leadership"],
  ["/exceptions", "Exceptions"],
  ["/assessments", "Assessments"],
  ["/integrations", "Integrations"],
];

for (const [path, heading] of PAGES) {
  test(`${path} renders inside the shell under the real CSP`, async ({ page, problems }) => {
    void problems;
    await visit(page, path);
    await expect(page.getByRole("heading", { level: 1 }).first()).toContainText(heading);
    await expect(page.locator("main")).not.toContainText("Couldn't load");
  });
}

test("the administrator sees Admin and nothing about applications", async ({ page, problems }) => {
  void problems;
  await visit(page, "/admin", "padmin");
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link", { name: "Admin" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Exceptions" })).toHaveCount(0);
});

test("a deep link loads directly and old hash links are redirected", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps/APP-00001");
  await expect(page.getByRole("link", { name: "Applications" }).first()).toHaveAttribute("aria-current", "page");
  await page.goto("/?as=cpatel#/apps/APP-00002");
  await expect(page).toHaveURL(/\/apps\/APP-00002/);
  await expect(page.getByRole("heading", { level: 1 }).first()).toContainText("Payments Portal");
});

test("in-app links navigate without a full reload", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  await page.evaluate(() => { (window as unknown as { marker: number }).marker = 1; });
  await page.getByRole("link", { name: "Claims API" }).click();
  await expect(page).toHaveURL(/\/apps\/APP-00001$/);
  expect(await page.evaluate(() => (window as unknown as { marker?: number }).marker)).toBe(1);
});

test("the command palette opens with the keyboard and jumps to an application", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  await page.keyboard.press("ControlOrMeta+k");
  const dialog = page.getByRole("dialog", { name: "Command palette" });
  await expect(dialog).toBeVisible();
  await page.keyboard.type("Payments");
  await expect(dialog.getByRole("option", { name: /Payments Portal/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden();
  await expect(page).toHaveURL(/\/apps\/APP-00002$/);
});

test("the theme switches and is remembered", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: /^Account:/ }).click();
  await page.getByRole("menuitem", { name: "Light" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("the applications table searches, filters by tier and sorts", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  const rows = page.locator("main tbody tr");
  await expect(rows.first()).toBeVisible();
  const all = await rows.count();
  await page.getByRole("textbox", { name: "Search applications" }).fill("Payments");
  await expect(rows).toHaveCount(1);
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(rows).toHaveCount(all);
  await page.getByRole("button", { name: "Tier" }).first().click();
  await page.getByRole("menuitemcheckbox", { name: /Tier 1/ }).click();
  await page.keyboard.press("Escape");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("Claims API");
});

test("application tabs live in the URL and a control opens in a drawer", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps/APP-00001");
  await page.getByRole("tab", { name: /Controls/ }).click();
  await expect(page).toHaveURL(/\/apps\/APP-00001\/controls/);
  await page.getByRole("button", { name: /Dependency review gates/ }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("How it is proven");
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.locator("main tbody tr").first()).toBeVisible();
  await page.reload();
  await expect(page.getByRole("tab", { name: "Evidence" })).toHaveAttribute("aria-selected", "true");
});

test("the forged submission is rejected with its reason, and accepted evidence shows how it was verified", async ({ page, problems }) => {
  void problems;
  await visit(page, "/evidence");
  await page.getByRole("tab", { name: /Rejected/ }).click();
  await expect(page).toHaveURL(/\/evidence\/view\/rejected/);
  await expect(page.locator("main")).toContainText("Untrusted producer");
  await expect(page.locator("main")).toContainText("refused");
  await page.getByRole("tab", { name: /Accepted/ }).click();
  await page.getByRole("link", { name: "Static analysis" }).first().click();
  const chain = page.getByRole("list", { name: "How this evidence was verified" });
  await expect(chain).toContainText("Produced by an approved workflow at an approved commit");
  await expect(chain).toContainText("Append-only ledger");
});

test("a finding opens from the global list with its risk explanation", async ({ page, problems }) => {
  void problems;
  await visit(page, "/findings");
  await page.locator("main tbody tr").first().getByRole("link").first().click();
  await expect(page.getByRole("heading", { name: /Why P\d|Why unscored/ })).toBeVisible();
  await expect(page.locator("main")).toContainText("History");
});
