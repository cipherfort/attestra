// SPDX-License-Identifier: Apache-2.0
import { expect, test, visit } from "./fixtures";

const PAGES: [string, string][] = [
  ["/apps", "Applications"],
  ["/apps/APP-00001", "Claims API"],
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
