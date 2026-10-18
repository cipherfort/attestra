// SPDX-License-Identifier: Apache-2.0
// Keyboard-only paths and reduced motion: everything the mouse can do on the main journeys, the keyboard can too.
import { expect, test, visit } from "./fixtures";

test("the skip link moves focus past the navigation", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to content" });
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("a table row opens with the keyboard", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps");
  const first = page.locator("main tbody tr").first().getByRole("link").first();
  await first.focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/apps\/APP-\d{5}$/);
});

test("tabs move with the arrow keys and the URL follows", async ({ page, problems }) => {
  void problems;
  await visit(page, "/apps/APP-00001");
  await page.getByRole("tab", { name: "Overview" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: /Controls/ })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/apps\/APP-00001\/controls$/);
});

test("a drawer opens from the keyboard, traps focus and closes with Escape", async ({ page, problems }) => {
  void problems;
  await visit(page, "/controls");
  await page.getByRole("link", { name: "Default branch protected" }).focus();
  await page.keyboard.press("Enter");
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  for (let i = 0; i < 12; i++) await page.keyboard.press("Tab");
  expect(await drawer.evaluate((d) => d.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(page).toHaveURL(/\/controls$/);
});

test("reduced motion turns transitions and animations off", async ({ page, problems }) => {
  void problems;
  await page.emulateMedia({ reducedMotion: "reduce" });
  await visit(page, "/");
  const sidebar = page.locator("aside").first();
  const duration = await sidebar.evaluate((el) => getComputedStyle(el).transitionDuration);
  expect(parseFloat(duration)).toBeLessThan(0.001);
});
