import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function login(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to deterministic demo" }).click();
  await expect(
    page.getByRole("heading", { name: "Health and active incidents" })
  ).toBeVisible();
}

test("canonical checkout journey is accessible and server-authoritative", async ({
  page
}) => {
  await login(page);
  expect(
    await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage)
    }))
  ).toEqual({ local: [], session: [] });

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);

  await page.getByRole("link", { name: "Investigation" }).click();
  await expect(
    page.getByText("<script>alert('untrusted')</script> is rendered as evidence text.")
  ).toBeVisible();
  await expect(page.locator("script").filter({ hasText: "untrusted" })).toHaveCount(0);

  await page.getByRole("link", { name: "Approvals" }).click();
  await expect(
    page.getByRole("button", { name: "Submit exact-scope approval" })
  ).toBeDisabled();
  await expect(
    page.getByText(/Agents and request creators cannot self-approve/)
  ).toBeVisible();

  await page.getByRole("link", { name: "Effects" }).click();
  await expect(page.locator(".status-ambiguous")).toContainText("ambiguous");
  await expect(page.locator(".status-success")).toHaveCount(0);
});

test("tenant switch tears down cached tenant data", async ({ page }) => {
  await login(page);
  await expect(page.getByText("Checkout failure rate above regional SLO")).toBeVisible();
  await page.getByLabel("Tenant").selectOption("tenant-beta");
  await expect(page.getByText("Checkout failure rate above regional SLO")).toHaveCount(0);
  await expect(page.getByText("No authorized records are available.")).toHaveCount(2);
});

test("UI lifecycle cannot affect the investigation runtime", async ({
  page,
  request
}) => {
  await login(page);
  await page.close();
  const health = await request.get("http://127.0.0.1:8123/healthz");
  expect(health.ok()).toBe(true);
  expect((await health.json()).status).toBe("ok");
});
