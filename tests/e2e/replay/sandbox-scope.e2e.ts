import { describe, test } from "@e2e-dev/web";
import { expect } from "e2e";
import { ACT_BUTTON, sandboxIdOf } from "../support/workbench.ts";

describe("Story 5: Sandbox Scope per visitor", () => {
  test("opening / assigns a fresh sbx_ scope at C₀, and Reset restores C₀ within 1 s while keeping mainnet links", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\/\?sandbox=sbx_[0-9a-f]{12}$/);
    const sandboxId = sandboxIdOf(await browser.url());
    await expect(screen.getByRole("status", "Sandbox scope")).toHaveText(sandboxId);

    const cfo = screen.getByRole("region", "CFO private witness");
    const chain = screen.getByRole("region", "ReserveRail gate").getByRole("list", "Ledger commitment chain");
    const links = screen.getByRole("region", "Mainnet explorer receipts");
    await expect(cfo.getByRole("row", "Treasury balance 100,000")).toBeVisible();
    await expect(cfo.getByRole("row", "Spent this epoch 0")).toBeVisible();
    await expect(chain.getByRole("listitem")).toHaveText(["C₀"]);
    await expect(links.getByRole("link", /0xa14d\.\.\.00ea/)).toBeVisible();

    await screen.getByRole("button", ACT_BUTTON.act2).tap();
    await expect(cfo.getByRole("row", "Spent this epoch 24,000")).toBeVisible({ timeout: 15_000 });
    await expect(chain.getByRole("listitem")).toHaveText(["C₀", "C₁", "C₂"]);

    await screen.getByRole("button", "Reset to C₀").tap();
    await expect(cfo.getByRole("row", "Spent this epoch 0")).toBeVisible({ timeout: 1_000 });
    await expect(chain.getByRole("listitem")).toHaveText(["C₀"], { timeout: 1_000 });
    await expect(cfo.getByRole("row", "Payroll reserve floor 60,000")).toBeVisible();
    await expect(links.getByRole("link", /0xa14d\.\.\.00ea/)).toBeVisible();
    await expect(browser).toHaveURL(new RegExp(`\\?sandbox=${sandboxId}$`));
  });

  test("a second visitor gets an independent scope, while the copied ?sandbox= URL shares state", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const first = sandboxIdOf(await browser.url());
    const cfo = screen.getByRole("region", "CFO private witness");
    await screen.getByRole("button", ACT_BUTTON.act2).tap();
    await expect(cfo.getByRole("row", "Spent this epoch 24,000")).toBeVisible({ timeout: 15_000 });

    await screen.getByRole("button", "Copy sandbox URL").tap();
    await expect(screen.getByRole("status", "Workbench status")).toContainText(`?sandbox=${first}`);

    // A fresh browser context stands in for an unrelated visitor.
    await app.clearState();
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const second = sandboxIdOf(await browser.url());
    expect(second).not.toBe(first);
    await expect(cfo.getByRole("row", "Spent this epoch 0")).toBeVisible();

    // The copied URL opened in another tab lands on the first visitor's shared state.
    await app.open(`/?sandbox=${first}`);
    await expect(screen.getByRole("status", "Sandbox scope")).toHaveText(first);
    await expect(cfo.getByRole("row", "Spent this epoch 24,000")).toBeVisible();
    await expect(
      screen.getByRole("region", "ReserveRail gate").getByRole("list", "Ledger commitment chain").getByRole("listitem"),
    ).toHaveText(["C₀", "C₁", "C₂"]);
  });
});
