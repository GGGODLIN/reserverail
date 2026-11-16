import { describe, test } from "@e2e-dev/web";
import { expect } from "e2e";
import { ACT_BUTTON, sandboxIdOf, serverStateOf } from "../support/workbench.ts";

describe("Story 5/7 on a LIVE relay (simulated Kurier, no credentials)", () => {
  test("Act 1 unlocks within 1 s of the relay accepting the proof while stages stream to Finalized", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    await expect(screen.getByRole("banner").getByText("LIVE", { exact: true })).toBeVisible();

    const run = screen.getByRole("button", ACT_BUTTON.act1);
    await Promise.all([browser.waitForResponse(/\/api\/demo\/propose$/), run.tap()]);
    await expect(run).toBeEnabled({ timeout: 1_000 });

    const stages = screen
      .getByRole("region", "ReserveRail gate")
      .getByRole("article", "Step 2")
      .getByRole("list", "Receipt stages")
      .getByRole("listitem");
    await expect(stages).toHaveText(
      ["Local Verified complete", "Kurier Submitted complete", "IncludedInBlock pending", "Finalized pending"],
      { timeout: 1_000 },
    );
    await expect(stages).toHaveText(
      ["Local Verified complete", "Kurier Submitted complete", "IncludedInBlock complete", "Finalized pending"],
      { timeout: 8_000 },
    );
    await expect(stages).toHaveText(
      ["Local Verified complete", "Kurier Submitted complete", "IncludedInBlock complete", "Finalized complete"],
      { timeout: 10_000 },
    );
  });

  test("Reset while finality is in flight shows a clean C₀ that later relay updates never overwrite", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const sandboxId = sandboxIdOf(await browser.url());
    const gate = screen.getByRole("region", "ReserveRail gate");
    const cfo = screen.getByRole("region", "CFO private witness");
    const chain = gate.getByRole("list", "Ledger commitment chain").getByRole("listitem");

    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/act$/),
      screen.getByRole("button", ACT_BUTTON.act2).tap(),
    ]);
    await expect(chain).toHaveText(["C₀", "C₁", "C₂"], { timeout: 1_000 });
    await expect(gate.getByRole("article", "Step 1").getByRole("list", "Receipt stages").getByRole("listitem").last()).toHaveText(
      "Finalized pending",
    );

    await screen.getByRole("button", "Reset to C₀").tap();
    await expect(chain).toHaveText(["C₀"], { timeout: 1_000 });
    await expect(cfo.getByRole("row", "Spent this epoch 0")).toBeVisible({ timeout: 1_000 });

    // Wait until the relay has finalized both pre-reset proofs on the server.
    await expect
      .poll(async () => (await serverStateOf(app, sandboxId)).mainnetExplorerLinks.length, { timeout: 20_000 })
      .toBe(3);
    await expect(chain).toHaveText(["C₀"]);
    await expect(cfo.getByRole("row", "Spent this epoch 0")).toBeVisible();
    await expect(gate.getByRole("article")).toHaveCount(0);
    await expect(screen.getByRole("alert")).toHaveCount(0);

    await browser.reload();
    await expect(screen.getByRole("region", "Mainnet explorer receipts").getByRole("link")).toHaveCount(3);
  });

  test("switching scope while an act and its finality are in flight keeps the old results, balances and error banner out", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const first = sandboxIdOf(await browser.url());
    const form = screen.getByRole("form", "Propose a payment");
    const naive = screen.getByRole("region", "Naive agent");
    const gate = screen.getByRole("region", "ReserveRail gate");

    await form.getByLabel("Recipient").fill("AWS");
    await form.getByLabel("Amount").fill("-5");
    await form.getByRole("button", "Propose payment").tap();
    await expect(screen.getByRole("alert")).toBeVisible();

    await screen.getByRole("button", ACT_BUTTON.act2).tap();
    await screen.getByRole("button", "New sandbox").tap();
    await expect.poll(async () => sandboxIdOf(await browser.url())).not.toBe(first);
    const second = sandboxIdOf(await browser.url());
    await expect(screen.getByRole("status", "Sandbox scope")).toHaveText(second);

    // The first scope keeps proving, relaying and finalizing on the server in the meantime.
    await expect
      .poll(
        async () =>
          (await serverStateOf(app, first)).receipts.filter((receipt) => receipt.provenance.status === "Finalized").length,
        { timeout: 20_000 },
      )
      .toBe(2);

    await expect(screen.getByRole("status", "Sandbox scope")).toHaveText(second);
    await expect(screen.getByRole("alert")).toHaveCount(0);
    await expect(naive.getByRole("article")).toHaveCount(0);
    await expect(gate.getByRole("article")).toHaveCount(0);
    await expect(gate.getByRole("list", "Ledger commitment chain").getByRole("listitem")).toHaveText(["C₀"]);
    await expect(screen.getByRole("region", "CFO private witness").getByRole("row", "Spent this epoch 0")).toBeVisible();

    // Control: the same locators do pick up this scope's own results.
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      screen.getByRole("button", ACT_BUTTON.act1).tap(),
    ]);
    await expect(naive.getByRole("article")).toHaveCount(2);
    await expect(gate.getByRole("article")).toHaveCount(2);
  });
});
