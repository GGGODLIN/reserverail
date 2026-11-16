import { describe, test } from "@e2e-dev/web";
import type { Screen } from "e2e";
import { expect } from "e2e";
import { ACT_BUTTON } from "../support/workbench.ts";

const ALL_STAGES_COMPLETE = [
  "Local Verified complete",
  "Kurier Submitted complete",
  "IncludedInBlock complete",
  "Finalized complete",
];

async function expectIdenticalIntent(screen: Screen, step: number): Promise<string> {
  const name = `Payment intent, step ${step}`;
  const naive = await screen.getByRole("region", "Naive agent").getByRole("group", name).textContent();
  const gate = await screen.getByRole("region", "ReserveRail gate").getByRole("group", name).textContent();
  expect(gate).toBe(naive);
  return naive ?? "";
}

describe("Story 5/F5: three guided acts", () => {
  test("Act 1: the naive agent pays the injected wallet, ReserveRail rejects it and settles the real AWS invoice", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const run = screen.getByRole("button", ACT_BUTTON.act1);
    await Promise.all([browser.waitForResponse(/\/api\/demo\/propose$/), run.tap()]);
    await expect(run).toBeEnabled({ timeout: 1_000 });

    const naive = screen.getByRole("region", "Naive agent");
    const gate = screen.getByRole("region", "ReserveRail gate");
    await expect(naive.getByRole("article", "Step 1")).toContainText("APPROVED", { timeout: 1_000 });
    await expect(gate.getByRole("article", "Step 1")).toContainText("REJECTED · ALLOWLIST_MISS");
    await expect(gate.getByRole("article", "Step 2")).toContainText("APPROVED · C₀ → C₁");
    await expect(naive.getByRole("article", "Step 2")).toContainText("APPROVED");

    const injected = await expectIdenticalIntent(screen, 1);
    expect(injected).toContain("0xBAD0000000000000000000000000000000000999");
    expect(injected).toContain("12,000");
    const legit = await expectIdenticalIntent(screen, 2);
    expect(legit).toContain("0x1111111111111111111111111111111111111001");

    await expect(
      gate.getByRole("article", "Step 2").getByRole("list", "Receipt stages").getByRole("listitem"),
    ).toHaveText(ALL_STAGES_COMPLETE);
    await expect(screen.getByRole("status", "Workbench status")).toContainText("Act 1 complete");
  });

  test("Act 2: three $12,000 shots pass the naive cap, and ReserveRail stops the third with EPOCH_CAP_EXCEEDED", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const run = screen.getByRole("button", ACT_BUTTON.act2);
    await Promise.all([browser.waitForResponse(/\/api\/demo\/act$/), run.tap()]);
    await expect(run).toBeEnabled({ timeout: 1_000 });

    const naive = screen.getByRole("region", "Naive agent");
    const gate = screen.getByRole("region", "ReserveRail gate");
    await expect(naive.getByRole("article")).toHaveCount(3, { timeout: 1_000 });
    for (const step of [1, 2, 3]) {
      await expect(naive.getByRole("article", `Step ${step}`)).toContainText("APPROVED");
      const intent = await expectIdenticalIntent(screen, step);
      expect(intent).toContain("Stripe");
    }
    await expect(gate.getByRole("article", "Step 1")).toContainText("APPROVED · C₀ → C₁");
    await expect(gate.getByRole("article", "Step 2")).toContainText("APPROVED · C₁ → C₂");
    await expect(gate.getByRole("article", "Step 3")).toContainText("REJECTED · EPOCH_CAP_EXCEEDED");
    await expect(gate.getByRole("list", "Ledger commitment chain").getByRole("listitem")).toHaveText(["C₀", "C₁", "C₂"]);
  });

  test("Act 3: two agents race for the same reserve; one settles, the runner-up is re-checked and hits PAYROLL_FLOOR_BREACH", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const run = screen.getByRole("button", ACT_BUTTON.act3);
    await Promise.all([browser.waitForResponse(/\/api\/demo\/act$/), run.tap()]);
    await expect(run).toBeEnabled({ timeout: 1_000 });

    const naive = screen.getByRole("region", "Naive agent");
    const gate = screen.getByRole("region", "ReserveRail gate");
    await expect(naive.getByRole("article")).toHaveCount(2, { timeout: 1_000 });
    await expect(naive.getByRole("article", "Step 1")).toContainText("APPROVED");
    await expect(naive.getByRole("article", "Step 2")).toContainText("APPROVED");
    await expectIdenticalIntent(screen, 1);
    await expectIdenticalIntent(screen, 2);

    await expect(gate.getByRole("article").filter({ hasText: "APPROVED · C₀ → C₁" })).toHaveCount(1);
    const runnerUp = gate.getByRole("article").filter({ hasText: "REJECTED · PAYROLL_FLOOR_BREACH" });
    await expect(runnerUp).toHaveCount(1);
    await expect(runnerUp).toContainText("Re-checked against C₁ after the In-Flight Lease · 0 stale proofs");
  });
});
