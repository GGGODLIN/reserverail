import { describe, test } from "@e2e-dev/web";
import { expect } from "e2e";
import { ACT_BUTTON, PUBLIC_SIGNAL_NAMES } from "../support/workbench.ts";

describe("Story 6: private witness vs public signals, and zero-trust verification", () => {
  test("the CFO private witness holds balance, floor and cap; the auditor's 7 public signals carry none of them", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      screen.getByRole("button", ACT_BUTTON.act1).tap(),
    ]);

    const cfo = screen.getByRole("region", "CFO private witness");
    await expect(cfo).toContainText("PRIVATE WITNESS — loaded locally, never on-chain");
    await expect(cfo.getByRole("row", "Treasury balance 100,000")).toBeVisible();
    await expect(cfo.getByRole("row", "Payroll reserve floor 60,000")).toBeVisible();
    await expect(cfo.getByRole("row", "Epoch spend cap 50,000")).toBeVisible();

    const auditor = screen.getByRole("region", "External auditor public signals");
    await expect(auditor.getByRole("rowheader")).toHaveText([...PUBLIC_SIGNAL_NAMES]);
    await expect(auditor.getByRole("row", "amount 12000")).toBeVisible();
    await expect(auditor).toContainText("Confidential values found in public signals: 0 of 3");
    await expect(auditor.getByRole("link", "View on zkVerify Subscan")).toHaveAttribute(
      "href",
      /^https:\/\/zkverify\.subscan\.io\/extrinsic\/0xa14dbafc/,
    );

    const auditorText = (await auditor.textContent()) ?? "";
    const cfoText = (await cfo.textContent()) ?? "";
    for (const secret of ["100,000", "60,000", "50,000"]) {
      // The same substring test finds each value in the CFO panel, so its absence below is meaningful.
      expect(cfoText).toContain(secret);
      expect(auditorText).not.toContain(secret);
      expect(auditorText).not.toContain(secret.replace(",", ""));
    }
  });

  test("editing the amount across the C₀ payroll floor flips the circuit between reject and settle", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const form = screen.getByRole("form", "Propose a payment");
    const gate = screen.getByRole("region", "ReserveRail gate");
    await form.getByLabel("Recipient").fill("AWS");

    await form.getByLabel("Amount").fill("40001");
    await expect(form).toContainText("Circuit preview: would breach the payroll reserve floor");
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      form.getByRole("button", "Propose payment").tap(),
    ]);
    await expect(gate.getByRole("article", "Step 1")).toContainText("REJECTED · PAYROLL_FLOOR_BREACH");

    await form.getByLabel("Amount").fill("40000");
    await expect(form).toContainText("Circuit preview: within bounds");
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      form.getByRole("button", "Propose payment").tap(),
    ]);
    await expect(gate.getByRole("article", "Step 1")).toContainText("APPROVED · C₀ → C₁");
    await expect(screen.getByRole("region", "CFO private witness").getByRole("row", "Spent this epoch 40,000")).toBeVisible();
  });

  test("the browser verifies Groth16 and the Audit Chain itself, and a tampered amount fails everywhere", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      screen.getByRole("button", ACT_BUTTON.act1).tap(),
    ]);
    // Server-side verification is cut off: every verdict below must come from this browser.
    await browser.route("**/api/demo/verify-chain", (route) => route.abort());

    const verify = screen.getByRole("region", "Zero-trust verification");
    await verify.getByRole("button", "Verify Groth16 proof in this browser").tap();
    await expect(verify).toContainText("Groth16 proof: VALID", { timeout: 20_000 });
    await verify.getByRole("button", "Verify audit chain in this browser").tap();
    await expect(verify).toContainText("Audit chain: VALID · 1 receipt", { timeout: 20_000 });

    await verify.getByRole("button", "Tamper & Send to Kurier Mainnet").tap();
    const tamper = verify.getByRole("group", "Tamper test result");
    await expect(tamper).toContainText("Amount 12000 → 12001", { timeout: 20_000 });
    await expect(tamper).toContainText("This browser: INVALID");
    await expect(tamper).toContainText("Server local verify: FAILED");
    await expect(tamper).toContainText("Kurier Mainnet: not attempted (DETERMINISTIC_REPLAY)");
    await expect(tamper).toContainText("Audit chain with the tampered receipt: INVALID · INVALID_PROOF");

    const bundle = await browser.waitForDownload(() =>
      verify.getByRole("button", "Download proof bundle").tap(),
    );
    expect(bundle.suggestedFilename).toMatch(/^reserverail-proof-C1-sbx_[0-9a-f]{12}\.json$/);
  });
});
