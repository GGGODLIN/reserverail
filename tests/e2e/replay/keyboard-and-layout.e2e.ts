import { describe, test } from "@e2e-dev/web";
import { expect } from "e2e";
import { ACT_BUTTON } from "../support/workbench.ts";

const VK_HASH = "0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba";

// Page-side sources: the root tsconfig carries no DOM types, so these stay strings the browser evaluates.
// Name of the focused control as a keyboard user meets it: aria-label, then <label>, then text without aria-hidden parts.
const FOCUSED_NAME = `() => {
  const el = document.activeElement;
  if (!el || el === document.body) return "";
  const labelled = el.getAttribute("aria-label");
  if (labelled) return labelled.trim();
  if ("labels" in el && el.labels && el.labels[0]) return (el.labels[0].textContent ?? "").trim();
  const visible = el.cloneNode(true);
  visible.querySelectorAll('[aria-hidden="true"]').forEach((node) => node.remove());
  return (visible.textContent ?? "").trim();
}`;

const OVERFLOW_PX = "document.documentElement.scrollWidth - document.documentElement.clientWidth";
const HORIZONTAL_OVERFLOW = `() => ${OVERFLOW_PX}`;

describe("Story 10/F2: keyboard, announcements, hex layout and relay badges", () => {
  test("every act trigger, input, perspective toggle and verification control works from the keyboard", async ({
    app,
    screen,
    browser,
  }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const status = screen.getByRole("status", "Workbench status");

    await screen.getByRole("button", ACT_BUTTON.act1).press("Enter");
    await expect(status).toContainText("Act 1 complete", { timeout: 20_000 });

    const reached = new Set<string>();
    for (let press = 0; press < 80; press += 1) {
      await browser.keyboard.press("Tab");
      reached.add(await browser.evaluate<string>(FOCUSED_NAME));
    }
    for (const control of [
      "Copy sandbox URL",
      "New sandbox",
      "Reset to C₀",
      ACT_BUTTON.act1,
      ACT_BUTTON.act2,
      ACT_BUTTON.act3,
      "Recipient",
      "Amount",
      "Memo",
      "Propose payment",
      "CFO private witness",
      "Receipt",
      "Verify Groth16 proof in this browser",
      "Verify audit chain in this browser",
      "Tamper & Send to Kurier Mainnet",
      "Download proof bundle",
      "Expand vkHash",
    ]) {
      expect(reached.has(control), `Tab never reached "${control}"`).toBe(true);
    }

    const toggle = screen.getByRole("button", "CFO private witness");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await toggle.press("Space");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.press("Enter");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");

    const form = screen.getByRole("form", "Propose a payment");
    await form.getByLabel("Recipient").pressSequentially("Stripe");
    await form.getByLabel("Amount").pressSequentially("5000");
    await form.getByLabel("Amount").press("Enter");
    await expect(status).toContainText("Proposal settled: ReserveRail APPROVED", { timeout: 20_000 });

    const verify = screen.getByRole("region", "Zero-trust verification");
    await verify.getByRole("button", "Verify audit chain in this browser").press("Enter");
    await expect(status).toContainText("Audit chain: VALID · 2 receipts", { timeout: 20_000 });
    await verify.getByRole("button", "Expand vkHash").press("Enter");
    await expect(verify.getByText(VK_HASH)).toBeVisible();
  });

  test("expanded 66-character hex values wrap inside the layout at 375 px and 1440 px", async ({
    app,
    screen,
    browser,
  }) => {
    await browser.setViewport({ width: 375, height: 812 });
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      screen.getByRole("button", ACT_BUTTON.act1).tap(),
    ]);

    const verify = screen.getByRole("region", "Zero-trust verification");
    await expect(verify.getByText("0x3859...1fba")).toBeVisible();
    await verify.getByRole("button", "Expand vkHash").tap();
    await expect(verify.getByText(VK_HASH)).toBeVisible();
    const auditor = screen.getByRole("region", "External auditor public signals");
    for (const name of ["policyRoot", "prevCommitment", "newCommitment", "recipient", "invoiceHash"]) {
      await auditor.getByRole("button", `Expand ${name}`).tap();
    }
    expect(await browser.evaluate<number>(HORIZONTAL_OVERFLOW)).toBeLessThanOrEqual(0);

    // Control: the same probe reports overflow once an expanded value is forced onto one line.
    const forced = await browser.evaluate<number>(`() => {
      const el = document.querySelector('[data-hex-expanded="true"]');
      if (!el) return -1;
      el.style.whiteSpace = "nowrap";
      el.style.wordBreak = "normal";
      el.style.overflowWrap = "normal";
      el.style.display = "inline-block";
      return ${OVERFLOW_PX};
    }`);
    expect(forced).toBeGreaterThan(0);

    await browser.reload();
    await browser.setViewport({ width: 1440, height: 900 });
    await screen.getByRole("region", "Zero-trust verification").getByRole("button", "Expand vkHash").tap();
    expect(await browser.evaluate<number>(HORIZONTAL_OVERFLOW)).toBeLessThanOrEqual(0);
  });

  test("DETERMINISTIC_REPLAY badges carry the plain-language offline relay explanation", async ({ app, screen, browser }) => {
    await app.open("/");
    await expect(browser).toHaveURL(/\?sandbox=sbx_/);
    const banner = screen.getByRole("banner");
    await expect(banner.getByText("DETERMINISTIC_REPLAY")).toBeVisible();
    await expect(banner).toContainText(
      "Offline relay fallback: replaying a real on-chain receipt attestation. This Groth16 proof can still be verified zero-trust in your browser.",
    );

    await Promise.all([
      browser.waitForResponse(/\/api\/demo\/propose$/),
      screen.getByRole("button", ACT_BUTTON.act1).tap(),
    ]);
    const receipt = screen.getByRole("region", "ReserveRail gate").getByRole("article", "Step 2");
    await expect(receipt.getByText("DETERMINISTIC_REPLAY")).toBeVisible();
    await expect(receipt).toContainText("Offline relay fallback");
  });
});
