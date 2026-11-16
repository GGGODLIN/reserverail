import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  abbreviateHex,
  acceptError,
  acceptRun,
  acceptSnapshot,
  confidentialFieldsInSignals,
  createScopedView,
  enterScope,
  fieldToHex,
  isFinalReceiptStatus,
  previewCircuitOutcome,
  receiptStageProgress,
  ticketOf,
} from "../web/src/model/workbench-model.ts";

interface Snapshot {
  readonly sandboxId: string;
  readonly head: string;
}

// Public signals of a real Act 1 legitimate AWS settlement (C0 -> C1) returned by POST /api/demo/propose.
const ACT1_LEGIT_PUBLIC_SIGNALS = [
  "17899930462686436627025121097511576833237245406070455792717234463395872570282",
  "11967719255062927006718649243525882303949292943153787168131954881556306139408",
  "9106892448694265541213812064998974958659599874142867358695069931783268624436",
  "341735720648563745643579565712835384910761565655495128908610932328401463842",
  "12000",
  "1",
  "19488067298517112473414125300119190021008966077015353882103704429301274580305",
] as const;

const C0_BOUNDS = { balance: "100000", payrollFloor: "60000", epochCap: "50000", spentSoFar: "0" };

describe("Ticket 03 workbench model", () => {
  it("Story 7/F1: updates issued for an earlier scope never land after Reset or a scope switch", () => {
    let view = createScopedView<Snapshot, string>("sbx_aaaaaaaaaaaa");
    const beforeReset = ticketOf(view);
    view = acceptSnapshot(view, beforeReset, { sandboxId: "sbx_aaaaaaaaaaaa", head: "C2 submitted" });
    view = acceptError(view, beforeReset, "Kurier relay timed out");
    assert.equal(view.snapshot?.head, "C2 submitted");
    assert.equal(view.error, "Kurier relay timed out");

    view = enterScope(view, "sbx_aaaaaaaaaaaa");
    assert.equal(view.snapshot, null);
    assert.equal(view.error, null);
    assert.equal(view.run, null);
    view = acceptSnapshot(view, ticketOf(view), { sandboxId: "sbx_aaaaaaaaaaaa", head: "C0" });

    view = acceptSnapshot(view, beforeReset, { sandboxId: "sbx_aaaaaaaaaaaa", head: "C2 finalized" });
    view = acceptError(view, beforeReset, "late relay failure");
    view = acceptRun(view, beforeReset, "act2 steps");
    assert.equal(view.snapshot?.head, "C0");
    assert.equal(view.error, null);
    assert.equal(view.run, null);

    const actInFlight = ticketOf(view);
    view = enterScope(view, null);
    assert.equal(view.sandboxId, null);
    view = acceptRun(view, actInFlight, "act3 steps for sbx_aaaaaaaaaaaa");
    view = acceptSnapshot(view, actInFlight, { sandboxId: "sbx_aaaaaaaaaaaa", head: "C1" });
    assert.equal(view.run, null);
    assert.equal(view.snapshot, null);

    view = acceptSnapshot(view, ticketOf(view), { sandboxId: "sbx_bbbbbbbbbbbb", head: "C0" });
    assert.equal(view.sandboxId, "sbx_bbbbbbbbbbbb");
    assert.equal(view.snapshot?.head, "C0");
    view = acceptSnapshot(view, ticketOf(view), { sandboxId: "sbx_aaaaaaaaaaaa", head: "C1" });
    assert.equal(view.snapshot?.sandboxId, "sbx_bbbbbbbbbbbb");

    view = acceptRun(view, ticketOf(view), "act1 steps for sbx_bbbbbbbbbbbb");
    view = acceptError(view, ticketOf(view), "Amount is required");
    assert.equal(view.run, "act1 steps for sbx_bbbbbbbbbbbb");
    assert.equal(view.error, "Amount is required");
  });

  it("Story 5/F5: receipt status streams Local Verified -> Kurier Submitted -> IncludedInBlock -> Finalized", () => {
    const stages = (status: string): string[] =>
      receiptStageProgress(status).map((progress) => `${progress.stage}:${progress.state}`);

    assert.deepEqual(stages("PendingSubmit"), [
      "Local Verified:complete",
      "Kurier Submitted:pending",
      "IncludedInBlock:pending",
      "Finalized:pending",
    ]);
    assert.deepEqual(stages("Submitted"), [
      "Local Verified:complete",
      "Kurier Submitted:complete",
      "IncludedInBlock:pending",
      "Finalized:pending",
    ]);
    assert.deepEqual(stages("IncludedInBlock"), [
      "Local Verified:complete",
      "Kurier Submitted:complete",
      "IncludedInBlock:complete",
      "Finalized:pending",
    ]);
    assert.deepEqual(stages("Finalized"), [
      "Local Verified:complete",
      "Kurier Submitted:complete",
      "IncludedInBlock:complete",
      "Finalized:complete",
    ]);
    assert.equal(isFinalReceiptStatus("Finalized"), true);
    assert.equal(isFinalReceiptStatus("IncludedInBlock"), false);
  });

  it("Story 6: balance, payroll floor and epoch cap match none of a real receipt's public signals", () => {
    const confidential = { balance: "100000", payrollFloor: "60000", epochCap: "50000" };
    assert.deepEqual(confidentialFieldsInSignals(confidential, ACT1_LEGIT_PUBLIC_SIGNALS), []);

    // Same check against a signal set that does carry the floor, so a silent check cannot pass.
    const leaking: string[] = [...ACT1_LEGIT_PUBLIC_SIGNALS];
    leaking[4] = "60000";
    assert.deepEqual(confidentialFieldsInSignals(confidential, leaking), ["payrollFloor"]);
  });

  it("Story 6: editing the amount across C0 thresholds flips the circuit outcome preview", () => {
    assert.equal(previewCircuitOutcome(C0_BOUNDS, 40_000n), "WITHIN_BOUNDS");
    assert.equal(previewCircuitOutcome(C0_BOUNDS, 40_001n), "PAYROLL_FLOOR_BREACH");
    assert.equal(previewCircuitOutcome(C0_BOUNDS, 50_001n), "EPOCH_CAP_EXCEEDED");

    // Act 2 after two $12,000 shots, and Act 3 after the race winner: the server rejected the next request with these codes.
    const act2AfterTwoShots = { balance: "100000", payrollFloor: "55000", epochCap: "30000", spentSoFar: "24000" };
    assert.equal(previewCircuitOutcome(act2AfterTwoShots, 12_000n), "EPOCH_CAP_EXCEEDED");
    const act3AfterWinner = { balance: "100000", payrollFloor: "60000", epochCap: "50000", spentSoFar: "25000" };
    assert.equal(previewCircuitOutcome(act3AfterWinner, 25_000n), "PAYROLL_FLOOR_BREACH");
  });

  it("Story 10/F2: 66-character hex abbreviates to 0x3859...1fba and field elements render as 66-character hex", () => {
    assert.equal(
      abbreviateHex("0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba"),
      "0x3859...1fba",
    );
    assert.equal(
      abbreviateHex("0x1111111111111111111111111111111111111001"),
      "0x1111111111111111111111111111111111111001",
    );
    assert.equal(fieldToHex("255"), `0x${"0".repeat(62)}ff`);
    assert.equal(
      fieldToHex("13654436011996579767322874227440036850196879404656994590428961289007688052495"),
      "0x1e30230c660e478cd50dd807c70dda9048396968f9680f04753f8aa5f7abef0f",
    );
  });
});
