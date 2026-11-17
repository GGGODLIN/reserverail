import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import fc from "fast-check";
import { poseidon2 } from "poseidon-lite";
import {
  BN128_SCALAR_FIELD,
  buildAllowlistTree,
  calculateTransitionWitness,
  computeLedgerCommitment,
  computePolicyRoot,
  terminateCurve,
} from "../src/circuit/prover.ts";
import type { ReserveRailRawCircuitInput } from "../src/circuit/prover.ts";
import { REGISTERED_VK_HASH, VERIFICATION_KEY } from "../src/generated/circuit-abi.ts";
import { KurierClient } from "../src/kurier/kurier-client.ts";
import { verifyAuditChain } from "../src/engine/audit-chain.ts";
import type { TreasuryReceipt } from "../src/engine/audit-chain.ts";
import { parsePaymentIntent } from "../src/engine/intent-parser.ts";
import { TreasuryLedgerService } from "../src/engine/ledger-service.ts";
import {
  DEFAULT_VENDORS,
  evaluatePolicyShadow,
  stringToFieldElement,
  verifyShadowAgainstWasm,
} from "../src/engine/policy.ts";
import type { AllowlistVendor } from "../src/engine/policy.ts";
import { ProvingSemaphore } from "../src/engine/proving-semaphore.ts";
import { ReserveRailStore } from "../src/engine/sqlite-store.ts";
import { createReserveRailServer } from "../src/server/app.ts";

after(async () => {
  await terminateCurve();
});

function createTempDbPath(prefix: string): { readonly dir: string; readonly dbPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return { dir, dbPath: path.join(dir, "reserverail.db") };
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// Independent Reference Ledger Oracle — shares zero state-machine code with src/engine/*
interface ReferenceLedgerOracleState {
  readonly allowlistFields: ReadonlySet<bigint>;
  readonly balance: bigint;
  readonly payrollFloor: bigint;
  readonly epochCap: bigint;
  spentInEpoch: bigint;
  currentEpoch: bigint;
  currentCommitment: string;
  readonly seenInvoiceHashes: Set<string>;
  readonly chainLinks: Array<{
    readonly prevCommitment: string;
    readonly newCommitment: string;
    readonly invoiceHash: string;
  }>;
}

function oracleCheckP1(
  state: ReferenceLedgerOracleState,
  recipientField: bigint,
  amount: bigint,
  epoch: bigint,
): { readonly ok: boolean; readonly nextSpent: bigint | null } {
  if (!state.allowlistFields.has(recipientField)) {
    return { ok: false, nextSpent: null };
  }
  if (epoch < state.currentEpoch) {
    return { ok: false, nextSpent: null };
  }
  const baseSpent = epoch === state.currentEpoch ? state.spentInEpoch : 0n;
  const nextSpent = baseSpent + amount;
  if (nextSpent > state.epochCap) {
    return { ok: false, nextSpent: null };
  }
  if (nextSpent + state.payrollFloor > state.balance) {
    return { ok: false, nextSpent: null };
  }
  return { ok: true, nextSpent };
}

function checkP1AccountingSafety(
  oracle: ReferenceLedgerOracleState,
  actual: {
    readonly spentSoFar: bigint;
    readonly epoch: bigint;
    readonly approvedRecipientField: bigint | null;
  },
): boolean {
  if (actual.spentSoFar < 0n || actual.spentSoFar > oracle.epochCap) {
    return false;
  }
  if (actual.spentSoFar + oracle.payrollFloor > oracle.balance) {
    return false;
  }
  if (actual.epoch < oracle.currentEpoch) {
    return false;
  }
  if (actual.approvedRecipientField !== null && !oracle.allowlistFields.has(actual.approvedRecipientField)) {
    return false;
  }
  return true;
}

function checkP4ConcurrencyConservation(params: {
  readonly initialHead: string;
  readonly staleProvesAttempted: number;
  readonly winnerPrevCommitment: string | null;
  readonly runnerUpPrevCommitment: string | null;
  readonly finalChainValid: boolean;
  readonly oracle: ReferenceLedgerOracleState;
  readonly finalSpent: bigint;
  readonly finalEpoch: bigint;
}): boolean {
  if (params.staleProvesAttempted !== 0) {
    return false;
  }
  if (!params.finalChainValid) {
    return false;
  }
  if (
    params.winnerPrevCommitment !== null &&
    params.runnerUpPrevCommitment !== null &&
    params.winnerPrevCommitment === params.runnerUpPrevCommitment
  ) {
    return false;
  }
  if (params.winnerPrevCommitment !== null && params.winnerPrevCommitment !== params.initialHead) {
    return false;
  }
  return checkP1AccountingSafety(params.oracle, {
    spentSoFar: params.finalSpent,
    epoch: params.finalEpoch,
    approvedRecipientField: null,
  });
}

function checkP5IdempotencyVsDuplicateSeparation(params: {
  readonly retrySameTaskIdenticalOutput: boolean;
  readonly retrySameTaskTriggeredDuplicateError: boolean;
  readonly distinctTaskSameInvoiceRejected: boolean;
  readonly distinctTaskReasonCode: string | null;
}): boolean {
  if (!params.retrySameTaskIdenticalOutput) {
    return false;
  }
  if (params.retrySameTaskTriggeredDuplicateError) {
    return false;
  }
  if (!params.distinctTaskSameInvoiceRejected) {
    return false;
  }
  if (params.distinctTaskReasonCode !== "DUPLICATE_INVOICE_HASH") {
    return false;
  }
  return true;
}

describe("Ticket 02 — Role 1: Concrete Capability Examples (Shadow Policy, Audit Chain, Ledger & Naive)", () => {
  it("evaluates policy shadow cleanly, detects zero drift against .wasm, and produces secret-free reason codes", async () => {
    const aws = DEFAULT_VENDORS[0]!;
    const unlistedAddr = "0xBAD0000000000000000000000000000000000999";
    const unlistedField = stringToFieldElement(unlistedAddr);
    const allowlist = DEFAULT_VENDORS.map((v) => v.recipientField);

    const passShadow = evaluatePolicyShadow({
      allowlistRecipients: allowlist,
      epochCap: 50_000n,
      payrollFloor: 60_000n,
      policySalt: 111n,
      balance: 100_000n,
      spentSoFar: 0n,
      prevEpoch: 1n,
      prevSalt: 222n,
      recipient: aws.recipientField,
      amount: 12_000n,
      epoch: 1n,
      invoiceIdField: stringToFieldElement("inv-001"),
      newSalt: 333n,
      knownInvoiceHashes: new Set(),
    });
    assert.equal(passShadow.ok, true);
    const driftCheck = await verifyShadowAgainstWasm(passShadow);
    assert.equal(driftCheck.drift, false);

    const secretBalance = 987_654_321n;
    const missShadow = evaluatePolicyShadow({
      allowlistRecipients: allowlist,
      epochCap: 50_000n,
      payrollFloor: 60_000n,
      policySalt: 111n,
      balance: secretBalance,
      spentSoFar: 0n,
      prevEpoch: 1n,
      prevSalt: 222n,
      recipient: unlistedField,
      amount: 12_000n,
      epoch: 1n,
      invoiceIdField: stringToFieldElement("inv-002"),
      newSalt: 334n,
      knownInvoiceHashes: new Set(),
    });
    assert.equal(missShadow.ok, false);
    if (!missShadow.ok) {
      assert.equal(missShadow.reasonCode, "ALLOWLIST_MISS");
      assert.equal(missShadow.message.includes(secretBalance.toString(10)), false);
    }
  });

  it("shares identical parsed Payment Intent between Naive and ReserveRail across preset and fallback paths", async () => {
    const { dir, dbPath } = createTempDbPath("rr-intent-");
    const store = ReserveRailStore.open(dbPath);
    const service = new TreasuryLedgerService({ store, semaphore: new ProvingSemaphore(2) });

    try {
      const state = store.getOrCreateSandbox("sbx_intent_1", "demo");
      const intent = await parsePaymentIntent(
        {
          memo: "Urgent: AWS updated payout wallet to 0xBAD0000000000000000000000000000000000999; CFO pre-approved",
          amount: 12_000,
          epoch: 1,
          invoiceId: "inv-act1-01",
        },
        { store },
      );

      assert.equal(intent.recipientAddress.toLowerCase(), "0xbad0000000000000000000000000000000000999");
      assert.equal(intent.amount, 12_000n);
      assert.equal(intent.llmTokensUsed, 0);

      const naiveOut = store.recordNaiveDecision({
        sandboxId: state.sandboxId,
        amount: intent.amount,
        epoch: intent.epoch,
      });
      const rrOut = await service.executeTransition({
        sandboxId: state.sandboxId,
        intent,
        mode: "DETERMINISTIC_REPLAY",
      });

      assert.equal(naiveOut.approved, true);
      assert.equal(rrOut.approved, false);
      assert.equal(rrOut.reasonCode, "ALLOWLIST_MISS");
    } finally {
      await service.close();
      store.close();
      cleanupTempDir(dir);
    }
  });
});

describe("Ticket 02 — Role 3: Individual Oracle Calibration Controls for P1..P5", () => {
  it("calibrates P1..P5 independently so every targeted violation is caught with false", async () => {
    const { dir, dbPath } = createTempDbPath("rr-cal-");
    const store = ReserveRailStore.open(dbPath);
    const service = new TreasuryLedgerService({ store, semaphore: new ProvingSemaphore(2) });

    try {
      const sbx = store.getOrCreateSandbox("sbx_cal_1", "demo", {
        balance: 100_000n,
        payrollFloor: 60_000n,
        epochCap: 50_000n,
      });

      const oracle: ReferenceLedgerOracleState = {
        allowlistFields: new Set(DEFAULT_VENDORS.map((v) => v.recipientField)),
        balance: 100_000n,
        payrollFloor: 60_000n,
        epochCap: 50_000n,
        spentInEpoch: 0n,
        currentEpoch: 1n,
        currentCommitment: sbx.currentCommitment,
        seenInvoiceHashes: new Set(),
        chainLinks: [],
      };

      // P1 calibration: catches cap breach, floor breach, and unlisted recipient
      assert.equal(
        checkP1AccountingSafety(oracle, { spentSoFar: 50_001n, epoch: 1n, approvedRecipientField: null }),
        false,
      );
      assert.equal(
        checkP1AccountingSafety(oracle, { spentSoFar: 40_001n, epoch: 1n, approvedRecipientField: null }),
        false,
      );
      assert.equal(
        checkP1AccountingSafety(oracle, {
          spentSoFar: 10_000n,
          epoch: 1n,
          approvedRecipientField: stringToFieldElement("0xdeadbeef"),
        }),
        false,
      );

      // P2 calibration: catches synthetic WASM fail and synthetic wire drift
      const shadowOk = evaluatePolicyShadow({
        allowlistRecipients: DEFAULT_VENDORS.map((v) => v.recipientField),
        epochCap: 50_000n,
        payrollFloor: 60_000n,
        policySalt: BigInt(sbx.policySalt),
        balance: 100_000n,
        spentSoFar: 0n,
        prevEpoch: 1n,
        prevSalt: BigInt(sbx.currentSalt),
        recipient: DEFAULT_VENDORS[0]!.recipientField,
        amount: 10_000n,
        epoch: 1n,
        invoiceIdField: stringToFieldElement("cal-inv-1"),
        newSalt: 445566n,
        knownInvoiceHashes: new Set(),
      });
      assert.equal(shadowOk.ok, true);
      if (shadowOk.ok) {
        const realWasm = await verifyShadowAgainstWasm(shadowOk);
        assert.equal(realWasm.drift, false);

        const driftedInput = {
          ...shadowOk.circuitInput,
          newCommitment: BigInt(shadowOk.circuitInput.newCommitment) + 1n,
        };
        const driftedCheck = await verifyShadowAgainstWasm(shadowOk, driftedInput);
        assert.equal(driftedCheck.drift, true);
      }

      // Generate 2 real receipts for P3 calibration
      const intent1 = await parsePaymentIntent(
        { recipient: "AWS", amount: 10_000, epoch: 1, invoiceId: "cal-1" },
        { store },
      );
      const r1 = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent: intent1,
        mode: "DETERMINISTIC_REPLAY",
      });
      assert.equal(r1.approved, true);

      const intent2 = await parsePaymentIntent(
        { recipient: "Stripe", amount: 12_000, epoch: 1, invoiceId: "cal-2" },
        { store },
      );
      const r2 = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent: intent2,
        mode: "DETERMINISTIC_REPLAY",
      });
      assert.equal(r2.approved, true);

      const intent3 = await parsePaymentIntent(
        { recipient: "Anthropic", amount: 8_000, epoch: 1, invoiceId: "cal-3" },
        { store },
      );
      const r3 = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent: intent3,
        mode: "DETERMINISTIC_REPLAY",
      });
      assert.equal(r3.approved, true);

      const receipts = store.getReceipts(sbx.sandboxId);
      assert.equal(receipts.length, 3);

      // Valid contiguous chain -> valid: true
      const validChain = await verifyAuditChain(receipts, sbx.genesisCommitment, sbx.policyRoot, VERIFICATION_KEY);
      assert.equal(validChain.valid, true);

      // P3 calibration 1: omitted middle receipt
      const omitted = await verifyAuditChain(
        [receipts[0]!, receipts[2]!],
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(omitted.valid, false);
      assert.equal(omitted.reasonCode, "CHAIN_GAP");

      // P3 calibration 2: swapped ordering
      const swapped = await verifyAuditChain(
        [receipts[1]!, receipts[0]!, receipts[2]!],
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(swapped.valid, false);

      // P3 calibration 3: two-branch fork sharing C_old (same prevCommitment)
      const forkedReceipt: TreasuryReceipt = {
        ...receipts[1]!,
        receiptId: "forked-branch",
        publicSignals: {
          ...receipts[1]!.publicSignals,
          prevCommitment: receipts[0]!.publicSignals.prevCommitment,
          invoiceHash: stringToFieldElement("unique-fork-inv").toString(10),
        },
      };
      const forked = await verifyAuditChain(
        [receipts[0]!, forkedReceipt],
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(forked.valid, false);
      assert.equal(forked.violations.some((v) => v.code === "FORK_DETECTED"), true);

      // P3 calibration 4: tampered public signals
      const tamperedAmt = (BigInt(receipts[0]!.publicSignals.amount) + 1n).toString(10);
      const tamperedArr = [...receipts[0]!.publicSignalsArray];
      tamperedArr[4] = tamperedAmt;
      const tamperedReceipt: TreasuryReceipt = {
        ...receipts[0]!,
        publicSignals: { ...receipts[0]!.publicSignals, amount: tamperedAmt },
        publicSignalsArray: tamperedArr,
      };
      const tamperedChain = await verifyAuditChain(
        [tamperedReceipt],
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(tamperedChain.valid, false);
      assert.equal(tamperedChain.violations.some((v) => v.code === "INVALID_PROOF"), true);

      // P3 calibration 5: duplicate invoiceHash
      const dupInvReceipt: TreasuryReceipt = {
        ...receipts[1]!,
        publicSignals: {
          ...receipts[1]!.publicSignals,
          invoiceHash: receipts[0]!.publicSignals.invoiceHash,
        },
      };
      const dupChain = await verifyAuditChain(
        [receipts[0]!, dupInvReceipt],
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(dupChain.valid, false);
      assert.equal(dupChain.violations.some((v) => v.code === "DUPLICATE_INVOICE_HASH"), true);

      // P4 calibration: catches stale WASM proves > 0 or shared prevCommitment
      assert.equal(
        checkP4ConcurrencyConservation({
          initialHead: sbx.genesisCommitment,
          staleProvesAttempted: 1,
          winnerPrevCommitment: sbx.genesisCommitment,
          runnerUpPrevCommitment: null,
          finalChainValid: true,
          oracle,
          finalSpent: 10_000n,
          finalEpoch: 1n,
        }),
        false,
      );
      assert.equal(
        checkP4ConcurrencyConservation({
          initialHead: sbx.genesisCommitment,
          staleProvesAttempted: 0,
          winnerPrevCommitment: sbx.genesisCommitment,
          runnerUpPrevCommitment: sbx.genesisCommitment,
          finalChainValid: true,
          oracle,
          finalSpent: 10_000n,
          finalEpoch: 1n,
        }),
        false,
      );

      // P5 calibration: catches retry triggering duplicate error or duplicate distinct task passing
      assert.equal(
        checkP5IdempotencyVsDuplicateSeparation({
          retrySameTaskIdenticalOutput: true,
          retrySameTaskTriggeredDuplicateError: true,
          distinctTaskSameInvoiceRejected: true,
          distinctTaskReasonCode: "DUPLICATE_INVOICE_HASH",
        }),
        false,
      );
      assert.equal(
        checkP5IdempotencyVsDuplicateSeparation({
          retrySameTaskIdenticalOutput: true,
          retrySameTaskTriggeredDuplicateError: false,
          distinctTaskSameInvoiceRejected: false,
          distinctTaskReasonCode: null,
        }),
        false,
      );
    } finally {
      await service.close();
      store.close();
      cleanupTempDir(dir);
    }
  });
});

describe("Ticket 02 — Role 2: Multi-Step Conditional PBT (P1..P5) vs Independent Reference Oracle & Real .wasm", () => {
  it("enforces P1..P5 across 1-25 step action sequences with real Groth16 proofs and positive approved & rejected reachability witnesses", async () => {
    const POOL_VENDORS_16: readonly AllowlistVendor[] = [
      ...DEFAULT_VENDORS,
      ...Array.from({ length: 12 }, (_, idx) => {
        const num = idx + 5;
        const hexSuffix = num.toString(16).padStart(4, "0");
        const address = `0x111111111111111111111111111111111111${hexSuffix}`;
        return {
          name: `Vendor${String(num).padStart(2, "0")}`,
          address,
          recipientField: stringToFieldElement(address),
        };
      }),
    ];
    const unlistedField = stringToFieldElement("0xBAD0000000000000000000000000000000000999");
    const pbtHmacSecret = "pbt-ephemeral-hmac-secret";

    const amountStrategyArb = fc.constantFrom(
      "zero" as const,
      "cap_minus_1" as const,
      "cap_exact" as const,
      "cap_plus_1" as const,
      "headroom_minus_1" as const,
      "headroom_exact" as const,
      "headroom_plus_1" as const,
      "fraction" as const,
    );

    const stepArb = fc.oneof(
      fc.record({
        kind: fc.constant("ProposePayment" as const),
        vendorSeed: fc.integer({ min: 0, max: 15 }),
        useUnlisted: fc.boolean(),
        amountStrategy: amountStrategyArb,
        fractionNum: fc.integer({ min: 1, max: 6 }),
        fractionDen: fc.constant(4),
        epochBump: fc.integer({ min: -1, max: 1 }),
        reuseLastInvoice: fc.boolean(),
      }),
      fc.record({
        kind: fc.constant("ConcurrentPair" as const),
        vendorASeed: fc.integer({ min: 0, max: 15 }),
        vendorBSeed: fc.integer({ min: 0, max: 15 }),
        halfCapMultiplier: fc.integer({ min: 1, max: 3 }),
      }),
      fc.record({
        kind: fc.constant("AdvanceEpoch" as const),
        bump: fc.integer({ min: 1, max: 2 }),
      }),
      fc.record({
        kind: fc.constant("ResetSandbox" as const),
      }),
      fc.record({
        kind: fc.constant("AgentIdempotencyStep" as const),
        vendorSeed: fc.integer({ min: 0, max: 3 }),
      }),
    );

    const scenarioArb = fc.record({
      allowlistSize: fc.integer({ min: 4, max: 16 }),
      balance: fc.oneof(fc.constant(0n), fc.bigInt({ min: 1_000n, max: (1n << 62n) - 1n })),
      floorRatioPct: fc.integer({ min: 0, max: 100 }),
      capRatioPct: fc.integer({ min: 0, max: 120 }),
      steps: fc.array(stepArb, { minLength: 1, maxLength: 25 }),
    });

    let totalApproved = 0;
    let totalRejected = 0;
    let totalWasmVerified = 0;
    let totalNegativeWasmChecked = 0;
    let totalP5Checked = 0;

    const { dir, dbPath } = createTempDbPath("rr-pbt-");
    const srv = await createReserveRailServer({
      dbPath,
      agentHmacSecret: pbtHmacSecret,
      kurierClient: null,
    });
    await srv.listen(0, "127.0.0.1");
    const { store, service } = srv;

    try {
      let runIdx = 0;
      await fc.assert(
        fc.asyncProperty(scenarioArb, async (scenario) => {
          runIdx += 1;
          const sbxId = `sbx_pbt_${runIdx}`;
          const activeVendors = POOL_VENDORS_16.slice(0, scenario.allowlistSize);
          const allowlistFields = activeVendors.map((v) => v.recipientField);
          const allowlistTree = buildAllowlistTree(allowlistFields);
          const fallbackMerkleProof = allowlistTree.createInclusionProof(allowlistFields[0]!)!;

          const payrollFloor = (scenario.balance * BigInt(scenario.floorRatioPct)) / 100n;
          const rawCap = (scenario.balance * BigInt(scenario.capRatioPct)) / 100n;
          const epochCap = rawCap > (1n << 62n) - 1n ? (1n << 62n) - 1n : rawCap;
          const initial = store.resetSandbox(sbxId, {
            balance: scenario.balance,
            payrollFloor,
            epochCap,
            epoch: 1n,
            allowlist: activeVendors,
          });
          store.resetSandbox("competition", {
            balance: 100_000n,
            payrollFloor: 60_000n,
            epochCap: 50_000n,
            epoch: 1n,
          }, "competition");

          const oracle: ReferenceLedgerOracleState = {
            allowlistFields: new Set(allowlistFields),
            balance: scenario.balance,
            payrollFloor,
            epochCap,
            spentInEpoch: 0n,
            currentEpoch: 1n,
            currentCommitment: initial.genesisCommitment,
            seenInvoiceHashes: new Set(),
            chainLinks: [],
          };

          const verifyChainMatchesOracleNow = async (): Promise<boolean> => {
            const receipts = store.getReceipts(sbxId);
            const snap = store.getSandboxSnapshot(sbxId);
            const chainVerdict = await verifyAuditChain(
              receipts,
              snap.genesisCommitment,
              snap.policyRoot,
              VERIFICATION_KEY,
            );
            if (!chainVerdict.valid || receipts.length !== oracle.chainLinks.length) {
              return false;
            }
            for (let i = 0; i < receipts.length; i += 1) {
              if (
                receipts[i]!.publicSignals.prevCommitment !== oracle.chainLinks[i]!.prevCommitment ||
                receipts[i]!.publicSignals.newCommitment !== oracle.chainLinks[i]!.newCommitment ||
                receipts[i]!.publicSignals.invoiceHash !== oracle.chainLinks[i]!.invoiceHash
              ) {
                return false;
              }
            }
            return true;
          };

          const verifyShadowVsWasmEveryStep = async (
            snapBefore: ReturnType<ReserveRailStore["getSandboxSnapshot"]>,
            recipientField: bigint,
            amount: bigint,
            epoch: bigint,
            invIdField: bigint,
            shadow: ReturnType<typeof evaluatePolicyShadow>,
          ): Promise<boolean> => {
            if (shadow.ok) {
              const drift = await verifyShadowAgainstWasm(shadow);
              if (drift.drift) {
                return false;
              }
              totalWasmVerified += 1;
              return true;
            }
            if (shadow.reasonCode !== "DUPLICATE_INVOICE_HASH") {
              const merkleProof = allowlistTree.createInclusionProof(recipientField) ?? fallbackMerkleProof;
              const candidateSpent =
                ((epoch === BigInt(snapBefore.currentEpoch) ? BigInt(snapBefore.spentSoFar) : 0n) + amount) %
                BN128_SCALAR_FIELD;
              const rawNegInput: ReserveRailRawCircuitInput = {
                policyRoot: computePolicyRoot({
                  allowlistRoot: allowlistTree.root,
                  epochCap,
                  payrollFloor,
                  policySalt: BigInt(snapBefore.policySalt),
                }),
                prevCommitment: computeLedgerCommitment({
                  balance: scenario.balance,
                  spentSoFar: BigInt(snapBefore.spentSoFar),
                  epoch: BigInt(snapBefore.currentEpoch),
                  salt: BigInt(snapBefore.currentSalt),
                }),
                newCommitment: computeLedgerCommitment({
                  balance: scenario.balance,
                  spentSoFar: candidateSpent,
                  epoch,
                  salt: 777_888_999n,
                }),
                recipient: recipientField,
                amount,
                epoch,
                invoiceHash: poseidon2([recipientField, invIdField]),
                allowlistRoot: allowlistTree.root,
                allowlistPathIndices: merkleProof.pathIndices,
                allowlistSiblings: merkleProof.siblings,
                balance: scenario.balance,
                spentSoFar: BigInt(snapBefore.spentSoFar),
                prevEpoch: BigInt(snapBefore.currentEpoch),
                epochCap,
                payrollFloor,
                policySalt: BigInt(snapBefore.policySalt),
                prevSalt: BigInt(snapBefore.currentSalt),
                newSalt: 777_888_999n,
                invoiceIdField: invIdField,
              };
              let negThrew = false;
              try {
                await calculateTransitionWitness(rawNegInput);
              } catch {
                negThrew = true;
              }
              if (!negThrew) {
                return false;
              }
              totalNegativeWasmChecked += 1;
            }
            return true;
          };

          let invoiceSeq = 0;
          let p5Seq = 0;
          let p5CheckedInRun = false;
          let lastApprovedPair: { readonly vendorIdx: number; readonly invoiceId: string } | null = null;

          for (const step of scenario.steps) {
            if (step.kind === "ResetSandbox") {
              if (!(await verifyChainMatchesOracleNow())) {
                return false;
              }
              const resetState = store.resetSandbox(sbxId, {
                balance: scenario.balance,
                payrollFloor,
                epochCap,
                epoch: 1n,
                allowlist: activeVendors,
              });
              oracle.spentInEpoch = 0n;
              oracle.currentEpoch = 1n;
              oracle.currentCommitment = resetState.genesisCommitment;
              oracle.seenInvoiceHashes.clear();
              oracle.chainLinks.length = 0;
              lastApprovedPair = null;
              if (!(await verifyChainMatchesOracleNow())) {
                return false;
              }
              continue;
            }

            if (step.kind === "AgentIdempotencyStep") {
              if (p5CheckedInRun) {
                continue;
              }
              p5CheckedInRun = true;
              const vendor = DEFAULT_VENDORS[step.vendorSeed % DEFAULT_VENDORS.length]!;
              const taskId = `pbt-p5-${runIdx}-${++p5Seq}`;
              const invId = `pbt-p5-inv-${runIdx}-${p5Seq}`;
              const payload = JSON.stringify({
                taskId,
                recipient: vendor.address,
                amount: 100,
                epoch: 1,
                invoiceId: invId,
              });
              const sig = crypto.createHmac("sha256", pbtHmacSecret).update(payload).digest("hex");
              const res1 = await fetch(`${srv.url}/agent`, {
                method: "POST",
                headers: { "content-type": "application/json", "x-agent-games-signature": sig },
                body: payload,
              });
              const body1 = await res1.text();
              const resRetry = await fetch(`${srv.url}/agent`, {
                method: "POST",
                headers: { "content-type": "application/json", "x-agent-games-signature": sig },
                body: payload,
              });
              const bodyRetry = await resRetry.text();

              const dupTaskPayload = JSON.stringify({
                taskId: `${taskId}-dup`,
                recipient: vendor.address,
                amount: 100,
                epoch: 1,
                invoiceId: invId,
              });
              const dupSig = crypto.createHmac("sha256", pbtHmacSecret).update(dupTaskPayload).digest("hex");
              const resDup = await fetch(`${srv.url}/agent`, {
                method: "POST",
                headers: { "content-type": "application/json", "x-agent-games-signature": dupSig },
                body: dupTaskPayload,
              });
              const parsedDup = (await resDup.json()) as {
                readonly decision?: string;
                readonly approved: boolean;
                readonly reasonCode?: string;
              };

              const parsedRetry = JSON.parse(bodyRetry) as { readonly approved: boolean; readonly reasonCode?: string };
              const p5Ok = checkP5IdempotencyVsDuplicateSeparation({
                retrySameTaskIdenticalOutput: res1.status === 200 && resRetry.status === 200 && bodyRetry === body1,
                retrySameTaskTriggeredDuplicateError: parsedRetry.reasonCode === "DUPLICATE_INVOICE_HASH",
                distinctTaskSameInvoiceRejected: resDup.status === 200 && parsedDup.decision === "REJECT" && !parsedDup.approved,
                distinctTaskReasonCode: parsedDup.reasonCode ?? null,
              });
              if (!p5Ok) {
                return false;
              }
              totalP5Checked += 1;
              continue;
            }

            if (step.kind === "AdvanceEpoch") {
              const nextEpoch = oracle.currentEpoch + BigInt(step.bump);
              const vendor = activeVendors[0]!;
              const invId = `pbt-adv-${runIdx}-${++invoiceSeq}`;
              const amount = epochCap > 0n ? 1n : 0n;
              const invIdField = stringToFieldElement(invId);
              const invHash = poseidon2([vendor.recipientField, invIdField]).toString(10);

              const snapBefore = store.getSandboxSnapshot(sbxId);
              const shadow = evaluatePolicyShadow({
                allowlistRecipients: allowlistFields,
                epochCap,
                payrollFloor,
                policySalt: BigInt(snapBefore.policySalt),
                balance: scenario.balance,
                spentSoFar: BigInt(snapBefore.spentSoFar),
                prevEpoch: BigInt(snapBefore.currentEpoch),
                prevSalt: BigInt(snapBefore.currentSalt),
                recipient: vendor.recipientField,
                amount,
                epoch: nextEpoch,
                invoiceIdField: invIdField,
                newSalt: 777_888_999n,
                knownInvoiceHashes: oracle.seenInvoiceHashes,
              });
              if (!(await verifyShadowVsWasmEveryStep(snapBefore, vendor.recipientField, amount, nextEpoch, invIdField, shadow))) {
                return false;
              }

              const intent = await parsePaymentIntent(
                {
                  recipient: vendor.address,
                  amount: amount.toString(10),
                  epoch: nextEpoch.toString(10),
                  invoiceId: invId,
                },
                { store, allowlist: activeVendors },
              );

              const oracleRes = oracleCheckP1(oracle, vendor.recipientField, amount, nextEpoch);
              const execRes = await service.executeTransition({
                sandboxId: sbxId,
                intent,
                mode: "DETERMINISTIC_REPLAY",
              });

              if (oracleRes.ok !== execRes.approved) {
                return false;
              }
              if (execRes.approved && oracleRes.nextSpent !== null) {
                totalApproved += 1;
                oracle.spentInEpoch = oracleRes.nextSpent;
                oracle.currentEpoch = nextEpoch;
                oracle.currentCommitment = execRes.newCommitment!;
                oracle.seenInvoiceHashes.add(invHash);
                oracle.chainLinks.push({
                  prevCommitment: execRes.prevCommitment!,
                  newCommitment: execRes.newCommitment!,
                  invoiceHash: invHash,
                });
                lastApprovedPair = { vendorIdx: 0, invoiceId: invId };
              } else {
                totalRejected += 1;
              }
              if (!(await verifyChainMatchesOracleNow())) {
                return false;
              }
              continue;
            }

            if (step.kind === "ProposePayment") {
              const vendorIdx = step.vendorSeed % activeVendors.length;
              const useDup = step.reuseLastInvoice && lastApprovedPair !== null && !step.useUnlisted;
              const vendor = useDup
                ? activeVendors[lastApprovedPair!.vendorIdx]!
                : activeVendors[vendorIdx]!;
              const recipientAddr = step.useUnlisted
                ? "0xBAD0000000000000000000000000000000000999"
                : vendor.address;
              const recipientField = step.useUnlisted ? unlistedField : vendor.recipientField;
              const invId = useDup ? lastApprovedPair!.invoiceId : `pbt-pay-${runIdx}-${++invoiceSeq}`;
              const proposedEpochRaw = oracle.currentEpoch + BigInt(step.epochBump);
              const epoch = proposedEpochRaw < 1n ? 1n : proposedEpochRaw;
              const activeBaseSpent = epoch === oracle.currentEpoch ? oracle.spentInEpoch : 0n;
              const headroom =
                scenario.balance > payrollFloor + activeBaseSpent
                  ? scenario.balance - payrollFloor - activeBaseSpent
                  : 0n;
              const remainingCap = epochCap > activeBaseSpent ? epochCap - activeBaseSpent : 0n;
              let amount: bigint;
              switch (step.amountStrategy) {
                case "zero":
                  amount = 0n;
                  break;
                case "cap_minus_1":
                  amount = remainingCap > 0n ? remainingCap - 1n : 0n;
                  break;
                case "cap_exact":
                  amount = remainingCap;
                  break;
                case "cap_plus_1":
                  amount = remainingCap + 1n;
                  break;
                case "headroom_minus_1":
                  amount = headroom > 0n ? headroom - 1n : 0n;
                  break;
                case "headroom_exact":
                  amount = headroom;
                  break;
                case "headroom_plus_1":
                  amount = headroom + 1n;
                  break;
                case "fraction": {
                  const totalHeadroom = scenario.balance > payrollFloor ? scenario.balance - payrollFloor : 0n;
                  const unit = (totalHeadroom * BigInt(step.fractionNum)) / BigInt(step.fractionDen);
                  amount = unit === 0n && totalHeadroom > 0n ? 1n : unit;
                  break;
                }
              }
              const invIdField = stringToFieldElement(invId);
              const invHash = poseidon2([recipientField, invIdField]).toString(10);

              const snapBefore = store.getSandboxSnapshot(sbxId);
              const shadow = evaluatePolicyShadow({
                allowlistRecipients: allowlistFields,
                epochCap,
                payrollFloor,
                policySalt: BigInt(snapBefore.policySalt),
                balance: scenario.balance,
                spentSoFar: BigInt(snapBefore.spentSoFar),
                prevEpoch: BigInt(snapBefore.currentEpoch),
                prevSalt: BigInt(snapBefore.currentSalt),
                recipient: recipientField,
                amount,
                epoch,
                invoiceIdField: invIdField,
                newSalt: 777_888_999n,
                knownInvoiceHashes: oracle.seenInvoiceHashes,
              });

              const oracleP1 = oracleCheckP1(oracle, recipientField, amount, epoch);
              const isDup = oracle.seenInvoiceHashes.has(invHash);
              const oracleShouldPass = oracleP1.ok && !isDup;

              if (shadow.ok !== oracleShouldPass) {
                return false;
              }

              if (!(await verifyShadowVsWasmEveryStep(snapBefore, recipientField, amount, epoch, invIdField, shadow))) {
                return false;
              }

              const intent = await parsePaymentIntent(
                {
                  recipient: recipientAddr,
                  amount: amount.toString(10),
                  epoch: epoch.toString(10),
                  invoiceId: invId,
                },
                { store, allowlist: activeVendors },
              );

              const execRes = await service.executeTransition({
                sandboxId: sbxId,
                intent,
                mode: "DETERMINISTIC_REPLAY",
              });

              if (execRes.approved !== oracleShouldPass) {
                return false;
              }
              if (oracleP1.ok && isDup && execRes.reasonCode !== "DUPLICATE_INVOICE_HASH") {
                return false;
              }

              if (execRes.approved && oracleP1.nextSpent !== null) {
                totalApproved += 1;
                oracle.spentInEpoch = oracleP1.nextSpent;
                oracle.currentEpoch = epoch;
                oracle.currentCommitment = execRes.newCommitment!;
                oracle.seenInvoiceHashes.add(invHash);
                oracle.chainLinks.push({
                  prevCommitment: execRes.prevCommitment!,
                  newCommitment: execRes.newCommitment!,
                  invoiceHash: invHash,
                });
                if (!step.useUnlisted) {
                  lastApprovedPair = { vendorIdx, invoiceId: invId };
                }
              } else {
                totalRejected += 1;
              }

              const snapAfter = store.getSandboxSnapshot(sbxId);
              if (
                !checkP1AccountingSafety(oracle, {
                  spentSoFar: BigInt(snapAfter.spentSoFar),
                  epoch: BigInt(snapAfter.currentEpoch),
                  approvedRecipientField: execRes.approved ? recipientField : null,
                })
              ) {
                return false;
              }
              if (!(await verifyChainMatchesOracleNow())) {
                return false;
              }
              continue;
            }

            if (step.kind === "ConcurrentPair") {
              const vA = activeVendors[step.vendorASeed % activeVendors.length]!;
              const vB = activeVendors[step.vendorBSeed % activeVendors.length]!;
              const headroom = scenario.balance > payrollFloor ? scenario.balance - payrollFloor : 0n;
              const halfHeadroom = headroom / 2n;
              const amt = halfHeadroom > 0n ? (halfHeadroom * BigInt(step.halfCapMultiplier)) / 2n : 0n;
              const invA = `pbt-concA-${runIdx}-${++invoiceSeq}`;
              const invB = `pbt-concB-${runIdx}-${++invoiceSeq}`;
              const headBefore = oracle.currentCommitment;

              const [intentA, intentB] = await Promise.all([
                parsePaymentIntent(
                  { recipient: vA.address, amount: amt.toString(10), epoch: oracle.currentEpoch.toString(10), invoiceId: invA },
                  { store, allowlist: activeVendors },
                ),
                parsePaymentIntent(
                  { recipient: vB.address, amount: amt.toString(10), epoch: oracle.currentEpoch.toString(10), invoiceId: invB },
                  { store, allowlist: activeVendors },
                ),
              ]);

              const [resA, resB] = await Promise.all([
                service.executeTransition({
                  sandboxId: sbxId,
                  intent: intentA,
                  mode: "DETERMINISTIC_REPLAY",
                }),
                service.executeTransition({
                  sandboxId: sbxId,
                  intent: intentB,
                  mode: "DETERMINISTIC_REPLAY",
                }),
              ]);

              const approvedResults = [resA, resB]
                .filter((r) => r.approved)
                .sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
              for (const ar of approvedResults) {
                totalApproved += 1;
                const invHash = ar.invoiceHash!;
                oracle.spentInEpoch += BigInt(ar.amount!);
                oracle.currentCommitment = ar.newCommitment!;
                oracle.seenInvoiceHashes.add(invHash);
                oracle.chainLinks.push({
                  prevCommitment: ar.prevCommitment!,
                  newCommitment: ar.newCommitment!,
                  invoiceHash: invHash,
                });
              }
              totalRejected += 2 - approvedResults.length;

              const staleProves = (resA.staleProvesAttempted ?? 0) + (resB.staleProvesAttempted ?? 0);
              const snapAfter = store.getSandboxSnapshot(sbxId);
              if (
                !checkP4ConcurrencyConservation({
                  initialHead: headBefore,
                  staleProvesAttempted: staleProves,
                  winnerPrevCommitment: approvedResults[0]?.prevCommitment ?? null,
                  runnerUpPrevCommitment: approvedResults[1]?.prevCommitment ?? null,
                  finalChainValid: snapAfter.currentCommitment === oracle.currentCommitment,
                  oracle,
                  finalSpent: BigInt(snapAfter.spentSoFar),
                  finalEpoch: BigInt(snapAfter.currentEpoch),
                })
              ) {
                return false;
              }
              if (!(await verifyChainMatchesOracleNow())) {
                return false;
              }
            }
          }

          return await verifyChainMatchesOracleNow();
        }),
        { numRuns: 8 },
      );

      // Assert reachability witnesses OUTSIDE fc.property
      assert.equal(totalApproved > 0, true, "expected at least one approved transition");
      assert.equal(totalRejected > 0, true, "expected at least one rejected transition");
      assert.equal(totalWasmVerified + totalNegativeWasmChecked > 0, true, "expected real .wasm differential checks");
      assert.equal(totalP5Checked > 0, true, "expected in-loop P5 idempotency verification");
    } finally {
      await srv.close();
      cleanupTempDir(dir);
    }
  });
});

describe("Ticket 02 — Pre-Prove In-Flight Lease Concurrency & Kurier 503/202/422 Outbox Recovery", () => {
  it("serializes two concurrent 25,000 requests on C_0 with real Groth16 proving, 0 stale WASM proves, and PAYROLL_FLOOR_BREACH on runner-up", async () => {
    const { dir, dbPath } = createTempDbPath("rr-race-");
    const store = ReserveRailStore.open(dbPath);
    let proveCallCount = 0;
    const service = new TreasuryLedgerService({
      store,
      semaphore: new ProvingSemaphore(2),
      onProveStarted: () => {
        proveCallCount += 1;
      },
    });

    try {
      const sbx = store.getOrCreateSandbox("sbx_race_1", "demo", {
        balance: 100_000n,
        payrollFloor: 60_000n,
        epochCap: 50_000n,
      });

      const [intentA, intentB] = await Promise.all([
        parsePaymentIntent({ recipient: "AWS", amount: 25_000, epoch: 1, invoiceId: "race-a" }, { store }),
        parsePaymentIntent({ recipient: "Anthropic", amount: 25_000, epoch: 1, invoiceId: "race-b" }, { store }),
      ]);

      const [resA, resB] = await Promise.all([
        service.executeTransition({ sandboxId: sbx.sandboxId, intent: intentA, mode: "DETERMINISTIC_REPLAY" }),
        service.executeTransition({ sandboxId: sbx.sandboxId, intent: intentB, mode: "DETERMINISTIC_REPLAY" }),
      ]);

      const results = [resA, resB];
      const winners = results.filter((r) => r.approved);
      const losers = results.filter((r) => !r.approved);

      assert.equal(winners.length, 1);
      assert.equal(losers.length, 1);
      assert.equal(winners[0]!.prevCommitment, sbx.genesisCommitment);
      assert.equal(losers[0]!.reasonCode, "PAYROLL_FLOOR_BREACH");
      assert.equal(losers[0]!.staleProvesAttempted, 0);
      assert.equal(proveCallCount, 1, "Only the winner must invoke full Groth16 proving");

      const receipts = store.getReceipts(sbx.sandboxId);
      assert.equal(receipts.length, 1);
      const chain = await verifyAuditChain(receipts, sbx.genesisCommitment, sbx.policyRoot, VERIFICATION_KEY);
      assert.equal(chain.valid, true);
      assert.equal(store.getSandboxSnapshot(sbx.sandboxId).inFlightLeaseId, null);
    } finally {
      await service.close();
      store.close();
      cleanupTempDir(dir);
    }
  });

  it("rolls back Outbox cleanly on transient Kurier 503 pre-submit and retains SUBMITTED on 202 + job-status 503 without severing C_0 -> C_n", async () => {
    const { dir, dbPath } = createTempDbPath("rr-kurier-rec-");
    const store = ReserveRailStore.open(dbPath);
    const FAKE_KEY = "kurier-synthetic-test-key-9999";

    let callStep = 0;
    const mockFetch: typeof globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      callStep += 1;

      if (url.includes("/submit-proof/")) {
        // First 3 attempts (initial + 2 retries) fail with 503 -> clean rollback
        if (callStep <= 3) {
          return new Response(JSON.stringify({ message: `Service Unavailable at /submit-proof/${FAKE_KEY}` }), {
            status: 503,
            headers: { "content-type": "application/json" },
          });
        }
        // Next submit-proof succeeds with 202 pending
        return new Response(JSON.stringify({ jobId: "job-recover-202", status: "pending" }), {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      }

      if (url.includes("/job-status/")) {
        // First job-status poll returns 503 transient, next returns Finalized
        if (callStep === 5) {
          return new Response(JSON.stringify({ message: "Gateway blip 503" }), {
            status: 503,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            jobId: "job-recover-202",
            status: "Finalized",
            txHash: "0x" + "f".repeat(64),
            blockHash: "0x" + "e".repeat(64),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      return new Response("{}", { status: 404 });
    };

    const kurierClient = new KurierClient({
      apiKey: FAKE_KEY,
      fetchImpl: mockFetch,
      pollBaseDelayMs: 15,
      pollMaxDelayMs: 30,
    });

    const service = new TreasuryLedgerService({
      store,
      semaphore: new ProvingSemaphore(2),
      kurierClient,
      submitMaxRetries: 2,
      submitRetryDelayMs: 10,
      preferWebSocket: false,
    });

    try {
      const sbx = store.getOrCreateSandbox("sbx_kurier_rec", "demo", {
        balance: 100_000n,
        payrollFloor: 60_000n,
        epochCap: 50_000n,
      });

      const intent1 = await parsePaymentIntent(
        { recipient: "AWS", amount: 15_000, epoch: 1, invoiceId: "k-503-1" },
        { store },
      );

      // 1. Pre-submit 503 -> clean ROLLED_BACK, head remains C_0, secret scrubbed
      const failedRes = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent: intent1,
        mode: "LIVE",
      });
      assert.equal(failedRes.approved, false);
      assert.equal(failedRes.reasonCode, "KURIER_TRANSIENT_UNAVAILABLE");
      assert.equal((failedRes.errorMessage ?? "").includes(FAKE_KEY), false, "synthetic key leaked");
      assert.equal(store.getSandboxSnapshot(sbx.sandboxId).currentCommitment, sbx.genesisCommitment);
      assert.equal(store.getReceipts(sbx.sandboxId).length, 0);

      // 2. Subsequent request after Kurier recovers -> 202 accepted, head advances C_0 -> C_1, async 503 on job-status retains SUBMITTED and settles to FINALIZED
      const intent2 = await parsePaymentIntent(
        { recipient: "AWS", amount: 15_000, epoch: 1, invoiceId: "k-202-2" },
        { store },
      );
      const okRes = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent: intent2,
        mode: "LIVE",
      });
      assert.equal(okRes.approved, true);
      assert.equal(okRes.prevCommitment, sbx.genesisCommitment);
      assert.equal(okRes.provenanceMode, "LIVE");

      // Wait briefly for background finality tracker to weather the 503 poll and hit Finalized
      await service.waitForPendingFinality(okRes.receipt!.receiptId, 2_000);
      const finalReceipts = store.getReceipts(sbx.sandboxId);
      assert.equal(finalReceipts.length, 1);
      assert.equal(finalReceipts[0]!.provenance.status, "Finalized");
      assert.equal(finalReceipts[0]!.provenance.txHash, "0x" + "f".repeat(64));

      const chain = await verifyAuditChain(
        finalReceipts,
        sbx.genesisCommitment,
        sbx.policyRoot,
        VERIFICATION_KEY,
      );
      assert.equal(chain.valid, true);
      assert.equal(REGISTERED_VK_HASH.startsWith("0x"), true);
    } finally {
      await service.close();
      store.close();
      cleanupTempDir(dir);
    }
  });

  it("rolls back Outbox cleanly on permanent Kurier 422 pre-chain rejection without advancing C_0", async () => {
    const { dir, dbPath } = createTempDbPath("rr-kurier-422-");
    const store = ReserveRailStore.open(dbPath);
    const FAKE_KEY = "kurier-synthetic-422-key";

    const kurierClient = new KurierClient({
      apiKey: FAKE_KEY,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            statusCode: 422,
            code: "PROOF_VERIFICATION_FAILED",
            message: `Invalid proof at /submit-proof/${FAKE_KEY}`,
          }),
          { status: 422, headers: { "content-type": "application/json" } },
        ),
    });

    const service = new TreasuryLedgerService({
      store,
      semaphore: new ProvingSemaphore(2),
      kurierClient,
    });

    try {
      const sbx = store.getOrCreateSandbox("sbx_422", "demo");
      const intent = await parsePaymentIntent(
        { recipient: "AWS", amount: 12_000, epoch: 1, invoiceId: "k-422-1" },
        { store },
      );

      const res = await service.executeTransition({
        sandboxId: sbx.sandboxId,
        intent,
        mode: "LIVE",
      });
      assert.equal(res.approved, false);
      assert.equal(res.httpStatus, 422);
      assert.equal(res.reasonCode, "KURIER_PROOF_REJECTED");
      assert.equal((res.errorMessage ?? "").includes(FAKE_KEY), false);

      const snap = store.getSandboxSnapshot(sbx.sandboxId);
      assert.equal(snap.currentCommitment, sbx.genesisCommitment);
      assert.equal(snap.inFlightLeaseId, null);
      assert.equal(store.getDiagnosticsSummary().outboxCounts.ROLLED_BACK, 1);
      assert.equal(store.getReceipts(sbx.sandboxId).length, 0);
    } finally {
      await service.close();
      store.close();
      cleanupTempDir(dir);
    }
  });
});
