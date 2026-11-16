import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import { poseidon1, poseidon2 } from "poseidon-lite";
import {
  BN128_SCALAR_FIELD,
  buildAllowlistTree,
  calculateTransitionWitness,
  computeLedgerCommitment,
  computePolicyRoot,
  evaluateSingleStepTransition,
  proveTransition,
  terminateCurve,
  verifyTransitionProof,
} from "../src/circuit/prover.ts";
import type {
  ReserveRailRawCircuitInput,
  SingleStepEvaluationResult,
  SingleStepTransitionRequest,
} from "../src/circuit/prover.ts";
import {
  ALLOWLIST_TREE_DEPTH,
  CIRCUIT_CONSTRAINT_COUNT,
  CIRCUIT_RULE_LINE_MAP,
  PUBLIC_SIGNAL_NAMES,
  REGISTERED_VK_HASH,
  VERIFICATION_KEY,
  fromPublicSignalsArray,
  toPublicSignalsArray,
} from "../src/generated/circuit-abi.ts";
import type { ReserveRailPublicSignals } from "../src/generated/circuit-abi.ts";
import { KurierClient, KurierError, scrubKurierText } from "../src/kurier/kurier-client.ts";
import type { KurierJobStatus, KurierLogEntry, KurierSocketLike } from "../src/kurier/kurier-client.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

after(async () => {
  await terminateCurve();
});

function checkP2DifferentialEquivalence(params: {
  readonly oraclePass: boolean;
  readonly oracleNewSpent: bigint | null;
  readonly shadowEval: SingleStepEvaluationResult;
  readonly wasmSignals: ReserveRailPublicSignals | null;
}): boolean {
  if (params.oraclePass !== params.shadowEval.ok) {
    return false;
  }
  const wasmPassed = params.wasmSignals !== null;
  if (params.oraclePass !== wasmPassed) {
    return false;
  }
  if (params.shadowEval.ok && params.wasmSignals !== null) {
    if (params.shadowEval.newSpent !== params.oracleNewSpent) {
      return false;
    }
    const expectedArr = toPublicSignalsArray(params.shadowEval.publicSignals);
    const actualArr = toPublicSignalsArray(params.wasmSignals);
    if (expectedArr.length !== actualArr.length) {
      return false;
    }
    for (let i = 0; i < expectedArr.length; i += 1) {
      if (expectedArr[i] !== actualArr[i]) {
        return false;
      }
    }
  }
  return true;
}

function makeValidBaseFixture(): SingleStepTransitionRequest {
  const vendorAlpha = poseidon1([1001n]);
  const vendorBeta = poseidon1([1002n]);
  const vendorGamma = poseidon1([1003n]);
  const vendorDelta = poseidon1([1004n]);

  return {
    allowlistRecipients: [vendorAlpha, vendorBeta, vendorGamma, vendorDelta],
    epochCap: 50_000n,
    payrollFloor: 60_000n,
    policySalt: 918273645546372819n,
    balance: 100_000n,
    spentSoFar: 10_000n,
    prevEpoch: 202611n,
    prevSalt: 112233445566778899n,
    recipient: vendorBeta,
    amount: 30_000n,
    epoch: 202611n,
    invoiceIdField: poseidon1([2001n]),
    newSalt: 998877665544332211n,
  };
}

describe("AC1 & AC2: Compiled ReserveRail circuit artifacts, hygiene, and generated ABI wire order", () => {
  it("produces <= 16,384 constraints, zero .circom log() leaks, valid rule line mappings, and recorded Mainnet vkHash + receipt", () => {
    const wasmPath = path.join(REPO_ROOT, "artifacts", "reserverail.wasm");
    const zkeyPath = path.join(REPO_ROOT, "artifacts", "reserverail_final.zkey");
    const vkPath = path.join(REPO_ROOT, "artifacts", "verification_key.json");
    const lineMapPath = path.join(REPO_ROOT, "artifacts", "circuit-line-map.json");
    const receiptPath = path.join(REPO_ROOT, "artifacts", "gate01-mainnet-receipt.json");
    const circomPath = path.join(REPO_ROOT, "circuits", "reserverail.circom");

    assert.equal(fs.existsSync(wasmPath), true, "reserverail.wasm missing");
    assert.equal(fs.existsSync(zkeyPath), true, "reserverail_final.zkey missing");
    assert.equal(fs.existsSync(vkPath), true, "verification_key.json missing");
    assert.equal(fs.existsSync(lineMapPath), true, "circuit-line-map.json missing");
    assert.equal(fs.existsSync(circomPath), true, "reserverail.circom missing");

    assert.equal(CIRCUIT_CONSTRAINT_COUNT > 0, true, "constraint count must be positive");
    assert.equal(
      CIRCUIT_CONSTRAINT_COUNT <= 16_384,
      true,
      `constraint count ${CIRCUIT_CONSTRAINT_COUNT} exceeds 2^14`,
    );
    assert.equal(ALLOWLIST_TREE_DEPTH, 10);
    assert.equal(VERIFICATION_KEY.protocol, "groth16");
    assert.equal(VERIFICATION_KEY.curve, "bn128");
    assert.equal(VERIFICATION_KEY.nPublic, 7);

    const circomSource = fs.readFileSync(circomPath, "utf8");
    const circomLines = circomSource.split("\n");
    assert.equal(/\blog\s*\(/.test(circomSource), false, "log() must never remain in .circom");

    const requiredRules = [
      "UINT64_RANGE_CHECKS",
      "ALLOWLIST_MERKLE_INCLUSION",
      "EPOCH_MONOTONICITY",
      "EPOCH_SPEND_ACCUMULATION",
      "EPOCH_SPEND_CAP_BOUND",
      "PAYROLL_RESERVE_FLOOR_BOUND",
      "POLICY_COMMITMENT_BINDING",
      "PREV_COMMITMENT_BINDING",
      "NEW_COMMITMENT_BINDING",
      "INVOICE_HASH_BINDING",
    ] as const;

    for (const ruleId of requiredRules) {
      const loc = CIRCUIT_RULE_LINE_MAP[ruleId];
      assert.ok(loc, `missing rule location for ${ruleId}`);
      assert.equal(loc.file, "circuits/reserverail.circom");
      assert.equal(loc.startLine >= 1, true);
      assert.equal(loc.endLine >= loc.startLine, true);
      assert.equal(loc.endLine <= circomLines.length, true);
    }

    assert.match(REGISTERED_VK_HASH, /^0x[0-9a-fA-F]{16,}$/);
    assert.equal(fs.existsSync(receiptPath), true, "gate01-mainnet-receipt.json missing");

    const receiptRaw = fs.readFileSync(receiptPath, "utf8");
    const receipt = JSON.parse(receiptRaw) as {
      readonly vkHash: string;
      readonly idempotentReRegisterVerified: boolean;
      readonly validTransition: {
        readonly jobId: string;
        readonly status: string;
        readonly txHash: string;
        readonly blockHash: string;
        readonly txExplorerUrl: string;
        readonly publicSignals: Record<string, string>;
      };
      readonly tamperedProbe: {
        readonly rejected: boolean;
        readonly httpStatus: number;
        readonly optimisticVerify: string;
      };
    };

    assert.equal(receipt.vkHash, REGISTERED_VK_HASH);
    assert.equal(receipt.idempotentReRegisterVerified, true);
    assert.equal(receipt.validTransition.status, "Finalized");
    assert.match(receipt.validTransition.jobId, /^[0-9a-f-]{36}$/i);
    assert.match(receipt.validTransition.txHash, /^0x[0-9a-fA-F]{64}$/);
    assert.match(receipt.validTransition.blockHash, /^0x[0-9a-fA-F]{64}$/);
    assert.equal(receipt.validTransition.txExplorerUrl.startsWith("https://"), true);
    assert.equal(receipt.tamperedProbe.rejected, true);
  });

  it("maps named ReserveRailPublicSignals fields deterministically in exact Circom .sym wire order", () => {
    assert.equal(PUBLIC_SIGNAL_NAMES.length, 7);
    const expectedFieldSet = new Set([
      "policyRoot",
      "prevCommitment",
      "newCommitment",
      "recipient",
      "amount",
      "epoch",
      "invoiceHash",
    ]);
    assert.deepEqual(new Set(PUBLIC_SIGNAL_NAMES), expectedFieldSet);

    const sampleSignals: ReserveRailPublicSignals = {
      policyRoot: 101n,
      prevCommitment: 202n,
      newCommitment: 303n,
      recipient: 404n,
      amount: 505n,
      epoch: 606n,
      invoiceHash: 707n,
    };

    const wireArray = toPublicSignalsArray(sampleSignals);
    assert.equal(wireArray.length, 7);
    for (let i = 0; i < PUBLIC_SIGNAL_NAMES.length; i += 1) {
      const name = PUBLIC_SIGNAL_NAMES[i]!;
      assert.equal(wireArray[i], sampleSignals[name].toString(10));
    }

    const decoded = fromPublicSignalsArray(wireArray);
    assert.deepEqual(decoded, sampleSignals);

    assert.throws(() => fromPublicSignalsArray(wireArray.slice(0, 6)), /length/i);
    assert.throws(
      () =>
        fromPublicSignalsArray([
          BN128_SCALAR_FIELD.toString(10),
          "202",
          "303",
          "404",
          "505",
          "606",
          "707",
        ]),
      /field/i,
    );
  });
});

describe("AC3: Real Groth16 proving, local verification, boundaries, and modular-underflow rejection", () => {
  it("proves and verifies an exact reserve-floor boundary transition and rejects tampered publicSignals", async () => {
    const req = makeValidBaseFixture();
    const tree = buildAllowlistTree(req.allowlistRecipients);
    const expectedPolicyRoot = computePolicyRoot({
      allowlistRoot: tree.root,
      epochCap: req.epochCap,
      payrollFloor: req.payrollFloor,
      policySalt: req.policySalt,
    });
    const expectedPrevCommitment = computeLedgerCommitment({
      balance: req.balance,
      spentSoFar: req.spentSoFar,
      epoch: req.prevEpoch,
      salt: req.prevSalt,
    });
    const expectedNewCommitment = computeLedgerCommitment({
      balance: req.balance,
      spentSoFar: 40_000n,
      epoch: req.epoch,
      salt: req.newSalt,
    });
    const expectedInvoiceHash = poseidon2([req.recipient, req.invoiceIdField]);

    const bundle = await proveTransition(req);
    assert.equal(bundle.newSpent, 40_000n);
    assert.equal(bundle.publicSignals.policyRoot, expectedPolicyRoot);
    assert.equal(bundle.publicSignals.prevCommitment, expectedPrevCommitment);
    assert.equal(bundle.publicSignals.newCommitment, expectedNewCommitment);
    assert.equal(bundle.publicSignals.recipient, req.recipient);
    assert.equal(bundle.publicSignals.amount, 30_000n);
    assert.equal(bundle.publicSignals.epoch, 202611n);
    assert.equal(bundle.publicSignals.invoiceHash, expectedInvoiceHash);

    const isValid = await verifyTransitionProof(bundle.proof, bundle.publicSignals);
    assert.equal(isValid, true);

    const tamperedSignals: ReserveRailPublicSignals = {
      ...bundle.publicSignals,
      amount: bundle.publicSignals.amount - 1n,
    };
    const isTamperedValid = await verifyTransitionProof(bundle.proof, tamperedSignals);
    assert.equal(isTamperedValid, false);
  });

  it("resets baseSpent cleanly when advancing to a newer epoch while rejecting stale epoch regression", async () => {
    const base = makeValidBaseFixture();
    const nextEpochReq: SingleStepTransitionRequest = {
      ...base,
      spentSoFar: 48_000n,
      prevEpoch: 202611n,
      epoch: 202612n,
      amount: 35_000n,
    };

    const nextBundle = await proveTransition(nextEpochReq);
    assert.equal(nextBundle.newSpent, 35_000n);
    assert.equal(await verifyTransitionProof(nextBundle.proof, nextBundle.publicSignals), true);

    const staleEpochReq: SingleStepTransitionRequest = {
      ...base,
      prevEpoch: 202612n,
      epoch: 202611n,
      amount: 1_000n,
    };
    const staleEval = evaluateSingleStepTransition(staleEpochReq);
    assert.equal(staleEval.ok, false);
    if (!staleEval.ok) {
      assert.equal(staleEval.reasonCode, "STALE_EPOCH");
    }
    await assert.rejects(() => proveTransition(staleEpochReq));
  });

  it("rejects unlisted recipients, epochCap breach, payrollFloor breach, negative bigints, and >= 2^64 overflow in both TS and raw WASM", async () => {
    const base = makeValidBaseFixture();
    const unlistedRecipient = poseidon1([1099n]);

    // 1. Unlisted vendor
    const unlistedReq: SingleStepTransitionRequest = {
      ...base,
      recipient: unlistedRecipient,
    };
    const unlistedEval = evaluateSingleStepTransition(unlistedReq);
    assert.equal(unlistedEval.ok, false);
    if (!unlistedEval.ok) {
      assert.equal(unlistedEval.reasonCode, "ALLOWLIST_MISS");
    }
    await assert.rejects(() => proveTransition(unlistedReq));

    // Also verify raw .wasm rejects forged Merkle inclusion when unlisted leaf is paired with valid path
    const validEval = evaluateSingleStepTransition(base);
    assert.equal(validEval.ok, true);
    if (validEval.ok) {
      const forgedRaw: ReserveRailRawCircuitInput = {
        ...validEval.circuitInput,
        recipient: unlistedRecipient,
        invoiceHash: poseidon2([unlistedRecipient, base.invoiceIdField]),
      };
      await assert.rejects(() => calculateTransitionWitness(forgedRaw));

      // Non-binary Merkle selector index (e.g. 2) must also fail R1CS bit constraint
      const nonBinarySelectorRaw: ReserveRailRawCircuitInput = {
        ...validEval.circuitInput,
        allowlistPathIndices: [2, ...validEval.circuitInput.allowlistPathIndices.slice(1)],
      };
      await assert.rejects(() => calculateTransitionWitness(nonBinarySelectorRaw));
    }

    // 2. Epoch Spend Cap breach (10_000 + 40_001 = 50_001 > 50_000, while 50_001 + 40_000 <= 100_000)
    const capBreachReq: SingleStepTransitionRequest = {
      ...base,
      payrollFloor: 40_000n,
      amount: 40_001n,
    };
    const capEval = evaluateSingleStepTransition(capBreachReq);
    assert.equal(capEval.ok, false);
    if (!capEval.ok) {
      assert.equal(capEval.reasonCode, "EPOCH_CAP_EXCEEDED");
    }
    await assert.rejects(() => proveTransition(capBreachReq));

    // 3. Payroll Reserve Floor breach (10_000 + 30_001 + 60_000 = 100_001 > 100_000, while 40_001 <= 50_000)
    const floorBreachReq: SingleStepTransitionRequest = {
      ...base,
      amount: 30_001n,
    };
    const floorEval = evaluateSingleStepTransition(floorBreachReq);
    assert.equal(floorEval.ok, false);
    if (!floorEval.ok) {
      assert.equal(floorEval.reasonCode, "PAYROLL_FLOOR_BREACH");
    }
    await assert.rejects(() => proveTransition(floorBreachReq));

    // 4. Modular-underflow trap: payrollFloor (120_000) > balance (100_000)
    const underflowTrapReq: SingleStepTransitionRequest = {
      ...base,
      payrollFloor: 120_000n,
      amount: 1_000n,
    };
    const underflowEval = evaluateSingleStepTransition(underflowTrapReq);
    assert.equal(underflowEval.ok, false);
    if (!underflowEval.ok) {
      assert.equal(underflowEval.reasonCode, "PAYROLL_FLOOR_BREACH");
    }
    if (validEval.ok) {
      const underflowTree = buildAllowlistTree(base.allowlistRecipients);
      const rawUnderflow: ReserveRailRawCircuitInput = {
        ...validEval.circuitInput,
        payrollFloor: 120_000n,
        policyRoot: computePolicyRoot({
          allowlistRoot: underflowTree.root,
          epochCap: base.epochCap,
          payrollFloor: 120_000n,
          policySalt: base.policySalt,
        }),
      };
      await assert.rejects(() => calculateTransitionWitness(rawUnderflow));
    }

    // 5. Negative JS bigint (-1n) and >= 2^64 overflow, plus raw field p - 1n in .wasm
    const negativeReq: SingleStepTransitionRequest = {
      ...base,
      amount: -1n,
    };
    assert.equal(evaluateSingleStepTransition(negativeReq).ok, false);
    await assert.rejects(() => proveTransition(negativeReq));

    const overflowReq: SingleStepTransitionRequest = {
      ...base,
      amount: 1n << 64n,
    };
    assert.equal(evaluateSingleStepTransition(overflowReq).ok, false);
    await assert.rejects(() => proveTransition(overflowReq));

    if (validEval.ok) {
      const fieldMinusOne = BN128_SCALAR_FIELD - 1n;
      const rawFieldWrapAttempt: ReserveRailRawCircuitInput = {
        ...validEval.circuitInput,
        amount: fieldMinusOne,
        newCommitment: computeLedgerCommitment({
          balance: base.balance,
          spentSoFar: (base.spentSoFar + fieldMinusOne) % BN128_SCALAR_FIELD,
          epoch: base.epoch,
          salt: base.newSalt,
        }),
      };
      await assert.rejects(() => calculateTransitionWitness(rawFieldWrapAttempt));

      const rawTwoPow64Attempt: ReserveRailRawCircuitInput = {
        ...validEval.circuitInput,
        amount: 1n << 64n,
      };
      await assert.rejects(() => calculateTransitionWitness(rawTwoPow64Attempt));
    }
  });

  it("P2 single-step property guardian & independent oracle calibration maintain zero drift between TS policy and real .wasm", async () => {
    const base = makeValidBaseFixture();

    // Role 3: Oracle calibration (test-local synthetic drift must individually fail P2)
    const validEval = evaluateSingleStepTransition(base);
    assert.equal(validEval.ok, true);
    if (validEval.ok) {
      const validWasmSignals = await calculateTransitionWitness(validEval.circuitInput);
      assert.equal(
        checkP2DifferentialEquivalence({
          oraclePass: true,
          oracleNewSpent: validEval.newSpent,
          shadowEval: validEval,
          wasmSignals: validWasmSignals,
        }),
        true,
      );

      // Synthetic false-negative WASM mutation
      assert.equal(
        checkP2DifferentialEquivalence({
          oraclePass: true,
          oracleNewSpent: validEval.newSpent,
          shadowEval: validEval,
          wasmSignals: null,
        }),
        false,
      );

      // Synthetic public-signal wire drift mutation
      assert.equal(
        checkP2DifferentialEquivalence({
          oraclePass: true,
          oracleNewSpent: validEval.newSpent,
          shadowEval: validEval,
          wasmSignals: { ...validWasmSignals, newCommitment: validWasmSignals.newCommitment + 1n },
        }),
        false,
      );
    }

    // Role 2: Safety Property Guardian over single-step domain (Shape 2 accounting + allowlist + epoch)
    const allowlistPool = base.allowlistRecipients;
    const unlistedVendor = poseidon1([1098n]);
    const candidateArb = fc.record({
      balance: fc.bigInt({ min: 0n, max: (1n << 62n) - 1n }),
      payrollFloor: fc.bigInt({ min: 0n, max: (1n << 62n) - 1n }),
      epochCap: fc.bigInt({ min: 0n, max: (1n << 62n) - 1n }),
      spentSoFar: fc.bigInt({ min: 0n, max: (1n << 62n) - 1n }),
      amount: fc.bigInt({ min: 0n, max: (1n << 62n) - 1n }),
      prevEpoch: fc.bigInt({ min: 0n, max: 10n }),
      epochDelta: fc.integer({ min: -1, max: 2 }),
      useListedRecipient: fc.boolean(),
      listedIdx: fc.integer({ min: 0, max: allowlistPool.length - 1 }),
      invoiceNonce: fc.bigInt({ min: 1n, max: 1_000_000n }),
    });

    let approvedCount = 0;
    let rejectedCount = 0;

    await fc.assert(
      fc.asyncProperty(candidateArb, async (sample) => {
        const rawEpoch = sample.prevEpoch + BigInt(sample.epochDelta);
        const epoch = rawEpoch < 0n ? 0n : rawEpoch;
        const recipient = sample.useListedRecipient
          ? allowlistPool[sample.listedIdx]!
          : unlistedVendor;

        const req: SingleStepTransitionRequest = {
          allowlistRecipients: allowlistPool,
          epochCap: sample.epochCap,
          payrollFloor: sample.payrollFloor,
          policySalt: 777111n,
          balance: sample.balance,
          spentSoFar: sample.spentSoFar,
          prevEpoch: sample.prevEpoch,
          prevSalt: 888222n,
          recipient,
          amount: sample.amount,
          epoch,
          invoiceIdField: sample.invoiceNonce,
          newSalt: 999333n,
        };

        const shadowEval = evaluateSingleStepTransition(req);

        const tree = buildAllowlistTree(allowlistPool);
        const listedProof = tree.createInclusionProof(recipient);
        const fallbackProof = tree.createInclusionProof(allowlistPool[0]!)!;
        const merkleProof = listedProof ?? fallbackProof;
        const candidateNewSpent =
          (epoch === sample.prevEpoch ? sample.spentSoFar : 0n) + sample.amount;
        const expectedPass =
          sample.useListedRecipient &&
          epoch >= sample.prevEpoch &&
          candidateNewSpent <= sample.epochCap &&
          candidateNewSpent + sample.payrollFloor <= sample.balance;

        const rawCircuitInput: ReserveRailRawCircuitInput = {
          policyRoot: computePolicyRoot({
            allowlistRoot: tree.root,
            epochCap: sample.epochCap,
            payrollFloor: sample.payrollFloor,
            policySalt: req.policySalt,
          }),
          prevCommitment: computeLedgerCommitment({
            balance: sample.balance,
            spentSoFar: sample.spentSoFar,
            epoch: sample.prevEpoch,
            salt: req.prevSalt,
          }),
          newCommitment: computeLedgerCommitment({
            balance: sample.balance,
            spentSoFar: candidateNewSpent % BN128_SCALAR_FIELD,
            epoch,
            salt: req.newSalt,
          }),
          recipient,
          amount: sample.amount,
          epoch,
          invoiceHash: poseidon2([recipient, sample.invoiceNonce]),
          allowlistRoot: tree.root,
          allowlistPathIndices: merkleProof.pathIndices,
          allowlistSiblings: merkleProof.siblings,
          balance: sample.balance,
          spentSoFar: sample.spentSoFar,
          prevEpoch: sample.prevEpoch,
          epochCap: sample.epochCap,
          payrollFloor: sample.payrollFloor,
          policySalt: req.policySalt,
          prevSalt: req.prevSalt,
          newSalt: req.newSalt,
          invoiceIdField: sample.invoiceNonce,
        };

        let wasmSignals: ReserveRailPublicSignals | null = null;
        try {
          wasmSignals = await calculateTransitionWitness(rawCircuitInput);
        } catch {
          wasmSignals = null;
        }

        if (expectedPass) {
          approvedCount += 1;
        } else {
          rejectedCount += 1;
        }

        return checkP2DifferentialEquivalence({
          oraclePass: expectedPass,
          oracleNewSpent: expectedPass ? candidateNewSpent : null,
          shadowEval,
          wasmSignals,
        });
      }),
      { numRuns: 40 },
    );

    // Guarantee both approved and rejected branches are exercised across the batch
    if (approvedCount === 0) {
      const guaranteedPass = evaluateSingleStepTransition(base);
      assert.equal(guaranteedPass.ok, true);
      if (guaranteedPass.ok) {
        const ws = await calculateTransitionWitness(guaranteedPass.circuitInput);
        assert.equal(
          checkP2DifferentialEquivalence({
            oraclePass: true,
            oracleNewSpent: guaranteedPass.newSpent,
            shadowEval: guaranteedPass,
            wasmSignals: ws,
          }),
          true,
        );
        approvedCount += 1;
      }
    }
    assert.equal(approvedCount > 0, true);
    assert.equal(rejectedCount > 0, true);
  });
});

describe("AC4 & AC5: KurierClient HTTP 200/202/400/422 handling, WS rotation + singleflight fallback, and key redaction", () => {
  const FAKE_KEY = "kurier-synthetic-test-key-9999";

  it("asserts non-empty valid API keys before URL construction to block accidental x402 trailing-slash routes", () => {
    assert.throws(() => new KurierClient({ apiKey: "" }), Error);
    assert.throws(() => new KurierClient({ apiKey: "   " }), Error);
    assert.throws(() => new KurierClient({ apiKey: "bad/slash" }), Error);
    assert.throws(() => new KurierClient({ apiKey: "bad?query=1" }), Error);
  });

  it("handles register-vk 200 and idempotent 400 meta.vkHash, plus submit-proof 200, 202 (without optimisticVerify), and 422 rejection without chainId", async () => {
    const seenUrls: string[] = [];
    const seenBodies: Record<string, unknown>[] = [];
    let callIndex = 0;

    const mockFetch: typeof globalThis.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      seenUrls.push(url);
      const parsedBody =
        typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
      seenBodies.push(parsedBody);
      callIndex += 1;

      if (callIndex === 1) {
        return new Response(JSON.stringify({ vkHash: "0xvk_fresh_1234", warnings: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (callIndex === 2) {
        return new Response(
          JSON.stringify({
            error: "Bad Request",
            code: "VK_ALREADY_REGISTERED",
            message: "Verification key already registered",
            meta: { vkHash: "0xvk_fresh_1234" },
          }),
          { status: 400, headers: { "content-type": "application/json" } },
        );
      }
      if (callIndex === 3) {
        return new Response(
          JSON.stringify({
            jobId: "11111111-2222-4333-8444-555555555555",
            optimisticVerify: "success",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (callIndex === 4) {
        return new Response(
          JSON.stringify({
            jobId: "22222222-3333-4444-8555-666666666666",
            status: "pending",
            message: "Optimistic verification in progress",
          }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          statusCode: 422,
          code: "PROOF_VERIFICATION_FAILED",
          error: "Unprocessable Entity",
          message: `Invalid proof at /submit-proof/${FAKE_KEY}`,
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    };

    const client = new KurierClient({
      apiKey: FAKE_KEY,
      apiBaseUrl: "https://api.kurier.xyz/api/v1/",
      fetchImpl: mockFetch,
    });

    try {
      const reg1 = await client.registerVerificationKey(VERIFICATION_KEY);
      assert.equal(reg1.vkHash, "0xvk_fresh_1234");
      assert.equal(reg1.alreadyRegistered, false);

      const reg2 = await client.registerVerificationKey(VERIFICATION_KEY);
      assert.equal(reg2.vkHash, "0xvk_fresh_1234");
      assert.equal(reg2.alreadyRegistered, true);

      const dummyProof = {
        pi_a: ["1", "2", "1"],
        pi_b: [
          ["1", "2"],
          ["3", "4"],
          ["1", "0"],
        ],
        pi_c: ["5", "6", "1"],
        protocol: "groth16",
        curve: "bn128",
      };

      const sub200 = await client.submitProof({
        vkHash: reg1.vkHash,
        proof: dummyProof,
        publicSignals: ["1", "2", "3", "4", "5", "6", "7"],
      });
      assert.equal(sub200.outcome, "accepted");
      if (sub200.outcome === "accepted") {
        assert.equal(sub200.httpStatus, 200);
        assert.equal(sub200.jobId, "11111111-2222-4333-8444-555555555555");
        assert.equal(sub200.optimisticVerify, "success");
      }
      assert.equal("chainId" in seenBodies[2]!, false, "chainId must never be sent");

      const sub202 = await client.submitProof({
        vkHash: reg1.vkHash,
        proof: dummyProof,
        publicSignals: ["1", "2", "3", "4", "5", "6", "7"],
      });
      assert.equal(sub202.outcome, "accepted");
      if (sub202.outcome === "accepted") {
        assert.equal(sub202.httpStatus, 202);
        assert.equal(sub202.jobId, "22222222-3333-4444-8555-666666666666");
        assert.equal(sub202.optimisticVerify, "pending");
      }

      const sub422 = await client.submitProof({
        vkHash: reg1.vkHash,
        proof: dummyProof,
        publicSignals: ["999", "2", "3", "4", "5", "6", "7"],
      });
      assert.equal(sub422.outcome, "rejected");
      if (sub422.outcome === "rejected") {
        assert.equal(sub422.httpStatus, 422);
        assert.equal(sub422.optimisticVerify, "failed");
        assert.equal(sub422.reason.includes(FAKE_KEY), false, "synthetic key leaked in rejection reason");
        assert.equal(sub422.reason.includes("[REDACTED_KURIER_KEY]"), true);
      }

      for (const u of seenUrls) {
        assert.equal(u.endsWith("/submit-proof/"), false);
        assert.equal(u.endsWith("/register-vk/"), false);
      }
    } finally {
      await client.close();
    }
  });

  it("tracks job finality via persistent WebSocket subscribe-all with proactive rotation and singleflight REST fallback", async () => {
    const createdSockets: Array<{
      readonly url: string;
      readonly sent: string[];
      closed: boolean;
      socket: KurierSocketLike;
    }> = [];

    const createMockWs = (url: string): KurierSocketLike => {
      const sent: string[] = [];
      const record = {
        url,
        sent,
        closed: false,
        socket: {
          readyState: 1,
          onopen: null as (() => void) | null,
          onmessage: null as ((ev: { readonly data: unknown }) => void) | null,
          onerror: null as ((ev: unknown) => void) | null,
          onclose: null as ((ev: { readonly code?: number; readonly reason?: string }) => void) | null,
          send(data: string) {
            sent.push(data);
          },
          close() {
            record.closed = true;
            record.socket.onclose?.({ code: 1000, reason: "closed" });
          },
        },
      };
      createdSockets.push(record);
      queueMicrotask(() => {
        record.socket.onopen?.();
        record.socket.onmessage?.({
          data: JSON.stringify({ type: "connected", connectionId: `conn-${createdSockets.length}` }),
        });
      });
      return record.socket;
    };

    const wsClient = new KurierClient({
      apiKey: FAKE_KEY,
      createWebSocket: createMockWs,
      fetchImpl: async () => new Response("{}", { status: 500 }),
      wsRotationIntervalMs: 35,
      wsPingIntervalMs: 10_000,
    });

    try {
      const subscribed = await wsClient.ensureWebSocketSubscribed();
      assert.equal(subscribed, true);
      assert.equal(createdSockets.length, 1);
      assert.equal(
        createdSockets[0]!.sent.some((m) => JSON.parse(m).type === "subscribe-all"),
        true,
      );

      // Wait past proactive rotation window so socket #1 rotates to socket #2
      await new Promise((resolve) => setTimeout(resolve, 60));
      assert.equal(createdSockets.length >= 2, true);
      assert.equal(createdSockets[0]!.closed, true);
      const activeSocket = createdSockets[createdSockets.length - 1]!;
      assert.equal(
        activeSocket.sent.some((m) => JSON.parse(m).type === "subscribe-all"),
        true,
      );

      const observedStages: string[] = [];
      const waitPromise = wsClient.waitForJobFinality("job-ws-1", {
        timeoutMs: 2_000,
        onStageChange: (st: KurierJobStatus) => {
          observedStages.push(st.status);
        },
      });

      activeSocket.socket.onmessage?.({
        data: JSON.stringify({
          type: "job-status-update",
          data: {
            jobId: "job-ws-1",
            status: "IncludedInBlock",
            txHash: "0x" + "a".repeat(64),
            blockHash: "0x" + "b".repeat(64),
          },
        }),
      });
      activeSocket.socket.onmessage?.({
        data: JSON.stringify({
          type: "job-status-update",
          data: {
            jobId: "job-ws-1",
            status: "Finalized",
            txHash: "0x" + "a".repeat(64),
            blockHash: "0x" + "b".repeat(64),
            txExplorerUrl: "https://zkverify.subscan.io/extrinsic/0x" + "a".repeat(64),
          },
        }),
      });

      const finalStatus = await waitPromise;
      assert.equal(finalStatus.status, "Finalized");
      assert.equal(finalStatus.txHash, "0x" + "a".repeat(64));
      assert.equal(finalStatus.blockHash, "0x" + "b".repeat(64));
      assert.deepEqual(observedStages, ["IncludedInBlock", "Finalized"]);
    } finally {
      await wsClient.close();
    }

    // Fallback test: WS unavailable + concurrent waitForJobFinality calls share singleflight REST polling
    let restStatusCalls = 0;
    const fallbackClient = new KurierClient({
      apiKey: FAKE_KEY,
      createWebSocket: () => {
        const failingSocket: KurierSocketLike = {
          readyState: 3,
          onopen: null,
          onmessage: null,
          onerror: null,
          onclose: null,
          send() {},
          close() {},
        };
        queueMicrotask(() => {
          failingSocket.onerror?.(new Error(`WS failed wss://api.kurier.xyz/api/v1/ws?apiKey=${FAKE_KEY}`));
          failingSocket.onclose?.({ code: 1006, reason: "unreachable" });
        });
        return failingSocket;
      },
      fetchImpl: async () => {
        restStatusCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 25));
        const stage = restStatusCalls === 1 ? "IncludedInBlock" : "Finalized";
        return new Response(
          JSON.stringify({
            jobId: "job-rest-1",
            status: stage,
            txHash: "0x" + "c".repeat(64),
            blockHash: "0x" + "d".repeat(64),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
      wsConnectTimeoutMs: 50,
      pollBaseDelayMs: 20,
      pollMaxDelayMs: 60,
    });

    try {
      const [resA, resB] = await Promise.all([
        fallbackClient.waitForJobFinality("job-rest-1", { timeoutMs: 2_000 }),
        fallbackClient.waitForJobFinality("job-rest-1", { timeoutMs: 2_000 }),
      ]);
      assert.equal(resA.status, "Finalized");
      assert.equal(resB.status, "Finalized");
      assert.equal(resA.txHash, "0x" + "c".repeat(64));
      // Two concurrent callers over 2 stages must coalesce via singleflight (2 HTTP calls, not 4)
      assert.equal(restStatusCalls, 2);
    } finally {
      await fallbackClient.close();
    }
  });

  it("scrubs synthetic API keys across REST errors, network exceptions, WS logs, and stack traces with positive control", async () => {
    const rawUrl = `https://api.kurier.xyz/api/v1/submit-proof/${FAKE_KEY}`;
    const rawWsUrl = `wss://api.kurier.xyz/api/v1/ws?apiKey=${FAKE_KEY}`;

    // Positive controls proving matcher detects fakeKey before scrubbing and replaces with marker
    assert.equal(rawUrl.includes(FAKE_KEY), true);
    const scrubbedRest = scrubKurierText(rawUrl, FAKE_KEY);
    assert.equal(scrubbedRest.includes("[REDACTED_KURIER_KEY]"), true);
    assert.equal(scrubbedRest.includes(FAKE_KEY), false, "synthetic key leaked");

    const scrubbedWs = scrubKurierText(rawWsUrl, FAKE_KEY);
    assert.equal(scrubbedWs.includes("[REDACTED_KURIER_KEY]"), true);
    assert.equal(scrubbedWs.includes(FAKE_KEY), false, "synthetic key leaked");

    const capturedLogs: KurierLogEntry[] = [];
    const errorClient = new KurierClient({
      apiKey: FAKE_KEY,
      onLog: (entry) => {
        capturedLogs.push(entry);
      },
      fetchImpl: async (input) => {
        const u = typeof input === "string" ? input : input.toString();
        throw new TypeError(`Network socket hang up calling ${u}`);
      },
    });

    try {
      let caughtError: unknown = null;
      try {
        await errorClient.getJobStatus("job-err-99");
      } catch (err: unknown) {
        caughtError = err;
      }

      assert.equal(caughtError instanceof KurierError, true);
      if (caughtError instanceof KurierError) {
        const combinedErrorDump = `${caughtError.message}\n${caughtError.stack ?? ""}\n${JSON.stringify(caughtError)}`;
        assert.equal(combinedErrorDump.includes(FAKE_KEY), false, "synthetic key leaked");
        assert.equal(combinedErrorDump.includes("[REDACTED_KURIER_KEY]"), true);
      }

      assert.equal(capturedLogs.length > 0, true);
      const serializedLogs = JSON.stringify(capturedLogs);
      assert.equal(serializedLogs.includes(FAKE_KEY), false, "synthetic key leaked");
      assert.equal(serializedLogs.includes("[REDACTED_KURIER_KEY]"), true);
    } finally {
      await errorClient.close();
    }
  });
});
