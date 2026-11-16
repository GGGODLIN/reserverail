import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { IMT } from "@zk-kit/imt";
import { poseidon1, poseidon2, poseidon4 } from "poseidon-lite";
import * as snarkjs from "snarkjs";
import type { Groth16Proof, Groth16VerificationKey } from "snarkjs";
import {
  ALLOWLIST_TREE_DEPTH,
  PUBLIC_SIGNAL_NAMES,
  VERIFICATION_KEY,
  fromPublicSignalsArray,
  toPublicSignalsArray,
} from "../generated/circuit-abi.ts";
import type { ReserveRailPublicSignals } from "../generated/circuit-abi.ts";

export const BN128_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const MAX_UINT64 = (1n << 64n) - 1n;

const DEFAULT_ARTIFACTS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "artifacts",
);
const DEFAULT_WASM_PATH = path.join(DEFAULT_ARTIFACTS_DIR, "reserverail.wasm");
const DEFAULT_ZKEY_PATH = path.join(DEFAULT_ARTIFACTS_DIR, "reserverail_final.zkey");

// Bound linear WASM memory to 512 pages (32 MiB) instead of circom_runtime's 2 GiB default.
const WTNS_CALC_OPTIONS = {
  sanityCheck: true,
  memorySize: 512,
} as const;

export interface AllowlistMerkleProof {
  readonly root: bigint;
  readonly leaf: bigint;
  readonly leafIndex: number;
  readonly pathIndices: readonly number[];
  readonly siblings: readonly bigint[];
}

export interface AllowlistTree {
  readonly depth: number;
  readonly root: bigint;
  readonly leaves: readonly bigint[];
  createInclusionProof(recipient: bigint): AllowlistMerkleProof | null;
}

export interface PolicyCommitmentInput {
  readonly allowlistRoot: bigint;
  readonly epochCap: bigint;
  readonly payrollFloor: bigint;
  readonly policySalt: bigint;
}

export interface LedgerCommitmentInput {
  readonly balance: bigint;
  readonly spentSoFar: bigint;
  readonly epoch: bigint;
  readonly salt: bigint;
}

export interface ReserveRailRawCircuitInput {
  readonly policyRoot: bigint | string;
  readonly prevCommitment: bigint | string;
  readonly newCommitment: bigint | string;
  readonly recipient: bigint | string;
  readonly amount: bigint | string;
  readonly epoch: bigint | string;
  readonly invoiceHash: bigint | string;
  readonly allowlistRoot: bigint | string;
  readonly allowlistPathIndices: readonly (number | bigint | string)[];
  readonly allowlistSiblings: readonly (bigint | string)[];
  readonly balance: bigint | string;
  readonly spentSoFar: bigint | string;
  readonly prevEpoch: bigint | string;
  readonly epochCap: bigint | string;
  readonly payrollFloor: bigint | string;
  readonly policySalt: bigint | string;
  readonly prevSalt: bigint | string;
  readonly newSalt: bigint | string;
  readonly invoiceIdField: bigint | string;
}

export interface SingleStepTransitionRequest {
  readonly allowlistRecipients: readonly bigint[];
  readonly epochCap: bigint;
  readonly payrollFloor: bigint;
  readonly policySalt: bigint;
  readonly balance: bigint;
  readonly spentSoFar: bigint;
  readonly prevEpoch: bigint;
  readonly prevSalt: bigint;
  readonly recipient: bigint;
  readonly amount: bigint;
  readonly epoch: bigint;
  readonly invoiceIdField: bigint;
  readonly newSalt: bigint;
}

export type SingleStepEvaluationResult =
  | {
      readonly ok: true;
      readonly newSpent: bigint;
      readonly publicSignals: ReserveRailPublicSignals;
      readonly circuitInput: ReserveRailRawCircuitInput;
    }
  | {
      readonly ok: false;
      readonly reasonCode: string;
    };

export interface ReserveRailProofBundle {
  readonly proof: Groth16Proof;
  readonly publicSignals: ReserveRailPublicSignals;
  readonly publicSignalsArray: string[];
  readonly newSpent: bigint;
}

function isUint64BigInt(value: bigint): boolean {
  return typeof value === "bigint" && value >= 0n && value <= MAX_UINT64;
}

function isFieldElementBigInt(value: bigint): boolean {
  return typeof value === "bigint" && value >= 0n && value < BN128_SCALAR_FIELD;
}

export function assertFieldElement(value: bigint, fieldName: string): bigint {
  if (!isFieldElementBigInt(value)) {
    throw new RangeError(`Field "${fieldName}" must be within bn128 scalar field [0, p)`);
  }
  return value;
}

export function buildAllowlistTree(
  recipients: readonly bigint[],
  depth: number = ALLOWLIST_TREE_DEPTH,
): AllowlistTree {
  const leaves = recipients.map((r, idx) =>
    poseidon1([assertFieldElement(r, `allowlistRecipients[${idx}]`)]),
  );
  const tree = new IMT(
    (nodes) => poseidon2([BigInt(nodes[0] ?? 0n), BigInt(nodes[1] ?? 0n)]),
    depth,
    0n,
    2,
    leaves,
  );
  const root = BigInt(tree.root);

  return {
    depth,
    root,
    leaves,
    createInclusionProof(recipient: bigint): AllowlistMerkleProof | null {
      if (!isFieldElementBigInt(recipient)) {
        return null;
      }
      const leaf = poseidon1([recipient]);
      const index = tree.indexOf(leaf);
      if (index < 0) {
        return null;
      }
      const rawProof = tree.createProof(index);
      const siblings = (rawProof.siblings as unknown[]).map((entry) => {
        if (Array.isArray(entry)) {
          return BigInt((entry[0] as bigint | number | string | undefined) ?? 0n);
        }
        return BigInt(entry as bigint | number | string);
      });
      const pathIndices = rawProof.pathIndices.map((idxVal) => Number(idxVal));

      return {
        root: BigInt(rawProof.root),
        leaf: BigInt(rawProof.leaf),
        leafIndex: rawProof.leafIndex,
        pathIndices,
        siblings,
      };
    },
  };
}

export function computePolicyRoot(input: PolicyCommitmentInput): bigint {
  return poseidon4([
    assertFieldElement(input.allowlistRoot, "allowlistRoot"),
    assertFieldElement(input.epochCap, "epochCap"),
    assertFieldElement(input.payrollFloor, "payrollFloor"),
    assertFieldElement(input.policySalt, "policySalt"),
  ]);
}

export function computeLedgerCommitment(input: LedgerCommitmentInput): bigint {
  return poseidon4([
    assertFieldElement(input.balance, "balance"),
    assertFieldElement(input.spentSoFar, "spentSoFar"),
    assertFieldElement(input.epoch, "epoch"),
    assertFieldElement(input.salt, "salt"),
  ]);
}

export function evaluateSingleStepTransition(
  request: SingleStepTransitionRequest,
): SingleStepEvaluationResult {
  const uint64Candidates = [
    request.epochCap,
    request.payrollFloor,
    request.balance,
    request.spentSoFar,
    request.prevEpoch,
    request.amount,
    request.epoch,
  ];
  if (!uint64Candidates.every(isUint64BigInt)) {
    return { ok: false, reasonCode: "UINT64_OUT_OF_RANGE" };
  }

  const fieldCandidates = [
    request.recipient,
    request.invoiceIdField,
    request.policySalt,
    request.prevSalt,
    request.newSalt,
    ...request.allowlistRecipients,
  ];
  if (!fieldCandidates.every(isFieldElementBigInt)) {
    return { ok: false, reasonCode: "FIELD_OUT_OF_RANGE" };
  }

  const allowlistTree = buildAllowlistTree(request.allowlistRecipients, ALLOWLIST_TREE_DEPTH);
  const inclusionProof = allowlistTree.createInclusionProof(request.recipient);
  if (inclusionProof === null) {
    return { ok: false, reasonCode: "ALLOWLIST_MISS" };
  }

  if (request.epoch < request.prevEpoch) {
    return { ok: false, reasonCode: "STALE_EPOCH" };
  }

  const baseSpent = request.epoch === request.prevEpoch ? request.spentSoFar : 0n;
  const newSpent = baseSpent + request.amount;

  if (newSpent > request.epochCap) {
    return { ok: false, reasonCode: "EPOCH_CAP_EXCEEDED" };
  }

  if (newSpent + request.payrollFloor > request.balance) {
    return { ok: false, reasonCode: "PAYROLL_FLOOR_BREACH" };
  }

  const policyRoot = computePolicyRoot({
    allowlistRoot: allowlistTree.root,
    epochCap: request.epochCap,
    payrollFloor: request.payrollFloor,
    policySalt: request.policySalt,
  });
  const prevCommitment = computeLedgerCommitment({
    balance: request.balance,
    spentSoFar: request.spentSoFar,
    epoch: request.prevEpoch,
    salt: request.prevSalt,
  });
  const newCommitment = computeLedgerCommitment({
    balance: request.balance,
    spentSoFar: newSpent,
    epoch: request.epoch,
    salt: request.newSalt,
  });
  const invoiceHash = poseidon2([request.recipient, request.invoiceIdField]);

  const publicSignals: ReserveRailPublicSignals = {
    policyRoot,
    prevCommitment,
    newCommitment,
    recipient: request.recipient,
    amount: request.amount,
    epoch: request.epoch,
    invoiceHash,
  };

  const circuitInput: ReserveRailRawCircuitInput = {
    policyRoot,
    prevCommitment,
    newCommitment,
    recipient: request.recipient,
    amount: request.amount,
    epoch: request.epoch,
    invoiceHash,
    allowlistRoot: allowlistTree.root,
    allowlistPathIndices: inclusionProof.pathIndices,
    allowlistSiblings: inclusionProof.siblings,
    balance: request.balance,
    spentSoFar: request.spentSoFar,
    prevEpoch: request.prevEpoch,
    epochCap: request.epochCap,
    payrollFloor: request.payrollFloor,
    policySalt: request.policySalt,
    prevSalt: request.prevSalt,
    newSalt: request.newSalt,
    invoiceIdField: request.invoiceIdField,
  };

  return {
    ok: true,
    newSpent,
    publicSignals,
    circuitInput,
  };
}

function serializeScalarForSnarkJs(
  raw: number | bigint | string,
  fieldName: string,
): string {
  const value = typeof raw === "bigint" ? raw : BigInt(raw);
  // Reject negative values before circom_runtime normalizes -x to p - x.
  if (value < 0n || value >= BN128_SCALAR_FIELD) {
    throw new RangeError(`Circuit signal "${fieldName}" outside [0, p)`);
  }
  return value.toString(10);
}

function serializeRawCircuitInput(
  input: ReserveRailRawCircuitInput,
): Record<string, string | string[]> {
  return {
    policyRoot: serializeScalarForSnarkJs(input.policyRoot, "policyRoot"),
    prevCommitment: serializeScalarForSnarkJs(input.prevCommitment, "prevCommitment"),
    newCommitment: serializeScalarForSnarkJs(input.newCommitment, "newCommitment"),
    recipient: serializeScalarForSnarkJs(input.recipient, "recipient"),
    amount: serializeScalarForSnarkJs(input.amount, "amount"),
    epoch: serializeScalarForSnarkJs(input.epoch, "epoch"),
    invoiceHash: serializeScalarForSnarkJs(input.invoiceHash, "invoiceHash"),
    allowlistRoot: serializeScalarForSnarkJs(input.allowlistRoot, "allowlistRoot"),
    allowlistPathIndices: input.allowlistPathIndices.map((v, i) =>
      serializeScalarForSnarkJs(v, `allowlistPathIndices[${i}]`),
    ),
    allowlistSiblings: input.allowlistSiblings.map((v, i) =>
      serializeScalarForSnarkJs(v, `allowlistSiblings[${i}]`),
    ),
    balance: serializeScalarForSnarkJs(input.balance, "balance"),
    spentSoFar: serializeScalarForSnarkJs(input.spentSoFar, "spentSoFar"),
    prevEpoch: serializeScalarForSnarkJs(input.prevEpoch, "prevEpoch"),
    epochCap: serializeScalarForSnarkJs(input.epochCap, "epochCap"),
    payrollFloor: serializeScalarForSnarkJs(input.payrollFloor, "payrollFloor"),
    policySalt: serializeScalarForSnarkJs(input.policySalt, "policySalt"),
    prevSalt: serializeScalarForSnarkJs(input.prevSalt, "prevSalt"),
    newSalt: serializeScalarForSnarkJs(input.newSalt, "newSalt"),
    invoiceIdField: serializeScalarForSnarkJs(input.invoiceIdField, "invoiceIdField"),
  };
}

export async function calculateTransitionWitness(
  circuitInput: ReserveRailRawCircuitInput,
): Promise<ReserveRailPublicSignals> {
  const wasmBytes = new Uint8Array(fs.readFileSync(DEFAULT_WASM_PATH));
  const serialized = serializeRawCircuitInput(circuitInput);
  const wtnsMem: { type: "mem"; data?: Uint8Array } = { type: "mem" };

  await snarkjs.wtns.calculate(serialized, wasmBytes, wtnsMem, WTNS_CALC_OPTIONS);
  const witnessVector = await snarkjs.wtns.exportJson(wtnsMem);
  const publicSlice = witnessVector.slice(1, 1 + PUBLIC_SIGNAL_NAMES.length);
  return fromPublicSignalsArray(publicSlice);
}

export async function proveTransition(
  request: SingleStepTransitionRequest,
): Promise<ReserveRailProofBundle> {
  const evaluation = evaluateSingleStepTransition(request);
  if (!evaluation.ok) {
    throw new RangeError(`Policy transition rejected: ${evaluation.reasonCode}`);
  }

  const wasmBytes = new Uint8Array(fs.readFileSync(DEFAULT_WASM_PATH));
  const serialized = serializeRawCircuitInput(evaluation.circuitInput);

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    serialized,
    wasmBytes,
    DEFAULT_ZKEY_PATH,
    undefined,
    WTNS_CALC_OPTIONS,
  );

  const decodedSignals = fromPublicSignalsArray(publicSignals);
  const expectedWireStrings = toPublicSignalsArray(evaluation.publicSignals);
  for (let idx = 0; idx < expectedWireStrings.length; idx += 1) {
    if (publicSignals[idx] !== expectedWireStrings[idx]) {
      throw new Error(`INVARIANT_BROKEN: public signal wire mismatch at index ${idx}`);
    }
  }

  return {
    proof,
    publicSignals: decodedSignals,
    publicSignalsArray: publicSignals,
    newSpent: evaluation.newSpent,
  };
}

export async function verifyTransitionProof(
  proof: Groth16Proof,
  signals: ReserveRailPublicSignals | readonly string[],
  verificationKey: Groth16VerificationKey = VERIFICATION_KEY,
): Promise<boolean> {
  const publicSignalStrings = Array.isArray(signals)
    ? [...signals]
    : toPublicSignalsArray(signals as ReserveRailPublicSignals);
  return snarkjs.groth16.verify(verificationKey, publicSignalStrings, proof);
}

export async function terminateCurve(): Promise<void> {
  await globalThis.curve_bn128?.terminate();
  globalThis.curve_bn128 = undefined;
}
