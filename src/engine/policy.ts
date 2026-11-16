import crypto from "node:crypto";
import { poseidon2 } from "poseidon-lite";
import {
  BN128_SCALAR_FIELD,
  MAX_UINT64,
  calculateTransitionWitness,
  evaluateSingleStepTransition,
} from "../circuit/prover.ts";
import type {
  ReserveRailRawCircuitInput,
  SingleStepTransitionRequest,
} from "../circuit/prover.ts";
import { toPublicSignalsArray } from "../generated/circuit-abi.ts";
import type { ReserveRailPublicSignals } from "../generated/circuit-abi.ts";

export interface AllowlistVendor {
  readonly name: string;
  readonly address: string;
  readonly recipientField: bigint;
}

export function stringToFieldElement(raw: string): bigint {
  const normalized = /^0x[0-9a-fA-F]+$/.test(raw.trim()) ? raw.trim().toLowerCase() : raw.trim();
  const digest = crypto.createHash("sha256").update(normalized, "utf8").digest("hex");
  return BigInt(`0x${digest.slice(0, 62)}`);
}

export function computeInvoiceHash(recipientField: bigint, invoiceIdField: bigint): bigint {
  return poseidon2([recipientField, invoiceIdField]);
}

export const DEFAULT_VENDORS: readonly AllowlistVendor[] = [
  {
    name: "AWS",
    address: "0x1111111111111111111111111111111111111001",
    recipientField: stringToFieldElement("0x1111111111111111111111111111111111111001"),
  },
  {
    name: "Stripe",
    address: "0x1111111111111111111111111111111111111002",
    recipientField: stringToFieldElement("0x1111111111111111111111111111111111111002"),
  },
  {
    name: "Anthropic",
    address: "0x1111111111111111111111111111111111111003",
    recipientField: stringToFieldElement("0x1111111111111111111111111111111111111003"),
  },
  {
    name: "Cloudflare",
    address: "0x1111111111111111111111111111111111111004",
    recipientField: stringToFieldElement("0x1111111111111111111111111111111111111004"),
  },
];

export interface PolicyShadowInput extends SingleStepTransitionRequest {
  readonly knownInvoiceHashes?: ReadonlySet<string>;
}

export type PolicyShadowResult =
  | {
      readonly ok: true;
      readonly reasonCode: "POLICY_PASS";
      readonly newSpent: bigint;
      readonly invoiceHash: bigint;
      readonly publicSignals: ReserveRailPublicSignals;
      readonly circuitInput: ReserveRailRawCircuitInput;
    }
  | {
      readonly ok: false;
      readonly reasonCode:
        | "UINT64_OUT_OF_RANGE"
        | "FIELD_OUT_OF_RANGE"
        | "ALLOWLIST_MISS"
        | "STALE_EPOCH"
        | "EPOCH_CAP_EXCEEDED"
        | "PAYROLL_FLOOR_BREACH"
        | "DUPLICATE_INVOICE_HASH"
        | "INVARIANT_BROKEN";
      readonly invariantDrift: boolean;
      readonly message: string;
    };

function isUint64(v: bigint): boolean {
  return typeof v === "bigint" && v >= 0n && v <= MAX_UINT64;
}

function isField(v: bigint): boolean {
  return typeof v === "bigint" && v >= 0n && v < BN128_SCALAR_FIELD;
}

const REASON_MESSAGES: Readonly<Record<string, string>> = {
  UINT64_OUT_OF_RANGE: "Monetary or epoch input is outside the 64-bit unsigned integer domain",
  FIELD_OUT_OF_RANGE: "Field input is outside the bn128 scalar field",
  ALLOWLIST_MISS: "Recipient address is not a member of the committed Vendor Allowlist",
  STALE_EPOCH: "Proposed epoch regresses behind the active committed epoch",
  EPOCH_CAP_EXCEEDED: "Cumulative epoch spend would exceed the committed Epoch Spend Cap",
  PAYROLL_FLOOR_BREACH: "Disbursement would breach the committed Payroll Reserve Floor",
  DUPLICATE_INVOICE_HASH: "Invoice Digest has already been settled in this Audit Chain",
  INVARIANT_BROKEN: "Internal shadow policy and circuit transition check diverged",
};

export function evaluatePolicyShadow(input: PolicyShadowInput): PolicyShadowResult {
  const uint64Fields = [
    input.epochCap,
    input.payrollFloor,
    input.balance,
    input.spentSoFar,
    input.prevEpoch,
    input.amount,
    input.epoch,
  ];
  if (!uint64Fields.every(isUint64)) {
    return {
      ok: false,
      reasonCode: "UINT64_OUT_OF_RANGE",
      invariantDrift: false,
      message: REASON_MESSAGES.UINT64_OUT_OF_RANGE!,
    };
  }

  const scalarFields = [
    input.recipient,
    input.invoiceIdField,
    input.policySalt,
    input.prevSalt,
    input.newSalt,
    ...input.allowlistRecipients,
  ];
  if (!scalarFields.every(isField)) {
    return {
      ok: false,
      reasonCode: "FIELD_OUT_OF_RANGE",
      invariantDrift: false,
      message: REASON_MESSAGES.FIELD_OUT_OF_RANGE!,
    };
  }

  const allowlistSet = new Set(input.allowlistRecipients);
  if (!allowlistSet.has(input.recipient)) {
    return {
      ok: false,
      reasonCode: "ALLOWLIST_MISS",
      invariantDrift: false,
      message: REASON_MESSAGES.ALLOWLIST_MISS!,
    };
  }

  if (input.epoch < input.prevEpoch) {
    return {
      ok: false,
      reasonCode: "STALE_EPOCH",
      invariantDrift: false,
      message: REASON_MESSAGES.STALE_EPOCH!,
    };
  }

  const baseSpent = input.epoch === input.prevEpoch ? input.spentSoFar : 0n;
  const newSpent = baseSpent + input.amount;

  if (newSpent > input.epochCap) {
    return {
      ok: false,
      reasonCode: "EPOCH_CAP_EXCEEDED",
      invariantDrift: false,
      message: REASON_MESSAGES.EPOCH_CAP_EXCEEDED!,
    };
  }

  if (newSpent + input.payrollFloor > input.balance) {
    return {
      ok: false,
      reasonCode: "PAYROLL_FLOOR_BREACH",
      invariantDrift: false,
      message: REASON_MESSAGES.PAYROLL_FLOOR_BREACH!,
    };
  }

  const invoiceHash = computeInvoiceHash(input.recipient, input.invoiceIdField);
  if (input.knownInvoiceHashes?.has(invoiceHash.toString(10))) {
    return {
      ok: false,
      reasonCode: "DUPLICATE_INVOICE_HASH",
      invariantDrift: false,
      message: REASON_MESSAGES.DUPLICATE_INVOICE_HASH!,
    };
  }

  const circuitEval = evaluateSingleStepTransition(input);
  if (!circuitEval.ok) {
    return {
      ok: false,
      reasonCode: "INVARIANT_BROKEN",
      invariantDrift: true,
      message: `${REASON_MESSAGES.INVARIANT_BROKEN}: ${circuitEval.reasonCode}`,
    };
  }

  if (circuitEval.newSpent !== newSpent || circuitEval.publicSignals.invoiceHash !== invoiceHash) {
    return {
      ok: false,
      reasonCode: "INVARIANT_BROKEN",
      invariantDrift: true,
      message: REASON_MESSAGES.INVARIANT_BROKEN!,
    };
  }

  return {
    ok: true,
    reasonCode: "POLICY_PASS",
    newSpent,
    invoiceHash,
    publicSignals: circuitEval.publicSignals,
    circuitInput: circuitEval.circuitInput,
  };
}

export async function verifyShadowAgainstWasm(
  shadow: PolicyShadowResult,
  overrideCircuitInput?: ReserveRailRawCircuitInput,
): Promise<{ readonly drift: boolean; readonly reasonCode: string | null }> {
  if (!shadow.ok) {
    if (overrideCircuitInput === undefined) {
      return { drift: false, reasonCode: null };
    }
    try {
      await calculateTransitionWitness(overrideCircuitInput);
      return { drift: true, reasonCode: "WASM_UNEXPECTED_PASS" };
    } catch {
      return { drift: false, reasonCode: null };
    }
  }

  const targetInput = overrideCircuitInput ?? shadow.circuitInput;
  try {
    const wasmSignals = await calculateTransitionWitness(targetInput);
    const expectedWire = toPublicSignalsArray(shadow.publicSignals);
    const actualWire = toPublicSignalsArray(wasmSignals);
    for (let i = 0; i < expectedWire.length; i += 1) {
      if (expectedWire[i] !== actualWire[i]) {
        return { drift: true, reasonCode: "WIRE_SIGNAL_MISMATCH" };
      }
    }
    return { drift: false, reasonCode: null };
  } catch {
    return { drift: true, reasonCode: "WASM_UNEXPECTED_FAIL" };
  }
}
