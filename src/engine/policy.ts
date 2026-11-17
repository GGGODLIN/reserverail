import crypto from "node:crypto";
import { poseidon2 } from "poseidon-lite";
import {
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
  const circuitEval = evaluateSingleStepTransition(input);
  if (!circuitEval.ok) {
    const code = circuitEval.reasonCode as Exclude<PolicyShadowResult, { readonly ok: true }>["reasonCode"];
    return {
      ok: false,
      reasonCode: REASON_MESSAGES[code] !== undefined ? code : "INVARIANT_BROKEN",
      invariantDrift: REASON_MESSAGES[code] === undefined,
      message: REASON_MESSAGES[code] ?? `${REASON_MESSAGES.INVARIANT_BROKEN}: ${circuitEval.reasonCode}`,
    };
  }

  const invoiceHash = circuitEval.publicSignals.invoiceHash;
  if (input.knownInvoiceHashes?.has(invoiceHash.toString(10))) {
    return {
      ok: false,
      reasonCode: "DUPLICATE_INVOICE_HASH",
      invariantDrift: false,
      message: REASON_MESSAGES.DUPLICATE_INVOICE_HASH!,
    };
  }

  return {
    ok: true,
    reasonCode: "POLICY_PASS",
    newSpent: circuitEval.newSpent,
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
