import type { Groth16VerificationKey } from "snarkjs";
import { z } from "zod";
import { verifyTransitionProof } from "../circuit/verifier.ts";
import {
  SNARK_SCALAR_FIELD,
  VERIFICATION_KEY,
  fromPublicSignalsArray,
  toPublicSignalsArray,
} from "../generated/circuit-abi.ts";

const DECIMAL_BIGINT_RE = /^(0|[1-9][0-9]*)$/;

const DecimalFieldSchema = z.string().regex(DECIMAL_BIGINT_RE, "Expected decimal field string");

export const Groth16ProofSchema = z
  .object({
    pi_a: z.array(z.string()).min(2).readonly(),
    pi_b: z.array(z.array(z.string()).min(2).readonly()).min(2).readonly(),
    pi_c: z.array(z.string()).min(2).readonly(),
    protocol: z.string(),
    curve: z.string(),
  })
  .superRefine((val, ctx) => {
    if (val.protocol !== "groth16") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["protocol"],
        message: "Expected groth16 protocol",
      });
    }
    if (val.curve !== "bn128") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["curve"],
        message: "Expected bn128 curve",
      });
    }
  });

export const PublicSignalsObjectSchema = z.object({
  policyRoot: DecimalFieldSchema,
  prevCommitment: DecimalFieldSchema,
  newCommitment: DecimalFieldSchema,
  recipient: DecimalFieldSchema,
  amount: DecimalFieldSchema,
  epoch: DecimalFieldSchema,
  invoiceHash: DecimalFieldSchema,
});

export const ReceiptProvenanceSchema = z.object({
  mode: z.enum(["LIVE", "DETERMINISTIC_REPLAY"]),
  network: z.string().min(1),
  vkHash: z.string().min(1),
  jobId: z.string().nullable(),
  txHash: z.string().nullable(),
  blockHash: z.string().nullable(),
  txExplorerUrl: z.string().nullable(),
  blockExplorerUrl: z.string().nullable(),
  status: z.string().min(1),
  note: z.string().optional(),
});

export const TreasuryReceiptSchema = z.object({
  receiptId: z.string().min(1),
  sandboxId: z.string().min(1),
  seq: z.number().int().nonnegative(),
  vendorName: z.string().optional(),
  invoiceId: z.string().optional(),
  proof: Groth16ProofSchema,
  publicSignals: PublicSignalsObjectSchema,
  publicSignalsArray: z.array(DecimalFieldSchema).length(7),
  provenance: ReceiptProvenanceSchema,
  createdAt: z.string().min(1),
  settledAt: z.string().nullable().optional(),
});

export type TreasuryReceipt = z.infer<typeof TreasuryReceiptSchema>;

export type AuditChainViolationCode =
  | "MALFORMED_RECEIPT"
  | "MALFORMED_SIGNALS"
  | "POLICY_ROOT_MISMATCH"
  | "FORK_DETECTED"
  | "DUPLICATE_INVOICE_HASH"
  | "OUT_OF_ORDER"
  | "CHAIN_GAP"
  | "INVALID_PROOF";

export interface AuditChainViolation {
  readonly code: AuditChainViolationCode;
  readonly index: number;
  readonly receiptId: string;
  readonly message: string;
}

export interface AuditChainVerificationResult {
  readonly valid: boolean;
  readonly count: number;
  readonly headCommitment: string;
  readonly violations: readonly AuditChainViolation[];
  readonly reasonCode: AuditChainViolationCode | null;
}

function normalizeFieldString(value: string | bigint, label: string): string {
  if (typeof value === "string" && !DECIMAL_BIGINT_RE.test(value)) {
    throw new RangeError(`${label} must be a non-negative decimal integer string`);
  }
  const big = typeof value === "bigint" ? value : BigInt(value);
  if (big < 0n || big >= SNARK_SCALAR_FIELD) {
    throw new RangeError(`${label} is outside bn128 scalar field`);
  }
  return big.toString(10);
}

export async function verifyAuditChain(
  receipts: readonly unknown[],
  genesisCommitment: string | bigint,
  expectedPolicyRoot: string | bigint,
  verificationKey: Groth16VerificationKey = VERIFICATION_KEY,
): Promise<AuditChainVerificationResult> {
  const normalizedGenesis = normalizeFieldString(genesisCommitment, "genesisCommitment");
  const normalizedPolicyRoot = normalizeFieldString(expectedPolicyRoot, "expectedPolicyRoot");
  const violations: AuditChainViolation[] = [];

  if (receipts.length === 0) {
    return {
      valid: true,
      count: 0,
      headCommitment: normalizedGenesis,
      violations: [],
      reasonCode: null,
    };
  }

  const parsedReceipts: Array<{ readonly index: number; readonly receipt: TreasuryReceipt }> = [];
  for (let i = 0; i < receipts.length; i += 1) {
    const parsed = TreasuryReceiptSchema.safeParse(receipts[i]);
    if (!parsed.success) {
      violations.push({
        code: "MALFORMED_RECEIPT",
        index: i,
        receiptId: `index:${i}`,
        message: `Receipt at index ${i} failed schema validation`,
      });
      continue;
    }
    parsedReceipts.push({ index: i, receipt: parsed.data });
  }

  const seenPrevCommitments = new Set<string>();
  const seenInvoiceHashes = new Set<string>();
  const knownNewCommitments = new Set<string>(
    parsedReceipts.map((r) => r.receipt.publicSignals.newCommitment),
  );

  let expectedPrev = normalizedGenesis;

  for (const entry of parsedReceipts) {
    const { index: i, receipt } = entry;
    const { publicSignals, publicSignalsArray } = receipt;

    let arrayMatchesObject = true;
    try {
      const decoded = fromPublicSignalsArray(publicSignalsArray);
      const expectedArr = toPublicSignalsArray({
        policyRoot: BigInt(publicSignals.policyRoot),
        prevCommitment: BigInt(publicSignals.prevCommitment),
        newCommitment: BigInt(publicSignals.newCommitment),
        recipient: BigInt(publicSignals.recipient),
        amount: BigInt(publicSignals.amount),
        epoch: BigInt(publicSignals.epoch),
        invoiceHash: BigInt(publicSignals.invoiceHash),
      });
      for (let idx = 0; idx < expectedArr.length; idx += 1) {
        if (expectedArr[idx] !== publicSignalsArray[idx]) {
          arrayMatchesObject = false;
          break;
        }
      }
      if (decoded.newCommitment !== BigInt(publicSignals.newCommitment)) {
        arrayMatchesObject = false;
      }
    } catch {
      arrayMatchesObject = false;
    }

    if (!arrayMatchesObject) {
      violations.push({
        code: "MALFORMED_SIGNALS",
        index: i,
        receiptId: receipt.receiptId,
        message: `Receipt ${receipt.receiptId} publicSignals object disagrees with wire array`,
      });
    }

    if (publicSignals.policyRoot !== normalizedPolicyRoot) {
      violations.push({
        code: "POLICY_ROOT_MISMATCH",
        index: i,
        receiptId: receipt.receiptId,
        message: `Receipt ${receipt.receiptId} policyRoot does not match expectedPolicyRoot`,
      });
    }

    if (seenPrevCommitments.has(publicSignals.prevCommitment)) {
      violations.push({
        code: "FORK_DETECTED",
        index: i,
        receiptId: receipt.receiptId,
        message: `Fork detected: multiple receipts share prevCommitment ${publicSignals.prevCommitment}`,
      });
    } else {
      seenPrevCommitments.add(publicSignals.prevCommitment);
    }

    if (seenInvoiceHashes.has(publicSignals.invoiceHash)) {
      violations.push({
        code: "DUPLICATE_INVOICE_HASH",
        index: i,
        receiptId: receipt.receiptId,
        message: `Duplicate invoiceHash ${publicSignals.invoiceHash} detected at index ${i}`,
      });
    } else {
      seenInvoiceHashes.add(publicSignals.invoiceHash);
    }

    if (publicSignals.prevCommitment !== expectedPrev) {
      const isPermutation = knownNewCommitments.has(publicSignals.prevCommitment);
      violations.push({
        code: isPermutation ? "OUT_OF_ORDER" : "CHAIN_GAP",
        index: i,
        receiptId: receipt.receiptId,
        message: isPermutation
          ? `Out-of-order receipt at index ${i}: expected prevCommitment ${expectedPrev}, got ${publicSignals.prevCommitment}`
          : `Chain gap at index ${i}: expected prevCommitment ${expectedPrev}, got ${publicSignals.prevCommitment}`,
      });
    }
    expectedPrev = publicSignals.newCommitment;

    let proofOk = false;
    try {
      proofOk = await verifyTransitionProof(
        receipt.proof as Parameters<typeof verifyTransitionProof>[0],
        publicSignalsArray,
        verificationKey,
      );
    } catch {
      proofOk = false;
    }

    if (!proofOk) {
      violations.push({
        code: "INVALID_PROOF",
        index: i,
        receiptId: receipt.receiptId,
        message: `Groth16 proof verification failed for receipt ${receipt.receiptId}`,
      });
    }
  }

  const lastEntry = parsedReceipts[parsedReceipts.length - 1];
  const headCommitment = lastEntry
    ? lastEntry.receipt.publicSignals.newCommitment
    : normalizedGenesis;

  return {
    valid: violations.length === 0,
    count: parsedReceipts.length,
    headCommitment,
    violations,
    reasonCode: violations[0]?.code ?? null,
  };
}
