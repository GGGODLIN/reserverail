import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { Groth16ProofSchema, PublicSignalsObjectSchema } from "./audit-chain.ts";

const DEFAULT_CASSETTE_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "artifacts",
  "gate01-mainnet-receipt.json",
);

export const VerificationEnvelopeSchema = z.object({
  schemaVersion: z.literal("reserverail.gate01.v1"),
  network: z.literal("zkverify-mainnet"),
  vkHash: z.string().regex(/^0x[0-9a-fA-F]{16,}$/),
  firstRegisterAlreadyRegistered: z.boolean(),
  idempotentReRegisterVerified: z.boolean(),
  secondRegisterAlreadyRegisteredFlag: z.boolean(),
  constraintCount: z.number().int().positive(),
  validTransition: z.object({
    jobId: z.string().min(1),
    submitHttpStatus: z.number().int(),
    optimisticVerify: z.string().min(1),
    observedStages: z.array(z.string()).min(1),
    status: z.literal("Finalized"),
    txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    blockHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    txExplorerUrl: z.string().url(),
    blockExplorerUrl: z.string().url().nullable().optional(),
    statement: z.string().nullable().optional(),
    settledAt: z.string().min(1),
    publicSignals: PublicSignalsObjectSchema,
    publicSignalsArray: z.array(z.string()).length(7),
    proof: Groth16ProofSchema,
  }),
  tamperedProbe: z.object({
    rejected: z.literal(true),
    httpStatus: z.number().int(),
    optimisticVerify: z.string().min(1),
    reason: z.string().min(1),
  }),
});

export type BaselineMainnetCassette = z.infer<typeof VerificationEnvelopeSchema>;

export function loadBaselineMainnetCassette(
  filePath: string = DEFAULT_CASSETTE_PATH,
): BaselineMainnetCassette {
  const raw = fs.readFileSync(filePath, "utf8");
  const parsedJson: unknown = JSON.parse(raw);
  return VerificationEnvelopeSchema.parse(parsedJson);
}
