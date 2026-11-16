import * as snarkjs from "snarkjs";
import type { Groth16Proof, Groth16VerificationKey } from "snarkjs";
import { VERIFICATION_KEY, toPublicSignalsArray } from "../generated/circuit-abi.ts";
import type { ReserveRailPublicSignals } from "../generated/circuit-abi.ts";

// Kept free of Node built-ins: the workbench bundles this module to verify proofs inside the browser.
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
