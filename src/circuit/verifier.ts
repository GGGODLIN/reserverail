import * as snarkjs from "snarkjs";
import type { Groth16Proof, Groth16VerificationKey } from "snarkjs";
import {
  SNARK_SCALAR_FIELD,
  VERIFICATION_KEY,
  toPublicSignalsArray,
} from "../generated/circuit-abi.ts";
import type { ReserveRailPublicSignals } from "../generated/circuit-abi.ts";

const DECIMAL_FIELD_RE = /^(0|[1-9][0-9]*)$/;

// Kept free of Node built-ins: the workbench bundles this module to verify proofs inside the browser.
export async function verifyTransitionProof(
  proof: Groth16Proof,
  signals: ReserveRailPublicSignals | readonly string[],
  verificationKey: Groth16VerificationKey = VERIFICATION_KEY,
): Promise<boolean> {
  let publicSignalStrings: string[];
  if (Array.isArray(signals)) {
    if (signals.length !== verificationKey.nPublic) {
      return false;
    }
    for (const s of signals) {
      if (typeof s !== "string" || !DECIMAL_FIELD_RE.test(s) || BigInt(s) >= SNARK_SCALAR_FIELD) {
        return false;
      }
    }
    publicSignalStrings = [...signals];
  } else {
    publicSignalStrings = toPublicSignalsArray(signals as ReserveRailPublicSignals);
  }
  try {
    return await snarkjs.groth16.verify(verificationKey, publicSignalStrings, proof);
  } catch {
    return false;
  }
}
