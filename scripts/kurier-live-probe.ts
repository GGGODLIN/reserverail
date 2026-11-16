import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { poseidon1 } from "poseidon-lite";
import {
  proveTransition,
  terminateCurve,
  verifyTransitionProof,
} from "../src/circuit/prover.ts";
import {
  CIRCUIT_CONSTRAINT_COUNT,
  CIRCUIT_RULE_LINE_MAP,
  PUBLIC_SIGNAL_NAMES,
  VERIFICATION_KEY,
  toPublicSignalsArray,
} from "../src/generated/circuit-abi.ts";
import { KurierClient, KurierError, scrubKurierText } from "../src/kurier/kurier-client.ts";
import { renderGeneratedCircuitAbiSource } from "./build-circuit.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GENERATED_ABI_PATH = path.join(REPO_ROOT, "src", "generated", "circuit-abi.ts");
const RECEIPT_OUTPUT_PATH = path.join(REPO_ROOT, "artifacts", "gate01-mainnet-receipt.json");

function writeSafeJsonLine(payload: unknown, apiKey: string): void {
  const serialized = scrubKurierText(JSON.stringify(payload), apiKey);
  if (apiKey.trim().length > 0 && serialized.includes(apiKey.trim())) {
    throw new Error("Refusing to print unredacted output");
  }
  process.stdout.write(`${serialized}\n`);
}

async function runLiveMainnetProbe(): Promise<void> {
  const rawApiKey = process.env.KURIER_API_KEY ?? "";
  const trimmedKey = rawApiKey.trim();
  if (trimmedKey.length === 0) {
    throw new Error("KURIER_API_KEY environment variable is required for live Mainnet probe");
  }

  const client = new KurierClient({
    apiKey: trimmedKey,
    apiBaseUrl: process.env.KURIER_API_URL ?? "https://api.kurier.xyz/api/v1",
    wsUrl: process.env.KURIER_WS_URL ?? "wss://api.kurier.xyz/api/v1/ws",
    onLog: (entry) => {
      writeSafeJsonLine({ source: "KurierClient", ...entry }, trimmedKey);
    },
  });

  try {
    // 1. Register VK (handles fresh 200 or already-registered 400 meta.vkHash)
    const firstRegistration = await client.registerVerificationKey(VERIFICATION_KEY);
    // 2. Verify second call succeeds idempotently with identical non-empty vkHash (HTTP 200 or 400 meta.vkHash)
    const secondRegistration = await client.registerVerificationKey(VERIFICATION_KEY);
    if (
      secondRegistration.vkHash !== firstRegistration.vkHash ||
      firstRegistration.vkHash.length === 0
    ) {
      throw new Error("vkHash mismatch across idempotent register-vk calls");
    }

    // Persist REGISTERED_VK_HASH into src/generated/circuit-abi.ts without touching .zkey
    const updatedAbiSource = renderGeneratedCircuitAbiSource({
      constraintCount: CIRCUIT_CONSTRAINT_COUNT,
      orderedPublicSignals: PUBLIC_SIGNAL_NAMES,
      lineMap: CIRCUIT_RULE_LINE_MAP,
      verificationKey: VERIFICATION_KEY,
      registeredVkHash: firstRegistration.vkHash,
    });
    fs.writeFileSync(GENERATED_ABI_PATH, updatedAbiSource, "utf8");

    // 3. Generate real C_0 -> C_1 transition proof matching ReserveRail 3-act baseline policy
    const vendorAws = poseidon1([1001n]);
    const vendorDatadog = poseidon1([1002n]);
    const vendorCloudflare = poseidon1([1003n]);
    const vendorLinear = poseidon1([1004n]);

    const genesisTransition = await proveTransition({
      allowlistRecipients: [vendorAws, vendorDatadog, vendorCloudflare, vendorLinear],
      epochCap: 50_000n,
      payrollFloor: 60_000n,
      policySalt: 202611160001n,
      balance: 100_000n,
      spentSoFar: 0n,
      prevEpoch: 1n,
      prevSalt: 202611160002n,
      recipient: vendorAws,
      amount: 15_000n,
      epoch: 1n,
      invoiceIdField: poseidon1([2001n]),
      newSalt: 202611160003n,
    });

    const localVerified = await verifyTransitionProof(
      genesisTransition.proof,
      genesisTransition.publicSignals,
      VERIFICATION_KEY,
    );
    if (!localVerified) {
      throw new Error("Local Groth16 verification failed before Kurier submission");
    }

    const observedStages: string[] = ["LocalVerified"];
    await client.ensureWebSocketSubscribed();

    const validSubmit = await client.submitProof({
      vkHash: firstRegistration.vkHash,
      proof: genesisTransition.proof,
      publicSignals: genesisTransition.publicSignalsArray,
    });
    if (validSubmit.outcome !== "accepted") {
      throw new Error(`Valid C_0 -> C_1 proof rejected by Kurier: ${validSubmit.reason}`);
    }
    observedStages.push("KurierSubmitted");

    const finalizedJob = await client.waitForJobFinality(validSubmit.jobId, {
      timeoutMs: 180_000,
      onStageChange: (st) => {
        if (!observedStages.includes(st.status)) {
          observedStages.push(st.status);
        }
        writeSafeJsonLine(
          {
            event: "probe.stage_update",
            jobId: st.jobId,
            status: st.status,
            txHash: st.txHash,
          },
          trimmedKey,
        );
      },
    });

    if (finalizedJob.status !== "Finalized" || finalizedJob.txHash === null || finalizedJob.blockHash === null) {
      throw new Error("Kurier job finished without Finalized txHash/blockHash");
    }

    // 4. Submit tampered publicSignals (inflated amount without re-proving) and confirm rejection
    const tamperedSignals = toPublicSignalsArray({
      ...genesisTransition.publicSignals,
      amount: genesisTransition.publicSignals.amount + 1n,
    });

    const tamperedSubmit = await client.submitProof({
      vkHash: firstRegistration.vkHash,
      proof: genesisTransition.proof,
      publicSignals: tamperedSignals,
    });

    let tamperedRejected = false;
    let tamperedHttpStatus: number = tamperedSubmit.httpStatus;
    let tamperedOptimisticVerify: string = tamperedSubmit.optimisticVerify;
    let tamperedReason = "";

    if (tamperedSubmit.outcome === "rejected") {
      tamperedRejected = true;
      tamperedReason = tamperedSubmit.reason;
    } else {
      // Handle HTTP 202 async optimistic verification where failure surfaces on job-status
      try {
        await client.waitForJobFinality(tamperedSubmit.jobId, { timeoutMs: 60_000 });
      } catch (err: unknown) {
        if (err instanceof KurierError && err.code === "JOB_FAILED") {
          tamperedRejected = true;
          tamperedOptimisticVerify = "failed";
          tamperedReason = err.message;
        } else {
          throw err;
        }
      }
    }

    if (!tamperedRejected) {
      throw new Error("SECURITY CRITICAL: Tampered publicSignals were not rejected by Kurier");
    }

    const receiptPayload = {
      schemaVersion: "reserverail.gate01.v1",
      network: "zkverify-mainnet",
      vkHash: firstRegistration.vkHash,
      firstRegisterAlreadyRegistered: firstRegistration.alreadyRegistered,
      idempotentReRegisterVerified:
        secondRegistration.vkHash === firstRegistration.vkHash &&
        firstRegistration.vkHash.length > 0,
      secondRegisterAlreadyRegisteredFlag: secondRegistration.alreadyRegistered,
      constraintCount: CIRCUIT_CONSTRAINT_COUNT,
      validTransition: {
        jobId: validSubmit.jobId,
        submitHttpStatus: validSubmit.httpStatus,
        optimisticVerify: validSubmit.optimisticVerify,
        observedStages,
        status: finalizedJob.status,
        txHash: finalizedJob.txHash,
        blockHash: finalizedJob.blockHash,
        txExplorerUrl:
          finalizedJob.txExplorerUrl ??
          `https://zkverify.subscan.io/extrinsic/${finalizedJob.txHash}`,
        blockExplorerUrl: finalizedJob.blockExplorerUrl,
        statement: finalizedJob.statement,
        settledAt: finalizedJob.updatedAt ?? new Date().toISOString(),
        publicSignals: {
          policyRoot: genesisTransition.publicSignals.policyRoot.toString(10),
          prevCommitment: genesisTransition.publicSignals.prevCommitment.toString(10),
          newCommitment: genesisTransition.publicSignals.newCommitment.toString(10),
          recipient: genesisTransition.publicSignals.recipient.toString(10),
          amount: genesisTransition.publicSignals.amount.toString(10),
          epoch: genesisTransition.publicSignals.epoch.toString(10),
          invoiceHash: genesisTransition.publicSignals.invoiceHash.toString(10),
        },
        publicSignalsArray: genesisTransition.publicSignalsArray,
        proof: genesisTransition.proof,
      },
      tamperedProbe: {
        rejected: tamperedRejected,
        httpStatus: tamperedHttpStatus,
        optimisticVerify: tamperedOptimisticVerify,
        reason: scrubKurierText(tamperedReason, trimmedKey),
      },
    };

    const safeReceiptText = `${scrubKurierText(JSON.stringify(receiptPayload, null, 2), trimmedKey)}\n`;
    if (safeReceiptText.includes(trimmedKey)) {
      throw new Error("Refusing to write receipt containing API key substring");
    }
    fs.writeFileSync(RECEIPT_OUTPUT_PATH, safeReceiptText, "utf8");

    writeSafeJsonLine(
      {
        ok: true,
        vkHash: receiptPayload.vkHash,
        idempotentReRegisterVerified: receiptPayload.idempotentReRegisterVerified,
        jobId: receiptPayload.validTransition.jobId,
        status: receiptPayload.validTransition.status,
        txHash: receiptPayload.validTransition.txHash,
        blockHash: receiptPayload.validTransition.blockHash,
        txExplorerUrl: receiptPayload.validTransition.txExplorerUrl,
        tamperedRejected: receiptPayload.tamperedProbe.rejected,
        tamperedHttpStatus: receiptPayload.tamperedProbe.httpStatus,
        tamperedOptimisticVerify: receiptPayload.tamperedProbe.optimisticVerify,
      },
      trimmedKey,
    );
  } catch (err: unknown) {
    const rawMessage = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    process.stderr.write(
      `${JSON.stringify({ ok: false, error: scrubKurierText(rawMessage, trimmedKey) })}\n`,
    );
    process.exitCode = 1;
  } finally {
    await client.close();
    await terminateCurve();
  }
}

await runLiveMainnetProbe();
