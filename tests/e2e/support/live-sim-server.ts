import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import type { Groth16Proof } from "snarkjs";
import { terminateCurve } from "../../../src/circuit/prover.ts";
import { VERIFICATION_KEY } from "../../../src/generated/circuit-abi.ts";
import { KurierClient } from "../../../src/kurier/kurier-client.ts";
import { createReserveRailServer } from "../../../src/server/app.ts";

// Test-only entry: the real ReserveRail server wired to a simulated Kurier relay, so the workbench's
// LIVE path (Submitted -> IncludedInBlock -> Finalized) runs with no credentials and no network.
// Stage timings are slow enough for the browser to observe each stage between polls.
const SUBMIT_LATENCY_MS = 400;
const INCLUDED_AFTER_MS = 1_500;
const FINALIZED_AFTER_MS = 4_000;

interface SimulatedJob {
  readonly submittedAt: number;
  readonly txHash: string;
  readonly blockHash: string;
}

const jobs = new Map<string, SimulatedJob>();

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function urlOf(input: string | URL | Request): string {
  if (typeof input === "string") {
    return input;
  }
  return input instanceof URL ? input.href : input.url;
}

async function simulatedKurier(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = urlOf(input);
  if (url.includes("/submit-proof/")) {
    await new Promise((resolve) => setTimeout(resolve, SUBMIT_LATENCY_MS));
    const payload = JSON.parse(String(init?.body ?? "{}")) as {
      readonly proofData?: { readonly proof?: Groth16Proof; readonly publicSignals?: string[] };
    };
    const proof = payload.proofData?.proof;
    const signals = payload.proofData?.publicSignals ?? [];
    // Kurier verifies optimistically before queueing; a tampered proof is refused the same way here.
    const valid = proof === undefined ? false : await snarkjs.groth16.verify(VERIFICATION_KEY, signals, proof);
    if (!valid) {
      return json(200, { optimisticVerify: "failed", error: "Simulated relay: optimistic Groth16 verification failed" });
    }
    const jobId = `sim-${crypto.randomUUID()}`;
    jobs.set(jobId, {
      submittedAt: Date.now(),
      txHash: `0x${crypto.randomBytes(32).toString("hex")}`,
      blockHash: `0x${crypto.randomBytes(32).toString("hex")}`,
    });
    return json(202, { jobId, status: "pending" });
  }

  if (url.includes("/job-status/")) {
    const jobId = decodeURIComponent(url.split("/").pop() ?? "");
    const job = jobs.get(jobId);
    if (job === undefined) {
      return json(404, { message: "Unknown simulated job" });
    }
    const age = Date.now() - job.submittedAt;
    if (age < INCLUDED_AFTER_MS) {
      return json(200, { jobId, status: "Submitted" });
    }
    return json(200, {
      jobId,
      status: age < FINALIZED_AFTER_MS ? "IncludedInBlock" : "Finalized",
      txHash: job.txHash,
      blockHash: job.blockHash,
      // A reserved .invalid host: the simulated transaction must never look like a real explorer entry.
      txExplorerUrl: `https://explorer.simulated.invalid/extrinsic/${job.txHash}`,
    });
  }

  return json(404, { message: "Unexpected simulated relay route" });
}

const kurierClient = new KurierClient({
  apiKey: "kurier-synthetic-e2e-live-sim",
  apiBaseUrl: "https://kurier.simulated.invalid/api/v1",
  wsUrl: "wss://kurier.simulated.invalid/api/v1/ws",
  fetchImpl: simulatedKurier,
  // Without this the client would dial the default WebSocket; failing here forces REST polling of the simulation.
  createWebSocket: () => {
    throw new Error("WebSocket is disabled for the simulated relay");
  },
  pollBaseDelayMs: 150,
  pollMaxDelayMs: 300,
});

const server = await createReserveRailServer({
  dbPath: process.env.RESERVERAIL_DB_PATH ?? ".e2e/db/live-sim.db",
  kurierClient,
});

await server.listen(Number(process.env.PORT ?? 0), process.env.HOST ?? "127.0.0.1");
process.stdout.write(`${JSON.stringify({ event: "live-sim.listening", url: server.url })}\n`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void (async () => {
      await server.close();
      await kurierClient.close();
      await terminateCurve();
      process.exit(0);
    })();
  });
}
