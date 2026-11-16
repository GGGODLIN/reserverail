import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, describe, it } from "node:test";
import { terminateCurve } from "../src/circuit/prover.ts";
import { verifyAuditChain } from "../src/engine/audit-chain.ts";
import { parsePaymentIntent } from "../src/engine/intent-parser.ts";
import { ProvingSemaphore } from "../src/engine/proving-semaphore.ts";
import { VERIFICATION_KEY } from "../src/generated/circuit-abi.ts";
import { KurierClient } from "../src/kurier/kurier-client.ts";
import { createReserveRailServer } from "../src/server/app.ts";

after(async () => {
  await terminateCurve();
});

function signTestPayload(raw: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("hex");
}

describe("Tier 2 Bounded State-Transition & Concurrency Inspection", () => {
  it("coalesces concurrent identical taskId retries, rejects concurrent conflicting taskId with 409, and drains clean on shutdown", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rr-tier2-"));
    const dbPath = path.join(dir, "tier2.db");
    const hmacSecret = "tier2-hmac-secret";
    let kurierSubmitCalls = 0;

    const kurierClient = new KurierClient({
      apiKey: "kurier-synthetic-tier2-key",
      fetchImpl: async (input) => {
        const u = typeof input === "string" ? input : input.toString();
        if (u.includes("/submit-proof/")) {
          kurierSubmitCalls += 1;
          await new Promise((r) => setTimeout(r, 80));
          return new Response(JSON.stringify({ jobId: "job-tier2-1", status: "pending" }), {
            status: 202,
          });
        }
        // Slow job-status so server.close() drains active async finality tracker safely
        await new Promise((r) => setTimeout(r, 200));
        return new Response(
          JSON.stringify({
            jobId: "job-tier2-1",
            status: "Finalized",
            txHash: "0x" + "a".repeat(64),
            blockHash: "0x" + "b".repeat(64),
          }),
          { status: 200 },
        );
      },
      pollBaseDelayMs: 25,
      pollMaxDelayMs: 50,
      wsConnectTimeoutMs: 10,
      createWebSocket: () => ({
        readyState: 3,
        send: () => undefined,
        close: () => undefined,
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null,
      }),
    });

    const srv = await createReserveRailServer({
      dbPath,
      agentHmacSecret: hmacSecret,
      kurierClient,
    });

    try {
      await srv.listen(0, "127.0.0.1");

      const payloadSame = JSON.stringify({
        taskId: "tier2-task-1",
        recipient: "AWS",
        amount: 10_000,
        epoch: 1,
        invoiceId: "tier2-inv-1",
      });
      const payloadConflict = JSON.stringify({
        taskId: "tier2-task-1",
        recipient: "AWS",
        amount: 10_001,
        epoch: 1,
        invoiceId: "tier2-inv-1",
      });

      const [r1, r2, rConflict] = await Promise.all([
        fetch(`${srv.url}/agent`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-agent-games-signature": signTestPayload(payloadSame, hmacSecret),
          },
          body: payloadSame,
        }),
        fetch(`${srv.url}/agent`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-agent-games-signature": signTestPayload(payloadSame, hmacSecret),
          },
          body: payloadSame,
        }),
        (async () => {
          await new Promise((r) => setTimeout(r, 15));
          return fetch(`${srv.url}/agent`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-agent-games-signature": signTestPayload(payloadConflict, hmacSecret),
            },
            body: payloadConflict,
          });
        })(),
      ]);

      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(await r1.text(), await r2.text());
      assert.equal(rConflict.status, 409);
      assert.equal(kurierSubmitCalls, 1, "Coalesced concurrent retries must submit to Kurier only once");

      // Concurrent dual-agent race on demo sandbox leaves zero dangling leases, zero unexpected 500s, and valid chain
      const raceRes = await fetch(`${srv.url}/api/demo/act`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_tier2_race", actId: "act3_concurrency" }),
      });
      assert.equal(raceRes.status, 200);
      const raceJson = (await raceRes.json()) as {
        readonly steps: Array<{
          readonly reserveRailResult: {
            readonly approved: boolean;
            readonly reasonCode: string;
            readonly staleProvesAttempted: number;
          };
        }>;
      };
      const raceWinners = raceJson.steps.filter((s) => s.reserveRailResult.approved);
      const raceLosers = raceJson.steps.filter((s) => !s.reserveRailResult.approved);
      assert.equal(raceWinners.length, 1);
      assert.equal(raceLosers.length, 1);
      assert.equal(raceLosers[0]!.reserveRailResult.reasonCode, "PAYROLL_FLOOR_BREACH");
      assert.equal(raceLosers[0]!.reserveRailResult.staleProvesAttempted, 0);

      const diag = srv.store.getDiagnosticsSummary();
      assert.equal(diag.activeLeases, 0);
      assert.equal(diag.outboxCounts.PENDING_SUBMIT, 0);
      assert.equal(diag.outboxCounts.ROLLED_BACK, 0);
      assert.equal(diag.invariantDriftCount, 0);

      const sbx = srv.store.getSandboxSnapshot("sbx_tier2_race");
      const receipts = srv.store.getReceipts("sbx_tier2_race");
      const chain = await verifyAuditChain(receipts, sbx.genesisCommitment, sbx.policyRoot, VERIFICATION_KEY);
      assert.equal(chain.valid, true);
      assert.equal(receipts.length, 1);

      // Verify aborting a queued semaphore waiter releases cleanly with zero slot leaks
      const sem = new ProvingSemaphore(1);
      const releaseFirst = await sem.acquire(0);
      const abortCtrl = new AbortController();
      const queuedPromise = sem.acquire(1, abortCtrl.signal);
      abortCtrl.abort();
      await assert.rejects(() => queuedPromise, /PROVING_QUEUE_ABORTED/);
      releaseFirst();
      assert.equal(sem.getStats().activeProves, 0);

      // Verify intent_cache row cap (<= 500)
      for (let i = 0; i < 510; i += 1) {
        await parsePaymentIntent(
          { memo: `Pay AWS 100 for batch-${i}`, invoiceId: `cap-${i}` },
          { store: srv.store },
        );
      }
      const inspectDb = new DatabaseSync(dbPath);
      try {
        const row = inspectDb.prepare("SELECT COUNT(*) AS cnt FROM intent_cache").get() as Record<string, unknown>;
        assert.equal(Number(row.cnt) <= 500, true, `Expected <= 500 cached intents, got ${row.cnt}`);
      } finally {
        inspectDb.close();
      }
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
