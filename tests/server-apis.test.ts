import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { terminateCurve } from "../src/circuit/prover.ts";
import { REGISTERED_VK_HASH } from "../src/generated/circuit-abi.ts";
import { KurierClient } from "../src/kurier/kurier-client.ts";
import { ReserveRailStore } from "../src/engine/sqlite-store.ts";
import { createReserveRailServer } from "../src/server/app.ts";

after(async () => {
  await terminateCurve();
});

const PRIMARY_HMAC = "hmac-synthetic-primary-secret-9999";
const PREVIOUS_HMAC = "hmac-synthetic-previous-secret-8888";
const FAKE_KURIER_KEY = "kurier-synthetic-test-key-9999";

function signRawBody(raw: string | Buffer, secret: string, prefix = ""): string {
  const digest = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return `${prefix}${digest}`;
}

function verifyResponseHmac(rawBody: string, signatureHeader: string | undefined, secret: string): boolean {
  if (!signatureHeader) {
    return false;
  }
  const cleanHex = signatureHeader.replace(/^sha256=/i, "").trim().toLowerCase();
  const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("hex");
  if (cleanHex.length !== expected.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(cleanHex, "utf8"), Buffer.from(expected, "utf8"));
}

function createTempDbPath(prefix: string): { readonly dir: string; readonly dbPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return { dir, dbPath: path.join(dir, "reserverail-server.db") };
}

describe("Ticket 02 — Signed /agent Endpoint (HMAC, Preflight, Idempotency, Soft Deadline & Docs)", () => {
  it("serves human-readable JSON docs on GET /agent and verifies bidirectional raw-body HMAC + <50ms preflight + rotation grace", async () => {
    const { dir, dbPath } = createTempDbPath("rr-srv-agent-");
    const srv = await createReserveRailServer({
      dbPath,
      agentHmacSecret: PRIMARY_HMAC,
      agentHmacSecretPrevious: PREVIOUS_HMAC,
    });

    try {
      await srv.listen(0, "127.0.0.1");

      // GET /healthz
      const healthRes = await fetch(`${srv.url}/healthz`);
      assert.equal(healthRes.status, 200);
      const healthJson = (await healthRes.json()) as {
        readonly ok: boolean;
        readonly vkHash: string;
        readonly maxConcurrency: number;
      };
      assert.equal(healthJson.ok, true);
      assert.equal(healthJson.vkHash, REGISTERED_VK_HASH);
      assert.equal(healthJson.maxConcurrency, 2);

      // GET /agent -> human-readable docs, never 401
      const docsRes = await fetch(`${srv.url}/agent`);
      assert.equal(docsRes.status, 200);
      const docsJson = (await docsRes.json()) as {
        readonly name: string;
        readonly curlExample: string;
        readonly signatureHeader: string;
      };
      assert.equal(docsJson.name, "ReserveRail");
      assert.equal(docsJson.signatureHeader, "x-agent-games-signature");
      assert.equal(docsJson.curlExample.includes("POST"), true);

      // Missing / bad signature -> 401 with signed outbound response
      const badSigRes = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-agent-games-signature": "deadbeef" },
        body: JSON.stringify({ type: "preflight" }),
      });
      assert.equal(badSigRes.status, 401);
      const badSigText = await badSigRes.text();
      assert.equal(
        verifyResponseHmac(badSigText, badSigRes.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );

      // Preflight <50ms with primary secret & sha256= prefix
      const preflightBody = JSON.stringify({ type: "agent-games.preflight.v1", challenge: "c-1" });
      const t0 = performance.now();
      const preRes = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(preflightBody, PRIMARY_HMAC, "sha256="),
        },
        body: preflightBody,
      });
      const elapsedMs = performance.now() - t0;
      assert.equal(preRes.status, 200);
      assert.equal(elapsedMs < 50, true, `Expected <50ms preflight, got ${elapsedMs}ms`);
      const preText = await preRes.text();
      assert.equal(
        verifyResponseHmac(preText, preRes.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );
      const preJson = JSON.parse(preText) as { readonly ok: boolean; readonly protocolVersion: string };
      assert.equal(preJson.ok, true);
      assert.equal(preJson.protocolVersion, "v1");

      // Previous secret rotation grace
      const rotBody = JSON.stringify({ type: "preflight", challenge: "c-rot" });
      const rotRes = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(rotBody, PREVIOUS_HMAC),
        },
        body: rotBody,
      });
      assert.equal(rotRes.status, 200);
      const rotText = await rotRes.text();
      assert.equal(
        verifyResponseHmac(rotText, rotRes.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enforces (taskId, rawBody) idempotency before DUPLICATE_INVOICE_HASH, returns 409 on conflict, never caches 5xx, and enforces soft deadline", async () => {
    const { dir, dbPath } = createTempDbPath("rr-srv-idem-");
    let kurierCalls = 0;
    const mockKurierFetch: typeof globalThis.fetch = async () => {
      kurierCalls += 1;
      if (kurierCalls === 1) {
        return new Response(JSON.stringify({ message: "Temporary Kurier 503" }), { status: 503 });
      }
      if (kurierCalls === 2) {
        return new Response(JSON.stringify({ jobId: "job-agent-1", optimisticVerify: "success" }), { status: 200 });
      }
      // 3rd call (for deadline test) stalls beyond 3000ms soft deadline
      await new Promise((resolve) => setTimeout(resolve, 3_500));
      return new Response(JSON.stringify({ jobId: "job-late", optimisticVerify: "success" }), { status: 200 });
    };

    const kurierClient = new KurierClient({
      apiKey: FAKE_KURIER_KEY,
      fetchImpl: mockKurierFetch,
      createWebSocket: () => ({
        readyState: 3,
        send: () => undefined,
        close: () => undefined,
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null,
      }),
      wsConnectTimeoutMs: 10,
      pollBaseDelayMs: 10,
      pollMaxDelayMs: 20,
    });

    const srv = await createReserveRailServer({
      dbPath,
      agentHmacSecret: PRIMARY_HMAC,
      kurierClient,
      agentSoftDeadlineMs: 3_000,
      submitMaxRetries: 0,
    });

    try {
      await srv.listen(0, "127.0.0.1");

      const taskPayload = JSON.stringify({
        taskId: "task-101",
        recipient: "AWS",
        amount: 12_000,
        epoch: 1,
        invoiceId: "agent-inv-101",
      });

      // 1. First attempt hits 503 -> returns 503 and is NOT cached
      const res503 = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(taskPayload, PRIMARY_HMAC),
        },
        body: taskPayload,
      });
      assert.equal(res503.status, 503);
      const text503 = await res503.text();
      assert.equal(text503.includes(FAKE_KURIER_KEY), false, "synthetic key leaked");
      assert.equal(
        verifyResponseHmac(text503, res503.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );

      // 2. Retry same taskId + identical rawBody -> succeeds (200) because 5xx was never cached!
      const resOk1 = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(taskPayload, PRIMARY_HMAC),
        },
        body: taskPayload,
      });
      assert.equal(resOk1.status, 200);
      const bodyOk1 = await resOk1.text();
      const parsedOk1 = JSON.parse(bodyOk1) as { readonly approved: boolean; readonly receipt: { readonly receiptId: string } };
      assert.equal(parsedOk1.approved, true);

      // 3. Network retry with identical (taskId, rawBody) -> replays byte-identical response WITHOUT DUPLICATE_INVOICE_HASH
      const resReplay = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(taskPayload, PRIMARY_HMAC),
        },
        body: taskPayload,
      });
      assert.equal(resReplay.status, 200);
      const bodyReplay = await resReplay.text();
      assert.equal(bodyReplay, bodyOk1);

      // 4. Conflicting payload under same taskId -> 409
      const conflictPayload = JSON.stringify({
        taskId: "task-101",
        recipient: "AWS",
        amount: 13_000,
        epoch: 1,
        invoiceId: "agent-inv-101",
      });
      const resConflict = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(conflictPayload, PRIMARY_HMAC),
        },
        body: conflictPayload,
      });
      assert.equal(resConflict.status, 409);

      // 5. Distinct taskId with same invoice -> signed HTTP 200 decision=REJECT with DUPLICATE_INVOICE_HASH
      const dupTaskPayload = JSON.stringify({
        taskId: "task-102",
        recipient: "AWS",
        amount: 12_000,
        epoch: 1,
        invoiceId: "agent-inv-101",
      });
      const resDup = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(dupTaskPayload, PRIMARY_HMAC),
        },
        body: dupTaskPayload,
      });
      assert.equal(resDup.status, 200);
      const dupText = await resDup.text();
      assert.equal(
        verifyResponseHmac(dupText, resDup.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );
      const parsedDup = JSON.parse(dupText) as {
        readonly ok: boolean;
        readonly decision: string;
        readonly approved: boolean;
        readonly reasonCode: string;
      };
      assert.equal(parsedDup.ok, true);
      assert.equal(parsedDup.decision, "REJECT");
      assert.equal(parsedDup.approved, false);
      assert.equal(parsedDup.reasonCode, "DUPLICATE_INVOICE_HASH");

      // 6. Soft deadline guard -> 504 and never cached
      const slowPayload = JSON.stringify({
        taskId: "task-103",
        recipient: "Stripe",
        amount: 5_000,
        epoch: 1,
        invoiceId: "agent-inv-103",
      });
      const resDeadline = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": signRawBody(slowPayload, PRIMARY_HMAC),
        },
        body: slowPayload,
      });
      assert.equal(resDeadline.status, 504);
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("Ticket 02 — Public /api/demo/* (3-Act Flow, Input Defense, Circular Eviction, Reset, Tamper & Replay)", () => {
  it("runs Acts 1-3, enforces input caps, circularly evicts demo sandboxes, resets <1s preserving explorer links, and verifies tamper", async () => {
    const { dir, dbPath } = createTempDbPath("rr-srv-demo-");
    let llmCalls = 0;
    const mockLlmFetch: typeof globalThis.fetch = async () => {
      llmCalls += 1;
      // Simulate slow upstream timeout so 4s (100ms in test) deterministic fallback triggers without paid pools
      await new Promise((resolve) => setTimeout(resolve, 250));
      return new Response("rate limited", { status: 429 });
    };

    const srv = await createReserveRailServer({
      dbPath,
      maxDemoSandboxes: 3,
      maritacaApiKey: "synthetic-maritaca-key",
      llmFetchImpl: mockLlmFetch,
      llmTimeoutMs: 60,
    });

    try {
      await srv.listen(0, "127.0.0.1");

      // Public route forbids touching competition scope
      const forbiddenRes = await fetch(`${srv.url}/api/demo/state?sandbox=competition`);
      assert.equal(forbiddenRes.status, 403);

      // Circular eviction: create 4 sandboxes when cap is 3 -> oldest evicted
      await fetch(`${srv.url}/api/demo/state?sandbox=sbx_old_1`);
      await new Promise((r) => setTimeout(r, 15));
      await fetch(`${srv.url}/api/demo/state?sandbox=sbx_old_2`);
      await new Promise((r) => setTimeout(r, 15));
      await fetch(`${srv.url}/api/demo/state?sandbox=sbx_old_3`);
      await new Promise((r) => setTimeout(r, 15));
      await fetch(`${srv.url}/api/demo/state?sandbox=sbx_main`);

      const countStore = ReserveRailStore.open(dbPath);
      try {
        assert.equal(countStore.countDemoSandboxes(), 3);
      } finally {
        countStore.close();
      }

      // Oversized >16KB -> 413, float amount -> 400, negative -> 400, memo >512 -> 400
      const oversized = JSON.stringify({ sandboxId: "sbx_main", memo: "x".repeat(17_000), amount: 100 });
      const resOver = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: oversized,
      });
      assert.equal(resOver.status, 413);

      const resFloat = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", recipient: "AWS", amount: 12.5 }),
      });
      assert.equal(resFloat.status, 400);

      const resNeg = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", recipient: "AWS", amount: -10 }),
      });
      assert.equal(resNeg.status, 400);

      const resLongMemo = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", memo: "m".repeat(513), amount: 100 }),
      });
      assert.equal(resLongMemo.status, 400);

      // Fail-closed natural-language memo checks (negative / fractional / missing recipient)
      const resNegMemo = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", memo: "Pay AWS -500 for compute" }),
      });
      assert.equal(resNegMemo.status, 400);

      const resFracMemo = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", memo: "Pay AWS $12.34 for compute" }),
      });
      assert.equal(resFracMemo.status, 400);

      const resNoVendorMemo = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_main", memo: "Pay mystery contractor 500" }),
      });
      assert.equal(resNoVendorMemo.status, 400);

      // Memo with non-monetary tokens (0x..., epoch 1, INV-...) parses cleanly
      const resTokenMemo = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sandboxId: "sbx_main",
          memo: "Pay AWS 400 for INV-2026-01 epoch 1 wallet 0x1111111111111111111111111111111111111001",
          invoiceId: "tok-memo-1",
        }),
      });
      assert.equal(resTokenMemo.status, 200);
      const tokenMemoJson = (await resTokenMemo.json()) as {
        readonly intent: { readonly amount: string };
      };
      assert.equal(tokenMemoJson.intent.amount, "400");

      // Uncached custom memo triggers card-free endpoint with 60ms timeout fallback -> deterministic parser
      const customRes = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sandboxId: "sbx_main",
          memo: "Pay AWS 1000 for November compute",
          invoiceId: "custom-fb-1",
        }),
      });
      assert.equal(customRes.status, 200);
      const customJson = (await customRes.json()) as {
        readonly intent: { readonly parserSource: string; readonly amount: string; readonly llmTokensUsed: number };
        readonly reserveRailResult: { readonly approved: boolean; readonly provenanceMode: string };
      };
      assert.equal(customJson.intent.parserSource, "deterministic_fallback");
      assert.equal(customJson.intent.amount, "1000");
      assert.equal(customJson.intent.llmTokensUsed, 0);
      assert.equal(customJson.reserveRailResult.approved, true);
      assert.equal(customJson.reserveRailResult.provenanceMode, "DETERMINISTIC_REPLAY");
      assert.equal(llmCalls, 2);

      // Repeated normalized memo hits cache -> 0 LLM calls
      const cachedRes = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sandboxId: "sbx_main",
          memo: "  pay   AWS 1000 for November compute ",
          invoiceId: "custom-fb-2",
        }),
      });
      assert.equal(cachedRes.status, 200);
      assert.equal(llmCalls, 2, "Repeated normalized memo must hit cache without calling LLM");

      // Act 1 Injection
      const act1Res = await fetch(`${srv.url}/api/demo/act`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_act1", actId: "act1_injection" }),
      });
      assert.equal(act1Res.status, 200);
      const act1Json = (await act1Res.json()) as {
        readonly steps: Array<{
          readonly naiveResult: { readonly approved: boolean };
          readonly reserveRailResult: { readonly approved: boolean; readonly reasonCode: string };
        }>;
      };
      assert.equal(act1Json.steps[0]!.naiveResult.approved, true);
      assert.equal(act1Json.steps[0]!.reserveRailResult.approved, false);
      assert.equal(act1Json.steps[0]!.reserveRailResult.reasonCode, "ALLOWLIST_MISS");

      // Act 2 Structuring (3 x 12,000 under epochCap=30,000)
      const act2Res = await fetch(`${srv.url}/api/demo/act`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_act2", actId: "act2_structuring" }),
      });
      assert.equal(act2Res.status, 200);
      const act2Json = (await act2Res.json()) as {
        readonly steps: Array<{
          readonly naiveResult: { readonly approved: boolean };
          readonly reserveRailResult: { readonly approved: boolean; readonly reasonCode?: string | null };
        }>;
      };
      assert.equal(act2Json.steps.length, 3);
      assert.equal(act2Json.steps.every((s) => s.naiveResult.approved), true);
      assert.equal(act2Json.steps[0]!.reserveRailResult.approved, true);
      assert.equal(act2Json.steps[1]!.reserveRailResult.approved, true);
      assert.equal(act2Json.steps[2]!.reserveRailResult.approved, false);
      assert.equal(act2Json.steps[2]!.reserveRailResult.reasonCode, "EPOCH_CAP_EXCEEDED");

      // Act 3 Concurrency Race (2 x 25,000 under balance=100,000, payrollFloor=60,000)
      const act3Res = await fetch(`${srv.url}/api/demo/act`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_act3", actId: "act3_concurrency" }),
      });
      assert.equal(act3Res.status, 200);
      const act3Json = (await act3Res.json()) as {
        readonly steps: Array<{
          readonly naiveResult: { readonly approved: boolean };
          readonly reserveRailResult: {
            readonly approved: boolean;
            readonly reasonCode?: string | null;
            readonly staleProvesAttempted: number;
          };
        }>;
        readonly auditChain: { readonly valid: boolean; readonly count: number };
      };
      assert.equal(act3Json.steps.length, 2);
      assert.equal(act3Json.steps.every((s) => s.naiveResult.approved), true);
      const rrApproved = act3Json.steps.filter((s) => s.reserveRailResult.approved);
      const rrRejected = act3Json.steps.filter((s) => !s.reserveRailResult.approved);
      assert.equal(rrApproved.length, 1);
      assert.equal(rrRejected.length, 1);
      assert.equal(rrRejected[0]!.reserveRailResult.reasonCode, "PAYROLL_FLOOR_BREACH");
      assert.equal(rrRejected[0]!.reserveRailResult.staleProvesAttempted, 0);
      assert.equal(act3Json.auditChain.valid, true);
      assert.equal(act3Json.auditChain.count, 1);

      // Tamper test on baseline mainnet receipt
      const tamperRes = await fetch(`${srv.url}/api/demo/tamper`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ useBaselineCassette: true }),
      });
      assert.equal(tamperRes.status, 200);
      const tamperJson = (await tamperRes.json()) as {
        readonly localVerified: boolean;
        readonly optimisticVerify: string;
      };
      assert.equal(tamperJson.localVerified, false);
      assert.equal(tamperJson.optimisticVerify, "local_only_failed");

      // Reset sandbox restores C_0 <1s while preserving historical mainnet links
      const resetT0 = performance.now();
      const resetRes = await fetch(`${srv.url}/api/demo/reset`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_act3" }),
      });
      assert.equal(resetRes.status, 200);
      assert.equal(performance.now() - resetT0 < 1_000, true);
      const resetJson = (await resetRes.json()) as {
        readonly state: {
          readonly auditorView: { readonly genesisCommitment: string; readonly currentCommitment: string };
          readonly receipts: unknown[];
          readonly mainnetExplorerLinks: Array<{ readonly txExplorerUrl: string }>;
        };
      };
      assert.equal(resetJson.state.auditorView.currentCommitment, resetJson.state.auditorView.genesisCommitment);
      assert.equal(resetJson.state.receipts.length, 0);
      assert.equal(resetJson.state.mainnetExplorerLinks.length >= 1, true);
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enforces proving semaphore maxConcurrency <= 2 and prioritizes high-priority /agent tasks ahead of /api/demo/*", async () => {
    const { ProvingSemaphore } = await import("../src/engine/proving-semaphore.ts");
    const sem = new ProvingSemaphore(2);
    const dispatchOrder: string[] = [];

    const release1 = await sem.acquire(1);
    const release2 = await sem.acquire(1);
    assert.equal(sem.getStats().activeProves, 2);

    const demoWaiter1 = sem.acquire(1).then((rel) => {
      dispatchOrder.push("demo-1");
      return rel;
    });
    const demoWaiter2 = sem.acquire(1).then((rel) => {
      dispatchOrder.push("demo-2");
      return rel;
    });
    const agentWaiter = sem.acquire(0).then((rel) => {
      dispatchOrder.push("agent-high");
      return rel;
    });

    assert.equal(sem.getStats().queuedHigh, 1);
    assert.equal(sem.getStats().queuedNormal, 2);

    release1();
    const relA = await agentWaiter;
    assert.equal(dispatchOrder[0], "agent-high");
    assert.equal(sem.getStats().activeProves <= 2, true);

    relA();
    const relD1 = await demoWaiter1;
    release2();
    const relD2 = await demoWaiter2;
    relD1();
    relD2();

    assert.deepEqual(dispatchOrder, ["agent-high", "demo-1", "demo-2"]);
    assert.equal(sem.getStats().activeProves, 0);
  });

  it("rejects unmutated proofs on /api/demo/tamper, inherits active sandbox epoch, signs /agent 413/non-ASCII 401, and stops finality polling on timeout", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rr-review-reg-"));
    const dbPath = path.join(dir, "reg.db");
    let tamperSubmits = 0;
    let pollHits = 0;

    const kurierClient = new KurierClient({
      apiKey: FAKE_KURIER_KEY,
      fetchImpl: async (input) => {
        const u = typeof input === "string" ? input : input.toString();
        if (u.includes("/submit-proof/")) {
          tamperSubmits += 1;
          return new Response(JSON.stringify({ jobId: "job-t", optimisticVerify: "failed" }), { status: 422 });
        }
        pollHits += 1;
        return new Response(JSON.stringify({ jobId: "job-stuck", status: "Queued" }), { status: 200 });
      },
      createWebSocket: () => ({
        readyState: 3,
        send: () => undefined,
        close: () => undefined,
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null,
      }),
      wsConnectTimeoutMs: 5,
      pollBaseDelayMs: 15,
      pollMaxDelayMs: 15,
    });

    const srv = await createReserveRailServer({
      dbPath,
      agentHmacSecret: PRIMARY_HMAC,
      kurierClient,
    });

    try {
      await srv.listen(0, "127.0.0.1");

      // 1. Untampered baseline cassette amount ("15000") must be rejected with 400 and 0 Kurier calls
      const unmutatedRes = await fetch(`${srv.url}/api/demo/tamper`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tamperedAmount: "15000" }),
      });
      assert.equal(unmutatedRes.status, 400);
      assert.equal(tamperSubmits, 0);

      // 2. Non-decimal signal in /api/demo/tamper returns 400 (not 500)
      const badSigRes = await fetch(`${srv.url}/api/demo/tamper`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          receipt: {
            proof: srv.service.cassette.validTransition.proof,
            publicSignalsArray: ["0", "0", "0", "0", "12.5", "1", "0"],
          },
        }),
      });
      assert.equal(badSigRes.status, 400);

      // 3. Omitted epoch after reset to epoch=2 uses active sandbox epoch=2 instead of hardcoding 1
      await fetch(`${srv.url}/api/demo/reset`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sandboxId: "sbx_ep2", epoch: 2 }),
      });
      const ep2Propose = await fetch(`${srv.url}/api/demo/propose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sandboxId: "sbx_ep2",
          recipient: "AWS",
          amount: "1000",
          mode: "DETERMINISTIC_REPLAY",
        }),
      });
      assert.equal(ep2Propose.status, 200);
      const ep2Json = (await ep2Propose.json()) as {
        readonly intent: { readonly epoch: string };
        readonly reserveRailResult: { readonly approved: boolean };
      };
      assert.equal(ep2Json.intent.epoch, "2");
      assert.equal(ep2Json.reserveRailResult.approved, true);

      // 4. Oversized /agent POST returns 413 signed with x-agent-games-signature
      const oversized = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ pad: "a".repeat(20_000) }),
      });
      assert.equal(oversized.status, 413);
      const oversizedText = await oversized.text();
      assert.equal(
        verifyResponseHmac(oversizedText, oversized.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );

      // 5. High-byte 64-char signature header returns signed 401 (never unsigned 500)
      const highByteRes = await fetch(`${srv.url}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": "é".repeat(64),
        },
        body: '{"type":"agent-games.preflight.v1"}',
      });
      assert.equal(highByteRes.status, 401);
      const highByteText = await highByteRes.text();
      assert.equal(
        verifyResponseHmac(highByteText, highByteRes.headers.get("x-agent-games-signature") ?? undefined, PRIMARY_HMAC),
        true,
      );

      // 6. waitForJobFinality stops background REST polling after timeoutMs
      await assert.rejects(
        () => kurierClient.waitForJobFinality("job-stuck", { timeoutMs: 40, preferWebSocket: false }),
        (err: unknown) =>
          err instanceof Error &&
          "code" in err &&
          (err as { readonly code?: unknown }).code === "FINALITY_TIMEOUT",
      );
      const hitsAtTimeout = pollHits;
      await new Promise((r) => setTimeout(r, 80));
      assert.equal(pollHits <= hitsAtTimeout + 1, true, "Background polling must stop once activeWaiters hits 0");
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
