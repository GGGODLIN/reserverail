import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { verifyTransitionProof } from "../src/circuit/verifier.ts";
import { type TreasuryReceipt, verifyAuditChain } from "../src/engine/audit-chain.ts";
import { REGISTERED_VK_HASH, VERIFICATION_KEY } from "../src/generated/circuit-abi.ts";

interface LiveSmokeConfig {
  readonly baseUrl: string;
  readonly runMainnet: boolean;
  readonly receiptOut?: string;
  readonly reserverailHmacSecret?: string;
  readonly gatekeeperHmacSecret?: string;
  readonly finalizeTimeoutMs: number;
}

function parseCliArgs(argv: readonly string[]): LiveSmokeConfig {
  let baseUrl = process.env.LIVE_BASE_URL ?? "https://reserverail.gggodlin.com";
  let runMainnet = process.env.LIVE_SMOKE_RUN_MAINNET === "1";
  let receiptOut: string | undefined;
  let finalizeTimeoutMs = 120_000;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--base-url" && argv[i + 1] !== undefined) {
      baseUrl = argv[i + 1] ?? baseUrl;
      i += 1;
    } else if (arg === "--run-mainnet") {
      runMainnet = true;
    } else if (arg === "--receipt-out" && argv[i + 1] !== undefined) {
      receiptOut = argv[i + 1];
      i += 1;
    } else if (arg === "--timeout-ms" && argv[i + 1] !== undefined) {
      const parsed = Number.parseInt(argv[i + 1] ?? "120000", 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        finalizeTimeoutMs = parsed;
      }
      i += 1;
    }
  }

  return {
    baseUrl: baseUrl.replace(/\/+$/, ""),
    runMainnet,
    receiptOut,
    reserverailHmacSecret: process.env.LIVE_RESERVERAIL_HMAC_SECRET?.trim(),
    gatekeeperHmacSecret: process.env.LIVE_GATEKEEPER_HMAC_SECRET?.trim(),
    finalizeTimeoutMs,
  };
}

function hmacHex(raw: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("hex");
}

function verifyOutboundHmac(rawBody: string, headerVal: string | null, secret: string): boolean {
  if (headerVal === null) {
    return false;
  }
  const clean = headerVal.trim().replace(/^sha256=/i, "").toLowerCase();
  const expected = hmacHex(rawBody, secret);
  if (clean.length !== expected.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(clean, "utf8"), Buffer.from(expected, "utf8"));
}

async function verifySignedPreflight(
  endpointUrl: string,
  secret: string,
  label: string,
): Promise<{ readonly status: number; readonly latencyMs: number }> {
  // Negative control: unsigned POST must be rejected with 401
  const unsignedRes = await fetch(endpointUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"type":"agent-games.preflight.v1"}',
  });
  assert.equal(unsignedRes.status, 401, `${label}: unsigned POST must return HTTP 401`);

  const rawRequest = JSON.stringify({ type: "agent-games.preflight.v1" });
  const inboundSig = hmacHex(rawRequest, secret);
  const startedAt = performance.now();
  const signedRes = await fetch(endpointUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": `sha256=${inboundSig}`,
    },
    body: rawRequest,
  });
  const latencyMs = Math.round(performance.now() - startedAt);
  const rawResponse = await signedRes.text();
  assert.equal(signedRes.status, 200, `${label}: signed preflight must return HTTP 200`);

  const outboundSig = signedRes.headers.get("x-agent-games-signature");
  assert.equal(
    verifyOutboundHmac(rawResponse, outboundSig, secret),
    true,
    `${label}: outbound x-agent-games-signature failed constant-time verification`,
  );

  const parsed = JSON.parse(rawResponse) as Record<string, unknown>;
  assert.equal(parsed.ok, true, `${label}: preflight payload ok must be true`);
  assert.equal(parsed.protocolVersion, "v1", `${label}: protocolVersion must be v1`);
  return { status: signedRes.status, latencyMs };
}

export async function runLiveProductionSmoke(config: LiveSmokeConfig): Promise<void> {
  // 1. Verify .env-free clean working directory isolation
  const cwdEntries = fs.readdirSync(process.cwd());
  const envFiles = cwdEntries.filter((entry) => entry.startsWith(".env"));
  assert.equal(
    envFiles.length,
    0,
    "Live smoke must run from a directory with zero .env files",
  );
  assert.equal(
    Boolean(process.env.KURIER_API_KEY),
    false,
    "Client smoke environment must not carry KURIER_API_KEY",
  );

  // 2. Verify GET / serves compiled workbench HTML
  const rootRes = await fetch(`${config.baseUrl}/`);
  const rootHtml = await rootRes.text();
  assert.equal(rootRes.status, 200, "GET / must return HTTP 200");
  assert.equal(
    (rootRes.headers.get("content-type") ?? "").includes("text/html"),
    true,
    "GET / must serve text/html",
  );
  assert.equal(rootHtml.includes("ReserveRail"), true, "GET / HTML must mention ReserveRail");
  assert.equal(rootHtml.includes('id="root"'), true, "GET / HTML must mount #root");

  // 3. Verify GET /healthz & GET /agent human-readable docs
  const healthRes = await fetch(`${config.baseUrl}/healthz`);
  const healthJson = (await healthRes.json()) as Record<string, unknown>;
  assert.equal(healthRes.status, 200, "GET /healthz must return HTTP 200");
  assert.equal(healthJson.ok, true, "GET /healthz ok must be true");

  const docsRes = await fetch(`${config.baseUrl}/agent`);
  const docsJson = (await docsRes.json()) as Record<string, unknown>;
  assert.equal(docsRes.status, 200, "GET /agent must return HTTP 200 human-readable docs");
  assert.equal(docsJson.name, "ReserveRail", "GET /agent name must be ReserveRail");
  assert.equal(docsJson.vkHash, REGISTERED_VK_HASH, "GET /agent vkHash must match registered vkHash");

  // 4. Verify GET /api/demo/state assigns fresh Sandbox Scope in LIVE relayMode
  const stateRes = await fetch(`${config.baseUrl}/api/demo/state`);
  const stateJson = (await stateRes.json()) as {
    readonly sandboxId: string;
    readonly relayMode: string;
    readonly cfoView: { readonly balance: string; readonly payrollFloor: string; readonly epochCap: string };
    readonly auditorView: {
      readonly policyRoot: string;
      readonly genesisCommitment: string;
      readonly currentCommitment: string;
      readonly vkHash: string;
    };
  };
  assert.equal(stateRes.status, 200, "GET /api/demo/state must return HTTP 200");
  assert.match(stateJson.sandboxId, /^sbx_[0-9a-f]{12}$/, "sandboxId format mismatch");
  assert.equal(stateJson.relayMode, "LIVE", "Production server relayMode must be LIVE");
  assert.equal(stateJson.cfoView.balance, "100000", "Initial C_0 balance must be 100000");
  assert.equal(stateJson.auditorView.vkHash, REGISTERED_VK_HASH, "auditorView vkHash mismatch");
  assert.equal(
    stateJson.auditorView.currentCommitment,
    stateJson.auditorView.genesisCommitment,
    "Fresh sandbox must start at genesisCommitment C_0",
  );

  // 5. Verify signed POST /agent and POST /gatekeeper/agent preflight handshakes when secrets supplied
  let reserverailPreflight: { readonly status: number; readonly latencyMs: number } | null = null;
  if (config.reserverailHmacSecret !== undefined && config.reserverailHmacSecret.length > 0) {
    reserverailPreflight = await verifySignedPreflight(
      `${config.baseUrl}/agent`,
      config.reserverailHmacSecret,
      "ReserveRail /agent",
    );
  }

  let gatekeeperPreflight: { readonly status: number; readonly latencyMs: number } | null = null;
  if (config.gatekeeperHmacSecret !== undefined && config.gatekeeperHmacSecret.length > 0) {
    gatekeeperPreflight = await verifySignedPreflight(
      `${config.baseUrl}/gatekeeper/agent`,
      config.gatekeeperHmacSecret,
      "Gatekeeper /gatekeeper/agent",
    );
  }

  // 6. Optional live C_0 -> C_1 Groth16 Mainnet Finalized transition
  let finalizedSummary: Record<string, unknown> | null = null;
  if (config.runMainnet) {
    const invoiceId = `prod-smoke-${Date.now()}`;
    const proposeRes = await fetch(`${config.baseUrl}/api/demo/propose`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sandboxId: stateJson.sandboxId,
        recipient: "AWS",
        amount: "12000",
        epoch: "1",
        invoiceId,
        memo: "Production .env-free live smoke verification",
        mode: "LIVE",
      }),
    });
    const proposeJson = (await proposeRes.json()) as {
      readonly reserveRailResult: {
        readonly decision: string;
        readonly receipt?: TreasuryReceipt;
      };
    };
    assert.equal(proposeRes.status, 200, "POST /api/demo/propose must return HTTP 200");
    assert.equal(
      proposeJson.reserveRailResult.decision,
      "APPROVE",
      "Valid AWS 12,000 transition must be APPROVED",
    );
    assert.equal(
      proposeJson.reserveRailResult.receipt?.provenance.mode,
      "LIVE",
      "Production receipt provenance.mode must be LIVE",
    );

    const deadline = Date.now() + config.finalizeTimeoutMs;
    let settledReceipt: TreasuryReceipt | undefined;
    while (Date.now() < deadline) {
      const pollRes = await fetch(
        `${config.baseUrl}/api/demo/state?sandbox=${encodeURIComponent(stateJson.sandboxId)}`,
      );
      const pollJson = (await pollRes.json()) as {
        readonly receipts: readonly TreasuryReceipt[];
      };
      const candidate = pollJson.receipts[0];
      if (candidate !== undefined && candidate.provenance.status === "Finalized") {
        settledReceipt = candidate;
        break;
      }
      if (candidate !== undefined && candidate.provenance.status === "Failed") {
        throw new Error(
          `Live Kurier submission failed before Finalized (jobId=${candidate.provenance.jobId ?? "unknown"})`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 3_000));
    }

    assert.notEqual(
      settledReceipt,
      undefined,
      `Live receipt did not reach Finalized within ${config.finalizeTimeoutMs}ms`,
    );
    if (settledReceipt === undefined) {
      throw new Error("Unreachable");
    }

    assert.match(
      settledReceipt.provenance.txHash ?? "",
      /^0x[0-9a-f]{64}$/i,
      "Finalized txHash must be 32-byte hex",
    );
    assert.equal(
      (settledReceipt.provenance.txExplorerUrl ?? "").startsWith(
        "https://zkverify.subscan.io/extrinsic/0x",
      ),
      true,
      "txExplorerUrl must point to zkVerify Subscan extrinsic",
    );

    const proofValid = await verifyTransitionProof(
      settledReceipt.proof,
      settledReceipt.publicSignalsArray,
      VERIFICATION_KEY,
    );
    assert.equal(proofValid, true, "Client-side zero-trust Groth16 verification failed");

    const chainCheck = await verifyAuditChain(
      [settledReceipt],
      stateJson.auditorView.genesisCommitment,
      stateJson.auditorView.policyRoot,
      VERIFICATION_KEY,
    );
    assert.equal(chainCheck.valid, true, "Client-side verifyAuditChain failed on live receipt");

    finalizedSummary = {
      verifiedAt: new Date().toISOString(),
      baseUrl: config.baseUrl,
      sandboxId: stateJson.sandboxId,
      vkHash: REGISTERED_VK_HASH,
      genesisCommitment: stateJson.auditorView.genesisCommitment,
      newCommitment: settledReceipt.publicSignals.newCommitment,
      amount: settledReceipt.publicSignals.amount,
      epoch: settledReceipt.publicSignals.epoch,
      invoiceHash: settledReceipt.publicSignals.invoiceHash,
      mode: settledReceipt.provenance.mode,
      status: settledReceipt.provenance.status,
      jobId: settledReceipt.provenance.jobId,
      txHash: settledReceipt.provenance.txHash,
      blockHash: settledReceipt.provenance.blockHash,
      txExplorerUrl: settledReceipt.provenance.txExplorerUrl,
      clientGroth16Valid: proofValid,
      clientAuditChainValid: chainCheck.valid,
    };

    if (config.receiptOut !== undefined) {
      const resolvedOut = path.resolve(config.receiptOut);
      fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
      fs.writeFileSync(resolvedOut, `${JSON.stringify(finalizedSummary, null, 2)}\n`, "utf8");
    }
  }

  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      cwd: process.cwd(),
      baseUrl: config.baseUrl,
      relayMode: stateJson.relayMode,
      sandboxId: stateJson.sandboxId,
      reserverailPreflight,
      gatekeeperPreflight,
      finalizedMainnet: finalizedSummary,
    })}\n`,
  );
  process.exit(0);
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (invokedDirectly) {
  runLiveProductionSmoke(parseCliArgs(process.argv.slice(2))).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${JSON.stringify({ ok: false, error: message })}\n`);
    process.exit(1);
  });
}
