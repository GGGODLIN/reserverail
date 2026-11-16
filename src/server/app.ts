import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { verifyTransitionProof } from "../circuit/prover.ts";
import { REGISTERED_VK_HASH, VERIFICATION_KEY } from "../generated/circuit-abi.ts";
import { KurierClient } from "../kurier/kurier-client.ts";
import { Groth16ProofSchema, verifyAuditChain } from "../engine/audit-chain.ts";
import {
  MAX_MEMO_CHARS,
  NaiveSingleCapExecutor,
  parsePaymentIntent,
  parseStrictNonNegativeUint64,
} from "../engine/intent-parser.ts";
import type { ProposedPaymentIntent } from "../engine/intent-parser.ts";
import { TreasuryLedgerService } from "../engine/ledger-service.ts";
import type { ExecuteTransitionResult } from "../engine/ledger-service.ts";
import { ProvingSemaphore } from "../engine/proving-semaphore.ts";
import { loadBaselineMainnetCassette } from "../engine/replay-cassette.ts";
import { ReserveRailStore } from "../engine/sqlite-store.ts";
import type { NaiveLedgerEntry } from "../engine/sqlite-store.ts";
import { AgentEndpointHandler } from "./agent-handler.ts";

const SMALL_BODY_MAX_BYTES = 16 * 1024;

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "dist", "web");

const WORKBENCH_CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
};

export interface ReserveRailServerOptions {
  readonly dbPath?: string;
  readonly maxDemoSandboxes?: number;
  readonly maxProvingConcurrency?: number;
  readonly kurierApiKey?: string;
  readonly kurierClient?: KurierClient | null;
  readonly agentHmacSecret?: string;
  readonly agentHmacSecretPrevious?: string;
  readonly agentSoftDeadlineMs?: number;
  readonly submitMaxRetries?: number;
  readonly submitRetryDelayMs?: number;
  readonly maritacaApiKey?: string;
  readonly amdTokenLabApiKey?: string;
  readonly llmFetchImpl?: typeof globalThis.fetch;
  readonly llmTimeoutMs?: number;
}

export interface ReserveRailServerHandle {
  readonly httpServer: http.Server;
  readonly store: ReserveRailStore;
  readonly service: TreasuryLedgerService;
  readonly semaphore: ProvingSemaphore;
  readonly port: number;
  readonly url: string;
  listen(port?: number, host?: string): Promise<void>;
  close(): Promise<void>;
}

const ProposeBodySchema = z
  .object({
    sandboxId: z.string().optional(),
    actId: z.string().max(64).optional(),
    memo: z.string().max(MAX_MEMO_CHARS).optional(),
    recipient: z.string().min(1).max(128).optional(),
    amount: z.union([z.number(), z.string()]).optional(),
    epoch: z.union([z.number(), z.string()]).optional(),
    invoiceId: z.string().min(1).max(128).optional(),
    mode: z.enum(["LIVE", "DETERMINISTIC_REPLAY"]).optional(),
  })
  .strict();

const ActBodySchema = z
  .object({
    sandboxId: z.string().optional(),
    actId: z.enum(["act1_injection", "act1_legit", "act2_structuring", "act3_concurrency"]),
    mode: z.enum(["LIVE", "DETERMINISTIC_REPLAY"]).optional(),
  })
  .strict();

const ResetBodySchema = z
  .object({
    sandboxId: z.string().min(3).max(64),
    balance: z.union([z.number(), z.string()]).optional(),
    payrollFloor: z.union([z.number(), z.string()]).optional(),
    epochCap: z.union([z.number(), z.string()]).optional(),
    naiveSingleCap: z.union([z.number(), z.string()]).optional(),
    epoch: z.union([z.number(), z.string()]).optional(),
  })
  .strict();

const TamperBodySchema = z
  .object({
    useBaselineCassette: z.boolean().optional(),
    tamperedAmount: z.string().regex(/^(0|[1-9][0-9]*)$/).optional(),
    receipt: z
      .object({
        proof: Groth16ProofSchema,
        publicSignalsArray: z.array(z.string()).length(7).optional(),
        publicSignals: z
          .object({
            policyRoot: z.string(),
            prevCommitment: z.string(),
            newCommitment: z.string(),
            recipient: z.string(),
            amount: z.string(),
            epoch: z.string(),
            invoiceHash: z.string(),
          })
          .optional(),
      })
      .optional(),
  })
  .strict();

class PayloadTooLargeError extends Error {
  public constructor(maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.name = "PayloadTooLargeError";
  }
}

async function readRawBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    req.on("data", (chunk: Buffer) => {
      if (settled) {
        return;
      }
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        chunks.length = 0;
        req.resume();
        reject(new PayloadTooLargeError(maxBytes));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });

    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

function sendJson(
  res: http.ServerResponse,
  statusCode: number,
  data: unknown,
  closeConnection = false,
): void {
  const text = JSON.stringify(data);
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,x-agent-games-signature",
  };
  if (closeConnection) {
    headers.connection = "close";
  }
  res.writeHead(statusCode, headers);
  res.end(text);
}

// Serves the built workbench (index.html and dist/web assets) without ever reading outside webRoot.
async function serveWorkbenchFile(res: http.ServerResponse, pathname: string, webRoot: string): Promise<boolean> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return false;
  }
  const target = path.resolve(webRoot, decoded === "/" ? "index.html" : `.${decoded}`);
  // Encoded "..", doubled slashes and absolute segments all resolve outside the root and fall through to 404.
  if (!target.startsWith(`${webRoot}${path.sep}`)) {
    return false;
  }
  const contentType = WORKBENCH_CONTENT_TYPES[path.extname(target).toLowerCase()];
  if (contentType === undefined) {
    return false;
  }
  let body: Buffer;
  try {
    body = await fs.readFile(target);
  } catch {
    return false;
  }
  res.writeHead(200, {
    "content-type": contentType,
    "content-length": String(body.length),
    "cache-control": "no-cache",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
  return true;
}

function serializeIntent(intent: ProposedPaymentIntent): Record<string, unknown> {
  return {
    vendorName: intent.vendorName,
    recipientAddress: intent.recipientAddress,
    recipientField: intent.recipientField.toString(10),
    amount: intent.amount.toString(10),
    epoch: intent.epoch.toString(10),
    invoiceId: intent.invoiceId,
    invoiceIdField: intent.invoiceIdField.toString(10),
    memo: intent.memo,
    parserSource: intent.parserSource,
    llmTokensUsed: intent.llmTokensUsed,
  };
}

function resolveSandboxId(raw?: string | null): { readonly ok: true; readonly sandboxId: string } | { readonly ok: false; readonly status: number; readonly error: string } {
  const candidate = raw?.trim() ?? "";
  if (candidate.length === 0) {
    return { ok: true, sandboxId: `sbx_${crypto.randomBytes(6).toString("hex")}` };
  }
  if (candidate === "competition") {
    return {
      ok: false,
      status: 403,
      error: "Public demo routes cannot access the signed competition scope",
    };
  }
  if (!/^[a-zA-Z0-9_-]{3,64}$/.test(candidate)) {
    return {
      ok: false,
      status: 400,
      error: "Invalid sandboxId format (must match ^[a-zA-Z0-9_-]{3,64}$)",
    };
  }
  return { ok: true, sandboxId: candidate };
}

async function buildDemoStateResponse(
  store: ReserveRailStore,
  service: TreasuryLedgerService,
  sandboxId: string,
  relayMode: "LIVE" | "DETERMINISTIC_REPLAY",
): Promise<Record<string, unknown>> {
  const sbx = store.getOrCreateSandbox(sandboxId, "demo");
  const receipts = store.getReceipts(sandboxId);
  const naiveLedger = store.getNaiveEntries(sandboxId);
  const historicalLinks = store.getHistoricalMainnetLinks(sandboxId);
  const auditChain = await verifyAuditChain(
    receipts,
    sbx.genesisCommitment,
    sbx.policyRoot,
    VERIFICATION_KEY,
  );

  const baselineEntry = {
    id: "gate01-baseline",
    sandboxId,
    txHash: service.cassette.validTransition.txHash,
    txExplorerUrl: service.cassette.validTransition.txExplorerUrl,
    jobId: service.cassette.validTransition.jobId,
    amount: service.cassette.validTransition.publicSignals.amount,
    createdAt: service.cassette.validTransition.settledAt,
  };

  const mainnetExplorerLinks =
    historicalLinks.length > 0 ? [...historicalLinks, baselineEntry] : [baselineEntry];

  return {
    sandboxId: sbx.sandboxId,
    relayMode,
    cfoView: {
      balance: sbx.balance,
      payrollFloor: sbx.payrollFloor,
      epochCap: sbx.epochCap,
      spentSoFar: sbx.spentSoFar,
      epoch: sbx.currentEpoch,
      naiveSingleCap: sbx.naiveSingleCap,
      naiveSpentTotal: sbx.naiveSpentTotal,
      naiveEpochSpent: sbx.naiveEpochSpent,
      allowlist: sbx.allowlist,
    },
    auditorView: {
      policyRoot: sbx.policyRoot,
      genesisCommitment: sbx.genesisCommitment,
      currentCommitment: sbx.currentCommitment,
      vkHash: REGISTERED_VK_HASH,
    },
    naiveLedger,
    receipts,
    mainnetExplorerLinks,
    auditChain,
    baselineMainnetCassette: {
      vkHash: service.cassette.vkHash,
      jobId: service.cassette.validTransition.jobId,
      txHash: service.cassette.validTransition.txHash,
      blockHash: service.cassette.validTransition.blockHash,
      txExplorerUrl: service.cassette.validTransition.txExplorerUrl,
      status: service.cassette.validTransition.status,
    },
  };
}

export async function createReserveRailServer(
  options: ReserveRailServerOptions = {},
): Promise<ReserveRailServerHandle> {
  const dbPath = options.dbPath ?? process.env.RESERVERAIL_DB_PATH ?? "reserverail.db";
  const kurierKey = options.kurierApiKey ?? process.env.KURIER_API_KEY;
  const trimmedKurierKey = kurierKey?.trim() ?? "";

  const store = ReserveRailStore.open(dbPath, {
    maxDemoSandboxes: options.maxDemoSandboxes ?? 200,
    scrubKey: trimmedKurierKey.length > 0 ? trimmedKurierKey : undefined,
  });

  const kurierClient =
    options.kurierClient !== undefined
      ? options.kurierClient
      : trimmedKurierKey.length > 0
        ? new KurierClient({
            apiKey: trimmedKurierKey,
            onLog: (entry) => {
              if (entry.level === "error") {
                store.recordDiagnosticEvent("kurier_error", entry.message);
              }
            },
          })
        : null;
  const relayMode = kurierClient !== null ? "LIVE" : "DETERMINISTIC_REPLAY";

  const semaphore = new ProvingSemaphore(options.maxProvingConcurrency ?? 2);
  const cassette = loadBaselineMainnetCassette();

  // Warm up bn128 curve worker once at startup and validate baseline cassette
  await verifyTransitionProof(
    cassette.validTransition.proof,
    cassette.validTransition.publicSignalsArray,
    VERIFICATION_KEY,
  );

  const service = new TreasuryLedgerService({
    store,
    semaphore,
    kurierClient,
    cassette,
    submitMaxRetries: options.submitMaxRetries,
    submitRetryDelayMs: options.submitRetryDelayMs,
  });

  const naiveExecutor = new NaiveSingleCapExecutor();

  const maritacaKey = options.maritacaApiKey ?? process.env.MARITACA_API_KEY;
  const amdKey = options.amdTokenLabApiKey ?? process.env.AMD_TOKEN_LAB_API_KEY;

  const agentHandler = new AgentEndpointHandler({
    store,
    service,
    hmacSecret: options.agentHmacSecret ?? process.env.AGENT_GAMES_HMAC_SECRET,
    hmacSecretPrevious:
      options.agentHmacSecretPrevious ?? process.env.AGENT_GAMES_HMAC_SECRET_PREVIOUS,
    softDeadlineMs: options.agentSoftDeadlineMs ?? 45_000,
    maritacaApiKey: maritacaKey,
    amdTokenLabApiKey: amdKey,
    llmFetchImpl: options.llmFetchImpl,
    llmTimeoutMs: options.llmTimeoutMs,
  });

  const runSingleDemoStep = async (params: {
    readonly sandboxId: string;
    readonly rawInput: {
      readonly actId?: string;
      readonly memo?: string;
      readonly recipient?: string;
      readonly amount?: number | string;
      readonly epoch?: number | string;
      readonly invoiceId?: string;
    };
    readonly mode?: "LIVE" | "DETERMINISTIC_REPLAY";
    readonly clientIp: string;
  }): Promise<{
    readonly intent: ProposedPaymentIntent;
    readonly naiveResult: NaiveLedgerEntry;
    readonly reserveRailResult: ExecuteTransitionResult;
  }> => {
    const sbx = store.getOrCreateSandbox(params.sandboxId, "demo");
    const allowlist = sbx.allowlist.map((v) => ({
      name: v.name,
      address: v.address,
      recipientField: BigInt(v.recipientField),
    }));

    const intent = await parsePaymentIntent(params.rawInput, {
      store,
      allowlist,
      maritacaApiKey: maritacaKey,
      amdTokenLabApiKey: amdKey,
      llmFetchImpl: options.llmFetchImpl,
      llmTimeoutMs: options.llmTimeoutMs,
      clientIp: params.clientIp,
    });

    const naiveResult = naiveExecutor.execute(store, params.sandboxId, intent);
    const reserveRailResult = await service.executeTransition({
      sandboxId: params.sandboxId,
      scopeType: "demo",
      intent,
      mode: params.mode ?? (kurierClient !== null ? "LIVE" : "DETERMINISTIC_REPLAY"),
      priority: 1,
    });

    return { intent, naiveResult, reserveRailResult };
  };

  const httpServer = http.createServer(async (req, res) => {
    try {
      const urlObj = new URL(req.url ?? "/", "http://localhost");
      const pathname = urlObj.pathname;
      const method = (req.method ?? "GET").toUpperCase();
      const clientIp = req.socket.remoteAddress ?? "local";

      if (method === "OPTIONS") {
        sendJson(res, 204, {});
        return;
      }

      if (method === "GET" && pathname === "/healthz") {
        const stats = semaphore.getStats();
        sendJson(res, 200, {
          ok: true,
          vkHash: REGISTERED_VK_HASH,
          activeProves: stats.activeProves,
          maxConcurrency: stats.maxConcurrency,
          queueDepth: stats.queuedHigh + stats.queuedNormal,
        });
        return;
      }

      if (pathname === "/agent") {
        if (method === "GET") {
          agentHandler.handleGet(res);
          return;
        }
        if (method === "POST") {
          let rawBody: Buffer;
          try {
            rawBody = await readRawBody(req, SMALL_BODY_MAX_BYTES);
          } catch (err: unknown) {
            if (err instanceof PayloadTooLargeError) {
              sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message }, true);
              return;
            }
            sendJson(res, 400, { ok: false, code: "READ_ERROR", error: "Unable to read request body" });
            return;
          }
          await agentHandler.handlePost(req, res, rawBody);
          return;
        }
        sendJson(res, 405, { ok: false, error: "Method not allowed" });
        return;
      }

      if (method === "GET" && pathname === "/api/demo/state") {
        const sbxResolved = resolveSandboxId(urlObj.searchParams.get("sandbox"));
        if (!sbxResolved.ok) {
          sendJson(res, sbxResolved.status, { ok: false, error: sbxResolved.error });
          return;
        }
        const statePayload = await buildDemoStateResponse(store, service, sbxResolved.sandboxId, relayMode);
        sendJson(res, 200, statePayload);
        return;
      }

      if (method === "POST" && pathname === "/api/demo/propose") {
        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, SMALL_BODY_MAX_BYTES);
        } catch (err: unknown) {
          if (err instanceof PayloadTooLargeError) {
            sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message });
            return;
          }
          sendJson(res, 400, { ok: false, error: "Unable to read request body" });
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, code: "INVALID_JSON", error: "Malformed JSON body" });
          return;
        }

        const validated = ProposeBodySchema.safeParse(parsed);
        if (!validated.success) {
          sendJson(res, 400, {
            ok: false,
            code: "INVALID_BODY",
            error: "Request body failed validation",
            issues: validated.error.issues.map((i) => i.message),
          });
          return;
        }

        const body = validated.data;
        const sbxResolved = resolveSandboxId(body.sandboxId);
        if (!sbxResolved.ok) {
          sendJson(res, sbxResolved.status, { ok: false, error: sbxResolved.error });
          return;
        }

        try {
          if (body.amount !== undefined) {
            parseStrictNonNegativeUint64(body.amount, "amount");
          }
          if (body.epoch !== undefined) {
            const ep = parseStrictNonNegativeUint64(body.epoch, "epoch");
            if (ep === 0n) {
              throw new RangeError('Field "epoch" must be >= 1');
            }
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "Invalid numeric parameter";
          sendJson(res, 400, { ok: false, code: "INVALID_NUMERIC_INPUT", error: msg });
          return;
        }

        try {
          const stepRes = await runSingleDemoStep({
            sandboxId: sbxResolved.sandboxId,
            rawInput: {
              actId: body.actId,
              memo: body.memo,
              recipient: body.recipient,
              amount: body.amount,
              epoch: body.epoch,
              invoiceId: body.invoiceId,
            },
            mode: body.mode,
            clientIp,
          });
          const statePayload = await buildDemoStateResponse(store, service, sbxResolved.sandboxId, relayMode);
          sendJson(res, 200, {
            ok: true,
            sandboxId: sbxResolved.sandboxId,
            intent: serializeIntent(stepRes.intent),
            naiveResult: stepRes.naiveResult,
            reserveRailResult: stepRes.reserveRailResult,
            auditChainStatus: statePayload.auditChain,
            state: statePayload,
          });
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "Failed to process proposal";
          sendJson(res, 400, { ok: false, code: "PROPOSAL_ERROR", error: msg });
        }
        return;
      }

      if (method === "POST" && pathname === "/api/demo/act") {
        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, SMALL_BODY_MAX_BYTES);
        } catch (err: unknown) {
          if (err instanceof PayloadTooLargeError) {
            sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message });
            return;
          }
          sendJson(res, 400, { ok: false, error: "Unable to read request body" });
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, code: "INVALID_JSON", error: "Malformed JSON body" });
          return;
        }

        const validated = ActBodySchema.safeParse(parsed);
        if (!validated.success) {
          sendJson(res, 400, { ok: false, code: "INVALID_BODY", error: "Invalid act request" });
          return;
        }

        const sbxResolved = resolveSandboxId(validated.data.sandboxId);
        if (!sbxResolved.ok) {
          sendJson(res, sbxResolved.status, { ok: false, error: sbxResolved.error });
          return;
        }
        const sandboxId = sbxResolved.sandboxId;
        const mode = validated.data.mode;
        const actId = validated.data.actId;

        if (actId === "act1_injection" || actId === "act1_legit") {
          store.resetSandbox(sandboxId, {
            balance: 100_000n,
            payrollFloor: 60_000n,
            epochCap: 50_000n,
            naiveSingleCap: 15_000n,
            epoch: 1n,
          });
          const step = await runSingleDemoStep({
            sandboxId,
            rawInput: { actId, invoiceId: `${actId}-${crypto.randomUUID().slice(0, 8)}` },
            mode,
            clientIp,
          });
          const statePayload = await buildDemoStateResponse(store, service, sandboxId, relayMode);
          sendJson(res, 200, {
            ok: true,
            actId,
            sandboxId,
            steps: [
              {
                intent: serializeIntent(step.intent),
                naiveResult: step.naiveResult,
                reserveRailResult: step.reserveRailResult,
              },
            ],
            auditChain: statePayload.auditChain,
            state: statePayload,
          });
          return;
        }

        if (actId === "act2_structuring") {
          store.resetSandbox(sandboxId, {
            balance: 100_000n,
            payrollFloor: 55_000n,
            epochCap: 30_000n,
            naiveSingleCap: 15_000n,
            epoch: 1n,
          });
          const steps = [];
          for (let shot = 1; shot <= 3; shot += 1) {
            const step = await runSingleDemoStep({
              sandboxId,
              rawInput: {
                recipient: "Stripe",
                amount: 12_000,
                epoch: 1,
                memo: `Structuring batch shot ${shot}/3 to Stripe for $12,000`,
                invoiceId: `act2-shot-${shot}-${crypto.randomUUID().slice(0, 8)}`,
              },
              mode,
              clientIp,
            });
            steps.push({
              intent: serializeIntent(step.intent),
              naiveResult: step.naiveResult,
              reserveRailResult: step.reserveRailResult,
            });
          }
          const statePayload = await buildDemoStateResponse(store, service, sandboxId, relayMode);
          sendJson(res, 200, {
            ok: true,
            actId,
            sandboxId,
            steps,
            auditChain: statePayload.auditChain,
            state: statePayload,
          });
          return;
        }

        // act3_concurrency: simultaneous Promise.all two-agent race (2 x 25,000)
        store.resetSandbox(sandboxId, {
          balance: 100_000n,
          payrollFloor: 60_000n,
          epochCap: 50_000n,
          naiveSingleCap: 30_000n,
          epoch: 1n,
        });
        const sbx = store.getSandboxSnapshot(sandboxId);
        const allowlist = sbx.allowlist.map((v) => ({
          name: v.name,
          address: v.address,
          recipientField: BigInt(v.recipientField),
        }));

        const [intentA, intentB] = await Promise.all([
          parsePaymentIntent(
            {
              recipient: "AWS",
              amount: 25_000,
              epoch: 1,
              invoiceId: `act3-agentA-${crypto.randomUUID().slice(0, 8)}`,
            },
            { store, allowlist },
          ),
          parsePaymentIntent(
            {
              recipient: "Anthropic",
              amount: 25_000,
              epoch: 1,
              invoiceId: `act3-agentB-${crypto.randomUUID().slice(0, 8)}`,
            },
            { store, allowlist },
          ),
        ]);

        const naiveA = naiveExecutor.execute(store, sandboxId, intentA);
        const naiveB = naiveExecutor.execute(store, sandboxId, intentB);

        const effectiveMode = mode ?? (kurierClient !== null ? "LIVE" : "DETERMINISTIC_REPLAY");
        const [rrA, rrB] = await Promise.all([
          service.executeTransition({
            sandboxId,
            scopeType: "demo",
            intent: intentA,
            mode: effectiveMode,
            priority: 1,
          }),
          service.executeTransition({
            sandboxId,
            scopeType: "demo",
            intent: intentB,
            mode: effectiveMode,
            priority: 1,
          }),
        ]);

        const statePayload = await buildDemoStateResponse(store, service, sandboxId, relayMode);
        sendJson(res, 200, {
          ok: true,
          actId,
          sandboxId,
          steps: [
            {
              intent: serializeIntent(intentA),
              naiveResult: naiveA,
              reserveRailResult: rrA,
            },
            {
              intent: serializeIntent(intentB),
              naiveResult: naiveB,
              reserveRailResult: rrB,
            },
          ],
          auditChain: statePayload.auditChain,
          state: statePayload,
        });
        return;
      }

      if (method === "POST" && pathname === "/api/demo/reset") {
        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, SMALL_BODY_MAX_BYTES);
        } catch (err: unknown) {
          if (err instanceof PayloadTooLargeError) {
            sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message });
            return;
          }
          sendJson(res, 400, { ok: false, error: "Unable to read request body" });
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, code: "INVALID_JSON", error: "Malformed JSON body" });
          return;
        }

        const validated = ResetBodySchema.safeParse(parsed);
        if (!validated.success) {
          sendJson(res, 400, { ok: false, code: "INVALID_BODY", error: "Invalid reset payload" });
          return;
        }

        const sbxResolved = resolveSandboxId(validated.data.sandboxId);
        if (!sbxResolved.ok) {
          sendJson(res, sbxResolved.status, { ok: false, error: sbxResolved.error });
          return;
        }

        try {
          const d = validated.data;
          const balance = d.balance !== undefined ? parseStrictNonNegativeUint64(d.balance, "balance") : undefined;
          const payrollFloor =
            d.payrollFloor !== undefined ? parseStrictNonNegativeUint64(d.payrollFloor, "payrollFloor") : undefined;
          const epochCap = d.epochCap !== undefined ? parseStrictNonNegativeUint64(d.epochCap, "epochCap") : undefined;
          const naiveSingleCap =
            d.naiveSingleCap !== undefined ? parseStrictNonNegativeUint64(d.naiveSingleCap, "naiveSingleCap") : undefined;
          const epoch = d.epoch !== undefined ? parseStrictNonNegativeUint64(d.epoch, "epoch") : undefined;
          if (epoch !== undefined && epoch === 0n) {
            throw new RangeError('Field "epoch" must be >= 1');
          }
          if ((payrollFloor ?? 60_000n) > (balance ?? 100_000n)) {
            throw new RangeError("payrollFloor cannot exceed balance");
          }
          store.resetSandbox(
            sbxResolved.sandboxId,
            { balance, payrollFloor, epochCap, naiveSingleCap, epoch },
            "demo",
          );
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "Invalid policy parameters";
          sendJson(res, 400, { ok: false, code: "INVALID_POLICY_CONFIG", error: msg });
          return;
        }

        const statePayload = await buildDemoStateResponse(store, service, sbxResolved.sandboxId, relayMode);
        sendJson(res, 200, { ok: true, state: statePayload });
        return;
      }

      if (method === "POST" && pathname === "/api/demo/tamper") {
        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, 262_144);
        } catch (err: unknown) {
          if (err instanceof PayloadTooLargeError) {
            sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message }, true);
            return;
          }
          sendJson(res, 400, { ok: false, error: "Unable to read request body" });
          return;
        }

        let parsed: unknown = {};
        if (rawBody.length > 0) {
          try {
            parsed = JSON.parse(rawBody.toString("utf8"));
          } catch {
            sendJson(res, 400, { ok: false, code: "INVALID_JSON", error: "Malformed JSON body" });
            return;
          }
        }

        const validated = TamperBodySchema.safeParse(parsed);
        if (!validated.success) {
          sendJson(res, 400, { ok: false, code: "INVALID_BODY", error: "Invalid tamper payload" });
          return;
        }

        const r = validated.data.receipt;
        const signalsArr =
          r?.publicSignalsArray ??
          (r?.publicSignals
            ? [
                r.publicSignals.policyRoot,
                r.publicSignals.prevCommitment,
                r.publicSignals.newCommitment,
                r.publicSignals.recipient,
                r.publicSignals.amount,
                r.publicSignals.epoch,
                r.publicSignals.invoiceHash,
              ]
            : undefined);

        const tamperRes = await service.tamperCheck({
          proof: r?.proof,
          publicSignalsArray: signalsArr,
          tamperedAmount: validated.data.tamperedAmount,
        });
        sendJson(res, 200, tamperRes);
        return;
      }

      if (method === "POST" && pathname === "/api/demo/verify-chain") {
        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, 262_144);
        } catch (err: unknown) {
          if (err instanceof PayloadTooLargeError) {
            sendJson(res, 413, { ok: false, code: "PAYLOAD_TOO_LARGE", error: err.message }, true);
            return;
          }
          sendJson(res, 400, { ok: false, error: "Unable to read request body" });
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, code: "INVALID_JSON", error: "Malformed JSON body" });
          return;
        }

        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          sendJson(res, 400, { ok: false, code: "INVALID_BODY", error: "Invalid verify-chain payload" });
          return;
        }

        const body = parsed as Record<string, unknown>;
        if (typeof body.sandboxId === "string") {
          const sbxResolved = resolveSandboxId(body.sandboxId);
          if (!sbxResolved.ok) {
            sendJson(res, sbxResolved.status, { ok: false, error: sbxResolved.error });
            return;
          }
          const sbx = store.getOrCreateSandbox(sbxResolved.sandboxId, "demo");
          const receipts = store.getReceipts(sbxResolved.sandboxId);
          const verifyRes = await verifyAuditChain(
            receipts,
            sbx.genesisCommitment,
            sbx.policyRoot,
            VERIFICATION_KEY,
          );
          sendJson(res, 200, verifyRes);
          return;
        }

        if (
          !Array.isArray(body.receipts) ||
          typeof body.genesisCommitment !== "string" ||
          typeof body.policyRoot !== "string"
        ) {
          sendJson(res, 400, {
            ok: false,
            code: "MISSING_FIELDS",
            error: "Provide either sandboxId or { receipts, genesisCommitment, policyRoot }",
          });
          return;
        }

        try {
          const verifyRes = await verifyAuditChain(
            body.receipts,
            body.genesisCommitment,
            body.policyRoot,
            VERIFICATION_KEY,
          );
          sendJson(res, 200, verifyRes);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "Chain verification error";
          sendJson(res, 400, { ok: false, code: "VERIFY_ERROR", error: msg });
        }
        return;
      }

      if (method === "GET" && (await serveWorkbenchFile(res, pathname, WEB_ROOT))) {
        return;
      }

      sendJson(res, 404, { ok: false, error: "Not found" });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Internal server error";
      sendJson(res, 500, { ok: false, code: "INTERNAL_ERROR", error: msg });
    }
  });

  let boundPort = 0;

  return {
    httpServer,
    store,
    service,
    semaphore,
    get port(): number {
      return boundPort;
    },
    get url(): string {
      return `http://127.0.0.1:${boundPort}`;
    },
    async listen(port = 0, host = "127.0.0.1"): Promise<void> {
      await new Promise<void>((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(port, host, () => {
          httpServer.off("error", reject);
          const addr = httpServer.address() as AddressInfo | null;
          boundPort = addr?.port ?? port;
          resolve();
        });
      });
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      });
      await service.close();
      store.close();
    },
  };
}
