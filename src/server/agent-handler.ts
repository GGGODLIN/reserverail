import crypto from "node:crypto";
import type http from "node:http";
import { z } from "zod";
import { REGISTERED_VK_HASH } from "../generated/circuit-abi.ts";
import { parsePaymentIntent, parseStrictNonNegativeUint64 } from "../engine/intent-parser.ts";
import type { TreasuryLedgerService } from "../engine/ledger-service.ts";
import type { ReserveRailStore } from "../engine/sqlite-store.ts";

export interface AgentHandlerConfig {
  readonly store: ReserveRailStore;
  readonly service: TreasuryLedgerService;
  readonly hmacSecret?: string;
  readonly hmacSecretPrevious?: string;
  readonly softDeadlineMs?: number;
  readonly maritacaApiKey?: string;
  readonly amdTokenLabApiKey?: string;
  readonly llmFetchImpl?: typeof globalThis.fetch;
  readonly llmTimeoutMs?: number;
}

const AgentTaskSchema = z.object({
  type: z.string().optional(),
  kind: z.string().optional(),
  mode: z.string().optional(),
  taskId: z.string().min(1).max(128).optional(),
  memo: z.string().max(512).optional(),
  recipient: z.string().min(1).max(128).optional(),
  amount: z.union([z.number(), z.string()]).optional(),
  epoch: z.union([z.number(), z.string()]).optional(),
  invoiceId: z.string().min(1).max(128).optional(),
  challenge: z.unknown().optional(),
});

function computeHmacHex(raw: Buffer | string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

function constantTimeHexEquals(providedRaw: string, expectedHex: string): boolean {
  const clean = providedRaw.replace(/^sha256=/i, "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean) || clean.length !== expectedHex.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(clean, "hex"), Buffer.from(expectedHex, "hex"));
}

function verifyInboundSignature(
  rawBody: Buffer,
  headerValue: string | string[] | undefined,
  primarySecret: string,
  previousSecret?: string,
): boolean {
  const sig = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (typeof sig !== "string" || sig.trim().length === 0) {
    return false;
  }
  const primaryExpected = computeHmacHex(rawBody, primarySecret);
  if (constantTimeHexEquals(sig, primaryExpected)) {
    return true;
  }
  if (previousSecret !== undefined && previousSecret.trim().length > 0) {
    const prevExpected = computeHmacHex(rawBody, previousSecret.trim());
    if (constantTimeHexEquals(sig, prevExpected)) {
      return true;
    }
  }
  return false;
}

function sendSignedJson(
  res: http.ServerResponse,
  statusCode: number,
  bodyString: string,
  hmacSecret?: string,
): void {
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  };
  if (hmacSecret !== undefined && hmacSecret.length > 0) {
    headers["x-agent-games-signature"] = computeHmacHex(bodyString, hmacSecret);
  }
  res.writeHead(statusCode, headers);
  res.end(bodyString);
}

export function buildAgentDocsPayload(): Record<string, unknown> {
  return {
    name: "ReserveRail",
    description:
      "Verifiable multi-agent treasury spend rail backed by Circom 2.x Groth16 state-transition proofs on zkVerify Mainnet via Kurier.",
    protocolVersion: "v1",
    signatureHeader: "x-agent-games-signature",
    signatureAlgorithm: "HMAC-SHA256 (hex or sha256=<hex>) over exact raw request body bytes; outbound responses are signed with the same header.",
    preflightTypes: ["agent-games.preflight.v1", "preflight"],
    vkHash: REGISTERED_VK_HASH,
    endpoints: {
      health: "GET /healthz",
      agentDocs: "GET /agent",
      agentExecute: "POST /agent",
      demoState: "GET /api/demo/state?sandbox=<id>",
      demoPropose: "POST /api/demo/propose",
      demoAct: "POST /api/demo/act",
      demoReset: "POST /api/demo/reset",
      demoTamper: "POST /api/demo/tamper",
      demoVerifyChain: "POST /api/demo/verify-chain",
    },
    curlExample:
      'SIG=$(printf \'%s\' \'{"type":"agent-games.preflight.v1"}\' | openssl dgst -sha256 -hmac "$AGENT_GAMES_HMAC_SECRET" -hex | awk \'{print $2}\') && curl -sS -X POST https://reserverail.gggodlin.com/agent -H "content-type: application/json" -H "x-agent-games-signature: $SIG" -d \'{"type":"agent-games.preflight.v1"}\'',
  };
}

export class AgentEndpointHandler {
  private readonly config: AgentHandlerConfig;
  private readonly inFlightTasks = new Map<
    string,
    {
      readonly rawBodySha256: string;
      readonly promise: Promise<{ readonly statusCode: number; readonly bodyString: string }>;
    }
  >();

  public constructor(config: AgentHandlerConfig) {
    this.config = config;
  }

  public handleGet(res: http.ServerResponse): void {
    const payload = JSON.stringify(buildAgentDocsPayload(), null, 2);
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(payload);
  }

  public async handlePost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    rawBody: Buffer,
  ): Promise<void> {
    const secret = this.config.hmacSecret?.trim();
    if (secret === undefined || secret.length === 0) {
      sendSignedJson(
        res,
        503,
        JSON.stringify({
          ok: false,
          code: "AGENT_HMAC_UNCONFIGURED",
          error: "Agent HMAC secret is not configured on this server",
        }),
      );
      return;
    }

    const sigHeader = req.headers["x-agent-games-signature"];
    if (!verifyInboundSignature(rawBody, sigHeader, secret, this.config.hmacSecretPrevious)) {
      sendSignedJson(
        res,
        401,
        JSON.stringify({
          ok: false,
          code: "INVALID_SIGNATURE",
          error: "Missing or invalid x-agent-games-signature",
        }),
        secret,
      );
      return;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendSignedJson(
        res,
        400,
        JSON.stringify({
          ok: false,
          code: "INVALID_JSON",
          error: "Malformed JSON request body",
        }),
        secret,
      );
      return;
    }

    const validated = AgentTaskSchema.safeParse(parsedJson);
    if (!validated.success) {
      sendSignedJson(
        res,
        400,
        JSON.stringify({
          ok: false,
          code: "INVALID_PAYLOAD",
          error: "Request body failed schema validation",
        }),
        secret,
      );
      return;
    }

    const body = validated.data;

    // <50ms fast preflight handshake path
    const isPreflight =
      body.type === "agent-games.preflight.v1" ||
      body.type === "preflight" ||
      body.kind === "preflight" ||
      body.mode === "preflight";

    if (isPreflight) {
      const preflightResp = JSON.stringify({
        ok: true,
        protocolVersion: "v1",
        type: body.type ?? "agent-games.preflight.v1",
        vkHash: REGISTERED_VK_HASH,
      });
      sendSignedJson(res, 200, preflightResp, secret);
      return;
    }

    const taskId = body.taskId;
    if (taskId === undefined || taskId.trim().length === 0) {
      sendSignedJson(
        res,
        400,
        JSON.stringify({
          ok: false,
          code: "MISSING_TASK_ID",
          error: "Field taskId is required for non-preflight agent requests",
        }),
        secret,
      );
      return;
    }

    const rawBodySha256 = crypto.createHash("sha256").update(rawBody).digest("hex");

    // 1. Check persisted idempotency cache BEFORE invoiceHash / policy evaluation
    const existingIdem = this.config.store.getIdempotencyRecord(taskId);
    if (existingIdem !== null) {
      if (existingIdem.rawBodySha256 !== rawBodySha256) {
        sendSignedJson(
          res,
          409,
          JSON.stringify({
            ok: false,
            code: "TASK_ID_PAYLOAD_CONFLICT",
            error: "Conflicting payload submitted for an already-recorded taskId",
          }),
          secret,
        );
        return;
      }
      sendSignedJson(res, existingIdem.statusCode, existingIdem.responseJson, secret);
      return;
    }

    // 2. Coalesce concurrent identical in-flight taskId retries
    const existingFlight = this.inFlightTasks.get(taskId);
    if (existingFlight !== undefined) {
      if (existingFlight.rawBodySha256 !== rawBodySha256) {
        sendSignedJson(
          res,
          409,
          JSON.stringify({
            ok: false,
            code: "TASK_ID_PAYLOAD_CONFLICT",
            error: "Conflicting payload submitted while taskId is in flight",
          }),
          secret,
        );
        return;
      }
      const outcome = await existingFlight.promise;
      sendSignedJson(res, outcome.statusCode, outcome.bodyString, secret);
      return;
    }

    const executionPromise = this.executeTaskWithDeadline(taskId, rawBodySha256, body);
    this.inFlightTasks.set(taskId, { rawBodySha256, promise: executionPromise });
    try {
      const outcome = await executionPromise;
      sendSignedJson(res, outcome.statusCode, outcome.bodyString, secret);
    } finally {
      this.inFlightTasks.delete(taskId);
    }
  }

  private async executeTaskWithDeadline(
    taskId: string,
    rawBodySha256: string,
    body: z.infer<typeof AgentTaskSchema>,
  ): Promise<{ readonly statusCode: number; readonly bodyString: string }> {
    const softDeadlineMs = this.config.softDeadlineMs ?? 45_000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), softDeadlineMs);
    timer.unref?.();

    const finish = (
      statusCode: number,
      payload: Record<string, unknown>,
    ): { readonly statusCode: number; readonly bodyString: string } => {
      const bodyString = JSON.stringify(payload);
      if (statusCode < 500) {
        this.config.store.saveIdempotencyRecord({
          taskId,
          rawBodySha256,
          statusCode,
          responseJson: bodyString,
          createdAt: Date.now(),
        });
      }
      return { statusCode, bodyString };
    };

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
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : "Invalid numeric field";
      return finish(400, {
        ok: false,
        approved: false,
        code: "INVALID_AMOUNT_OR_EPOCH",
        error: msg,
      });
    }

    try {
      const sbx = this.config.store.getOrCreateSandbox("competition", "competition");
      const allowlist = sbx.allowlist.map((v) => ({
        name: v.name,
        address: v.address,
        recipientField: BigInt(v.recipientField),
      }));

      const intent = await parsePaymentIntent(
        {
          memo: body.memo,
          recipient: body.recipient,
          amount: body.amount,
          epoch: body.epoch,
          invoiceId: body.invoiceId,
        },
        {
          store: this.config.store,
          allowlist,
          maritacaApiKey: this.config.maritacaApiKey,
          amdTokenLabApiKey: this.config.amdTokenLabApiKey,
          llmFetchImpl: this.config.llmFetchImpl,
          llmTimeoutMs: this.config.llmTimeoutMs,
          clientIp: "agent",
          defaultEpoch: BigInt(sbx.currentEpoch),
        },
      );

      const racePromise = this.config.service.executeTransition({
        sandboxId: "competition",
        scopeType: "competition",
        intent,
        mode: "LIVE",
        priority: 0,
        signal: controller.signal,
      });

      const deadlinePromise = new Promise<never>((_, reject) => {
        const onAbort = () => reject(new Error("SOFT_DEADLINE_EXCEEDED"));
        if (controller.signal.aborted) {
          onAbort();
          return;
        }
        controller.signal.addEventListener("abort", onAbort, { once: true });
      });

      const result = await Promise.race([racePromise, deadlinePromise]);

      if (result.httpStatus >= 500) {
        return finish(result.httpStatus, {
          ok: false,
          approved: false,
          taskId,
          reasonCode: result.reasonCode,
          error: result.errorMessage ?? "Transient backend failure",
        });
      }

      if (!result.approved) {
        return finish(200, {
          ok: true,
          decision: "REJECT",
          approved: false,
          taskId,
          reasonCode: result.reasonCode,
          error: result.errorMessage ?? result.reasonCode,
        });
      }

      return finish(200, {
        ok: true,
        decision: "APPROVE",
        approved: true,
        taskId,
        reasonCode: result.reasonCode,
        provenanceMode: result.provenanceMode,
        receipt: result.receipt,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === "SOFT_DEADLINE_EXCEEDED" || controller.signal.aborted) {
        this.config.store.recordDiagnosticEvent(
          "deadline_abort",
          `POST /agent taskId=${taskId} exceeded ${softDeadlineMs}ms soft deadline`,
        );
        return finish(504, {
          ok: false,
          approved: false,
          taskId,
          reasonCode: "DEADLINE_EXCEEDED",
          error: "Agent soft deadline exceeded before completion",
        });
      }
      return finish(400, {
        ok: false,
        approved: false,
        taskId,
        reasonCode: "INVALID_INTENT",
        error: msg,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
