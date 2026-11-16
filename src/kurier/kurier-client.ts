import WebSocket from "ws";
import type { Groth16Proof, Groth16VerificationKey } from "snarkjs";

const DEFAULT_KURIER_API_URL = "https://api.kurier.xyz/api/v1";
const DEFAULT_KURIER_WS_URL = "wss://api.kurier.xyz/api/v1/ws";
const DEFAULT_WS_CONNECT_TIMEOUT_MS = 5_000;
const DEFAULT_POLL_BASE_DELAY_MS = 1_500;
const DEFAULT_POLL_MAX_DELAY_MS = 8_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const REDACTED_MARKER = "[REDACTED_KURIER_KEY]";

export interface KurierLogEntry {
  readonly level: "info" | "warn" | "error";
  readonly event: string;
  readonly message: string;
  readonly jobId?: string;
  readonly status?: string;
}

export interface KurierSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: (() => void) | null;
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onclose: ((event: { readonly code?: number; readonly reason?: string }) => void) | null;
}

export interface KurierClientOptions {
  readonly apiKey: string;
  readonly apiBaseUrl?: string;
  readonly wsUrl?: string;
  readonly fetchImpl?: typeof globalThis.fetch;
  readonly createWebSocket?: (url: string) => KurierSocketLike;
  readonly onLog?: (entry: KurierLogEntry) => void;
  readonly wsRotationIntervalMs?: number;
  readonly wsPingIntervalMs?: number;
  readonly wsConnectTimeoutMs?: number;
  readonly pollBaseDelayMs?: number;
  readonly pollMaxDelayMs?: number;
  readonly requestTimeoutMs?: number;
}

export interface RegisterVkResult {
  readonly vkHash: string;
  readonly alreadyRegistered: boolean;
  readonly warnings: readonly string[];
}

export interface SubmitGroth16ProofParams {
  readonly vkHash: string;
  readonly proof: Groth16Proof;
  readonly publicSignals: readonly string[];
}

export type SubmitProofResult =
  | {
      readonly outcome: "accepted";
      readonly httpStatus: 200 | 202;
      readonly jobId: string;
      readonly optimisticVerify: "success" | "pending";
      readonly warnings: readonly string[];
    }
  | {
      readonly outcome: "rejected";
      readonly httpStatus: 200 | 400 | 422;
      readonly jobId: string | null;
      readonly optimisticVerify: "failed";
      readonly reason: string;
      readonly code?: string;
    };

export interface KurierJobStatus {
  readonly jobId: string;
  readonly status: string;
  readonly txHash: string | null;
  readonly txExplorerUrl: string | null;
  readonly blockHash: string | null;
  readonly blockExplorerUrl: string | null;
  readonly statement: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly errorDetails: Record<string, unknown> | null;
}

export interface WaitForFinalityOptions {
  readonly timeoutMs?: number;
  readonly preferWebSocket?: boolean;
  readonly onStageChange?: (status: KurierJobStatus) => void;
}

export class KurierError extends Error {
  public readonly statusCode: number | null;
  public readonly retryable: boolean;
  public readonly code: string | null;

  public constructor(
    message: string,
    options?: {
      readonly statusCode?: number | null;
      readonly retryable?: boolean;
      readonly code?: string | null;
      readonly apiKeyForScrub?: string;
    },
  ) {
    const safeMessage = scrubKurierText(message, options?.apiKeyForScrub);
    super(safeMessage);
    this.name = "KurierError";
    this.statusCode = options?.statusCode ?? null;
    this.retryable = options?.retryable ?? false;
    this.code = options?.code ?? null;
    if (this.stack !== undefined) {
      this.stack = scrubKurierText(this.stack, options?.apiKeyForScrub);
    }
  }
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function scrubKurierText(text: string, apiKey?: string): string {
  let scrubbed = text;
  const trimmedKey = apiKey?.trim() ?? "";
  if (trimmedKey.length > 0) {
    scrubbed = scrubbed.replace(new RegExp(escapeRegExp(trimmedKey), "g"), REDACTED_MARKER);
    const encodedKey = encodeURIComponent(trimmedKey);
    if (encodedKey !== trimmedKey) {
      scrubbed = scrubbed.replace(new RegExp(escapeRegExp(encodedKey), "g"), REDACTED_MARKER);
    }
  }

  scrubbed = scrubbed.replace(
    /(\/(?:register-vk|submit-proof|job-status)\/)(?!\[REDACTED_KURIER_KEY\])([^/?#\s"']+)/gi,
    `$1${REDACTED_MARKER}`,
  );
  scrubbed = scrubbed.replace(
    /(\/kurier-oracle\/requests\/)(?!\[REDACTED_KURIER_KEY\])([^/?#\s"']+)/gi,
    `$1${REDACTED_MARKER}`,
  );
  scrubbed = scrubbed.replace(
    /([?&]apiKey=)(?!\[REDACTED_KURIER_KEY\])([^&#\s"']+)/gi,
    `$1${REDACTED_MARKER}`,
  );
  return scrubbed;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractString(obj: Record<string, unknown>, key: string): string | null {
  const val = obj[key];
  return typeof val === "string" && val.length > 0 ? val : null;
}

function validatePathSegment(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error(`${label} must be non-empty`);
  }
  if (/[/?#\s]/.test(trimmed)) {
    throw new Error(`${label} contains invalid URL path characters`);
  }
  return trimmed;
}

function createNodeWsAdapter(url: string): KurierSocketLike {
  const ws = new WebSocket(url);
  const adapter: KurierSocketLike = {
    get readyState(): number {
      return ws.readyState;
    },
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    send(data: string): void {
      ws.send(data);
    },
    close(code?: number, reason?: string): void {
      ws.close(code, reason);
    },
  };

  ws.on("open", () => {
    adapter.onopen?.();
  });
  ws.on("message", (rawData) => {
    const text =
      typeof rawData === "string"
        ? rawData
        : Buffer.isBuffer(rawData)
          ? rawData.toString("utf8")
          : Array.isArray(rawData)
            ? Buffer.concat(rawData).toString("utf8")
            : Buffer.from(rawData).toString("utf8");
    adapter.onmessage?.({ data: text });
  });
  ws.on("error", (err) => {
    adapter.onerror?.(err);
  });
  ws.on("close", (code, reasonBuf) => {
    adapter.onclose?.({
      code,
      reason: Buffer.isBuffer(reasonBuf) ? reasonBuf.toString("utf8") : String(reasonBuf ?? ""),
    });
  });

  return adapter;
}

function parseJobStatusPayload(
  raw: Record<string, unknown>,
  fallbackJobId: string,
  apiKey: string,
  apiBaseUrl: string,
): KurierJobStatus {
  const jobId = extractString(raw, "jobId") ?? fallbackJobId;
  const status = extractString(raw, "status") ?? "Queued";
  const txHash = extractString(raw, "txHash");
  const rawTxExplorer = extractString(raw, "txExplorerUrl");
  const isMainnet = apiBaseUrl.includes("api.kurier.xyz");
  const txExplorerUrl =
    rawTxExplorer ??
    (txHash !== null && isMainnet ? `https://zkverify.subscan.io/extrinsic/${txHash}` : null);
  const blockHash = extractString(raw, "blockHash");
  const blockExplorerUrl = extractString(raw, "blockExplorerUrl");
  const statement = extractString(raw, "statement");
  const createdAt = extractString(raw, "createdAt");
  const updatedAt = extractString(raw, "updatedAt");

  let errorDetails: Record<string, unknown> | null = null;
  if (isPlainRecord(raw.errorDetails)) {
    const scrubbedJson = scrubKurierText(JSON.stringify(raw.errorDetails), apiKey);
    errorDetails = JSON.parse(scrubbedJson) as Record<string, unknown>;
  }

  return {
    jobId,
    status,
    txHash,
    txExplorerUrl,
    blockHash,
    blockExplorerUrl,
    statement,
    createdAt,
    updatedAt,
    errorDetails,
  };
}

interface SharedFinalityTracker {
  readonly promise: Promise<KurierJobStatus>;
  readonly stageCallbacks: Set<(status: KurierJobStatus) => void>;
  lastSignature: string;
}

export class KurierClient {
  private readonly apiKey: string;
  private readonly apiBaseUrl: string;
  private readonly wsUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly createWebSocket: (url: string) => KurierSocketLike;
  private readonly onLog: ((entry: KurierLogEntry) => void) | undefined;
  private readonly wsRotationIntervalMs: number;
  private readonly wsPingIntervalMs: number;
  private readonly wsConnectTimeoutMs: number;
  private readonly pollBaseDelayMs: number;
  private readonly pollMaxDelayMs: number;
  private readonly requestTimeoutMs: number;

  private readonly singleflightJobStatus = new Map<string, Promise<KurierJobStatus>>();
  private readonly wsJobSubscribers = new Map<string, Set<(status: KurierJobStatus) => void>>();
  private readonly sharedFinalityTrackers = new Map<string, SharedFinalityTracker>();

  private activeSocket: KurierSocketLike | null = null;
  private wsSubscribedAll = false;
  private wsConnectInFlight: Promise<boolean> | null = null;
  private rotationTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  public constructor(options: KurierClientOptions) {
    this.apiKey = validatePathSegment(options.apiKey, "KURIER_API_KEY");
    const trimmedBase = (options.apiBaseUrl ?? DEFAULT_KURIER_API_URL).trim().replace(/\/+$/, "");
    if (trimmedBase.length === 0) {
      throw new Error("apiBaseUrl must be non-empty");
    }
    this.apiBaseUrl = trimmedBase;
    this.wsUrl = (options.wsUrl ?? DEFAULT_KURIER_WS_URL).trim().replace(/\/+$/, "");
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.createWebSocket = options.createWebSocket ?? createNodeWsAdapter;
    this.onLog = options.onLog;
    this.wsRotationIntervalMs = options.wsRotationIntervalMs ?? 23 * 60 * 60 * 1_000;
    this.wsPingIntervalMs = options.wsPingIntervalMs ?? 30_000;
    this.wsConnectTimeoutMs = options.wsConnectTimeoutMs ?? DEFAULT_WS_CONNECT_TIMEOUT_MS;
    this.pollBaseDelayMs = options.pollBaseDelayMs ?? DEFAULT_POLL_BASE_DELAY_MS;
    this.pollMaxDelayMs = options.pollMaxDelayMs ?? DEFAULT_POLL_MAX_DELAY_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  private emitLog(entry: KurierLogEntry): void {
    if (this.onLog === undefined) {
      return;
    }
    this.onLog({
      ...entry,
      message: scrubKurierText(entry.message, this.apiKey),
    });
  }

  private buildAuthenticatedRestUrl(endpoint: "register-vk" | "submit-proof" | "job-status", suffix?: string): string {
    const safeKey = encodeURIComponent(validatePathSegment(this.apiKey, "KURIER_API_KEY"));
    const baseSegment = `${this.apiBaseUrl}/${endpoint}/${safeKey}`;
    // Guard against x402 paid trailing-slash routes (/register-vk/ or /submit-proof/).
    if (baseSegment.endsWith(`/${endpoint}/`)) {
      throw new Error(`Refusing empty API key path on ${endpoint}`);
    }
    if (suffix !== undefined) {
      const safeSuffix = encodeURIComponent(validatePathSegment(suffix, "jobId"));
      return `${baseSegment}/${safeSuffix}`;
    }
    return baseSegment;
  }

  private async requestJson(
    url: string,
    init: RequestInit,
    timeoutMsOverride?: number,
  ): Promise<{ readonly status: number; readonly data: Record<string, unknown> }> {
    const controller = new AbortController();
    const effectiveTimeoutMs = timeoutMsOverride ?? this.requestTimeoutMs;
    const timer = setTimeout(() => controller.abort(), effectiveTimeoutMs);
    timer.unref?.();

    try {
      const response = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
      });
      const rawText = await response.text();
      let parsed: Record<string, unknown> = {};
      if (rawText.trim().length > 0) {
        try {
          const candidate: unknown = JSON.parse(rawText);
          parsed = isPlainRecord(candidate) ? candidate : { raw: scrubKurierText(rawText, this.apiKey) };
        } catch {
          parsed = { message: scrubKurierText(rawText, this.apiKey) };
        }
      }
      return { status: response.status, data: parsed };
    } catch (err: unknown) {
      const rawMsg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      const safeMsg = scrubKurierText(rawMsg, this.apiKey);
      this.emitLog({
        level: "error",
        event: "kurier.http.transport_error",
        message: safeMsg,
      });
      throw new KurierError(`Kurier HTTP request failed: ${safeMsg}`, {
        statusCode: null,
        retryable: true,
        apiKeyForScrub: this.apiKey,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  public async registerVerificationKey(vk: Groth16VerificationKey): Promise<RegisterVkResult> {
    const url = this.buildAuthenticatedRestUrl("register-vk");
    const { status, data } = await this.requestJson(
      url,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          proofOptions: {
            library: "snarkjs",
            curve: "bn128",
          },
          vk,
        }),
      },
      Math.max(this.requestTimeoutMs, 90_000),
    );

    if (status === 200) {
      const vkHash = extractString(data, "vkHash");
      if (vkHash === null) {
        throw new KurierError("Kurier register-vk HTTP 200 missing vkHash", {
          statusCode: 200,
          retryable: false,
          apiKeyForScrub: this.apiKey,
        });
      }
      const warnings = Array.isArray(data.warnings)
        ? data.warnings.filter((item): item is string => typeof item === "string")
        : [];
      const alreadyByWarning =
        warnings.some((w) => /already/i.test(w)) ||
        /already/i.test(extractString(data, "message") ?? "");
      return {
        vkHash,
        alreadyRegistered: alreadyByWarning,
        warnings,
      };
    }

    if (status === 400) {
      const meta = isPlainRecord(data.meta) ? data.meta : null;
      const existingVkHash =
        (meta !== null ? extractString(meta, "vkHash") : null) ?? extractString(data, "vkHash");
      if (existingVkHash !== null) {
        return {
          vkHash: existingVkHash,
          alreadyRegistered: true,
          warnings: [],
        };
      }
    }

    const reason =
      extractString(data, "message") ?? extractString(data, "error") ?? `HTTP ${status}`;
    throw new KurierError(`Kurier register-vk failed (${status}): ${reason}`, {
      statusCode: status,
      retryable: status === 429 || status >= 500,
      code: extractString(data, "code"),
      apiKeyForScrub: this.apiKey,
    });
  }

  public async submitProof(params: SubmitGroth16ProofParams): Promise<SubmitProofResult> {
    const vkHash = validatePathSegment(params.vkHash, "vkHash");
    const url = this.buildAuthenticatedRestUrl("submit-proof");
    // Omit chainId intentionally so zkVerify settles directly without 2-5 min cross-chain aggregation.
    const payload = {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: {
        library: "snarkjs",
        curve: "bn128",
      },
      proofData: {
        proof: params.proof,
        publicSignals: [...params.publicSignals],
        vk: vkHash,
      },
    };

    const { status, data } = await this.requestJson(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (status === 200) {
      const optimisticVerify = extractString(data, "optimisticVerify");
      const jobId = extractString(data, "jobId");
      if (optimisticVerify === "failed") {
        const errReason =
          extractString(data, "error") ??
          extractString(data, "message") ??
          "Optimistic verification failed";
        return {
          outcome: "rejected",
          httpStatus: 200,
          jobId,
          optimisticVerify: "failed",
          reason: scrubKurierText(errReason, this.apiKey),
        };
      }
      if (jobId === null) {
        throw new KurierError("Kurier submit-proof HTTP 200 missing jobId", {
          statusCode: 200,
          retryable: false,
          apiKeyForScrub: this.apiKey,
        });
      }
      return {
        outcome: "accepted",
        httpStatus: 200,
        jobId,
        optimisticVerify: "success",
        warnings: Array.isArray(data.warnings)
          ? data.warnings.filter((item): item is string => typeof item === "string")
          : [],
      };
    }

    if (status === 202) {
      const jobId = extractString(data, "jobId");
      if (jobId === null) {
        throw new KurierError("Kurier submit-proof HTTP 202 missing jobId", {
          statusCode: 202,
          retryable: false,
          apiKeyForScrub: this.apiKey,
        });
      }
      return {
        outcome: "accepted",
        httpStatus: 202,
        jobId,
        optimisticVerify: "pending",
        warnings: Array.isArray(data.warnings)
          ? data.warnings.filter((item): item is string => typeof item === "string")
          : [],
      };
    }

    if (status === 400 || status === 422) {
      const rawReason =
        extractString(data, "message") ??
        extractString(data, "error") ??
        `Rejected with HTTP ${status}`;
      const code = extractString(data, "code") ?? undefined;
      return {
        outcome: "rejected",
        httpStatus: status,
        jobId: null,
        optimisticVerify: "failed",
        reason: scrubKurierText(rawReason, this.apiKey),
        code,
      };
    }

    const errMsg =
      extractString(data, "message") ?? extractString(data, "error") ?? `HTTP ${status}`;
    throw new KurierError(`Kurier submit-proof failed (${status}): ${errMsg}`, {
      statusCode: status,
      retryable: status === 429 || status >= 500,
      code: extractString(data, "code"),
      apiKeyForScrub: this.apiKey,
    });
  }

  public async getJobStatus(jobId: string): Promise<KurierJobStatus> {
    const safeJobId = validatePathSegment(jobId, "jobId");
    const existing = this.singleflightJobStatus.get(safeJobId);
    if (existing !== undefined) {
      return existing;
    }

    const requestPromise = (async (): Promise<KurierJobStatus> => {
      const url = this.buildAuthenticatedRestUrl("job-status", safeJobId);
      const { status, data } = await this.requestJson(url, { method: "GET" });
      if (status !== 200) {
        const errMsg =
          extractString(data, "message") ?? extractString(data, "error") ?? `HTTP ${status}`;
        this.emitLog({
          level: "warn",
          event: "kurier.job_status.http_error",
          jobId: safeJobId,
          message: `job-status returned ${status}: ${errMsg}`,
        });
        throw new KurierError(`Kurier job-status failed (${status}): ${errMsg}`, {
          statusCode: status,
          retryable: status === 429 || status >= 500,
          code: extractString(data, "code"),
          apiKeyForScrub: this.apiKey,
        });
      }
      return parseJobStatusPayload(data, safeJobId, this.apiKey, this.apiBaseUrl);
    })();

    this.singleflightJobStatus.set(safeJobId, requestPromise);
    try {
      return await requestPromise;
    } finally {
      this.singleflightJobStatus.delete(safeJobId);
    }
  }

  private clearWsTimers(): void {
    if (this.rotationTimer !== null) {
      clearTimeout(this.rotationTimer);
      this.rotationTimer = null;
    }
    if (this.pingTimer !== null) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleWsMaintenance(socket: KurierSocketLike): void {
    this.clearWsTimers();
    this.rotationTimer = setTimeout(() => {
      if (!this.closed && this.activeSocket === socket) {
        void this.rotateWebSocket();
      }
    }, this.wsRotationIntervalMs);
    this.rotationTimer.unref?.();

    this.pingTimer = setInterval(() => {
      if (!this.closed && this.activeSocket === socket && socket.readyState === 1) {
        try {
          socket.send(JSON.stringify({ type: "ping" }));
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.emitLog({
            level: "warn",
            event: "kurier.ws.ping_failed",
            message: msg,
          });
        }
      }
    }, this.wsPingIntervalMs);
    this.pingTimer.unref?.();
  }

  private dispatchWsJobUpdate(status: KurierJobStatus): void {
    const subscribers = this.wsJobSubscribers.get(status.jobId);
    if (subscribers === undefined) {
      return;
    }
    for (const fn of subscribers) {
      fn(status);
    }
  }

  private async openFreshSubscribedSocket(): Promise<KurierSocketLike | null> {
    if (this.closed) {
      return null;
    }
    const fullWsUrl = `${this.wsUrl}?apiKey=${encodeURIComponent(this.apiKey)}`;
    let socket: KurierSocketLike;
    try {
      socket = this.createWebSocket(fullWsUrl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.emitLog({
        level: "warn",
        event: "kurier.ws.create_failed",
        message: msg,
      });
      return null;
    }

    return new Promise<KurierSocketLike | null>((resolve) => {
      let settled = false;
      let sentSubscribeAll = false;
      const connectTimer = setTimeout(() => {
        if (!settled) {
          settled = true;
          try {
            socket.close(1000, "connect-timeout");
          } catch {
            // Ignore close failure on timed-out socket
          }
          resolve(null);
        }
      }, this.wsConnectTimeoutMs);
      connectTimer.unref?.();

      const sendSubscribeOnce = (): void => {
        if (sentSubscribeAll) {
          return;
        }
        sentSubscribeAll = true;
        socket.send(JSON.stringify({ type: "subscribe-all" }));
      };

      socket.onopen = () => {
        try {
          sendSubscribeOnce();
          if (!settled) {
            settled = true;
            clearTimeout(connectTimer);
            resolve(socket);
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.emitLog({
            level: "warn",
            event: "kurier.ws.subscribe_send_failed",
            message: msg,
          });
          if (!settled) {
            settled = true;
            clearTimeout(connectTimer);
            resolve(null);
          }
        }
      };

      socket.onmessage = (event) => {
        const rawText = typeof event.data === "string" ? event.data : String(event.data ?? "");
        let msg: unknown;
        try {
          msg = JSON.parse(rawText);
        } catch {
          return;
        }
        if (!isPlainRecord(msg)) {
          return;
        }
        if (msg.type === "connected") {
          sendSubscribeOnce();
          return;
        }
        if (msg.type === "job-status-update" && isPlainRecord(msg.data)) {
          const parsed = parseJobStatusPayload(msg.data, "", this.apiKey, this.apiBaseUrl);
          if (parsed.jobId.length > 0) {
            this.dispatchWsJobUpdate(parsed);
          }
          return;
        }
        if (msg.type === "error") {
          const errMessage = extractString(msg, "message") ?? "WebSocket error frame";
          this.emitLog({
            level: "warn",
            event: "kurier.ws.server_error",
            message: errMessage,
          });
        }
      };

      socket.onerror = (err) => {
        const rawMsg = err instanceof Error ? err.message : String(err ?? "WebSocket error");
        this.emitLog({
          level: "warn",
          event: "kurier.ws.error",
          message: rawMsg,
        });
        if (!settled) {
          settled = true;
          clearTimeout(connectTimer);
          resolve(null);
        }
      };

      socket.onclose = () => {
        if (this.activeSocket === socket) {
          this.activeSocket = null;
          this.wsSubscribedAll = false;
          this.clearWsTimers();
        }
        if (!settled) {
          settled = true;
          clearTimeout(connectTimer);
          resolve(null);
        }
      };
    });
  }

  private async rotateWebSocket(): Promise<void> {
    if (this.closed) {
      return;
    }
    const previousSocket = this.activeSocket;
    const replacement = await this.openFreshSubscribedSocket();
    if (replacement === null) {
      return;
    }
    this.activeSocket = replacement;
    this.wsSubscribedAll = true;
    this.scheduleWsMaintenance(replacement);
    if (previousSocket !== null && previousSocket !== replacement) {
      try {
        previousSocket.close(1000, "proactive-23h-rotation");
      } catch {
        // Ignore close error on superseded socket
      }
    }
    this.emitLog({
      level: "info",
      event: "kurier.ws.rotated",
      message: "Rotated persistent Kurier subscribe-all WebSocket",
    });
  }

  public async ensureWebSocketSubscribed(): Promise<boolean> {
    if (this.closed) {
      return false;
    }
    if (this.activeSocket !== null && this.wsSubscribedAll && this.activeSocket.readyState === 1) {
      return true;
    }
    if (this.wsConnectInFlight !== null) {
      return this.wsConnectInFlight;
    }

    const connectPromise = (async (): Promise<boolean> => {
      const opened = await this.openFreshSubscribedSocket();
      if (opened === null) {
        return false;
      }
      this.activeSocket = opened;
      this.wsSubscribedAll = true;
      this.scheduleWsMaintenance(opened);
      return true;
    })();

    this.wsConnectInFlight = connectPromise;
    try {
      return await connectPromise;
    } finally {
      this.wsConnectInFlight = null;
    }
  }

  private ensureSharedFinalityTracker(
    safeJobId: string,
    preferWebSocket: boolean,
  ): SharedFinalityTracker {
    const existing = this.sharedFinalityTrackers.get(safeJobId);
    if (existing !== undefined) {
      return existing;
    }

    const stageCallbacks = new Set<(status: KurierJobStatus) => void>();
    const trackerRef: { lastSignature: string } = { lastSignature: "" };

    const notifyStage = (status: KurierJobStatus): void => {
      const sig = `${status.status}:${status.txHash ?? ""}:${status.blockHash ?? ""}`;
      if (sig === trackerRef.lastSignature) {
        return;
      }
      trackerRef.lastSignature = sig;
      for (const cb of stageCallbacks) {
        cb(status);
      }
    };

    const promise = (async (): Promise<KurierJobStatus> => {
      let resolvedTerminal: KurierJobStatus | null = null;
      let wakeLoop: (() => void) | null = null;

      const onWsUpdate = (status: KurierJobStatus): void => {
        notifyStage(status);
        if (status.status === "Finalized" || status.status === "Failed") {
          resolvedTerminal = status;
          wakeLoop?.();
        }
      };

      let jobSet = this.wsJobSubscribers.get(safeJobId);
      if (jobSet === undefined) {
        jobSet = new Set();
        this.wsJobSubscribers.set(safeJobId, jobSet);
      }
      jobSet.add(onWsUpdate);

      try {
        const wsReady = preferWebSocket ? await this.ensureWebSocketSubscribed() : false;
        let attempt = 0;

        while (!this.closed) {
          if (resolvedTerminal !== null) {
            break;
          }

          if (wsReady && attempt === 0) {
            const initialGraceMs = Math.min(this.pollMaxDelayMs, Math.max(this.pollBaseDelayMs, 250));
            await new Promise<void>((resolve) => {
              wakeLoop = resolve;
              const t = setTimeout(() => {
                wakeLoop = null;
                resolve();
              }, initialGraceMs);
              t.unref?.();
            });
            if (resolvedTerminal !== null || this.closed) {
              break;
            }
          }

          try {
            const polled = await this.getJobStatus(safeJobId);
            notifyStage(polled);
            if (polled.status === "Finalized" || polled.status === "Failed") {
              resolvedTerminal = polled;
              break;
            }
          } catch (err: unknown) {
            if (err instanceof KurierError && !err.retryable) {
              throw err;
            }
          }

          const delayMs = Math.min(this.pollBaseDelayMs * 2 ** attempt, this.pollMaxDelayMs);
          attempt += 1;
          await new Promise<void>((resolve) => {
            wakeLoop = resolve;
            const t = setTimeout(() => {
              wakeLoop = null;
              resolve();
            }, delayMs);
            t.unref?.();
          });
        }

        const terminal = resolvedTerminal as KurierJobStatus | null;
        if (terminal === null) {
          throw new KurierError(`Kurier client closed while waiting for job ${safeJobId}`, {
            retryable: false,
            apiKeyForScrub: this.apiKey,
          });
        }
        if (terminal.status === "Failed") {
          throw new KurierError(`Kurier job ${safeJobId} failed on-chain verification`, {
            statusCode: null,
            retryable: false,
            code: "JOB_FAILED",
            apiKeyForScrub: this.apiKey,
          });
        }
        return terminal;
      } finally {
        const subSet = this.wsJobSubscribers.get(safeJobId);
        subSet?.delete(onWsUpdate);
        if (subSet !== undefined && subSet.size === 0) {
          this.wsJobSubscribers.delete(safeJobId);
        }
        this.sharedFinalityTrackers.delete(safeJobId);
      }
    })();

    const tracker: SharedFinalityTracker = {
      promise,
      stageCallbacks,
      get lastSignature(): string {
        return trackerRef.lastSignature;
      },
      set lastSignature(val: string) {
        trackerRef.lastSignature = val;
      },
    };
    this.sharedFinalityTrackers.set(safeJobId, tracker);
    return tracker;
  }

  public async waitForJobFinality(
    jobId: string,
    options?: WaitForFinalityOptions,
  ): Promise<KurierJobStatus> {
    const safeJobId = validatePathSegment(jobId, "jobId");
    const timeoutMs = options?.timeoutMs ?? 90_000;
    const preferWebSocket = options?.preferWebSocket ?? true;
    const tracker = this.ensureSharedFinalityTracker(safeJobId, preferWebSocket);

    const onStageChange = options?.onStageChange;
    if (onStageChange !== undefined) {
      tracker.stageCallbacks.add(onStageChange);
    }

    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(
          new KurierError(`Timed out after ${timeoutMs}ms waiting for Kurier job ${safeJobId}`, {
            retryable: true,
            code: "FINALITY_TIMEOUT",
            apiKeyForScrub: this.apiKey,
          }),
        );
      }, timeoutMs);
      timeoutHandle.unref?.();
    });

    try {
      return await Promise.race([tracker.promise, timeoutPromise]);
    } finally {
      if (timeoutHandle !== null) {
        clearTimeout(timeoutHandle);
      }
      if (onStageChange !== undefined) {
        tracker.stageCallbacks.delete(onStageChange);
      }
    }
  }

  public async close(): Promise<void> {
    this.closed = true;
    this.clearWsTimers();
    const sock = this.activeSocket;
    this.activeSocket = null;
    this.wsSubscribedAll = false;
    if (sock !== null) {
      try {
        sock.close(1000, "client-close");
      } catch {
        // Ignore close errors during teardown
      }
    }
  }
}
