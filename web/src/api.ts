import type {
  ActResponse,
  DemoState,
  ProposalBody,
  ProposeResponse,
  ResetResponse,
  ServerActId,
  TamperResponse,
  TreasuryReceipt,
} from "./api-types.ts";

export class ApiError extends Error {}

async function readJson<T>(response: Response): Promise<T> {
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null && "error" in body && typeof body.error === "string"
        ? body.error
        : `HTTP ${response.status}`;
    throw new ApiError(message);
  }
  return body as T;
}

function postJson<T>(path: string, payload: unknown, signal: AbortSignal): Promise<T> {
  return fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal,
  }).then((response) => readJson<T>(response));
}

export function fetchDemoState(sandboxId: string | null, signal: AbortSignal): Promise<DemoState> {
  const query = sandboxId === null ? "" : `?sandbox=${encodeURIComponent(sandboxId)}`;
  return fetch(`/api/demo/state${query}`, { signal }).then((response) => readJson<DemoState>(response));
}

export function runServerAct(sandboxId: string, actId: ServerActId, signal: AbortSignal): Promise<ActResponse> {
  return postJson<ActResponse>("/api/demo/act", { sandboxId, actId }, signal);
}

export function proposePayment(sandboxId: string, body: ProposalBody, signal: AbortSignal): Promise<ProposeResponse> {
  return postJson<ProposeResponse>("/api/demo/propose", { sandboxId, ...body }, signal);
}

export function resetSandbox(sandboxId: string, signal: AbortSignal): Promise<ResetResponse> {
  return postJson<ResetResponse>("/api/demo/reset", { sandboxId }, signal);
}

export function sendTamperedReceipt(
  receipt: TreasuryReceipt,
  tamperedAmount: string,
  signal: AbortSignal,
): Promise<TamperResponse> {
  return postJson<TamperResponse>(
    "/api/demo/tamper",
    { tamperedAmount, receipt: { proof: receipt.proof, publicSignalsArray: receipt.publicSignalsArray } },
    signal,
  );
}
