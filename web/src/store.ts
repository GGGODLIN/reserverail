import { useSyncExternalStore } from "react";
import { fetchDemoState, proposePayment, resetSandbox, runServerAct, sendTamperedReceipt } from "./api.ts";
import type { DemoState, DemoStep, ServerActId, TamperResponse, TreasuryReceipt } from "./api-types.ts";
import {
  acceptError,
  acceptRun,
  acceptSnapshot,
  commitmentLabel,
  createScopedView,
  enterScope,
  isCurrentScope,
  isFinalReceiptStatus,
  ticketOf,
  withTamperedAmount,
} from "./model/workbench-model.ts";
import type { RelayMode, ScopeTicket, ScopedView } from "./model/workbench-model.ts";

export type ActKey = "act1" | "act2" | "act3";
export type BusyKind = ActKey | "proposal" | "reset";
export type VerificationKind = "groth16" | "chain" | "tamper";

export interface WorkbenchRun {
  readonly label: string;
  readonly steps: readonly DemoStep[];
}

export interface Draft {
  readonly recipient: string;
  readonly amount: string;
  readonly memo: string;
}

export interface VerificationResults {
  readonly running: VerificationKind | null;
  readonly groth16: string | null;
  readonly chain: string | null;
  readonly tamper: readonly string[] | null;
}

export interface WorkbenchState {
  readonly view: ScopedView<DemoState, WorkbenchRun>;
  readonly relayMode: RelayMode | null;
  readonly busy: BusyKind | null;
  readonly announcement: string;
  readonly cfoOpen: boolean;
  readonly selectedReceiptId: string | null;
  readonly draft: Draft;
  readonly verification: VerificationResults;
}

export interface WorkbenchStore {
  getState(): WorkbenchState;
  subscribe(listener: () => void): () => void;
  boot(): void;
  runAct(act: ActKey): Promise<void>;
  propose(): Promise<void>;
  reset(): Promise<void>;
  newSandbox(): Promise<void>;
  copySandboxUrl(): Promise<void>;
  toggleCfo(): void;
  selectReceipt(receiptId: string): void;
  updateDraft(patch: Partial<Draft>): void;
  verifySelectedProof(): Promise<void>;
  verifyChain(): Promise<void>;
  tamperSelected(): Promise<void>;
}

export const ACT_LABELS: Readonly<Record<ActKey, string>> = {
  act1: "Act 1",
  act2: "Act 2",
  act3: "Act 3",
};

const SERVER_ACT: Readonly<Record<"act2" | "act3", ServerActId>> = {
  act2: "act2_structuring",
  act3: "act3_concurrency",
};

const POLL_INTERVAL_MS = 700;

const NO_VERIFICATION: VerificationResults = { running: null, groth16: null, chain: null, tamper: null };

function sandboxFromLocation(): string | null {
  return optional(new URLSearchParams(window.location.search).get("sandbox") ?? "") ?? null;
}

function sandboxUrl(sandboxId: string): string {
  return `${window.location.pathname}?sandbox=${encodeURIComponent(sandboxId)}`;
}

function optional(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function randomSuffix(): string {
  return (crypto.getRandomValues(new Uint32Array(1))[0] ?? 0).toString(16).padStart(8, "0");
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function stepOf(response: DemoStep): DemoStep {
  return {
    intent: response.intent,
    naiveResult: response.naiveResult,
    reserveRailResult: response.reserveRailResult,
  };
}

function verdictOf(step: DemoStep): string {
  const rr = step.reserveRailResult;
  return rr.approved && rr.seq !== undefined
    ? `APPROVED (${commitmentLabel(rr.seq - 1)} → ${commitmentLabel(rr.seq)})`
    : `REJECTED (${rr.reasonCode})`;
}

function summarizeRun(label: string, steps: readonly DemoStep[]): string {
  const naiveApproved = steps.filter((step) => step.naiveResult.approved).length;
  const gateApproved = steps.filter((step) => step.reserveRailResult.approved).length;
  const rejected = steps.filter((step) => !step.reserveRailResult.approved).map((step) => step.reserveRailResult.reasonCode);
  const rejection = rejected.length > 0 ? `, rejected ${rejected.join(", ")}` : "";
  return `${label} complete: naive agent approved ${naiveApproved} of ${steps.length}; ReserveRail approved ${gateApproved} of ${steps.length}${rejection}.`;
}

function finalityAnnouncement(previous: DemoState | null, next: DemoState): string | null {
  const before = new Map(previous?.receipts.map((receipt) => [receipt.receiptId, receipt.provenance.status]) ?? []);
  const changes = next.receipts
    .filter((receipt) => before.has(receipt.receiptId) && before.get(receipt.receiptId) !== receipt.provenance.status)
    .map((receipt) => `Receipt ${commitmentLabel(receipt.seq)} reached ${receipt.provenance.status}`);
  return changes.length > 0 ? `${changes.join("; ")}.` : null;
}

export function selectedReceipt(state: WorkbenchState): TreasuryReceipt | null {
  const receipts = state.view.snapshot?.receipts ?? [];
  return receipts.find((receipt) => receipt.receiptId === state.selectedReceiptId) ?? receipts.at(-1) ?? null;
}

function tamperServerLines(server: TamperResponse | Error, relayMode: RelayMode): string[] {
  if (server instanceof Error) {
    return [`Server: unavailable (${server.message})`];
  }
  const kurier = !server.kurierAttempted
    ? `Kurier Mainnet: not attempted (${relayMode === "LIVE" ? server.optimisticVerify : relayMode})`
    : server.kurierRejected === true
      ? `Kurier Mainnet: REJECTED (optimisticVerify: ${server.optimisticVerify})`
      : server.kurierRejected === null
        ? `Kurier Mainnet: unavailable (${server.reason})`
        : "Kurier Mainnet: ACCEPTED (unexpected)";
  return [`Server local verify: ${server.localVerified ? "PASSED (unexpected)" : "FAILED"}`, kurier];
}

export function createWorkbenchStore(): WorkbenchStore {
  let state: WorkbenchState = {
    view: createScopedView<DemoState, WorkbenchRun>(sandboxFromLocation()),
    relayMode: null,
    busy: null,
    announcement: "",
    cfoOpen: true,
    selectedReceiptId: null,
    draft: { recipient: "", amount: "", memo: "" },
    verification: NO_VERIFICATION,
  };
  const listeners = new Set<() => void>();
  // Aborted on every Reset and scope switch, so nothing issued for the old scope keeps running.
  let scopeAbort = new AbortController();
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let pollAbort: AbortController | null = null;

  function commit(next: WorkbenchState): void {
    state = { ...next, relayMode: next.view.snapshot?.relayMode ?? next.relayMode };
    for (const listener of listeners) {
      listener();
    }
  }

  function announce(announcement: string): void {
    commit({ ...state, announcement });
  }

  function cancelPoll(): void {
    if (pollTimer !== null) {
      clearTimeout(pollTimer);
    }
    pollTimer = null;
    pollAbort?.abort();
    pollAbort = null;
  }

  function beginScope(sandboxId: string | null): ScopeTicket {
    scopeAbort.abort();
    scopeAbort = new AbortController();
    cancelPoll();
    commit({
      ...state,
      view: enterScope(state.view, sandboxId),
      busy: null,
      selectedReceiptId: null,
      verification: NO_VERIFICATION,
    });
    return ticketOf(state.view);
  }

  // Resolves to null when the call failed (the banner is set) or its scope has been left (dropped silently).
  async function guarded<T>(ticket: ScopeTicket, failure: string, call: (signal: AbortSignal) => Promise<T>): Promise<T | null> {
    const signal = scopeAbort.signal;
    try {
      const value = await call(signal);
      return isCurrentScope(state.view, ticket) ? value : null;
    } catch (error: unknown) {
      if (isCurrentScope(state.view, ticket) && !signal.aborted) {
        const message = `${failure}: ${messageOf(error)}`;
        commit({ ...state, busy: null, view: acceptError(state.view, ticket, message), announcement: message });
      }
      return null;
    }
  }

  function hasPendingFinality(): boolean {
    const receipts = state.view.snapshot?.receipts ?? [];
    return receipts.some((receipt) => !isFinalReceiptStatus(receipt.provenance.status));
  }

  function schedulePoll(): void {
    if (pollTimer !== null || !hasPendingFinality()) {
      return;
    }
    pollTimer = setTimeout(() => {
      pollTimer = null;
      pollNow();
    }, POLL_INTERVAL_MS);
  }

  // Polls never overlap an action in the same scope, so a slower poll cannot overwrite a newer snapshot.
  function pollNow(): void {
    const sandboxId = state.view.sandboxId;
    if (sandboxId === null || state.busy !== null || pollAbort !== null) {
      return;
    }
    const ticket = ticketOf(state.view);
    const controller = new AbortController();
    pollAbort = controller;
    fetchDemoState(sandboxId, controller.signal)
      .then((snapshot) => {
        if (controller.signal.aborted || state.busy !== null || !isCurrentScope(state.view, ticket)) {
          return;
        }
        const announcement = finalityAnnouncement(state.view.snapshot, snapshot) ?? state.announcement;
        commit({ ...state, view: acceptSnapshot(state.view, ticket, snapshot), announcement });
      })
      // A missed poll is retried on the next tick while receipts are still settling.
      .catch(() => undefined)
      .finally(() => {
        if (pollAbort === controller) {
          pollAbort = null;
        }
        schedulePoll();
      });
  }

  function finishRun(ticket: ScopeTicket, run: WorkbenchRun, snapshot: DemoState, announcement: string): void {
    if (!isCurrentScope(state.view, ticket)) {
      return;
    }
    commit({
      ...state,
      view: acceptRun(acceptSnapshot(state.view, ticket, snapshot), ticket, run),
      busy: null,
      selectedReceiptId: null,
      verification: NO_VERIFICATION,
      announcement,
    });
    schedulePoll();
  }

  function startAction(busy: BusyKind, announcement: string): ScopeTicket | null {
    if (state.view.sandboxId === null || state.busy !== null) {
      return null;
    }
    cancelPoll();
    const ticket = ticketOf(state.view);
    commit({ ...state, busy, view: acceptError(state.view, ticket, null), announcement });
    return ticket;
  }

  async function openScopeFromLocation(): Promise<void> {
    const requested = sandboxFromLocation();
    const ticket = beginScope(requested);
    const snapshot = await guarded(ticket, "Could not load the sandbox", (signal) => fetchDemoState(requested, signal));
    if (snapshot === null) {
      return;
    }
    if (requested !== snapshot.sandboxId) {
      window.history.replaceState(null, "", sandboxUrl(snapshot.sandboxId));
    }
    commit({
      ...state,
      view: acceptSnapshot(state.view, ticket, snapshot),
      announcement: `Sandbox ${snapshot.sandboxId} ready at ${commitmentLabel(snapshot.receipts.length)}.`,
    });
    schedulePoll();
  }

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    boot() {
      window.addEventListener("popstate", () => {
        void openScopeFromLocation();
      });
      // A second tab on the same sandbox catches up when the visitor switches back to this one.
      window.addEventListener("focus", pollNow);
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
          pollNow();
        }
      });
      void openScopeFromLocation();
    },

    async runAct(act) {
      const label = ACT_LABELS[act];
      const ticket = startAction(act, `${label} running: proving each payment…`);
      const sandboxId = state.view.sandboxId;
      if (ticket === null || sandboxId === null) {
        return;
      }
      const failure = `${label} failed`;
      if (act !== "act1") {
        const response = await guarded(ticket, failure, (signal) => runServerAct(sandboxId, SERVER_ACT[act], signal));
        if (response !== null) {
          finishRun(ticket, { label, steps: response.steps }, response.state, summarizeRun(label, response.steps));
        }
        return;
      }
      const injection = await guarded(ticket, failure, (signal) => runServerAct(sandboxId, "act1_injection", signal));
      if (injection === null) {
        return;
      }
      commit({
        ...state,
        view: acceptRun(acceptSnapshot(state.view, ticket, injection.state), ticket, { label, steps: injection.steps }),
      });
      const legit = await guarded(ticket, failure, (signal) =>
        proposePayment(sandboxId, { actId: "act1_legit", invoiceId: `act1-legit-${randomSuffix()}` }, signal),
      );
      if (legit !== null) {
        const steps = [...injection.steps, stepOf(legit)];
        finishRun(ticket, { label, steps }, legit.state, summarizeRun(label, steps));
      }
    },

    async propose() {
      const ticket = startAction("proposal", "Proposal running: parsing and proving…");
      const sandboxId = state.view.sandboxId;
      if (ticket === null || sandboxId === null) {
        return;
      }
      const { recipient, amount, memo } = state.draft;
      const response = await guarded(ticket, "Proposal failed", (signal) =>
        proposePayment(
          sandboxId,
          { recipient: optional(recipient), amount: optional(amount), memo: optional(memo) },
          signal,
        ),
      );
      if (response === null) {
        return;
      }
      const step = stepOf(response);
      const naive = `${step.naiveResult.approved ? "APPROVED" : "REJECTED"} (${step.naiveResult.reasonCode})`;
      finishRun(
        ticket,
        { label: "Custom proposal", steps: [step] },
        response.state,
        `Proposal settled: ReserveRail ${verdictOf(step)}; naive agent ${naive}.`,
      );
    },

    async reset() {
      const sandboxId = state.view.sandboxId;
      if (sandboxId === null || state.busy !== null) {
        return;
      }
      const started = performance.now();
      const ticket = beginScope(sandboxId);
      commit({ ...state, busy: "reset", announcement: "Resetting to C₀…" });
      const response = await guarded(ticket, "Reset failed", (signal) => resetSandbox(sandboxId, signal));
      if (response === null) {
        return;
      }
      commit({
        ...state,
        busy: null,
        view: acceptSnapshot(state.view, ticket, response.state),
        announcement: `Sandbox reset to C₀ in ${Math.round(performance.now() - started)} ms; mainnet explorer links kept.`,
      });
    },

    async newSandbox() {
      const ticket = beginScope(null);
      announce("Opening a fresh sandbox…");
      const snapshot = await guarded(ticket, "Could not open a fresh sandbox", (signal) => fetchDemoState(null, signal));
      if (snapshot === null) {
        return;
      }
      window.history.pushState(null, "", sandboxUrl(snapshot.sandboxId));
      commit({
        ...state,
        view: acceptSnapshot(state.view, ticket, snapshot),
        announcement: `Switched to fresh sandbox ${snapshot.sandboxId} at C₀.`,
      });
    },

    async copySandboxUrl() {
      const url = window.location.href;
      try {
        await navigator.clipboard.writeText(url);
        announce(`Sandbox URL copied: ${url} — open it in a second tab to share this scope.`);
      } catch {
        announce(`Copy was blocked by the browser; share this URL instead: ${url}`);
      }
    },

    toggleCfo() {
      commit({ ...state, cfoOpen: !state.cfoOpen });
    },

    selectReceipt(receiptId) {
      const clearRunning =
        state.verification.running === "groth16" || state.verification.running === "tamper"
          ? null
          : state.verification.running;
      commit({
        ...state,
        selectedReceiptId: receiptId,
        verification: { ...state.verification, running: clearRunning, groth16: null, tamper: null },
      });
    },

    updateDraft(patch) {
      commit({ ...state, draft: { ...state.draft, ...patch } });
    },

    async verifySelectedProof() {
      const receipt = selectedReceipt(state);
      if (receipt === null || state.verification.running !== null) {
        return;
      }
      const ticket = ticketOf(state.view);
      commit({
        ...state,
        verification: { ...state.verification, running: "groth16" },
        announcement: "Verifying the Groth16 proof in this browser…",
      });
      const started = performance.now();
      try {
        const { verifyTransitionProof } = await import("./zero-trust.ts");
        const valid = await verifyTransitionProof(receipt.proof, receipt.publicSignalsArray).catch(() => false);
        if (
          !isCurrentScope(state.view, ticket) ||
          state.verification.running !== "groth16" ||
          selectedReceipt(state)?.receiptId !== receipt.receiptId
        ) {
          return;
        }
        const line = `Groth16 proof: ${valid ? "VALID" : "INVALID"} · receipt ${commitmentLabel(receipt.seq)} · checked in this browser in ${Math.round(performance.now() - started)} ms`;
        commit({ ...state, verification: { ...state.verification, running: null, groth16: line }, announcement: line });
      } catch (error: unknown) {
        if (isCurrentScope(state.view, ticket) && state.verification.running === "groth16") {
          const line = `Groth16 proof check failed to load: ${messageOf(error)}`;
          commit({ ...state, verification: { ...state.verification, running: null, groth16: line }, announcement: line });
        }
      }
    },

    async verifyChain() {
      const snapshot = state.view.snapshot;
      if (snapshot === null || state.verification.running !== null) {
        return;
      }
      const ticket = ticketOf(state.view);
      commit({
        ...state,
        verification: { ...state.verification, running: "chain" },
        announcement: "Verifying the Audit Chain in this browser…",
      });
      try {
        const { verifyAuditChain } = await import("./zero-trust.ts");
        const result = await verifyAuditChain(
          snapshot.receipts,
          snapshot.auditorView.genesisCommitment,
          snapshot.auditorView.policyRoot,
        );
        if (!isCurrentScope(state.view, ticket) || state.verification.running !== "chain") {
          return;
        }
        const line = result.valid
          ? `Audit chain: VALID · ${result.count} receipt${result.count === 1 ? "" : "s"} · C₀ → ${commitmentLabel(result.count)} · checked in this browser`
          : `Audit chain: INVALID · ${result.reasonCode ?? "UNKNOWN"} · checked in this browser`;
        commit({ ...state, verification: { ...state.verification, running: null, chain: line }, announcement: line });
      } catch (error: unknown) {
        if (isCurrentScope(state.view, ticket) && state.verification.running === "chain") {
          const line = `Audit chain check failed to load: ${messageOf(error)}`;
          commit({ ...state, verification: { ...state.verification, running: null, chain: line }, announcement: line });
        }
      }
    },

    async tamperSelected() {
      const snapshot = state.view.snapshot;
      const receipt = selectedReceipt(state);
      if (snapshot === null || receipt === null || state.verification.running !== null) {
        return;
      }
      const ticket = ticketOf(state.view);
      const signal = scopeAbort.signal;
      commit({
        ...state,
        verification: { ...state.verification, running: "tamper" },
        announcement: "Tampering with the amount and sending it to Kurier Mainnet…",
      });
      const tamperedAmount = (BigInt(receipt.publicSignals.amount) + 1n).toString(10);
      const forged = withTamperedAmount(receipt, tamperedAmount);
      try {
        const { verifyAuditChain, verifyTransitionProof } = await import("./zero-trust.ts");
        const [server, browserValid, chain] = await Promise.all([
          sendTamperedReceipt(receipt, tamperedAmount, signal).catch((error: unknown) => new Error(messageOf(error))),
          verifyTransitionProof(forged.proof, forged.publicSignalsArray).catch(() => false),
          verifyAuditChain(
            snapshot.receipts.map((candidate) => (candidate.receiptId === receipt.receiptId ? forged : candidate)),
            snapshot.auditorView.genesisCommitment,
            snapshot.auditorView.policyRoot,
          ),
        ]);
        if (
          !isCurrentScope(state.view, ticket) ||
          state.verification.running !== "tamper" ||
          selectedReceipt(state)?.receiptId !== receipt.receiptId
        ) {
          return;
        }
        const lines = [
          `Amount ${receipt.publicSignals.amount} → ${tamperedAmount} on receipt ${commitmentLabel(receipt.seq)}`,
          `This browser: ${browserValid ? "VALID (unexpected)" : "INVALID — the proof no longer matches its public signals"}`,
          ...tamperServerLines(server, snapshot.relayMode),
          `Audit chain with the tampered receipt: ${chain.valid ? "VALID (unexpected)" : `INVALID · ${chain.reasonCode ?? "UNKNOWN"}`}`,
        ];
        commit({
          ...state,
          verification: { ...state.verification, running: null, tamper: lines },
          announcement: `Tamper test finished: ${lines.slice(1).join("; ")}.`,
        });
      } catch (error: unknown) {
        if (isCurrentScope(state.view, ticket) && state.verification.running === "tamper") {
          const line = `Tamper test failed to load: ${messageOf(error)}`;
          commit({
            ...state,
            verification: { ...state.verification, running: null, tamper: [line] },
            announcement: line,
          });
        }
      }
    },
  };
}

export function useWorkbench(store: WorkbenchStore): WorkbenchState {
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}
