import crypto from "node:crypto";
import type { Groth16Proof } from "snarkjs";
import { proveTransition, verifyTransitionProof } from "../circuit/prover.ts";
import { REGISTERED_VK_HASH, VERIFICATION_KEY, toPublicSignalsArray } from "../generated/circuit-abi.ts";
import { KurierClient, KurierError, scrubKurierText } from "../kurier/kurier-client.ts";
import type { KurierJobStatus, SubmitProofResult } from "../kurier/kurier-client.ts";
import type { TreasuryReceipt } from "./audit-chain.ts";
import type { ProposedPaymentIntent } from "./intent-parser.ts";
import type { ProvingPriority, ProvingSemaphore } from "./proving-semaphore.ts";
import { loadBaselineMainnetCassette } from "./replay-cassette.ts";
import type { BaselineMainnetCassette } from "./replay-cassette.ts";
import type { ReserveRailStore, SandboxScopeType } from "./sqlite-store.ts";

export interface ExecuteTransitionParams {
  readonly sandboxId: string;
  readonly scopeType?: SandboxScopeType;
  readonly intent: ProposedPaymentIntent;
  readonly mode?: "LIVE" | "DETERMINISTIC_REPLAY";
  readonly priority?: ProvingPriority;
  readonly signal?: AbortSignal;
}

export interface ExecuteTransitionResult {
  readonly approved: boolean;
  readonly transientError?: boolean;
  readonly httpStatus: number;
  readonly reasonCode: string;
  readonly errorMessage?: string;
  readonly seq?: number;
  readonly prevCommitment?: string;
  readonly newCommitment?: string;
  readonly amount?: string;
  readonly invoiceHash?: string;
  readonly provenanceMode?: "LIVE" | "DETERMINISTIC_REPLAY";
  readonly receipt?: TreasuryReceipt;
  readonly staleProvesAttempted: number;
  readonly reEvaluatedAfterLease: boolean;
}

export interface TamperResult {
  readonly localVerified: boolean;
  readonly kurierAttempted: boolean;
  readonly kurierRejected: boolean | null;
  readonly optimisticVerify: string;
  readonly reason: string;
  readonly tamperedPublicSignals: readonly string[];
}

export interface TreasuryLedgerServiceOptions {
  readonly store: ReserveRailStore;
  readonly semaphore: ProvingSemaphore;
  readonly kurierClient?: KurierClient | null;
  readonly cassette?: BaselineMainnetCassette;
  readonly submitMaxRetries?: number;
  readonly submitRetryDelayMs?: number;
  readonly preferWebSocket?: boolean;
  readonly onProveStarted?: () => void;
}

class LeaseReleaseNotifier {
  private readonly waiters = new Map<string, Set<() => void>>();

  private key(sandboxId: string, leaseId: string): string {
    return `${sandboxId}::${leaseId}`;
  }

  public notifyReleased(sandboxId: string, leaseId: string): void {
    const k = this.key(sandboxId, leaseId);
    const set = this.waiters.get(k);
    if (set === undefined) {
      return;
    }
    this.waiters.delete(k);
    for (const wake of set) {
      wake();
    }
  }

  public async waitForSettlement(
    store: ReserveRailStore,
    sandboxId: string,
    heldLeaseId: string,
    signal?: AbortSignal,
    maxWaitMs = 15_000,
  ): Promise<void> {
    const k = this.key(sandboxId, heldLeaseId);
    const deadlineAt = Date.now() + maxWaitMs;

    while (Date.now() < deadlineAt) {
      if (signal?.aborted) {
        throw new Error("WAIT_ABORTED");
      }

      let woke = false;
      let wakeResolve: (() => void) | null = null;
      const waiterPromise = new Promise<void>((resolve) => {
        wakeResolve = () => {
          if (!woke) {
            woke = true;
            resolve();
          }
        };
      });

      let set = this.waiters.get(k);
      if (set === undefined) {
        set = new Set();
        this.waiters.set(k, set);
      }
      set.add(wakeResolve!);

      // Re-check SQLite AFTER registering waiter to eliminate lost-wakeup races
      const snap = store.getSandboxSnapshot(sandboxId);
      if (snap.inFlightLeaseId !== heldLeaseId) {
        set.delete(wakeResolve!);
        if (set.size === 0) {
          this.waiters.delete(k);
        }
        return;
      }

      const remaining = Math.max(1, Math.min(100, deadlineAt - Date.now()));
      let timer: ReturnType<typeof setTimeout> | null = null;
      const cleanups: Array<() => void> = [];

      await Promise.race([
        waiterPromise,
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, remaining);
          timer.unref?.();
        }),
        ...(signal
          ? [
              new Promise<void>((resolve) => {
                const onAbort = () => resolve();
                signal.addEventListener("abort", onAbort, { once: true });
                cleanups.push(() => signal.removeEventListener("abort", onAbort));
              }),
            ]
          : []),
      ]);

      if (timer !== null) {
        clearTimeout(timer);
      }
      for (const fn of cleanups) {
        fn();
      }
      set.delete(wakeResolve!);
      if (set.size === 0) {
        this.waiters.delete(k);
      }

      const afterSnap = store.getSandboxSnapshot(sandboxId);
      if (afterSnap.inFlightLeaseId !== heldLeaseId) {
        return;
      }
    }
  }
}

export class TreasuryLedgerService {
  private readonly store: ReserveRailStore;
  private readonly semaphore: ProvingSemaphore;
  private readonly kurierClient: KurierClient | null;
  public readonly cassette: BaselineMainnetCassette;
  private readonly submitMaxRetries: number;
  private readonly submitRetryDelayMs: number;
  private readonly preferWebSocket: boolean;
  private readonly onProveStarted: (() => void) | undefined;
  private readonly leaseNotifier = new LeaseReleaseNotifier();
  private readonly pendingFinalityTasks = new Map<string, Promise<void>>();
  private readonly activeExecutions = new Set<Promise<ExecuteTransitionResult>>();
  private closed = false;

  public constructor(options: TreasuryLedgerServiceOptions) {
    this.store = options.store;
    this.semaphore = options.semaphore;
    this.kurierClient = options.kurierClient ?? null;
    this.cassette = options.cassette ?? loadBaselineMainnetCassette();
    this.submitMaxRetries = options.submitMaxRetries ?? 2;
    this.submitRetryDelayMs = options.submitRetryDelayMs ?? 150;
    this.preferWebSocket = options.preferWebSocket ?? true;
    this.onProveStarted = options.onProveStarted;
  }

  public async close(): Promise<void> {
    this.closed = true;
    if (this.kurierClient !== null) {
      await this.kurierClient.close();
    }
    await Promise.allSettled([
      ...this.activeExecutions,
      ...this.pendingFinalityTasks.values(),
    ]);
  }

  public async waitForPendingFinality(receiptId: string, timeoutMs = 5_000): Promise<void> {
    const task = this.pendingFinalityTasks.get(receiptId);
    if (task === undefined) {
      return;
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      await Promise.race([
        task,
        new Promise<void>((_, reject) => {
          timer = setTimeout(() => reject(new Error("WAIT_FINALITY_TIMEOUT")), timeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
      }
    }
  }

  private async submitProofWithRetry(params: {
    readonly proof: Groth16Proof;
    readonly publicSignalsArray: readonly string[];
    readonly signal?: AbortSignal;
  }): Promise<SubmitProofResult> {
    if (this.kurierClient === null) {
      throw new Error("KURIER_CLIENT_NOT_CONFIGURED");
    }

    let attempt = 0;
    while (true) {
      if (params.signal?.aborted || this.closed) {
        throw new Error("DEADLINE_EXCEEDED");
      }
      try {
        const submitPromise = this.kurierClient.submitProof({
          vkHash: REGISTERED_VK_HASH,
          proof: params.proof,
          publicSignals: params.publicSignalsArray,
        });
        if (params.signal === undefined) {
          return await submitPromise;
        }
        const sig = params.signal;
        let abortCleanup: (() => void) | null = null;
        try {
          return await Promise.race([
            submitPromise,
            new Promise<never>((_, reject) => {
              const onAbort = () => reject(new Error("DEADLINE_EXCEEDED"));
              sig.addEventListener("abort", onAbort, { once: true });
              abortCleanup = () => sig.removeEventListener("abort", onAbort);
            }),
          ]);
        } finally {
          (abortCleanup as (() => void) | null)?.();
        }
      } catch (err: unknown) {
        const isRetryable = err instanceof KurierError && err.retryable;
        if (!isRetryable || attempt >= this.submitMaxRetries) {
          throw err;
        }
        attempt += 1;
        await new Promise<void>((resolve) => {
          const delay = this.submitRetryDelayMs * attempt;
          const t = setTimeout(resolve, delay);
          t.unref?.();
        });
      }
    }
  }

  private trackFinalityAsync(params: {
    readonly outboxId: string;
    readonly sandboxId: string;
    readonly jobId: string;
    readonly amount: string;
  }): void {
    if (this.kurierClient === null || this.closed) {
      return;
    }
    const client = this.kurierClient;
    const task = (async () => {
      try {
        const terminal: KurierJobStatus = await client.waitForJobFinality(params.jobId, {
          timeoutMs: 120_000,
          preferWebSocket: this.preferWebSocket,
          onStageChange: (st) => {
            if (st.status === "IncludedInBlock" || st.status === "Finalized") {
              this.store.updateOutboxKurierStatus({
                outboxId: params.outboxId,
                sandboxId: params.sandboxId,
                status: st.status === "Finalized" ? "FINALIZED" : "INCLUDED_IN_BLOCK",
                txHash: st.txHash,
                blockHash: st.blockHash,
                txExplorerUrl: st.txExplorerUrl,
                blockExplorerUrl: st.blockExplorerUrl,
                amount: params.amount,
                jobId: params.jobId,
              });
            }
          },
        });
        if (terminal.status === "Finalized") {
          this.store.updateOutboxKurierStatus({
            outboxId: params.outboxId,
            sandboxId: params.sandboxId,
            status: "FINALIZED",
            txHash: terminal.txHash,
            blockHash: terminal.blockHash,
            txExplorerUrl: terminal.txExplorerUrl,
            blockExplorerUrl: terminal.blockExplorerUrl,
            amount: params.amount,
            jobId: params.jobId,
          });
        }
      } catch (err: unknown) {
        if (!this.closed) {
          const msg = err instanceof Error ? err.message : String(err);
          this.store.recordDiagnosticEvent("kurier_error", `Async finality tracking note: ${msg}`);
        }
      } finally {
        this.pendingFinalityTasks.delete(params.outboxId);
      }
    })();

    this.pendingFinalityTasks.set(params.outboxId, task);
  }

  public async executeTransition(params: ExecuteTransitionParams): Promise<ExecuteTransitionResult> {
    const execPromise = this.executeTransitionInternal(params);
    this.activeExecutions.add(execPromise);
    try {
      return await execPromise;
    } finally {
      this.activeExecutions.delete(execPromise);
    }
  }

  private async executeTransitionInternal(params: ExecuteTransitionParams): Promise<ExecuteTransitionResult> {
    const maxRetries = 1;
    let reEvaluatedAfterLease = false;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      if (params.signal?.aborted) {
        return {
          approved: false,
          transientError: true,
          httpStatus: 504,
          reasonCode: "DEADLINE_EXCEEDED",
          errorMessage: "Soft deadline exceeded before lease acquisition",
          staleProvesAttempted: 0,
          reEvaluatedAfterLease,
        };
      }

      const leaseAttempt = this.store.tryAcquireInFlightLease({
        sandboxId: params.sandboxId,
        scopeType: params.scopeType,
        recipientField: params.intent.recipientField,
        amount: params.intent.amount,
        epoch: params.intent.epoch,
        invoiceIdField: params.intent.invoiceIdField,
      });

      if (leaseAttempt.status === "policy_rejected") {
        if (leaseAttempt.shadow.invariantDrift) {
          this.store.recordDiagnosticEvent("invariant_drift", leaseAttempt.shadow.message);
        }
        return {
          approved: false,
          httpStatus: 422,
          reasonCode: leaseAttempt.shadow.reasonCode,
          errorMessage: leaseAttempt.shadow.message,
          staleProvesAttempted: 0,
          reEvaluatedAfterLease,
        };
      }

      if (leaseAttempt.status === "lease_held") {
        if (attempt >= maxRetries) {
          this.store.recordDiagnosticEvent(
            "lease_contention",
            `Max lease re-evaluation retries (${maxRetries}) reached for ${params.sandboxId}`,
          );
          return {
            approved: false,
            transientError: true,
            httpStatus: 409,
            reasonCode: "LEASE_CONTENTION",
            errorMessage: "Concurrent transition still holds In-Flight Lease after re-evaluation",
            staleProvesAttempted: 0,
            reEvaluatedAfterLease,
          };
        }

        await this.leaseNotifier.waitForSettlement(
          this.store,
          params.sandboxId,
          leaseAttempt.heldLeaseId,
          params.signal,
        );
        reEvaluatedAfterLease = true;
        continue;
      }

      // Acquired exclusive In-Flight Lease on current committed head C_k
      const { leaseId, sandbox, shadow, newSalt, nextSeq } = leaseAttempt;
      const outboxId = `tx_${crypto.randomUUID()}`;
      const requestedLive = params.mode === "LIVE" && this.kurierClient !== null;
      const effectiveMode: "LIVE" | "DETERMINISTIC_REPLAY" = requestedLive
        ? "LIVE"
        : "DETERMINISTIC_REPLAY";

      let outboxInserted = false;

      try {
        let proof: Groth16Proof;
        let publicSignalsArray: string[];

        const releaseSlot = await this.semaphore.acquire(params.priority ?? 1, params.signal);
        try {
          this.onProveStarted?.();
          const bundle = await proveTransition({
            allowlistRecipients: sandbox.allowlist.map((v) => BigInt(v.recipientField)),
            epochCap: BigInt(sandbox.epochCap),
            payrollFloor: BigInt(sandbox.payrollFloor),
            policySalt: BigInt(sandbox.policySalt),
            balance: BigInt(sandbox.balance),
            spentSoFar: BigInt(sandbox.spentSoFar),
            prevEpoch: BigInt(sandbox.currentEpoch),
            prevSalt: BigInt(sandbox.currentSalt),
            recipient: params.intent.recipientField,
            amount: params.intent.amount,
            epoch: params.intent.epoch,
            invoiceIdField: params.intent.invoiceIdField,
            newSalt,
          });
          const localOk = await verifyTransitionProof(
            bundle.proof,
            bundle.publicSignalsArray,
            VERIFICATION_KEY,
          );
          if (!localOk) {
            this.store.recordDiagnosticEvent(
              "invariant_drift",
              "Local Groth16 verifyTransitionProof returned false on freshly proved bundle",
            );
            throw new Error("INVARIANT_BROKEN: local verification failed");
          }
          proof = bundle.proof;
          publicSignalsArray = bundle.publicSignalsArray;
        } finally {
          releaseSlot();
        }

        const publicSignalsObj = {
          policyRoot: shadow.publicSignals.policyRoot.toString(10),
          prevCommitment: shadow.publicSignals.prevCommitment.toString(10),
          newCommitment: shadow.publicSignals.newCommitment.toString(10),
          recipient: shadow.publicSignals.recipient.toString(10),
          amount: shadow.publicSignals.amount.toString(10),
          epoch: shadow.publicSignals.epoch.toString(10),
          invoiceHash: shadow.publicSignals.invoiceHash.toString(10),
        };

        this.store.insertOutboxPending({
          outboxId,
          sandboxId: params.sandboxId,
          leaseId,
          seq: nextSeq,
          prevCommitment: publicSignalsObj.prevCommitment,
          newCommitment: publicSignalsObj.newCommitment,
          recipient: publicSignalsObj.recipient,
          vendorName: params.intent.vendorName,
          amount: publicSignalsObj.amount,
          epoch: publicSignalsObj.epoch,
          invoiceId: params.intent.invoiceId,
          invoiceHash: publicSignalsObj.invoiceHash,
          newSpent: shadow.newSpent.toString(10),
          newSalt: newSalt.toString(10),
          provenanceMode: effectiveMode,
          proofJson: JSON.stringify(proof),
          publicSignalsJson: JSON.stringify(publicSignalsObj),
          publicSignalsArrayJson: JSON.stringify(publicSignalsArray),
        });
        outboxInserted = true;

        if (effectiveMode === "DETERMINISTIC_REPLAY") {
          this.store.commitOutboxSubmissionAndReleaseLease({
            outboxId,
            sandboxId: params.sandboxId,
            leaseId,
            seq: nextSeq,
            newCommitment: publicSignalsObj.newCommitment,
            newSpent: shadow.newSpent.toString(10),
            newEpoch: publicSignalsObj.epoch,
            newSalt: newSalt.toString(10),
            status: "FINALIZED",
            jobId: this.cassette.validTransition.jobId,
            txHash: this.cassette.validTransition.txHash,
            blockHash: this.cassette.validTransition.blockHash,
            txExplorerUrl: this.cassette.validTransition.txExplorerUrl,
            blockExplorerUrl: this.cassette.validTransition.blockExplorerUrl ?? null,
          });
          this.leaseNotifier.notifyReleased(params.sandboxId, leaseId);

          const receipt: TreasuryReceipt = {
            receiptId: outboxId,
            sandboxId: params.sandboxId,
            seq: nextSeq,
            vendorName: params.intent.vendorName,
            invoiceId: params.intent.invoiceId,
            proof,
            publicSignals: publicSignalsObj,
            publicSignalsArray,
            provenance: {
              mode: "DETERMINISTIC_REPLAY",
              network: "zkverify-mainnet",
              vkHash: REGISTERED_VK_HASH,
              jobId: this.cassette.validTransition.jobId,
              txHash: this.cassette.validTransition.txHash,
              blockHash: this.cassette.validTransition.blockHash,
              txExplorerUrl: this.cassette.validTransition.txExplorerUrl,
              blockExplorerUrl: this.cassette.validTransition.blockExplorerUrl ?? null,
              status: "Finalized",
              note: "Offline replay cassette (Gate 01 Mainnet attestation attached; local Groth16 verified)",
            },
            createdAt: new Date().toISOString(),
            settledAt: this.cassette.validTransition.settledAt,
          };

          return {
            approved: true,
            httpStatus: 200,
            reasonCode: "POLICY_PASS",
            seq: nextSeq,
            prevCommitment: publicSignalsObj.prevCommitment,
            newCommitment: publicSignalsObj.newCommitment,
            amount: publicSignalsObj.amount,
            invoiceHash: publicSignalsObj.invoiceHash,
            provenanceMode: "DETERMINISTIC_REPLAY",
            receipt,
            staleProvesAttempted: 0,
            reEvaluatedAfterLease,
          };
        }

        // LIVE mode: submit to Kurier and unlock once queued (200/202), tracking finality async
        const submitRes = await this.submitProofWithRetry({
          proof,
          publicSignalsArray,
          signal: params.signal,
        });

        if (submitRes.outcome === "rejected") {
          this.store.rollbackOutboxAndReleaseLease({
            outboxId,
            sandboxId: params.sandboxId,
            leaseId,
            errorMessage: submitRes.reason,
          });
          this.leaseNotifier.notifyReleased(params.sandboxId, leaseId);
          return {
            approved: false,
            httpStatus: 422,
            reasonCode: "KURIER_PROOF_REJECTED",
            errorMessage: submitRes.reason,
            staleProvesAttempted: 0,
            reEvaluatedAfterLease,
          };
        }

        this.store.commitOutboxSubmissionAndReleaseLease({
          outboxId,
          sandboxId: params.sandboxId,
          leaseId,
          seq: nextSeq,
          newCommitment: publicSignalsObj.newCommitment,
          newSpent: shadow.newSpent.toString(10),
          newEpoch: publicSignalsObj.epoch,
          newSalt: newSalt.toString(10),
          status: "SUBMITTED",
          jobId: submitRes.jobId,
          txHash: null,
          blockHash: null,
          txExplorerUrl: null,
          blockExplorerUrl: null,
        });
        this.leaseNotifier.notifyReleased(params.sandboxId, leaseId);

        this.trackFinalityAsync({
          outboxId,
          sandboxId: params.sandboxId,
          jobId: submitRes.jobId,
          amount: publicSignalsObj.amount,
        });

        const receipt: TreasuryReceipt = {
          receiptId: outboxId,
          sandboxId: params.sandboxId,
          seq: nextSeq,
          vendorName: params.intent.vendorName,
          invoiceId: params.intent.invoiceId,
          proof,
          publicSignals: publicSignalsObj,
          publicSignalsArray,
          provenance: {
            mode: "LIVE",
            network: "zkverify-mainnet",
            vkHash: REGISTERED_VK_HASH,
            jobId: submitRes.jobId,
            txHash: null,
            blockHash: null,
            txExplorerUrl: null,
            blockExplorerUrl: null,
            status: "Submitted",
          },
          createdAt: new Date().toISOString(),
          settledAt: null,
        };

        return {
          approved: true,
          httpStatus: 200,
          reasonCode: "POLICY_PASS",
          seq: nextSeq,
          prevCommitment: publicSignalsObj.prevCommitment,
          newCommitment: publicSignalsObj.newCommitment,
          amount: publicSignalsObj.amount,
          invoiceHash: publicSignalsObj.invoiceHash,
          provenanceMode: "LIVE",
          receipt,
          staleProvesAttempted: 0,
          reEvaluatedAfterLease,
        };
      } catch (err: unknown) {
        const rawMsg = err instanceof Error ? err.message : String(err);
        const isDeadline = rawMsg === "DEADLINE_EXCEEDED" || rawMsg === "PROVING_QUEUE_ABORTED";
        const isTransient =
          isDeadline || (err instanceof KurierError && (err.retryable || err.statusCode === 503));

        if (outboxInserted) {
          this.store.rollbackOutboxAndReleaseLease({
            outboxId,
            sandboxId: params.sandboxId,
            leaseId,
            errorMessage: rawMsg,
          });
        } else {
          this.store.releaseLeaseOnly(params.sandboxId, leaseId);
        }
        this.leaseNotifier.notifyReleased(params.sandboxId, leaseId);

        if (rawMsg.includes("INVARIANT_BROKEN")) {
          this.store.recordDiagnosticEvent("invariant_drift", rawMsg);
        } else if (isDeadline) {
          this.store.recordDiagnosticEvent("deadline_abort", rawMsg);
        } else {
          this.store.recordDiagnosticEvent("kurier_error", rawMsg);
        }

        return {
          approved: false,
          transientError: isTransient,
          httpStatus: isDeadline ? 504 : isTransient ? 503 : 500,
          reasonCode: isDeadline
            ? "DEADLINE_EXCEEDED"
            : isTransient
              ? "KURIER_TRANSIENT_UNAVAILABLE"
              : "EXECUTION_FAILED",
          errorMessage: scrubKurierText(rawMsg),
          staleProvesAttempted: 0,
          reEvaluatedAfterLease,
        };
      }
    }

    return {
      approved: false,
      transientError: true,
      httpStatus: 409,
      reasonCode: "LEASE_CONTENTION",
      errorMessage: "Unable to acquire In-Flight Lease",
      staleProvesAttempted: 0,
      reEvaluatedAfterLease,
    };
  }

  public async tamperCheck(params?: {
    readonly proof?: Groth16Proof;
    readonly publicSignalsArray?: readonly string[];
    readonly tamperedAmount?: string;
  }): Promise<TamperResult> {
    const sourceProof = params?.proof ?? (this.cassette.validTransition.proof as Groth16Proof);
    const sourceSignals =
      params?.publicSignalsArray ?? this.cassette.validTransition.publicSignalsArray;

    const mutatedSignals = [...sourceSignals];
    const currentAmt = BigInt(mutatedSignals[4] ?? "0");
    mutatedSignals[4] =
      params?.tamperedAmount ?? (currentAmt + 1n).toString(10);

    const localVerified = await verifyTransitionProof(
      sourceProof,
      mutatedSignals,
      VERIFICATION_KEY,
    );

    if (this.kurierClient === null) {
      return {
        localVerified,
        kurierAttempted: false,
        kurierRejected: null,
        optimisticVerify: localVerified ? "unexpected_pass" : "local_only_failed",
        reason: localVerified
          ? "Unexpected local pass"
          : "Local Groth16 verification failed on tampered publicSignals (KURIER_API_KEY unset)",
        tamperedPublicSignals: mutatedSignals,
      };
    }

    try {
      const submitRes = await this.kurierClient.submitProof({
        vkHash: REGISTERED_VK_HASH,
        proof: sourceProof,
        publicSignals: mutatedSignals,
      });

      if (submitRes.outcome === "rejected") {
        return {
          localVerified,
          kurierAttempted: true,
          kurierRejected: true,
          optimisticVerify: submitRes.optimisticVerify,
          reason: submitRes.reason,
          tamperedPublicSignals: mutatedSignals,
        };
      }

      try {
        await this.kurierClient.waitForJobFinality(submitRes.jobId, {
          timeoutMs: 30_000,
          preferWebSocket: this.preferWebSocket,
        });
        return {
          localVerified,
          kurierAttempted: true,
          kurierRejected: false,
          optimisticVerify: "unexpected_pass",
          reason: "Tampered proof was unexpectedly finalized",
          tamperedPublicSignals: mutatedSignals,
        };
      } catch (err: unknown) {
        if (err instanceof KurierError && err.code === "JOB_FAILED") {
          return {
            localVerified,
            kurierAttempted: true,
            kurierRejected: true,
            optimisticVerify: "failed",
            reason: err.message,
            tamperedPublicSignals: mutatedSignals,
          };
        }
        throw err;
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        localVerified,
        kurierAttempted: true,
        kurierRejected: null,
        optimisticVerify: "error",
        reason: scrubKurierText(msg),
        tamperedPublicSignals: mutatedSignals,
      };
    }
  }
}
