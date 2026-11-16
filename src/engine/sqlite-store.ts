import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  buildAllowlistTree,
  computeLedgerCommitment,
  computePolicyRoot,
} from "../circuit/prover.ts";
import { REGISTERED_VK_HASH } from "../generated/circuit-abi.ts";
import { scrubKurierText } from "../kurier/kurier-client.ts";
import type { TreasuryReceipt } from "./audit-chain.ts";
import { DEFAULT_VENDORS, evaluatePolicyShadow } from "./policy.ts";
import type { AllowlistVendor, PolicyShadowResult } from "./policy.ts";

export type SandboxScopeType = "demo" | "competition";
export type OutboxStatus =
  | "PENDING_SUBMIT"
  | "SUBMITTED"
  | "INCLUDED_IN_BLOCK"
  | "FINALIZED"
  | "ROLLED_BACK";

export interface SandboxPolicyConfig {
  readonly balance?: bigint;
  readonly payrollFloor?: bigint;
  readonly epochCap?: bigint;
  readonly naiveSingleCap?: bigint;
  readonly epoch?: bigint;
  readonly allowlist?: readonly AllowlistVendor[];
}

export interface SandboxSnapshot {
  readonly sandboxId: string;
  readonly scopeType: SandboxScopeType;
  readonly policyRoot: string;
  readonly allowlist: readonly {
    readonly name: string;
    readonly address: string;
    readonly recipientField: string;
  }[];
  readonly epochCap: string;
  readonly payrollFloor: string;
  readonly policySalt: string;
  readonly balance: string;
  readonly spentSoFar: string;
  readonly currentEpoch: string;
  readonly currentSalt: string;
  readonly genesisCommitment: string;
  readonly currentCommitment: string;
  readonly naiveSingleCap: string;
  readonly naiveSpentTotal: string;
  readonly naiveEpochSpent: string;
  readonly naiveEpoch: string;
  readonly inFlightLeaseId: string | null;
  readonly inFlightAcquiredAt: number | null;
  readonly seqCounter: number;
}

export interface NaiveLedgerEntry {
  readonly id: string;
  readonly sandboxId: string;
  readonly seq: number;
  readonly vendorName: string;
  readonly recipientAddress: string;
  readonly amount: string;
  readonly epoch: string;
  readonly invoiceId: string;
  readonly approved: boolean;
  readonly reasonCode: string;
  readonly memo: string | null;
  readonly createdAt: string;
}

export interface MainnetExplorerLink {
  readonly id: string;
  readonly sandboxId: string;
  readonly txHash: string;
  readonly txExplorerUrl: string;
  readonly jobId: string | null;
  readonly amount: string;
  readonly createdAt: string;
}

export interface IdempotencyRecord {
  readonly taskId: string;
  readonly rawBodySha256: string;
  readonly statusCode: number;
  readonly responseJson: string;
  readonly createdAt: number;
}

export interface DiagnosticsSummary {
  readonly totalSandboxes: number;
  readonly demoSandboxes: number;
  readonly activeLeases: number;
  readonly outboxCounts: Readonly<Record<OutboxStatus, number>>;
  readonly invariantDriftCount: number;
  readonly recentEvents: readonly {
    readonly eventType: string;
    readonly detail: string;
    readonly createdAt: string;
  }[];
}

export type LeaseAcquireResult =
  | {
      readonly status: "acquired";
      readonly leaseId: string;
      readonly sandbox: SandboxSnapshot;
      readonly shadow: Extract<PolicyShadowResult, { readonly ok: true }>;
      readonly newSalt: bigint;
      readonly nextSeq: number;
    }
  | {
      readonly status: "lease_held";
      readonly heldLeaseId: string;
      readonly heldAt: number;
    }
  | {
      readonly status: "policy_rejected";
      readonly shadow: Extract<PolicyShadowResult, { readonly ok: false }>;
    };

function randomSaltBigInt(): bigint {
  const bytes = crypto.randomBytes(30);
  return BigInt(`0x${bytes.toString("hex")}`);
}

interface StoredVendor {
  readonly name: string;
  readonly address: string;
  readonly recipientField: string;
}

function toStoredVendors(vendors: readonly AllowlistVendor[]): StoredVendor[] {
  return vendors.map((v) => ({
    name: v.name,
    address: v.address,
    recipientField: v.recipientField.toString(10),
  }));
}

function parseSandboxRow(row: Record<string, unknown>): SandboxSnapshot {
  const allowlistRaw = JSON.parse(String(row.allowlist_json)) as StoredVendor[];
  return {
    sandboxId: String(row.sandbox_id),
    scopeType: row.scope_type === "competition" ? "competition" : "demo",
    policyRoot: String(row.policy_root),
    allowlist: allowlistRaw,
    epochCap: String(row.epoch_cap),
    payrollFloor: String(row.payroll_floor),
    policySalt: String(row.policy_salt),
    balance: String(row.balance),
    spentSoFar: String(row.spent_so_far),
    currentEpoch: String(row.current_epoch),
    currentSalt: String(row.current_salt),
    genesisCommitment: String(row.genesis_commitment),
    currentCommitment: String(row.current_commitment),
    naiveSingleCap: String(row.naive_single_cap),
    naiveSpentTotal: String(row.naive_spent_total),
    naiveEpochSpent: String(row.naive_epoch_spent),
    naiveEpoch: String(row.naive_epoch),
    inFlightLeaseId: row.in_flight_lease_id === null ? null : String(row.in_flight_lease_id),
    inFlightAcquiredAt:
      row.in_flight_acquired_at === null ? null : Number(row.in_flight_acquired_at),
    seqCounter: Number(row.seq_counter),
  };
}

export class ReserveRailStore {
  private readonly db: DatabaseSync;
  private readonly maxDemoSandboxes: number;
  private readonly scrubKey: string | undefined;

  private constructor(db: DatabaseSync, maxDemoSandboxes: number, scrubKey?: string) {
    this.db = db;
    this.maxDemoSandboxes = maxDemoSandboxes;
    this.scrubKey = scrubKey;
  }

  public static open(
    dbPath: string,
    options?: { readonly maxDemoSandboxes?: number; readonly scrubKey?: string },
  ): ReserveRailStore {
    const db = new DatabaseSync(dbPath);
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS sandboxes (
        sandbox_id TEXT PRIMARY KEY,
        scope_type TEXT NOT NULL,
        policy_root TEXT NOT NULL,
        allowlist_json TEXT NOT NULL,
        epoch_cap TEXT NOT NULL,
        payroll_floor TEXT NOT NULL,
        policy_salt TEXT NOT NULL,
        balance TEXT NOT NULL,
        spent_so_far TEXT NOT NULL,
        current_epoch TEXT NOT NULL,
        current_salt TEXT NOT NULL,
        genesis_commitment TEXT NOT NULL,
        current_commitment TEXT NOT NULL,
        naive_single_cap TEXT NOT NULL,
        naive_spent_total TEXT NOT NULL,
        naive_epoch_spent TEXT NOT NULL,
        naive_epoch TEXT NOT NULL,
        in_flight_lease_id TEXT,
        in_flight_acquired_at INTEGER,
        seq_counter INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_accessed_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS outbox_transitions (
        id TEXT PRIMARY KEY,
        sandbox_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        prev_commitment TEXT NOT NULL,
        new_commitment TEXT NOT NULL,
        recipient TEXT NOT NULL,
        vendor_name TEXT NOT NULL,
        amount TEXT NOT NULL,
        epoch TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        invoice_hash TEXT NOT NULL,
        new_spent TEXT NOT NULL,
        new_salt TEXT NOT NULL,
        status TEXT NOT NULL,
        provenance_mode TEXT NOT NULL,
        job_id TEXT,
        tx_hash TEXT,
        block_hash TEXT,
        tx_explorer_url TEXT,
        block_explorer_url TEXT,
        proof_json TEXT NOT NULL,
        public_signals_json TEXT NOT NULL,
        public_signals_array_json TEXT NOT NULL,
        error_message TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_active_invoice
        ON outbox_transitions(sandbox_id, invoice_hash)
        WHERE status != 'ROLLED_BACK';

      CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_active_prev
        ON outbox_transitions(sandbox_id, prev_commitment)
        WHERE status != 'ROLLED_BACK';

      CREATE INDEX IF NOT EXISTS idx_outbox_sandbox_seq
        ON outbox_transitions(sandbox_id, seq);

      CREATE TABLE IF NOT EXISTS naive_ledger_entries (
        id TEXT PRIMARY KEY,
        sandbox_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        vendor_name TEXT NOT NULL,
        recipient_address TEXT NOT NULL,
        amount TEXT NOT NULL,
        epoch TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        approved INTEGER NOT NULL,
        reason_code TEXT NOT NULL,
        memo TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS historical_mainnet_links (
        id TEXT PRIMARY KEY,
        sandbox_id TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        tx_explorer_url TEXT NOT NULL,
        job_id TEXT,
        amount TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS agent_idempotency (
        task_id TEXT PRIMARY KEY,
        raw_body_sha256 TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        response_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS intent_cache (
        cache_key TEXT PRIMARY KEY,
        intent_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS diagnostics_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        detail TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);

    const maxDemo = options?.maxDemoSandboxes ?? 200;
    return new ReserveRailStore(db, maxDemo, options?.scrubKey);
  }

  public close(): void {
    this.db.close();
  }

  private runImmediate<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err: unknown) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // Ignore rollback failure
      }
      throw err;
    }
  }

  private buildGenesisValues(config?: SandboxPolicyConfig) {
    const balance = config?.balance ?? 100_000n;
    const payrollFloor = config?.payrollFloor ?? 60_000n;
    const epochCap = config?.epochCap ?? 50_000n;
    const naiveSingleCap = config?.naiveSingleCap ?? 15_000n;
    const epoch = config?.epoch ?? 1n;
    const allowlist = config?.allowlist ?? DEFAULT_VENDORS;
    const policySalt = randomSaltBigInt();
    const currentSalt = randomSaltBigInt();

    const tree = buildAllowlistTree(allowlist.map((v) => v.recipientField));
    const policyRoot = computePolicyRoot({
      allowlistRoot: tree.root,
      epochCap,
      payrollFloor,
      policySalt,
    });
    const genesisCommitment = computeLedgerCommitment({
      balance,
      spentSoFar: 0n,
      epoch,
      salt: currentSalt,
    });

    return {
      balance,
      payrollFloor,
      epochCap,
      naiveSingleCap,
      epoch,
      allowlist,
      policySalt,
      currentSalt,
      policyRoot,
      genesisCommitment,
    };
  }

  private evictExcessDemoSandboxes(): void {
    const countRow = this.db
      .prepare("SELECT COUNT(*) AS cnt FROM sandboxes WHERE scope_type = 'demo'")
      .get() as Record<string, unknown> | undefined;
    const count = Number(countRow?.cnt ?? 0);
    if (count < this.maxDemoSandboxes) {
      return;
    }
    const overflow = count - this.maxDemoSandboxes + 1;
    const victims = this.db
      .prepare(
        `SELECT sandbox_id FROM sandboxes
         WHERE scope_type = 'demo' AND in_flight_lease_id IS NULL
         ORDER BY last_accessed_at ASC
         LIMIT ?`,
      )
      .all(overflow) as Record<string, unknown>[];

    const delOutbox = this.db.prepare("DELETE FROM outbox_transitions WHERE sandbox_id = ?");
    const delNaive = this.db.prepare("DELETE FROM naive_ledger_entries WHERE sandbox_id = ?");
    const delLinks = this.db.prepare("DELETE FROM historical_mainnet_links WHERE sandbox_id = ?");
    const delSbx = this.db.prepare("DELETE FROM sandboxes WHERE sandbox_id = ?");

    for (const v of victims) {
      const id = String(v.sandbox_id);
      delOutbox.run(id);
      delNaive.run(id);
      delLinks.run(id);
      delSbx.run(id);
    }
  }

  public getOrCreateSandbox(
    sandboxId: string,
    scopeType: SandboxScopeType = "demo",
    config?: SandboxPolicyConfig,
  ): SandboxSnapshot {
    return this.runImmediate(() => {
      const now = Date.now();
      const existing = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(sandboxId) as Record<string, unknown> | undefined;

      if (existing !== undefined) {
        this.db
          .prepare("UPDATE sandboxes SET last_accessed_at = ? WHERE sandbox_id = ?")
          .run(now, sandboxId);
        return parseSandboxRow(existing);
      }

      if (scopeType === "demo") {
        this.evictExcessDemoSandboxes();
      }

      const init = this.buildGenesisValues(config);
      this.db
        .prepare(
          `INSERT INTO sandboxes (
            sandbox_id, scope_type, policy_root, allowlist_json,
            epoch_cap, payroll_floor, policy_salt, balance,
            spent_so_far, current_epoch, current_salt,
            genesis_commitment, current_commitment,
            naive_single_cap, naive_spent_total, naive_epoch_spent, naive_epoch,
            in_flight_lease_id, in_flight_acquired_at, seq_counter,
            created_at, updated_at, last_accessed_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?)`,
        )
        .run(
          sandboxId,
          scopeType,
          init.policyRoot.toString(10),
          JSON.stringify(toStoredVendors(init.allowlist)),
          init.epochCap.toString(10),
          init.payrollFloor.toString(10),
          init.policySalt.toString(10),
          init.balance.toString(10),
          "0",
          init.epoch.toString(10),
          init.currentSalt.toString(10),
          init.genesisCommitment.toString(10),
          init.genesisCommitment.toString(10),
          init.naiveSingleCap.toString(10),
          "0",
          "0",
          init.epoch.toString(10),
          now,
          now,
          now,
        );

      const inserted = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(sandboxId) as Record<string, unknown>;
      return parseSandboxRow(inserted);
    });
  }

  public resetSandbox(
    sandboxId: string,
    config?: SandboxPolicyConfig,
    scopeType: SandboxScopeType = "demo",
  ): SandboxSnapshot {
    return this.runImmediate(() => {
      const now = Date.now();
      const existing = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(sandboxId) as Record<string, unknown> | undefined;

      if (existing === undefined && scopeType === "demo") {
        this.evictExcessDemoSandboxes();
      }

      const init = this.buildGenesisValues(config);
      this.db.prepare("DELETE FROM outbox_transitions WHERE sandbox_id = ?").run(sandboxId);
      this.db.prepare("DELETE FROM naive_ledger_entries WHERE sandbox_id = ?").run(sandboxId);

      if (existing === undefined) {
        this.db
          .prepare(
            `INSERT INTO sandboxes (
              sandbox_id, scope_type, policy_root, allowlist_json,
              epoch_cap, payroll_floor, policy_salt, balance,
              spent_so_far, current_epoch, current_salt,
              genesis_commitment, current_commitment,
              naive_single_cap, naive_spent_total, naive_epoch_spent, naive_epoch,
              in_flight_lease_id, in_flight_acquired_at, seq_counter,
              created_at, updated_at, last_accessed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?)`,
          )
          .run(
            sandboxId,
            scopeType,
            init.policyRoot.toString(10),
            JSON.stringify(toStoredVendors(init.allowlist)),
            init.epochCap.toString(10),
            init.payrollFloor.toString(10),
            init.policySalt.toString(10),
            init.balance.toString(10),
            "0",
            init.epoch.toString(10),
            init.currentSalt.toString(10),
            init.genesisCommitment.toString(10),
            init.genesisCommitment.toString(10),
            init.naiveSingleCap.toString(10),
            "0",
            "0",
            init.epoch.toString(10),
            now,
            now,
            now,
          );
      } else {
        this.db
          .prepare(
            `UPDATE sandboxes SET
              policy_root = ?,
              allowlist_json = ?,
              epoch_cap = ?,
              payroll_floor = ?,
              policy_salt = ?,
              balance = ?,
              spent_so_far = '0',
              current_epoch = ?,
              current_salt = ?,
              genesis_commitment = ?,
              current_commitment = ?,
              naive_single_cap = ?,
              naive_spent_total = '0',
              naive_epoch_spent = '0',
              naive_epoch = ?,
              in_flight_lease_id = NULL,
              in_flight_acquired_at = NULL,
              seq_counter = 0,
              updated_at = ?,
              last_accessed_at = ?
            WHERE sandbox_id = ?`,
          )
          .run(
            init.policyRoot.toString(10),
            JSON.stringify(toStoredVendors(init.allowlist)),
            init.epochCap.toString(10),
            init.payrollFloor.toString(10),
            init.policySalt.toString(10),
            init.balance.toString(10),
            init.epoch.toString(10),
            init.currentSalt.toString(10),
            init.genesisCommitment.toString(10),
            init.genesisCommitment.toString(10),
            init.naiveSingleCap.toString(10),
            init.epoch.toString(10),
            now,
            now,
            sandboxId,
          );
      }

      const row = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(sandboxId) as Record<string, unknown>;
      return parseSandboxRow(row);
    });
  }

  public getSandboxSnapshot(sandboxId: string): SandboxSnapshot {
    const row = this.db
      .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
      .get(sandboxId) as Record<string, unknown> | undefined;
    if (row === undefined) {
      throw new Error(`Sandbox ${sandboxId} does not exist`);
    }
    return parseSandboxRow(row);
  }

  public countDemoSandboxes(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS cnt FROM sandboxes WHERE scope_type = 'demo'")
      .get() as Record<string, unknown> | undefined;
    return Number(row?.cnt ?? 0);
  }

  public tryAcquireInFlightLease(params: {
    readonly sandboxId: string;
    readonly scopeType?: SandboxScopeType;
    readonly recipientField: bigint;
    readonly amount: bigint;
    readonly epoch: bigint;
    readonly invoiceIdField: bigint;
  }): LeaseAcquireResult {
    return this.runImmediate(() => {
      const now = Date.now();
      let row = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(params.sandboxId) as Record<string, unknown> | undefined;

      if (row === undefined) {
        const scope = params.scopeType ?? (params.sandboxId === "competition" ? "competition" : "demo");
        if (scope === "demo") {
          this.evictExcessDemoSandboxes();
        }
        const init = this.buildGenesisValues();
        this.db
          .prepare(
            `INSERT INTO sandboxes (
              sandbox_id, scope_type, policy_root, allowlist_json,
              epoch_cap, payroll_floor, policy_salt, balance,
              spent_so_far, current_epoch, current_salt,
              genesis_commitment, current_commitment,
              naive_single_cap, naive_spent_total, naive_epoch_spent, naive_epoch,
              in_flight_lease_id, in_flight_acquired_at, seq_counter,
              created_at, updated_at, last_accessed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?)`,
          )
          .run(
            params.sandboxId,
            scope,
            init.policyRoot.toString(10),
            JSON.stringify(toStoredVendors(init.allowlist)),
            init.epochCap.toString(10),
            init.payrollFloor.toString(10),
            init.policySalt.toString(10),
            init.balance.toString(10),
            "0",
            init.epoch.toString(10),
            init.currentSalt.toString(10),
            init.genesisCommitment.toString(10),
            init.genesisCommitment.toString(10),
            init.naiveSingleCap.toString(10),
            "0",
            "0",
            init.epoch.toString(10),
            now,
            now,
            now,
          );
        row = this.db
          .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
          .get(params.sandboxId) as Record<string, unknown>;
      }

      const sandbox = parseSandboxRow(row);
      if (sandbox.inFlightLeaseId !== null) {
        return {
          status: "lease_held",
          heldLeaseId: sandbox.inFlightLeaseId,
          heldAt: sandbox.inFlightAcquiredAt ?? now,
        };
      }

      const activeInvoiceRows = this.db
        .prepare(
          `SELECT invoice_hash FROM outbox_transitions
           WHERE sandbox_id = ? AND status != 'ROLLED_BACK'`,
        )
        .all(params.sandboxId) as Record<string, unknown>[];
      const knownInvoiceHashes = new Set<string>(
        activeInvoiceRows.map((r) => String(r.invoice_hash)),
      );

      const newSalt = randomSaltBigInt();
      const shadow = evaluatePolicyShadow({
        allowlistRecipients: sandbox.allowlist.map((v) => BigInt(v.recipientField)),
        epochCap: BigInt(sandbox.epochCap),
        payrollFloor: BigInt(sandbox.payrollFloor),
        policySalt: BigInt(sandbox.policySalt),
        balance: BigInt(sandbox.balance),
        spentSoFar: BigInt(sandbox.spentSoFar),
        prevEpoch: BigInt(sandbox.currentEpoch),
        prevSalt: BigInt(sandbox.currentSalt),
        recipient: params.recipientField,
        amount: params.amount,
        epoch: params.epoch,
        invoiceIdField: params.invoiceIdField,
        newSalt,
        knownInvoiceHashes,
      });

      if (!shadow.ok) {
        return {
          status: "policy_rejected",
          shadow,
        };
      }

      const leaseId = `lease_${crypto.randomUUID()}`;
      this.db
        .prepare(
          `UPDATE sandboxes
           SET in_flight_lease_id = ?, in_flight_acquired_at = ?, last_accessed_at = ?
           WHERE sandbox_id = ?`,
        )
        .run(leaseId, now, now, params.sandboxId);

      return {
        status: "acquired",
        leaseId,
        sandbox,
        shadow,
        newSalt,
        nextSeq: sandbox.seqCounter + 1,
      };
    });
  }

  public releaseLeaseOnly(sandboxId: string, leaseId: string): boolean {
    return this.runImmediate(() => {
      const res = this.db
        .prepare(
          `UPDATE sandboxes
           SET in_flight_lease_id = NULL, in_flight_acquired_at = NULL
           WHERE sandbox_id = ? AND in_flight_lease_id = ?`,
        )
        .run(sandboxId, leaseId);
      return Number(res.changes) > 0;
    });
  }

  public insertOutboxPending(params: {
    readonly outboxId: string;
    readonly sandboxId: string;
    readonly leaseId: string;
    readonly seq: number;
    readonly prevCommitment: string;
    readonly newCommitment: string;
    readonly recipient: string;
    readonly vendorName: string;
    readonly amount: string;
    readonly epoch: string;
    readonly invoiceId: string;
    readonly invoiceHash: string;
    readonly newSpent: string;
    readonly newSalt: string;
    readonly provenanceMode: "LIVE" | "DETERMINISTIC_REPLAY";
    readonly proofJson: string;
    readonly publicSignalsJson: string;
    readonly publicSignalsArrayJson: string;
  }): void {
    this.runImmediate(() => {
      const now = Date.now();
      const sbx = this.db
        .prepare("SELECT in_flight_lease_id FROM sandboxes WHERE sandbox_id = ?")
        .get(params.sandboxId) as Record<string, unknown> | undefined;
      if (sbx?.in_flight_lease_id !== params.leaseId) {
        throw new Error("IN_FLIGHT_LEASE_LOST");
      }

      this.db
        .prepare(
          `INSERT INTO outbox_transitions (
            id, sandbox_id, seq, prev_commitment, new_commitment,
            recipient, vendor_name, amount, epoch, invoice_id, invoice_hash,
            new_spent, new_salt, status, provenance_mode,
            job_id, tx_hash, block_hash, tx_explorer_url, block_explorer_url,
            proof_json, public_signals_json, public_signals_array_json,
            error_message, retry_count, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_SUBMIT', ?, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, NULL, 0, ?, ?)`,
        )
        .run(
          params.outboxId,
          params.sandboxId,
          params.seq,
          params.prevCommitment,
          params.newCommitment,
          params.recipient,
          params.vendorName,
          params.amount,
          params.epoch,
          params.invoiceId,
          params.invoiceHash,
          params.newSpent,
          params.newSalt,
          params.provenanceMode,
          params.proofJson,
          params.publicSignalsJson,
          params.publicSignalsArrayJson,
          now,
          now,
        );
    });
  }

  public commitOutboxSubmissionAndReleaseLease(params: {
    readonly outboxId: string;
    readonly sandboxId: string;
    readonly leaseId: string;
    readonly seq: number;
    readonly newCommitment: string;
    readonly newSpent: string;
    readonly newEpoch: string;
    readonly newSalt: string;
    readonly status: "SUBMITTED" | "FINALIZED";
    readonly jobId: string | null;
    readonly txHash: string | null;
    readonly blockHash: string | null;
    readonly txExplorerUrl: string | null;
    readonly blockExplorerUrl: string | null;
  }): void {
    this.runImmediate(() => {
      const now = Date.now();
      const sbx = this.db
        .prepare("SELECT in_flight_lease_id FROM sandboxes WHERE sandbox_id = ?")
        .get(params.sandboxId) as Record<string, unknown> | undefined;
      if (sbx?.in_flight_lease_id !== params.leaseId) {
        throw new Error("IN_FLIGHT_LEASE_LOST");
      }

      this.db
        .prepare(
          `UPDATE outbox_transitions SET
            status = ?,
            job_id = ?,
            tx_hash = ?,
            block_hash = ?,
            tx_explorer_url = ?,
            block_explorer_url = ?,
            updated_at = ?
          WHERE id = ? AND sandbox_id = ?`,
        )
        .run(
          params.status,
          params.jobId,
          params.txHash,
          params.blockHash,
          params.txExplorerUrl,
          params.blockExplorerUrl,
          now,
          params.outboxId,
          params.sandboxId,
        );

      this.db
        .prepare(
          `UPDATE sandboxes SET
            current_commitment = ?,
            spent_so_far = ?,
            current_epoch = ?,
            current_salt = ?,
            seq_counter = ?,
            in_flight_lease_id = NULL,
            in_flight_acquired_at = NULL,
            updated_at = ?,
            last_accessed_at = ?
          WHERE sandbox_id = ? AND in_flight_lease_id = ?`,
        )
        .run(
          params.newCommitment,
          params.newSpent,
          params.newEpoch,
          params.newSalt,
          params.seq,
          now,
          now,
          params.sandboxId,
          params.leaseId,
        );
    });
  }

  public rollbackOutboxAndReleaseLease(params: {
    readonly outboxId: string;
    readonly sandboxId: string;
    readonly leaseId: string;
    readonly errorMessage: string;
  }): void {
    this.runImmediate(() => {
      const now = Date.now();
      const safeMsg = scrubKurierText(params.errorMessage, this.scrubKey);
      this.db
        .prepare(
          `UPDATE outbox_transitions SET
            status = 'ROLLED_BACK',
            error_message = ?,
            updated_at = ?
          WHERE id = ? AND sandbox_id = ?`,
        )
        .run(safeMsg, now, params.outboxId, params.sandboxId);

      this.db
        .prepare(
          `UPDATE sandboxes SET
            in_flight_lease_id = NULL,
            in_flight_acquired_at = NULL,
            updated_at = ?
          WHERE sandbox_id = ? AND in_flight_lease_id = ?`,
        )
        .run(now, params.sandboxId, params.leaseId);
    });
  }

  public updateOutboxKurierStatus(params: {
    readonly outboxId: string;
    readonly sandboxId: string;
    readonly status: "SUBMITTED" | "INCLUDED_IN_BLOCK" | "FINALIZED";
    readonly txHash: string | null;
    readonly blockHash: string | null;
    readonly txExplorerUrl: string | null;
    readonly blockExplorerUrl: string | null;
    readonly amount: string;
    readonly jobId: string | null;
  }): void {
    this.runImmediate(() => {
      const now = Date.now();
      this.db
        .prepare(
          `UPDATE outbox_transitions SET
            status = ?,
            tx_hash = COALESCE(?, tx_hash),
            block_hash = COALESCE(?, block_hash),
            tx_explorer_url = COALESCE(?, tx_explorer_url),
            block_explorer_url = COALESCE(?, block_explorer_url),
            updated_at = ?
          WHERE id = ? AND status != 'ROLLED_BACK'`,
        )
        .run(
          params.status,
          params.txHash,
          params.blockHash,
          params.txExplorerUrl,
          params.blockExplorerUrl,
          now,
          params.outboxId,
        );

      if (params.status === "FINALIZED" && params.txHash !== null && params.txExplorerUrl !== null) {
        const existingLink = this.db
          .prepare("SELECT id FROM historical_mainnet_links WHERE id = ?")
          .get(params.outboxId);
        if (existingLink === undefined) {
          this.db
            .prepare(
              `INSERT INTO historical_mainnet_links (
                id, sandbox_id, tx_hash, tx_explorer_url, job_id, amount, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              params.outboxId,
              params.sandboxId,
              params.txHash,
              params.txExplorerUrl,
              params.jobId,
              params.amount,
              now,
            );
        }
      }
    });
  }

  public recordNaiveDecision(params: {
    readonly sandboxId: string;
    readonly vendorName: string;
    readonly recipientAddress: string;
    readonly amount: bigint;
    readonly epoch: bigint;
    readonly invoiceId: string;
    readonly memo: string | null;
  }): NaiveLedgerEntry {
    return this.runImmediate(() => {
      const now = Date.now();
      const sbxRow = this.db
        .prepare("SELECT * FROM sandboxes WHERE sandbox_id = ?")
        .get(params.sandboxId) as Record<string, unknown> | undefined;
      if (sbxRow === undefined) {
        throw new Error(`Sandbox ${params.sandboxId} not found for naive execution`);
      }

      const singleCap = BigInt(String(sbxRow.naive_single_cap));
      const prevEpoch = BigInt(String(sbxRow.naive_epoch));
      const prevEpochSpent = BigInt(String(sbxRow.naive_epoch_spent));
      const prevTotal = BigInt(String(sbxRow.naive_spent_total));

      const approved = params.amount >= 0n && params.amount <= singleCap;
      const reasonCode = approved ? "NAIVE_SINGLE_CAP_PASS" : "NAIVE_SINGLE_CAP_EXCEEDED";

      const countRow = this.db
        .prepare("SELECT COUNT(*) AS cnt FROM naive_ledger_entries WHERE sandbox_id = ?")
        .get(params.sandboxId) as Record<string, unknown> | undefined;
      const seq = Number(countRow?.cnt ?? 0) + 1;
      const entryId = `naive_${crypto.randomUUID()}`;

      if (approved) {
        const nextTotal = prevTotal + params.amount;
        const nextEpochSpent =
          params.epoch === prevEpoch ? prevEpochSpent + params.amount : params.amount;
        this.db
          .prepare(
            `UPDATE sandboxes SET
              naive_spent_total = ?,
              naive_epoch_spent = ?,
              naive_epoch = ?,
              updated_at = ?
            WHERE sandbox_id = ?`,
          )
          .run(
            nextTotal.toString(10),
            nextEpochSpent.toString(10),
            params.epoch.toString(10),
            now,
            params.sandboxId,
          );
      }

      this.db
        .prepare(
          `INSERT INTO naive_ledger_entries (
            id, sandbox_id, seq, vendor_name, recipient_address,
            amount, epoch, invoice_id, approved, reason_code, memo, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          entryId,
          params.sandboxId,
          seq,
          params.vendorName,
          params.recipientAddress,
          params.amount.toString(10),
          params.epoch.toString(10),
          params.invoiceId,
          approved ? 1 : 0,
          reasonCode,
          params.memo,
          now,
        );

      return {
        id: entryId,
        sandboxId: params.sandboxId,
        seq,
        vendorName: params.vendorName,
        recipientAddress: params.recipientAddress,
        amount: params.amount.toString(10),
        epoch: params.epoch.toString(10),
        invoiceId: params.invoiceId,
        approved,
        reasonCode,
        memo: params.memo,
        createdAt: new Date(now).toISOString(),
      };
    });
  }

  public getNaiveEntries(sandboxId: string): NaiveLedgerEntry[] {
    const rows = this.db
      .prepare("SELECT * FROM naive_ledger_entries WHERE sandbox_id = ? ORDER BY seq ASC")
      .all(sandboxId) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: String(r.id),
      sandboxId: String(r.sandbox_id),
      seq: Number(r.seq),
      vendorName: String(r.vendor_name),
      recipientAddress: String(r.recipient_address),
      amount: String(r.amount),
      epoch: String(r.epoch),
      invoiceId: String(r.invoice_id),
      approved: Number(r.approved) === 1,
      reasonCode: String(r.reason_code),
      memo: r.memo === null ? null : String(r.memo),
      createdAt: new Date(Number(r.created_at)).toISOString(),
    }));
  }

  public getReceipts(sandboxId: string): TreasuryReceipt[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM outbox_transitions
         WHERE sandbox_id = ? AND status != 'ROLLED_BACK'
         ORDER BY seq ASC`,
      )
      .all(sandboxId) as Record<string, unknown>[];

    return rows.map((r) => {
      const provenanceMode =
        r.provenance_mode === "LIVE" ? ("LIVE" as const) : ("DETERMINISTIC_REPLAY" as const);
      const statusStr = String(r.status);
      const humanStatus =
        statusStr === "FINALIZED"
          ? "Finalized"
          : statusStr === "INCLUDED_IN_BLOCK"
            ? "IncludedInBlock"
            : statusStr === "SUBMITTED"
              ? "Submitted"
              : "PendingSubmit";

      return {
        receiptId: String(r.id),
        sandboxId: String(r.sandbox_id),
        seq: Number(r.seq),
        vendorName: String(r.vendor_name),
        invoiceId: String(r.invoice_id),
        proof: JSON.parse(String(r.proof_json)) as TreasuryReceipt["proof"],
        publicSignals: JSON.parse(String(r.public_signals_json)) as TreasuryReceipt["publicSignals"],
        publicSignalsArray: JSON.parse(String(r.public_signals_array_json)) as string[],
        provenance: {
          mode: provenanceMode,
          network: "zkverify-mainnet",
          vkHash: REGISTERED_VK_HASH,
          jobId: r.job_id === null ? null : String(r.job_id),
          txHash: r.tx_hash === null ? null : String(r.tx_hash),
          blockHash: r.block_hash === null ? null : String(r.block_hash),
          txExplorerUrl: r.tx_explorer_url === null ? null : String(r.tx_explorer_url),
          blockExplorerUrl: r.block_explorer_url === null ? null : String(r.block_explorer_url),
          status: humanStatus,
          ...(provenanceMode === "DETERMINISTIC_REPLAY"
            ? {
                note: "Offline replay cassette (Gate 01 Mainnet attestation attached; local Groth16 verified)",
              }
            : {}),
        },
        createdAt: new Date(Number(r.created_at)).toISOString(),
        settledAt: statusStr === "FINALIZED" ? new Date(Number(r.updated_at)).toISOString() : null,
      };
    });
  }

  public getActiveOutboxLinks(
    sandboxId: string,
  ): Array<{
    readonly prevCommitment: string;
    readonly newCommitment: string;
    readonly invoiceHash: string;
  }> {
    const rows = this.db
      .prepare(
        `SELECT prev_commitment, new_commitment, invoice_hash
         FROM outbox_transitions
         WHERE sandbox_id = ? AND status != 'ROLLED_BACK'
         ORDER BY seq ASC`,
      )
      .all(sandboxId) as Record<string, unknown>[];
    return rows.map((r) => ({
      prevCommitment: String(r.prev_commitment),
      newCommitment: String(r.new_commitment),
      invoiceHash: String(r.invoice_hash),
    }));
  }

  public getHistoricalMainnetLinks(sandboxId: string): MainnetExplorerLink[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM historical_mainnet_links
         WHERE sandbox_id = ?
         ORDER BY created_at DESC LIMIT 20`,
      )
      .all(sandboxId) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: String(r.id),
      sandboxId: String(r.sandbox_id),
      txHash: String(r.tx_hash),
      txExplorerUrl: String(r.tx_explorer_url),
      jobId: r.job_id === null ? null : String(r.job_id),
      amount: String(r.amount),
      createdAt: new Date(Number(r.created_at)).toISOString(),
    }));
  }

  public recordHistoricalMainnetLink(params: {
    readonly id: string;
    readonly sandboxId: string;
    readonly txHash: string;
    readonly txExplorerUrl: string;
    readonly jobId: string | null;
    readonly amount: string;
  }): void {
    this.runImmediate(() => {
      const existing = this.db
        .prepare("SELECT id FROM historical_mainnet_links WHERE id = ?")
        .get(params.id);
      if (existing !== undefined) {
        return;
      }
      this.db
        .prepare(
          `INSERT INTO historical_mainnet_links (
            id, sandbox_id, tx_hash, tx_explorer_url, job_id, amount, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          params.id,
          params.sandboxId,
          params.txHash,
          params.txExplorerUrl,
          params.jobId,
          params.amount,
          Date.now(),
        );
    });
  }

  public getIdempotencyRecord(taskId: string): IdempotencyRecord | null {
    const row = this.db
      .prepare("SELECT * FROM agent_idempotency WHERE task_id = ?")
      .get(taskId) as Record<string, unknown> | undefined;
    if (row === undefined) {
      return null;
    }
    return {
      taskId: String(row.task_id),
      rawBodySha256: String(row.raw_body_sha256),
      statusCode: Number(row.status_code),
      responseJson: String(row.response_json),
      createdAt: Number(row.created_at),
    };
  }

  public saveIdempotencyRecord(record: IdempotencyRecord): void {
    if (record.statusCode >= 500) {
      return;
    }
    this.runImmediate(() => {
      this.db
        .prepare(
          `INSERT OR IGNORE INTO agent_idempotency (
            task_id, raw_body_sha256, status_code, response_json, created_at
          ) VALUES (?, ?, ?, ?, ?)`,
        )
        .run(
          record.taskId,
          record.rawBodySha256,
          record.statusCode,
          record.responseJson,
          record.createdAt,
        );
    });
  }

  public getCachedIntent(cacheKey: string): string | null {
    const row = this.db
      .prepare("SELECT intent_json FROM intent_cache WHERE cache_key = ?")
      .get(cacheKey) as Record<string, unknown> | undefined;
    return row === undefined ? null : String(row.intent_json);
  }

  public saveCachedIntent(cacheKey: string, intentJson: string): void {
    this.runImmediate(() => {
      this.db
        .prepare(
          `INSERT OR REPLACE INTO intent_cache (cache_key, intent_json, created_at)
           VALUES (?, ?, ?)`,
        )
        .run(cacheKey, intentJson, Date.now());

      const countRow = this.db
        .prepare("SELECT COUNT(*) AS cnt FROM intent_cache")
        .get() as Record<string, unknown> | undefined;
      const count = Number(countRow?.cnt ?? 0);
      if (count > 500) {
        this.db
          .prepare(
            `DELETE FROM intent_cache WHERE cache_key IN (
               SELECT cache_key FROM intent_cache ORDER BY created_at ASC LIMIT ?
             )`,
          )
          .run(count - 500);
      }
    });
  }

  public recordDiagnosticEvent(
    eventType:
      | "invariant_drift"
      | "kurier_error"
      | "lease_contention"
      | "deadline_abort"
      | "llm_fallback",
    detail: string,
  ): void {
    const safeDetail = scrubKurierText(detail, this.scrubKey);
    this.runImmediate(() => {
      this.db
        .prepare(
          `INSERT INTO diagnostics_events (event_type, detail, created_at)
           VALUES (?, ?, ?)`,
        )
        .run(eventType, safeDetail, Date.now());
    });
  }

  public getDiagnosticsSummary(): DiagnosticsSummary {
    const totalSbx = Number(
      (this.db.prepare("SELECT COUNT(*) AS c FROM sandboxes").get() as Record<string, unknown>)?.c ??
        0,
    );
    const demoSbx = Number(
      (
        this.db
          .prepare("SELECT COUNT(*) AS c FROM sandboxes WHERE scope_type = 'demo'")
          .get() as Record<string, unknown>
      )?.c ?? 0,
    );
    const activeLeases = Number(
      (
        this.db
          .prepare("SELECT COUNT(*) AS c FROM sandboxes WHERE in_flight_lease_id IS NOT NULL")
          .get() as Record<string, unknown>
      )?.c ?? 0,
    );

    const outboxCounts: Record<OutboxStatus, number> = {
      PENDING_SUBMIT: 0,
      SUBMITTED: 0,
      INCLUDED_IN_BLOCK: 0,
      FINALIZED: 0,
      ROLLED_BACK: 0,
    };

    const grouped = this.db
      .prepare("SELECT status, COUNT(*) AS c FROM outbox_transitions GROUP BY status")
      .all() as Record<string, unknown>[];
    for (const g of grouped) {
      const st = String(g.status) as OutboxStatus;
      if (st in outboxCounts) {
        outboxCounts[st] = Number(g.c);
      }
    }

    const driftCount = Number(
      (
        this.db
          .prepare("SELECT COUNT(*) AS c FROM diagnostics_events WHERE event_type = 'invariant_drift'")
          .get() as Record<string, unknown>
      )?.c ?? 0,
    );

    const events = this.db
      .prepare("SELECT event_type, detail, created_at FROM diagnostics_events ORDER BY id DESC LIMIT 10")
      .all() as Record<string, unknown>[];

    return {
      totalSandboxes: totalSbx,
      demoSandboxes: demoSbx,
      activeLeases,
      outboxCounts,
      invariantDriftCount: driftCount,
      recentEvents: events.map((e) => ({
        eventType: String(e.event_type),
        detail: scrubKurierText(String(e.detail), this.scrubKey),
        createdAt: new Date(Number(e.created_at)).toISOString(),
      })),
    };
  }
}
