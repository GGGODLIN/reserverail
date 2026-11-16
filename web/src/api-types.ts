import type { AuditChainVerificationResult, TreasuryReceipt } from "../../src/engine/audit-chain.ts";
import type { RelayMode } from "./model/workbench-model.ts";

export type { AuditChainVerificationResult, TreasuryReceipt };

export interface AllowlistVendor {
  readonly name: string;
  readonly address: string;
  readonly recipientField: string;
}

export interface CfoView {
  readonly balance: string;
  readonly payrollFloor: string;
  readonly epochCap: string;
  readonly spentSoFar: string;
  readonly epoch: string;
  readonly naiveSingleCap: string;
  readonly naiveSpentTotal: string;
  readonly naiveEpochSpent: string;
  readonly allowlist: readonly AllowlistVendor[];
}

export interface AuditorView {
  readonly policyRoot: string;
  readonly genesisCommitment: string;
  readonly currentCommitment: string;
  readonly vkHash: string;
}

export interface MainnetLink {
  readonly id: string;
  readonly txHash: string;
  readonly txExplorerUrl: string;
  readonly amount: string;
}

export interface DemoState {
  readonly sandboxId: string;
  readonly relayMode: RelayMode;
  readonly cfoView: CfoView;
  readonly auditorView: AuditorView;
  readonly receipts: readonly TreasuryReceipt[];
  readonly mainnetExplorerLinks: readonly MainnetLink[];
  readonly auditChain: AuditChainVerificationResult;
}

export interface PaymentIntentView {
  readonly vendorName: string;
  readonly recipientAddress: string;
  readonly amount: string;
  readonly epoch: string;
  readonly invoiceId: string;
  readonly memo: string | null;
  readonly parserSource: string;
}

export interface NaiveResult {
  readonly approved: boolean;
  readonly reasonCode: string;
}

export interface ReserveRailResult {
  readonly approved: boolean;
  readonly reasonCode: string;
  readonly errorMessage?: string;
  readonly seq?: number;
  readonly receipt?: TreasuryReceipt;
  readonly staleProvesAttempted: number;
  readonly reEvaluatedAfterLease: boolean;
}

export interface DemoStep {
  readonly intent: PaymentIntentView;
  readonly naiveResult: NaiveResult;
  readonly reserveRailResult: ReserveRailResult;
}

export interface ActResponse {
  readonly steps: readonly DemoStep[];
  readonly state: DemoState;
}

export interface ProposeResponse extends DemoStep {
  readonly state: DemoState;
}

export interface ResetResponse {
  readonly state: DemoState;
}

export interface TamperResponse {
  readonly localVerified: boolean;
  readonly kurierAttempted: boolean;
  readonly kurierRejected: boolean | null;
  readonly optimisticVerify: string;
  readonly reason: string;
}

export type ServerActId = "act1_injection" | "act2_structuring" | "act3_concurrency";

export interface ProposalBody {
  readonly actId?: "act1_legit";
  readonly recipient?: string;
  readonly amount?: string;
  readonly memo?: string;
  readonly invoiceId?: string;
}
