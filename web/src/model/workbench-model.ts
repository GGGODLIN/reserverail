import type { TreasuryReceipt } from "../../../src/engine/audit-chain.ts";

export type RelayMode = "LIVE" | "DETERMINISTIC_REPLAY";

export const RECEIPT_STAGES = ["Local Verified", "Kurier Submitted", "IncludedInBlock", "Finalized"] as const;
export type ReceiptStage = (typeof RECEIPT_STAGES)[number];
export type StageState = "complete" | "pending";

export interface StageProgress {
  readonly stage: ReceiptStage;
  readonly state: StageState;
}

// How many stages a receipt status has reached; a receipt only exists once its proof verified locally.
const STAGES_REACHED: Readonly<Record<string, number>> = {
  PendingSubmit: 1,
  Submitted: 2,
  IncludedInBlock: 3,
  Finalized: 4,
};

export function receiptStageProgress(receiptStatus: string): readonly StageProgress[] {
  const reached = STAGES_REACHED[receiptStatus] ?? 1;
  return RECEIPT_STAGES.map((stage, index) => ({ stage, state: index < reached ? "complete" : "pending" }));
}

export function isFinalReceiptStatus(receiptStatus: string): boolean {
  return receiptStatus === "Finalized";
}

const FIELD_HEX = /^0x[0-9a-fA-F]{64}$/;

export function abbreviateHex(value: string): string {
  return FIELD_HEX.test(value) ? `${value.slice(0, 6)}...${value.slice(-4)}` : value;
}

export function fieldToHex(decimalField: string): string {
  return `0x${BigInt(decimalField).toString(16).padStart(64, "0")}`;
}

const SUBSCRIPT_DIGITS = "₀₁₂₃₄₅₆₇₈₉";

export function commitmentLabel(index: number): string {
  return `C${[...String(index)].map((digit) => SUBSCRIPT_DIGITS[Number(digit)]).join("")}`;
}

export function formatAmount(decimal: string): string {
  return BigInt(decimal).toLocaleString("en-US");
}

export interface PrivateWitnessBounds {
  readonly balance: string;
  readonly payrollFloor: string;
  readonly epochCap: string;
  readonly spentSoFar: string;
}

export type CircuitPreview = "WITHIN_BOUNDS" | "EPOCH_CAP_EXCEEDED" | "PAYROLL_FLOOR_BREACH";

export interface SpendHeadroom {
  readonly maxAmount: bigint;
  readonly binding: "EPOCH_SPEND_CAP" | "PAYROLL_RESERVE_FLOOR";
}

export function spendHeadroom(bounds: PrivateWitnessBounds): SpendHeadroom {
  const spent = BigInt(bounds.spentSoFar);
  const capRoom = BigInt(bounds.epochCap) - spent;
  const floorRoom = BigInt(bounds.balance) - BigInt(bounds.payrollFloor) - spent;
  const floorBinds = floorRoom < capRoom;
  const room = floorBinds ? floorRoom : capRoom;
  return { maxAmount: room > 0n ? room : 0n, binding: floorBinds ? "PAYROLL_RESERVE_FLOOR" : "EPOCH_SPEND_CAP" };
}

// Mirrors the circuit's check order (cap before floor), so the preview names the code the prover would hit.
export function previewCircuitOutcome(bounds: PrivateWitnessBounds, amount: bigint): CircuitPreview {
  const newSpent = BigInt(bounds.spentSoFar) + amount;
  if (newSpent > BigInt(bounds.epochCap)) {
    return "EPOCH_CAP_EXCEEDED";
  }
  if (newSpent + BigInt(bounds.payrollFloor) > BigInt(bounds.balance)) {
    return "PAYROLL_FLOOR_BREACH";
  }
  return "WITHIN_BOUNDS";
}

export type ConfidentialField = "balance" | "payrollFloor" | "epochCap";

const CONFIDENTIAL_FIELDS: readonly ConfidentialField[] = ["balance", "payrollFloor", "epochCap"];

function canonicalDecimal(value: string): string {
  try {
    return BigInt(value).toString(10);
  } catch {
    return value;
  }
}

export function confidentialFieldsInSignals(
  bounds: Pick<PrivateWitnessBounds, ConfidentialField>,
  publicSignals: readonly string[],
): readonly ConfidentialField[] {
  const published = new Set(publicSignals.map(canonicalDecimal));
  return CONFIDENTIAL_FIELDS.filter((field) => published.has(canonicalDecimal(bounds[field])));
}

// Changes the amount in both encodings so the Audit Chain reports the forged proof, not a format mismatch.
export function withTamperedAmount(receipt: TreasuryReceipt, amount: string): TreasuryReceipt {
  const publicSignalsArray = receipt.publicSignalsArray.map((signal, index) => (index === 4 ? amount : signal));
  return { ...receipt, publicSignals: { ...receipt.publicSignals, amount }, publicSignalsArray };
}

export interface ScopeTicket {
  readonly generation: number;
  readonly sandboxId: string | null;
}

export interface ScopedView<Snapshot extends { readonly sandboxId: string }, Run> {
  readonly generation: number;
  readonly sandboxId: string | null;
  readonly snapshot: Snapshot | null;
  readonly run: Run | null;
  readonly error: string | null;
}

export function createScopedView<Snapshot extends { readonly sandboxId: string }, Run>(
  sandboxId: string | null,
): ScopedView<Snapshot, Run> {
  return { generation: 0, sandboxId, snapshot: null, run: null, error: null };
}

// Reset and scope switches both start a new generation: anything still in flight belongs to the old one.
export function enterScope<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
  sandboxId: string | null,
): ScopedView<Snapshot, Run> {
  return { generation: view.generation + 1, sandboxId, snapshot: null, run: null, error: null };
}

export function ticketOf<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
): ScopeTicket {
  return { generation: view.generation, sandboxId: view.sandboxId };
}

export function isCurrentScope<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
  ticket: ScopeTicket,
): boolean {
  return ticket.generation === view.generation;
}

export function acceptSnapshot<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
  ticket: ScopeTicket,
  snapshot: Snapshot,
): ScopedView<Snapshot, Run> {
  if (!isCurrentScope(view, ticket)) {
    return view;
  }
  // A scope waiting for its server-assigned id adopts the first answer; afterwards the id is fixed.
  if (view.sandboxId !== null && snapshot.sandboxId !== view.sandboxId) {
    return view;
  }
  return { ...view, sandboxId: snapshot.sandboxId, snapshot };
}

export function acceptRun<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
  ticket: ScopeTicket,
  run: Run,
): ScopedView<Snapshot, Run> {
  return isCurrentScope(view, ticket) ? { ...view, run } : view;
}

export function acceptError<Snapshot extends { readonly sandboxId: string }, Run>(
  view: ScopedView<Snapshot, Run>,
  ticket: ScopeTicket,
  message: string | null,
): ScopedView<Snapshot, Run> {
  return isCurrentScope(view, ticket) ? { ...view, error: message } : view;
}
