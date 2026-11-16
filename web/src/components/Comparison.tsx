import type { CfoView, DemoStep, PaymentIntentView, TreasuryReceipt } from "../api-types.ts";
import {
  abbreviateHex,
  commitmentLabel,
  formatAmount,
  receiptStageProgress,
} from "../model/workbench-model.ts";

interface IntentCardProps {
  readonly intent: PaymentIntentView;
  readonly step: number;
}

// Rendered from the same parsed intent in both columns, so the comparison is about policy, not parsing.
function IntentCard({ intent, step }: IntentCardProps) {
  return (
    <div role="group" aria-label={`Payment intent, step ${step}`} className="intent">
      <dl>
        <div>
          <dt>Vendor</dt>
          <dd>{intent.vendorName}</dd>
        </div>
        <div>
          <dt>Amount</dt>
          <dd className="mono">
            {formatAmount(intent.amount)} · epoch {intent.epoch}
          </dd>
        </div>
        <div className="intent-wide">
          <dt>Recipient</dt>
          <dd className="mono wrap">{intent.recipientAddress}</dd>
        </div>
        <div>
          <dt>Invoice</dt>
          <dd className="mono wrap">{intent.invoiceId}</dd>
        </div>
        <div>
          <dt>Parsed by</dt>
          <dd>{intent.parserSource}</dd>
        </div>
      </dl>
      {intent.memo !== null ? <p className="memo">“{intent.memo}”</p> : null}
    </div>
  );
}

function ReceiptStatus({ receipt }: { readonly receipt: TreasuryReceipt }) {
  const replay = receipt.provenance.mode === "DETERMINISTIC_REPLAY";
  const txHash = receipt.provenance.txHash;
  return (
    <div className="receipt">
      <p className="provenance">
        <strong className={replay ? "badge badge-replay" : "badge badge-live"}>{receipt.provenance.mode}</strong>
        <span>
          {replay ? "Offline relay fallback · Gate 01 mainnet attestation" : "Live relay · zkVerify Mainnet via Kurier"}
        </span>
      </p>
      <ol className="stages" aria-label="Receipt stages">
        {receiptStageProgress(receipt.provenance.status).map((progress) => (
          <li key={progress.stage} className={`stage stage-${progress.state}`}>
            {progress.stage} <span className="visually-hidden">{progress.state}</span>
          </li>
        ))}
      </ol>
      {receipt.provenance.txExplorerUrl !== null && txHash !== null ? (
        <a className="tx-link" href={receipt.provenance.txExplorerUrl} target="_blank" rel="noreferrer">
          tx {abbreviateHex(txHash)}
        </a>
      ) : null}
    </div>
  );
}

interface ColumnProps {
  readonly steps: readonly DemoStep[];
  readonly cfo: CfoView | null;
}

function EmptySteps() {
  return <p className="empty">No steps yet. Run an act or propose a payment.</p>;
}

function NaiveColumn({ steps, cfo }: ColumnProps) {
  const reserveLeft = cfo === null ? null : BigInt(cfo.balance) - BigInt(cfo.naiveEpochSpent);
  return (
    <section className="column column-naive" aria-labelledby="naive-heading">
      <header className="column-head">
        <h2 id="naive-heading">Naive agent</h2>
        <p className="column-sub">
          Single-payment cap {cfo === null ? "…" : formatAmount(cfo.naiveSingleCap)} · no proof · no reserve check
        </p>
      </header>
      {steps.length === 0 ? (
        <EmptySteps />
      ) : (
        <ol className="steps">
          {steps.map((step, index) => (
            <li key={step.intent.invoiceId}>
              <article aria-label={`Step ${index + 1}`} className="step">
                <IntentCard intent={step.intent} step={index + 1} />
                <p className={step.naiveResult.approved ? "verdict verdict-ok" : "verdict verdict-no"}>
                  {step.naiveResult.approved ? "APPROVED" : "REJECTED"} · {step.naiveResult.reasonCode}
                </p>
                {step.naiveResult.approved ? (
                  <p className="note">Paid without checking the allowlist, the epoch cap or the payroll reserve.</p>
                ) : null}
              </article>
            </li>
          ))}
        </ol>
      )}
      {cfo !== null && reserveLeft !== null ? (
        <p className="column-foot">
          Naive payouts this epoch {formatAmount(cfo.naiveEpochSpent)}
          {BigInt(cfo.naiveEpochSpent) > BigInt(cfo.epochCap) ? ` — over the ${formatAmount(cfo.epochCap)} epoch cap` : ""}
          {" · "}reserve left {formatAmount(reserveLeft.toString())}
          {reserveLeft < BigInt(cfo.payrollFloor) ? ` — below the ${formatAmount(cfo.payrollFloor)} payroll floor` : ""}
        </p>
      ) : null}
    </section>
  );
}

interface GateColumnProps extends ColumnProps {
  readonly receipts: readonly TreasuryReceipt[];
}

function GateColumn({ steps, receipts }: GateColumnProps) {
  const chain = [...receipts].sort((left, right) => left.seq - right.seq);
  const live = new Map(receipts.map((receipt) => [receipt.receiptId, receipt]));
  // The runner-up of a race is re-evaluated against whatever head the winner left behind.
  const leaseHead = commitmentLabel(
    Math.max(
      chain.at(-1)?.seq ?? 0,
      ...steps.map((step) => (step.reserveRailResult.approved ? step.reserveRailResult.seq ?? 0 : 0)),
    ),
  );
  return (
    <section className="column column-gate" aria-labelledby="gate-heading">
      <header className="column-head">
        <h2 id="gate-heading">ReserveRail gate</h2>
        <p className="column-sub">One Groth16 state-transition proof per payment · allowlist, epoch cap and payroll floor enforced in-circuit</p>
        <ol className="chain" aria-label="Ledger commitment chain">
          <li>{commitmentLabel(0)}</li>
          {chain.map((receipt) => (
            <li key={receipt.receiptId}>{commitmentLabel(receipt.seq)}</li>
          ))}
        </ol>
      </header>
      {steps.length === 0 ? (
        <EmptySteps />
      ) : (
        <ol className="steps">
          {steps.map((step, index) => {
            const result = step.reserveRailResult;
            const receipt = result.receipt === undefined ? undefined : (live.get(result.receipt.receiptId) ?? result.receipt);
            return (
              <li key={step.intent.invoiceId}>
                <article aria-label={`Step ${index + 1}`} className="step">
                  <IntentCard intent={step.intent} step={index + 1} />
                  {result.approved && result.seq !== undefined ? (
                    <p className="verdict verdict-ok">
                      APPROVED · {commitmentLabel(result.seq - 1)} → {commitmentLabel(result.seq)}
                    </p>
                  ) : (
                    <p className="verdict verdict-no">REJECTED · {result.reasonCode}</p>
                  )}
                  {!result.approved && result.errorMessage !== undefined ? <p className="note">{result.errorMessage}</p> : null}
                  {result.reEvaluatedAfterLease ? (
                    <p className="note note-lease">
                      {`Re-checked against ${leaseHead} after the In-Flight Lease · ${result.staleProvesAttempted} stale proof${result.staleProvesAttempted === 1 ? "" : "s"}`}
                    </p>
                  ) : null}
                  {receipt !== undefined ? <ReceiptStatus receipt={receipt} /> : null}
                </article>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

interface ComparisonProps {
  readonly steps: readonly DemoStep[];
  readonly cfo: CfoView | null;
  readonly receipts: readonly TreasuryReceipt[];
  readonly busy: boolean;
}

export function Comparison({ steps, cfo, receipts, busy }: ComparisonProps) {
  return (
    <div className="compare" aria-busy={busy}>
      <NaiveColumn steps={steps} cfo={cfo} />
      <GateColumn steps={steps} cfo={cfo} receipts={receipts} />
    </div>
  );
}
