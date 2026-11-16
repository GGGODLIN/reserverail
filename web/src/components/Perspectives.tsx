import { PUBLIC_SIGNAL_NAMES } from "../../../src/generated/circuit-abi.ts";
import type { CfoView, TreasuryReceipt } from "../api-types.ts";
import {
  commitmentLabel,
  confidentialFieldsInSignals,
  fieldToHex,
  formatAmount,
} from "../model/workbench-model.ts";
import { HexValue } from "./HexValue.tsx";

interface CfoPanelProps {
  readonly cfo: CfoView | null;
  readonly open: boolean;
  readonly onToggle: () => void;
}

export function CfoPanel({ cfo, open, onToggle }: CfoPanelProps) {
  return (
    <section className="panel panel-cfo" aria-labelledby="cfo-heading">
      <h2 id="cfo-heading" className="panel-title">
        <button type="button" className="disclosure" aria-expanded={open} aria-controls="cfo-body" onClick={onToggle}>
          CFO private witness
          <span className="disclosure-icon" aria-hidden="true">
            {open ? "▾" : "▸"}
          </span>
        </button>
      </h2>
      <p className="tag tag-private">PRIVATE WITNESS — loaded locally, never on-chain</p>
      <div id="cfo-body" hidden={!open}>
        {cfo === null ? (
          <p className="empty">Loading the private witness…</p>
        ) : (
          <>
            <table className="kv" aria-label="Private witness values">
              <tbody>
                <tr>
                  <th scope="row">Treasury balance</th>
                  <td>{formatAmount(cfo.balance)}</td>
                </tr>
                <tr>
                  <th scope="row">Payroll reserve floor</th>
                  <td>{formatAmount(cfo.payrollFloor)}</td>
                </tr>
                <tr>
                  <th scope="row">Epoch spend cap</th>
                  <td>{formatAmount(cfo.epochCap)}</td>
                </tr>
                <tr>
                  <th scope="row">Spent this epoch</th>
                  <td>{formatAmount(cfo.spentSoFar)}</td>
                </tr>
              </tbody>
            </table>
            <details className="allowlist-details">
              <summary>Vendor allowlist · {cfo.allowlist.length} vendors</summary>
              <ul className="allowlist" aria-label="Vendor allowlist">
                {cfo.allowlist.map((vendor) => (
                  <li key={vendor.address}>
                    <span>{vendor.name}</span> <code className="hex">{vendor.address}</code>
                  </li>
                ))}
              </ul>
            </details>
          </>
        )}
      </div>
    </section>
  );
}

interface AuditorPanelProps {
  readonly cfo: CfoView | null;
  readonly receipts: readonly TreasuryReceipt[];
  readonly receipt: TreasuryReceipt | null;
  readonly onSelect: (receiptId: string) => void;
}

const DECIMAL_SIGNALS: ReadonlySet<string> = new Set(["amount", "epoch"]);

export function AuditorPanel({ cfo, receipts, receipt, onSelect }: AuditorPanelProps) {
  const leaks = cfo === null || receipt === null ? [] : confidentialFieldsInSignals(cfo, receipt.publicSignalsArray);
  const explorerUrl = receipt?.provenance.txExplorerUrl ?? null;
  return (
    <section className="panel panel-auditor" aria-labelledby="auditor-heading">
      <h2 id="auditor-heading" className="panel-title">
        External auditor public signals
      </h2>
      <p className="tag tag-public">PUBLIC SIGNALS — all that zkVerify and any auditor ever see</p>
      {receipt === null ? (
        <p className="empty">No receipts yet. Run an act to publish public signals.</p>
      ) : (
        <>
          <div className="field-inline">
            <label htmlFor="receipt-select">Receipt</label>
            <select id="receipt-select" value={receipt.receiptId} onChange={(event) => onSelect(event.target.value)}>
              {receipts.map((option) => (
                <option key={option.receiptId} value={option.receiptId}>
                  {`${commitmentLabel(option.seq - 1)} → ${commitmentLabel(option.seq)} · ${option.vendorName ?? "vendor"} · ${formatAmount(option.publicSignals.amount)}`}
                </option>
              ))}
            </select>
          </div>
          <table className="kv signals" aria-label="Public signals">
            <tbody>
              {PUBLIC_SIGNAL_NAMES.map((name, index) => {
                const value = receipt.publicSignalsArray[index] ?? "";
                return (
                  <tr key={name}>
                    <th scope="row">{name}</th>
                    <td>{DECIMAL_SIGNALS.has(name) ? value : <HexValue value={fieldToHex(value)} label={name} />}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className={leaks.length === 0 ? "leak-check leak-none" : "leak-check leak-found"}>
            {`Confidential values found in public signals: ${leaks.length} of 3 (balance, payroll floor, epoch cap)`}
          </p>
          {explorerUrl !== null ? (
            <a className="explorer-link" href={explorerUrl} target="_blank" rel="noreferrer">
              {explorerUrl.includes("subscan.io") ? "View on zkVerify Subscan" : "View on the relay explorer"}
            </a>
          ) : null}
        </>
      )}
    </section>
  );
}
