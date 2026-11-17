import { REGISTERED_VK_HASH } from "../../../src/generated/circuit-abi.ts";
import type { MainnetLink } from "../api-types.ts";
import { abbreviateHex, formatAmount } from "../model/workbench-model.ts";
import type { VerificationResults } from "../store.ts";
import { HexValue } from "./HexValue.tsx";

interface VerificationPanelProps {
  readonly results: VerificationResults;
  readonly hasReceipt: boolean;
  readonly hasState: boolean;
  readonly onVerifyProof: () => void;
  readonly onVerifyChain: () => void;
  readonly onTamper: () => void;
}

export function VerificationPanel({
  results,
  hasReceipt,
  hasState,
  onVerifyProof,
  onVerifyChain,
  onTamper,
}: VerificationPanelProps) {
  const running = results.running !== null;
  const lines = [results.groth16, results.chain].filter((line): line is string => line !== null);
  return (
    <section className="panel panel-verify" aria-labelledby="verify-heading" aria-busy={running}>
      <h2 id="verify-heading" className="panel-title">
        Zero-trust verification
      </h2>
      <p className="panel-sub">
        snarkjs checks the selected receipt in this browser against the embedded verification key; the server is never
        asked whether a proof is valid.
      </p>
      <p className="vk">
        <span>Verification key on zkVerify</span> <HexValue value={REGISTERED_VK_HASH} label="vkHash" />
      </p>
      <div className="button-grid">
        <button type="button" disabled={!hasReceipt || running} onClick={onVerifyProof}>
          Verify Groth16 proof in this browser
        </button>
        <button type="button" disabled={!hasState || running} onClick={onVerifyChain}>
          Verify audit chain in this browser
        </button>
        <button type="button" className="button-danger" disabled={!hasReceipt || running} onClick={onTamper}>
          {"Tamper & Send to Kurier Mainnet"}
        </button>
      </div>
      {lines.length > 0 ? (
        <ul className="results" aria-label="Verification results">
          {lines.map((line) => (
            <li key={line} className={line.includes("INVALID") ? "result-bad" : "result-good"}>
              {line}
            </li>
          ))}
        </ul>
      ) : null}
      {results.tamper !== null ? (
        <div role="group" aria-label="Tamper test result" className="tamper">
          {results.tamper.map((line) => (
            <p key={line}>{line}</p>
          ))}
        </div>
      ) : null}
    </section>
  );
}

const BASELINE_LINK_ID = "gate01-baseline";

export function MainnetLinks({ links }: { readonly links: readonly MainnetLink[] }) {
  return (
    <section className="panel panel-links" aria-labelledby="links-heading">
      <h2 id="links-heading" className="panel-title">
        Mainnet explorer receipts
      </h2>
      <p className="panel-sub">Kept across resets: this sandbox's finalized relays plus the Gate 01 mainnet baseline.</p>
      <ul className="links">
        {links.map((link) => (
          <li key={link.id}>
            <a href={link.txExplorerUrl} target="_blank" rel="noreferrer">
              {`${link.id === BASELINE_LINK_ID ? "Gate 01 baseline" : "Finalized payment"} · ${formatAmount(link.amount)} · tx ${abbreviateHex(link.txHash)}`}
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}
