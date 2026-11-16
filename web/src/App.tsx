import { Comparison } from "./components/Comparison.tsx";
import { AuditorPanel, CfoPanel } from "./components/Perspectives.tsx";
import { MainnetLinks, VerificationPanel } from "./components/Verification.tsx";
import type { AllowlistVendor, CfoView } from "./api-types.ts";
import { previewCircuitOutcome } from "./model/workbench-model.ts";
import type { RelayMode } from "./model/workbench-model.ts";
import { selectedReceipt, useWorkbench } from "./store.ts";
import type { ActKey, BusyKind, Draft, WorkbenchStore } from "./store.ts";

const ACTS: readonly { readonly key: ActKey; readonly button: string; readonly description: string }[] = [
  {
    key: "act1",
    button: "Run Act 1: Prompt injection",
    description: "A poisoned memo swaps the AWS payout wallet for 0xBAD…0999, then the genuine AWS invoice arrives.",
  },
  {
    key: "act2",
    button: "Run Act 2: 3-shot structuring",
    description: "Three $12,000 Stripe payments each clear a $15,000 single-payment cap but not a $30,000 epoch cap.",
  },
  {
    key: "act3",
    button: "Run Act 3: Two-agent reserve race",
    description: "Two agents fire $25,000 at the same instant; only one fits above the $60,000 payroll reserve.",
  },
];

function RelayBadge({ mode }: { readonly mode: RelayMode | null }) {
  if (mode === null) {
    return <p className="relay relay-pending">Relay mode loading…</p>;
  }
  return mode === "DETERMINISTIC_REPLAY" ? (
    <div className="relay">
      <strong className="badge badge-replay">DETERMINISTIC_REPLAY</strong>
      <p>
        Offline relay fallback: replaying a real on-chain receipt attestation. This Groth16 proof can still be verified
        zero-trust in your browser.
      </p>
    </div>
  ) : (
    <div className="relay">
      <strong className="badge badge-live">LIVE</strong>
      <p>Live relay: every approved proof is submitted to zkVerify Mainnet through Kurier.</p>
    </div>
  );
}

interface TopBarProps {
  readonly sandboxId: string | null;
  readonly loaded: boolean;
  readonly relayMode: RelayMode | null;
  readonly busy: BusyKind | null;
  readonly store: WorkbenchStore;
}

function TopBar({ sandboxId, loaded, relayMode, busy, store }: TopBarProps) {
  return (
    <header className="topbar">
      <div className="brand">
        <h1>ReserveRail treasury workbench</h1>
        <p>Naive payment agent vs. zero-knowledge spend gate · Groth16 proofs on zkVerify</p>
      </div>
      <div className="scope" role="group" aria-label="Sandbox controls">
        <span className="scope-label">Sandbox scope</span>
        <output className="scope-id" aria-label="Sandbox scope">
          {sandboxId ?? "assigning…"}
        </output>
        <div className="scope-actions">
          <button type="button" disabled={sandboxId === null} onClick={() => void store.copySandboxUrl()}>
            Copy sandbox URL
          </button>
          <button type="button" onClick={() => void store.newSandbox()}>
            New sandbox
          </button>
          <button type="button" disabled={!loaded || busy !== null} onClick={() => void store.reset()}>
            Reset to C₀
          </button>
        </div>
      </div>
      <RelayBadge mode={relayMode} />
    </header>
  );
}

interface ActsPanelProps {
  readonly busy: BusyKind | null;
  readonly disabled: boolean;
  readonly onRun: (act: ActKey) => void;
}

function ActsPanel({ busy, disabled, onRun }: ActsPanelProps) {
  return (
    <section className="panel panel-acts" aria-labelledby="acts-heading">
      <h2 id="acts-heading" className="panel-title">
        Guided walkthrough
      </h2>
      <p className="panel-sub">Each act resets this sandbox to its own policy at C₀, then sends the same intents to both agents.</p>
      <ol className="act-list">
        {ACTS.map((act) => (
          <li key={act.key}>
            <button
              type="button"
              className="act-button"
              disabled={disabled}
              aria-describedby={`${act.key}-description`}
              onClick={() => onRun(act.key)}
            >
              {act.button}
              {busy === act.key ? <span className="spinner" aria-hidden="true" /> : null}
            </button>
            <p id={`${act.key}-description`} className="act-description">
              {act.description}
            </p>
          </li>
        ))}
      </ol>
    </section>
  );
}

function circuitPreview(cfo: CfoView | null, amount: string): { readonly text: string; readonly tone: string } {
  if (cfo === null) {
    return { text: "Circuit preview: waiting for the CFO private witness…", tone: "muted" };
  }
  const trimmed = amount.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    return { text: "Circuit preview: enter a whole-number amount to see which bound it meets.", tone: "muted" };
  }
  switch (previewCircuitOutcome(cfo, BigInt(trimmed))) {
    case "WITHIN_BOUNDS":
      return { text: "Circuit preview: within bounds.", tone: "ok" };
    case "PAYROLL_FLOOR_BREACH":
      return { text: "Circuit preview: would breach the payroll reserve floor.", tone: "no" };
    case "EPOCH_CAP_EXCEEDED":
      return { text: "Circuit preview: would exceed the epoch spend cap.", tone: "no" };
  }
}

interface ProposeFormProps {
  readonly draft: Draft;
  readonly cfo: CfoView | null;
  readonly vendors: readonly AllowlistVendor[];
  readonly disabled: boolean;
  readonly store: WorkbenchStore;
}

function ProposeForm({ draft, cfo, vendors, disabled, store }: ProposeFormProps) {
  const preview = circuitPreview(cfo, draft.amount);
  return (
    <form
      className="panel panel-propose"
      aria-label="Propose a payment"
      onSubmit={(event) => {
        event.preventDefault();
        void store.propose();
      }}
    >
      <h2 className="panel-title">Propose a payment</h2>
      <p className="panel-sub">
        Both agents get the same parsed intent. The preview reads the CFO witness in this browser; the circuit decides on
        submit.
      </p>
      <label className="field">
        Recipient
        <input
          name="recipient"
          list="vendor-names"
          autoComplete="off"
          spellCheck={false}
          placeholder="AWS, Stripe… or a 0x wallet"
          value={draft.recipient}
          onChange={(event) => store.updateDraft({ recipient: event.target.value })}
        />
      </label>
      <datalist id="vendor-names">
        {vendors.map((vendor) => (
          <option key={vendor.address} value={vendor.name} />
        ))}
      </datalist>
      <label className="field">
        Amount
        <input
          name="amount"
          inputMode="numeric"
          autoComplete="off"
          placeholder="40000"
          aria-describedby="circuit-preview"
          value={draft.amount}
          onChange={(event) => store.updateDraft({ amount: event.target.value })}
        />
      </label>
      <label className="field">
        Memo
        <textarea
          name="memo"
          rows={2}
          placeholder="Optional invoice note"
          value={draft.memo}
          onChange={(event) => store.updateDraft({ memo: event.target.value })}
        />
      </label>
      <p id="circuit-preview" className={`preview preview-${preview.tone}`}>
        {preview.text}
      </p>
      <button type="submit" className="button-primary" disabled={disabled}>
        Propose payment
      </button>
    </form>
  );
}

export function App({ store }: { readonly store: WorkbenchStore }) {
  const state = useWorkbench(store);
  const { view, busy } = state;
  const snapshot = view.snapshot;
  const cfo = snapshot?.cfoView ?? null;
  const receipts = snapshot?.receipts ?? [];
  const receipt = selectedReceipt(state);
  const actionsBlocked = busy !== null || view.sandboxId === null || snapshot === null;
  return (
    <>
      <a className="skip-link" href="#workbench">
        Skip to the workbench
      </a>
      <TopBar
        sandboxId={view.sandboxId}
        loaded={snapshot !== null}
        relayMode={state.relayMode}
        busy={busy}
        store={store}
      />
      <div role="status" aria-label="Workbench status" className="statusbar">
        {state.announcement}
      </div>
      {view.error !== null ? (
        <div role="alert" className="error-banner">
          {view.error}
        </div>
      ) : null}
      <main id="workbench" className="layout">
        <div className="col-left">
          <ActsPanel busy={busy} disabled={actionsBlocked} onRun={(act) => void store.runAct(act)} />
          <VerificationPanel
            results={state.verification}
            hasReceipt={receipt !== null}
            hasState={snapshot !== null}
            onVerifyProof={() => void store.verifySelectedProof()}
            onVerifyChain={() => void store.verifyChain()}
            onTamper={() => void store.tamperSelected()}
            onDownload={store.downloadProofBundle}
          />
          <ProposeForm
            draft={state.draft}
            cfo={cfo}
            vendors={cfo?.allowlist ?? []}
            disabled={actionsBlocked}
            store={store}
          />
        </div>
        <div className="col-center">
          <Comparison steps={view.run?.steps ?? []} cfo={cfo} receipts={receipts} busy={busy !== null} />
        </div>
        <div className="col-right">
          <CfoPanel cfo={cfo} open={state.cfoOpen} onToggle={store.toggleCfo} />
          <AuditorPanel cfo={cfo} receipts={receipts} receipt={receipt} onSelect={store.selectReceipt} />
          <MainnetLinks links={snapshot?.mainnetExplorerLinks ?? []} />
        </div>
      </main>
    </>
  );
}
