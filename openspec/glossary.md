# ReserveRail Glossary

Ubiquitous language for ReserveRail, a verifiable multi-agent treasury spend rail where autonomous payment agents prove compliance against confidential treasury policies without exposing internal balances, limits, or vendor rosters.

## Treasury Policy & State

**Policy Commitment (`policyRoot`)**:
A public cryptographic commitment published ahead of a spending period by the treasury owner, binding the confidential vendor allowlist root, epoch spend cap, and payroll reserve floor.
_Avoid_: Rule hash, config digest

**Vendor Allowlist**:
The confidential roster of pre-approved recipient addresses authorized to receive treasury disbursements under a Policy Commitment.
_Avoid_: Whitelist, payee table

**Epoch Spend Cap (`epochCap`)**:
The confidential maximum cumulative disbursement permitted within a single fixed accounting epoch across all payment agents sharing a treasury.
_Avoid_: Rolling window limit, daily sliding cap

**Payroll Reserve Floor (`payrollFloor`)**:
The confidential minimum treasury balance that must remain untouched after cumulative disbursements so mandatory obligations such as payroll cannot be breached.
_Avoid_: Safety buffer, minimum balance

**Ledger Commitment (`ledgerCommitment`)**:
A salted cryptographic commitment to a treasury's cumulative epoch spend, active epoch identifier, and underlying balance at a single point in the state chain (`C_0`, `C_1`, ..., `C_n`).
_Avoid_: State hash, balance snapshot

**Genesis Commitment (`C_0`)**:
The initial Ledger Commitment anchoring the start of an auditable treasury state chain before any agent disbursement occurs.
_Avoid_: Initial root, seed state

## Execution & Verification Roles

**Payment Intent**:
An untrusted proposal containing a recipient address, integer payment amount, epoch identifier, and invoice reference extracted from a payment request before policy verification.
_Avoid_: Order, transaction draft

**Invoice Digest (`invoiceHash`)**:
A deterministic public identifier derived from the vendor and invoice reference to surface duplicate billing across a sequence of Treasury Receipts.
_Avoid_: Nullifier, dedupe token

**In-Flight Lease**:
A short-lived exclusive reservation over the current Ledger Commitment acquired before proof generation so concurrent payment agents cannot build conflicting state transitions from the same head.
_Avoid_: Mutex, optimistic retry loop

**Treasury Receipt**:
The verifiable record of an approved disbursement combining a zero-knowledge transition proof (`C_old -> C_new`), public statement signals, and its zkVerify mainnet attestation metadata.
_Avoid_: Audit log entry, payment ticket

**Audit Chain**:
An ordered sequence of Treasury Receipts linking `C_0` to `C_n` without gaps, forks from a shared prior commitment, or repeated Invoice Digests.
_Avoid_: Transaction history, ledger log

**Sandbox Scope**:
An isolated treasury state chain namespace assigned to an interactive evaluator session so concurrent public visitors do not exhaust or corrupt one another's balances.
_Avoid_: Tenant account, test user
