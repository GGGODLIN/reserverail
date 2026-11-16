---
status: accepted
---

# Three-Layer Trust Decomposition Over Stateless zkVerify

`zkVerify` (via Kurier) is a stateless zero-knowledge proof verification network with no on-chain application state storage to reject stale state roots or previously consumed nullifiers. Rather than claiming that a single Groth16 proof prevents double-spending or invoice replay on its own—or embedding a high-constraint Sparse Merkle Tree inside the circuit and a stateful cross-request `HOLD` protocol that collides with platform `taskId` retry idempotency—we decompose guarantees into three explicit layers: (1) a compact Groth16 circuit proves single-step confidential policy compliance (Vendor Allowlist membership, Epoch Spend Cap, Payroll Reserve Floor) and valid `C_old -> C_new` Ledger Commitment transition; (2) a local transactional Outbox with an In-Flight Lease prevents concurrent honest agents from double-reserving the same head or severing the chain on transient API failures; and (3) a public offline `verifyAuditChain` function verifies that the published Audit Chain from `C_0` to `C_n` has zero missing links, zero forks from a shared `C_old`, and zero duplicate `invoiceHash` entries.

## Considered Options

- **In-circuit Sparse Merkle non-membership + cross-request `HOLD` resume**: Rejected because stateless proof verification still cannot stop a malicious prover from signing two forks off the same `C_0`, while same-`taskId` resume violates platform network-retry idempotency rules.
- **Full EVM rollup settlement before returning**: Rejected because cross-chain aggregation takes 2–5 minutes per proof, breaching the 60-second agent response deadline and adding gas dependencies that violate the zero-spend constraint.

## Consequences

- Proving stays within $2^{14}$ constraints (~1 second per proof) with zero gas cost.
- Product copy, UI labels, and documentation must state clearly that internal race prevention comes from the local In-Flight Lease while external equivocation detection comes from inspecting the unbroken `C_0 -> C_n` Audit Chain.
