# Event 03: Wildcard Portal Submission Copy — ReserveRail

## 1. Exact Portal Field Values (`/dashboard/submissions?category=wildcard`)

- **PROJECT TITLE**: `ReserveRail`
- **GITHUB REPOSITORY LINK**: [https://github.com/GGGODLIN/reserverail](https://github.com/GGGODLIN/reserverail)
- **AGENT ENDPOINT**: [https://reserverail.gggodlin.com/agent](https://reserverail.gggodlin.com/agent)
- **PROOF REFERENCE**: [https://zkverify.subscan.io/extrinsic/0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4](https://zkverify.subscan.io/extrinsic/0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4)

### WHAT IT DOES (`<= 2,000` characters)

```text
ReserveRail is a verifiable multi-agent treasury spend gate backed by Circom 2.1.5 Groth16 state-transition proofs settled on zkVerify Mainnet via Kurier.

Teams running multiple AI payment agents (cloud bills, SaaS renewals, contractor invoices) against a shared treasury hit three failure modes that per-transaction limits and ordinary signatures cannot stop:
1. Prompt Injection Hijack: Poisoned invoice memos swap a vendor wallet for 0xBAD...0999.
2. Structuring: Three $12,000 invoices individually clear a $15,000 single-tx cap while breaching a $30,000 epoch cap.
3. Concurrent Reserve Race: Two honest agents read a $100,000 balance simultaneously and each spend $25,000, breaching a $60,000 mandatory Payroll Reserve Floor.

Publishing balances, reserve floors, caps, and supplier allowlists on-chain leaks confidential runway; signing agent logs only proves who spoke, not whether cumulative spend stayed inside policy.

Because zkVerify verifies stateless ZK proofs rather than storing mutable app state, ReserveRail enforces an honest Three-Layer Trust Architecture:
- Layer 1 (9,055-constraint Groth16 Circuit, vkHash 0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba): Proves Poseidon Merkle allowlist inclusion (depth 10), 64-bit pure-addition bounds (newSpent <= epochCap and newSpent + payrollFloor <= balance, preventing finite-field underflow), and C_old -> C_new commitment linkage with zero confidential leakage.
- Layer 2 (SQLite Outbox & Pre-Prove In-Flight Lease): Serializes concurrent internal agents before WASM proving so runners-up perform 0 wasted proofs on stale C_old and immediately re-evaluate against C_1.
- Layer 3 (Public Offline verifyAuditChain): Runs identically in CLI, server, and browser (snarkjs.groth16.verify) to catch any omitted link, C_old fork, or duplicate invoiceHash across C_0 -> C_n.
```

### MESSAGE TO JUDGES (`<= 1,000` characters)

```text
60-Second Judge Script (zero login or wallet):
1. Open https://reserverail.gggodlin.com — isolated ?sandbox=sbx_<id> at C_0 in LIVE Mainnet mode.
2. Click Act 1 (Prompt Injection -> ALLOWLIST_MISS + AWS C_0->C_1), Act 2 (3x$12k -> 3rd shot EPOCH_CAP_EXCEEDED), and Act 3 (2x$25k race -> 0 stale proofs + PAYROLL_FLOOR_BREACH).
3. Compare CFO Private Witness (100k/60k/50k) vs External Auditor Public Signals (0/3 confidential values exposed), then click "Verify Groth16 proof in this browser", "Verify audit chain in this browser", and "Tamper & Send to Kurier Mainnet".

Live Finalized Mainnet Extrinsic: https://zkverify.subscan.io/extrinsic/0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4
Agent Docs (GET) & HMAC (POST): https://reserverail.gggodlin.com/agent
Local zero-mock check (Node >=24.1): git clone https://github.com/GGGODLIN/reserverail && cd reserverail && npm ci && npm test
```

---

## 2. Live Workbench Screenshots

![Initial Dual Columns at C0](https://raw.githubusercontent.com/GGGODLIN/reserverail/main/docs/screenshots/01-initial-dual-columns-C0.png)

![Act 1 Prompt Injection Blocked and Legit Settled](https://raw.githubusercontent.com/GGGODLIN/reserverail/main/docs/screenshots/02-act1-injection-blocked-legit-settled.png)

![Act 2 Structuring Third Shot Blocked](https://raw.githubusercontent.com/GGGODLIN/reserverail/main/docs/screenshots/03-act2-third-shot-EPOCH_CAP_EXCEEDED.png)

![Act 3 Two-Agent Reserve Race and Browser Zero-Trust Verifier](https://raw.githubusercontent.com/GGGODLIN/reserverail/main/docs/screenshots/04-act3-PAYROLL_FLOOR_BREACH-cfo-auditor-browser-verified.png)
