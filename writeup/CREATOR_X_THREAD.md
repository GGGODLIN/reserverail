# Event 04: Creator Track X Thread & Portal Copy — ReserveRail

## 1. X / Twitter Thread Draft (6 Posts — `#AgentGames` & `@ZKVProtocol`)

**Post 1/6**
Static per-tx spending caps don't stop AI treasury drains:
- Prompt injection swaps AWS's wallet for 0xBAD...0999
- 3x $12k structuring slips right under a $15k single cap
- Two honest agents race on $100k & breach a $60k payroll floor

Meet **ReserveRail** on @ZKVProtocol Mainnet. #AgentGames

**Post 2/6**
Putting balances, payroll floors & vendor allowlists on-chain leaks confidential runway. Signing agent logs only proves *who* spoke, not *whether* cumulative spend stayed inside policy.

ReserveRail proves every payment transition (`C_old -> C_new`) in a 9,055-constraint Circom Groth16 circuit via Kurier.

**Post 3/6**
Because @ZKVProtocol is a stateless proof verifier—not a mutable state DB—we don't overclaim what one proof does. ReserveRail splits trust into 3 honest layers:
1. Groth16 circuit: Merkle allowlist + 64-bit pure-addition epoch cap & payroll floor (zero modular underflow)
2. SQLite pre-prove In-Flight Lease (0 wasted stale proofs)
3. Public `verifyAuditChain` (`C_0 -> C_n`)

**Post 4/6**
Try the credential-free workbench (each visitor gets an isolated `?sandbox=sbx_<id>` in LIVE Mainnet mode):
https://reserverail.gggodlin.com

Compare the CFO Private Witness (`100k / 60k / 50k`) vs External Auditor Public Signals (`0 of 3` confidential numbers exposed), run `snarkjs` zero-trust in your browser, or fire a live Tamper Test at Kurier Mainnet!

**Post 5/6**
On-chain proof receipts on zkVerify Mainnet:
- Registered `vkHash`: `0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba`
- Live Finalized extrinsic: https://zkverify.subscan.io/extrinsic/0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4
- 28 unit & `fast-check` differential PBT suites (`P1..P5` vs real `.wasm`) + 14 Chromium E2E tests

**Post 6/6**
Open-source MIT repo + full technical writeup:
https://github.com/GGGODLIN/reserverail

One-line local verification (Node >= 24.1, zero credentials required):
`git clone https://github.com/GGGODLIN/reserverail && cd reserverail && npm ci && npm test`

Built for @ZKVProtocol #AgentGames

---

## 2. Creator Track Portal Fields (`/dashboard/submissions`)

- **CATEGORY**: `ARTICLE` / `VIDEO` / `THREAD` (crossposted links added under `Add another link` for bonus XP)
- **TITLE**: `ReserveRail: Stopping Multi-Agent Treasury Drains with Stateless ZK State Chains on zkVerify`

### SUPPORTING CONTEXT (`<= 1,000` characters)

```text
This technical deep-dive, launch video, and X thread walk through ReserveRail—our open-source Wildcard agent built on zkVerify Mainnet (vkHash 0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba, live Finalized extrinsic 0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4).

Rather than overclaiming that a stateless ZK verifier stores application state, the piece teaches builders how to combine: (1) a 9,055-constraint Circom Groth16 transition circuit using 64-bit pure-addition bounds to prevent BN254 modular underflow while keeping treasury balances, payroll floors, and allowlists private; (2) a pre-prove SQLite In-Flight Lease that eliminates wasted proving during two-agent races; and (3) a browser-runnable zero-trust Audit Chain verifier. Readers can test all 3 acts live at https://reserverail.gggodlin.com or reproduce all 28 unit/PBT tests locally via https://github.com/GGGODLIN/reserverail.
```
