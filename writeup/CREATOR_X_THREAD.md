# Event 04: Creator Track X Thread & Portal Copy — ReserveRail

## 1. Published X Thread (6 posts, @GGGODLIN, 2026-11-17)

First post: [https://x.com/GGGODLIN/status/2122684298369384846](https://x.com/GGGODLIN/status/2122684298369384846)

**Post 1/6**

```text
Per-payment caps don't stop AI treasury drains:
- A poisoned memo swaps the payee for 0xBAD...0999
- Three $12k bills each dodge a $15k cap
- Two agents race and breach a $60k payroll floor

ReserveRail stops all three on @ZKVProtocol Mainnet. #AgentGames
https://youtu.be/NO--HeY-e3A
```

**Post 2/6**

```text
Putting balances, payroll floors and vendor allowlists on-chain leaks your runway. Signed agent logs only prove who spoke, not whether total spend stayed inside policy.

ReserveRail proves every payment transition (C_old -> C_new) with a 9,055-constraint Circom Groth16 circuit.
```

**Post 3/6**

```text
@ZKVProtocol verifies proofs; it doesn't store app state, so one proof can't stop forks alone. ReserveRail uses 3 layers:
1. Groth16 circuit: allowlist, epoch cap, payroll floor
2. SQLite lease before proving (0 wasted proofs)
3. Public verifyAuditChain (C_0 -> C_n)
```

**Post 4/6**

```text
Try the no-login workbench, live on Mainnet with a sandbox per visitor:
https://reserverail.gggodlin.com

Compare the CFO's private numbers with the auditor's public signals (0 of 3 exposed), verify proofs in your browser, or send a tampered proof to Kurier and watch it fail.
```

**Post 5/6**

```text
On-chain receipts on zkVerify Mainnet:
- vkHash 0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba
- Finalized payment: https://zkverify.subscan.io/extrinsic/0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4
- 28 unit + fast-check differential property tests against the real .wasm, plus 14 Chromium E2E tests
```

**Post 6/6**

```text
Technical write-up: https://blog.gggodlin.com/hackathon/reserverail/
MIT-licensed source: https://github.com/GGGODLIN/reserverail

Verify locally with zero credentials (Node >= 24.1):
git clone https://github.com/GGGODLIN/reserverail && cd reserverail && npm ci && npm test

Built for @ZKVProtocol #AgentGames
```

---

## 2. Submitted Creator Track Portal Fields (`/dashboard/submissions`, submitted 2026-11-17, `CREATOR-TRACK-2026-W47`, status `PENDING`)

- **CATEGORY**: `ARTICLE`
- **TITLE**: `ReserveRail: Stopping AI Treasury Drains with ZK State Chains`
- **SUBMISSION LINKS**:
  1. Other… (`Personal blog`): [https://blog.gggodlin.com/hackathon/reserverail/](https://blog.gggodlin.com/hackathon/reserverail/)
  2. YouTube: [https://youtu.be/NO--HeY-e3A](https://youtu.be/NO--HeY-e3A)
  3. X / Twitter: [https://x.com/GGGODLIN/status/2122684298369384846](https://x.com/GGGODLIN/status/2122684298369384846)

### SUPPORTING CONTEXT (`921` characters)

```text
This technical write-up, 53-second launch video, and 6-post X thread walk through ReserveRail, our open-source Wildcard agent on zkVerify Mainnet (vkHash 0x38596f3f67e25da5e07975ab2f1cb68da47baed202a4c2c765afcb910c1f1fba; finalized extrinsic 0xbfecb76a413b16c25669e703b84305d00d6b8cc06c5f714dca1431c6f1379de4).

Rather than overclaiming that a stateless ZK verifier stores application state, the piece shows builders how to combine (1) a 9,055-constraint Circom Groth16 transition circuit with 64-bit pure-addition bounds that prevent BN254 modular underflow while keeping balances, payroll floors, and allowlists private; (2) a pre-prove SQLite In-Flight Lease that eliminates wasted proving during two-agent races; and (3) a browser-runnable zero-trust audit-chain verifier. Readers can try all 3 acts at https://reserverail.gggodlin.com or rerun all 28 unit/property tests from https://github.com/GGGODLIN/reserverail.
```
