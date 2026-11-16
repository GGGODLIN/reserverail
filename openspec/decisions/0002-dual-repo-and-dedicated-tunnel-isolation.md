---
status: accepted
---

# Dual-Repository and Dedicated Tunnel Isolation

Although `ReserveRail` (for `Event 03: Wildcard` and `Event 04: Creator Track`) and an optional `Event 01: Proof Gatekeeper` qualification agent run on the same Always Free Arm VM, we isolate them into two separate personal GitHub repositories, two separate handler paths and SQLite files, and a dedicated `cloudflared-reserverail` tunnel unit distinct from the VM's existing default `cloudflared` service. Pre-JSON raw-body HMAC verification with per-agent secrets prevents sharing a single endpoint path cleanly, `Event 01` mandates proofs against a fixed platform `gatekeeper.wasm` verification key that would pollute the `ReserveRail` repository narrative, and the VM's existing `cloudflared` tunnel is scheduled for teardown on `2026-11-29`—one day before `zkVerify Agent Games` judging concludes on `2026-11-30`.

## Considered Options

- **Single repository and shared `POST /agent` payload sniffing**: Rejected due to per-agent raw-body HMAC secret ambiguity prior to JSON parsing, round-lock coupling during `Event 01` windows, and competitor confusion with `Gatekeeper` clones.
- **Reusing the VM's existing `/etc/cloudflared/config.yml`**: Rejected because editing the shared ingress risks breaking existing relay traffic and scheduled `2026-11-29` teardown of the default service would take `ReserveRail` offline during active judging.

## Consequences

- `ReserveRail` remains 100% focused on verifiable multi-agent treasury state chains and stays online independently through `2026-11-30` with a clean post-judging teardown script.
- Unlocking the fifth portal eligibility checkmark (`At least one scored agent`) uses a minimal standalone runner repository registered as a second agent on the platform.
