# Clockchain MCP — Roadmap & Limitations

A single, accurate "what works / what's limited / what's next" for the hosted
Clockchain MCP server. Last updated 2026-09-10.

> Supersedes the earlier v1/v2/v3 (local → Mac mini → AWS) plan — all of which has
> shipped past: the server is hosted on **GCP Cloud Run** with 50 tools and a public
> HTTP endpoint, well beyond the original v2 bar.

## Status

- **Live:** `https://mcp.clockchain.network/mcp` (GCP Cloud Run), **50 tools** across
  seven modules. Browser visitors to `mcp.clockchain.network` get a landing page; agents
  `POST /mcp`. Keyless CI/CD (WIF) with a test gate; Cloud Armor + LB + managed TLS.
- **Status dashboard:** `status.clockchain.network` (pending one DNS record) /
  `clockchain-research.vercel.app/dashboard` — live availability, tool catalog, demos.
- **Tier-1 hardening complete** (epic AGE-181): MCP protocol conformance tests,
  idempotency keys on write tools, async attest (submit→poll via `complete_attestation`),
  upstream resilience (timeout / GET-retry / circuit-breaker), and an all-tools eval
  coverage gate in CI.

## What works today

- **Time** — consensus block time + height via the public `/getTime` (works for any key).
- **Logging / notarization** — anchor a hash, fetch/search ledger entries, verify an asset.
- **Agent identity** — `attest_action` → self-verifying receipt → `verify_receipt`;
  `complete_attestation` (non-blocking submit→poll); mint/revoke/history; `verify_identity_at`;
  keyless `verify_cross_party`.
- **Commitments (TSA)** — issue → checkpoint → attest → settle, with a kept/`broken-late`/`broken` verdict.
- **Audit** — audit trails, compliance reports (EU AI Act Art. 12 / SEC 17a-4 / ISO 27001), evidence packages.
- **Scheduler** — contract types, estimates, list (reads); `create_schedule` is a preview (see below).
- **Independent verification + tamper detection** — recompute the hash, compare to the
  immutable on-chain block; a changed byte fails verification.
- **Verified time tools** — `stopwatch_start/stop/verify` (anchored elapsed time, duration
  re-verified from block times); `timer_set` / `alarm_set` / `timer_status` / `timer_cancel` /
  `timer_list` (hosted keeper: fires while the client is offline, poll for the receipt;
  account-gated; webhooks off until the allow-list ships). Gates and live results in
  [`packages/clock-sdk/GATES.md`](packages/clock-sdk/GATES.md).

## Known limitations

| Limitation | Detail | Tracked / owner |
|---|---|---|
| **Blocks mint only on writes** | Consensus "now" (`/getTime`) is the last block's time, so it goes stale on an idle chain (86 s observed). Confirmed-mode alarms hold until something writes; absolute alarms inherit the idle gap. Plan: keeper heartbeat (ours) or periodic blocks / live oracle (network) — [`clock-tools-production-plan.md`](clock-tools-production-plan.md). | **network team** (N1/N2) |
| **Single-validator testnet** | Receipts are `single-validator-testnet`; multi-validator supermajority ("court-grade") attestation is mainnet-gated. | AGE-152 · **D4 / network** |
| **Consensus-time scope for BYO logging-only keys** | `get_time` uses the public `/getTime` (works), but the gated `/api/time/*` family 401s for logging-scope keys, so a receipt's per-block `consensusTime` falls back to gateway record time until that scope is provisioned. | AGE-150 · **D4 / gateway** |
| **ERC-8004 RPC dependency** | `resolve_agent` defaults to the official registry on Ethereum Sepolia through a public RPC. Hosted production should override `EVM_RPC_URL` with an operationally owned endpoint; RPC failures return `status: "unknown"`. | AGE-151 · hosted ops |
| **`create_schedule` is a preview** | The scheduling API is live and non-custodial (caller signs), but the exact signed-message format is one sentence pending from the protocol team; the tool never fabricates a signature. | AGE-157 · **protocol team** |
| **Gateway exposes mutable ledger endpoints** | `PUT`/`DELETE /ledger/{id}` exist; the on-chain anchor still protects integrity (verification reads the immutable block), but it's a surface to close. | flagged to network team |
| **Discovery is clientId-scoped** | Cross-party *verification* is keyless (present-and-verify), but *enumeration* (`searchAsset`) is scoped — you can't look up a record you were never handed. Needs a public resolver. | network team |
| **Dashboard demo caps are in-memory** | Per-IP/global write-demo caps are best-effort until Vercel KV + a dedicated low-balance demo key are provisioned. | AGE-191 follow-up · needs KV |

## Roadmap

**No external dependency (we can ship anytime):**
- Dashboard V2 demos — agent receipt, submit→poll, commitment lifecycle; receipt gallery.
- Thin-client playground (epic AGE-173 / AGE-175 / AGE-177) — consume the hosted
  `tools/list`/`callTool` and delete the vendored client (the dashboard already proves the pattern).
- Tier-2 server hardening — structured request tracing, load tests.

**Blocked on an external party:**
- Time-read key scope (AGE-150, D4), ERC-8004 infra (AGE-151), scheduler signing spec
  (AGE-157, protocol team), Vercel KV provisioning (dashboard caps / passive prompt
  capture AGE-170), historical-uptime storage for the status page.

**Milestone:**
- **Mainnet multi-validator threshold** (AGE-152) — unlocks the supermajority / court-grade
  evidentiary claim. Network-side, D4-owned.

See the **MCP Playground** project in Linear (AgentDash) for the live backlog.
