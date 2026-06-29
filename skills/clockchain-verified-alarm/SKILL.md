---
name: clockchain-verified-alarm
description: Use when an agent must act at a verified future time and prove it — or timestamp/verify any event — via Clockchain. Covers the zero-creds hosted-MCP alarm flow and the full client-side SDK alarm, plus the operational invariants that prevent early fires and false anchors.
---

# Clockchain verified-time alarm

Clockchain provides neutral, verifiable time. The **MCP server** gives an agent the tools; this skill is the **playbook** for using them correctly the first time. The alarm is **client-side by design** — a blockchain cannot (and for neutrality must not) reach into your systems, so scheduling + firing run in your trust boundary; the chain supplies the consensus clock and a keyless-verifiable anchor.

## Fastest test — zero creds, safe to run unattended
```bash
curl -fsSL https://raw.githubusercontent.com/thetangstr/clockchain-developer-tools/main/packages/clock-sdk/examples/try-alarm-mcp.sh | bash
```
No account, no API key, no secrets — it spends one log credit on a **shared demo account** (nothing of yours), so an agent may run it directly without approval. Requires `jq`. Mints a demo token (cached), checks pool health, arms a ~30s alarm, fires + anchors, asserts a real blockHeight, keyless-verifies. Shorten with `CC_WAIT_S=5`.

## The surfaces (real files — there is NO alarm.mjs, alarm-at.mjs, or bin/clark)
- **Zero-creds MCP flow:** `packages/clock-sdk/examples/try-alarm-mcp.sh` — anchor + keyless verify through the hosted MCP. No creds.
- **Full SDK alarm:** `packages/clock-sdk/examples/alarm-live.mjs` (run via `try-alarm.sh`) — disciplined clock + `ClockScheduler` → fire → anchor → keyless verify. Needs `CLOCKCHAIN_API_KEY` / `CLOCKCHAIN_CLIENT_ID` / `CLOCKCHAIN_WALLET_ID`.
- **Production daemon:** `packages/clock-sdk/examples/clark-slack-alarm.mjs` — always-on, durable, re-arms on restart.

## Invariants (do not violate)
1. **Client-side.** The chain can't wake your client; schedule + actions stay in your trust boundary.
2. **Never fire early.** Poll `get_timestamp.madMarzulloTime` (format `DD-MM-YYYY_HH:MM:SS:mmm`) until it is ≥ your target time T.
3. **Fire with confirmation.** Use `log_action` (or `attest_action` for receipts) with `wait:true, wait_ms ≥ 30000` — the reply carries `blockHeight` directly; don't chase a null.
4. **`blockHeight == null` = FAILURE, not "pending"** (a degraded pool dropped the fire). If blocks are advancing but `nodeParticipation%` reads 0, pass `allow_degraded:true` (single-validator testnet — anchored, NOT court-grade). Never claim success on a null blockHeight.
5. **Keyless verify:** `verify_cross_party {ledger_id, block_height:<number>}` → expect `.onChain.verifiedAgainst == "on-chain block"` and `.onChain.keyless == true`. The authoritative fields live under `.onChain`.
6. **"Keyless" ≠ trustless.** It's a cryptographic integrity check against the immutable on-chain block, but the block is still served by a single gateway operator (multi-validator is on the roadmap). Don't say "trustless" or "court-grade" to a compliance buyer.

## Measured (2026-06)
Clock read ≈0.12s; **fire→anchored ≈1.4s (< 3s)**; 35 unit tests. Single-validator testnet.

## Env knobs (try-alarm-mcp.sh)
`CC_WAIT_S` (alarm delay, default 30s) · `CC_ALLOW_DEGRADED` (1=allow / 0=refuse / unset=auto) · `CC_TOKEN_FILE` (token cache, default `/tmp/cc_demo_token`).

## Source of truth
This skill is versioned with the repo (`packages/clock-sdk` README + examples). CI fails the build if it references a file that doesn't exist.
