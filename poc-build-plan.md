# POC Build Plan - Get the MCP Server Running on the Mac Mini

## Goal

**Stand up the Clockchain MCP server on the Mac mini as an HTTP endpoint that
AgentDash and a few business testers can hit, demonstrating the verified loop
(consensus time -> log -> verify -> retrieve) plus an ERC-8004 identity read,
with tester auth and a capped credit budget.**

Done = the POC success criteria in `implementation-plan.md` are met: an agent
completes the loop unaided through the Mac mini endpoint, a logged action carries
an ERC-8004 `agentId`, and we have findings + first customer signal for a
go / no-go.

## How the Mac mini connects to the Clockchain network

Important, because it scopes the whole build: **the Mac mini does not run a
Clockchain node, join consensus, or hold a wallet.** The MCP server on it is just
an authenticated HTTPS client of two services:

```
   Business testers / AgentDash
            │  (LAN, or Cloudflare Tunnel)
            ▼
   ┌─────────────────────┐
   │  Mac mini           │   MCP server (HTTP)
   │  @clockchain/mcp    │
   └──────┬───────┬──────┘
          │       │  both are plain outbound HTTPS
          ▼       ▼
  node.clockchain     EVM RPC
  .network (gateway)  (Base / Ethereum)
  x-api-key           ERC-8004 reads
  time + log + ledger
  (spends log credits)
```

- **Clockchain gateway** (`https://node.clockchain.network`): outbound HTTPS with
  the `x-api-key` header - the exact endpoints we verified (time, timestamp,
  block, log, ledger, searchAsset, getValidationBlock). Logging spends log
  credits on the account. No wallet or private key is needed; the API key lives
  in the Mac mini's env and never leaves it.
- **EVM RPC** (Base or Ethereum): outbound HTTPS, for ERC-8004 identity reads.

So "connecting to the network" = internet access + a Clockchain API key with
credits + an EVM RPC URL. No node hosting, no P2P, no chain sync, no validator.
Inbound, the only thing reaching the Mac mini is testers/AgentDash hitting the
MCP HTTP port (LAN-direct or via the tunnel).

## The plan (sequenced)

### Step 0 - Inputs / provisioning (unblocks everything)
- EVM RPC URL + target chain (recommend **Base Sepolia** for testnet parity).
- Test Clockchain account: API key + `clientId` + `walletId`, with log credits
  and a budget cap (we already have a working key; confirm credits + cap).
- Tester tokens (MCP-layer auth, separate from the Clockchain key).
- Mac mini prep (probed 2026-06): it is `192.168.86.48` / `mac-mini.lan`, on
  Tailscale (`100.71.225.125`), **no Docker** but node v26 + pnpm present - so run
  via node + pm2 (or install Colima). Disable sleep.
- AgentDash question: **resolved.** AgentDash runs ON this Mac mini and is not an
  MCP client itself; it orchestrates agent runtimes (`claude_local`,
  `codex_local`, `cursor`, etc.). We integrate by configuring our MCP into the
  runtime AgentDash launches, on `localhost:3000`. No tunnel needed for local
  agents.
- **Done:** all values in hand; Mac mini reachable.

### Step 1 - Build `@clockchain/core`
The shared client. Typed wrappers for the verified endpoints, per-endpoint
envelope handling, rate-limit handling, `computeHash`/`hashFile`,
`waitForConfirmation`, and `resolveAgent(agentId)` (ERC-8004 read via the EVM
RPC). Unit tests (mocked) + integration tests against the live testnet (the loop
we already proved by hand).
- **Done:** in a test, core logs an asset and reads it back, and `resolveAgent`
  returns an ERC-8004 record.

### Step 2 - Build `@clockchain/mcp-server` (minimal POC)
MCP SDK server exposing the 7 verified tools + `log_action` keyed to an ERC-8004
`agentId` + `resolve_agent` / `get_agent` (ERC-8004 read). stdio and HTTP
transports. Build in the client-side mitigations from day one: local ref index
(history), request throttling, low-credit warning, structured errors,
idempotency key on `log_action`, and tool-call logging (observability). Tester
auth via `MCP_AUTH_TOKENS`.
- **Done:** protocol test passes (handshake + tool call over stdio); an
  integration test runs the full loop through the MCP layer.

### Step 3 - Containerize + run on the Mac mini
Dockerfile (node:22-alpine), build the image, run it with the env file, verify
`/health` and an MCP handshake from localhost. (Runbook is in `deployment.md`.)
- **Done:** container up with `--restart unless-stopped`, health green, the loop
  works from `localhost:3000`.

### Step 4 - Expose + connect AgentDash
AgentDash has no MCP client of its own, so we do not point "AgentDash" at the MCP.
Instead, configure our MCP into the **agent runtime AgentDash launches**
(`claude_local` / `codex_local` / `cursor` / ...) - it runs on the same Mac mini,
so it reaches our server at `http://localhost:3000/mcp` (HTTP) or via stdio. For
off-network business testers, use Tailscale (the box is already on the tailnet) or
a Cloudflare Tunnel.
- **Done:** an agent run by AgentDash completes time -> log -> verify -> retrieve
  through our MCP on localhost.

### Step 5 - Test with business users + capture findings
Run sessions with AgentDash and 3-5 testers. Grade against the MCP-experience
requirements (A-K), verify idempotency (no double-spent credits) and the credit
cap, and write the findings + go / no-go.
- **Done:** POC success criteria met (functional + learning + decision bars).

## Critical path and rough sizing

Order: **Step 0 (inputs) -> Step 1 -> Step 2 -> Step 3 -> Step 4 -> Step 5.**
Steps 1-2 are the bulk of the engineering. Rough order-of-magnitude (estimates,
not commitments):

| Step | Rough size |
|---|---|
| 0 Inputs | hours (mostly waiting on values) |
| 1 core | ~2-3 days |
| 2 mcp-server | ~3-4 days |
| 3 containerize + Mac mini | ~0.5 day |
| 4 expose + AgentDash | ~0.5-1 day |
| 5 test + findings | ongoing |

So roughly **1.5-2 weeks of build** to "running on the Mac mini + AgentDash smoke
test," consistent with the Phase 1-3 window in `implementation-plan.md`.

## What unblocks the start right now

Only Step 0. The single highest-leverage input is the **EVM RPC URL + target
chain** (for the ERC-8004 read); everything Clockchain-side we already have
verified. Provide that and the build can start on Step 1 immediately - the
Clockchain client half is just wrapping endpoints we have already tested live.
