# Clockchain Developer Tools

A **CLI** and an **MCP server** that add Clockchain's tools — **consensus time,
notarization, smart-contract scheduling, audit trails, and agent identity
verification** — to **any MCP client** (Claude Code, Cursor, Claude Desktop, Codex,
Hermes, OpenClaw, …) and your terminal. It wraps the live D4 node gateway at
`node.clockchain.network`; it does **not** change the blockchain protocol.

> **Install it in your MCP client:** [`INSTALL.md`](INSTALL.md) — hosted endpoint (any client, recommended) or self-host (local stdio).
> **Non-engineer? Try it in ~10 min:** [`TRY-IT.md`](TRY-IT.md) · **Engineers:** [`QUICKSTART.md`](QUICKSTART.md)
> **Roadmap + current limitations:** [`roadmap.md`](roadmap.md)

## Quick install — hosted endpoint (any MCP client)

Works with **any MCP client** — Claude Code, Cursor, Claude Desktop, Codex, Hermes,
OpenClaw. Get a testnet **token** (`x-api-key`; ask the team), then add this to your
client's MCP config:

```json
{
  "mcpServers": {
    "clockchain": {
      "type": "http",
      "url": "https://mcp.clockchain.network/mcp",
      "headers": { "x-api-key": "<YOUR_TOKEN>" }
    }
  }
}
```

CLI with an `mcp add` command (Claude Code shown):

```bash
claude mcp add clockchain --transport http https://mcp.clockchain.network/mcp \
  --header "x-api-key: <YOUR_TOKEN>"
```

Then run `/mcp` (or your client's equivalent), confirm `clockchain` (31 tools), and
ask: *"use clockchain to get the current consensus time."* Self-host (local stdio),
bring-your-own-key, and chat-connector setup are in [`INSTALL.md`](INSTALL.md).

## Ask an agent to connect it — no install

No machine to set up? Hand any MCP-capable agent (Claude Code, Cursor, Codex,
Hermes, OpenClaw, Claude Desktop) the prompt below — the server is already hosted,
so there's nothing to clone or build:

> I want to use the Clockchain MCP server. It's already hosted, so do NOT clone or
> build any repo — just connect to the remote server over HTTP. Add an MCP server
> named `clockchain` with this config (substitute my token):
> ```json
> { "mcpServers": { "clockchain": { "type": "http", "url": "https://mcp.clockchain.network/mcp", "headers": { "x-api-key": "<YOUR_TOKEN>" } } } }
> ```
> Then list your MCP servers to confirm `clockchain` is connected, and call its
> `get_time` tool to show me the current Clockchain consensus time.

Ask the team for a per-user token — the Clockchain key stays on the server. The
same hosted endpoint (`https://mcp.clockchain.network/mcp`) works from any MCP
client. Chat-connector clients (claude.ai chat, Cowork) are different — see
[`INSTALL.md`](INSTALL.md).

## What you get

**31 tools across six modules:**

- **Time:** `get_time`, `get_timestamp`, `get_block`, `get_validation`.
- **Logging (notarization):** `log_action`, `get_log_entry`, `search_actions`,
  `verify_asset`.
- **Scheduler (smart-contract):** `get_contract_types`, `estimate_schedule`,
  `create_schedule`, `list_schedules`. Types/estimate/list are live;
  `create_schedule` is a preview — it's blocked on the backend signing-message
  spec. Scheduling is **non-custodial**: the caller's own EVM wallet signs, the
  server never fabricates a signature.
- **Audit (derivative — composes Time + Logging + Identity, no new primitive):**
  `generate_audit_trail`, `generate_compliance_report` (EU AI Act Art. 12 /
  SEC 17a-4 / ISO 27001 presets), `build_evidence_package`, `verify_package`.
- **Agent identity (verification, valid-at-T — not authentication):**
  `resolve_agent`, `attest_action`, `complete_attestation`, `verify_receipt`,
  `mint_identity`, `revoke_identity`, `delegate_authority`,
  `get_identity_history`, `verify_identity_at`, `verify_cross_party`.
  `attest_action` with `wait=false` submits without blocking; `complete_attestation`
  is the poll that returns the confirmed receipt once the block lands.
- **Commitments (TSA):** `tsa_issue`, `tsa_checkpoint`, `tsa_attest`,
  `tsa_settle`, `tsa_status`. A commitment lifecycle on the anchor primitives —
  issue → checkpoint → attest (kept/broken) → settle, plus status. `tsa_attest`
  reconciles the on-chain anchor time vs the deadline into a kept/`broken-late`/
  `broken` verdict; the consequence is **recorded, not enforced** (MVP).

**Cross-party verification is live and keyless:** `GET /searchAssetFromChain?blockHeight={h}`
reads the immutable on-chain block with no API key. That block — not the mutable
`/ledger/{id}` cache — is the authoritative record; verification resolves to the chain.

**Packages (this monorepo):**

| Package | What it is |
|---|---|
| [`@clockchain/mcp-server`](packages/mcp-server) | The MCP server — `clockchain-mcp` (`dist/stdio.js`), stdio + HTTP transports. |
| [`@clockchain/core`](packages/core) | Shared client, types, hashing/receipt + ERC-8004 helpers (Node-only, no extra deps). |
| [`@clockchain/web-demo`](packages/web-demo) | Browser chat demo — an LLM agent driving the tools over MCP. |

A `@clockchain/cli` for the terminal is planned — see [roadmap.md](./roadmap.md).

## Status

Working against the live gateway. The MCP server is **verified working** —
`initialize` + `tools/list` returns 31 tools and live calls succeed. Verified
surface (updated 2026-06-11):

- **Time:** read consensus time from the **public `/getTime`** (no key scope). The
  `/api/time/*` family 401s on logging-scope keys.
- **Notarization:** `/log`, `/ledger/{id}`, `/searchAsset`, `/getValidationBlock`
  all confirmed working — log, confirm on-chain, retrieve, verify.
- **Cross-party verification:** **live and keyless** —
  `GET /searchAssetFromChain?blockHeight={h}` reads the immutable on-chain block
  with no API key, and that block is the authoritative record.
- **Smart-contract scheduling:** contract types, estimate, and list are **live**;
  `create_schedule` is a preview, blocked on the backend signing-message spec.
  Signature-based and non-custodial (the caller's EVM wallet signs).
- **Agent identity:** verification (valid-at-T), not authentication. The ERC-8004
  registry is live and resolving; identity-graph writes (`mint`/`revoke`/`delegate`)
  resolve against a directory that is still preview.
- Designed for **court-grade** evidence. Single-validator testnet; tight rate limits.

**Full current limitations + roadmap: [roadmap.md](./roadmap.md).**

## Hosting, CI/CD & ops

Hosted on **GCP Cloud Run** at `https://mcp.clockchain.network/mcp` (token-gated +
bring-your-own-key), auto-deployed on push to `main` behind a test gate.

| File | What it is |
|---|---|
| [`CLOUD-RUN.md`](CLOUD-RUN.md) | Deploy + ops runbook: keyless WIF CI/CD, Cloud Armor, monitoring, secret/token rotation, rollback. **Canonical hosting doc.** |
| [`cicd-plan.md`](cicd-plan.md) | CI/CD pipeline, non-negotiable rules, and forward plan. |
| [`AGENTS.md`](AGENTS.md) | Contributor/agent guide — run tests before push, never bypass the deploy gate, one agent per worktree. |
| [`auth-and-traffic-decision.md`](auth-and-traffic-decision.md) | Single-ID front door, delegated vs BYO, Cowork vs Claude Code, channel/traffic + cost model. |
| [`agentdash-mcp-integration-brief.md`](agentdash-mcp-integration-brief.md) | Hand-off brief for the AgentDash team to integrate the hosted MCP. |
| [`eval/`](eval/) | Execution-scored eval harness — Layer-A perf + Layer-B agent task suite (on-chain checks, no LLM judge). |
| [`RETRO-2026-06-13.md`](RETRO-2026-06-13.md) | Retro of the 06-11 → 06-13 build (Cloud Run, CI/CD, TSA, eval). |

`DELEGATED-ACCESS.md` below describes the **retired** Mac-mini path — superseded by `CLOUD-RUN.md`.

## Specs & planning docs

Background, design decisions, and rollout plans (this repo started as the planning
surface for the work, and those docs still live here):

| File | What it is | Audience |
|---|---|---|
| [`mcp-deployment-brief.md`](mcp-deployment-brief.md) | **Start here for approval.** One-page brief: requirements + deployment dependencies + network-exposure model, with sign-off blocks for stakeholders, network team, and backend. | Stakeholders / Network / Backend |
| [`DELEGATED-ACCESS.md`](DELEGATED-ACCESS.md) | Give testers access without the API key or a VPN: Cloudflare Access in front of the web demo + MCP endpoint, with token/rate/budget caps. | Engineering / ops |
| [`implementation-plan.md`](implementation-plan.md) | Full technical spec and build plan. Source of truth. | Engineering |
| [`implementation-plan-technical.html`](implementation-plan-technical.html) | Slide version of the spec, with the design detail. | Engineering review |
| [`implementation-plan.html`](implementation-plan.html) | Short, high-level overview deck. | Business / stakeholders |
| [`product-findings.md`](product-findings.md) | Hands-on findings from the live network + dashboard. | Product / engineering |
| [`industry-landscape.md`](industry-landscape.md) | Evidence on what leading timestamping/provenance platforms do, and where Clockchain can differentiate. | Product / strategy |
| [`mcp-readiness.md`](mcp-readiness.md) | Per-tool assessment of which APIs are ready to become MCP tools for Products A & B, grounded in live tests. | Engineering / product |
| [`journeys.md`](journeys.md) | Developer and agent end-to-end journeys, marking where the current API flow supports or breaks autonomous agent usage. | Engineering / product |
| [`product-a-identity-decision.md`](product-a-identity-decision.md) | Decision memo: proprietary DID vs ERC-8004 + SIWA for agent identity. Recommends a hybrid — adopt the standard, differentiate on time/validation. | Product / leadership |
| [`deployment.md`](deployment.md) | Hosting plan: local stdio (devs), Mac mini test host (business users + AgentDash), and the AWS production plan + info checklist. | Engineering / ops |
| [`poc-build-plan.md`](poc-build-plan.md) | Goal + sequenced plan to get the MCP server running on the Mac mini (and how it connects to Clockchain). | Engineering / leadership |
| [`roadmap.md`](roadmap.md) | Current roadmap, what works, and known limitations. | Product / engineering |

Open either `.html` file in a browser to present (arrow keys to navigate,
`Esc` for the slide overview).
