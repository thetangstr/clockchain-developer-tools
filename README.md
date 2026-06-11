# Clockchain Developer Tools

A **CLI** and an **MCP server** that add Clockchain's tools — **consensus time,
notarization, agent-attested receipts, and ERC-8004 identity reads** — to your AI
agent (Claude Code / Desktop / Cursor) and your terminal. It wraps the live D4 node
gateway at `node.clockchain.network`; it does **not** change the blockchain protocol.

> **Install it in your AI agent:** [`INSTALL.md`](INSTALL.md) — local stdio (recommended) or remote HTTP.
> **Non-engineer? Try it in ~10 min:** [`TRY-IT.md`](TRY-IT.md) · **Engineers:** [`QUICKSTART.md`](QUICKSTART.md)
> **Roadmap + current limitations:** [`ROADMAP.md`](ROADMAP.md)

## Quick install (local stdio — recommended)

Not on npm yet, so install from source (private repo — ask the team for access):

```bash
git clone https://github.com/thetangstr/clockchain-developer-tools.git
cd clockchain-developer-tools
npm install && npm run build
```

Register it with Claude Code (run from the repo root):

```bash
claude mcp add clockchain \
  --env CLOCKCHAIN_API_KEY=<your key> \
  --env CLOCKCHAIN_CLIENT_ID=<you@example.com> \
  --env CLOCKCHAIN_WALLET_ID=<you@example.com> \
  -- node "$(pwd)/packages/mcp-server/dist/stdio.js"
```

Open a **new** session, run `/mcp` (you should see `clockchain`), and ask:
*"use clockchain to get the current consensus time."* Claude Desktop / Cursor
config, the remote-HTTP option, and troubleshooting are in [`INSTALL.md`](INSTALL.md).

## What you get

**Tools:** `get_time`, `get_timestamp`, `get_block`, `get_validation` (time) ·
`log_action`, `get_log_entry`, `search_actions`, `verify_asset` (notarization) ·
`attest_action`, `verify_receipt` (agent-attested receipt) · `resolve_agent`
(ERC-8004 identity, read).

**Packages (this monorepo):**

| Package | What it is |
|---|---|
| [`@clockchain/mcp-server`](packages/mcp-server) | The MCP server — `clockchain-mcp` (`dist/stdio.js`), stdio + HTTP transports. |
| [`@clockchain/core`](packages/core) | Shared client, types, hashing/receipt + ERC-8004 helpers (Node-only, no extra deps). |
| [`@clockchain/web-demo`](packages/web-demo) | Browser chat demo — an LLM agent driving the tools over MCP. |

A `@clockchain/cli` for the terminal is planned — see [ROADMAP.md](./ROADMAP.md).

## Status

Working against the live gateway. Verified surface (updated 2026-06-10):

- **Time:** read consensus time from the **public `/getTime`** (no key scope). The
  `/api/time/*` family 401s on logging-scope keys.
- **Notarization:** `/log`, `/ledger/{id}`, `/searchAsset`, `/getValidationBlock`
  all confirmed working — log, confirm on-chain, retrieve, verify.
- **Smart-contract scheduling:** **live** at `POST /api/contract/schedule`
  (signature-based, non-custodial) — *not* blocked, and *not* `/schedule`.
- **Agent identity:** the ERC-8004 registry is live and resolving; `resolve_agent`
  just needs `EVM_RPC_URL` + registry + chain set.
- Single-validator testnet; tight rate limits; no cross-client verification yet.

**Full current limitations + v1/v2/v3 plan: [ROADMAP.md](./ROADMAP.md).**

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
| [`roadmap.md`](roadmap.md) | Original v1/v2/v3 milestones + MCP feature inventory. (Current status: [ROADMAP.md](./ROADMAP.md).) | Product / engineering |

Open either `.html` file in a browser to present (arrow keys to navigate,
`Esc` for the slide overview).
