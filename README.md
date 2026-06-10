# Clockchain Developer Tools

> **Want to test it yourself?** Non-engineers start with [`TRY-IT.md`](TRY-IT.md)
> (~10 min, plain steps). Engineers see [`QUICKSTART.md`](QUICKSTART.md).
> **Add it to your AI agent (Claude Code / Desktop / Cursor):** [`INSTALL.md`](INSTALL.md).

Specs and plans for the Clockchain developer surface: a CLI and an MCP server
over the existing D4 node API, plus the agent-identity (Product A) and
Agent-SDK (Product B) work built on top.

Nothing here changes the blockchain protocol. Everything wraps the existing
gateway at `node.clockchain.network`.

**Verified status (2026-06-10):** consensus time (public `/getTime`), Logging,
Search/Ledger, validation blocks, the `/api/contract/*` smart-contract surface,
and the ERC-8004 identity registry are all confirmed working against the live
network. Logging is funded by a separate "logs" credit balance (see
`product-findings.md`). Full current state in [ROADMAP.md](./ROADMAP.md).

## Contents

| File | What it is | Audience |
|---|---|---|
| [`mcp-deployment-brief.md`](mcp-deployment-brief.md) | **Start here for approval.** One-page brief: requirements + deployment dependencies + network-exposure model, with sign-off blocks for stakeholders, network team, and backend. | Stakeholders / Network / Backend |
| [`TRY-IT.md`](TRY-IT.md) | Hands-on test for non-engineers (~10 min). | Business testers |
| [`DELEGATED-ACCESS.md`](DELEGATED-ACCESS.md) | Give testers access without the API key or a VPN: Cloudflare Access in front of the web demo + MCP endpoint, with token/rate/budget caps. | Engineering / ops |
| [`implementation-plan.md`](implementation-plan.md) | Full technical spec and build plan. Source of truth. | Engineering |
| [`implementation-plan-technical.html`](implementation-plan-technical.html) | Slide version of the spec, with the design detail. | Engineering review |
| [`implementation-plan.html`](implementation-plan.html) | Short, high-level overview deck. | Business / stakeholders |
| [`product-findings.md`](product-findings.md) | Hands-on findings from the live network + dashboard (2026-06-02). | Product / engineering |
| [`industry-landscape.md`](industry-landscape.md) | Evidence on what leading timestamping/provenance platforms do, and where Clockchain can differentiate. | Product / strategy |
| [`mcp-readiness.md`](mcp-readiness.md) | Per-tool assessment of which APIs are ready to become MCP tools for Products A & B, grounded in live tests. | Engineering / product |
| [`journeys.md`](journeys.md) | Developer and agent end-to-end journeys, marking where the current API flow supports or breaks autonomous agent usage. | Engineering / product |
| [`product-a-identity-decision.md`](product-a-identity-decision.md) | Decision memo: proprietary DID vs ERC-8004 + SIWA for agent identity. Recommends a hybrid - adopt the standard, differentiate on time/validation. | Product / leadership |
| [`deployment.md`](deployment.md) | Hosting plan: local stdio (devs), Mac mini test host (business users + AgentDash), and the AWS production plan + info checklist. | Engineering / ops |
| [`poc-build-plan.md`](poc-build-plan.md) | Goal + sequenced plan to get the MCP server running on the Mac mini (and how it connects to Clockchain). | Engineering / leadership |
| [`roadmap.md`](roadmap.md) | v1/v2/v3 milestones + the MCP feature inventory (time oracle, notarization, identity, contracts) with honest status. | Product / engineering |

Open either `.html` file in a browser to present (arrow keys to navigate,
`Esc` for the slide overview).

## Status

Working against the live gateway. Verified surface (updated 2026-06-10):

- **Time:** read consensus time from the **public `/getTime`** (no key scope). The
  `/api/time/*` family 401s on logging-scope keys.
- **Notarization:** `/log`, `/ledger/{id}`, `/searchAsset`, `/getValidationBlock`
  all confirmed working - log, confirm on-chain, retrieve, verify.
- **Smart-contract scheduling:** **live** at `POST /api/contract/schedule`
  (signature-based, non-custodial) - *not* blocked, and *not* `/schedule`.
- **Agent identity:** the ERC-8004 registry is live and resolving; `resolve_agent`
  just needs `EVM_RPC_URL` + registry + chain set.
- Single-validator testnet; tight rate limits; no cross-client verification yet.

**See [ROADMAP.md](./ROADMAP.md) for the full current limitations + v1/v2/v3 plan.**

## Build order (5 weeks)

1. `@clockchain/core` - shared client, types, DID helpers
2. `@clockchain/cli` - developer terminal access
3. `@clockchain/mcp-server` - AI agent access (stdio, then remote)
4. Docs, registry listings
5. Subnets + triggers - gated on backend
