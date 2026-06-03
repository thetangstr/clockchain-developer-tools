# Clockchain Developer Tools

Specs and plans for the Clockchain developer surface: a CLI and an MCP server
over the existing D4 node API, plus the agent-identity (Product A) and
Agent-SDK (Product B) work built on top.

Nothing here changes the blockchain protocol. Everything wraps the existing
gateway at `node.clockchain.network`.

**Verified status (2026-06-03):** Timestamp API, Logging, and Search/Ledger are
confirmed working against the live network - a real log wrote, anchored on-chain
in ~0.6s, and read back. Smart-contract triggers (`/schedule`) are not yet on the
gateway. Logging is funded by a separate "logs" credit balance (see
`product-findings.md`).

## Contents

| File | What it is | Audience |
|---|---|---|
| [`implementation-plan.md`](implementation-plan.md) | Full technical spec and build plan. Source of truth. | Engineering |
| [`implementation-plan-technical.html`](implementation-plan-technical.html) | Slide version of the spec, with the design detail. | Engineering review |
| [`implementation-plan.html`](implementation-plan.html) | Short, high-level overview deck. | Business / stakeholders |
| [`product-findings.md`](product-findings.md) | Hands-on findings from the live network + dashboard (2026-06-02). | Product / engineering |
| [`industry-landscape.md`](industry-landscape.md) | Evidence on what leading timestamping/provenance platforms do, and where Clockchain can differentiate. | Product / strategy |
| [`mcp-readiness.md`](mcp-readiness.md) | Per-tool assessment of which APIs are ready to become MCP tools for Products A & B, grounded in live tests. | Engineering / product |
| [`journeys.md`](journeys.md) | Developer and agent end-to-end journeys, marking where the current API flow supports or breaks autonomous agent usage. | Engineering / product |
| [`product-a-identity-decision.md`](product-a-identity-decision.md) | Decision memo: proprietary DID vs ERC-8004 + SIWA for agent identity. Recommends a hybrid - adopt the standard, differentiate on time/validation. | Product / leadership |

Open either `.html` file in a browser to present (arrow keys to navigate,
`Esc` for the slide overview).

## Status

This is a plan, not shipped code. Key points called out in the spec:

- Only the three time endpoints, `/searchAsset`, and `/getValidationBlock` are
  confirmed on the public gateway (probed 2026-06-02).
- Smart-contract triggers (`/schedule`) are **not** exposed on the gateway yet.
- Cross-client identity resolution and `walletId` provisioning are open
  questions for the D4 team. See "Verified API Surface" and "Open assumptions"
  in the spec.

## Build order (5 weeks)

1. `@clockchain/core` - shared client, types, DID helpers
2. `@clockchain/cli` - developer terminal access
3. `@clockchain/mcp-server` - AI agent access (stdio, then remote)
4. Docs, registry listings
5. Subnets + triggers - gated on backend
