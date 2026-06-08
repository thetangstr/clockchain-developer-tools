# Clockchain MCP - Milestone & Weekly Update (June 8)

Commentable - leave comments inline. The live demo carries the detail; this is the
at-a-glance + what we need.

## Progress on the MCP
We have a **working MCP server + playground on the testnet.** An AI agent uses
Clockchain's **existing network APIs** through MCP and turns them into independently
verifiable, on-chain proof. This is the M1 foundation - demonstrated ahead of the
formal build.

## In scope vs not in scope (right now)
**In scope - working on testnet:**
- Verifiable time (the consensus clock)
- Notarization + **proof of existence (TSA-style)**
- **Agent attested receipt** - who acted, what they did, when; tamper-evident
- Independent verification + tamper detection
- **Agent identity - read** (ERC-8004)

**Not in scope yet:**
- Agent identity **write** (validation attestation) - designed (non-custodial
  propose-then-approve), not wired
- **Smart-contract triggers** - blocked (backend `/schedule` not exposed)
- Multi-validator / mainnet-grade proofs; any public launch

## Testnet, not mainnet
Everything runs on the **testnet** with a **single validator**. The workflow and
proofs are real and verifiable; the multi-validator supermajority and the strongest
"court-grade" claims arrive with **mainnet**.

## Features available + how to access
| Audience | How to access | Status |
|---|---|---|
| **Developers** | Clone the repo on GitHub and add the MCP to their own AI agent - [repo](https://github.com/thetangstr/clockchain-developer-tools) · [INSTALL.md](https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md) | **Available now** |
| **Ken & Tetsuji (leadership)** | The **playground** - a zero-install, access-controlled web link (Cloudflare Access; free; no VPN, no install). Screen-share available now. | **Waiting on one thing: domain access** (clockchain.network, ~2 days). Then the link is ~same-day. |

## What we need
1. **Domain access** (`clockchain.network`, or any domain we control) → unlocks the
   playground link for Ken & Tetsuji. This is the only thing gating their access.
2. **Confirm the production identity registry** (ERC-8004) - today a documented assumption.
3. **Go / no-go to publish the developer package** (one-command install).

## What we are NOT asking yet
The network/infra exposure model → separate sign-off with the network/tech team.
A public launch → mainnet-gated.
