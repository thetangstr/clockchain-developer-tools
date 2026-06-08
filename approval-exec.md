# Clockchain MCP - Business Approval (live walkthrough)

**For:** business execs / leadership · **Format:** demo-led, ~15 min · Date: 2026-06.

One page. The demo does the talking; this is the agenda + what we need you to approve.

## What it is (one line)
An MCP server that lets AI agents use Clockchain to turn a high-stakes agent action
into an **independently verifiable, tamper-evident on-chain receipt** - proof of
*who* acted, *what* they did, and *when*.

## What we validated - shown live
A working **MCP Playground** on the testnet: an AI agent drives Clockchain's tools
and produces verifiable proof. We'll demo:
- **Verifiable time** - the network's consensus clock.
- **Agent attested receipt** - an agent executes a treasury trade → instant on-chain proof.
- **Proof of existence (TSA-style)** - timestamp a document; alter one word and it fails verification.
- **Independent verification + tamper detection.**
- **Agent identity (read)** - resolve an agent's ERC-8004 on-chain identity.

## How to access it
- **Today (this meeting):** we **screen-share** the live playground - nothing to set up.
- **Remote, self-serve access for business folks - what it needs:** a **zero-install,
  access-controlled web link** via **Cloudflare Access** (log in with your email, no
  VPN, no install). It is **free** (Cloudflare Tunnel + Access, free up to 50 users;
  TLS included). The **one prerequisite is a domain on Cloudflare** - we'll use
  **`clockchain.network`** (access expected in ~2 days) or any domain we control;
  once the domain is in hand the gated link is roughly same-day. *(Approval ask #2.)*
- **The MCP, for developers:** clone the client repo and add it to your own AI
  agent - [github.com/thetangstr/clockchain-developer-tools](https://github.com/thetangstr/clockchain-developer-tools)
  → [`INSTALL.md`](https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md).
  One-command `npx` install comes once we publish (ask #4).

## What we're asking you to approve today
1. **Direction** - lead with the **Agent Attested Receipt** wedge (ERC-8004 hybrid
   identity + agent-payable funding), not a broad compliance platform.
2. **Design-partner test** - put the playground behind access control for **3-5
   business / design-partner testers** (v2).
3. **An owner to confirm the production identity registry** (ERC-8004) - today it's
   a documented assumption.
4. **Go-ahead to publish a developer package** so teams can self-install the MCP.

## Honest caveats (so the approval is informed)
- **Testnet, single validator** - workflow + proofs are real; multi-validator
  supermajority and "court-grade" claims arrive at mainnet.
- **The demo talks to the LLM directly** - production path is the same tools via our agent.
- **Reads are live; writes are designed** (attestation, contracts) - not yet wired.
- **Install is from source** today; the one-command npm publish is prepped.

## What we are NOT asking today
- The **network / infra exposure model** → separate sign-off with the network/tech
  team (`approval-network.md`).
- A **public launch** → mainnet-gated.

## Detail behind this (if asked)
Full spec + milestones: Engineering Spec · roadmap (v1/v2/v3) · `deployment.md`.
