# MCP Server Roadmap - v1 / v2 / v3

Three milestones with target dates: **v1 (Fri Jun 19, 2026)** = the basic
features work (local), **v2 (Fri Jun 26, 2026)** = it runs on the Mac mini and is
used by Claude ("Clark") and AgentDash, **v3 (TBD)** = deployed and testable on
AWS, gated on network-team deploy readiness + the smart-contract API.

> Naming note: "Clark" is read here as **Claude / Claude Code** (the runtime
> AgentDash launches as `claude_local`). Correct me if it means something else.

---

## Feature inventory (what this MCP actually has)

Grouped by Clockchain product area, mapped to the "timestamp / tsa / contract"
shorthand, with honest, conservative status.

### A. Time oracle  ("time stamp")  - IN PROGRESS
Read the decentralized clock.
- `get_time` - current consensus time + latest block height
- `get_timestamp` - full node status (Marzullo offset, drift, votes, node count)
- `get_block` - block details by height (proposer, time)
- `get_validation` - validator vote / trust data for a block

### B. Notarization  ("tsa" - proof of existence)  - IN PROGRESS
Hash in, tamper-proof timestamped record out. This is the logging product.
- `log_action` - record a SHA-256 hash on-chain with a consensus timestamp
- `get_log_entry` - fetch a record by ledger id (shows on-chain confirmation)
- `search_actions` - find a record by exact asset reference
- `verify_asset` - prove a hash matches the on-chain record (court-style check)

> Note on "TSA": Clockchain is not literally an RFC-3161 Timestamp Authority; the
> notarization feature is the equivalent (hash + consensus timestamp + verifiable
> proof). If you specifically need RFC-3161 TSA wire format, that is a separate
> build, not in scope here.

### C. Agent identity  (ERC-8004)  - PARTIAL
- `resolve_agent` - read an agent's ERC-8004 identity. **Built but stubbed**:
  returns `unknown` until an EVM RPC URL + registry address + chain are set.
- `mint` / `attest_time` (write to the ERC-8004 Validation Registry) - future;
  attest is an EVM write, so it is subject to the non-custodial / propose-then-
  approve rule.

### D. Smart contracts  ("contract")  - BLOCKED
- `schedule_trigger` and friends - **not available.** `/schedule` returns 404 on
  the public gateway (verified), and the documented design passed a private key in
  a URL, which violates the non-custodial rule. Blocked on both a backend (expose
  `/schedule`) and a redesign (propose-then-approve). **Cannot be in v1.**

---

## v1 - Basic features work (local)  -  target: Fri Jun 19, 2026

**Goal:** prove the feature set runs end to end on a dev machine.

- **Where:** local - `npx`/stdio, driven by a script or the CLI. No hosting.
- **In scope:** Group A (time oracle, 4 tools) + Group B (notarization, 4 tools) -
  the 8 core tools. `resolve_agent` (Group C) read **once an EVM RPC + chain
  are provided** (recommend Base Sepolia).
- **Polish to add for v1:** a `wait` option on `log_action` (poll
  `waitForConfirmation` until `blockHeight` populates), structured agent-facing
  errors, low-credit warning, and per-call logging (observability).
- **Out of scope:** smart contracts (blocked), `attest_time` (write), HTTP host,
  multi-tenant, remote access.
- **How we test it:** the stdio smoke loop (`log_action -> get_log_entry ->
  verify_asset`, positive and negative) plus the time-oracle reads.
- **Exit:** all 8 core tools pass a scripted loop locally; `resolve_agent`
  returns a real ERC-8004 record once the RPC is set.
- **Status:** in progress. The package is built and the smoke loop runs in dev;
  integration testing against the gateway is underway. Remaining: the `wait`
  option and wiring `resolve_agent` to a real RPC.

## v2 - Working on Claude ("Clark") + AgentDash (Mac mini)  -  target: Fri Jun 26, 2026

**Goal:** real agents and business users actually use it, hosted on the Mac mini.

- **Where:** the Mac mini (`192.168.86.48`, which is also the AgentDash host).
- **Transports:**
  - **stdio** wired into `~/.claude.json` `mcpServers` - this is how Claude /
    AgentDash's `claude_local` agents reach it (same box, no network).
  - **HTTP** endpoint for remote business testers (Tailscale, the box is already
    on the tailnet, or a Cloudflare Tunnel).
- **Auth & safety:** tester tokens (`MCP_AUTH_TOKENS`); the Clockchain API key
  stays on the box only; a credit-budget cap so a runaway test can't drain logs;
  observability on.
- **Features:** the v1 set (A + B + `resolve_agent`). Still no contracts, no
  `attest_time` write.
- **Exit (this is the POC success bar):** a Claude/AgentDash agent completes
  time -> log -> verify unaided via `~/.claude.json`; 3-5 business testers hit the
  HTTP endpoint and react; findings graded + a go / no-go.

## v3 - Deployed and testable on AWS (final state)  -  target: TBD (gated)

**Goal:** production-grade hosting, the form we would actually launch from.

- **Where:** AWS - ECR image -> ECS Fargate -> ALB (TLS), per `deployment.md`.
- **Adds:** managed EVM RPC at the edge; multi-tenant non-custodial key handling
  (SIWA for identity, `x-api-key` per request, never stored/logged); the **x402 /
  API-credit funding seam** so agents can pay without a wallet; health checks,
  autoscale, CloudWatch logs, CI/CD.
- **Gated:** a *public* endpoint waits for mainnet (Q9). On AWS we run a private /
  test endpoint first.
- **May add if the backend lands by then:** smart-contract triggers
  (propose-then-approve, no key in the tool) and `attest_time` (ERC-8004
  Validation Registry write).
- **Exit:** deployed on AWS; remote MCP handshake + the time/log/verify loop pass
  over HTTP; a light load test passes; the AWS info checklist in `deployment.md`
  is filled in.

---

## At a glance

| Dimension | v1 | v2 | v3 |
|---|---|---|---|
| Target date | Fri Jun 19, 2026 | Fri Jun 26, 2026 | TBD (gated) |
| Runs where | local (npx/stdio) | Mac mini | AWS (Fargate) |
| Who tests | us | Claude + AgentDash agents, 3-5 business testers | us, on AWS |
| Transport | stdio | stdio (agents) + HTTP (testers) | HTTP (remote) |
| Time oracle (A) | yes | yes | yes |
| Notarization (B) | yes | yes | yes |
| Agent identity (C) | resolve (read) | resolve (read) | resolve + attest (write) if backend ready |
| Contracts (D) | no (blocked) | no (blocked) | only if `/schedule` exposed |
| Funding | local credit | credit + cap | x402 / API-credit seam |
| Auth | none (local) | tester tokens | per-request, non-custodial |
| Public? | no | private test | private until mainnet |

## What gates each version

- **v1:** the EVM RPC URL + chain (for `resolve_agent`); everything else is built.
- **v2:** v1 done + the Mac mini setup (wire `~/.claude.json`, run the HTTP host,
  set tester tokens + credit cap) + 3-5 business testers lined up.
- **v3:** the AWS info checklist (account, domain/DNS, secrets, managed RPC,
  funding decision) + a go decision after v2.
