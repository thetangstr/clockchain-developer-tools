# MCP Server - Slide Materials

Two slides, distilled from the MCP plan (Phase 3 of `implementation-plan.md`).
Kept simple. Source detail is in `implementation-plan.md`, `mcp-readiness.md`,
and `product-a-identity-decision.md`.

---

## Slide 1 - Requirements

**Title:** What a Clockchain MCP server must get right

**Takeaway line:** Two bars to clear - the blockchain non-negotiables, and the
things that make it actually usable by an agent.

**Must-have (blockchain provider)**
- Non-custodial - the server never holds a private key
- Propose-then-approve - the agent prepares a write, a human / keyring signs it
- Standards-based identity - ERC-8004 + SIWA, not a proprietary DID
- Separate read tools from write / custody tools
- Agent-payable funding - API credit or gasless stablecoin (x402), not wallet + gas

**Usable by agents (experience)**
- Clear, recoverable errors - no raw 500s or cryptic "no tokens"
- Idempotent writes - a retry never double-spends a credit
- Rate-limit resilience - throttle, queue, cache reads
- Recall - a local index so an agent can find its own history
- Observability - every tool call traced

**Optional footnote:** The current `/schedule` tool (private key in a URL) and the
proprietary DID both violate the must-haves and are being redesigned.

---

## Slide 2 - Implementation Plan (Phases)

**Title:** MCP server - phased plan

**Takeaway line:** Ship a verified core as a POC first; the standards work is
later and conditional.

| Phase | What | When |
|---|---|---|
| 1 | Core client over the verified APIs (time, log, verify) | Wk 1-2 |
| 2 | CLI - terminal access | Wk 2-3 |
| 3 | **MCP server POC** - local, verified tools; learn the requirements (not a launch) | Wk 3-4 |
| 4 | Remote MCP + docs | After POC go / no-go |
| 5 | ERC-8004 hybrid + time-attestation | Conditional on customer |

**Ships first (verified, works today):** time, log, verify, search.

**Gated on the backend (not our tooling):** smart-contract triggers (`/schedule`),
agent-payable funding, public identity resolver.

**Honest framing:** Phase 3 produces a findings document and a go / no-go, not a
shipped product. We do not market autonomous agent usage until funding and
resolution are solved.
