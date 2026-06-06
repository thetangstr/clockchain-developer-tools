# Clockchain MCP Server - Requirements & Deployment Brief

**For approval by: Stakeholders (Product / Leadership) + Network Team + Backend (D4).**
**Status: PROPOSED - awaiting sign-off.**  Date: 2026-06.

This is the single approval document. It consolidates what the MCP server is, the
requirements it must meet, and the technical/deployment dependencies that need
provisioning or a decision. Detailed specs are linked at the end; this brief is
meant to stand alone for a sign-off meeting.

---

## 1. Executive summary

- **What:** an MCP server that lets AI agents and developers use Clockchain's
  time oracle and notarization (and, next, ERC-8004 agent identity) through
  standard agent tooling.
- **Where it is:** **in progress.** Core development and integration testing are
  underway against the Clockchain gateway.
- **Milestones:** **v1 - Fri Jun 19, 2026** (basic features, local) · **v2 - Fri
  Jun 26, 2026** (Claude + AgentDash on the Mac mini) · **v3 - TBD** (AWS, gated on
  network-team readiness + the smart-contract API). See Section 4.
- **What we are asking to approve:**
  1. the requirements (Section 3),
  2. the network exposure model (Section 5) - this is the network team's main item,
  3. provisioning the deployment dependencies (Section 6) so we can run v1 and v2.
- **Guardrails (what this is NOT):** smart contracts are blocked (gateway 404); no
  public endpoint until mainnet; we are not marketing autonomous agent usage yet.

---

## 2. What we are building (feature status)

| Capability | Shorthand | Status |
|---|---|---|
| Time oracle (read consensus time, blocks, validation) | "time stamp" | **In progress** |
| Notarization (hash in, timestamped proof, verify) | "tsa" | **In progress** |
| Agent identity read (ERC-8004) | identity | **In progress** (needs EVM RPC) |
| Smart-contract triggers | "contract" | **Blocked** (gateway 404) |

---

## 3. Requirements

### 3a. Functional
- Read consensus time and block/validation data.
- Notarize a SHA-256 hash on-chain and verify a hash against the on-chain record.
- Resolve an agent's ERC-8004 identity (read).
- Later: attest a consensus-time validation to the ERC-8004 Validation Registry.

### 3b. Blockchain-MCP requirements (must-haves)
- **Non-custodial:** the server never holds a private key.
- **Propose-then-approve:** any value-moving or contract action is prepared by the
  agent and signed by a human/keyring, never auto-signed.
- **Standards-based identity:** ERC-8004 + SIWA (committed), not a proprietary DID.
- **Read vs write/custody tool separation.**
- **Agent-payable funding:** API credit or gasless stablecoin (x402), not
  wallet + gas.

### 3c. Security & non-exposure
- Default to **stdio (no network listener)**; the Clockchain API key stays on the
  host; per-tester auth tokens; a credit-budget cap; every tool call logged.

---

## 4. Milestones (v1 / v2 / v3) with target dates

| Milestone | Target date | Where | What "done" means |
|---|---|---|---|
| **v1** - basic features | **Fri Jun 19, 2026** | local (npx / stdio) | time oracle + notarization tools working locally; identity read once the EVM RPC is provided |
| **v2** - Claude + AgentDash | **Fri Jun 26, 2026** | Mac mini | an agent uses it via `~/.claude.json` (stdio); remote testers via tailnet; first business-tester feedback |
| **v3** - production (AWS) | **TBD - gated** | AWS (Fargate + ALB) | deployed on AWS, tested. Gated on (a) network-team deploy readiness and (b) the smart-contract (`/schedule`) API being ready |

Dependencies that move these dates: **v1** assumes the EVM RPC + chain are
provided (Section 6); **v3** has no fixed date because it depends on the network
team's deploy window and the backend exposing the smart-contract API.

Detail: `roadmap.md` (v1/v2/v3) and `poc-build-plan.md`.

---

## 5. Network exposure model (NETWORK-TEAM APPROVAL)

**Proposal:** default to **stdio (no listener)**; when a networked endpoint is
genuinely needed, bind to the **tailnet only**; **never a public bind for a
key-holding endpoint.**

Reachability scopes on the Mac mini (probed 2026-06; the box is behind NAT, so not
public unless we add a tunnel):

| Scope | Address | Reachable by |
|---|---|---|
| loopback | `127.0.0.1` | the host only |
| LAN | `192.168.86.0/24` | the office/home subnet |
| tailnet | `100.71.225.125` (Tailscale) | Clockchain tailnet members |
| public | only via a tunnel | the internet (avoid) |

Posture: AgentDash and Claude run **on** the Mac mini, so they reach the MCP over
stdio / loopback - **no network exposure.** Remote testers use the **tailnet**
only. The Clockchain gateway is reached **outbound**; this model adds no inbound
credentialed path. Full tables in `deployment.md` Section 0.

**Network-team decisions:**
1. Approve **stdio / loopback default** for co-located agents (no exposure). [ ]
2. Approve **tailnet-only** for remote testers; no LAN-wide, no public bind. [ ]
3. Clarify "expose the Clockchain server":
   - (a) "no new hosted credentialed MCP endpoint" -> covered by 1 + 2. [ ]
   - (b) "lock `node.clockchain.network` to a private network/allowlist" -> larger
     change; consumers must be on that network (tailnet fits). [ ]
4. v3 on AWS: public, mainnet-gated [ ] / tailnet-VPN-only [ ] / do not host,
   distribute stdio [ ].

---

## 6. Technical deployment dependencies (to provision or decide)

| Dependency | Needed for | Owner |
|---|---|---|
| EVM RPC URL + target chain (recommend Base Sepolia) + ERC-8004 registry address | identity read (`resolve_agent`), v1+ | Network / Backend |
| Clockchain test account: API key + client/wallet + **log credits** + budget cap | logging, all versions | Product / Backend |
| Mac mini host prep: node + pm2 (no Docker installed), disable sleep, tailnet on, tester tokens | v2 | Engineering |
| AWS: account + region + VPC (new or reuse D4's) | v3 | Network / Eng |
| Domain + DNS in Route53 (for TLS cert) | v3 | Network |
| Secrets store (Secrets Manager / SSM) for API key + RPC + tokens | v2/v3 | Eng |
| Managed EVM RPC at the edge | v3 | Network / Eng |
| Funding decision: x402 / API-credit seam | v3 (agent-payable) | Product |
| Expected scale + monthly budget ceiling | v3 sizing | Product |

Backend (D4) items that gate the *full* product (not v1/v2): expose `/schedule`
for contracts, a **public DID resolver** for cross-agent verification, a real
**multi-validator** network for meaningful proofs, and a real **rate tier**.

---

## 7. Out of scope (for now)

Smart-contract triggers (gateway 404), any public MCP-directory listing
(mainnet-gated), "autonomous agents at scale" (depends on funding + resolver), and
RFC-3161 TSA wire format (separate build).

---

## 8. Approvals

| Role | Name | Date | Decision (approve / changes / discuss) |
|---|---|---|---|
| Stakeholder / Product owner |  |  |  |
| Network team |  |  |  |
| Backend (D4) owner |  |  |  |

**Stakeholder sign-off covers:** build + run v1-v2 on the verified feature set,
the guardrails in Section 1, and the ERC-8004 hybrid direction (decided 2026-06).
**Network-team sign-off covers:** the decisions in Section 5.
**Backend sign-off covers:** the dependencies in Section 6 it owns.

---

## 9. References (detail behind this brief)

- `roadmap.md` - v1/v2/v3 + full feature inventory
- `implementation-plan.md` - the spec, blockchain-MCP requirements, and the MCP
  tool detail (Appendix A)
- `mcp-readiness.md` - per-tool readiness, grounded in live tests
- `deployment.md` - Section 0 (network model), Mac mini runbook, AWS plan + checklist
- `poc-build-plan.md` - sequenced build plan + how the Mac mini connects to Clockchain
- `product-a-identity-decision.md` - ERC-8004 vs proprietary DID (decision)

Status throughout this brief is **in progress**: the verified-slice tools (time,
logging, verify) are being built and tested against the Clockchain gateway. We
will update the status once integration testing is complete.
