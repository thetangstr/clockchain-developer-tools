# Clockchain MCP Server - Requirements & Deployment Brief

**For approval by: Stakeholders (Product / Leadership) + Network Team + Backend (D4).**
**Status: PROPOSED - awaiting sign-off. V1 POC validated on testnet.**  Date: 2026-06-08.

This is the single approval document. It consolidates what the MCP server is, the
requirements it must meet, and the technical/deployment dependencies that need
provisioning or a decision. Detailed specs are linked at the end; this brief is
meant to stand alone for a sign-off meeting.

---

## 1. Executive summary

- **What:** an MCP server that lets AI agents and developers use Clockchain's
  time oracle and notarization (and, next, ERC-8004 agent identity) through
  standard agent tooling.
- **Where it is:** **V1 POC validated on the testnet.** A live **MCP Playground**
  demonstrates the core end to end against the real network: an AI agent reads
  consensus time, produces tamper-evident **attested receipts**, **timestamps
  documents (TSA-style)**, **verifies + detects tampering**, and **resolves an
  ERC-8004 agent identity (read)**. Remaining for V1 hardening: access-controlled
  hosting for external testers, and the identity *write* path.
- **What we can validate/test today:** the five capabilities above, through a chat
  agent driving the MCP tools, with every result an independently verifiable,
  downloadable on-chain receipt.
- **Milestones:** **v1 - Fri Jun 19, 2026** (basic features - core already
  validated) · **v2 - Fri Jun 26, 2026** (hosted for testers + agent use) ·
  **v3 - TBD** (managed cloud, gated on network-team readiness + the smart-contract
  API). See Section 4.
- **What we are asking to approve:**
  1. the requirements (Section 3),
  2. the network exposure model (Section 5) - this is the network team's main item,
  3. provisioning the deployment dependencies (Section 6) so we can run v1 and v2.
- **Caveats / guardrails (what this is NOT yet):** **single-validator testnet** -
  the workflow + proofs are real, but multi-validator supermajority and "court-grade"
  claims come with mainnet; the **demo talks to the LLM directly** (not yet via our
  production agent); **reads are live, writes are designed** (identity write +
  smart-contract triggers use non-custodial propose-then-approve, not yet wired;
  `/schedule` is gateway-404); **install is from source** (npm publish prepped, not
  yet live); no public endpoint until mainnet.

---

## 2. What we are building (feature status)

| Capability | Shorthand | Status |
|---|---|---|
| Time oracle (read consensus time, blocks, validation) | "time stamp" | **Validated on testnet** |
| Notarization / proof-of-existence (hash in, timestamped proof, verify) | "tsa" | **Validated on testnet** |
| Agent attested receipt (who/what/when, tamper-evident) | receipt | **Validated on testnet** |
| Agent identity **read** (ERC-8004) | identity | **Validated on testnet** (reference registry - assumption to confirm) |
| Agent identity **write** (validation attestation) | identity | **Designed** (non-custodial propose-then-approve; needs a signer) |
| Smart-contract triggers | "contract" | **Blocked** (gateway 404 + non-custodial redesign) |

### Business use cases (and the Goldilocks one to lead with)

What the capabilities above are *for*, in business terms:

| Use case | What it does for a customer | Built on |
|---|---|---|
| **Tamper-evident proof of an AI agent's action** | Prove an agent did X at a verifiable time, and that the record hasn't changed - accountability for autonomous agents. | notarization + time oracle |
| Document / contract notarization | Hash a file, get a timestamped on-chain record, later prove it is unaltered (court-style check). | notarization |
| Audit trail for records | A verifiable, append-only log of events with consensus timestamps. | notarization |
| Verifiable time as a primitive | Read a decentralized, multi-source consensus clock instead of trusting one server. | time oracle |

**Goldilocks (lead) use case:** *tamper-evident proof of an AI agent's action.*
It is the **just-right wedge** - narrow enough to demo today on the verified
tools, it combines our two differentiators (verifiable **time** + agent
**action**), and it rides the agent/ERC-8004 direction we have already committed
to. Broader claims (a full compliance audit platform) are too big for the current
1-node testnet; bare "timestamp an API call" is too small to be differentiated.
We lead the demo and the pitch with the agent-action proof.

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
| **v2** - Claude + AgentDash | **Fri Jun 26, 2026** | Mac mini | agents use it locally; remote testers over a private network; first business-tester feedback |
| **v3** - production (AWS or GCP) | **TBD - gated** | AWS (Fargate + ALB) **or GCP (Cloud Run)** | deployed to a managed cloud, tested. Gated on (a) network-team deploy readiness and (b) the smart-contract (`/schedule`) API being ready |

Dependencies that move these dates: **v1** assumes the EVM RPC + chain are
provided (Section 6); **v3** has no fixed date because it depends on the network
team's deploy window and the backend exposing the smart-contract API.

Detail: `roadmap.md` (v1/v2/v3) and `poc-build-plan.md`.

---

## 5. Network exposure model (NETWORK-TEAM APPROVAL)

**Proposal:** default to **stdio (no network listener)**; if a networked endpoint
is ever needed, bind to a **private network (VPN / tailnet) only**; **never a
public bind for a key-holding endpoint.**

For **v1 and v2 there is no new inbound credentialed path** to Clockchain: the
agents that use the MCP run locally alongside it, and any remote testing is fronted
by an **identity gate** (below). The MCP only ever calls the Clockchain gateway
**outbound**. (The host and transport setup itself is an internal engineering
detail, not part of this approval.)

**Delegated tester access (how business users test without the key or a VPN).**
To let business testers try it, we put the endpoint behind **two independent
gates** instead of handing out the Clockchain key or asking testers onto a VPN:

1. **Edge identity gate (Cloudflare Access):** only allowlisted people (by email /
   SSO) can reach the endpoint at all; everyone else is blocked at the edge before
   any request touches our host. No VPN, nothing for testers to install.
2. **Application gate (our server):** per-tester revocable token, per-token rate
   limit, a logging-credit spend cap, read + notarize tools only, and
   **non-custodial** (no private key on the host). The Clockchain API key stays on
   the server and is never sent to the tester.

This is **not a public, open endpoint** - it is allowlist-gated and capped, which
satisfies the "do not expose the Clockchain server" ask while still enabling a
controlled business test. Detail: `DELEGATED-ACCESS.md`.

**Network-team decisions:**
1. Approve **local / no-listener default** for co-located agents (no exposure). [ ]
2. Approve **delegated tester access** = identity-gated (Cloudflare Access) +
   token + caps; no public bind, no key shared, no VPN required. [ ]
3. Clarify "expose the Clockchain server":
   - (a) "no new hosted credentialed MCP endpoint" -> covered by 1 + 2. [ ]
   - (b) "lock `node.clockchain.network` itself to a private network / allowlist"
     -> larger change, flagged for discussion. [ ]
4. v3 on AWS/GCP: public, mainnet-gated [ ] / identity-gated (Access/IAP) only [ ] /
   do not host, distribute the local server [ ].

---

## 6. Technical deployment dependencies (to provision or decide)

| Dependency | Needed for | Owner |
|---|---|---|
| EVM RPC URL + target chain (recommend Base Sepolia) + ERC-8004 registry address | identity read (`resolve_agent`), v1+ | Network / Backend |
| Clockchain test account: API key + client/wallet + **log credits** + budget cap | logging, all versions | Product / Backend |
| Mac mini test host prep + tester access tokens (internal engineering setup) | v2 | Engineering |
| Delegated tester access: a Cloudflare domain + Zero Trust **Access** app/policy + per-tester tokens (fronts the web demo and the MCP endpoint) | v2 (business testing) | Network / Eng |
| Cloud account + region: **AWS** (account/VPC) or **GCP** (project, e.g. reuse `yarda-740f4`) | v3 | Network / Eng |
| Domain + DNS for TLS (Route53 on AWS; managed cert / `*.run.app` on GCP Cloud Run) | v3 | Network |
| Secrets store (AWS Secrets Manager / SSM, or GCP Secret Manager) for API key + RPC + tokens | v2/v3 | Eng |
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

**Stakeholder sign-off covers:** build + run v1-v2 on the core feature set,
the guardrails in Section 1, and the ERC-8004 hybrid direction (decided 2026-06).
**Network-team sign-off covers:** the decisions in Section 5.
**Backend sign-off covers:** the dependencies in Section 6 it owns.

---

## 9. References (detail behind this brief)

- `roadmap.md` - v1/v2/v3 + full feature inventory
- `implementation-plan.md` - the spec, blockchain-MCP requirements, and the MCP
  tool detail (Appendix A)
- `mcp-readiness.md` - per-tool readiness, grounded in live tests
- `deployment.md` - Section 0 (network model), Mac mini runbook, AWS/GCP plans + checklist
- `DELEGATED-ACCESS.md` - how testers get access without the key or a VPN (Cloudflare Access + token/rate/budget caps)
- `poc-build-plan.md` - sequenced build plan + how the Mac mini connects to Clockchain
- `product-a-identity-decision.md` - ERC-8004 vs proprietary DID (decision)

Status throughout this brief is **in progress**: the core-slice tools (time,
logging, verify) are being built and tested against the Clockchain gateway. We
will update the status once integration testing is complete.
