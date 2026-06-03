# Developer & Agent Journeys - Does the API Flow Support Agent Usage?

The MCP-readiness assessment scored tools one by one. This document does the
other half: it walks the two end-to-end journeys - a human developer setting it
up, and an AI agent using it autonomously at runtime - and marks where each one
holds up or breaks against the **verified** API behavior.

The question driving this: in the agent-tooling product category, an MCP server
is judged by whether an agent can actually operate through it without a human in
the loop. So the agent journey is the one that matters most, and it is graded
hardest here.

Grounded in live tests (2026-06-02/03). PASS = verified to work. BREAK = verified
to fail or be impossible today. FRICTION = works but with a cost that will hurt
adoption.

---

## What "supports agent usage" means in this category

An agent-facing notarization + identity product is expected to let an autonomous
agent:

1. **Self-register** an identity on first run
2. **Log its actions** as it works, without asking a human each time
3. **Verify** another agent or piece of data before trusting it
4. **Recall** its own history (what did I do, and when?)
5. **Prove** an action when challenged
6. **Pay** for all of the above without a human signing each transaction

That list is the bar. The journeys below are graded against it.

---

## Developer journey (human, one-time setup + integration)

| Step | What happens | Status |
|---|---|---|
| 1. Sign up | Get a Client ID (email) and an API key from the dashboard | PASS |
| 2. Understand what to fund | Three separate meters (API requests, D4D tokens, logs) with only one shown on the main dashboard; logging needs "logs," which start at 0 | FRICTION |
| 3. Get logs | Buy via card ($2 / 1,000) or a wallet + gas-token swap on Sepolia | FRICTION (wallet path is a multi-step cliff; card path is fine) |
| 4. Install MCP server | `npx @clockchain/mcp-server` (once built) | PASS (planned) |
| 5. Configure | API key + clientId + walletId (= email) in MCP env | PASS (verified the email works as walletId) |
| 6. First read | `get_time` returns live data | PASS |
| 7. First write | `log_action` anchors on-chain in ~0.6s | PASS (verified) |
| 8. Build a real integration | e.g. log every step of a chain | FRICTION (rate limits + credit burn, see agent journey) |
| 9. Verify / prove | Works for a record whose exact reference you kept | PASS / FRICTION |

**Developer verdict:** the happy path works. The friction is concentrated in
funding (steps 2-3) and in the fact that history only works if the developer
retains references (step 9). Nothing here is a hard blocker for a human - they
can click, pay $2, and keep their own IDs.

---

## Agent journey (runtime, autonomous - the real test)

This is the same flow with no human available to click, pay, or remember things.

| Step | What the agent needs to do | Status | Why |
|---|---|---|---|
| 1. Connect | Load MCP server with operator-provided creds | PASS | Creds are set once by the human operator; fine |
| 2. Discover tools | `tools/list` | PASS | Standard MCP |
| 3. Read time | `get_time` / `get_timestamp` | PASS | Verified |
| 4. Self-register identity | `mint_agent_identity` | FRICTION | Write works, but the identity doc (name, capabilities, owner) cannot be stored on-chain - `additionalInfo` strips structure. Agent must keep the doc itself somewhere |
| 5. Log an action | `log_action` (hash + ref) | PASS, then BREAK | First writes succeed. But each spends a "log" credit, and when they run out the agent gets `"No enough tokens"` and **cannot refill** - topping up needs a card or a wallet+gas transaction, neither of which an agent can do |
| 6. Log frequently | Log many actions in a session | BREAK | Rate limiting trips after ~1-2 quick calls with a ~100s cooldown. An agent logging per-step (the LangChain-callback vision) stalls almost immediately |
| 7. Recall own history | "What have I logged?" | BREAK (unaided) | `searchAsset` is exact-match only - no list, no prefix. An agent cannot enumerate its own actions unless it (or the MCP server) kept every reference client-side |
| 8. Verify another agent | `verify_agent_identity` on a peer's DID | BREAK | `searchAsset` is scoped to the caller's own clientId. An agent literally cannot see another client's identity record. The agent-to-agent handshake - the headline Product A scenario - is impossible today |
| 9. Prove an action | `generate_proof` | FRICTION | Works, but only 2 of 5 layers are real, and on the single-node testnet the consensus numbers are all 0 |
| 10. Pay for all of it | Sustain funding autonomously | BREAK | No API-credit / prepaid funding path. Funding is wallet- or card-only, both human actions |

**Agent verdict:** the agent journey supports the *read-and-occasionally-log*
path and nothing more. Four of the six things the category requires
(self-fund, log-at-volume, recall history, verify peers) break today. The flow as
it stands supports an agent that reads time and notarizes the occasional action
under a human-funded, low-frequency budget - not an autonomous agent operating at
runtime scale.

---

## The breakpoints, ranked by how badly they block agent usage

1. **Funding is not agent-payable (step 5/10).** The hardest blocker. An agent
   cannot refill logs - it needs API-key / prepaid-credit funding set up once by
   the operator. Without this, every agent eventually halts and waits for a human.
   This is also the industry-standard model (prepaid credits; or gasless USDC via
   x402) - see `industry-landscape.md`.

2. **Rate limiting kills per-step logging (step 6).** ~100s cooldowns make the
   "log every action" pattern impossible. Agents need either a real rate tier or a
   batch/anchor-many-in-one-write endpoint.

3. **No cross-client verification (step 8).** Without an unscoped resolver, the
   agent-to-agent trust scenario (Product A's reason to exist) cannot run.

4. **No history enumeration (step 7).** Agents cannot recall their own trail
   through the API. Mitigable client-side (below), but the API gives no help.

5. **No structured on-chain metadata (step 4).** The identity/action document
   can't live on-chain; only its hash can. Mitigable client-side, but it means the
   chain is an anchor, not a record.

---

## What the MCP server can paper over vs what it cannot

A well-built MCP server can hide some of these. It cannot hide the existential
ones. Being clear about which is which matters for scoping.

**The MCP server CAN mitigate (client-side, no backend change):**
- **History (step 7):** keep a local index of every `ledgerId` / `assetReferenceId`
  it writes, so `search_actions` can list an agent's own history from that index.
- **Metadata (step 4):** maintain the off-chain identity/action documents, anchor
  only their hashes, and rehydrate on read. The agent sees rich records; the chain
  holds hashes.
- **Rate limits (step 6), partially:** throttle, queue, and cache reads
  (`get_time`) to stay under the cooldown. This smooths bursts; it cannot raise the
  ceiling for genuinely high-frequency logging.
- **Funding errors (step 5):** detect low balance and surface a clear, early
  "operator must refill" signal instead of a cryptic failure mid-task.

**The MCP server CANNOT fix (backend required):**
- **Agent-payable funding (step 10):** an agent still cannot buy credits. Needs an
  API-credit / x402-style funding path on the platform.
- **Cross-client verify (step 8):** needs a public resolver endpoint.
- **High-frequency logging ceiling (step 6):** needs a real rate tier or a
  batch-anchor endpoint.
- **Real proofs (step 9):** needs a multi-validator network.
- **Triggers:** `/schedule` must be exposed.

---

## Category requirements vs current state

| Category expectation (agent tooling) | Clockchain today |
|---|---|
| Agent self-funds via API credit / gasless stablecoin (x402) | Wallet- or card-only; not agent-payable |
| Agent logs continuously without throttling | ~100s cooldown after a couple calls |
| Agent verifies peers / external identities | Same-client only; no resolver |
| Agent recalls its own history via the API | Exact-match fetch only; no list |
| Records are self-describing | Hash-anchor only; metadata sanitized |
| Proofs are independently meaningful | 2 of 5 layers; single-node zeros |

---

## Recommendation

**Ship the MCP server now for the verified slice, and build it so the client-side
mitigations are in from day one** - local ref index for history, off-chain doc
store for metadata, request throttling, and early low-credit warnings. That makes
the developer journey and the *read-plus-occasional-log* agent journey genuinely
good today.

**But do not market autonomous agent usage until the backend closes the two
existential gaps:** agent-payable funding and a public resolver. Until those land,
an agent on Clockchain is a human-funded, low-frequency notary that cannot verify
its peers - which is a useful tool, but not the autonomous-agent story Product A
and B are sold on.

The honest one-liner: **the API flow supports agent *integration* today, but not
agent *autonomy* yet.** The gap between those two is funding and resolution, and
both are backend decisions, not tooling.
