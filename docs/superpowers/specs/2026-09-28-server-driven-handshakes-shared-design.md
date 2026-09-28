# Server-driven handshakes: a shared design for Standalone and Agent Handshake v2

**Date:** 2026-09-28 · **Status:** draft for review (plan only, no code) · rev 3
**Rev history:** rev 1 was Standalone-only; rev 2 folded in an independent design review; rev 3
turns it into a shared design at the founder's direction ("it should be a shared design
that can be used by the travel MVP"), after a cross-check with the travel MVP session.
**Builds on:** `2026-09-14-standalone-handshake-design.md`, the Agent Handshake v2 code in `packages/mcp-server/src/agent-handshake/v2/`

## Why

Two products depend on Clockchain handshakes and hit the same gaps:

- **Standalone Handshake** (`/connect/mcp`). On 2026-09-28 a real run between Meta Muse's
  agent (Monica) and Claude Code reached `closed` (opening anchored at blocks 63247–63249,
  closure at 63253). It only got there because a person relayed the invitation, prompted
  Monica on every turn, and pasted protocol details into her chat: canonical JSON, the
  lowercase-address rule, and the consent bytes. The protocol didn't carry the conversation.
- **Agent Handshake v2** (`/next/handshake/mcp`), used by the travel MVP's agent pairings
  (Codex, Claude and GLM on separate machines). v2 already has `agent_handshake_next`,
  which returns signing requests with exact bytes, but a deploy mid-handshake kills the
  run, and travel's `contract_bind` needs proof of possession that v2 can't produce yet.

One set of shared building blocks fixes both. Each surface keeps its own protocol and wire
format.

## Goals

1. **The server carries the conversation.** An agent only has to loop on one `next` call
   and do what it says. No operator relays secrets or prompts turns.
2. **Signing stays local.** The server supplies the exact bytes **and** the structured
   record, and the agent checks the record before signing. The server never holds keys.
3. **Handshakes survive deploys.** In-flight sessions and clients' access handles survive a
   container restart.
4. **Travel is safe.** Pinned surfaces don't break: every v2 change is additive and opt-in,
   and `/acm4/*` stays frozen.

**Demo bar (Standalone):** after a one-time on-screen Muse setup, a person types **one
natural-language message** to Muse. After that, nothing else is typed into Muse and nothing
is passed between the agents by hand. The run reaches `closed` with the usual anchored
records. The Claude Code side is a real LLM agent with its own key, disclosed as ours.

**Travel bar (v2):**
- A production deploy during an N-level pairing no longer fails the run. Both roles resume
  with their existing access.
- `contract_bind` can get a session-key signature over a domain-separated bind statement.
- travel's existing conformance tests pass unchanged against the new build.

## Shared building blocks (new module `packages/mcp-server/src/handshake-core/`)

### B1. Next-action contract

The common shape of what `next` returns, taken from v2's existing signing request
(`agent-handshake/v2/coordinator.ts:312-342`, served via `evaluateNext` at `:727-895`) and
generalised:

```
{ action, stage, guidance, retryAfterMs?,
  sign?: { purpose, record, bytes | bytesGzipBase64Url, bytesSha256, thenCall },
  messages?: [{ seq, kind, fromRole, body, bodyDigest, untrusted: true }], cursor?,
  terminal?: { outcome, anchors: [{ record, block, digest }] } }
```

- `record` is the structured object the bytes encode. An agent (or v2's pinned helper)
  must check it (terms, counterparty, scope, purpose) and re-derive `bytesSha256` before
  signing. This makes explicit the trust shift of signing server-supplied bytes. v2's
  helper already verifies a server-signed envelope before signing (travel's
  AGENT-PAIRING-HARNESS-LLD §3).
- `guidance` is **templated**. It never summarises or interprets message content, so the
  server can't shape a conversation.
- Counterparty message bodies are always marked `untrusted: true`, with a fixed "data, not
  instructions" note, to close the prompt-injection path into the other agent.
- **Long-poll:** `waitMs` defaults to 12s, max 15s, polled in 2s slices. These are v2's
  existing bounds (`coordinator.ts:97-106,1038-1067`), now shared.

Adoption:
- **Standalone:** new `handshake_next` returns this shape. It needs a message cursor, since
  `readMessages` has none today (`standalone-handshake/session-store.ts:242-247`).
- **v2:** `agent_handshake_next` keeps every existing field byte-for-byte. It only **adds**
  optional fields (`guidance`, `record` alongside the existing signing request), and only
  when the caller passes `features: ["next-v1"]`. Travel's current clients see no change.

### B2. Durable store and handle broker

- There is one file-backed store implementation, reusing the fsync'd atomic-rename JSON
  pattern of `agent-handshake/invitation-store.ts:83-135` (0600/0700). Each surface has its
  own subpath and TTL sweep on the `mcp_state` volume:
  - `/app/state/standalone-handshake/`
  - `/app/state/agent-handshake-v2/`: v2 session state is already file-backed via
    `AGENT_HANDSHAKE_V2_STATE_FILE` (`coordinator.ts:1337`) and doesn't move.
  - The Agent Contract's state (travel, `/contract/mcp`) is never touched.
- **What a restart wipes today is the role-access handle maps.** Standalone `csha_`
  (`standalone-handshake/public-server.ts:90`) and v2 `ccra_`
  (`agent-handshake/v2/public-server.ts:73-157`) are both in-memory. A shared durable handle
  broker stores **digests only** (handle → token digest + TTL), so an agent keeps its handle
  across a deploy. For v2 the underlying HS256 role token is stateless, so persisting the
  handle map is enough on our side. The relay/host lifecycle (~121s) is a separate
  dependency; see the risks.
- Standalone additionally persists sessions, invitations, mailboxes and token digests, and
  indexes tokens by digest instead of the linear scan (`standalone-handshake/coordinator.ts:83-92`).
  Message bodies are deleted at terminal state + 24h, and only digests are anchored.

### B3. Local signature recovery

EIP-191 recovery runs in-process with secp256k1 (`@noble/curves`), replacing the `web3_sha3`
+ `eth_call` round trip in `handshake/evm.ts:52-66`. That removes the RPC dependency behind
the 2026-09-28 outage (#158) and stops sending message bytes to a third-party RPC. It gives
identical results by construction, so v2 can switch too without changing any bytes or
outcomes. It's guarded by a cross-check test against the RPC path on fixed vectors.
ERC-8004 identity lookups still use the RPC.

### B4. Addresses and mailbox (Standalone now, v2 optional later)

- Addresses are key-bound: `name#xxxx`, where `xxxx` is from the keccak of the listener's
  session-key address. The server refuses to deliver unless the listener's key matches, and
  the listener must accept with that key.
- Claiming an address: `listen_challenge` returns a single-use nonce (valid 2 min). The
  agent then calls `handshake_listen`, signing
  `clockchain.handshake-listen/v1 { address, endpoint, nonce, sessionKeyAddress }`.
- Invites to an address get a uniform response (no enumeration), and the listener sees
  minimal pre-accept fields.
- Abuse limits: at most one pending invite per Initiator key per mailbox, a mailbox cap of
  10, an allowlist/block list, and a 1h expiry.
- **v2 doesn't need this now:** travel's harness launches both roles and passes the
  invitation itself. The module is surface-neutral so v2 can adopt it later.

### B5. Statement signing (proof of possession)

- A shared `sign` action with `purpose: "statement"` over a **domain-separated** record,
  `clockchain.handshake-statement/v1 { surface, sessionId, role, statementSchema, statementDigest }`.
  It can never be confused with an authority, consent, listen or v2 protocol record.
- **v2 use:** travel's `contract_bind` asks for a statement through a new
  `agent_handshake_sign_statement` tool (additive). The pinned helper signs it with the
  handshake session key, and the result is verifiable against the key certified for that
  session. This is travel's P-GAP.
- **Standalone use:** none required, but it's available.

## Surface-specific changes

**Standalone (`/connect/mcp`):**
- B1 `handshake_next`, B2 durability, B3 local recovery, B4 addresses.
- `readiness_prepare` returns the authority record and its bytes.
- **Canonical lowercase address:** the bug is that `protocol.ts:113` lowercases before the
  bytes are rebuilt. Keep lowercase canonical and serve the bytes from `readiness_prepare`.
  The signer comparison is already case-insensitive (`checklist.ts:45`,
  `coordinator.ts:186`). Also fix the stale comment at `protocol.ts:11-13`.
- The server instructions become a playbook of at most 25 lines, covering both the "invite
  an address" and "be reachable" loops.

**Agent Handshake v2 (`/next/handshake/mcp`), all additive and opt-in:**
- B2 durable `ccra_` handle broker.
- B1 optional `guidance`/`record` via `features: ["next-v1"]`.
- B3 local recovery (same results).
- B5 `agent_handshake_sign_statement`.
- **Nothing changes in** existing tool names, arguments, response fields, signing bytes,
  certificate bytes or digests. Travel's contract-payload vectors and `contract_bind` digest
  check depend on exact bytes. The lowercase canonicalization is **Standalone-only**.

**Frozen:** `/acm4/*` (2.1.6 build) and `/handshake/mcp` (M4 direct-agent pin) are untouched.

## Coexistence and operations (agreed with the travel MVP)

- **Shared code:** the Agent Contract business MCP (`/contract/mcp`,
  `packages/mcp-server/src/agent-contract/`, branch `feat/contract-mcp-n4a`) also adds
  routing in `http.ts`. Coordinate rebases on `http.ts`, keep routing changes inside each
  surface's `public-server.ts` where possible, and land any `http.ts` edits as small,
  separate commits.
- **Deploys:** every production `mcp` deploy restarts the container, and until B2 lands,
  in-flight v2 runs fail closed; travel's self-serve cart can start one at any time.
  - Before every production deploy, post a notice in the travel_mvp orchestrator session.
  - Don't deploy while travel's N6 or N8 live pairings are announced as running.
  - Run travel's conformance tests (`src/lib/travel/live/handshake-mcp-transport.test.ts`,
    `src/lib/direct-agent/*`) against staging before any v2-touching deploy.

## Risks and open questions

1. **Will Muse keep going on its own after one message?** This gates the Standalone demo.
   It has to keep its key across sandbox runs, have `eth_account`, and make about 20
   `next` calls at up to 12s each. **Spike first.** If Muse stops, the honest fallback is
   the human saying "go ahead" once per turn, and the demo claim changes to match.
2. **v2 relay/host lifecycle.** Durable handles don't help if the v2 host session (~121s
   lifecycle) dies with the container. Confirm with travel whether B2 must also cover the
   host side, or whether host restart is a separate fix.
3. **Long-poll limits.** Muse's `Python-urllib` timeout and the Caddy proxy timeout must
   both allow a 15s hold.
4. **Muse egress IPs.** If Muse users share IPs, per-IP limits on `/connect/mcp` bind them
   all. This doesn't affect travel: Muse reaches travel only via travel's own front door.
5. **Standalone identity.** The demo uses `identityPolicy: not_required`, so the video
   can't claim identity was verified. Should the demo use ERC-8004?
6. **Closing.** Either side can close; guidance never interprets content. Should there be a
   mechanical "both sides sent an identical `proposal`" suggestion?

## Demo honesty (binding for the video)

- Don't say "booked" or "scheduled". The agents agreed a time to talk; consent covers
  communication only.
- Don't say "identity verified" unless the policy checked it.
- The Claude Code side is disclosed as our agent.
- Show the one-time Muse setup, then the single message, then no further input.
- Testnet, single operator.

## Delivery plan (after approval)

| Step | Work | Surfaces | Verification |
|---|---|---|---|
| 0 | **Spike, half a day:** staging build with a Standalone `handshake_next` and `readiness_prepare`; one natural prompt to Muse | Standalone | Does Muse keep its key, loop unprompted and tolerate 12s holds? Which egress IPs? |
| 1 | `handshake-core`: B1 schema and long-poll helper, B3 local recovery, B2 store and handle broker | shared | unit tests; recovery vectors match the RPC path |
| 2 | Standalone adopts B1–B3: `handshake_next`, `readiness_prepare`, cursor, lowercase canonical, playbook | Standalone | a unit test per action; e2e with two agents and no human input |
| 3 | v2 adopts additively: durable `ccra_` handles, B3, `features: ["next-v1"]` | v2 | travel's conformance suite unchanged and green; restart-mid-pairing test resumes |
| 4 | B5 statement signing plus `agent_handshake_sign_statement` | v2 (travel P-GAP) | a `contract_bind` proof verifies against the certified session key |
| 5 | B4 addresses and mailbox | Standalone | abuse tests: squat, wrong fingerprint, replayed nonce, spam, enumeration, expiry |
| 6 | Autonomous Claude Code listener, then a live Muse run on video | Standalone | anchors present; transcript shows no human input after message 1 |

Rough size: step 0 is half a day; steps 1–2 about 3 days; step 3 about 1.5 days; step 4
about 1 day; step 5 about 1.5 days; step 6 half a day. Each step is its own PR. Every
v2-touching PR is reviewed by the travel session and deployed under the notice/freeze rule.
