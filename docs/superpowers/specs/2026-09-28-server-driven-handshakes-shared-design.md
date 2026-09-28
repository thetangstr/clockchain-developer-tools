# Server-driven handshakes: a shared design for Standalone and Agent Handshake v2

**Date:** 2026-09-28 · **Status:** draft for review (plan only, no code) · rev 5
**Rev history:** rev 1 was Standalone-only; rev 2 folded in an independent design review; rev 3
turns it into a shared design at the founder's direction ("it should be a shared design
that can be used by the travel MVP"), after a cross-check with the travel MVP session. Rev 4 applies the travel review of rev 3. Rev 5 adds supervised sessions (S1–S4) after the second Muse run failed and could only be recovered by a human relay.
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
  which returns signing requests with exact bytes. But a deploy mid-handshake is *expected* to
  fail the run closed (in-memory role handles; not yet observed in a travel run), and
  travel's `contract_bind` needs proof of possession that v2 can't produce yet.

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
- A production deploy during a pairing, which is expected (not yet observed) to fail it
  closed today, no longer does. Both roles resume with their existing access. Step 3's
  restart-mid-pairing test is the proof, including the host cases in risk 2.
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

- `record` is the structured object the bytes encode. **Normative:** the signer is the
  verifier. v2's pinned helper stays the verifier and signs nothing whose bytes and digest
  it didn't re-derive from `record` itself. Standalone agents are told the same by the
  playbook. The server's copy of the bytes is a convenience, never an authority.
- An agent (or v2's pinned helper)
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
  - The response echoes `features` with the set actually applied. Unknown features are
    ignored, not an error, so a newer client works against an older server.
  - Adding the optional `features` argument changes v2's published tool schema and its
    `tools/list` digest. Before deploy, confirm that neither the pinned helper 2.1.8
    manifest nor anything in travel pins that digest. Travel's staging conformance run
    also catches it.

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
outcomes. It's guarded by a cross-check test against the RPC path on fixed vectors. The vectors include
real v2 signatures from travel's live runs (`docs/travel-mvp/evidence/live/*/handshake-events*.jsonl`,
2026-09-21/22), not only synthetic ones.
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

- A shared `sign` action with `purpose: "statement"` over a **domain-separated** envelope:
  `clockchain.handshake-statement/v1 { surface, sessionId, handshakeSide, statementSchema, statementDigest }`.
  `handshakeSide` is `initiator` or `responder`, the handshake side. It's named that way so
  it can't be confused with a business role such as buyer or provider. The envelope can
  never be confused with an authority, consent, listen or v2 protocol record.
- **Schema allowlist:** the server and v2's pinned helper refuse any `statementSchema`
  outside an explicit allowlist, so this never becomes a general signing oracle. The
  initial allowlist is `agent-contract.bind/v1`.
- **v2 use (travel's P-GAP):** a new, additive tool `agent_handshake_sign_statement`.
  - **Bind statement** `agent-contract.bind/v1`, canonical JSON (travel proposal; the
    travel audit agent confirms the final schema, LLD §3):
    `{ schema, contractEndpoint: "https://mcp.clockchain.network/contract/mcp", handshakeSessionId, certificateDigest (of the signed result), side, businessRole, agentId (ERC-8004), businessKeyId, bindNonce (single-use, issued by /contract/mcp, TTL ≤ 2 min), issuedAtMs, expiresAtMs }`.
    `statementDigest` is the sha256 of those canonical bytes.
  - **Signed with the party's session key**, not `hostSessionKeyCertificate`, because the
    host key certifies the coordinator, not the party. `/contract/mcp` recovers the
    envelope signer and requires all of:
    - the signer equals `certificate.result.<side>.sessionKeyAddress`;
    - `surface == "v2"`;
    - `sessionId == handshakeSessionId`;
    - `handshakeSide == side`;
    - the digest matches.
  - **Works after the certificate is issued** (terminal state) for as long as the
    certificate is fresh (`validUntil` plus a grace period), with the existing `ccra_`
    handle. The handle's TTL must cover that post-certificate bind window. Until step 3
    makes handles durable, a deploy during the bind window loses the handle, so the
    notice/freeze rule applies.
- **Standalone use:** none required, but the same module is available.

### Supervised sessions (S1–S4): no human relay, ever

**Rule:** no agent may ever need its human to relay something to the other agent. Anything
one side needs from the other goes through the server, and people see what happened from
the server, not by reading an assistant's screen.

Evidence, from the 2026-09-28 second Muse run (staging session `fe08b229`):
- Monica's readiness failed with `MANIFEST_MISMATCH`: her data-handling class differed from
  the Initiator's. The session went terminal and the invitation was burned.
- Monica could only ask her human to "get a fresh invitation plus the exact purpose from
  your Claude Code agent". In real use that message never reaches the other agent.
- She also misstated the cause (she said the purpose, not the data class). The server knew
  the precise reason; her summary didn't.

- **S1. Preview before accepting.** A public, read-only `handshake_preview_invitation { invitation }`
  returns the terms the Responder must match: purpose, channel limits, identity policy, the
  required `dataHandlingClass`, and the invitation expiry. It burns nothing and needs no
  access. Its free-text fields are marked untrusted. With B4 this becomes
  `review_invitation`.
- **S2. Failed checks can be recovered.** A readiness that fails the checklist no longer
  ends the session:
  - The session enters `readiness_retry`. The invitation stays claimable by the **same**
    Responder, up to 3 attempts, and only within the invitation TTL.
  - Failure codes are specific: `PURPOSE_MISMATCH`, `DATA_CLASS_MISMATCH`,
    `AUTHORITY_INVALID`, `IDENTITY_UNVERIFIED`. Each comes with a machine-readable
    `required` object, e.g. `{ capabilityManifest.dataHandlingClass: "public" }`.
  - The Responder's `handshake_next` returns `action: "fix_readiness"` with those details.
  - The Initiator's `handshake_next` returns `wait` with templated status: "counterparty
    correcting readiness (attempt 2/3, DATA_CLASS_MISMATCH)".
  - After the last attempt, the session ends as `ready_failed` for both sides, with the
    same reason.
- **S3. Both sides hear the same facts, from the server.** Every terminal or blocking state
  reaches **both** parties through `handshake_next`, with the precise reason code and the
  next legitimate step (e.g. "the Initiator may issue a new invitation"). A templated
  `tellYourUser` line gives the agent an accurate, non-speculative sentence to report.
  Agents are told never to ask their human to relay anything to the counterparty.
- **S4. The server keeps a timeline for supervision.** Every session keeps an append-only
  event timeline:
  - Events: invited, previewed, accepted/attempted, checklist result per attempt with
    codes, consent per role, open, message (kind, seq, digest, never the body), close,
    revoke, expire, abandon.
  - Each event carries a timestamp and, where anchored, block and digest.
  - Parties read their own session's timeline with `handshake_timeline { access }`.
  - Operators read all sessions through an admin-only read API. This is the data source for
    the Agent Contract ops dashboard (handshakes, contracts, negotiation steps).
  - The timeline is persisted with B2. Bodies are never stored in it.

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

**Frozen:** `/acm4/*` (2.1.6 build) and `/handshake/mcp` are untouched. `/handshake/mcp`
is still used by travel's M4 direct-agent path (`src/lib/direct-agent/conformance.ts:25`)
and runs in the same container, so the step-3 durability test also asserts its
`tools/list` and responses are byte-identical before and after.

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
  - **No v2 behaviour change ships without travel's staging conformance run attached to
    the PR.** That makes the review rule checkable.
- **Deploy blast radius (ops fix, independent of this spec).** `deploy-box.sh` runs
  `install-clockchain-mcp-deploy-assets.sh`, which does `systemctl restart clockchain-mcp`.
  The unit's `ExecStop` is `docker compose down` (`infra/clockchain-mcp/clockchain-mcp.service:12`)
  and `ExecStart` runs `compose-up.sh` (`up -d --build --wait`). So every code deploy
  recreates **every** service in that compose: `mcp`, `host` (the v2 host, ~121s
  invitation cycle by design) and `caddy`. Because Caddy is recreated too, `/acm4/*`
  (the frozen 2.1.6 path behind the ACM4 cart) and `/mcp` anchoring also drop briefly on
  every deploy, not only v2.
  - **Default** `deploy-box.sh` to a code-only path (`docker compose up -d --no-deps --wait mcp`).
    A full unit restart requires an explicit flag (e.g. `--full-restart`) and is used only
    for infra/config changes.
  - Any full-unit restart gets the same notice/freeze rule, and the notice also goes to
    the ACM4 production owner (the travel orchestrator routes it).
  - `--no-deps mcp` still recreates the `mcp` container, so in-memory `ccra_`/`csha_`
    handles are still lost on every code deploy. **The notice/freeze rule stays in force
    until step 3 is deployed and its restart test is green**, not merely once the code-only
    path exists.

## Risks and open questions

1. **Will Muse keep going on its own after one message?** This gates the Standalone demo.
   It has to keep its key across sandbox runs, have `eth_account`, and make about 20
   `next` calls at up to 12s each. **Spike first.** If Muse stops, the honest fallback is
   the human saying "go ahead" once per turn, and the demo claim changes to match.
2. **v2 host lifecycle.** `clockchain-mcp-host-1` is a separate compose service. By
   design it runs a 120s invitation window, then exits 0 and restarts (~121s cycle).
   Travel's only observed failure from it is the invite dead tail, which they handle
   client-side. B2 stays scoped to our handle map, and the host is out of scope. The step-3
   test adds two cases:
   - (i) a deploy **before** acceptance: must be a retryable transient;
   - (ii) a deploy **after** acceptance, mid-signing.
   If (ii) fails because the host was recreated, that becomes its own fix. The code-only
   deploy path above (recreate `mcp` only) likely avoids it.
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
| 0b | Ops: `deploy-box.sh` defaults to the code-only `mcp` recreate; `--full-restart` flag for the full unit | ops | a deploy leaves `caddy`, `host` and `/acm4/*` up (container start times unchanged); full restart only with the flag |
| 0 | **Spike, half a day:** staging build with a Standalone `handshake_next` and `readiness_prepare`; one natural prompt to Muse | Standalone | Does Muse keep its key, loop unprompted and tolerate 12s holds? Which egress IPs? |
| 1 | `handshake-core`: B1 schema and long-poll helper, B3 local recovery, B2 store and handle broker | shared | unit tests; recovery vectors match the RPC path |
| 2 | Standalone adopts B1–B3: `handshake_next`, `readiness_prepare`, cursor, lowercase canonical, playbook | Standalone | a unit test per action; e2e with two agents and no human input |
| 3 | v2 adopts additively: durable `ccra_` handles, B3, `features: ["next-v1"]`; code-only deploy path | v2 | travel's conformance suite unchanged and green (run attached); restart-mid-pairing cases (i) and (ii); `/handshake/mcp` byte-identical |
| 4 | B5 statement signing plus `agent_handshake_sign_statement` (**runs right after step 1, in parallel with step 2**; travel's N8 is blocked on it) | v2 (travel P-GAP) | a `contract_bind` proof verifies against the party's certified session key; non-allowlisted schema refused; works after the certificate is issued |
| 5 | B4 addresses and mailbox | Standalone | abuse tests: squat, wrong fingerprint, replayed nonce, spam, enumeration, expiry |
| 6 | Autonomous Claude Code listener, then a live Muse run on video | Standalone | anchors present; transcript shows no human input after message 1 |

Rough size: step 0 is half a day; steps 1–2 about 3 days; step 3 about 1.5 days; step 4
about 1 day; step 5 about 1.5 days; step 6 half a day. Each step is its own PR. Order: 0b and 0 first (independent), then 1 → (2 ∥ 4) → 3 → 5 → 6.
Every v2-touching PR is reviewed by the travel session, carries travel's staging
conformance run, and is deployed under the notice/freeze rule.
