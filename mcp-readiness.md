# MCP Readiness Assessment - Clockchain APIs for Products A & B

A hands-on review of every Clockchain API we've tested, scored for how ready it
is to become an MCP tool serving **Product A (Agent Identity)** and
**Product B (Agent-SDK: logging, proofs, time)**.

Everything below is grounded in live calls against `node.clockchain.network`
(read probes 2026-06-02; write path and DID-convention tests 2026-06-03 on a
funded account). Where something is marked blocked or partial, it was tested,
not assumed.

---

## Verdict in one screen

| Capability area | MCP tools | Status |
|---|---|---|
| Time oracle (read) | `get_time`, `get_timestamp`, `get_block`, `get_validation` | **Ready** |
| Logging core loop | `log_action`, `get_log_entry`, `verify_asset` | **Ready** |
| Evidence / proof | `generate_proof` | **Partial** - 2 of 5 layers are real |
| Action history / search | `search_actions` | **Partial** - exact-match only, no listing |
| Agent identity (anchor) | `mint_agent_identity`, `verify_agent_identity`, `revoke_agent_identity` | **Partial** - works only as a hash anchor, same-client, known-ref |
| Agent identity (real DID) | `get_agent_identity`, `identity list`, cross-agent verify | **Blocked** - needs backend |
| Time-triggered contracts | `schedule_trigger`, `get_trigger_status` | **Blocked** - `/schedule` is 404 |
| Agent-payable funding | (cross-cutting) | **Blocked** - logs are bought via wallet, not API |

**Bottom line:** Product B's core loop - get authoritative time, log an action,
retrieve it, verify it - is real and verified today. Product A works as a
hash-anchoring convention but not yet as a self-describing, listable,
cross-agent identity system. Two backend gaps (agent-payable funding and a
public lookup/resolver) decide whether either product is genuinely
agent-ready at scale.

---

## The five constraints that shape everything

These were discovered by testing and they constrain almost every tool below.
Read these first; the per-tool ratings follow from them.

1. **`searchAsset` is exact-match only.** Querying the exact `assetReferenceId`
   returns the record. Querying a prefix (`did:mint`, `did`) returns `[]`. There
   is no list, no browse, no wildcard. **You can only retrieve records whose exact
   reference you already hold.** (Tested: exact ref returned the entry; both
   prefixes returned empty.)

2. **`additionalInfo` is sanitized to alphanumeric + spaces.** Sent
   `special:chars-test {"k":"v"} a-b_c @x.com 12.5`; stored
   `special chars test   k   v   a b c  x com 12 5`. Every `:`, `-`, `{`, `}`,
   `"`, `,`, `_`, `@`, `.` became a space. **You cannot store JSON, a DID
   document, a URL, an email, or any structured metadata on-chain in this field.**

3. **`assetReferenceId` preserves `:` and `-`** (a full DID survives as a
   reference) but is capped at 128 chars and is the lookup key, not a metadata
   store.

4. **`searchAsset` is scoped to the caller's `clientId`.** You cannot see another
   client's records. Cross-agent / cross-org verification is impossible through
   this endpoint.

5. **`/schedule` is not on the public gateway** (404 on GET, POST, `/api/schedule`).
   Time-triggered smart contracts cannot be driven from the API today.

Two more, already documented elsewhere but relevant here: writes confirm on-chain
in ~0.6s (good for a `--wait` tool); rate limiting is aggressive (~100s cooldown
after a couple of calls), which constrains any high-frequency agent logging on
the current tier.

---

## What "store metadata on-chain" actually has to become

Because of constraints 2 and 3, the only durable on-chain fields are:

- `assetReferenceId` - a clean key (`:` and `-` allowed), 128 chars
- `assetHash` - the SHA-256 of whatever you're notarizing (hex, survives intact)

So the correct pattern - and it is the same one OpenTimestamps and C2PA use - is:
**keep the real document (identity doc, action metadata) client-side or in your
own store, hash it, and anchor only the hash.** Verification = recompute the hash
of the client-held doc and compare to `assetHash` on-chain. This works today. What
does **not** work is expecting the chain to hand back a rich, self-describing
record - the metadata field destroys structure.

This is the single most important design correction from this assessment.

---

## Per-tool readiness

### Product B - Agent-SDK (the stronger story)

| MCP tool | Endpoint(s) | Status | Notes |
|---|---|---|---|
| `get_time` | `GET /api/time/time` | **Ready** | Verified live |
| `get_timestamp` | `GET /api/time/timestamp` | **Ready** | Verified; single-node so consensus fields are 0 |
| `get_block` | `GET /api/time/block` | **Ready** | Verified incl. genesis and the block our log landed in |
| `get_validation` | `GET /getValidationBlock/{h}` | **Ready** | Verified; all vote/trust fields 0 on testnet |
| `log_action` | `POST /log` | **Ready** | Verified end-to-end: wrote, anchored at block 2824376, read back. Caveat: metadata is hash-only (constraint 2) |
| `get_log_entry` | `GET /ledger/{id}` | **Ready** | Verified; returns full record incl. `blockHeight` once written |
| `verify_asset` | `/ledger` + `/api/time/block` | **Ready** | Hash compare + block time. The strongest proof primitive we have |
| `search_actions` | `GET /searchAsset` | **Partial** | Works only for an exact reference you already hold. Cannot list or browse an agent's history (constraint 1). Client must maintain its own index of refs/ledgerIds |
| `generate_proof` | `/ledger` + `/block` + `/getValidationBlock` | **Partial** | Layers 4-5 (consensus + ledger) are real; layers 1-3 (VRF election, raw time-source readings) have no endpoint and are descriptive only. On a single node the consensus numbers are 0 |
| `schedule_trigger` | `GET /schedule` | **Blocked** | 404 on the gateway (constraint 5) |
| `get_trigger_status` | (TBD) | **Blocked** | Depends on `/schedule` being exposed |

**Product B read:** the loop that matters - authoritative time in, action hashed
and anchored, retrievable and verifiable out - is **ready and proven**. The
limits are real but bounded: history is fetch-by-known-ref (not browse), proofs
are honest-2-layer (not 5), and triggers are unavailable.

### Product A - Agent Identity (the weaker story)

Product A is implemented as a convention on top of `/log` + `/searchAsset`: a mint
is a log record with `assetReferenceId = did:mint:{did}`, a revoke is
`did:revoke:{did}`. The DID-convention test confirms what works and what doesn't.

| MCP tool | Mechanism | Status | Notes |
|---|---|---|---|
| `mint_agent_identity` | `POST /log` with `did:mint:{did}` ref | **Partial** | The write works and anchors on-chain (verified, block 2824376). But the identity *document* (name, capabilities, owner) cannot live on-chain - `additionalInfo` strips it (constraint 2). You anchor a hash of the doc; the doc stays client-side |
| `verify_agent_identity` | `searchAsset` exact `did:mint:{did}` | **Partial** | Works only if you know the exact DID and it belongs to your own client. Returns the hash, not the capabilities/owner (those were sanitized). You verify by re-hashing the client-held doc |
| `revoke_agent_identity` | `POST /log` with `did:revoke:{did}` ref | **Partial** | Writes a revocation record; checkable by exact lookup within your client |
| `get_agent_identity` | `searchAsset` exact ref | **Blocked (as specced)** | Returns a hash + reference, not a usable identity document. "Full DID details" is not achievable on-chain |
| `identity list` / enumerate | `searchAsset` by prefix | **Blocked** | No prefix or list search exists (constraint 1). A client cannot enumerate its own DIDs through the API |
| cross-agent verify | `searchAsset` other client | **Blocked** | `searchAsset` is clientId-scoped (constraint 4). Agent B cannot verify Agent A's identity - which is the entire point of an agent-to-agent handshake |

**Product A read:** buildable as "anchor a DID's hash, keep the document
client-side, verify a known DID within your own account." Not buildable as a real,
self-describing, listable, cross-agent DID system. The gap between those two is
where the product promise lives, and it needs backend work (below).

---

## Cross-cutting blockers, in priority order

These are the things the D4 team would need to change. Ranked by how much they
gate the products.

1. **Agent-payable funding (gates Product B at scale).** Logging spends a "logs"
   credit balance that today can only be topped up via the dashboard - card, or a
   wallet + gas token swap. An AI agent cannot do either. Until logs can be funded
   by an API-key / prepaid account credit (set up once by the human operator),
   no autonomous agent can sustain logging. See `product-findings.md` and the
   x402 discussion in `industry-landscape.md`.

2. **A public lookup / resolver (gates Product A entirely).** Two missing
   capabilities collapse into one ask: (a) prefix/list search so a client can
   enumerate its records, and (b) an unscoped `GET /did/{id}` (or
   `GET /ledger/{id}` that is not client-scoped) so one party can verify another's
   identity. Without these, "agent identity" is a private per-client log, not a
   verifiable identity.

3. **A real metadata field (or stop sanitizing `additionalInfo`).** To return
   self-describing records, there needs to be a field that preserves structure
   (JSON, or at least `:`, `-`, `.`). Otherwise every product is hash-anchor-only
   and all human-readable metadata lives off-chain.

4. **Expose `/schedule` on the gateway (gates triggers).** Until then the
   time-conditional-contract story is undeliverable through the API.

5. **A real validator set on testnet (gates the proof story).** With one node,
   every consensus/trust/participation number is 0, so `generate_proof` and any
   "court-grade" claim are hollow. Multi-validator testnet makes the proofs real.

6. **A usable rate tier (gates high-frequency agents).** ~100s cooldowns make
   continuous agent logging impractical. A real per-key rate or burst allowance is
   needed for any agent that logs more than occasionally.

---

## Recommended MCP build order

**Ship now (verified, no caveats):**
`get_time`, `get_timestamp`, `get_block`, `get_validation`, `log_action`,
`get_log_entry`, `verify_asset`. This is a complete, honest Product B core - an
agent can read authoritative time and notarize its actions with verifiable proof.

**Ship with explicit caveats (works, but bounded):**
- `generate_proof` - label it a consensus+ledger proof, not 5-layer, and render
  the real (currently zero) testnet numbers.
- `search_actions` - frame it as "fetch an action by its exact reference," and
  have the MCP server maintain a local index of the refs/ledgerIds it created so
  an agent can still find its own history.
- `mint_agent_identity` / `verify_agent_identity` / `revoke_agent_identity` -
  ship as a hash-anchor convention: store the DID doc client-side, anchor its
  hash, verify a known DID within the same client. Do not present it as a W3C-grade
  DID system.

**Do not ship until backend lands:**
`identity list`, cross-agent `verify_agent_identity`, `get_agent_identity` as a
rich record, `schedule_trigger` / `get_trigger_status`, and any "agent funds its
own logging" flow.

---

## What this means for the two products

- **Product B is real now, at small scale.** The MCP server can ship a genuine,
  verified notarization-and-time toolset. Its ceiling is set by funding (agents
  can't pay) and history (no browse), not by whether the core works - it does.

- **Product A is a demo, not a product, until the resolver lands.** You can mint
  and verify a DID you own and know. You cannot list them, return their details,
  or let another agent verify them. That last one is the definition of the
  feature, so Product A's headline capability is currently blocked on a backend
  endpoint, not on our tooling.

Tooling is not the bottleneck for either product. The verified core is buildable
today; the gaps are all backend product decisions (funding, resolver, metadata,
triggers, validators).
