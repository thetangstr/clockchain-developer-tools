# N4b-1 changes 1 (orchestrator, 2026-09-28 ~11:35): the adversarial review REJECTED fb06861 + 638f0ad

Tests pass 585/585 and they reproduce. But the review's probe
(`/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/.omc/state/audit-2026-09-28/n4b1-probe.mjs`, read-only;
the orchestrator reproduced every finding) shows the following:
- auth bypass with no tokens configured;
- run squatting;
- no link between the principal and the certificate's parties;
- a malleable certificate digest;
- no expiry check;
- a bind that commits without a receipt.

**N4b-1 is not accepted.** Fix each item **test-first (seen red)**. The tests must go through the real
`tokenAuthenticator` and the `http.ts` wiring, not a test-only authenticator.

## Must-fix
1. **C1, prototype-key bypass.** Parse tokens into a `Map` (or a null-prototype object). Compare `sha256(token)`
   with `timingSafeEqual`. Validate the principal's shape (role ∈ {buyer, provider}, non-empty keyId).
   Tests: with no tokens configured, `Bearer constructor|__proto__|toString|hasOwnProperty` each get 401 on
   `initialize`, `tools/list` and `tools/call`. Also reject duplicate token entries and tokens containing `:`
   (parse error at startup).
2. **C2, tie the principal to a certificate party.** This decision is the orchestrator's (LLD §3, rev 6.2).
   - Each token is provisioned as `token:role:keyId:agentId:side`, where `agentId` is the party's ERC-8004 agent id
     (as it appears in the certificate's parties) and `side` is `initiator` or `responder`.
   - `contract_bind` succeeds only when the certificate's party on that `side` has exactly that `agentId`. The run
     records `{buyer: side/agentId, provider: side/agentId}`, and the two roles must sit on different sides.
   - **Replay:** a bind by a second principal for a seat that's already taken → `SEAT_TAKEN`. A retried bind by the
     same principal is idempotent **only** with identical `{certDigest, signerKey}`.
   - **Gap to state (don't fake it):** proof that the caller *possesses* the party's handshake session key isn't
     implemented. It needs the handshake helper to sign a bind statement. Add a `// P-GAP` comment, and add a
     `bindAssurance: "agentId-pinned-token"` field to the bind result and receipt.
   - Tests: a certificate from a session the principal isn't a party to is refused; the wrong side is refused;
     both roles on one side are refused; a different principal replaying the payload gets `SEAT_TAKEN`.
3. **C3, malleable digest and run creation order.**
   - Take the run identity as `sessionId` + `canonicalDigest(result)` (signed content only), not a digest of the
     envelope bytes.
   - Pin `signer.keyId` to the verified session key. Require canonical base64 or hex (reject non-canonical encodings).
   - **Create the run only after every check passes.** A refused bind must not create or alter any state.
   - Tests: the probe's malleated envelope maps to the same identity, or is refused, and genuine parties can still
     bind afterwards. A refused bind leaves no run.
4. **H1, freshness.** Require `now ≤ session validUntil + grace` (grace ≤ 10 min, configurable). Keep a durable
   record of used session IDs per run in the state directory, so a restart can't start a second genesis.
   Tests: an expired certificate is refused; a bind after a restart is refused or idempotent (it never starts a new chain).
5. **H2, receipt before commit.**
   - Sign the receipt **before** committing the state change. If the receipt fails, roll back and return an error,
     with no silent commit.
   - `sourceIp` is the socket address, or the **last** XFF hop appended by our own proxy, and only when
     `CONTRACT_TRUST_PROXY=1`. Truncate or validate it to fit the schema.
   - Tests: an 80-character XFF can't leave a bound run with 0 receipts; client XFF isn't trusted by default.
6. **H3, explicit enable.** `/contract/mcp` answers **404** unless `CONTRACT_MCP_ENABLED=1`. When it's enabled but
   `CONTRACT_SERVER_ED25519_SEED` is missing and `CONTRACT_ALLOW_EPHEMERAL_KEY` isn't `1`, refuse to start the
   route. The ephemeral key's keyId is **forced** to `ephemeral-dev-*` (not overridable). Tests cover each case.

## Also fix here, since they're cheap
- **M4:** cap receipts per run and runs per process (reject when full), and apply the TTL from §3.
- **M5:** principals can rebind in a new run once their previous run has ended.
- **LOW:** constant-time token lookup (covered by 1), and receipt `ts` from the injected `now`.

## Deferred to N4b-2, but they block P (note them in your report)
- **M1:** a per-principal pre-bind receipt chain, linked into the run chain at bind.
- **M2:** `mcpSessionId` / `clientInfo` in receipts.
- **M3:** publishing the server public key.

Same scope and hard limits (no deploy, push, real keys or network). Commit as "N4b-1 review fixes". Report commits,
raw tails of `npm test` and `tsc -b`, and each item with its test name. Then idle.
