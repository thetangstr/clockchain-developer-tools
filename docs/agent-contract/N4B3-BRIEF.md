# Brief N4b-3: P-hardening of `/contract/mcp` (second travel Devin)

**From:** orchestrator, 2026-09-28. N4b-2 was **ACCEPTED** local-only at `4001953`. These items block level **P**
(GOAL-GRAPH N4b rows, LLD §3/§9 R8/R13, rev 6.4+). Same worktree and branch, same scope (`agent-contract/**`,
`test/agent-contract-*`, the `/contract/mcp` block in `http.ts`). Test-first (seen red).

1. **M1: receipts before bind.**
   - Keep a per-principal **pre-bind receipt chain** (signed, hash-chained, with `serverNonce`) covering rendezvous,
     `contract_status` and refused binds.
   - At `contract_bind`, the run chain's genesis records a `preBindHead` link to that principal's pre-bind chain head
     (one for each side).
   - The observer feed serves both chains.
   - Tests: every rendezvous call has a receipt with a nonce; the run genesis links both pre-bind heads; tampering
     with a pre-bind receipt breaks verification.
2. **M2: session and client identity.**
   - Switch `/contract/mcp` to a **stateful** Streamable-HTTP transport (the SDK's session support), so each receipt
     carries `mcpSessionId` and `clientInfo {name, version}` from `initialize`.
   - These are evidence only (R9), never proof.
   - Tests: receipts carry both; a request without a valid session is refused per the MCP spec; session TTL.
3. **M3: publish the server key.**
   - The server card (`/.well-known/mcp/server-card.json`) and a key endpoint publish the receipt and envelope
     signing public key(s) with `keyId` and `alg`, plus key rotation metadata (`validFrom`, `validUntil`).
   - The ephemeral dev key is marked `ephemeral: true` and must never appear at P.
   - Tests: the published key verifies live receipts; an ephemeral key is flagged.
4. **Salted `argsDigest` for cap-bearing calls.**
   - For `mandate_*` and any call whose arguments contain an amount, the receipt `argsDigest` is
     `HMAC-SHA256(runSalt, canonicalJson(args))`.
   - `runSalt` is a per-run secret, disclosed **only** through a separate verifier-scoped endpoint (the observer
     token can't read it).
   - Other calls keep the plain `canonicalDigest`.
   - **Tell the orchestrator** the exact receipt fields, so R8's fallback correlation can use the salt.
   - Test: the probe's cap brute force against the observer feed fails without the salt.
5. **LOWs from the closing review:**
   - inbox messages carry the sender's `agentId` (from the token pin), so the provider's signer can check that the
     handshake names that buyer;
   - a bind consumes only the listing its rendezvous delivery came from, not all of the provider's listings;
   - prune `used-mandates.json` of expired mandates (keep them for at least the mandate's `expiresAt` + grace).

The P-GAP (a signed session-key bind statement) needs the handshake helper, so it's **out of scope here**. Keep
`bindAssurance: "agentId-pinned-token"`.

**Hard limits:** no deploy, no `deploy-box.sh`, no push, no real keys, no network. Commit per item. Report commits,
raw `npm test` / `tsc -b` tails and the item → test map. Then idle.
