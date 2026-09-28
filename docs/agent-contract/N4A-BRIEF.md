# Brief N4a: `/contract/mcp` foundation, module only (second travel Devin)

**From:** orchestrator, 2026-09-28. **Authority:** the founder's 2026-09-28 decision, the published-MCP agent pairing goal.
This follows your own host mapping. **Design of record:** `/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/docs/travel-mvp/design/AGENT-PAIRING-HARNESS-LLD.md`
rev 5, sections §3 (surface), §9 (receipts, R8/R13) and §13 (signing). Goal: `docs/travel-mvp/GOAL-GRAPH.md` in that repo, node N4 (N4a).

## Where
- **Worktree:** `/Volumes/mac_studio_ssd/Projects/handshake/.worktrees/contract-mcp-n4a`
- **Branch:** `feat/contract-mcp-n4a`, off `main` c30b9d9
- `node_modules` is symlinked, so don't run `npm install`. Don't touch the main checkout.
- **Your paths only:**
  - `packages/mcp-server/src/agent-contract/**`
  - `packages/mcp-server/test/agent-contract-*.test.mjs`
  - `packages/mcp-server/test/fixtures/agent-contract-*`
  - this `docs/agent-contract/` folder

## Build (module only; NOT wired into `http.ts`, so nothing on the box can change even if this merges)
1. **`schemas.ts`:** zod 3 input and output schemas for **every tool in LLD §3**, with role scoping (buyer,
   provider, both). Outputs carry `simulated: true` where sim-backed. Refusals use generic codes; `MANDATE_REFUSED`
   never includes the cap value.
2. **`tools-list.ts`:** the role-scoped `tools/list` (names, descriptions, input schemas) and the server
   instructions text.
   - Descriptions explain what each operation is for, and what each workflow stage requires, **in prose**. They
     never give a numbered order of calls (LLD R10: guidance is uniform and published, and gives no scripted order).
   - Export `guidanceDigests(role)`, which returns `{toolsListDigest, instructionsDigest}`.
3. **`server-card.ts`:** the JSON for `/.well-known/mcp/server-card.json`, listing surfaces, endpoints and the guidance digests.
   - Pin the handshake endpoint as ONE constant, `https://mcp.clockchain.network/next/handshake/mcp`.
   - The business endpoint is `/contract/mcp`; staging is `/staging/contract/mcp`.
4. **`canonical.ts`:** a port of `canonicalJson` / `canonicalDigest` (`0x` + sha256 hex of sorted-key canonical JSON).
   It must reproduce **every** vector in `test/fixtures/agent-contract-canonical-digest-vectors.json` byte-for-byte.
   Those vectors were generated from the travel repo's T0; the two repos use different zod majors, so parity is by
   vectors, not by shared code.
5. **`receipts.ts`:** the receipt-chain primitives from LLD §3 and §9.
   - `newServerNonce()`, 128-bit random.
   - `makeReceipt(prev, fields, signer)`, producing a receipt with `prevHash`, `serverNonce`, `responseDigest`,
     `mcpSessionId?`, `clientInfo?`, and `serverSignature {alg: "ed25519", keyId, sig}`, using `node:crypto`.
   - `verifyChain(receipts, publicKeys)`, which fails on a gap, a reorder, tampering or a bad signature.
   - `chainHead(receipts)`.
   - There is NO `transport` field.
6. **`envelope.ts`:** the server-signed prepare envelope `{bytes, runId, tool, expiresAt, nonce, serverSig}`, with
   `signEnvelope` / `verifyEnvelope`. This is what the local signer verifies before signing (LLD §13).

## Tests (`node --test` via the package's `npm test`)
Cover all of the following:
- schema reject cases per tool
- wrong-role tools are absent from `tools/list`
- descriptions contain no ordered-steps pattern: no "first … then", no numbered call list, and no tool name
  referenced inside another tool's description
- guidance digests are stable
- canonical vector parity
- the chain verifies; a single-byte tamper, a dropped or reordered receipt, or a wrong key fails it
- envelope expiry and a bad signature are refused
- `MANDATE_REFUSED` doesn't leak the cap

## Hard limits
- No deploys, no `deploy-box.sh`, no SSM, no ssh, no pushes, no network calls.
- No credentials created or activated, and no `http.ts` / Caddy / compose edits.
- No sim port and no signing split: those are N4b.
- Commit on the branch as each piece goes green.

## Report back with
1. Commits, each as a hash and one line.
2. Raw tails of `npm test` for `packages/mcp-server` (or the narrowest equivalent that includes your tests), plus `tsc -b`.
3. Any LLD §3 tool you think is wrong or missing, and anything in this brief you disagree with.

Then STOP and idle. The orchestrator reviews it independently.
