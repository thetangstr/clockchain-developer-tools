# Clockchain MCP — Launch Plan (marketplaces + ChatGPT)

*2026-06-27 · testnet stage. Goal: get the MCP "out there" — MCP marketplaces + a ChatGPT app.*

Both tracks run on the **same hardened hosted MCP** (`mcp.clockchain.network/mcp`). Harden once, ship to both.

## Sequencing (decided)
- **Registries now** (dev audience, low volume) — `server.json` is ready.
- **ChatGPT app + broad push: gated** on AGE-193 (truthful confirmation) + per-user OAuth + AGE-194 fix.
- DRIs: **Lane D** = distribution (ChatGPT + listings) · **Lane B** = the gates · **Lane A** = `server.json`/SDK.

---

## Track 1 — MCP marketplaces

**`server.json`** (repo root) is ready: namespace `network.clockchain/clockchain`, hosted remote → `/mcp`, `x-api-key` auth hint.

Publish (official registry, propagates downstream):
1. Build/get `mcp-publisher` (from `modelcontextprotocol/registry`).
2. **Verify the `network.clockchain` namespace** via a **DNS TXT** on `clockchain.network` (the DNS login prints the exact record). *(human — you own the domain)*
3. `mcp-publisher validate` → `mcp-publisher publish`. *(human — outward release)*

Then submit to: **Smithery · mcp.so · Glama · PulseMCP** + PR the awesome-mcp-servers lists.

---

## Track 2 — ChatGPT app (OpenAI Apps SDK = MCP)

The Apps SDK *is* MCP (server + tools + optional iframe UI), so we reuse the server.

- **Reuse:** the hosted MCP. Expose a **curated subset** (e.g. `get_timestamp`, `log_action`, `attest_action`, `verify_cross_party`, `verify_receipt`) — reviewers test every advertised tool.
- **Add:** tool hints (`readOnly`/`destructive`/`openWorld`), app manifest (OpenAI dashboard), CSP, and an optional **React "verify-a-receipt" widget** (MCP resource + `openai/outputTemplate`).
- **Auth — OAuth 2.1 only.** Published apps allow anonymous/read-only or **OAuth 2.1**; **user-supplied API keys are NOT allowed**. So: a thin OAuth 2.1 layer (MCP-conformant: discovery, DCR/CIMD, PKCE S256, `resource`→`aud`) mapping each ChatGPT user → a **per-user Clockchain key**, via a managed IdP (Stytch / WorkOS / Auth0). **Do not** auto-mint via `/token` in the auth path (AGE-194).
- **First milestone (doable now, no OAuth/submission):** a **private dev-mode connector** (Settings → Apps & Connectors → Developer mode) with a per-tester `x-api-key` header + the read-only verify widget.
- **Submission reqs:** verified builder/business profile; public HTTPS `/mcp` live at review; CSP; demo creds with **no MFA**; privacy-policy + company URLs, logo, screenshots, test prompts; **no "court-grade" claims** (single-validator).
- **First 3 steps:** (1) build the Apps-SDK wrapper (curated subset + hints + widget), smoke-test read-only via MCP Inspector; (2) stand up the private dev-mode test; (3) spec OAuth 2.1 + key-mapping.

---

## Launch gates (Lane B spec — verify line numbers against current code)

### AGE-193 — never report success on an un-anchored fire
**Cause:** writes return `blockHeight: null` (pending) through an unconditional `ok()` success envelope; no `pending`/`anchored` status, no pool-health check, no backfill. In degraded windows (`totalNodes:1`, `nodeParticipation%:0`) a block may never be written, yet the tool already reported success.
**Code:** `packages/core/src/client.ts` (`log`, `waitForConfirmation` — silently returns pending on timeout, `attestAction`, identity writes, `getTimestamp` has the pool fields); `packages/core/src/receipt.ts` (`buildReceipt` computes `confirmed` but no top-level `status`); `packages/core/src/tsa.ts` (all 5 TSA verbs); `packages/mcp-server/src/tools.ts` (`ok()`, `log_action`, `attest_action`, TSA/identity handlers); `packages/core/src/types.ts`.
**Changes:** add `AnchorStatus = anchored|pending|degraded` + `poolHealth` to types; `PoolDegradedError`/`NotAnchoredError`; `getPoolHealth()` + `backfillPending()` in client; stamp `status` everywhere (no silent greenlight on timeout); `buildReceipt` adds top-level `status`; `okWrite()` helper emits explicit PENDING note when not anchored; **pool-health guard refuses writes at 0% participation** unless `allow_degraded` set.

### AGE-194 — per-user auth / token model
**Cause:** `POST /token` mints identical shared-delegated-key tokens, rate-limited **per IP** with **no `Retry-After`**; a public app behind one egress IP trips it. All demo tokens share one gateway key/budget; payload has no per-user identity.
**Code:** `packages/mcp-server/src/http.ts` (`/token` mint per-IP 429 with no headers; `createRateLimiter` returns bare boolean; `callerKey` already keys per-token for tool calls); `packages/mcp-server/src/token.ts` (`TokenPayload` has no `sub`/`jti`); `packages/mcp-server/src/tools.ts` (`getSharedLogBudget` = one shared budget); `packages/core/src/errors.ts` (`RateLimitError` carries no retry-after).
**Changes:** `createRateLimiter.allow()` returns `{allowed,limit,remaining,resetAt}`; set `Retry-After`/`X-RateLimit-*` on 429 **and** success; add `jti`+`sub` to tokens; rate-limit per token/`sub` (not IP) — keep only a coarse per-IP abuse ceiling; make **BYO key** (`x-clockchain-api-key`) the recommended per-user production path now; medium-term map `/token` `sub` → a distinct delegated sub-key/credit bucket; thread upstream `Retry-After` into `RateLimitError`.

**Cross-cutting:** both touch the same write handlers in `tools.ts` — do AGE-193 first so AGE-194's per-user budget reuses that refactor.

---

## Human-only prerequisites
1. **DNS TXT on `clockchain.network`** → verify the `network.clockchain` namespace (registry publish).
2. **`mcp-publisher` auth + the publish trigger** (outward release).
3. **OpenAI builder/business verification** + a privacy/safety policy page (ChatGPT submission).
