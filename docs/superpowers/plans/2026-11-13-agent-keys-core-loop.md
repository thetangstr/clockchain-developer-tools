# Agent keys, core loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent that runs code makes its own Ed25519 key, gets a Starter token in one call by proving it holds the key, and signs its own Shadow checkpoints. Each key is filed on the Clockchain ledger before its first record, listed in a public lookup, and checked automatically by the viewer. Clockchain holds no customer or agent private key.

**Architecture:** The OAuth endpoint gains a `client_credentials` grant authenticated by an RFC 7523 signed client assertion (EdDSA). The resulting token carries the key's fingerprint, and Shadow owns records by the agent's root key (`ak:<fingerprint>`). Checkpoints for agent owners become two-phase: the server builds the body, and the agent signs its hash through a new tool. A new `agent-keys` module is the "public book": a local store, ledger filing, and a public JSON lookup with replace and revoke. Every other owner moves from per-owner server keys to Clockchain's single published witness key.

**Tech Stack:** TypeScript (Node 24, `node:crypto` Ed25519), `node:test` over `dist/`, npm workspaces. The work is in `packages/mcp-server`.

**Spec:** `project-shadow/project-shadow-lld.md` §17 ("Agent keys") and §18 ("Hosted mode"), plus `project-shadow/project-shadow-prd-v4.3.md` FR-24 and AT-7. Both live in `/Users/Kailor/Projects/ac/clockchain/project-shadow/`.

**Base:** branch `feat/agent-keys`, cut from `origin/feat/staging-labels-search` at `c9ae606`. That branch is what staging runs, and it is 47 commits ahead of `main`. Rebase onto `main` once staging-labels-search merges.

**Scope:** this is build-order steps 1 and 2 of LLD §17 (the core loop and its abuse limits). The rest gets its own plans:
- Claiming (step 3).
- Chat sign-in with existing accounts, and labels on anonymous records (step 4).
- Anonymous Shadow writes. They wait on the founder's open decision, "may chat apps keep Shadow records without signing in?". Until then Shadow keeps refusing non-account and non-agent-key owners with `account_required`.
- DPoP-bound tokens. See Review Focus #1 for why bearer tokens are acceptable for now.

## Global Constraints

**Rollout**
- FR-23: the change is additive and off by default, and goes to staging first.
  - `MCP_AGENT_KEYS=1` turns on the grant, `ak:` owners and the `/agent-keys/*` routes.
  - `SHADOW_WITNESS_KEY_FILE` turns on the witness key.
  - With both unset, every existing test passes unchanged.
- The frozen routes `/handshake/mcp`, `/next/handshake/mcp` and `/acm4/*` are not touched.
- No production deploy without the founder's go. The production rule applies: notify the travel orchestrator, no N6/N8 windows.

**Keys and secrets**
- Clockchain never receives, stores or logs an agent private key.
- No key, token or client assertion appears in a tool result, an MCP log line or an error message (AT-7e).
- Key format: canonical Ed25519 SPKI PEM, as `ed25519PublicKeyDer` in `shadow/lib/keys.ts` accepts it.
- Fingerprint: `fingerprint(pem)` from `shadow/lib/keys.ts`, 64 hex characters.
- `shadow/lib/*` is vendored. Do not edit it; every task works around it.

**Tokens and the grant**
- Assertion lifetime is at most 300 s (`exp - iat <= 300`), with ±60 s clock skew allowed. Each `jti` is single-use until its `exp`.
- Starter token TTL is 3600 s. No refresh token is issued for this grant; the agent signs a new assertion instead.
- Agent ids shown to people are the first 16 hex characters of the root fingerprint.

**Limits**
- New-key mints per network address: `MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR`, default 10. Keys already in the book don't count.
- One Starter anchor budget shared by every `ak:` owner, kept apart from accounts: `SHADOW_STARTER_ANCHORS_PER_DAY`, default 2000.
- The per-key anchor and session limits are the existing per-owner `ShadowLimits`, applied to the agent's root key.
- Starter tokens cannot call `KEEPER_TOOLS` (unattended timers or alarms that spend credits).

**Ledger**
- Ledger reference ids: `agent-key:v1:<fingerprint>` for every key event.
- Labels: `agent key filed`, `agent key replaced`, `agent key revoked`.
- Labels are plain words only, because the gateway strips punctuation.

**Copy and code conventions**
- Viewer copy is plain words.
- Never claim independence: the server checking its own book says "checked against Clockchain's public key list". Never "verified" or "independently".
- Never say "one validator"; say "our own single-operator gateway".
- Follow `AGENTS.md`: surgical commits with `git add <paths>`, and `npm test -w @clockchain/mcp-server` green before every commit.

## Review Focus

1. **A stolen Starter token.** It can append steps, but it cannot produce a valid checkpoint. The viewer must show steps after the last agent-signed checkpoint as "not signed by the agent" and never as proven. Test owner: Task 7.
2. **An assertion replayed within its lifetime, or presented to another audience** (staging versus production issuer). It must be refused with `invalid_client` and must not mint. Test owner: Task 3.
3. **A key minted but never used, then used for the first time after the per-IP window resets.** It must be filed on chain before the session's start marker anchors, so the filing's block is never later than the record's. Test owner: Task 8.
4. **A revoked key.** Tokens minted before revocation are refused on the next call. Checkpoints signed before the revocation still read "made by this agent". Checkpoints whose anchor is later than the revocation read "key was cancelled before this record". Test owners: Tasks 5 and 10.
5. **A server restart between the checkpoint request and `shadow_sign_checkpoint`.** The pending body must survive on disk, and a signature over a stale hash must be refused with a message saying which hash is current. Test owner: Task 7.

---

### Task 1: Stop trusting a faked network address

**Files:**
- Modify: `packages/mcp-server/src/http.ts:119-128` (`clientIp`), plus callers at `:1226`, `:1578`, `:1771` and `:1975`
- Test: `packages/mcp-server/test/http.test.mjs:126-132`

**Interfaces:**
- Produces: `clientIp(headers: IncomingHttpHeaders, remoteAddr: string | undefined, trustedProxy?: string): string`. It honours `X-Forwarded-For` only when `remoteAddr === trustedProxy`, by delegating to `standaloneClientIp` in `standalone-handshake/public-server.ts:130`.

- [ ] **Step 1: Replace the XFF-first assertions with failing tests**
  - `clientIp ignores X-Forwarded-For from an untrusted peer`: headers `{ "x-forwarded-for": "6.6.6.6" }`, remote `"10.0.0.5"`, no proxy → `"10.0.0.5"`.
  - `clientIp uses X-Forwarded-For from the trusted proxy`: same headers, remote `"172.30.0.3"`, proxy `"172.30.0.3"` → `"6.6.6.6"`.
  - `POST /token mint ceiling cannot be dodged by rotating X-Forwarded-For`: boot with `MCP_TOKEN_MINT_PER_HOUR=2` and no trusted proxy. Make three mints with three different XFF values from one socket. The third returns 429.
- [ ] **Step 2:** Run `npm test -w @clockchain/mcp-server -- --test-name-pattern clientIp`. Expect it to FAIL.
- [ ] **Step 3:** Implement the new `clientIp` signature. Pass `oauthTrustedProxy` (already read at `http.ts:1169` from `MCP_OAUTH_TRUSTED_PROXY`) at all four call sites. Production compose already sets it to `172.30.0.3` (`infra/clockchain-mcp/docker-compose.yml:127`).
- [ ] **Step 4:** Run `npm test -w @clockchain/mcp-server`. Expect PASS.
- [ ] **Step 5:** Commit `http.ts` and `test/http.test.mjs`: "Trust X-Forwarded-For only from the configured proxy".

### Task 2: The agent key book (local store)

**Files:**
- Create: `packages/mcp-server/src/agent-keys/book.ts`
- Test: `packages/mcp-server/test/agent-keys-book.test.mjs`

**Interfaces:**
- Produces:
  ```ts
  export type KeyStatus = "active" | "replaced" | "revoked";
  export type KeyFiling = { state: "unfiled" | "pending" | "filed"; ledgerId?: string; block?: number; filedAt?: string };
  export type KeyEntry = { fingerprint: string; publicKeyPem: string; root: string; status: KeyStatus;
    firstSeenAt: string; filing: KeyFiling; replacedBy?: string; revokedAt?: string;
    events: { action: "filed" | "replaced" | "revoked"; at: string; ledgerId?: string; block?: number }[] };
  export class AgentKeyBook {
    constructor(opts: { dir: string; now: () => Date });
    get(fingerprint: string): KeyEntry | null;
    /** Adds a first-seen key as its own root, or returns the existing entry. `created` says which. */
    admit(publicKeyPem: string): { entry: KeyEntry; created: boolean };
    rootOf(fingerprint: string): string | null;            // follows `root`
    setFiling(fingerprint: string, filing: KeyFiling): void;
    replace(oldFp: string, newPem: string): KeyEntry;     // new entry gets root = old.root; old.status = "replaced"
    revoke(fingerprint: string): KeyEntry;
  }
  ```
- Storage: `<dir>/<fp>.json`, directory 0700, files 0600, written atomically (temp file plus rename, as `shadow/store.ts` does). `dir` is `<MCP_STATE_DIR>/agent-keys`.

- [ ] **Step 1: Write the failing tests**
  - `admit returns created:true once, then the same entry`.
  - `admit rejects a non-canonical PEM`: throws `AgentKeyError("invalid_key")`.
  - `replace keeps the root and marks the old key replaced`.
  - `revoke is final`: a second revoke throws `AgentKeyError("already_revoked")`, and replacing a revoked key throws.
  - `a fresh book over the same dir reads the same entries`.
  - `files are 0600`.
- [ ] **Step 2:** Run them. Expect FAIL (module missing).
- [ ] **Step 3:** Implement `book.ts`. Validate PEMs with `ed25519PublicKeyDer` and compute fingerprints with `fingerprint`, both from `../shadow/lib/keys.js`. Export `class AgentKeyError extends Error { code: string }`.
- [ ] **Step 4:** Run them. Expect PASS.
- [ ] **Step 5:** Commit: "Add the agent key book".

### Task 3: Prove key possession with a signed client assertion

**Files:**
- Create: `packages/mcp-server/src/agent-keys/proof.ts`
- Test: `packages/mcp-server/test/agent-keys-proof.test.mjs`
- Create: `packages/mcp-server/test/helpers/agent-key.mjs` (test-side agent: makes a key, signs assertions, signs hashes)

**Interfaces:**
- Produces:
  ```ts
  /** One interface, so the proof format can be swapped (LLD §17 caveat). */
  export interface KeyProof { verify(input: { assertion: string; audience: string; nowSec: number }): { publicKeyPem: string; jti: string; exp: number } }
  export function jwtBearerProof(): KeyProof;   // RFC 7523 client assertion, alg EdDSA
  ```
- Assertion format:
  - Header: `{ alg: "EdDSA", typ: "JWT", jwk: { kty: "OKP", crv: "Ed25519", x } }`.
  - Claims: `iss` and `sub` both equal the RFC 7638 JWK thumbprint of `jwk`. `aud` equals the token endpoint URL. Also `iat`, `exp` and `jti` (8 to 128 characters).
  - The PEM is derived from `jwk.x`.
- Errors: `AgentKeyError("invalid_client", <plain reason>)`. The reason never echoes the assertion.
- Helper produces: `makeAgentKey(): { publicKeyPem, fingerprint, jwk, assertion(aud, {iat?, exp?, jti?}), signHash(hex): string }`. `signHash` returns base64 in the 86-character `==` form that `verifySignature` expects.

- [ ] **Step 1: Write the failing tests**
  - These verify: a valid assertion; the derived `publicKeyPem` has `fingerprint` equal to the helper's.
  - These throw `invalid_client`:
    - wrong `aud`
    - `exp - iat = 301`
    - `iat` 61 s in the future
    - expired assertion
    - `alg: "none"`
    - `alg: "HS256"`
    - an `iss` that is not the thumbprint
    - a tampered payload
    - a header without `jwk`
  - An error message must not contain any 20-character slice of the assertion.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement with `node:crypto`: `createPublicKey({ key: jwk, format: "jwk" })`, then `verify(null, …)`. Replay is not handled here; Task 4 owns it.
- [ ] **Step 4:** Run them. Expect PASS.
- [ ] **Step 5:** Commit: "Verify an agent's signed client assertion".

### Task 4: The `client_credentials` grant mints a Starter token

**Files:**
- Modify: `packages/mcp-server/src/token.ts:20` (`TokenPayload`) and add `mintAgentToken` beside `mintToken` (`:76`)
- Modify: `packages/mcp-server/src/oauth.ts`: metadata `:860-870`, `token()` `:1309`, grant dispatch `:1371-1441`, limiters `:714-723`, config `:122-150`
- Test: `packages/mcp-server/test/oauth-agent-keys.test.mjs`. Copy the setup from `test/oauth.test.mjs:1-35`.

**Interfaces:**
- Consumes: `AgentKeyBook.admit` and `get` (Task 2), and `jwtBearerProof` (Task 3).
- Produces:
  - `TokenPayload.akf?: string`, the fingerprint of the key that proved possession (64 hex).
  - `mintAgentToken(secret: string, ttlSeconds: number, nowSec: number, jti: string, akf: string): { token: string; payload: TokenPayload }`. It throws if `akf` is not 64 hex characters. `verifyToken` accepts it unchanged.
  - The endpoint is `POST /oauth/token` with these fields:
    - `grant_type=client_credentials`
    - `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
    - `client_assertion=<jwt>`
  - Success: `200 { access_token, token_type: "Bearer", expires_in: 3600, agent_id: <16 hex>, key_filed: false | true }`.
  - Failures:
    - `401 invalid_client` for a bad proof, a replayed `jti`, or a key that is replaced or revoked.
    - `429` with `Retry-After` when the new-key limit is hit.
  - `OAuthConfig.agentKeys: { enabled: boolean; newPerIpPerHour: number; tokenTtl: 3600 }`.
- With `MCP_AGENT_KEYS` unset, the grant answers `unsupported_grant_type` exactly as today, and the metadata is unchanged.

- [ ] **Step 1: Write the failing tests**
  - `one call from a fresh key returns a Starter token with akf`.
  - `metadata advertises client_credentials and private_key_jwt only when enabled`.
  - `a replayed assertion is refused`: same `jti` twice → second call `invalid_client`.
  - `the 11th new key from one address in an hour gets 429, but a known key still mints`.
  - `a revoked key cannot mint`.
  - `no refresh_token is returned`.
  - `the response and server log never contain the assertion`: capture `console.*` during the call and search for the assertion text.
  - `disabled by default`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement:
  - Replay protection is `durableExpiringSet(<state>/oauth, "used-assertions", 100_000, nowSec)`, keyed `sha256(fp + ":" + jti)`.
  - The new-key limiter uses `limiter(newPerIpPerHour, 3_600_000, now)`, keyed by `ipOf(req)`, and is called only when `admit(...).created` would be true. Check with `get` first.
  - Read `MCP_AGENT_KEYS` and `MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR` in `loadOAuthConfig`.
- [ ] **Step 4:** Run `npm test -w @clockchain/mcp-server`. Expect PASS.
- [ ] **Step 5:** Commit: "Let an agent get a Starter token with its own key".

### Task 5: Agent tokens are recognised everywhere, with Starter limits

**Files:**
- Modify: `packages/mcp-server/src/shadow/mcp.ts:219` (`shadowOwnerFromClaims`)
- Modify: `packages/mcp-server/src/http.ts:1113` (`checkAuth`), `:1202-1224` (`shadowAccountRequired` and `shadowAuthenticate`)
- Modify: `packages/mcp-server/src/entitlement.ts:180` and `:272` (`buildKeeperGate`)
- Test: add to `test/shadow-http.test.mjs` and `test/entitlement.test.mjs`

**Interfaces:**
- Consumes: `TokenPayload.akf` (Task 4) and `AgentKeyBook.get` and `rootOf` (Task 2).
- Produces:
  - `shadowOwnerFromClaims({ jti, acct, akf }, raw)` returns `ak:<root fingerprint>` when `akf` is present. `acct` keeps precedence.
  - `shadowAuthenticate` accepts owners matching `ACCT_PATTERN` or `/^ak:[0-9a-f]{64}$/`.
  - `checkAuth` refuses a token whose `akf` key is revoked (401 `invalid_token`, "this agent key was cancelled").
  - `Entitlement.reason` gains `"agent_key"` with `plan: "starter"`. The keeper gate refuses `KEEPER_TOOLS` for it with a plain message.

- [ ] **Step 1: Write the failing tests**
  - `an agent token opens /shadow/mcp and owns by ak:<root>`.
  - `after replace, a token from the new key owns the same sessions`.
  - `a token minted before revoke is refused after it`.
  - `a starter token cannot call timer_set or alarm_set on /mcp`.
  - `account tokens are unchanged`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement. Pass the shared `AgentKeyBook` instance from `http.ts` into the OAuth handler, `checkAuth` and the Shadow handler. Construct it once, next to `oauthConfig`.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "Recognise agent-key tokens, with Starter limits".

### Task 6: Retire per-owner server keys; add the single witness key

**Files:**
- Modify: `packages/mcp-server/src/shadow/recorder.ts:22-29` (`HOSTED_LIMITS`) and `:202` (`checkpointOver`)
- Modify: `packages/mcp-server/src/shadow/store.ts:119`, `:149-154`, `:213-240` (`operator`) and `:425` (`deleteOwner`)
- Modify: `packages/mcp-server/src/http.ts:1265` (pass the witness key into `ShadowService`)
- Test: `test/shadow-witness.test.mjs`. Copy `setup()` from `test/shadow-hosted.test.mjs:1-40`.

**Interfaces:**
- Produces:
  - `type SigningMode = "agent" | "witness" | "legacy"`.
  - `checkpointBody(meta: SessionMeta, events: ShadowEvent[], now: Date, mode: SigningMode): { body: CheckpointBody; hash: string } | { unchanged: Checkpoint }`. `checkpointOver(meta, events, keys, now, mode)` becomes `checkpointBody` plus `keys.sign`.
  - `limitsFor(mode)`: the `HOSTED_LIMITS` text whose last line depends on the mode:
    - agent: "Signed by the agent's own key. Clockchain received the steps and holds no key for this agent."
    - witness: "Witnessed: Clockchain received each step from the signed-in account and signed with its single published service key. The agent did not sign."
    - legacy: today's line, unchanged.
  - `ShadowStore.operator(ownerKey, now)` changes by mode:
    - With a witness key configured, it returns `{ operatorId, keys: witnessKeys }`. The `operatorId` comes from the new `owners/<k>/operator.json`, or from an existing `key.json` (whose private key is no longer read). No new `key.json` is ever written.
    - With no witness key, behaviour is unchanged (legacy).
  - Agent owners (`ak:`) get `operatorId = "agent-" + root.slice(0, 32)`, stable across sessions, and no keys. Task 7 handles their signing.
  - `ServiceOptions.witness?: KeyProvider`, loaded in `http.ts` from `SHADOW_WITNESS_KEY_FILE` via `fileKeyProvider` (`shadow/lib/keys.ts`).
  - `GET /.well-known/clockchain-witness-key.json` returns `{ publicKey, fingerprint }`.

- [ ] **Step 1: Write the failing tests**
  - `with a witness key, account checkpoints are signed by it and no key.json is created`.
  - `an existing key.json keeps its operatorId but its key is not used for new checkpoints`.
  - `verifyPacket passes and the pin fingerprint is the witness fingerprint`.
  - `knownLimits says witnessed`.
  - `without a witness key, behaviour is byte-identical`: the existing `shadow-hosted` suite passes untouched.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "Sign hosted checkpoints with one published witness key, not keys held per account".

### Task 7: Agents sign their own checkpoints

**Files:**
- Modify: `packages/mcp-server/src/shadow/service.ts`:
  - `checkpoint` `:1770`, `close` `:1798`, `sealClose` `:1048` and `queueFinal` `:1059`
  - `latest` `:1190` and `logSteps` `:1710`
- Modify: `packages/mcp-server/src/shadow/store.ts:81` (`SessionMeta`)
- Modify: `packages/mcp-server/src/shadow/mcp.ts:435-450` (register the new tool)
- Test: `test/shadow-agent-sign.test.mjs`

**Interfaces:**
- Consumes: `checkpointBody` (Task 6), `AgentKeyBook.get` (Task 2), and `verifySignature` (`shadow/lib/keys.ts`).
- Produces:
  - `SessionMeta.awaitingSignature?: { hash: string; body: CheckpointBody; final: boolean }`, persisted with the rest of the metadata.
  - For `ak:` owners:
    - `shadow_checkpoint` and `shadow_close_session` return `{ ..., sign: { hash, note: "Sign this hash with your key and call shadow_sign_checkpoint." } }` and queue nothing.
    - `close` writes `session.closed` first, as today, then waits for the signature.
  - New tool `shadow_sign_checkpoint({ session_id, hash, signature })`:
    - It verifies the signature against the token's `akf` key.
    - On success it sets `meta.checkpoint = { body, hash, publicKey: <agent PEM>, signature }`, then calls `queueCheckpoint` and `drain` as `checkpoint()` does today.
    - It refuses `hash_mismatch` (naming the current hash), `bad_signature` and `not_agent_owner`.
  - `latest()` for `ak:` owners returns the last agent-signed checkpoint and never signs.
  - `logSteps` for `ak:` owners appends and makes no checkpoint.

- [ ] **Step 1: Write the failing tests** (the test agent comes from `test/helpers/agent-key.mjs`)
  - `checkpoint returns a hash to sign; signing it anchors`.
  - `a signature by another key is refused`.
  - `a stale hash is refused with the current hash named`.
  - `pending body survives a new ShadowService over the same dir`.
  - `steps after the last signed checkpoint are not proven`: build the packet and assert that `verifyPacket` covers only `body.count` events, and that the viewer text contains "not signed by the agent".
  - `close then sign gives a closed, proven session`.
  - `account owners are unaffected`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement. Keep the existing `heavy.run` gate around reading events and writing metadata.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "Agents sign their own Shadow checkpoints".

### Task 8: File each key on the chain before its first record; one Starter budget

**Files:**
- Create: `packages/mcp-server/src/agent-keys/filing.ts`
- Modify: `packages/mcp-server/src/shadow/service.ts:2169` (`anchorNetwork`) and `:2192-2304` (`drain`)
- Test: `test/agent-keys-filing.test.mjs`, using `FakeLedger` from `test/helpers/shadow-fake-ledger.mjs`

**Interfaces:**
- Consumes: `anchorHash` (`shadow/ledger.ts:298`) and `AgentKeyBook.setFiling` (Task 2).
- Produces:
  - `fileKey(book, ledger, fp, event: "filed" | "replaced" | "revoked", extra?: { newFp?: string }): Promise<KeyFiling>`.
  - The hash is `fp` for "filed", and `hash("agent-key-event:v1", { fp, event, newFp, at })` (the `hash` from `shadow/lib/profile.ts`) otherwise. The reference is `agent-key:v1:<fp>` and the label comes from Global Constraints.
  - `drain` for an `ak:` owner calls `fileKey(..., "filed")` before the session's first row whenever the root's filing is not `filed`. If filing is pending or fails, the session's rows wait (status `pending`, reason "Filing this agent's key on Clockchain first.").
  - A Starter budget, `starterAnchors.check()` and `record()`, counts every anchor by an `ak:` owner, key filings included. Over the budget gives `anchor_status: "over_limit"` with reason "Today's free allowance for new agents is used up." Accounts never draw on it.

- [ ] **Step 1: Write the failing tests**
  - `first anchor of a new agent files its key first`: assert the FakeLedger write order is key, then start marker, and the key's block ≤ the start marker's block.
  - `a filed key is not filed again`.
  - `a failed filing holds the session rows and retries on the next checkpoint`.
  - `the Starter budget stops agent anchors but not account anchors`.
  - `filing counts toward the owner's daily anchors`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement. Read `SHADOW_STARTER_ANCHORS_PER_DAY` in the Shadow config next to the other limits.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "File each agent key on Clockchain before its first record".

### Task 9: The public lookup, and replacing or cancelling a key

**Files:**
- Create: `packages/mcp-server/src/agent-keys/routes.ts`
- Modify: `packages/mcp-server/src/http.ts` (dispatch `/agent-keys/*` before the OAuth handler at `:1755`, only when enabled)
- Test: `test/agent-keys-routes.test.mjs`

**Interfaces:**
- Consumes: `AgentKeyBook` (Task 2), `fileKey` (Task 8) and `jwtBearerProof` (Task 3, `aud` = the action URL).
- Produces:
  - `GET /agent-keys/<fp>.json` returns `200 { fingerprint, agentId, publicKey, status, root, firstSeenAt, filing, replacedBy?, revokedAt?, events[] }`.
    - Unknown key: `404`.
    - It needs no sign-in, is cacheable for 60 s, and is limited per `ipOf` by `SHADOW_ANON_PER_MINUTE`.
  - `POST /agent-keys/<fp>/replace`, body `{ assertion, new_public_key }`. The assertion is signed by the old key and the body names the new key. It returns the new entry and files a `replaced` event.
  - `POST /agent-keys/<fp>/revoke`, body `{ assertion }`, signed by the key itself. It files a `revoked` event.
  - The `jti` replay set is shared with Task 4.

- [ ] **Step 1: Write the failing tests**
  - `lookup shows a filed key with its ledger id and block`.
  - `lookup of an unknown key is 404`.
  - `replace needs the old key's signature`.
  - `revoke shows status revoked with revokedAt`.
  - `lookup never includes private material`: no `PRIVATE KEY` string, and no `d` member in any JWK.
  - `routes 404 when MCP_AGENT_KEYS is off`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "Publish agent keys, and let an agent replace or cancel its key".

### Task 10: The viewer and `shadow_verify` check the key automatically

**Files:**
- Create: `packages/mcp-server/src/agent-keys/check.ts`
- Modify: `packages/mcp-server/src/shadow/service.ts`: `verify` `:1917` (beside `verifyPacket` at `:1949`), and `buildLink` `:2110` (beside `:2136`, plus a post-processor next to `withAnchoringCaveat` at `:819-858`)
- Test: `test/agent-keys-check.test.mjs`

**Interfaces:**
- Consumes: the `AgentKeyBook` entry for `fingerprint(cp.publicKey)`, and the session's `AnchorInfo[]` (block of the checkpoint's anchor).
- Produces:
  - `checkAgentKey(entry: KeyEntry | null, cp: Checkpoint, cpBlock: number | null): { verdict, text }`, with these verdicts and texts:

    | verdict | text |
    |---|---|
    | `made_by_agent` | "Made by agent <agentId>, unchanged since <date>. Key filed <date>." |
    | `key_not_filed` | "Signed by agent <agentId>. Its key isn't filed on Clockchain yet." |
    | `key_filed_after` | "Signed by agent <agentId>, but its key was filed after this record." |
    | `key_revoked_before` | "Signed by agent <agentId>, but that key was cancelled before this record." |
    | `not_from_agent` | "Not from agent <agentId>: the signature doesn't match its key." |
    | `witnessed` | "Witnessed by Clockchain for a signed-in account." |
    | `legacy` | today's text |

  - Every text ends with " Checked against Clockchain's public key list." except `legacy`.
  - `shadow_verify` gains `agent_key: { verdict, text, lookup: "/agent-keys/<fp>.json" }`.
  - The viewer shows the text as the first line under the title. The page stays static, so the CSP is unchanged.

- [ ] **Step 1: Write the failing tests:** one per verdict, built from book entries and checkpoints made by the test helper, plus `the viewer HTML contains the verdict text and no script tag`.
- [ ] **Step 2:** Run them. Expect FAIL.
- [ ] **Step 3:** Implement. Include the book entry's filing state in the link cache key (`linkKey`), so a filing that lands later refreshes the page.
- [ ] **Step 4:** Run the whole package. Expect PASS.
- [ ] **Step 5:** Commit: "Check an agent's key automatically in the viewer and in shadow_verify".

### Task 11: Tell agents how, and prove AT-7(a), (d) and (e) end to end

**Files:**
- Modify: `packages/mcp-server/src/shadow/discovery.ts` (`connectInstructions`) and the `/llms.txt` text served at `http.ts:1512`, only when enabled
- Test: `test/agent-keys-e2e.test.mjs`. Boot as `test/shadow-http.test.mjs` does, with `MCP_AGENT_KEYS=1`, `SHADOW_ENABLED=1`, `SHADOW_WITNESS_KEY_FILE=<tmp>` and a FakeLedger.

**Interfaces:**
- Consumes: everything above.
- Produces: instructions of eight lines or fewer telling an agent that runs code to do four things:
  1. Make an Ed25519 key and keep the private half.
  2. Post one signed assertion to `/oauth/token`.
  3. Use the token on `/shadow/mcp`.
  4. Sign the hash `shadow_checkpoint` returns.

  They name the lookup URL, and say that Clockchain never sees the private key.

- [ ] **Step 1: Write the failing end-to-end test**
  1. A fresh helper key makes one token call.
  2. It runs `shadow_start_session`, three `shadow_record` steps and `shadow_checkpoint`, then `shadow_sign_checkpoint`, then close and sign.
  3. Assert the following:
     - The packet verifies and the viewer reads `made_by_agent`.
     - A second token from the same key sees the session in `shadow_list_sessions` (AT-7a).
     - The state directory holds no file containing "PRIVATE KEY" except the witness key file the test wrote (AT-7d).
     - No tool result or captured log line contains the token, the assertion, or a `cc_` prefix followed by 20 or more characters (AT-7e).
- [ ] **Step 2:** Run it. Expect FAIL until the instructions exist; everything else should already pass.
- [ ] **Step 3:** Write the instructions.
- [ ] **Step 4:** Run `npm run build && npm test` at the repo root. Expect PASS.
- [ ] **Step 5:** Commit: "Agent quick instructions, and an end-to-end test of key onboarding".

---

## After the plan (not tasks here)

1. A whole-branch review on the strongest model, with a security focus on Tasks 3, 4, 5 and 9.
2. Staging deploy with `MCP_AGENT_KEYS=1` and a staging witness key, only after the founder's go. Then:
   - Claude Code (headless) re-runs the 11 November onboarding test against it.
   - AT-7(a) is rechecked live.
3. Update the tracker's exit conditions with evidence (tests and staging run), and update LLD §17's "Not built".
4. Production waits on: the security review (LLD §17 step 6), the founder's go, and the production deploy rule.
