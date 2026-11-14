# Agent keys, production hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the items the founder deferred to "before production" (rulings 39, 40, 42; ledger D1–D7 minus D6), so agent keys can be switched on in production.
1. **D4.** A key cancelled while a signature is waiting for the session lock can no longer sign.
2. **D3.** The spent-assertion set (and the new DPoP proof set) refuses new entries when full, instead of dropping unexpired ones.
3. **D1.** An agent's access token is bound to the agent's own key (DPoP, RFC 9449). A stolen token alone is useless.
4. **D2.** The key book caches each key's durable file, so it stops doing disk reads per request and stops losing the corrupt-file guard; stale temp and quarantine copies are removed at boot.
5. **D5.** Keys that were never used are removed after a safe age, and nothing that a record, a filing or another key depends on is ever removed.
6. **D7.** A damaged old `key.json` with no valid backup no longer stays on disk, or locks its owner out.

D6 (idempotent retry) is done (`32830fa`) and is not in this plan.

**Base:** branch `feat/agent-keys` at the head after the change now uncommitted in the worktree (`src/shadow/service.ts`, `test/agent-keys-filing.test.mjs`, the held-session pass) is committed. Don't start Task 1 on a dirty tree. Work in `packages/mcp-server`.

**Spec:** this plan, plus `project-shadow/project-shadow-lld.md` §17 for everything it doesn't change. Decision logs: `project-shadow/docs/build-ledgers/2026-11-13-agent-keys-core-loop-ledger.md` and `2026-11-13-agent-keys-rulings.md` ("Deferred to before production"). RFC 9449 (DPoP) §4.2–4.3, §5, §7.

**Out of scope** (listed at the end under "Other production blockers", not planned here): deploy wiring of the settings, provisioning the witness key, switching anything on.

## Assumptions

- **A1.** No agent key or agent token exists in any environment. `MCP_AGENT_KEYS` has never been set on staging (checked 13 Nov, ruling 38) or production. So the token format and the sign-in request can change with no migration and no compatibility path.
- **A2.** One server process per state volume. This is already binding (ledger, Task 4 deploy note). The book cache (Task 7) and the replay sets rely on it: nothing else writes `<MCP_STATE_DIR>/agent-keys` or `<MCP_STATE_DIR>/oauth` while the server runs.
- **A3.** Agents keep their clocks within 60 s of real time, the window the client assertion already allows.
- **A4.** We don't use DPoP nonces (RFC 9449 §8). The `iat` window plus single-use `jti` is the replay control, which §11.1 allows.

## FOUNDER CALLS

Each one has a recommendation. The plan is written to the recommendation, and the "if you choose otherwise" line says what changes.

- **FC1 (D1). Is DPoP always required for agent tokens, or behind a setting?** **Recommend: always required, no setting.** By A1 there's nothing to stay compatible with, and a switch like `MCP_AGENT_KEYS_DPOP=off` is a downgrade path that a typo in SSM could open in production. *If you choose a setting:* Task 5 adds `MCP_AGENT_KEYS_DPOP=required|off` (default `required`, anything else turns agent keys off, as `MCP_AGENT_KEYS` does), about 15 lines plus one test.
- **FC2 (D4). Should only the signature be re-checked under the lock, or every agent write?** **Recommend: only the signature.** It's the only write that carries the key's authority. A step that a cancelled key's in-flight request appends is shown as "not signed by the agent", the same as any step after the last signed checkpoint (Review Focus #1 of the core-loop plan). *If you choose every write:* each Shadow write method takes the token's key and re-checks it inside the lock. That touches about 8 methods in `service.ts` and gets its own task.
- **FC3 (D3). Should the chat-app replay sets (used codes, used refresh tokens, revoked families) also refuse when full?** **Recommend: not in this plan.** You asked for chat-app tokens to stay unchanged, and refusing there would turn a flood into failed sign-ins for people. It's listed as a follow-up. *If you choose yes:* add `"refuse"` to those three `make(...)` calls in Task 2, and handle a full set in `mark(...)` (refusing closed, which the code already does for a write failure).
- **FC4 (D5). What age makes an unused key safe to remove?** **Recommend: 30 days after it was first seen.** That's 720 times the one-hour token, and the same as Shadow's record retention. An agent that comes back later with the same key signs in again as a new key.
- **FC5 (D7). What should happen to a damaged old `key.json` with no valid backup, when the witness key is on?** **Recommend: delete it and every copy, give the owner a fresh operator id, and log it loudly.**
  - In witness mode the private key is never used again: ruling 15 deletes it anyway, and a rollback makes a new key (ruling 16).
  - Its operator id can't be read, so keeping the file preserves nothing.
  - Today the owner is locked out of Shadow, and every attempt leaves one more quarantined copy of the private key bytes.
  - Records the owner made earlier still verify: their packets carry their own key, and their pins do too.
  - *Cost:* the owner's new sessions show a new operator id. A file that's "damaged" only because its permissions drifted (the durable reader refuses a group- or world-readable file) loses an id that could have been read.
  - *If you choose quarantine instead:* move the copies to `<SHADOW_STATE_DIR>/quarantine/<ownerKey>/` and leave the owner refused. That keeps a private key on disk, against ruling 15.

## Decisions made in this plan (no founder input needed; each says what it costs if wrong)

- **D1-a. The DPoP key is the agent key.** The proof's `jwk` thumbprint must equal the client assertion's key thumbprint at the token endpoint, and the token's `cnf.jkt` at the resource.
  - *Why:* the agent already holds exactly one key, in the same process, and a second key would protect against nothing.
  - *Also:* the token stays tied to the key the book can cancel.
  - *Cost if wrong:* an agent that wants a separate proof key can't have one. Lifting that later means dropping one equality check.
- **D1-b. Proof `jti`s go in a durable set (`<MCP_STATE_DIR>/oauth/used-dpop`), reusing `durableExpiringSet`, cap 200,000, refusing when full.** Each entry lasts until `iat + 61` s.
  - *Why:* this needs no new mechanism, and a restart can't let a captured request be replayed.
  - *Cost:* one fsync'd journal line per agent request, the same order of cost as the Shadow step append that most of those requests already make.
  - *Cost if wrong (too slow):* swap in `memoryExpiringSet` and refuse proofs with `iat` earlier than process start. That's one line plus a test.
- **D1-c. A token with `cnf` is accepted only with a valid DPoP proof, and an agent token (`akf`) is accepted only with `cnf` and a proof.** Account (chat) tokens never have `cnf`, so they behave as they do today.
- **D1-d. `htu` is checked against `MCP_PUBLIC_URL` plus the request path**, the same base the assertion audiences use, not the `Host` header. Query and fragment are ignored, as RFC 9449 §4.3 says.
- **D1-e. The working client example is a file in the repo (`packages/mcp-server/examples/agent-key-client.mjs`).** The end-to-end test imports it as it is, so it can't drift from the server. The RUNBOOK points to it. `/llms.txt` keeps its eight lines and states the proof's fields in them.
  - *Cost if wrong:* if agents need the example from the server itself, add one static route.
- **D2-a. The book cache holds at most 10,000 entries**, dropping the oldest. A dropped entry is re-read from disk on the next use, so the corrupt-file guard is never lost while a file object is in use.

## Global Constraints

- The frozen routes `/handshake/mcp`, `/next/handshake/mcp` and `/acm4/*` aren't touched.
- `shadow/lib/*` is vendored: don't edit it.
- With `MCP_AGENT_KEYS` and `SHADOW_WITNESS_KEY_FILE` unset, every existing test passes unchanged, apart from the fixture updates that a task names.
- Chat-app (OAuth account) tokens, sign-in, refresh and their replay sets behave byte for byte as before.
- No key, token, assertion, DPoP proof, raw IP address or address hash appears in any tool result, public route, ledger payload, log line or error message.
- No new dependencies. `@modelcontextprotocol/sdk` 1.30.0 is already a dependency, and the example uses only it and `node:crypto`.
- Per-task test command: `cd packages/mcp-server && npx tsc -b && node --test test/<file>.test.mjs`.
- Before each commit, run the full suite with `cd packages/mcp-server && npx tsc -b && node --test --test-concurrency=4`. Unbounded parallel runs hit port-race flakes that have nothing to do with this code.
- Write tests first: show the failing run, then write the code.
- Commit after each task on `feat/agent-keys` with `git add <paths>`. Never push, merge or deploy.

## Review Focus

1. **A captured agent request, replayed** (the token plus its DPoP proof, on the same or another URL or method, before or after a restart) is refused. Owner: Tasks 3 and 5.
2. **A stolen agent token without the key** can't be used with any proof it can make. Owner: Task 5.
3. **A key cancelled while its signature waits for the lock** signs nothing. Owner: Task 1.
4. **A flood that fills a replay set** gets a clear refusal, and never re-admits a spent assertion or proof. Owner: Task 2.
5. **Cleanup never removes a key with records, a filing, a pending filing or a replacement**, and never removes a book file that's in use. Owner: Task 8.
6. **Chat tokens are unchanged.** Owner: Task 5 (regression tests).

---

### Task 1 (D4): Re-check the signing key inside the session lock

**Why:** `signCheckpoint` (`src/shadow/service.ts`, around line 2160) reads the key entry with `this.agentKeys.get(agentKey)` before `await this.session(...)`. The lock is a queue, so the replace and revoke routes can cancel the key in between. That's `book.revoke`, which is synchronous and answers "revoked" at once. The waiting call then verifies the signature with the old entry and accepts it. Ledger, Task 7 minor: "revoke TOCTOU — book.get before session lock".

**Where else a key's status gates a write:**
- The token grant (`oauth.ts agentGrant`) and the replace/revoke routes (`agent-keys/routes.ts`) read and change the book in one synchronous stretch, so they have no gap.
- `fileFirst` and `fileAgentKeyEvent` file history, and a cancelled key's history is still filed by design (ruling, Task 9).
- So `signCheckpoint` is the only fix. Per FC2, unsigned steps are not re-gated.

**Files:**
- Modify: `src/shadow/service.ts` (`signCheckpoint` only)
- Test: `test/shadow-agent-sign.test.mjs`

**Design:**
- Move the entry read, its `SHADOW_UNAVAILABLE` handling and the `!entry || entry.status !== "active" || entry.root !== root` refusal to the top of the `this.session(ownerKey, sessionId, (meta) => { ... })` callback, before the D6 retry branch and before `verifySignature`. The callback is synchronous from there to `writeMeta`, so nothing can change the book in between.
- Delete the read before the lock. One read only, so there are no two sources of truth.
- `const key = entry.publicKeyPem` moves in with it. `made` is unchanged.

**Steps:**
- [ ] **Step 1: Failing tests.** In `shadow-agent-sign.test.mjs`, using `setup()` and `agentIn(book)` with the service's own `book`:
  - `a key revoked while its signature waits for the session lock signs nothing`:
    1. Start a session, record a step and call `checkpoint`, which leaves `awaitingSignature` set.
    2. Hold the session's lock with `let release; const held = svc.locks.run(\`${ownerKeyOf(owner)}/${sessionId}\`, () => new Promise((r) => { release = r; }));`.
    3. Start `const p = svc.signCheckpoint(owner, fp, { session_id, hash, signature })` without awaiting it.
    4. Call `book.revoke(fp)`, then `release()` and `await held`.
    5. Expect `p` to reject with the same code the existing "not this agent's key" refusal uses (`NOT_AGENT_OWNER`'s code). Expect `metaOf(...).awaitingSignature.hash === hash`, `meta.checkpoint` unchanged, and `fake.writes.length` unchanged.
  - The same test for `book.replace(fp, other.publicKeyPem)`, which must also refuse (ruling T5: replaced counts as cancelled).
  - `a resend of the same signature after the key is cancelled is still refused` already exists (Task 4 of the follow-ups). Keep it green.
- [ ] **Step 2:** Run `node --test test/shadow-agent-sign.test.mjs`. Expect the two new tests to FAIL (the signature is accepted).
- [ ] **Step 3:** Implement the design.
- [ ] **Step 4:** Run the file again (PASS), then the full suite.
- [ ] **Step 5:** Commit `src/shadow/service.ts test/shadow-agent-sign.test.mjs`: "Check the agent's key inside the session lock before taking its signature".

### Task 2 (D3): Agent replay sets refuse when full

**Why:** `memoryExpiringSet` (`src/oauth-replay.ts`) evicts the oldest entry once it holds `cap`. Under a flood of 100,000 fresh assertions inside one assertion lifetime (300 s), a captured, still-valid assertion falls out and can be replayed (ledger, Task 4 minor). The founder ruled that we refuse instead.

**Files:**
- Modify: `src/oauth-replay.ts`, `src/oauth.ts` (the `make(...)` call for `used-assertions`, and `agentGrant`), `src/agent-keys/routes.ts` (the spend loop around line 282)
- Test: `test/oauth-replay.test.mjs` (create it: no unit test of the sets exists today; they're covered through `oauth.test.mjs`), `test/oauth-agent-keys.test.mjs`, `test/agent-keys-routes.test.mjs`

**Interfaces:**
```ts
/** Thrown by add() on a set made with whenFull "refuse" that holds `cap` unexpired entries. Nothing was written. */
export class ReplayStateFullError extends Error { name = "ReplayStateFullError" }
export function memoryExpiringSet(cap: number, nowSec: () => number, whenFull?: "evict" | "refuse"): ExpiringSet & { full(): boolean };
export function durableExpiringSet(dir: string, name: string, cap: number, nowSec: () => number, whenFull?: "evict" | "refuse"): ExpiringSet;
```
`whenFull` defaults to `"evict"`, which is today's behaviour, for the chat sets (FC3).

**Design:**
- `memoryExpiringSet`:
  - `full()` sweeps the expired entries when they're due, then returns `entries.size >= cap`.
  - In `"refuse"` mode, `add` calls `full()` and throws `ReplayStateFullError` instead of running the eviction loop.
- `durableExpiringSet`:
  - In `"refuse"` mode, `add` checks `memory.full()` before `appendDurableLine`, so a refused entry is never journalled.
  - `remember` keeps its `live` trimming only in `"evict"` mode.
  - At boot, loading can't exceed `cap` unless the code constant was lowered. If it does, `memory.add` throws, the set fails to open, and the endpoint refuses closed (503), as for a corrupt snapshot. Note that in the module comment.
  - `ReplayStateFullError` is deliberately **not** a `DurableStateError`, so `add`'s compact-and-retry branch never catches it.
- `oauth.ts`:
  - Use `make("used-assertions", agentKeys.spentAssertionsCap ?? 100_000, "refuse")`, where `make` passes `whenFull` through. `OAuthOptions.agentKeys` gains `spentAssertionsCap?: number`, for tests only, and it isn't read from the environment.
  - In `agentGrant`, the `usedAssertions.add` catch tells `ReplayStateFullError` apart: log `{ event: "oauth_replay_state_full", set: "used-assertions" }` and answer 503 `temporarily_unavailable`, "Clockchain is taking too many agent sign-ins right now. Try again in a minute.", with `retry-after: 60`. Any other error keeps today's 503 and log.
- `routes.ts`:
  - The same split in the spend-loop catch: log `{ event: "agent_keys_replay_state_full" }`, then 503 with "Clockchain is taking too many key changes right now. Try again in a minute."
  - If a replace's second spend is refused after the first is written, the old key's assertion stays spent and the request fails closed. That's the same as today's write-failure case (ledger, Task 9 minor). Say so in a comment, and don't add code for it.

**Steps:**
- [ ] **Step 1: Failing tests.**
  - `oauth-replay.test.mjs`, with an injectable clock:
    - a `"refuse"` memory set with cap 2 takes 2 unexpired entries, then the third `add` throws `ReplayStateFullError` and `has()` of the first two stays true;
    - once the clock passes the first entry's `exp`, `add` succeeds;
    - an `"evict"` set (the default) still evicts the oldest, exactly as before;
    - a `"refuse"` durable set at cap writes no journal line for the refused key (the journal file's size is unchanged), and a reopened set still has the first entries.
  - `oauth-agent-keys.test.mjs`, with `spentAssertionsCap: 1`:
    - the first grant gets 200;
    - a second key's grant gets 503 with that message, `retry-after: 60`, the log event `oauth_replay_state_full`, and no token;
    - replaying the first assertion is still `invalid_client` "already used";
    - after the clock moves past the first assertion's `exp`, the second key mints.
  - `agent-keys-routes.test.mjs`: build the routes with `usedAssertions: memoryExpiringSet(1, nowSec, "refuse")` already holding one entry. A revoke gets 503, and the book is unchanged.
- [ ] **Step 2:** Run the three files. Expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the three files plus `test/oauth.test.mjs`, which checks that the chat sets are unchanged (PASS). Then run the full suite.
- [ ] **Step 5:** Commit `src/oauth-replay.ts src/oauth.ts src/agent-keys/routes.ts` and the three test files: "Refuse new agent assertions when the spent list is full instead of dropping live ones".

### Task 3 (D1, part 1): A DPoP proof verifier

**Why:** Tasks 4 and 5 both check proofs. This task is one pure function, tested on its own.

**Files:**
- Create: `src/agent-keys/dpop.ts`
- Modify: `src/agent-keys/proof.ts`. Export its existing `decode`, `decodeJson`, `thumbprint` and `frozen` helpers instead of copying them, and add the `nowSec` guard below.
- Modify: `test/helpers/agent-key.mjs`. Add `dpop(htm, htu, { accessToken, iat, jti, header = {}, claims = {} } = {})` to `makeAgentKey()`, built like `assertion()`: header `{ alg: "EdDSA", typ: "dpop+jwt", jwk }`, claims `{ jti, htm, htu, iat, ath? }`, with `ath = base64url(sha256(accessToken))` when `accessToken` is given.
- Test: `test/agent-keys-dpop.test.mjs` (create it)

**Interfaces:**
```ts
/** RFC 9449 §4.3. Throws AgentKeyError("invalid_dpop_proof", <reason that never echoes the proof>). */
export function verifyDpopProof(input: {
  proof: string | string[] | undefined;   // the raw `dpop` request header
  htm: string;                            // the request method
  htu: string;                            // the expected URL: MCP_PUBLIC_URL + path, no query or fragment
  nowSec: number;
  accessToken?: string;                   // set at a resource: then `ath` is required and must match
}): { jkt: string; jti: string; iat: number; replayKey: string; replayExp: number };
/** RFC 7638 thumbprint of an Ed25519 SPKI PEM (what jwtBearerProof's publicKeyPem is). */
export function jwkThumbprintOfPem(pem: string): string;
```
- `replayKey` is `sha256b64url(\`${jkt}:${jti}\`)`, which fits `oauth-replay`'s ID pattern.
- `replayExp` is `iat + 61`.

**Rules** (each refusal is its own test):
1. The header must be present, a single value, a string, and at most 8 KiB. Node joins repeated unknown headers with `", "`, and a JWT can't contain a comma, so a comma or an array means more than one proof, which is refused (RFC §4.3 check 1).
2. Three canonical base64url segments, as `proof.ts` decodes them.
3. `typ` is exactly `dpop+jwt`, `alg` is `EdDSA`, there's no `crit`, and `jwk` is an Ed25519 OKP key with a 32-byte `x` and no `d`.
4. The signature verifies under that `jwk`, and is checked before any claim is trusted.
5. `jti` is a string of 8 to 128 characters. `htm === input.htm`.
6. `htu` with any `?…`/`#…` cut off must equal `input.htu`.
7. `iat` is a whole number with `nowSec - 60 <= iat <= nowSec + 60`.
8. With `accessToken`, `ath` must equal `base64url(sha256(accessToken))`. Without it, `ath` is ignored.
9. `nonce` is ignored (A4).
10. A non-integer `nowSec` throws (the guard below).

**The `nowSec` guard:** `jwtBearerProof().verify` also starts with `if (!Number.isSafeInteger(nowSec)) throw new Error("nowSec must be whole seconds")`. Today a `NaN` makes every time check false, so an expired assertion would pass. That's the ledger's Task 3 security minor; callers pass integers now, so behaviour doesn't change. It's a plain `Error` (a server bug), not `invalid_client`.

**Steps:**
- [ ] **Step 1: Failing tests** in `agent-keys-dpop.test.mjs`:
  - one happy path with and one without `accessToken`, with the returned `jkt` equal to `jwkThumbprint(agent.jwk)` from the helper;
  - one refusal per rule above;
  - `jwkThumbprintOfPem(agent.publicKeyPem) === agent.thumbprint`;
  - a `NaN` `nowSec` throws in both `verifyDpopProof` and `jwtBearerProof().verify`;
  - no refusal message contains the proof or any of its segments.
- [ ] **Step 2:** Run it. Expect FAIL (no module).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it plus `test/agent-keys-proof.test.mjs` (PASS), then the full suite.
- [ ] **Step 5:** Commit `src/agent-keys/dpop.ts src/agent-keys/proof.ts test/helpers/agent-key.mjs test/agent-keys-dpop.test.mjs`: "Add a DPoP proof check for agent keys".

### Task 4 (D1, part 2): The token grant binds the token to the agent key

**Files:**
- Modify: `src/token.ts` (`TokenPayload.cnf`, `mintAgentToken`, `verifyToken`)
- Modify: `src/oauth.ts` (`agentGrant`, the replay sets, the metadata, and `OAuthHandler.usedDpopProofs`)
- Test: `test/oauth-agent-keys.test.mjs`, plus any test that calls `mintAgentToken` directly (grep for it)

**Design:**
- `token.ts`:
  - `TokenPayload` gains `cnf?: { jkt: string }`.
  - `mintAgentToken(secret, ttl, nowSec, jti, akf, jkt)`: `jkt` is required and must match `/^[A-Za-z0-9_-]{43}$/` (otherwise it throws, like `akf`), and is written as `cnf: { jkt }`.
  - `verifyToken` returns `{ valid: false, reason: "bad cnf" }` for a present `cnf` that isn't exactly `{ jkt: <43 base64url> }`.
  - `mintToken` is unchanged, so account tokens never carry `cnf`.
- `oauth.ts`, the replay state: add `usedDpopProofs: make("used-dpop", agentKeys.spentDpopCap ?? 200_000, "refuse")` next to `usedAssertions`, only when `agentKeys` is set. `spentDpopCap` is test-only, like Task 2's `spentAssertionsCap`. Expose it on `OAuthHandler` as `readonly usedDpopProofs: ExpiringSet | undefined`, documented like `usedAssertions`.
- `agentGrant`, in this order, with everything from the replay checks to the response synchronous:
  1. Verify the client assertion, as today.
  2. `verifyDpopProof({ proof: req.headers.dpop, htm: "POST", htu: tokenEndpoint, nowSec: nowSec() })` with no `accessToken`.
     - If it throws `AgentKeyError`, answer 400 `{ error: "invalid_dpop_proof", error_description }` (RFC 9449 §5) and log `oauth_agent_token_refused` with outcome `bad_dpop`.
     - Its `jkt` must equal `jwkThumbprintOfPem(proven.publicKeyPem)`. Otherwise answer 400 `invalid_dpop_proof`, "Sign the DPoP proof with the same key as the client assertion."
  3. If either set already has the request's key, refuse: the assertion's as today, the proof's with 400 `invalid_dpop_proof` "This DPoP proof was already used."
  4. Then the book checks and allowances, as today.
  5. Spend the proof's key first, then the assertion's. A `ReplayStateFullError` on either gets Task 2's 503, with `set` naming the set that's full.
  6. If the proof set is missing (the replay state couldn't open), answer 503, the same as a missing `usedAssertions`.
  7. Mint with `jkt`, and answer `token_type: "DPoP"`, with every other field as today.
- Metadata: when `agentKeys` is set, the authorization-server metadata adds `dpop_signing_alg_values_supported: ["EdDSA"]` (RFC 9449 §5.1). The protected-resource metadata is unchanged: chat tokens on the same resource stay Bearer.

**Steps:**
- [ ] **Step 1: Failing tests** in `oauth-agent-keys.test.mjs`. Add a `dpop` field to the existing grant helper: by default `agent.dpop("POST", TOKEN_ENDPOINT)`, sent as the `DPoP` header. The existing tests then go through the new path.
  - A grant with a valid proof gets `token_type: "DPoP"`, and `verifyToken(...).payload.cnf.jkt === agent.thumbprint`.
  - Each of these gets 400 `invalid_dpop_proof` and mints nothing: no proof; two proofs; a proof from another key; a proof with `htu` for another URL; a proof with `htm: "GET"`; a proof with `iat` 120 s old.
  - A refused proof leaves its assertion unspent: the same assertion with a good proof then mints.
  - A replayed proof (with a fresh assertion) gets 400 "already used".
  - With agent keys off, the metadata has no `dpop_signing_alg_values_supported` (extend the existing "only when enabled" test).
  - `mintAgentToken` refuses a malformed `jkt`, and `verifyToken` refuses `cnf: {}` and `cnf: { jkt: "x" }`.
  - Neither the log nor the response contains the proof (extend "the response and server log never contain the assertion").
- [ ] **Step 2:** Run it. Expect FAIL.
- [ ] **Step 3:** Implement. Update direct `mintAgentToken` callers in tests to pass a `jkt`.
- [ ] **Step 4:** Run `oauth-agent-keys`, `oauth`, `agent-keys-routes` (PASS). Some HTTP tests that use agent tokens on `/mcp` or `/shadow/mcp` still pass, because the resource side changes in Task 5. Run the full suite.
- [ ] **Step 5:** Commit `src/token.ts src/oauth.ts` and the tests: "Bind each agent token to the agent's key with DPoP at sign-in".

### Task 5 (D1, part 3): Every agent request carries a DPoP proof

**Why:** a token bound at sign-in protects nothing until the resource checks the binding.

**Where agent tokens are accepted:** `checkAuth` in `src/http.ts` (around line 1147), which serves `/mcp` (line 2049) and every `/shadow` MCP path through `shadowResolveOwner` (line 1293). There's also the open-mode branch of `shadowResolveOwner` (line 1309), and `shadowUnauthorized` calls `checkAuth` a second time (line 1236). `/agent-keys/*` takes assertions, not tokens, so it doesn't change.

**Files:**
- Modify: `src/http.ts`
- Test: `test/shadow-http.test.mjs`, which already boots runHttp with agent keys and mints through `tokenFor`
- Fixture updates: every test that sends an agent token. Find them with `grep -ln "client_credentials\|tokenFor(\|mintAgentToken" test/*.mjs`; at the time of writing that's `shadow-http`, `agent-keys-e2e`, `agent-keys-routes`, `oauth-agent-keys` and `oauth`. Each moves to `Authorization: DPoP <token>` plus `dpop: agent.dpop(method, PUBLIC + path, { accessToken })`. Don't change account-token requests.

**Design:**
- **Reading the credential.**
  - Add `presentedDpopToken(headers): string`, the token from `/^DPoP\s+(\S+)$/i` on `authorization`, or `""`.
  - Change `presentedApiKey` to return it as well when there's no `x-api-key` and no Bearer value, **and only when `looksLikeSelfServe(token)`**. A non-`cc_` value under the DPoP scheme is then never treated as a bring-your-own Clockchain key.
  - `matchStaticToken` stays Bearer and `x-api-key` only.
- **In `checkAuth`, after `verifyToken` succeeds:**
  - Let `bound = v1.payload.cnf !== undefined`, `agent = agentKeys on && v1.payload.akf !== undefined`, and `dpopScheme = presentedDpopToken(req.headers) === presented`.
  - If `bound || agent || dpopScheme`, all of these must hold, otherwise return the new outcome `{ ok: false, dpopRefused: <reason> }`:
    - `dpopScheme`;
    - `cnf` is present (so an `akf` token minted before Task 4 is refused);
    - `verifyDpopProof({ proof: req.headers.dpop, htm: req.method, htu: publicUrl + pathOf(req.url), nowSec, accessToken: presented })` passes;
    - its `jkt === cnf.jkt`;
    - the proof's replay key isn't in `oauth.usedDpopProofs`;
    - and it can be added.
  - A missing proof set, or a write failure, returns `{ ok: false, unavailable: true }`, answered as 503. A full set gets the same 503 with the Task 2 wording: "Clockchain is taking too many agent requests right now. Try again in a minute."
  - Then the existing `agentKeyOf` checks run.
  - `publicUrl` is `oauthConfig.publicUrl`. With OAuth not ready no agent tokens exist, and any `cnf` token is refused.
- **Once per request.** Wrap `checkAuth` in a `WeakMap<IncomingMessage, AuthOutcome>`, so the second call in `shadowUnauthorized`, and any later one, returns the first outcome and never spends a proof twice.
- **Open mode.** The open-mode branch of `shadowResolveOwner` gets the same check, through the same helper. It's local only (`MCP_REQUIRE_AUTH` is always set in production), but it must not be a way around the binding.
- **The 401 for `dpopRefused`, on `/mcp` and the `/shadow` MCP paths:**
  - Headers: status 401, `content-type: application/json`, `cache-control: no-store`, and a `www-authenticate` of `DPoP algs="EdDSA", error="invalid_dpop_proof"`. Use `error="invalid_token"` instead when the scheme was Bearer or `x-api-key`. Add `oauth.challenge(...)`'s Bearer challenge as a second challenge, comma-separated.
  - Body: `{ error, message }`. Bearer for an agent token: "This agent token is bound to your key: send it as \"Authorization: DPoP <token>\" with a DPoP proof on every request." A bad proof: the verifier's reason.
  - It uses the same shape as `agentKeyCancelledUnauthorized`, in the same three places that one is handled (`/mcp`, `shadowUnauthorized`, and `shadowResolveOwner`'s refusal).
- **Rate-limit key.** Confirm that `callerKey`/`callerPrincipalId` get the verified `jti` or agent root for these requests, as they do today (`selfServeJti`, `ak:<root>`). If any path falls back to the Bearer regex, it would bucket a DPoP request by IP. In that case, pass the verified value; don't widen the regex.

**Steps:**
- [ ] **Step 1: Failing tests** in `shadow-http.test.mjs`, against runHttp with agent keys on, each on `/shadow/mcp` unless it says otherwise:
  - DPoP with a valid proof: `tools/list` and `shadow_start_session` get 200. The same on `/mcp` with `tools/list`.
  - An agent token as `Bearer` gets 401, and `www-authenticate` matches `/^DPoP /` and contains `error="invalid_token"`. The body says to send it as DPoP, and the body and logs don't contain the token.
  - Each gets 401 `invalid_dpop_proof`: DPoP scheme with no proof; a proof whose `ath` is for another token; `htu` for `/mcp` sent to `/shadow/mcp`; `htm` POST on a GET (open the SSE stream with GET); a proof signed by another key; `iat` 120 s old.
  - The same valid proof sent twice: the first gets 200, the second 401 `invalid_dpop_proof` "already used".
  - A request refused by the proof check logs no "already used" (the second `checkAuth` call is memoised): assert the log has exactly one refusal line for the request.
  - The proof set refuses when full: with `agentKeys.spentDpopCap: 1` (Task 4), a second agent's valid request gets 503 with the "too many agent requests" message. runHttp doesn't take OAuth options, so test this through `createOAuthHandler` plus a minimal `checkAuth` harness. If `checkAuth` can't be reached outside runHttp, test the 503 mapping where the outcome is turned into a response, with a fake set whose `add` throws `ReplayStateFullError`.
  - Chat tokens unchanged: an account token as Bearer still gets 200 on `/shadow/mcp`, and the same account token under the DPoP scheme gets 401 (it has no `cnf`).
  - The bring-your-own fallback isn't reachable through the scheme: `Authorization: DPoP not-a-cc-token` on `/mcp` gets the ordinary 401, and the gateway receives no call.
- [ ] **Step 2:** Run it. Expect FAIL.
- [ ] **Step 3:** Implement, then move the fixtures named above to DPoP.
- [ ] **Step 4:** Run `shadow-http`, `agent-keys-e2e`, `agent-keys-routes`, `oauth-agent-keys`, `oauth` and `http` (PASS), then the full suite.
- [ ] **Step 5:** Commit `src/http.ts` and the tests: "Require a DPoP proof from the agent's key on every agent request".

### Task 6 (D1, part 4): The client example, the instructions and the end-to-end test

**Why:** agents onboard from `/llms.txt` and `/shadow/connect` alone (ruling 37). They must learn to send a DPoP proof, and the TypeScript MCP SDK is how most of them will connect.

**Files:**
- Create: `packages/mcp-server/examples/agent-key-client.mjs` (plain ESM, imports only `node:crypto`, no `dist/` import)
- Modify: `src/shadow/discovery.ts` (`agentKeyLines`)
- Modify: `test/agent-keys-e2e.test.mjs` (the first test, from Task 11)
- Modify: `infra/clockchain-mcp/RUNBOOK.md` (the `MCP_AGENT_KEYS` row, one sentence plus a pointer to the example)

**The example.** It's load-bearing: the e2e test runs it unmodified.
```js
// A minimal agent client: its own Ed25519 key, one signed assertion for a DPoP-bound token, and a fetch that adds a fresh
// DPoP proof to every request. Use it with the MCP TypeScript SDK:
//   const key = agentKey();                                    // keep key.privateKey; Clockchain never sees it
//   const token = tokenSource(key, "https://mcp.clockchain.network/oauth/token");
//   const transport = new StreamableHTTPClientTransport(new URL("https://mcp.clockchain.network/shadow/mcp"),
//     { fetch: dpopFetch(key, token) });
//   await new Client({ name: "my-agent", version: "1" }).connect(transport);
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";
const b64u = (b) => Buffer.from(b).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

export function agentKey(privateKey = generateKeyPairSync("ed25519").privateKey) {
  const { kty, crv, x } = createPublicKey(privateKey).export({ format: "jwk" });
  const jwk = { kty, crv, x };
  const thumbprint = b64u(createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest());
  const jwt = (header, claims) => {
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
    return `${input}.${b64u(sign(null, Buffer.from(input, "ascii"), privateKey))}`;
  };
  return {
    privateKey, jwk, thumbprint,
    assertion: (aud) => jwt({ alg: "EdDSA", typ: "JWT", jwk }, { iss: thumbprint, sub: thumbprint, aud, iat: now(), exp: now() + 300, jti: randomUUID() }),
    dpop: (htm, htu, accessToken) => jwt({ alg: "EdDSA", typ: "dpop+jwt", jwk }, {
      jti: randomUUID(), htm, htu, iat: now(),
      ...(accessToken ? { ath: b64u(createHash("sha256").update(accessToken, "ascii").digest()) } : {}),
    }),
  };
}

/** An async getter for a DPoP-bound access token, signed for again a minute before each one expires (there is no refresh token). */
export function tokenSource(key, tokenEndpoint, { postTo = tokenEndpoint } = {}) {
  let token, until = 0;
  return async () => {
    if (token && now() < until) return token;
    const res = await fetch(postTo, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: key.dpop("POST", tokenEndpoint) },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: key.assertion(tokenEndpoint),
      }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(`token: ${body.error}: ${body.error_description}`);
    token = body.access_token;
    until = now() + body.expires_in - 60;
    return token;
  };
}

/** A fetch for StreamableHTTPClientTransport: "Authorization: DPoP <token>" and a new proof per request. */
export function dpopFetch(key, getToken, { htuOf = (url) => url.split(/[?#]/)[0] } = {}) {
  return async (url, init = {}) => {
    const href = url instanceof URL ? url.href : String(url);
    const accessToken = await getToken();
    const headers = new Headers(init.headers);
    headers.set("authorization", `DPoP ${accessToken}`);
    headers.set("dpop", key.dpop((init.method ?? "GET").toUpperCase(), htuOf(href), accessToken));
    return fetch(href, { ...init, headers });
  };
}
```
`postTo` and `htuOf` exist only because the tests reach the server at `127.0.0.1` while `MCP_PUBLIC_URL` is `https://mcp.example.test`. Real agents leave them unset.

**The instructions** (`agentKeyLines`): keep eight lines at most, and change two of them in place.
- **Step 2:** "…`client_assertion=<JWT>`, with a `DPoP` header: a second JWT signed by the same key, header `typ dpop+jwt`, `alg EdDSA` and the same `jwk`; claims `htm POST`, `htu` the `token_endpoint`, `iat` now, a new `jti`."
- **Step 3:** "Send `\"Authorization: DPoP <access_token>\"` and a new `DPoP` proof on every request to `${shadow}` (streamable HTTP): `htm` the method, `htu` the URL without its query, `iat` now, a new `jti`, `ath` the base64url SHA-256 of the access_token. A Bearer token is refused."
- Don't change any other line.

**Steps:**
- [ ] **Step 1: Failing tests** in `agent-keys-e2e.test.mjs`:
  - Add `"DPoP"`, `"dpop+jwt"`, `"htm"`, `"htu"` and `"ath"` to the instruction facts. Keep the eight-line check.
  - `issued.token_type === "DPoP"`.
  - Replace the hand-built `rpc` calls with the SDK. The rest of the test's assertions stay as they are:
    ```js
    const key = agentKey(agent.privateKey)
    const t = tokenSource(key, meta.token_endpoint, { postTo: `${app.url}/oauth/token` })
    new StreamableHTTPClientTransport(new URL(`${app.url}/shadow/mcp`), { fetch: dpopFetch(key, t, { htuOf: (u) => PUBLIC + new URL(u).pathname }) })
    ```
    Then `Client.connect`, `client.listTools()` and `client.callTool(...)`.
    - **Helper change:** `makeAgentKey()` in `test/helpers/agent-key.mjs` also returns `privateKey`, so the checkpoint hashes are signed by the same key.
    - **Fallback:** if `callTool` result parsing differs from the current `call()`, wrap `client.callTool` in the existing `call` signature.
  - The same session sees a second token (AT-7a) through a second `tokenSource`.
  - AT-7e: every DPoP proof the fetch sent is collected. Wrap `dpopFetch` to record the `dpop` header. No log line or tool result contains any of them.
- [ ] **Step 2:** Run `node --test test/agent-keys-e2e.test.mjs`. Expect FAIL: the example is missing and the instruction facts are missing.
- [ ] **Step 3:** Write the example, update `agentKeyLines`, and update the RUNBOOK row: "Agent tokens are DPoP-bound (RFC 9449): every request needs a proof from the agent's key. A working client for the MCP TypeScript SDK is `packages/mcp-server/examples/agent-key-client.mjs`."
- [ ] **Step 4:** Run `agent-keys-e2e`, plus any discovery tests that assert the agent lines exactly (`grep -ln "Agents that run code" test/*.mjs`) (PASS), then the full suite. Also run `cd infra && npm test` if RUNBOOK assertions exist (`grep -rn "RUNBOOK" infra/test`).
- [ ] **Step 5:** Commit `examples/agent-key-client.mjs src/shadow/discovery.ts test/agent-keys-e2e.test.mjs test/helpers/agent-key.mjs infra/clockchain-mcp/RUNBOOK.md` and any updated discovery tests: "Tell agents to send a DPoP proof, with a working MCP SDK client".

### Task 7 (D2): Cache the book's durable files, and clean stale copies at boot

**Why:**
- `AgentKeyBook.get()` (`src/agent-keys/book.ts`) builds a new durable-file object and reads the disk on every call. It's called on every agent request (`agentKeyOf` in `http.ts`), in the grant, the routes and Shadow's sign and verify paths.
- `save()` builds yet another object that never loaded, so its `mainCorrupt` flag is false. Take a main file that's corrupt but has a good `.bak`: the first save renames the corrupt main over the good `.bak` (ledger, Task 2 minor; the same defect was probe-confirmed for `StarterAnchors` in Task 8).
- The book also never calls `cleanStaleFiles`, so temp and quarantine copies stay forever.

**Files:**
- Modify: `src/agent-keys/book.ts`
- Test: `test/agent-keys-book.test.mjs`
- Fixture update: `test/shadow-http.test.mjs`. `app.book` is a second `AgentKeyBook` on the server's directory, and the tests at about lines 455, 476 and 501 replace or revoke keys through it. With a cache, the server wouldn't see those changes (A2: one writer). Change them to the real `POST /agent-keys/<fp>/replace` and `/revoke` routes, which `agent-keys-routes.test.mjs` already shows how to call, and remove `app.book`.

**Design:**
```ts
type Slot = { file: DurableJsonFile<KeyEntry>; entry: KeyEntry };
private readonly slots = new Map<string, Slot>();        // fingerprint -> its one file object; at most MAX_CACHED (10_000)
```
- **Constructor:** `cleanStaleFiles(this.dir)`, after the existing fields. It's a no-op when the directory doesn't exist yet.
- **`get(fp)`:**
  - On a slot hit, move the slot to the newest position (`delete` + `set`) and return `structuredClone(slot.entry)`.
  - On a miss, create the file with `snapshot: () => slot.entry` and call `load()`. That's where `mainCorrupt` gets set, on the object that will also save.
  - `undefined`: return `null` and cache nothing, so a flood of unknown fingerprints costs no memory.
  - A value: store the slot, drop the oldest slot past `MAX_CACHED`, and return a clone.
  - A `DurableStateError` propagates as today.
- **`save(entry)`:**
  - Use the slot's file. If there's no slot (a new key), create the file and `load()` it first.
  - Set `slot.entry = entry` only after `file.save("now")` succeeds. If the save throws, delete the slot and rethrow, so the next `get()` reads what's actually on disk.
  - Internal callers already work on the clone that `must()` / `get()` returned, so they never mutate the cached object.
- **`admit`, `replace`, `revoke`, `setFiling`, `setEventFiling`** keep their logic. Only `get`, `save` and `file` change.
- **One code comment:** the cache makes this instance the only writer, and an operator who edits a key file by hand restarts the server. Add the same sentence to the RUNBOOK's `MCP_AGENT_KEYS` row.

**Steps:**
- [ ] **Step 1: Failing tests** in `agent-keys-book.test.mjs`:
  - `a corrupt key file with a good backup is never rotated over the backup`:
    1. Admit a key, then `setFiling(pending)`. There are now a main and a `.bak`.
    2. Overwrite the main with `{"schema":"agent-key-v1","value":{}}`, mode 0600.
    3. Open a new book. `get()` returns the `.bak`'s entry.
    4. `setFiling(filed)`.
    5. The `.bak` is byte-identical to before step 2 (the good entry): `write()`'s `mainCorrupt` branch unlinks the corrupt main instead of renaming it over the `.bak`. The main holds the new entry.
    6. This FAILS today.
  - `a second get() of a key reads the cache`: `get()`, then delete the file on disk, then `get()` still returns the entry.
  - `changing what get() returned changes nothing stored`.
  - `a failed save leaves the book as the disk says`: `chmod 0o500` the dir, `setFiling` throws, `chmod` back, and `get()` returns the old filing.
  - `opening the book removes temp files and quarantined copies older than 7 days, and keeps newer ones`. Use the `.corrupt-<ms>` / `.tmp` names that `cleanStaleFiles` matches.
  - `past 10,000 cached keys the oldest is dropped and still loads from disk`. Lower the cap through a constructor option, `maxCached?: number`, for tests only.
- [ ] **Step 2:** Run it. Expect the first two (or three) to FAIL.
- [ ] **Step 3:** Implement, then move `shadow-http.test.mjs` off `app.book`.
- [ ] **Step 4:** Run `agent-keys-book`, `shadow-http`, `oauth-agent-keys`, `agent-keys-routes`, `agent-keys-check`, `agent-keys-filing` and `shadow-agent-sign` (PASS), then the full suite.
- [ ] **Step 5:** Commit `src/agent-keys/book.ts test/agent-keys-book.test.mjs test/shadow-http.test.mjs infra/clockchain-mcp/RUNBOOK.md`: "Keep one durable file per agent key in memory, and clear stale copies at boot".

### Task 8 (D5): Remove agent keys that were never used

**Why:** ruling 39. Every sign-in from a new key writes about 1 KB that's kept forever. The ceiling is 200 new keys an hour, which is up to about 1.7 million files a year.

**"Never used", precisely.** A key file is removed only when **all** of these hold:
1. `status === "active"`. A replaced or revoked key has history, and is the root of, or a link to, another key.
2. `root === fingerprint`, so it's a root. A replacement is linked from its old key's `replacedBy`.
3. `replacedBy` is unset and `events` is empty.
4. `filing.state === "unfiled"`. A filed key is on the public ledger, and its lookup must keep answering for old records. `pending` means a filing was tried for an anchor, so the key was used.
5. `firstSeenAt` is more than **30 days** ago (FC4).
6. Shadow has no owner directory for `ak:<fingerprint>`. That means no sessions, no settings and no operator file, whether alive or in retention.

**Why this also covers "root of another key":** only `replace` gives another key `root = X`, and `replace` sets X's status to `replaced`, which rule 1 excludes. A test pins this.

A key used only on `/mcp` (no Shadow records, never filed) counts as never used. If its agent signs in again after removal, it's admitted as a new key, which costs a new-key allowance. That's accepted.

**Files:**
- Modify: `src/agent-keys/book.ts` (add `forgetUnused`)
- Modify: `src/shadow/store.ts` (add `hasOwner(ownerKey): boolean`, which is `existsSync(this.ownerDir(ownerKey))`)
- Modify: `src/shadow/service.ts` (call it from `sweep()`)
- Test: `test/agent-keys-book.test.mjs`, `test/agent-keys-filing.test.mjs`

**Interfaces:**
```ts
/** Removes never-used keys (rules 1-6), returning how many. `inUse(fp)` is rule 6. Synchronous from check to unlink. */
forgetUnused(opts: { firstSeenBefore: Date; inUse: (fp: string) => boolean }): number;
```

**Design:**
- Read the directory once. For each `<fp>.json`, `statSync`, and skip it unless `mtimeMs < firstSeenBefore`. An unused entry is written once, at admit, so this prefilter avoids opening most files.
- Then `get(fp)`, apply rules 1–5, then `inUse(fp)`.
- Then `unlinkSync` the main and the `.bak` (with `force`), and delete the slot.
- A file that won't read is skipped and counted apart. Never delete what can't be read.
- No `await` anywhere, so no grant or route can interleave in this process.
- `ShadowService.sweep()` calls it once per sweep (hourly) when `this.agentKeys` is set:
  - `this.agentKeys.forgetUnused({ firstSeenBefore: new Date(this.now().getTime() - 30 * 86_400_000), inUse: (fp) => this.store.hasOwner(ownerKeyOf(\`ak:${fp}\`)) })`.
  - It's in its own `try`, and logs `{ event: "agent_keys_forgotten", keys: n }` only when `n > 0`. No fingerprints are logged.
- Make 30 days a named constant next to `DEFAULT_SHADOW_LIMITS`, not a setting.

**Steps:**
- [ ] **Step 1: Failing tests.**
  - `agent-keys-book.test.mjs`: one key per rule that **is kept**, plus one that's removed. Use the book's `now` clock for `firstSeenAt`, and `utimesSync` for the mtime prefilter.
    - Kept: revoked; replaced (and its replacement); a replacement itself; with a `filed` event; filing `pending`; filing `filed`; 29 days old; `inUse` true; an unreadable file.
    - Removed: a 31-day-old active unfiled root with no events and no owner. Afterwards `get()` returns `null`, and both the main and `.bak` are gone.
  - `agent-keys-filing.test.mjs`, at service level:
    - a key whose agent started a session that's still waiting (unfiled, owner dir present) survives `svc.sweep()` at +31 days;
    - an admitted key that never started a session is gone after `svc.sweep()` at +31 days;
    - its token now gets 401 (through `agentKeyOf` → `unusable`), and a fresh grant from the same key admits it again as new.
- [ ] **Step 2:** Run both. Expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run both (PASS), plus `shadow-witness` and `shadow-agent-sign`, then the full suite.
- [ ] **Step 5:** Commit `src/agent-keys/book.ts src/shadow/store.ts src/shadow/service.ts` and the two tests: "Remove agent keys nobody used after 30 days".

### Task 9 (D7): Remove a damaged old key.json in witness mode

**Why:** ruling 42.
- With the witness key on, `ShadowStore.witnessedOperatorId` (`src/shadow/store.ts`, around line 255) loads `key.json` only to carry its operator id over.
- When `key.json` and its `.bak` are both unreadable, `load()` throws `DurableStateError` after copying the bad file to `key.json.corrupt-<ms>`.
- So the owner can't start or use any session, every attempt adds another copy of private-key bytes, and the boot sweep counts it as `failed` and leaves it.

**Files:**
- Modify: `src/shadow/store.ts` (`witnessedOperatorId`, `migrateHeldKeys`)
- Modify: `src/shadow/service.ts` (`start()`'s boot log fields only)
- Test: `test/shadow-witness.test.mjs`

**Design (FC5):**
- In `witnessedOperatorId`, wrap only the `old.load()` call.
  - On `DurableStateError`, log `{ event: "shadow_damaged_key_removed", owner: ownerKey.slice(0, 16), note: "key.json and its backup were unreadable; a new operator id was issued and every copy removed" }` through the store's logger. If it has none, use `console.error(JSON.stringify(...))` as `durable-store.ts` does.
  - Then continue with `old = undefined`. The existing code then mints a fresh `operatorId`, saves `operator.json`, and only then calls `removeHeldKeys`, which deletes `key.json`, `.bak`, `.corrupt-*` and `.tmp`.
  - Any other error propagates as today.
- `migrateHeldKeys` returns `{ migrated, failed, damaged }`. `damaged` counts owners that took the branch above, so `witnessedOperatorId` needs to report it: have it return `{ operatorId, damaged }` internally, or set a flag. Pick the smaller change.
- `start()` logs `damaged` with the existing `shadow_held_keys_migrated` line.
- Legacy mode (no witness key) is unchanged. A damaged `key.json` there is still refused, because its private key would sign. The RUNBOOK covers it.

**Steps:**
- [ ] **Step 1: Failing tests** in `shadow-witness.test.mjs`, following its helpers:
  - `with the witness key, a key.json with no readable backup is removed and the owner gets a fresh operator id`:
    1. Create owner A's dir with `key.json` = `"{not json"` (mode 0600) and no `.bak`.
    2. Start the service with the witness key.
    3. No `key.json*` file is left, and `operator.json` has a UUID `operatorId`.
    4. The boot log has `damaged: 1` and one `shadow_damaged_key_removed` line, which doesn't include the file's contents.
    5. A can start, record and close a session that verifies.
  - The same damage found on first use rather than at boot: create the file after `start()`, then call `startSession`.
  - A damaged `key.json` with a **good** `.bak` still migrates the `.bak`'s `operatorId` (the existing behaviour, pinned here).
  - Without the witness key, a damaged `key.json` still makes A's `startSession` fail as it does today. The file stays, and nothing new is removed.
- [ ] **Step 2:** Run it. Expect the first two to FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `shadow-witness` and the Shadow store tests (`grep -ln "operator.json\|key.json" test/*.mjs`) (PASS), then the full suite.
- [ ] **Step 5:** Commit `src/shadow/store.ts src/shadow/service.ts test/shadow-witness.test.mjs`: "Remove an unreadable old key file when Clockchain's key is on, and give the owner a new operator id".

### Task 10: Close the small open security items from the build log

Added by the orchestrator (founder, 14 Nov: "do what is needed to productionize this").

- **Files:** `src/agent-keys/book.ts`, `src/agent-keys/routes.ts`, `src/oauth.ts`; tests in `test/agent-keys-book.test.mjs`, `test/agent-keys-routes.test.mjs`, `test/agent-keys-oauth.test.mjs` (or whichever existing files cover these; add to them).
- **Write first (failing):**
  1. A key file whose `publicKeyPem` does not hash to its `fingerprint` (or to its file name) is treated as corrupt: `get()` returns null, and the server never accepts it as that key.
  2. An assertion to a key route (replace, revoke) with an `aud` array is refused; the route requires `aud` to be the exact string. The token grant keeps accepting what RFC 7523 allows today, unless the existing tests show it already requires a string.
  3. A token request whose `client_id` is present and is not the assertion's `iss`/`sub` is refused with `invalid_client` (RFC 7523 §3).
  4. A replace whose replay write fails part-way leaves neither assertion usable: spend both ids in one durable write (one journal append) or spend the new key's id first, so a failure always fails closed. Test with a replay set whose second `add` throws.
- **Verify:** the touched test files, then the full suite.
- **Commit:** "Close the open key-file, audience, client_id and replace-spend items"

### Task 11: Pass the agent-key settings through the deploy, still off unless set

- **Files:** `infra/clockchain-mcp/docker-compose.yml`, `infra/clockchain-mcp/compose-up.sh` (`read_optional_env`), `infra/test/compose-contract.test.mjs`, `infra/clockchain-mcp/RUNBOOK.md`.
- **Change:** pass the six settings (blocker 1) through to the `mcp` service, each defaulting to empty so nothing changes until SSM sets it. Add a read-only mount for the witness key file at a fixed path (for example `/app/witness/witness-key.pem`, from a host path that compose-up writes from SSM only when the parameter exists), mirroring how the `host` service gets `/app/keys`. With the parameter absent, compose must not create the mount source or set `SHADOW_WITNESS_KEY_FILE`.
- **RUNBOOK:** a "Turning on agent keys" section: the order (witness key provisioned and backed up first, then `MCP_AGENT_KEYS=1`), the key backup and rotation procedure, that turning on the witness key deletes every account's `key.json` (ruling 15) and can't be undone, one process per state volume (blocker 5), the counter-file ceiling (blocker 6), and the production rule (founder's go, travel orchestrator notice, frozen routes untouched).
- **Write first (failing):** the compose contract test pins the new settings and the conditional mount.
- **Verify:** `cd infra && node --test` (expect all pass), and `bash -n infra/clockchain-mcp/compose-up.sh`.
- **Commit:** "Pass the agent-key settings through the deploy, off unless set"
- **Never** run compose-up, SSM writes or any deploy.

---

## Other production blockers (not planned here)

1. **Six settings aren't wired into the deploy.** `MCP_AGENT_KEYS`, `MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR`, `MCP_AGENT_KEYS_NEW_PER_HOUR`, `SHADOW_WITNESS_KEY_FILE`, `SHADOW_STARTER_ANCHORS_PER_DAY` and `SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY` aren't in `infra/clockchain-mcp/docker-compose.yml` or `compose-up.sh`'s `read_optional_env` list (RUNBOOK lines 329–331). Setting them in SSM does nothing. `infra/test/compose-contract.test.mjs` pins the compose environment list and needs the same change. This needs the founder's go.
2. **The witness key isn't provisioned.**
   - There's no secret, and the `mcp` service mounts only `mcp_state` (no `/app/keys` mount like the `host` service's).
   - There's no backup or rotation procedure for the key.
   - Turning it on deletes every account's `key.json` (ruling 15), which can't be undone.
   - This needs the founder's go and a written key procedure.
3. **`MCP_AGENT_KEYS` defaults to off**, by design. Enabling it in production needs the founder's go and the usual production rule: notify the travel orchestrator before any production MCP deploy, and leave the frozen v2/acm4 routes alone.
4. **The branch base.** `feat/agent-keys` is cut from `feat/staging-labels-search`, which is 47 commits ahead of `main`, so the merge order must be decided. The worktree also has uncommitted Shadow work (the plan's base).
5. **One process per state volume** is required (A2). Nothing in compose stops a second `mcp` replica or a second container on the same volume. Document it, or enforce it with a lock file.
6. **Starter counter ceiling.** `starter-anchors.json` is capped at 512 KiB, which is about 10,000 anchors a day (RUNBOOK line 334).
7. **Smaller security items from the ledger that are still open:**
   - `validEntry` in `book.ts` doesn't check `fingerprint(publicKeyPem) === fingerprint` (a tampered file);
   - route assertions accept an `aud` array;
   - RFC 7523 `client_id` mismatch is accepted silently;
   - replace's two `jti`s aren't spent atomically.
   Task 3 closes the `nowSec` NaN item.
8. **The chat-app replay sets** (used codes, used refresh tokens, revoked families) still evict live entries when full (FC3).
9. **The suite isn't a reliable gate.** Full-suite port-race flakes recur (`oauth.test.mjs`, `agent-contract-wiring`, `shadow-http`). Every task here relies on `--test-concurrency=4` and per-file reruns.
10. **Staging has no storage volume.** A container recreate wipes the key book, the replay sets and the counters (rulings, "Staging trial notes"). Production has `mcp_state`.
