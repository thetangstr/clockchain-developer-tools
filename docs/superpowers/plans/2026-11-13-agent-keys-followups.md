# Agent keys, founder follow-ups — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four changes the founder approved after reviewing the core loop on 13 Nov 2026.
1. The page and the verify tool say plainly what a signature proves.
2. One address can't use up the shared Starter allowance.
3. A test proves that old records still verify after switching to Clockchain's key and back.
4. A repeated identical signature returns the original result instead of an error.

**Base:** branch `feat/agent-keys` at `6ffe671` (the core loop, reviewed). Work in `packages/mcp-server`.

**Spec:** the founder's review notes of 13 Nov 2026, as summarised in this plan's tasks, and `project-shadow/project-shadow-lld.md` §17 for everything they don't change. The decision log is `project-shadow/docs/build-ledgers/2026-11-13-agent-keys-rulings.md`.

**Out of scope:** the founder listed these as production gates, tracked separately:
- DPoP-bound tokens;
- the used-message list refusing when full;
- the race when a key is cancelled during signing.

## Global Constraints

- Everything stays off by default. With `MCP_AGENT_KEYS` and `SHADOW_WITNESS_KEY_FILE` unset, every existing test passes unchanged, apart from the expected-text updates Task 1 names.
- `shadow/lib/*` is vendored: don't edit it.
- No key, token, assertion, raw IP address or address hash appears in any tool result, public route, ledger payload, log line or error message.
- The frozen routes `/handshake/mcp`, `/next/handshake/mcp` and `/acm4/*` are not touched.
- No new dependencies.
- Test command: `cd packages/mcp-server && npx tsc -b && node --test --test-concurrency=4`. Unbounded parallel runs hit port-race flakes that have nothing to do with this code.
- Commit after each task on `feat/agent-keys`. Never push, merge or deploy.
- Write tests first: a failing test, then the code.

---

### Task 1: Say what a signature proves

**Why:** the founder wrote, "An agent signature says the registered agent key signed the record. It does not, by itself, prove that a particular person or company authorized the agent, or that the recorded work actually happened. A Clockchain signature is a different claim again." The rule that Shadow never puts its own signature on an agent's record stays as it is; it already holds, so don't change it.

**Files:**
- `src/agent-keys/check.ts`
- `test/agent-keys-check.test.mjs`
- `test/agent-keys-e2e.test.mjs`
- any other test that asserts these exact texts

- [ ] Add, next to `CHECKED`:
  `export const SCOPE = " An agent's signature shows which key signed, not who runs the agent or that the work happened.";`
- [ ] The verdict texts become exactly the following. `<id>` is the agent id, `<d>` the anchored date, `<f>` the filed date, `${SCOPE}` and `${CHECKED}` the constants.

  | verdict | text |
  |---|---|
  | `made_by_agent` (anchored) | `Made by agent <id>, unchanged since <d>. Key filed <f>.${SCOPE}${CHECKED}` |
  | `made_by_agent` (not yet anchored) | `Signed by agent <id>. Key filed <f>. Not yet anchored on Clockchain.${SCOPE}${CHECKED}` |
  | `key_not_filed` | `Signed by agent <id>. Its key isn't filed on Clockchain yet.${SCOPE}${CHECKED}` |
  | `key_check_unavailable` | `Signed by agent <id>. Its key can't be checked right now.${SCOPE}` |
  | `witnessed` | `Witnessed by Clockchain for a signed-in account: Clockchain's key signed these steps as it received them, not the agent's own key.${CHECKED}` |

  Every other verdict's text (`record_failed` in both forms, `not_from_agent`, `key_revoked_before`, `key_filed_after`, `legacy`) stays byte-identical.
- [ ] Update the tests that assert the changed texts, and nothing else in them.
- [ ] Add one test checking that `SCOPE` appears in the viewer page and in the `shadow_verify` `agent_key.text` for a `made_by_agent` record.
- [ ] Run the full test command. Commit as "Say what an agent's signature does and doesn't prove".

### Task 2: A per-address share of the Starter allowance

**Why:** at present, one address can use up the shared Starter daily allowance (2,000) in about 3½ hours by staying inside the per-agent and per-address-per-hour limits. The founder wants the shared cap kept as a backstop, "not the only protection against one user starving the trial".

**Design:**
- **Recording the address.**
  - When the token grant admits a **new** key (`oauth.ts`, `keys.book.admit(...)`), it records the address it came from as `source` on the new entry.
  - `source` = the first 32 hex characters of `HMAC-SHA256(options.signingSecret, "agent-key-source:v1\0" + ipOf(req))`. `ipOf` already gives the proxy-aware, IPv6-/64 bucket.
  - Only the hash is stored, never the address.
  - Replacement keys made by the replace route get no `source` of their own. A root's source is the root entry's `source`.
- **Book changes** (`src/agent-keys/book.ts`):
  - `KeyEntry` gains `source?: string`, which must match `/^[0-9a-f]{32}$/` when present.
  - `admit(publicKeyPem, source?)` stores it on a newly created entry and ignores it for a known one.
  - Entries without `source` stay valid.
- **The counter** (`src/agent-keys/filing.ts`, `StarterAnchors`):
  - The file becomes `{ day, anchors, sources?: Record<string, number> }`, under the same schema name, and still validates old files.
  - `check(source?)` throws `StarterLimitError` when `anchors >= max`, or when `source` is given and `sources[source] >= perSource`.
  - `record(source?)` adds 1 to `anchors`, and to `sources[source]` when `source` is given.
  - A new day resets both.
  - Raise `maxBytes` to `512 * 1024`.
  - An unreadable file still fails closed, as now.
- **The setting:** `SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY`, default **200**, parsed the same way as `SHADOW_STARTER_ANCHORS_PER_DAY` in `service.ts`. It's added to `DEFAULT_SHADOW_LIMITS` as `maxStarterAnchorsPerSourcePerDay` and documented in `infra/clockchain-mcp/RUNBOOK.md` next to `SHADOW_STARTER_ANCHORS_PER_DAY`. Don't change compose files.
- **Wiring** (`src/shadow/service.ts`): `anchoring(...)` / `withStarter(...)` pass the agent root's `source`, from `this.agentKeys.get(<root fingerprint>)?.source`, to `check` and `record`.
  - If the book can't be read here, treat it as no source. The existing filing path already fails closed on an unreadable book.
  - The row-to-root lookup uses whatever `fileFirst` / `keysToFile` already use.
- **The error:** `StarterLimitError` gains an optional reason, `"daily" | "source"`. The agent-facing over-limit message for `"source"` says: "Agents from this address have used their share of today's Starter allowance. Try again tomorrow (UTC), or sign in to a Clockchain account." Find the current message for `"daily"` and keep it unchanged.
- **Privacy:** `source` never appears in the `/agent-keys/<fp>.json` lookup, in any ledger filing payload, in logs or in tool results. The lookup view is already a whitelist, so keep it one.

**Files:**
- `src/agent-keys/book.ts`
- `src/agent-keys/filing.ts`
- `src/shadow/ledger.ts` (`StarterLimitError`)
- `src/shadow/service.ts`
- `src/oauth.ts`
- `infra/clockchain-mcp/RUNBOOK.md`
- tests: `test/agent-keys-book.test.mjs`, `test/agent-keys-filing.test.mjs`, `test/oauth-agent-keys.test.mjs`, and an end-to-end case in the suite that already boots HTTP with agent keys

**Steps:**
- [ ] Unit tests (book): `admit` stores `source`; a known key keeps its first `source`; a bad `source` on disk makes the entry invalid; old entries without one load.
- [ ] Unit tests (counter):
  - the per-source cap refuses at 200 while another source still passes;
  - the global cap still refuses;
  - a new day resets both;
  - an old-format file loads;
  - an unreadable file still fails closed.
- [ ] Grant test: two keys admitted from the same address share one `source`, and a different address gets a different one. The stored value is 32 hex characters and isn't the address.
- [ ] Privacy test: the lookup body and the filing payload for a key with `source` contain neither the `source` value nor the `source` field.
- [ ] End-to-end: with `SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY=2`, two agents from one address are refused on their third anchor in total, with the `"source"` message. An agent from another address still anchors.
- [ ] Implement, run the full test command, and commit as "Give each address a share of the Starter allowance".

### Task 3: Prove old records survive the key switch and the rollback

**Why:** turning on Clockchain's key deletes each account's old signing key (ruling 15), and rolling back creates new keys while keeping account IDs (ruling 16). The founder asked us to "prove that pre-switch records still verify after both the switch and the rollback" before existing accounts are involved.

**Files:** `test/shadow-witness.test.mjs`. Follow its existing helpers. This is a test-only task, unless the test exposes a bug.

- [ ] One test, on a single state directory:
  1. **Without a witness key:** an account owner records two steps and closes session A. Keep its packet and pin, and check that `verifyPacket` passes.
  2. **Restart with a witness key on the same directory:**
     - the owner's `key.json` is gone and its operator id is unchanged;
     - session A's packet (fetched again from the service) still verifies against its original pin;
     - its viewer page still shows the legacy text;
     - a new session B is witnessed and verifies.
  3. **Restart again without the witness key (rollback):**
     - A and B both still verify against their pins;
     - the operator id is still the same;
     - a new session C verifies under the newly created per-account key.
- [ ] If any step fails because of a product bug, stop. Report it as DONE_WITH_CONCERNS with the failing step; don't fix it inside this task.
- [ ] Run the full test command. Commit as "Prove records verify across the witness switch and rollback".

### Task 4: A repeated signature returns the original result

**Why:** at present, if an agent's `shadow_sign_checkpoint` succeeds but the reply is lost, the retry finds no checkpoint waiting and returns `hash_mismatch` (deferred item D6). The founder wants this fixed before any unattended pilot.

**Files:**
- `src/shadow/service.ts` (`signCheckpoint`)
- `test/shadow-agent-sign.test.mjs`

**Design:**
- Inside the session lock, before the "nothing waiting" refusal: if nothing is waiting, but the session's latest `meta.checkpoint` has the same `hash`, the same `signature` and the same `publicKey` as this call, then it's a retry. Don't write anything or queue anything, set `made.target` to that hash, and fall through to the existing drain and the existing reply.
- Anything else keeps today's behaviour, including:
  - the same hash with a different signature;
  - an older checkpoint's hash;
  - a key that is no longer active, since the key check before the lock stays as it is.

**Steps:**
- [ ] Tests:
  - signing a checkpoint, then sending the identical call again, returns the same `checkpoint` view (same ledger id or pending state), and `anchors_today` doesn't change;
  - the same for the final checkpoint after close, where the retry also returns the same `pin`;
  - the same hash with a different valid-format signature still gets `hash_mismatch`;
  - a retry after the key is cancelled is still refused.
- [ ] Implement, run the full test command, and commit as "Return the original result when an agent resends the same signature".
