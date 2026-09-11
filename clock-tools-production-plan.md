# Clock tools → production: stopwatch, timer, alarm as MCP-offered tools

Plan of record for taking the three verified-time primitives from "SDK examples that
worked in June" to **products offered through the hosted MCP**, plus the matching update to
the MCP page. Written 2026-09-10 from the gate results in
[`packages/clock-sdk/GATES.md`](packages/clock-sdk/GATES.md) and the Sep 10 product meeting
(action items *Test Agent Tools*, *Prepare Timer Agenda*; decision *scheduler supplies time
via MCP, execution stays on the local harness*).

## 1. Where we are (measured today, hosted MCP)

| Primitive | Works? | Offered via MCP today? | Blocking issue |
|---|---|---|---|
| **Stopwatch** | Yes — SDK (G1) and hosted `stopwatch_*` (G1b), elapsed re-verified from block times | **Yes** (since #98) | — |
| **Timer** | Yes — SDK (G2) and hosted `timer_set` (G2b, +922 ms on a 1 s tick), anchored, verified | **Yes** (since #104, 2026-09-11) | — |
| **Alarm** | Yes — SDK soft + confirmed (G3a/G3b) and hosted `alarm_set` (G3c), anchored, verified | **Yes** (since #104) | webhooks off until C6; `confirmed` variant of the hosted alarm is a follow-up |

Three root causes, three different owners:

1. **Code bug (ours, 1 line):** the gateway renamed `nodeParticipation%` → `nodeParticipation`;
   `core.getPoolHealth()` reads the old key, computes 0 %, and the MCP refuses every default
   write as "degraded". Every user hitting `log_action`/`attest_action` today gets this.
2. **Architecture (ours, real work):** timer/alarm need something always-on to hold the
   schedule and fire. The hosted MCP has no scheduler; `packages/keeper` is that component
   (control-plane tools `keeper_schedule/list/cancel` + a dispatch worker) and is built and
   unit-tested but **not mounted on the deployment**.
3. **Time source (ours — corrected 2026-09-11):** production's `CLOCKCHAIN_ENDPOINT` is the
   owned anchoring gateway container (`infra/anchoring-gateway/gateway.mjs`), because
   `node.clockchain.network` is unowned and down. `gateway.mjs` seals a block synchronously
   inside each `/log` and reports the last sealed block's time as `madMarzulloTime`. So "now"
   is as stale as the last write: 86 s observed after an idle window, reported as ±51 ms.
   Confirmed-mode alarms wait for a block that nothing will seal. This is a change to
   `gateway.mjs`, not a network-team dependency. (The June live-oracle fields came from the
   real network; the key rename is ours too.)

## Status — 2026-09-11: production ready on the stated definition

| Criterion | Stopwatch | Timer | Alarm |
|---|---|---|---|
| Gates green in prod | ✅ G1, G1b | ✅ G2, G2b | ✅ G3a, G3b, G3c |
| Offered as MCP tools | ✅ `stopwatch_*` | ✅ `timer_set` | ✅ `alarm_set` |
| Honest claims | ✅ substrate in receipts + page | ✅ | ✅ |
| Truthful anchoring | ✅ | ✅ | ✅ |
| Operable | ✅ deploy-box.sh, nightly gates, bounds | ✅ | ✅ |
| Driven by Clark (Hermes + Nova, its own box) | ✅ 4734 ms verified | ✅ fired, block 636 | ✅ set → listed → cancelled |
| Fresh Claude Code (Opus/Sonnet/Haiku) + Codex on a demo token, no account | ✅ 4 agents verified | ✅ 4 fires, blocks 718–740 | ✅ 4 cancels |
| The developer's own Hermes on this Mac (full 24-task suite) | ✅ | ✅ | ✅ 24 / 24 |

Clark's full-surface run (2026-09-11 05:28 UTC): **24 / 24 tasks, all 40 single-agent-testable
tools exercised, verdict PASS** — `eval/reports/2026-09-11T05-27-49-287Z-hermes:clockchain-eval@…md`.
Its first run (18 / 24) found that Hermes + Nova empty every free-form object argument; fixed in
PR #109 (object args accept `object | JSON string`) and deployed before the passing run.

Anyone with Claude Code or Codex can use the three tools with nothing but a demo token
(2026-09-11 06:09 UTC): five fresh agents, 4 / 4 clock tasks each — see GATES.md. That check
found the last blocker: the rate limit could 429 the MCP handshake itself; fixed in PR #111.

Still open, by choice: per-owner billing (needs gateway sub-keys); a `confirmed`-mode variant of
the hosted alarm; the real network (`node.clockchain.network`) coming back — re-run G0–G4 against
it before repointing production.

## 2. What "production ready" means here

A tool is production-ready when all of the following hold on the deployed endpoint:

- **Gates green:** G0–G4 pass on `mcp.clockchain.network` (live suite), unit gates in CI.
- **Offered, not just possible:** it is a first-class MCP tool with a typed schema, listed on
  the page, in `llms.txt`, the manifest, and the dashboard catalog — no SDK build required.
- **Honest claims:** every receipt still says `single-validator-testnet`; the page says
  *testnet* and *keyless, self-verifying on integrity* — not "trustless"/"court-grade".
- **Truthful anchoring preserved:** a fire/marker is never reported success without a block
  height; degraded pools refuse (once the guard reads the right key).
- **Operable:** rate-limit and credit budgets per token, evidence in CI logs, a canary that
  runs the live gates on a schedule and alerts on red.

## 3. Decisions needed Monday (Sep 14)

| # | Decision | Recommendation | Why |
|---|---|---|---|
| D1 | Ship timer/alarm as MCP tools via the **keeper** (server-side firing) vs. SDK-only | **Keeper — done.** `timer_set` / `alarm_set` on the hosted surface, loop in the MCP process. SDK stays for users who want firing inside their own boundary. | "Offered via the MCP" is not true while the user must build an npm workspace. |
| D2 | Fire notification: webhook, poll, or both | **Poll now, webhook when hardened.** `timer_status` returns the fire and its receipt; `webhook_url` is accepted by the schema but refused until `KEEPER_WEBHOOK_SECRET` + allow-list are configured (C6). | Server-side POSTs to arbitrary URLs are the abuse surface; polling needs no inbound URL. |
| D3 | How to keep consensus time fresh on a seal-on-write gateway | **Done (PR #100, deployed):** read-triggered heartbeat in `gateway.mjs` — every reading is still a real sealed block, readers never see a stale "now", an unread ledger stays quiet. G3b and G4 green in production. Monday: confirm this is the semantics we want to keep (vs. a live clock in `/getTime`), see D7. | The oracle is our own service, so this was a PR, not a network ask. |
| D4 | Default alarm mode offered on the MCP | **`confirmed`** — D3 has landed and G3b passes in production. | Confirmed is the product claim ("fires only after consensus crossed T"). |
| D5 | Uncertainty reporting | **Done.** `uncertaintyMs` = rtt/2 + reported spread + `|wall − consensus|` at sync; `skewMs` exposed. | "No false precision" is a README promise; G4 showed we broke it. |
| D6 | Page positioning | Add a seventh module **"Verified time tools"** (stopwatch / timer / alarm) with beta labels until Phase 2 ships; copy in §6. **Done, live.** | Meta tag already says seven modules; the page says six. |
| D7 | Honesty of "anchored on Clockchain" while the network is down | **Done.** Receipts carry `attestation.substrate` (`anchoring-gateway` on the box, from `CLOCKCHAIN_SUBSTRATE`) with substrate-specific note + disclaimer ("owned, single-operator … not yet attested by an independent validator set"); the page's disclaimer and module 07 name the same substrate. `status` stays `single-validator-testnet` for existing consumers. | The gates proved the mechanics; the claim now matches the substrate. |
| D8 | Make `main` == production | **Done.** Gateway wiring committed to `compose-up.sh` / `docker-compose.yml` with the deploy-assets fixture proving the env; RUNBOOK documents the gateway container and its SSM secret; Cloud Run `deploy.yml` is manual-only ("legacy standby"); `scripts/deploy-box.sh <sha>` is the one-command deploy that refuses a dirty box; nightly `clock-gates` job on `eval-nightly.yml` uploads evidence and opens an issue on red. | The 2026-09-11 deploy nearly reverted production's gateway wiring because it lived only on the box. |

## 4. Workstreams and steps

Owners: **MCP/SDK** = Yang; **network/gateway** = Rakesh to route (Lakesh, Satish, Himant per
Sep 10 notes); **product/demo** = Mimmo. Dates assume the Sep 14 decisions.

### WS-A — Unblock writes and tell the truth (by Mon Sep 14)

| Step | What | Verify |
|---|---|---|
| A1 | **Done on branch.** `core.getPoolHealth()` reads `nodeParticipation%` **or** `nodeParticipation`; *neither* present → throws "not reported", so the MCP guard fails open and receipts stay `pending` (never a silent 0 %) | core + MCP-layer tests with both payload shapes (5 guard tests); **G0.4 green** on the next deploy |
| A2 | **Done on branch.** Same fallback in `examples/try-alarm-mcp.sh` | script runs without the degraded banner on a 100 % pool |
| A3 | **Done on branch.** Doc truth: `time.ts` header, `clock-sdk/README.md`, the alarm skill (format, key, mint-on-write note, stopwatch tools, adapter), `README.md` / `INSTALL.md` / `QUICKSTART.md` / `roadmap.md` (31 → 45 tools, seven modules, new limitation row) | `npm run check:skill` passes; old key appears only as the documented fallback |
| A4 | Land the gate suite (`GATES.md`, `timer.test.mjs`, `gates-live.test.mjs`, `mcp-adapter.mjs`) on `main` behind the existing test gate; live suite stays opt-in. **PR open from `claude/clock-primitive-gates`.** | `npm test` green; `deploy.yml` unchanged |
| A5 | Present gate results + D1–D6 at Monday's timer/alarm agenda | this doc + `GATES.md` run table |

### WS-B — Stopwatch as MCP tools (week of Sep 14)

The stopwatch needs no scheduler, so it can be a first-class tool immediately and stay inside
the trust model (the server holds no state between calls).

| Step | What | Verify |
|---|---|---|
| B1 | **Done on branch.** `stopwatch_start {label}` → anchors `stopwatch:<label>:start`, waits for the block, returns the marker; `status` is truthful (`pending` + warning if no block) | `mcp-server/test/stopwatch-tools.test.mjs`; classified `FREE_TOOLS` |
| B2 | **Done on branch.** `stopwatch_stop {label, start_ledger_id}` — the server **re-reads the start marker from the ledger** (a caller cannot hand in a fabricated start time) and checks its reference id; returns both markers + `elapsedMs`; `anchored` only when both markers have a block. Implemented on `ClockchainClient` directly because the container image ships only core + mcp-server | unit: elapsed 6159 ms from two known timestamps, wrong-ledger rejection, pending-start handling; live: **G1b** (skips until deployed) |
| B3 | **Done on branch.** `stopwatch_verify {start_ledger_id, stop_ledger_id}` → both markers against the immutable blocks (keyless) **and `elapsedOnChainMs` recomputed from the two block times**, plus the advisory ledger-recorded elapsed for comparison | unit: verified + 6159 ms from block times, no api key on chain reads, unverified when a marker is missing |
| B4 | **Done on branch** except the research dashboard catalog (separate repo, `clockchain-research-ws5/src/lib/dashboard-tools.ts`). Page counts derive from the registered surface (42 → 45 automatically); README / INSTALL / QUICKSTART list the tools | landing tests assert page = `tools/list`; coverage + surface tests at 45 |
| B5 | **Done on branch.** `stopwatch` eval task (start → wait → stop → verify; pass = `stopwatch_verify.verified === true`); `stopwatch_start/stop` added to the eval's write-tool set | runs in the existing nightly eval |

### WS-C — Timer & alarm via the hosted keeper (weeks of Sep 14 – Sep 28)

| Step | What | Verify |
|---|---|---|
| C1 | **Done on branch.** `timer_set` / `alarm_set` / `timer_status` / `timer_cancel` / `timer_list` on the hosted surface (50 tools), classified `KEEPER_TOOLS` (anonymous trial tokens get the structured 402). Owner = the transport-resolved caller id; another caller gets 404. Bounds: delay 1 s–30 d, interval ≥ 60 s, per-owner cap 100 | `mcp-server/test/timer-tools.test.mjs` (11 tests, real Keeper + memory store); coverage/surface at 50 |
| C2 | **Done on branch — changed shape.** The keeper loop runs **inside the MCP process** (`keeper-runtime.ts`: one per box, non-blocking boot, clock disciplined before any fire, background resync) with the file store on the `mcp_state` volume (`KEEPER_STORE_PATH=/app/state/keeper-store.json`). No second service, route, or secret; the image now ships `clock-sdk` + `keeper`. DB store + leasing stay deferred (single box) | keeper re-arm-on-boot test; deploy-assets fixture asserts the store path |
| C3 | **Done (#100, gateway-side).** The read-triggered heartbeat in `gateway.mjs` replaced the planned keeper heartbeat | G3b and G4 green in production |
| C4 | **Done on branch (soft semantics).** Never early, one-shot never re-fires, a past `fire_at` fires once with a warning and the original target recorded, dead-letter on webhook exhaustion, **not done until anchored**. The keeper fires on its disciplined clock with a 1 s tick (no boundary re-read); with the heartbeat gateway that is within 2 s of consensus. A `confirmed` variant is a follow-up | **G2b / G3c live gates** (local 12/12); `timer-tools.test.mjs` |
| C5 | **Partial (bounded, not billed).** Self-serve v1 demo tokens are *authenticated* under LLD §13 and can set timers (Mimmo's pilot ask); only v2 trial tokens hit the 402. Bounds: 30 req/min/token, 10 mints/h/IP, ≤ 20 live triggers per owner, intervals ≥ 60 s, ≤ 10 fires/tick globally (≤ 600 credits/min), 30-day horizon, shared `MCP_LOG_BUDGET` as the hard stop, nightly gates as the alarm. Per-`sub` billing needs gateway sub-keys — deferred | `keeper-runtime.ts` DEFAULTS + `budgeted()` |
| C6 | **Done.** Webhook delivery is on: `KEEPER_WEBHOOK_SECRET` in SSM, `KEEPER_WEBHOOK_ALLOWLIST=hooks.slack.com,webhook.site` (deny-by-default, extend in `compose-up.sh`), every delivery **DNS-pinned** (resolve → range-check every address → connect to the vetted address, hostname kept for TLS; redirects never followed), and **per-owner secrets** derived from the server secret and shown at registration so receivers verify without a shared key | `keeper/test/webhook.test.mjs` (rebinding refused, pinned connect against a local server, derived secrets); `timer-tools.test.mjs` |
| C7 | **Done (D5).** `ClockchainClock.sync()` adds the consensus-vs-wall skew to `uncertaintyMs` and exposes `SyncResult.skewMs` — a 90 s-stale reading now reports ±90 s, not ±20 ms | `clock.test.mjs` D5 case; README "No false precision" |
| C8 | Retire the `clark-slack-alarm.mjs` daemon example in favour of `alarm_set` + webhook; keep `alarm-live.mjs` as the SDK reference | skill drift check passes |

### WS-D — Time-source work (ours) and the real network

Corrected 2026-09-11: N1–N3 turned out to be properties of our own anchoring gateway.

| Item | What | Owner |
|---|---|---|
| N1 | **Done and deployed (PR #100, 2026-09-11 01:02 UTC).** `gateway.mjs`: read-triggered heartbeat — a `/getTime` older than `GATEWAY_HEARTBEAT_MS` (2 s) seals an empty block first. **Production gates 10/10**: confirmed alarm fires (117 ms late), freshness drift −7 ms. | MCP/SDK |
| N2 | `gateway.mjs` response shape: keep `nodeParticipation`, also emit `nodeParticipation%` for one release, and version the payload so the next rename doesn't refuse writes again | MCP/SDK |
| N3 | Commit the on-box wiring; retire/repoint Cloud Run deploy (D8) | MCP/SDK |
| N4 | The real network: when `node.clockchain.network` returns, re-run G0–G4 against it before pointing production back; multi-validator timeline gates "court-grade" wording | network team via Rakesh |

### WS-E — Operate it (with WS-B, hardened in WS-C)

| Step | What |
|---|---|
| E1 | **Done.** `clock-gates` job on `eval-nightly.yml` runs the live gates nightly with `MCP_EVAL_TOKEN`, uploads evidence (30 days), opens/updates "Nightly clock gates red on production" on failure |
| E2 | **Done.** `scripts/deploy-box.sh` ends with the runbook canaries and gates `G0.*` (≈1 credit) when `CC_MCP_TOKEN` is set |
| E3 | Status dashboard shows stopwatch/timer/alarm availability from E1's last run |

## 5. Sequence and dates

```
Thu Sep 10  gates drafted + run (done)            ── GATES.md
Thu Sep 11  #98 #99 #100 merged + deployed (done)  ── guard fix, stopwatch tools, page, heartbeat gateway; prod gates 10/10
Thu Sep 11  #102 D8 (done)                          ── main == production; box checkout clean; deploy-box.sh (36 s restart); nightly gates armed
Thu Sep 11  #104 WS-C (done)                        ── hosted timer/alarm live (timer_set / alarm_set / timer_status); prod gates 12/12
Thu Sep 11  #106 finish (done)                      ── D5 skew-aware uncertainty, D7 honest substrate, C6 DNS-pinned webhooks + per-owner secrets, try-it script; prod 12/12 + webhook proof
Mon Sep 14  Monday meeting: results, D1–D6, N1–N4  ── WS-A landed on main (G0.4 green after deploy)
Wed Sep 17  handshake demo target (unchanged)       ── stopwatch tools + page v1 live (WS-B, in the same PR as WS-A)
Fri Sep 19  keeper worker deployed w/ heartbeat     ── C1–C4; G3b/G4 green; page update v2 (timer/alarm live, beta)
Fri Sep 26  budgets, SSRF pinning, nightly canary   ── C5–C7, WS-E; drop beta labels
Sep 28+     network items (N1–N4) as they land      ── remove heartbeat when cadence is native
```

## 6. MCP page update (the "products offered" fix)

Surfaces that must change together (all currently say "42 tools" and/or "six modules"):
`packages/mcp-server/src/landing.ts` (`MODULES`, hero, `<meta>`, `INSTALL_TXT`,
`MCP_MANIFEST.description`), `server.json`, `README.md`, `INSTALL.md`, `roadmap.md` (31 tools),
`llms.txt` (served from `landing.ts`), and the research dashboard catalog
(`clockchain-research-ws5/src/lib/dashboard-tools.ts`).

**v1 — done on branch `claude/clock-primitive-gates`, ships with WS-A (truthful today):**

- Module 07 added as a full-width card:
  > **07 · Verified time tools** — Stopwatch, timer, alarm on consensus time — elapsed time
  > between two anchored markers, and fires that land on verified time, never early, each
  > anchored as a keyless-verifiable receipt. Open clock SDK today; hosted tools in beta next.
- The live page was contradicting itself: hero/meta said "42 tools, seven modules", the
  stat strip said **31 / 6**, the section header said "Six". All counts are now derived from
  code (`TOOL_COUNT = CLASSIFIED_TOOLS.size`, `MODULE_COUNT = MODULES.length`) and
  `landing.test.mjs` asserts the page equals the registered `tools/list` count, so B1–B3 and
  C1 update the page automatically. Remaining stale literals live outside the page:
  `INSTALL.md` and `roadmap.md` (31), `README.md` (A3).

**v2 (ships with WS-C):** module 07 body becomes

> *Stopwatch* (`stopwatch_start/stop/verify`), *timer* (`timer_set`), *alarm* (`alarm_set`,
> confirmed mode) — hosted, fire while your client is offline, webhook or poll, every fire
> anchored and keyless-verifiable. Testnet, single validator.

Also add a **"Try it"** line under the demo video: the zero-creds stopwatch (two tool calls)
replaces `try-alarm-mcp.sh` as the 30-second first experience.

## 7. Risks

- **Deploy pipeline is misleading:** `deploy.yml` deploys to Cloud Run, which nothing points
  at; production is the AWS box via SSM and its wiring is not in git (D8). Until fixed, every
  deploy is a manual runbook step and a green Action means nothing.
- **Rate limit (30 req/min/token)** is too low for a confirmed alarm that polls at the
  boundary plus an agent doing other work; move the keeper's own reads to an internal path
  (no token limit) and give scheduled-tool users a higher tier.
- **Keeper is single-process:** no trigger leasing → exactly one worker instance until the
  DB store + lease land (C2). Cloud Run `max-instances 1`.
- **Gateway drift will happen again** (N3): the live gates are the early warning — keep E1.

## 8. Out of scope

`create_schedule`/`estimate_schedule`/`list_schedules` (on-chain contract scheduler, preview
pending the protocol team's signing spec), multi-validator consensus, and the handshake
product surface.
