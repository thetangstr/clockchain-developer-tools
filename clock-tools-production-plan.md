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
| **Stopwatch** | Yes — 6.16 s measured vs 6.08 s wall, both markers keyless-verified | Only as a *pattern* (`log_action` ×2 + `verify_cross_party`); no `stopwatch_*` tool | G0.4 guard bug refuses default writes |
| **Timer** | Yes (soft) — fired 1.2 ms late, anchored, verified | No — needs the client-side SDK (`ClockScheduler`) | G0.4; absolute time inherits chain idleness (G4) |
| **Alarm** | Mechanically yes (soft); **no** in confirmed mode | No — SDK, or the unshipped keeper | G0.4; confirmed mode deadlocks on an idle chain (G3b); absolute time stale (G4) |

Three root causes, three different owners:

1. **Code bug (ours, 1 line):** the gateway renamed `nodeParticipation%` → `nodeParticipation`;
   `core.getPoolHealth()` reads the old key, computes 0 %, and the MCP refuses every default
   write as "degraded". Every user hitting `log_action`/`attest_action` today gets this.
2. **Architecture (ours, real work):** timer/alarm need something always-on to hold the
   schedule and fire. The hosted MCP has no scheduler; `packages/keeper` is that component
   (control-plane tools `keeper_schedule/list/cancel` + a dispatch worker) and is built and
   unit-tested but **not mounted on the deployment**.
3. **Network (external):** the testnet mints a block **only when something is written**, and
   `/getTime` now returns the last block's time as "consensus now" (in June it carried live
   oracle fields — `AbsTimeDifference`, `systemTime`, `consentedOffset`; today
   `madMarzulloTime === latestBlockTime`). So "now" is as stale as the last write: 86 s
   observed after an idle window, reported as ±51 ms. Confirmed-mode alarms wait for a block
   that nothing will mint.

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
| D1 | Ship timer/alarm as MCP tools via the **keeper** (server-side firing) vs. SDK-only | **Keeper.** It is exactly the meeting's split: keeper = timing + notification, harness = job. SDK stays for users who want firing inside their own boundary. | "Offered via the MCP" is not true while the user must build an npm workspace. |
| D2 | Fire notification: webhook, poll, or both | **Both.** `keeper_schedule` takes an optional `webhook_url`; without one, the fire still anchors and `keeper_list` / `timer_status` returns the receipt. | Most agent harnesses can poll; few have an inbound URL. |
| D3 | How to keep consensus time fresh on a mint-on-write chain | **Interim (ours): keeper heartbeat** — the always-on worker anchors one heartbeat every N s (N = 10 s proposed), which mints a block and keeps `/getTime` within N s of real time for everyone. **Real fix (network):** periodic block production or a live time oracle in `/getTime`. | Unblocks G3b and bounds G4 to ≤ N s without waiting on the network team; cost ≈ 8.6 k credits/day on the ops key (Clark is unlimited). |
| D4 | Default alarm mode offered on the MCP | **`confirmed`** once D3 heartbeat lands; `soft` until then, labelled. | Confirmed is the product claim ("fires only after consensus crossed T"); it just needs cadence. |
| D5 | Uncertainty reporting | Widen `uncertaintyMs` by measured consensus staleness (`|wall − consensus|` at sync, and time since last block) and surface it in receipts. | "No false precision" is a README promise; G4 shows we break it today. |
| D6 | Page positioning | Add a seventh module **"Verified time tools"** (stopwatch / timer / alarm) with beta labels until Phase 2 ships; copy in §6. | Meta tag already says seven modules; the page says six. |

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
| C1 | Mount `registerKeeperTools` on the hosted MCP; surface as `alarm_set {fire_at}`, `timer_set {delay_ms}` (both thin wrappers over `keeper_schedule`), `timer_status`, `timer_cancel`, `timer_list`. Each must be added to `KEEPER_TOOLS` in `entitlement.ts` (account-gated "continuity" class; the boot-time `assertToolClassified` fails otherwise) — anonymous trial tokens get the structured 402, so server-side firing is never free-tier | tools/list shows them; 402 for anonymous tokens; boot passes classification |
| C2 | Deploy the keeper worker as its own always-on Cloud Run service (min-instances 1, not scale-to-zero) with the file store on a persistent volume → **SQLite/DB store** before multi-instance (deferred-scope item in `keeper/README.md`) | worker health endpoint; a trigger survives a restart (re-arm test already exists) |
| C3 | **Heartbeat** (D3): worker anchors `keeper:heartbeat` every N s when no other write landed in the last N s | G0.6 staleness ≤ N s across a 5-min idle window; **G3b and G4 green** |
| C4 | Fire semantics = the SDK's: never early, `confirmed` re-reads consensus at the boundary, one-shot never re-fires, missed triggers fire once with the original target recorded, dead-letter on webhook exhaustion, **not done until anchored** | reuse `timer.test.mjs` semantics against the keeper's `nextIntervalSlot`/fire loop; live G2/G3 re-pointed at the tools |
| C5 | Per-`sub` credit budget and rate tier for keeper writes (today all fires bill the delegated key) | budget test; a token cannot exceed `MCP_LOG_BUDGET` share |
| C6 | Webhook path hardening before public use: `KEEPER_WEBHOOK_ALLOWLIST` mandatory, DNS-pinned SSRF guard (deferred-scope item) | `ssrf.test.mjs` extended with rebind case |
| C7 | SDK: `ClockchainClock.sync()` widens `uncertaintyMs` by measured staleness (D5); receipts carry it | unit test: stale reading → band grows; G4 evidence shows the claimed band covers the drift |
| C8 | Retire the `clark-slack-alarm.mjs` daemon example in favour of `alarm_set` + webhook; keep `alarm-live.mjs` as the SDK reference | skill drift check passes |

### WS-D — Network dependencies (raise Monday, track weekly)

| Item | Ask | Owner |
|---|---|---|
| N1 | Did `/getTime` change from live Marzullo time to last-block time? If intentional, expose a live consensus clock field; if not, restore | gateway team via Rakesh |
| N2 | Periodic block production (or accept our heartbeat as the interim) | network team |
| N3 | Key rename policy: field renames (`nodeParticipation%`) broke every client silently — ask for versioned responses or a changelog | gateway team |
| N4 | Multi-validator testnet timeline (gates "court-grade" wording; unchanged from `roadmap.md`) | network team |

### WS-E — Operate it (with WS-B, hardened in WS-C)

| Step | What |
|---|---|
| E1 | Add a job to the existing `eval-nightly.yml` (it already has `MCP_EVAL_TOKEN`) that runs the live gates with `CC_MCP_TOKEN=${{ secrets.MCP_EVAL_TOKEN }}`, uploads the evidence JSON as an artifact, opens/updates an issue on red |
| E2 | Post-deploy smoke: `G0.1`–`G0.5` only (≈1 credit) as the last step of `deploy.yml` after Cloud Run goes healthy; full suite stays scheduled to keep the deploy gate credit-free |
| E3 | Status dashboard shows stopwatch/timer/alarm availability from E1's last run |

## 5. Sequence and dates

```
Thu Sep 10  gates drafted + run (done)            ── GATES.md
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

- **Heartbeat credits and noise:** 8.6 k heartbeat anchors/day on the ops key inflate log
  counts (the team tracks "1,295 events" as a KPI). Tag them `keeper:heartbeat` and exclude in
  dashboards; drop when N2 lands.
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
