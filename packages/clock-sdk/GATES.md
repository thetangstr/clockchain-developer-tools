# Clock-primitive gates — alarm, stopwatch, timer on the hosted MCP

Acceptance gates for the three `@clockchain/clock-sdk` primitives running against the
**deployed** MCP (`https://mcp.clockchain.network/mcp`, Cloud Run, full tool surface).
Drafted 2026-09-10 for the action item *"Test Agent Tools: verify that the timer, alarm,
and stopwatch functions work correctly in the current deployment"* (Clockchain AI Product
Meeting, 2026-09-10) and the Monday timer/alarm agenda.

Each gate is a short list of pass criteria. Every criterion maps 1:1 to an assertion in
a test file so "the gate passed" is a test run, not a judgement call:

| Gate | What it proves | Test file | Cost |
|---|---|---|---|
| **G0 — MCP surface** | the deployment still exposes what the primitives need, and time/pool signals parse | `test/gates-live.test.mjs` | 1 log credit (guard probe) |
| **G1 / G1b — Stopwatch** | tamper-evident *elapsed* time between two anchored markers, keyless-verifiable — via the SDK (G1) and via the `stopwatch_*` MCP tools (G1b) | `test/gates-live.test.mjs` + `test/stopwatch.test.mjs` + `mcp-server/test/stopwatch-tools.test.mjs` | 2 + 2 log credits |
| **G2 / G2b — Timer** | a one-shot fires after duration *D* on the disciplined clock, never early, anchored — via the SDK (G2) and via the hosted `timer_set` tool while the client only polls (G2b) | `test/gates-live.test.mjs` + `test/timer.test.mjs` + `mcp-server/test/timer-tools.test.mjs` | 1 + 1 log credits |
| **G3a — Alarm (soft)** | a one-shot fires at absolute time *T* on the disciplined clock, once, anchored | `test/gates-live.test.mjs` + `test/timer.test.mjs` (alarm semantics) | 1 log credit |
| **G3b — Alarm (confirmed)** | same, but fires only once consensus itself has crossed *T* | `test/gates-live.test.mjs` | 1 log credit |
| **G3c — Alarm (hosted)** | `alarm_set` at absolute *T* fires once after *T* on consensus time while the client only polls, anchored | `test/gates-live.test.mjs` + `mcp-server/test/timer-tools.test.mjs` | 1 log credit |
| **G4 — Consensus freshness** | after an idle window, the disciplined clock's fire time still agrees with the block that anchored it (no false precision) | `test/gates-live.test.mjs` | 1 log credit |

Two layers, on purpose:

- **Unit gates** (offline, deterministic, run in `npm test`): fake clock + fake timer +
  mock client. Prove the *semantics* (never-early, once-only, cancel, confirmed-hold,
  missed-alarm handling). Free, sub-second, run on every push.
- **Live gates** (opt-in, spend testnet credits): the real SDK classes driven by the hosted
  MCP through a thin JSON-RPC adapter (`examples/mcp-adapter.mjs`), so the code path
  under test is `ClockchainClock` → `ClockScheduler` → `timer()` / `stopwatchStart()` →
  MCP `get_timestamp` / `attest_action` / `log_action` → `verify_cross_party`. This is what
  "working on the MCP" means; the shell example `examples/try-alarm-mcp.sh` only exercises
  the raw tools, not the SDK.

## Running

```bash
# unit gates (always on)
npm test -w @clockchain/clock-sdk

# live gates against the hosted deployment (opt-in; spends ~7 testnet log credits, ~3 min)
export CC_MCP_TOKEN=<your x-api-key token>          # from: curl -X POST https://mcp.clockchain.network/token
npm run test:gates -w @clockchain/clock-sdk

# one gate only (G0.4 will not have run, so tell the writes to bypass the guard yourself)
CC_LIVE_GATES=1 CC_ALLOW_DEGRADED=1 node --test --test-name-pattern 'G3a' packages/clock-sdk/test/gates-live.test.mjs
```

Live-gate knobs (all optional):

| Var | Default | Meaning |
|---|---|---|
| `CC_LIVE_GATES` | unset | `1` enables the live gates; otherwise they are reported as skipped. |
| `CC_MCP_URL` | `https://mcp.clockchain.network/mcp` | MCP endpoint (point at a local `MCP_TRANSPORT=http` server to gate a candidate build). |
| `CC_MCP_TOKEN` | unset | `x-api-key` token. Required when live gates are on (or `CC_MINT_DEMO_TOKEN=1` to mint one self-serve token and cache it at `CC_TOKEN_FILE`). |
| `CC_TIMER_MS` | `8000` | G2 timer duration *D*. |
| `CC_ALARM_MS` | `10000` | G3 alarm offset: *T* = consensus-now + this. |
| `CC_STOPWATCH_HOLD_MS` | `6000` | G1 hold between the two markers. |
| `CC_TOLERANCE_MS` | `5000` | Slack allowed on elapsed / fire-lateness comparisons. |
| `CC_CONFIRM_MS` | `45000` | Max wait for an anchor to land (block cadence + gateway lag). |
| `CC_IDLE_MS` | `20000` | G4: how long to stay idle (no writes) before syncing the freshness probe. |
| `CC_ALLOW_DEGRADED` | auto | `1` always pass `allow_degraded`, `0` never; unset = only when G0.4 detects the guard mis-reporting. |
| `CC_EVIDENCE_DIR` | unset | When set, each gate writes `<gate>.json` evidence (ledgerIds, block heights, timings) here. |

Every live gate also prints its evidence as `node --test` diagnostics, so a CI log is the
audit trail even without `CC_EVIDENCE_DIR`.

---

## G0 — MCP surface preconditions (shared by G1–G3)

**Purpose.** The primitives were validated in June against a gateway that has since changed
shape. G0 catches drift in the deployment *before* a primitive gate fails for an unrelated
reason, and names the root cause.

**Procedure.** Connect to `CC_MCP_URL` with `CC_MCP_TOKEN`; `tools/list`; `get_timestamp`;
one minimal `log_action` (the guard probe); `get_timestamp` again.

**Pass criteria.**

| # | Criterion | Why it matters |
|---|---|---|
| G0.1 | `tools/list` contains `get_time`, `get_timestamp`, `log_action`, `get_log_entry`, `attest_action`, `verify_cross_party`. | If the deployment is on the `MCP_SURFACE=product` slice (only `get_time`), *none* of the primitives can work. Fail message names the surface. |
| G0.2 | `get_timestamp.madMarzulloTime` parses to a finite epoch via `parseGatewayTime`, and `blockHeight` is a non-negative integer. | `ClockchainClock.sync()` throws on an unparseable time. The gateway now emits ISO 8601 (`2026-09-10T22:59:34.197Z`), not the documented `DD-MM-YYYY_HH:MM:SS:mmm`; the parser's ISO fallback must keep carrying this. |
| G0.3 | Pool participation, read from **either** `nodeParticipation%` **or** `nodeParticipation`, is `> 0` and `totalNodes ≥ 1`. | A genuinely degraded pool drops anchors; the gate must not proceed on one. |
| G0.4 | A default `log_action` (no `allow_degraded`) is **not** refused with the pool-degraded error while G0.3 says the pool is healthy. | Observed 2026-09-10: the gateway renamed `nodeParticipation%` → `nodeParticipation`; `core.getPoolHealth()` still reads the old key, computes `0` and refuses every write. If this fails, G1–G3 automatically pass `allow_degraded:true` and say so in evidence, so the rest of the flow is still exercised. |
| G0.5 | After the guard probe anchors, `get_timestamp.blockHeight` is strictly greater than before the probe. | Distinguishes "blocks mint on write" (fine) from "chain stalled" (every anchor will time out). Observed 2026-09-10: height 136 unchanged for 25+ minutes with no writes. |
| G0.6 | Consensus staleness `wallNow − consensusNow` is recorded as evidence (informational, not a fail). | Large staleness means `confirmed`-mode alarms hold until *something* mints a block — see G3 risk. |

**Evidence.** Tool list, both `get_timestamp` payloads, the probe's ledgerId/blockHeight,
staleness in ms, and `poolGuardMismatch: true|false`.

---

## G1 — Stopwatch

**Claim under test.** *Elapsed time between two points is bracketed by two independently
anchored consensus events, and a counterparty can re-verify both keylessly.*

**Code path.** `stopwatchStart(client, label)` → `stopwatchStop(client, handle)` →
`elapsed()` / `verificationRefs()`, where `client` is the MCP adapter implementing
`log()` (→ `log_action`) and `waitForConfirmation()` (→ `get_log_entry` polling). Then
`verify_cross_party` on each marker.

**Procedure.** Start marker; hold `CC_STOPWATCH_HOLD_MS`; stop marker; verify both.

**Pass criteria.**

| # | Criterion |
|---|---|
| G1.1 | Both markers confirm: `start.blockHeight` and `stop.blockHeight` are non-null within `CC_CONFIRM_MS`. A null height is a *failed anchor*, never "pending" (README rule). |
| G1.2 | Both `createdTimestamp`s parse (`epochMs` finite). *(Shape may have changed with the gateway; this is the check.)* |
| G1.3 | `elapsed(measurement) ≥ 0` and `Number(stop.blockHeight) ≥ Number(start.blockHeight)` — consensus ordering matches causal ordering. |
| G1.4 | `\|elapsed − wallElapsed\| ≤ CC_TOLERANCE_MS`, where `wallElapsed` is the local wall-clock gap between issuing the two `log_action` calls. The stopwatch must measure the *real* gap, not the confirmation lag. |
| G1.5 | `verify_cross_party(ledger_id, block_height)` for **each** marker returns `onChain.verifiedAgainst === "on-chain block"` and `onChain.anchoredHash` equals the marker's `assetHash`. |
| G1.6 | The two markers carry distinct `assetReferenceId`s (`stopwatch:<label>:start` / `:stop`) and distinct hashes (unit-tested; asserted live too). |

**Evidence.** Both ledgerIds, block heights, createdTimestamps, `elapsed`, `wallElapsed`,
both verify payloads.

### G1b — the same claim through the MCP tools

Once the deployment exposes `stopwatch_start` / `stopwatch_stop` / `stopwatch_verify`
(WS-B in the production plan), G1b runs the identical procedure through those tools
instead of the SDK; until then it reports itself skipped. Extra criterion: **G1b.5**
`stopwatch_verify.verified === true` and its `elapsedOnChainMs` (difference of the two
immutable block times) agrees with the ledger-recorded `elapsedMs` within `CC_TOLERANCE_MS`
— a counterparty can verify the *duration*, not just the two hashes.

**Known risks (2026-09-10).** G0.4 (guard refuses default writes); G0.5 (if blocks only
mint on write, each marker's confirmation depends on its own block — expected to work, but
`CC_CONFIRM_MS` must exceed block cadence).

---

## G2 — Timer

**Claim under test.** *A timer armed for duration D fires after D has elapsed on the
Clockchain-disciplined clock — never early — and the fire is anchored and verifiable.*

**Code path.** `new ClockchainClock(mcp)` → `sync()` → `new ClockScheduler({ clock,
client: mcp, confirmSource: mcp })` → `timer(scheduler, clock, D, action, { mode })` →
poll `getStatus(id)` → `verify_cross_party`.

**Procedure.** Sync; arm `timer()` with `D = CC_TIMER_MS` in `soft` mode (the timer's
contract is duration on the disciplined clock; the boundary re-confirm is G3's job); wait
up to `D + CC_CONFIRM_MS`.

**Pass criteria.**

| # | Criterion |
|---|---|
| G2.1 | `clock.sync()` succeeds; `uncertaintyMs` is finite and `< 5000` (a wildly uncertain clock is not a usable timer). |
| G2.2 | `getStatus(id).fireAt === syncedNow + D` exactly (unit-tested); live: `fireAt − clock.now().epochMs ≈ D` at arm time. |
| G2.3 | The job reaches `state === "fired"` with `fireCount === 1` within `D + CC_CONFIRM_MS`. |
| G2.4 | **Never early:** `ctx.firedAt ≥ fireAt`. |
| G2.5 | **Not late beyond tolerance:** `ctx.firedAt − fireAt ≤ CC_TOLERANCE_MS` (poll cadence + one RTT). |
| G2.6 | `status.receipt.status === "anchored"` and `receipt.anchor.blockHeight` non-null (the scheduler attests every fire via `attest_action`). |
| G2.7 | `verify_cross_party(receipt.anchor.ledgerId, blockHeight)` returns `onChain.verifiedAgainst === "on-chain block"` and `onChain.anchoredHash === receipt.eventHash`. |
| G2.8 | `receipt.payload.inputs.id === id` and `receipt.action === "scheduler.fire"` — the anchored event is *this* timer's fire. |

**Unit semantics (test/timer.test.mjs).** fireAt computed from the *disciplined* clock (not
`Date.now()`); duration 0 fires on the next tick, once; cancel by returned id prevents the
fire; options (`id`, `agentId`, `mode`) pass through; `confirmed` timers hold until consensus
crosses; the receipt is attached to status.

### G2b — the same claim through the hosted `timer_set` tool

The hosted keeper (`packages/keeper`, run inside the MCP process) holds the schedule and fires
while the caller is offline; the caller only polls `timer_status`. Criteria: **G2b.1** exactly
one fire, trigger `done`; **G2b.2** `fireAtMs === armedAtMs + D` on the keeper's disciplined
clock; **G2b.3** never early, lateness `≤ CC_TOLERANCE_MS` (the keeper ticks every 1 s);
**G2b.4** `delivery.status === "skipped"` (poll-only), `anchor.status === "anchored"`, the
persisted receipt rides along and `verify_cross_party` resolves it to the immutable block with
`anchoredHash === receipt.eventHash`; **G2b.5** the anchoring block's time is not before the
armed instant. Skipped (not failed) when the deployment lacks the tools or the token is
account-gated.

---

## G3 — Alarm

The alarm is `scheduler.schedule({ fireAt: T, mode })` — the same one-shot machinery as the
timer, but targeting an **absolute** consensus time. It is gated in both modes because they
fail for different reasons on today's testnet (see G4 and the findings log).

### G3a — soft mode

**Claim under test.** *An alarm armed for absolute time T fires once when the disciplined
clock reaches T, and the fire is anchored and verifiable.*

**Procedure.** Sync; `T = disciplinedNow + CC_ALARM_MS`; `schedule({ fireAt: T, mode: "soft" })`;
wait up to `CC_ALARM_MS + CC_CONFIRM_MS`.

| # | Criterion |
|---|---|
| G3a.1 | `state === "fired"`, `fireCount === 1`. |
| G3a.2 | **Never early:** `ctx.firedAt ≥ T`; lateness `≤ CC_TOLERANCE_MS`. |
| G3a.3 | Receipt `status === "anchored"`, non-null `blockHeight`; `verify_cross_party` → `"on-chain block"`, `anchoredHash === eventHash`; `payload.inputs.id` is this alarm. |
| G3a.4 | The anchoring block's `consensusTime` is `≥ T − uncertaintyMs − CC_TOLERANCE_MS` (the fire is itself a write, so its block is minted at/after T). |

### G3b — confirmed mode

**Claim under test.** *A confirmed alarm fires only after Clockchain consensus itself has
crossed T (not just the local estimate), fires exactly once, and the fire is anchored and
verifiable.*

**Procedure.** As G3a with `mode: "confirmed"` and `confirmSource` = MCP, so each boundary
check is a real `get_timestamp` (polled every 3 s to respect the 30 req/min token limit). On
hold-timeout the gate fails with the measured staleness of the last consensus read.

| # | Criterion |
|---|---|
| G3b.1 | `state === "fired"`, `fireCount === 1`, within the bound. |
| G3b.2 | **Never early on the disciplined clock:** `ctx.firedAt ≥ T`; lateness `≤ CC_TOLERANCE_MS + 3000` (one boundary poll). |
| G3b.3 | **Consensus crossed T:** the last `get_timestamp` reading recorded *before* the fire parses to `≥ T`. |
| G3b.4 | At least one boundary read happened after sync — confirmed mode actually re-read consensus. |
| G3b.5 | Receipt anchored + keyless-verified, `anchoredHash === eventHash`; anchoring block time `≥ T − uncertainty − tolerance`. |

**Unit semantics (test/timer.test.mjs).** Confirmed hold until consensus ≥ T with repeated
boundary reads; one-shot never re-fires; a *missed* alarm (T already past at arm time) fires
once on the next tick and reports the original target so lateness is observable; a cancelled
alarm never fires and anchors nothing; an action error is captured, not retried, not attested.

### G3c — hosted alarm (`alarm_set`)

As G2b with an absolute `fire_at` = consensus-now + `CC_ALARM_MS`. Criteria mirror G2b plus
**G3c.2** `fireAtMs === T` exactly. The hosted keeper fires on its disciplined clock (the SDK's
"soft" semantics, 1 s tick); with the gateway's read-triggered heartbeat the consensus time at
fire is within the heartbeat of real time, and the anchoring block is sealed at/after T.
Unit coverage (`mcp-server/test/timer-tools.test.mjs`): never early, once, past-T warning and
once-only catch-up, cancel anchors nothing, owner scoping (another caller gets 404), webhook
refused while delivery is not configured, clear error before the clock is disciplined.

**Known risk — confirmed-mode hold on a quiet chain.** Consensus time is the *latest
block's* time. If the testnet only mints a block when something is written, a confirmed
alarm sits in the fail-closed hold until consensus ≥ T, and consensus will not advance until
someone writes — the alarm's own fire is the write that would have advanced it. Outcomes:

- G3b passes → blocks advance on their own (or on unrelated traffic); confirmed mode is
  usable as shipped.
- G3b holds until timeout with staleness growing → confirmed mode needs a cadence guarantee
  from the network **or** a documented `confirmFailOpen`/`soft` recommendation for
  agent-scheduler use. This is a product decision, not a test bug.

---

## G4 — Consensus freshness (no false precision)

**Claim under test.** *When the SDK says a job fired at disciplined time X ± u, the block that
anchored that fire is stamped within tolerance of X.* The README promises "no false
precision"; this is the check.

**Procedure.** Stay idle for `CC_IDLE_MS` (no writes from the suite), then sync a fresh
`ClockchainClock` and fire a 2 s soft `timer()` probe. Entirely from MCP data (no local wall
clock): `drift = anchoringBlockTime − ctx.firedAt`, for the probe and, as context, for every
earlier one-shot (G2 / G3a / G3b), whose syncs happened right after a write.

| # | Criterion |
|---|---|
| G4.1 | The probe fires and its receipt carries a parseable anchoring block time. |
| G4.2 | For every one-shot, `drift ≥ −(uncertaintyMs + CC_TOLERANCE_MS)` — the anchoring block never precedes the fire. |
| G4.3 | For the post-idle probe, `drift ≤ CC_TOLERANCE_MS` — the disciplined clock was not materially behind real consensus at fire time. |

The idle window is the point: the earlier gates keep writing, so their syncs see fresh
consensus (drift ≈ 0.3–0.6 s observed). A 20 s idle window on a mint-on-write chain produces
≈ 20 s of drift; a 2.5 min idle window produced 161 s (observed, isolated G3a run).

**Why this exists.** `ClockchainClock.sync()` takes the latest block time as "now" and
reports `uncertaintyMs = rtt/2 + AbsTimeDifference` (≈ 20 ms on the hosted MCP). If the last
block was minted minutes ago, "now" is minutes stale, the disciplined clock inherits the whole
gap, and every **absolute** alarm fires that much late in real terms while claiming ±20 ms.
Durations (G1, G2) are immune — they only need the clock to *advance* correctly.

---

## Out of scope for these gates

- `create_schedule` / `estimate_schedule` / `list_schedules` (the on-chain smart-contract
  scheduler) — different product surface, different credits.
- The hosted **keeper** (`schedule_trigger`) — not shipped; the README roadmap still points
  at this SDK.
- Multi-validator / court-grade claims — the receipts here are single-validator testnet.

## Findings log

Kept short; each entry is something a gate turned up, with the date it was observed.

- **2026-09-10** — `get_timestamp` now returns ISO 8601 `madMarzulloTime`, `nodeParticipation`
  (no `%`), no `AbsTimeDifference`. `try-alarm-mcp.sh` reads `."nodeParticipation%"` and gets
  `?`; `core.getPoolHealth()` reads the old key and computes `degraded: true` on a 100 %
  pool. G0.4 is the regression check.
- **2026-09-10** — block height 136 / `22:59:34Z` unchanged for 25+ min with no writes.
  G0.5 / G3 risk above.
- **2026-09-10** — `node.clockchain.network` is not reachable from a developer laptop
  (TCP timeout); the hosted MCP is the only surface these gates can exercise, which is what
  the action item asked for anyway.
- **2026-09-10** — the per-token rate limit (30 req/min) is real: a confirmed alarm polling
  every 3 s plus confirmation polls trips it; the adapter backs off 10 s on 429 and continues.
- **2026-09-11** — production is the AWS box (Caddy + docker-compose, deployed via SSM per
  `infra/clockchain-mcp/RUNBOOK.md`), not Cloud Run; the GitHub `deploy.yml` still deploys to
  Cloud Run and goes green without touching production. The box's gateway wiring
  (`CLOCKCHAIN_ENDPOINT=http://clockchain-anchor-gateway:8090`, `CLOCKCHAIN_SIGNING_SECRET`)
  exists only as on-box edits to `compose-up.sh` / `docker-compose.yml`; the pre-deploy state is
  preserved on the box as local branch `host/pre-main-2026-09-11`.

## Run results — 2026-09-11 01:03 UTC, production with the heartbeat gateway (PR #100) — 10 / 10

`CC_LIVE_GATES=1 node --test test/gates-live.test.mjs` against `mcp.clockchain.network` after the
anchoring gateway was redeployed with `GATEWAY_HEARTBEAT_MS=2000` — **10 pass / 0 fail, 67 s.**

| Gate | Result | Evidence |
|---|---|---|
| G0.6 staleness at start | — | **−5 ms** (was 1 485 195 ms on Sep 10) |
| G3b alarm (confirmed) | **PASS** | fired 117 ms after T after one boundary read; consensus `01:03:24.770Z` ≥ T `01:03:24.193Z`; anchored at block 180, keyless-verified |
| G4 freshness | **PASS** | post-idle probe drift **−7 ms** (was 86 s); G2 272 ms, G3a/G3b 582 ms |
| G0–G2, G3a, G1b | **PASS** | unchanged |

All three primitives — stopwatch, timer, alarm (soft and confirmed) — now pass their gates on the
deployed endpoint.

## Run results — 2026-09-11 00:57 UTC, local MCP + gateway with read-triggered heartbeat

`CC_LIVE_GATES=1 CC_MCP_URL=http://127.0.0.1:3210/mcp …` against a local `mcp-server` pointed at
`infra/anchoring-gateway/gateway.mjs` with `GATEWAY_HEARTBEAT_MS=2000` — **10 pass / 0 fail, 64 s.**

| Gate | Result | Evidence |
|---|---|---|
| G3b alarm (confirmed) | **PASS** (was FAIL) | fired 19 ms after T on the disciplined clock after **one** boundary read; consensus `00:57:29.956Z` ≥ T `00:57:29.417Z`; anchored + verified |
| G4 freshness | **PASS** (was FAIL) | post-idle probe drift **21 ms** (was 86 s); G2 40 ms, G3a 533 ms, G3b 539 ms |
| everything else | **PASS** | unchanged |

The fix: a `/getTime` read that finds the last seal older than the heartbeat seals an empty block first, so
consensus advances for whoever is reading it — the confirmed alarm's boundary poll now sees time cross T, and a
sync never inherits idle time. No background cadence, no credits.

## Run results — 2026-09-11 00:40 UTC, production after PR #98 (AWS box, 45 tools)

`CC_LIVE_GATES=1 node --test test/gates-live.test.mjs`, defaults — **8 pass / 2 fail, 121 s.**

| Gate | Result | Evidence |
|---|---|---|
| G0.1–G0.3, G0.5 | **PASS** | 45 tools; `nodeParticipation: 100`; probe anchored, height advanced |
| G0.4 pool guard | **PASS** (was FAIL) | default `log_action` accepted — the `getPoolHealth()` key fix is live |
| G1 stopwatch (SDK) | **PASS** | elapsed vs wall within tolerance, both markers verified |
| G1b stopwatch (MCP tools) | **PASS** (new) | blocks 162/163; `elapsedMs` 6138 vs wall 6001; `stopwatch_verify` → `verified: true`, `elapsedOnChainMs` 6138 |
| G2 timer, G3a alarm (soft) | **PASS** | sub-ms lateness, anchored, verified |
| G3b alarm (confirmed) | **FAIL** | held 65 s, 14 identical boundary reads — unchanged |
| G4 freshness | **FAIL** | 86 s behind the anchoring block after idle, claimed ±53 ms — unchanged |

**Where the time actually comes from (learned during the deploy).** Production's
`CLOCKCHAIN_ENDPOINT` is not `node.clockchain.network` (unowned, down) but the owned
anchoring gateway container `clockchain-anchor-gateway` (`infra/anchoring-gateway/gateway.mjs`).
That service *is* the `/getTime` oracle: `madMarzulloTime` is the time of the last block it
sealed, and it seals a block synchronously inside each `/log`. So G3b and G4 are properties of
our own gateway, fixable in `gateway.mjs` (a live clock in `/getTime`, or heartbeat seals) —
not a network-team dependency. Likewise the `nodeParticipation` key shape is ours.

## Run results — 2026-09-10, hosted MCP before PR #98 (42 tools)

Suite: `CC_LIVE_GATES=1 node --test test/gates-live.test.mjs`, defaults, run at 2026-09-10T23:31:54.816Z —
**6 pass / 3 fail, 114 s, 7 log credits.** Full evidence JSON per gate is in the run's
`CC_EVIDENCE_DIR`; the numbers below are copied from it.

| Gate | Result | Evidence |
|---|---|---|
| G0.1 surface | **PASS** | 42 tools; all six required present (full surface, not `product`). |
| G0.2/0.3 time + pool | **PASS** | `madMarzulloTime` ISO 8601 parses; `nodeParticipation: 100`, `totalNodes: 1`; legacy `%` key absent. Consensus was 135 s behind wall clock at start (idle chain). |
| G0.4 pool guard | **FAIL** | Default `log_action` refused: *"Node pool is degraded (0% participation)"* while participation is 100. Root cause: `core.getPoolHealth()` reads `nodeParticipation%`. **Every user write without `allow_degraded:true` is refused on the current deployment.** Remaining gates ran with `allow_degraded`. |
| G0.5 blocks advance | **PASS** | Probe anchored at height 147 in <100 ms; latest height 146 → 147; staleness after write 74 ms. **Blocks mint on write only.** |
| G1 stopwatch | **PASS** | Markers at blocks 148 / 149; `elapsed` 6159 ms vs wall 6083 ms (+76 ms); both keyless-verified against the on-chain block, hashes match. |
| G2 timer (8 s, soft) | **PASS** | Fired 1.24 ms after the disciplined target; sync rtt 48 ms, ±24 ms; receipt anchored at block 150, keyless-verified, `payload.inputs.id` matches. |
| G3a alarm (10 s, soft) | **PASS** | Fired 0.08 ms after T on the disciplined clock; anchored at block 151, verified; anchoring block 373 ms after the fire. |
| G3b alarm (10 s, confirmed) | **FAIL** | Never fired. 18 boundary reads over 65 s all returned the same consensus time (the block minted by G3a's fire); consensus ended 65 s behind wall clock, 10 s short of T. **Confirmed mode deadlocks on a mint-on-write chain.** |
| G4 freshness (20 s idle) | **FAIL** | After G3b's 65 s hold + 20 s idle, the probe's disciplined fire time was **86 s behind** its anchoring block while the SDK claimed ±51 ms. Same-run context: G2 drift 339 ms, G3a drift 373 ms (their syncs followed a write). **Absolute alarms are late by however long the chain was idle at sync, and the uncertainty band does not say so.** |

### What this means for Monday

- **Stopwatch and timer work on the current deployment** (durations only need the clock to
  advance, and it does — sub-ms lateness, ±20 ms band, anchored and keyless-verifiable).
- **Alarm works mechanically in soft mode** but its *absolute* time is only as fresh as the
  last block, and the chain mints only on writes. A "fire at 09:00" armed on an idle chain
  fires at 09:00 *plus* the idle gap. Confirmed mode cannot fire at all on an idle chain.
- **One code defect blocks everyone today**: the pool-health guard refuses default writes
  (G0.4). Fix is a one-line key fallback in `core.getPoolHealth()` (+ the same in
  `examples/try-alarm-mcp.sh`), then redeploy.
- **Two product decisions** (not test bugs): (a) does the network commit to a block cadence
  (or a real-time consensus clock endpoint) so absolute time is fresh, or does the SDK widen
  `uncertaintyMs` by the observed staleness and document alarms as "soft, ± idle gap"? (b) is
  `confirmed` mode kept (needs cadence) or should the agent scheduler ship on `soft` /
  `confirmFailOpen`?

