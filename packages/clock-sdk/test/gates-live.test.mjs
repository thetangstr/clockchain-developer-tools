// Live gates G0–G4 (see GATES.md): the real clock-sdk primitives driven through
// the HOSTED MCP via examples/mcp-adapter.mjs, then keyless-verified on-chain.
//
// Opt-in — spends ~7 testnet log credits and takes ~2 minutes:
//
//   CC_LIVE_GATES=1 CC_MCP_TOKEN=<x-api-key> node --test test/gates-live.test.mjs
//
// Without CC_LIVE_GATES=1 the whole suite is reported as skipped, so `npm test`
// stays offline and deterministic. Every gate prints its evidence (ledgerIds,
// block heights, timings) as a diagnostic; set CC_EVIDENCE_DIR to also write
// <gate>.json files. Knobs are documented in GATES.md.
//
// Ordering matters and node:test runs the tests in a file sequentially: G0.4
// decides whether later writes must pass allow_degraded (the pool-health guard
// was observed mis-reading a renamed gateway key on 2026-09-10), and G0.5 uses
// G0.4's probe write to check that blocks advance.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  ClockchainClock,
  ClockScheduler,
  timer,
  stopwatchStart,
  stopwatchStop,
  elapsed,
  verificationRefs,
  parseGatewayTime,
} from "../dist/index.js";

const LIVE = process.env.CC_LIVE_GATES === "1";
const env = (k, d) => (process.env[k] != null && process.env[k] !== "" ? process.env[k] : d);
const num = (k, d) => Number(env(k, d));

const CFG = Object.freeze({
  url: env("CC_MCP_URL", "https://mcp.clockchain.network/mcp"),
  timerMs: num("CC_TIMER_MS", 8000),
  alarmMs: num("CC_ALARM_MS", 10000),
  holdMs: num("CC_STOPWATCH_HOLD_MS", 6000),
  toleranceMs: num("CC_TOLERANCE_MS", 5000),
  confirmMs: num("CC_CONFIRM_MS", 45000),
  idleMs: num("CC_IDLE_MS", 20000),
  allowDegraded: env("CC_ALLOW_DEGRADED", ""), // "1" | "0" | "" (auto)
  evidenceDir: env("CC_EVIDENCE_DIR", ""),
});
// Headroom on each gate's node:test timeout beyond the modelled wait.
const SLACK_MS = 30_000;
// The hosted endpoint rate-limits 30 req/min per token: poll gently.
const LIVE_POLL_MS = 3000;

const REQUIRED_TOOLS = [
  "get_time",
  "get_timestamp",
  "log_action",
  "get_log_entry",
  "attest_action",
  "verify_cross_party",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : String(ms));
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

async function waitFor(pred, timeoutMs, stepMs = 500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await sleep(stepMs);
  }
  return pred();
}

function assertVerified(v, marker, label) {
  assert.ok(v && v.onChain, `${label}: verify_cross_party returned no onChain section: ${JSON.stringify(v)}`);
  assert.equal(
    v.onChain.verifiedAgainst,
    "on-chain block",
    `${label}: not resolved to the immutable block: ${JSON.stringify(v.onChain)}`,
  );
  assert.equal(
    String(v.onChain.anchoredHash ?? "").toLowerCase(),
    String(marker.hash).toLowerCase(),
    `${label}: anchored hash on-chain does not match what was written`,
  );
}

describe(
  "live clock-primitive gates (GATES.md G0–G4)",
  { skip: LIVE ? false : "set CC_LIVE_GATES=1 and CC_MCP_TOKEN to run against the hosted MCP" },
  () => {
    let mcp;
    let adapterMod;
    const state = {
      participation: NaN,
      heightBefore: null,
      probe: null,
      poolGuardMismatch: false,
      /** Every one-shot result (G2, G3a, G3b) for the G4 freshness gate. */
      oneShots: [],
    };

    async function evidence(t, gate, data) {
      const payload = { gate, at: new Date().toISOString(), url: CFG.url, ...data };
      t.diagnostic(`${gate} evidence ${JSON.stringify(payload)}`);
      if (CFG.evidenceDir) {
        const fs = await import("node:fs/promises");
        const path = await import("node:path");
        await fs.mkdir(CFG.evidenceDir, { recursive: true });
        await fs.writeFile(path.join(CFG.evidenceDir, `${gate}.json`), JSON.stringify(payload, null, 2));
      }
    }

    before(async () => {
      adapterMod = await import("../examples/mcp-adapter.mjs");
      let token = process.env.CC_MCP_TOKEN;
      if (!token && process.env.CC_MINT_DEMO_TOKEN === "1") {
        token = await adapterMod.mintDemoToken({ file: process.env.CC_TOKEN_FILE });
      }
      assert.ok(token, "CC_MCP_TOKEN is required (or CC_MINT_DEMO_TOKEN=1 to mint a cached demo token)");
      mcp = new adapterMod.McpClockchainAdapter({
        url: CFG.url,
        token,
        allowDegraded: CFG.allowDegraded === "1",
        waitMs: CFG.confirmMs,
        pollMs: LIVE_POLL_MS,
      });
      await mcp.connect();
    });

    after(async () => {
      await mcp?.close();
    });

    // ------------------------------------------------------------------ G0

    test("G0.1 deployment exposes the tools the primitives need", { timeout: 60_000 }, async (t) => {
      const tools = await mcp.listTools();
      const missing = REQUIRED_TOOLS.filter((n) => !tools.includes(n));
      await evidence(t, "G0.1", { toolCount: tools.length, missing });
      assert.deepEqual(
        missing,
        [],
        tools.length <= 2
          ? `deployment looks like the MCP_SURFACE=product slice (${tools.join(", ")}); the clock primitives need the full surface`
          : `missing tools: ${missing.join(", ")}`,
      );
    });

    test("G0.2/G0.3/G0.6 consensus time parses, height is sane, pool is healthy", { timeout: 60_000 }, async (t) => {
      const ts = await mcp.getTimestamp();
      const epochMs = parseGatewayTime(ts.madMarzulloTime);
      const height = Number(ts.blockHeight);
      const participation = adapterMod.participationOf(ts);
      const stalenessMs = Date.now() - epochMs;
      state.participation = participation;
      state.heightBefore = height;
      await evidence(t, "G0.2", {
        raw: ts,
        epochMs,
        consensusIso: iso(epochMs),
        stalenessMs,
        participation,
        legacyKeyPresent: ts["nodeParticipation%"] != null,
      });
      assert.ok(Number.isFinite(epochMs), `G0.2 madMarzulloTime unparseable: ${JSON.stringify(ts.madMarzulloTime)}`);
      assert.ok(Number.isInteger(height) && height >= 0, `G0.2 blockHeight not a non-negative integer: ${ts.blockHeight}`);
      assert.ok(Number.isFinite(participation), "G0.3 no nodeParticipation / nodeParticipation% in get_timestamp");
      assert.ok(participation > 0, `G0.3 pool degraded: participation ${participation}%`);
      assert.ok(Number(ts.totalNodes) >= 1, `G0.3 totalNodes ${ts.totalNodes}`);
    });

    test("G0.4 pool-health guard agrees with get_timestamp (default write is not refused)", { timeout: 90_000 }, async (t) => {
      const ref = `gates:g0:probe:${Date.now()}`;
      const entry = { assetHash: sha256(ref), assetReferenceId: ref, additionalInfo: "clock gates probe" };
      let refusedText = null;
      try {
        state.probe = await mcp.log(entry);
      } catch (err) {
        if (!adapterMod.isPoolDegradedError(err) || !(state.participation > 0)) throw err;
        refusedText = err.text;
        state.poolGuardMismatch = true;
        // Keep the rest of the run meaningful: opt later writes into allow_degraded
        // (unless the operator forbade it) and retry the probe the same way.
        if (CFG.allowDegraded !== "0") {
          mcp.allowDegraded = true;
          state.probe = await mcp.log(entry);
        }
      }
      await evidence(t, "G0.4", {
        poolGuardMismatch: state.poolGuardMismatch,
        allowDegradedForRemainingWrites: mcp.allowDegraded,
        refusedText,
        probeLedgerId: state.probe?.ledgerId ?? null,
      });
      assert.equal(
        state.poolGuardMismatch,
        false,
        `guard refused a default write while get_timestamp reports ${state.participation}% participation — ` +
          `core.getPoolHealth() reads "nodeParticipation%" but the gateway now sends "nodeParticipation". ` +
          `Server said: ${refusedText}`,
      );
    });

    test("G0.5 blocks advance: the probe anchors and the height moves", { timeout: CFG.confirmMs + SLACK_MS }, async (t) => {
      assert.ok(state.probe?.ledgerId, "no probe write to confirm (G0.4 could not write at all)");
      const confirmed = await mcp.waitForConfirmation(state.probe.ledgerId, CFG.confirmMs);
      const after = await mcp.getTimestamp();
      const heightAfter = Number(after.blockHeight);
      await evidence(t, "G0.5", {
        probeLedgerId: state.probe.ledgerId,
        probeBlockHeight: confirmed?.blockHeight ?? null,
        probeCreatedTimestamp: confirmed?.createdTimestamp ?? null,
        heightBefore: state.heightBefore,
        heightAfter,
        stalenessAfterMs: Date.now() - parseGatewayTime(after.madMarzulloTime),
      });
      assert.notEqual(
        confirmed?.blockHeight ?? null,
        null,
        `probe never anchored within ${CFG.confirmMs}ms (blockHeight null) — the chain is not producing blocks`,
      );
      assert.ok(
        heightAfter > state.heightBefore,
        `latest height did not advance past ${state.heightBefore} after an anchored write (now ${heightAfter})`,
      );
    });

    // ------------------------------------------------------------------ G1

    test("G1 stopwatch: two anchored markers, consistent elapsed, keyless-verified", { timeout: CFG.holdMs + 2 * CFG.confirmMs + SLACK_MS }, async (t) => {
      const label = `gate-${Date.now().toString(36)}`;
      const handle = await stopwatchStart(mcp, label, CFG.confirmMs);
      await sleep(CFG.holdMs);
      const m = await stopwatchStop(mcp, handle, CFG.confirmMs);
      const issued = mcp.logIssuedAt;
      const wallElapsed = issued[issued.length - 1] - issued[issued.length - 2];
      const el = elapsed(m);
      const refs = verificationRefs(m);

      // Keyless verify BOTH markers before asserting on timing, so evidence is complete.
      const vStart = await mcp.verifyCrossParty(refs.start);
      const vStop = await mcp.verifyCrossParty(refs.stop);
      await evidence(t, "G1", {
        label,
        start: m.start,
        stop: m.stop,
        elapsedMs: el,
        wallElapsedMs: wallElapsed,
        driftMs: el - wallElapsed,
        allowDegraded: mcp.allowDegraded,
        verify: { start: vStart?.onChain ?? vStart, stop: vStop?.onChain ?? vStop },
      });

      assert.notEqual(m.start.blockHeight, null, "G1.1 start marker never anchored (blockHeight null)");
      assert.notEqual(m.stop.blockHeight, null, "G1.1 stop marker never anchored (blockHeight null)");
      assert.ok(Number.isFinite(m.start.epochMs), `G1.2 start createdTimestamp unparseable: ${m.start.createdTimestamp}`);
      assert.ok(Number.isFinite(m.stop.epochMs), `G1.2 stop createdTimestamp unparseable: ${m.stop.createdTimestamp}`);
      assert.ok(el >= 0, `G1.3 elapsed negative: ${el}ms`);
      assert.ok(Number(m.stop.blockHeight) >= Number(m.start.blockHeight), "G1.3 stop block precedes start block");
      assert.ok(
        Math.abs(el - wallElapsed) <= CFG.toleranceMs,
        `G1.4 elapsed ${el}ms vs wall ${wallElapsed}ms differ by more than ${CFG.toleranceMs}ms`,
      );
      assertVerified(vStart, { hash: m.start.assetHash }, "G1.5 start");
      assertVerified(vStop, { hash: m.stop.assetHash }, "G1.5 stop");
      assert.equal(m.start.assetReferenceId, `stopwatch:${label}:start`, "G1.6");
      assert.equal(m.stop.assetReferenceId, `stopwatch:${label}:stop`, "G1.6");
      assert.notEqual(m.start.assetHash, m.stop.assetHash, "G1.6 markers share a hash");
    });

    test("G1b stopwatch via the MCP tools: start → stop → verify, elapsed recomputed from block times", { timeout: CFG.holdMs + 2 * CFG.confirmMs + SLACK_MS }, async (t) => {
      const tools = await mcp.listTools();
      if (!["stopwatch_start", "stopwatch_stop", "stopwatch_verify"].every((n) => tools.includes(n))) {
        t.skip("deployment does not expose stopwatch_* yet (ships with WS-B)");
        return;
      }
      const label = `gate-tools-${Date.now().toString(36)}`;
      const w = (args) => (mcp.allowDegraded ? { ...args, allow_degraded: true } : args);
      const started = await mcp.call("stopwatch_start", w({ label, wait_ms: CFG.confirmMs }));
      const issuedStart = Date.now();
      await sleep(CFG.holdMs);
      const issuedStop = Date.now();
      const stopped = await mcp.call("stopwatch_stop", w({ label, start_ledger_id: started.start.ledgerId, wait_ms: CFG.confirmMs }));
      const verified = await mcp.call("stopwatch_verify", {
        start_ledger_id: stopped.start.ledgerId,
        stop_ledger_id: stopped.stop.ledgerId,
        start_block_height: stopped.start.blockHeight,
        stop_block_height: stopped.stop.blockHeight,
      });
      const wallElapsed = issuedStop - issuedStart;
      await evidence(t, "G1b", { label, started, stopped, verified, wallElapsedMs: wallElapsed, allowDegraded: mcp.allowDegraded });

      assert.equal(started.status, "anchored", `G1b.1 start marker: ${started.warning ?? started.status}`);
      assert.equal(stopped.status, "anchored", `G1b.1 measurement: ${stopped.warning ?? stopped.status}`);
      assert.ok(Number.isFinite(stopped.elapsedMs) && stopped.elapsedMs >= 0, `G1b.3 elapsedMs ${stopped.elapsedMs}`);
      assert.ok(Math.abs(stopped.elapsedMs - wallElapsed) <= CFG.toleranceMs, `G1b.4 elapsed ${stopped.elapsedMs}ms vs wall ${wallElapsed}ms`);
      assert.equal(verified.verified, true, `G1b.5 ${verified.note}`);
      assert.equal(verified.start.verifiedAgainst, "on-chain block");
      assert.equal(verified.stop.verifiedAgainst, "on-chain block");
      assert.ok(
        Number.isFinite(verified.elapsedOnChainMs) && Math.abs(verified.elapsedOnChainMs - stopped.elapsedMs) <= CFG.toleranceMs,
        `G1b.5 on-chain elapsed ${verified.elapsedOnChainMs}ms vs recorded ${stopped.elapsedMs}ms`,
      );
    });

    // ------------------------------------------------- G2 / G3 one-shot runner

    /**
     * Sync a disciplined clock to the MCP, arm ONE job, wait for it to settle,
     * disarm, keyless-verify its receipt, and return everything a gate asserts on.
     * `arm(sch, clock)` returns the job id; `fireAtOf(clock)` is evaluated after
     * sync so absolute targets are on the disciplined clock.
     */
    async function runOneShot(t, gate, { arm, waitMs, confirmed = false }) {
      const clock = new ClockchainClock(mcp);
      const sync = await clock.sync();
      const readingsBefore = mcp.readings.length;
      const sch = new ClockScheduler({
        clock,
        client: mcp,
        confirmSource: confirmed ? mcp : undefined,
        pollMs: confirmed ? LIVE_POLL_MS : 1000,
        maxConfirmHoldMs: 10_000,
      });
      let ctx = null;
      let fireWall = null;
      let id;
      let st;
      try {
        id = arm(sch, clock, (c) => {
          ctx = c;
          fireWall = Date.now();
          return { firedAt: c.epochMs };
        });
        await waitFor(() => ["fired", "error"].includes(sch.getStatus(id).state), waitMs);
        st = sch.getStatus(id);
      } finally {
        sch.clearAll();
      }

      // readingsBefore was captured after clock.sync(), so everything from there on is a boundary read.
      const boundaryReads = mcp.readings.slice(readingsBefore);
      const lastBeforeFire = fireWall
        ? [...boundaryReads].reverse().find((r) => r.wallMs <= fireWall) ?? null
        : mcp.lastReading;
      const receipt = st.receipt;
      const v = receipt?.anchor?.ledgerId
        ? await mcp.verifyCrossParty({ ledgerId: receipt.anchor.ledgerId, blockHeight: receipt.anchor.blockHeight })
        : null;
      const consensusTimeMs = receipt?.anchor?.consensusTime ? parseGatewayTime(receipt.anchor.consensusTime) : NaN;
      const out = { gate, id, sync, st, ctx, fireWall, boundaryReads, lastBeforeFire, receipt, v, consensusTimeMs };
      state.oneShots.push(out);
      await evidence(t, gate, {
        id,
        mode: st.mode,
        sync: { offsetMs: sync.offsetMs, rttMs: sync.rttMs, uncertaintyMs: sync.uncertaintyMs, consensusIso: iso(sync.epochMs) },
        fireAt: st.fireAt,
        fireAtIso: iso(st.fireAt),
        state: st.state,
        error: st.error,
        firedAt: ctx?.firedAt ?? null,
        latenessMs: ctx ? ctx.firedAt - st.fireAt : null,
        fireWallIso: fireWall ? iso(fireWall) : null,
        boundaryReads: boundaryReads.map((r) => ({ consensusIso: iso(r.epochMs), wallIso: iso(r.wallMs), stalenessMs: r.wallMs - r.epochMs })),
        lastConsensusBeforeFire: lastBeforeFire ? iso(lastBeforeFire.epochMs) : null,
        receipt: receipt ? { status: receipt.status, anchor: receipt.anchor, eventHash: receipt.eventHash, warning: receipt.warning } : null,
        consensusTimeIso: Number.isFinite(consensusTimeMs) ? iso(consensusTimeMs) : null,
        // How far the disciplined clock's belief was from the block that anchored the fire.
        disciplinedDriftMs: ctx && Number.isFinite(consensusTimeMs) ? consensusTimeMs - ctx.firedAt : null,
        verify: v?.onChain ?? v,
        allowDegraded: mcp.allowDegraded,
      });
      return out;
    }

    /** Assertions shared by every one-shot: fired once, never early, anchored, verified. */
    function assertFiredOnce(r, g, { lateTolerance = CFG.toleranceMs } = {}) {
      const { st, ctx, receipt, v } = r;
      assert.equal(st.state, "fired", `${g}.1 job ended in state "${st.state}"${st.error ? `: ${st.error}` : ""}`);
      assert.equal(st.fireCount, 1, `${g}.1 fireCount`);
      assert.ok(ctx.firedAt >= st.fireAt, `${g}.2 fired EARLY by ${st.fireAt - ctx.firedAt}ms on the disciplined clock`);
      assert.ok(ctx.firedAt - st.fireAt <= lateTolerance, `${g} fired ${ctx.firedAt - st.fireAt}ms late (> ${lateTolerance}ms)`);
      assert.ok(receipt, `${g} no receipt attached to the fired job`);
      assert.equal(receipt.status, "anchored", `${g} receipt status "${receipt.status}"${receipt.warning ? ` — ${receipt.warning}` : ""}`);
      assert.notEqual(receipt.anchor.blockHeight, null, `${g} receipt blockHeight null`);
      assertVerified(v, { hash: receipt.eventHash }, `${g} verify`);
      assert.equal(receipt.action, "scheduler.fire", `${g} receipt action`);
      assert.equal(receipt.payload?.inputs?.id, r.id, `${g} anchored event is not this job's fire`);
    }

    // ------------------------------------------------------------------ G2

    test("G2 timer: fires after D on the disciplined clock, never early, anchored + verified", { timeout: CFG.timerMs + CFG.confirmMs + SLACK_MS }, async (t) => {
      let armedAt;
      const r = await runOneShot(t, "G2", {
        waitMs: CFG.timerMs + CFG.confirmMs + 10_000,
        arm: (sch, clock, action) => {
          armedAt = clock.now().epochMs;
          return timer(sch, clock, CFG.timerMs, action, { id: `timer-${Date.now().toString(36)}`, agentId: "clock-gates", mode: "soft" });
        },
      });
      assert.ok(Number.isFinite(r.sync.uncertaintyMs) && r.sync.uncertaintyMs < 5000, `G2.1 uncertainty ${r.sync.uncertaintyMs}ms`);
      assert.ok(Math.abs(r.st.fireAt - (armedAt + CFG.timerMs)) <= 100, `G2.2 fireAt ${r.st.fireAt} vs armed+D ${armedAt + CFG.timerMs}`);
      assertFiredOnce(r, "G2");
    });

    // ------------------------------------------------------------------ G3

    test("G3a alarm (soft): fires at absolute T on the disciplined clock, once, anchored + verified", { timeout: CFG.alarmMs + CFG.confirmMs + SLACK_MS }, async (t) => {
      let T;
      const r = await runOneShot(t, "G3a", {
        waitMs: CFG.alarmMs + CFG.confirmMs + 10_000,
        arm: (sch, clock, action) => {
          T = clock.now().epochMs + CFG.alarmMs;
          return sch.schedule({ id: `alarm-soft-${Date.now().toString(36)}`, fireAt: T, mode: "soft", agentId: "clock-gates", action });
        },
      });
      assert.equal(r.st.fireAt, T, "G3a armed at the requested absolute T");
      assertFiredOnce(r, "G3a");
      // The fire is itself a write, so the anchoring block is minted at/after T.
      if (Number.isFinite(r.consensusTimeMs)) {
        assert.ok(
          r.consensusTimeMs >= T - r.sync.uncertaintyMs - CFG.toleranceMs,
          `G3a.5 anchoring block time ${iso(r.consensusTimeMs)} precedes T ${iso(T)}`,
        );
      }
    });

    test("G3b alarm (confirmed): fires only after consensus itself crosses T, once, anchored + verified", { timeout: CFG.alarmMs + CFG.confirmMs + SLACK_MS }, async (t) => {
      let T;
      const r = await runOneShot(t, "G3b", {
        confirmed: true,
        waitMs: CFG.alarmMs + CFG.confirmMs + 10_000,
        arm: (sch, clock, action) => {
          T = clock.now().epochMs + CFG.alarmMs;
          return sch.schedule({ id: `alarm-${Date.now().toString(36)}`, fireAt: T, mode: "confirmed", agentId: "clock-gates", action });
        },
      });

      if (r.st.state !== "fired") {
        const last = mcp.lastReading;
        const staleness = last ? last.wallMs - last.epochMs : NaN;
        assert.fail(
          `G3b.1 alarm ended in state "${r.st.state}"${r.st.error ? ` (${r.st.error})` : ""} — ` +
            `T=${iso(T)}, last consensus read ${last ? iso(last.epochMs) : "none"} ` +
            `(${Number.isFinite(staleness) ? Math.round(staleness / 1000) : "?"}s behind wall clock, ` +
            `${last ? Math.round((T - last.epochMs) / 1000) : "?"}s short of T) after ${r.boundaryReads.length} boundary reads. ` +
            `If consensus is frozen, confirmed mode holds until something mints a block (GATES.md G3 risk).`,
        );
      }
      // Confirmed mode re-reads consensus at the boundary and pays a poll + RTT for it.
      assertFiredOnce(r, "G3b", { lateTolerance: CFG.toleranceMs + LIVE_POLL_MS });
      assert.ok(r.lastBeforeFire, "G3b.3 no boundary consensus read recorded before the fire");
      assert.ok(r.lastBeforeFire.epochMs >= T, `G3b.3 fired while consensus ${iso(r.lastBeforeFire.epochMs)} < T ${iso(T)}`);
      assert.ok(r.boundaryReads.length >= 1, "G3b.4 confirmed mode did not re-read consensus at the boundary");
      if (Number.isFinite(r.consensusTimeMs)) {
        assert.ok(
          r.consensusTimeMs >= T - r.sync.uncertaintyMs - CFG.toleranceMs,
          `G3b.5 anchoring block time ${iso(r.consensusTimeMs)} precedes T ${iso(T)}`,
        );
      }
    });

    // ------------------------------------------------------------------ G4

    test("G4 consensus freshness: after an idle window, the disciplined clock still agrees with the block that anchors its fire", { timeout: CFG.idleMs + 2000 + CFG.confirmMs + SLACK_MS }, async (t) => {
      // Measured entirely from MCP data — no local wall clock: drift = anchoring
      // block time − disciplined firedAt. On a chain that mints continuously this
      // is ~anchor latency; on a chain that only mints on writes it equals however
      // long the chain was idle at sync, and every ABSOLUTE alarm inherits that
      // error while reporting ±rtt/2. The earlier gates keep writing (fresh
      // consensus), so this gate first goes deliberately idle, then syncs and
      // fires a short probe timer.
      await sleep(CFG.idleMs);
      const probe = await runOneShot(t, "G4-probe", {
        waitMs: 2000 + CFG.confirmMs + 10_000,
        arm: (sch, clock, action) =>
          timer(sch, clock, 2000, action, { id: `fresh-${Date.now().toString(36)}`, agentId: "clock-gates", mode: "soft" }),
      });
      const rows = state.oneShots
        .filter((r) => r.ctx && Number.isFinite(r.consensusTimeMs))
        .map((r) => ({
          gate: r.gate,
          id: r.id,
          syncConsensusIso: iso(r.sync.epochMs),
          claimedUncertaintyMs: r.sync.uncertaintyMs,
          firedAtIso: iso(r.ctx.firedAt),
          anchoringBlockIso: iso(r.consensusTimeMs),
          driftMs: r.consensusTimeMs - r.ctx.firedAt,
        }));
      await evidence(t, "G4", { idleMs: CFG.idleMs, toleranceMs: CFG.toleranceMs, rows });
      assert.equal(probe.st.state, "fired", `G4 probe timer ended in state "${probe.st.state}"${probe.st.error ? `: ${probe.st.error}` : ""}`);
      assert.ok(Number.isFinite(probe.consensusTimeMs), "G4 probe receipt carries no parseable anchor consensusTime");
      for (const row of rows) {
        assert.ok(
          row.driftMs >= -row.claimedUncertaintyMs - CFG.toleranceMs,
          `G4 ${row.gate}: anchoring block ${row.anchoringBlockIso} precedes the disciplined fire ${row.firedAtIso}`,
        );
      }
      const p = rows.find((r) => r.gate === "G4-probe");
      assert.ok(
        p.driftMs <= CFG.toleranceMs,
        `G4 after ${CFG.idleMs}ms idle the disciplined clock was ${Math.round(p.driftMs / 1000)}s behind the anchoring block ` +
          `(claimed ±${Math.round(p.claimedUncertaintyMs)}ms) — consensus was stale at sync because the chain only mints on writes`,
      );
    });
  },
);
