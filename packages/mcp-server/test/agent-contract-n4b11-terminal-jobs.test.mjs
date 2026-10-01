import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTerminalOutbox } from "../dist/agent-contract/terminal-jobs.js";
import {
  boot, bindPair, fakeAnchor, waitFor, uuid,
} from "./n4b9-harness.mjs";

// N4b-11 — M3: the terminal transition must not be ACKNOWLEDGED without
// its durable outbox enqueue (a failed persist fails the transition
// closed; the run stays live and retryable). L3: the boot-recovery anchor
// confirm loop is bounded by anchorConfirmMaxAttempts, and
// terminal-jobs.json keeps at most terminalJobsMaxFinished FINISHED jobs.

const PENDING_LEDGER = {
  ledgerId: "ledger-fake", blockHeight: null, time: null, status: "pending_confirmation",
};

// ============================================================================
// M3 — a failed durable enqueue fails the terminal transition CLOSED.
// ============================================================================

test("M3: a persist failure at the terminal transition is not acknowledged — the run stays live and retryable", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n4b11-m3-"));
  const minted = [];
  const env = await boot({
    stateDir,
    onTerminalRun: (_run, _state, _principal, receipt) => minted.push(receipt),
  });
  // Deny/restore durable writes by toggling the state dir's write bit —
  // persistTerminalJobs then throws EACCES at the tmp-file open.
  let denied = false;
  const denyWrites = () => { chmodSync(stateDir, 0o555); denied = true; };
  const allowWrites = () => { if (denied) { chmodSync(stateDir, 0o700); denied = false; } };
  try {
    const runId = await bindPair(env, uuid(601), "tb1", "tp1");

    denyWrites();
    const refused = await env.callTool("tb1", "contract_withdraw", {});
    // The thrown persist surfaces as a code-only, RECEIPTED refusal
    // (server.ts wraps the dispatch throw) — never a success.
    assert.equal(refused.error, "CONTRACT_UNAVAILABLE", JSON.stringify(refused));
    assert.ok(
      env.service.receiptFeed(runId).receipts.some((r) => r.tool === "contract_withdraw"),
      "the refused transition is still receipted",
    );
    // The run is NOT terminal: no stage flip, no write-once state.
    const run = env.service.runFor(runId);
    assert.equal(run.terminalState, null);
    assert.notEqual(run.stage, "terminal");
    assert.notEqual(run.stage, "settled");
    // The emitter never fired — nothing terminal was acknowledged.
    assert.equal(minted.length, 0);
    // And the un-persisted mutation left no trace: no file, and the
    // in-memory outbox was rolled back (no half-terminal job a later
    // successful persist could silently carry to disk).
    assert.equal(existsSync(path.join(stateDir, "terminal-jobs.json")), false);
    assert.equal(env.service.terminalJobFor(runId), undefined);

    // Restore durability: the SAME call retries cleanly — no wedged state.
    allowWrites();
    const withdrawn = await env.callTool("tb1", "contract_withdraw", {});
    assert.equal(withdrawn.state, "withdrawn", JSON.stringify(withdrawn));
    assert.equal(env.service.runFor(runId).terminalState, "no_agreement");
    assert.equal(minted.length, 1);
    const jobsFile = JSON.parse(readFileSync(path.join(stateDir, "terminal-jobs.json"), "utf8"));
    const job = jobsFile.jobs.find((j) => j.runId === runId);
    assert.equal(job.terminalState, "no_agreement");
    assert.equal(job.close.status, "delivering");

    // The best-effort async paths still SWALLOW a persist failure: the
    // close-state writer cannot un-acknowledge the transition, so it keeps
    // the in-memory record (the next mutation retries the durable write).
    denyWrites();
    env.service.persistTerminalClose(runId, { status: "failed", attempts: 3, lastError: "sink unreachable" });
    assert.equal(env.service.terminalJobFor(runId).close.status, "failed");
    allowWrites();
    env.service.persistTerminalClose(runId, { status: "failed", attempts: 4, lastError: "sink unreachable" });
    const reconciled = JSON.parse(readFileSync(path.join(stateDir, "terminal-jobs.json"), "utf8"));
    assert.equal(reconciled.jobs.find((j) => j.runId === runId).close.attempts, 4);
  } finally {
    allowWrites();
    env.close();
  }
});

// ============================================================================
// L3a — recovered anchor confirm loops are bounded; the job rests pending.
// ============================================================================

test("L3: a recovered pending anchor stops polling at anchorConfirmMaxAttempts and rests for the next boot", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n4b11-recover-"));
  // Boot A: the terminal anchor write resolves pending and the confirm
  // loop is disabled (delay 0), so the job persists "pending".
  const envA = await boot({
    stateDir, anchor: fakeAnchor({ pending: true }), anchorConfirmDelayMs: 0,
  });
  const runId = await bindPair(envA, uuid(602), "tb1", "tp1");
  await envA.callTool("tb1", "contract_withdraw", {});
  await waitFor(() => envA.service.terminalJobFor(runId)?.anchors?.terminal?.status === "pending");
  envA.close();

  // Boot B: confirm() NEVER resolves block/time — a permanently
  // unconfirmable anchor. Recovery polls at most anchorConfirmMaxAttempts
  // (the initial poll IS attempt 1), then rests pending for the NEXT
  // boot — it does not burn the process forever.
  const anchorB = fakeAnchor({ confirmLedger: PENDING_LEDGER });
  const envB = await boot({ stateDir, anchor: anchorB, anchorConfirmDelayMs: 15, anchorConfirmMaxAttempts: 3 });
  try {
    const reached = await waitFor(() => anchorB.confirms.length >= 3, 5_000);
    assert.ok(reached, "recovery polled the confirm path");
    // ~8x the delay — a further re-armed poll would have fired by now.
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(anchorB.confirms.length, 3, "the recovered confirm loop is bounded");
    assert.equal(
      envB.service.terminalJobFor(runId).anchors.terminal.status, "pending",
      "past the budget the job rests pending — restart recovery resumes it",
    );
  } finally { envB.close(); }
});

// ============================================================================
// L3b — terminal-jobs.json retention: never grows past the finished cap.
// ============================================================================

test("L3: persisted terminal jobs keep at most terminalJobsMaxFinished FINISHED jobs — unfinished are never dropped", async () => {
  // Unit level: the durable write keeps the newest `maxFinished` finished
  // jobs plus every unfinished one; the in-memory map keeps them all.
  const dir = mkdtempSync(path.join(tmpdir(), "n4b11-retention-"));
  const outbox = createTerminalOutbox(dir, 2);
  for (const [i, runId] of ["r1", "r2", "r3", "r4"].entries()) {
    outbox.update(runId, 1_000 + i, (j) => {
      j.terminalState = "settled";
      j.close = { status: "delivered", attempts: 1 };
    });
  }
  outbox.update("r-pending", 2_000, (j) => {
    j.terminalState = "no_agreement";
    j.close = { status: "delivering", attempts: 0 };
  });
  const file = JSON.parse(readFileSync(path.join(dir, "terminal-jobs.json"), "utf8"));
  assert.deepEqual(
    file.jobs.map((j) => j.runId).sort(),
    ["r-pending", "r3", "r4"],
    "the 2 newest finished jobs + the unfinished one",
  );
  assert.ok(outbox.get("r1") !== undefined, "the in-memory map keeps jobs pruned from the file");

  // Service level: the option threads boot → service → outbox. Two
  // terminal transitions (no emitter wired → close absent → finished)
  // leave exactly one finished job in the file — the newest.
  const stateDir = mkdtempSync(path.join(tmpdir(), "n4b11-retention-svc-"));
  const env = await boot({ stateDir, terminalJobsMaxFinished: 1 });
  try {
    const run1 = await bindPair(env, uuid(603), "tb1", "tp1");
    const w1 = await env.callTool("tb1", "contract_withdraw", {});
    assert.equal(w1.state, "withdrawn", JSON.stringify(w1));
    const run2 = await bindPair(env, uuid(604), "tb2", "tp2");
    const w2 = await env.callTool("tb2", "contract_withdraw", {});
    assert.equal(w2.state, "withdrawn", JSON.stringify(w2));
    const jobs = JSON.parse(readFileSync(path.join(stateDir, "terminal-jobs.json"), "utf8")).jobs;
    assert.equal(jobs.length, 1, JSON.stringify(jobs));
    assert.equal(jobs[0].runId, run2, "the oldest finished job falls out first");
    assert.ok(env.service.terminalJobFor(run1) !== undefined, "in-memory record survives pruning");
  } finally { env.close(); }
});
