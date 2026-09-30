import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  boot, bindPair, uuid,
} from "./n4b9-harness.mjs";

// N4b-11 — M3: the terminal transition must not be ACKNOWLEDGED without
// its durable outbox enqueue (a failed persist fails the transition
// closed; the run stays live and retryable).

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

