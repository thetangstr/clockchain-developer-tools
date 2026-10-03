import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createCloseEmitter, mintTerminalReceipt } from "../dist/agent-contract/close-emitter.js";
import { createTsaContractAnchor } from "../dist/agent-contract/anchor.js";
import { CONTRACT_TERMINAL_STATES } from "../dist/agent-contract/schemas.js";
import {
  boot, bookPair, agreePair, bindPair, signedSubmit, makeApproval,
  fakeAnchor, sinkCheckReceipt, waitFor, statusSchema,
  SIGNER, serverPubKey, keys, uuid,
} from "./n4b9-harness.mjs";

// N4b-9 — terminal machinery: F10 (shared vocabulary), F11 (write-once
// terminal identity), F13 (pending vs confirmed anchors), F14 (durable
// outbox + restart recovery), F17 (adapter-boundary eventHash normalization).

// ============================================================================
// F10 — one versioned terminal-state vocabulary; every producer state closes.
// ============================================================================

test("F10: every producer terminal state mints a receipt the sink vocabulary accepts", async () => {
  // The sink's accepted set (telemetry-sink/src/sink.ts TERMINAL_STATES) —
  // duplicated here verbatim so producer-side drift is caught on this side.
  const sinkStates = new Set([
    "settled", "no_agreement", "verification_failed", "blocked_by_policy",
    "budget_exhausted", "harness_error", "cancelled", "expired_unbound",
  ]);
  assert.deepEqual(new Set(CONTRACT_TERMINAL_STATES), sinkStates);
  for (const terminalState of CONTRACT_TERMINAL_STATES) {
    const receipt = mintTerminalReceipt(
      { runId: "run-mx", terminalState, ts: "2026-09-01T00:00:00.000Z" },
      SIGNER,
    );
    assert.equal(sinkCheckReceipt(receipt, "run-mx", serverPubKey), true, `state ${terminalState} not accepted`);
  }
});

// ============================================================================
// F11 — write-once terminal identity: cleanup cancel after verification_failed.
// ============================================================================

test("F11: cancel after verification_failed is receipted but never re-closes or re-anchors", async () => {
  const terminalCalls = [];
  const anchor = fakeAnchor();
  const env = await boot({
    anchor,
    onTerminalRun: (run, terminalState) => terminalCalls.push({ runId: run.runId, terminalState }),
  });
  try {
    const { runId, booked } = await bookPair(env, uuid(501), "tb1", "tp1");
    const orderRef = booked.orderRef;

    // Claimed mismatch → terminal verification_failed: ONE close + ONE anchor.
    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef, result: "mismatch", findingsDigest: `0x${"bb".repeat(32)}`,
    });
    const verified = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    assert.equal(verified.terminalState, "verification_failed");
    await waitFor(() => env.service.runFor(runId)?.anchors?.terminal?.status === "anchored");
    const firstHead = env.service.runFor(runId).anchors.terminal.digest;
    assert.equal(terminalCalls.length, 1);
    assert.equal(terminalCalls[0].terminalState, "verification_failed");

    // Cleanup cancel AFTER the first terminal transition: the booking is
    // cancelled and receipted — but terminal state, close identity and the
    // anchor subject are write-once.
    const prepC = await env.callTool("tp1", "booking_cancel_prepare", { reason: "verification_failed" });
    assert.ok(prepC.envelope, JSON.stringify(prepC));
    const approval = makeApproval({
      envelope: prepC.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const cancelled = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared: prepC,
      submitTool: "booking_cancel_submit", extraArgs: { approval },
    });
    assert.equal(cancelled.status, "CANCELLED", JSON.stringify(cancelled));
    assert.equal(cancelled.terminalState, "verification_failed");

    const run = env.service.runFor(runId);
    assert.equal(run.terminalState, "verification_failed");
    assert.equal(terminalCalls.length, 1, "no second terminal transition");
    assert.equal(anchor.calls.filter((c) => c.kind === "terminal").length, 1, "no second terminal anchor");
    assert.equal(run.anchors.terminal.digest, firstHead, "anchor subject unchanged");

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "verification_failed");
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));

    const feed = env.service.receiptFeed(runId);
    assert.equal(verifyChain(feed.receipts, { [SIGNER.keyId]: serverPubKey }).ok, true);
    const cancelReceipt = feed.receipts.find((r) => r.tool === "booking_cancel_submit");
    assert.ok(cancelReceipt, "cleanup cancel is receipted on the same chain");
  } finally { env.close(); }
});

// ============================================================================
// F13 — pending vs confirmed anchor; ok only on confirmed block/time evidence.
// ============================================================================

test("F13: a pending_confirmation write reads pending, never ok, until confirm resolves block+time", async () => {
  const anchor = fakeAnchor({ pending: true });
  const env = await boot({ anchor, anchorConfirmDelayMs: 30, anchorConfirmMaxAttempts: 10 });
  try {
    const { runId } = await agreePair(env, uuid(502), "tb1", "tp1");

    // The write resolved but carries no block/time → pending, NOT anchored.
    await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "pending");
    const stPending = await env.callTool("tb1", "contract_status", {});
    assert.equal(stPending.anchor, "pending");
    assert.equal(stPending.anchors.agreement.status, "pending");
    assert.equal(stPending.anchors.agreement.ledger.blockHeight, null);
    assert.equal(statusSchema.safeParse(stPending).success, true, JSON.stringify(statusSchema.safeParse(stPending).error));

    // Confirmation polling resolves the block/time → anchored → summary ok.
    const confirmed = await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "anchored", 5_000);
    assert.ok(confirmed, "confirm() resolved the pending anchor");
    assert.ok(anchor.confirms.length >= 1, "the confirm path was used");
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.anchor, "ok");
    assert.equal(st.anchors.agreement.status, "anchored");
    assert.equal(st.anchors.agreement.ledger.blockHeight, "43");
  } finally { env.close(); }
});

// ============================================================================
// F14 — durable outbox: restart between terminal dispatch and outcome.
// ============================================================================

test("F14: a service restart recovers pending anchor + close jobs and mints their outcomes", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n4b9-restart-"));
  const anchorA = fakeAnchor({ pending: true });
  const minted = [];
  const envA = await boot({
    stateDir, anchor: anchorA, anchorConfirmDelayMs: 0, anchorConfirmMaxAttempts: 0,
    onTerminalRun: (_run, _state, _principal, receipt) => minted.push(receipt),
  });
  const runId = await bindPair(envA, uuid(503), "tb1", "tp1");
  await envA.callTool("tb1", "contract_withdraw", {});
  await waitFor(() => envA.service.runFor(runId)?.anchors?.terminal?.status === "pending");
  assert.equal(minted.length, 1, "the close receipt was minted at the transition");
  envA.close();

  // The persisted job survived the "process death": terminal state, the
  // immutable receipt, and the pending anchor write are all on disk.
  const jobsFile = JSON.parse(readFileSync(path.join(stateDir, "terminal-jobs.json"), "utf8"));
  const persisted = jobsFile.jobs.find((j) => j.runId === runId);
  assert.ok(persisted, "terminal job persisted before restart");
  assert.equal(persisted.terminalState, "no_agreement");
  assert.equal(persisted.anchors.terminal.status, "pending");
  assert.equal(persisted.close.status, "delivering");

  // Boot B over the same state dir: the anchor job is re-driven (confirm →
  // anchored), the same minted receipt is resumed and delivered, and both
  // outcomes mint into the job's persisted evidence.
  const anchorB = fakeAnchor({ pending: false });
  const sinkReceipts = [];
  const envB = await boot({ stateDir, anchor: anchorB, anchorConfirmDelayMs: 0 });
  try {
    const service = envB.service;
    const emitter = createCloseEmitter({
      signer: SIGNER, closeUrl: "http://127.0.0.1:1", backoffMs: [0],
      fetchImpl: async (_url, init) => {
        sinkReceipts.push(JSON.parse(init.body));
        return { status: 200, text: async () => JSON.stringify({ closed: true, head: {} }) };
      },
      setState: (rid, st) => service.persistTerminalClose(rid, st),
      recordOutcome: (outcome, d) => service.recordTerminalOutcome(d.runId, outcome, d),
    });
    const unfinished = service.pendingTerminalJobs();
    assert.equal(unfinished.length, 1);
    assert.equal(unfinished[0].runId, runId);
    // Boot recovery re-drives the persisted anchor job.
    const anchored = await waitFor(() =>
      service.terminalJobFor(runId)?.anchors?.terminal?.status === "anchored", 5_000);
    assert.ok(anchored, "recovered anchor job confirmed post-restart");

    // The close job resumes the SAME minted receipt — never re-minted.
    emitter.resume(unfinished[0].receipt);
    await emitter.flush();
    assert.equal(sinkReceipts.length, 1);
    assert.deepEqual(sinkReceipts[0], minted[0], "the persisted receipt bytes are re-delivered verbatim");

    const job = service.terminalJobFor(runId);
    assert.equal(job.close.status, "delivered");
    const evidenceTools = job.evidence.map((r) => `${r.tool}:${r.outcome}`);
    assert.ok(evidenceTools.includes("anchor:anchor_anchored"), JSON.stringify(evidenceTools));
    assert.ok(evidenceTools.includes("telemetry_close:telemetry_close_delivered"), JSON.stringify(evidenceTools));
    // Post-restart evidence chains on the recorded transition tip — verify
    // the segment given the tip's own prevHash (the tip links the rest).
    const chain = [job.prevReceipt, ...job.evidence];
    const seg = verifyChain(chain, { [SIGNER.keyId]: serverPubKey }, { firstPrevHash: job.prevReceipt.prevHash });
    assert.equal(seg.ok, true, JSON.stringify(seg));
    assert.equal(seg.head, canonicalDigest(job.evidence.at(-1)));

    // A bound caller still resolves the terminal run for status.
    assert.equal(service.runIdForPrincipal("kb1"), runId);
    const st = await envB.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "no_agreement");
    assert.equal(st.telemetryClose.status, "delivered");
    assert.equal(st.anchors.terminal.status, "anchored");
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
  } finally { envB.close(); }
});

// ============================================================================
// F17 — the real TSA adapter normalizes bare-hex eventHash; status validates.
// ============================================================================

test("F17: createTsaContractAnchor normalizes the bare-hex eventHash; contract_status stays schema-valid", async () => {
  // Stub ClockchainClient matching core tsaIssue/tsaStatus calls: log() gets
  // a pending record (blockHeight null — the gateway's honest write), and
  // searchAsset() later reports the confirmed event.
  const logs = [];
  let confirmed = false;
  const stubClient = {
    async log(req) {
      logs.push(req);
      return {
        ledgerId: "ledger-stub",
        blockHeight: null,
        createdTimestamp: null,
        status: "pending_confirmation",
        assetReferenceId: req.assetReferenceId,
        assetHash: req.assetHash,
      };
    },
    async searchAsset(assetReferenceId) {
      return [{
        ledgerId: "ledger-stub",
        blockHeight: confirmed ? "777" : null,
        createdTimestamp: confirmed ? "2026-09-01T00:00:30Z" : null,
        status: confirmed ? "anchored" : "pending_confirmation",
        assetReferenceId,
        assetHash: logs[0]?.assetHash ?? "0".repeat(64),
      }];
    },
  };
  const anchor = createTsaContractAnchor(stubClient);
  const env = await boot({ anchor, anchorConfirmDelayMs: 25, anchorConfirmMaxAttempts: 10 });
  try {
    const { runId } = await agreePair(env, uuid(508), "tb1", "tp1");
    await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "pending");

    // Core emits bare 64-hex event hashes — the adapter must 0x-prefix them
    // so contract_status still satisfies its own outputSchema.
    const stPending = await env.callTool("tb1", "contract_status", {});
    assert.equal(stPending.anchors.agreement.status, "pending");
    assert.match(stPending.anchors.agreement.eventHash, /^0x[0-9a-f]{64}$/);
    assert.equal(statusSchema.safeParse(stPending).success, true, JSON.stringify(statusSchema.safeParse(stPending).error));

    // The real confirm() path (searchAsset) resolves it → anchored → ok.
    confirmed = true;
    const resolved = await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "anchored", 5_000);
    assert.ok(resolved, "tsaStatus-driven confirm resolved the pending anchor");
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.anchor, "ok");
    assert.match(st.anchors.agreement.eventHash, /^0x[0-9a-f]{64}$/);
    assert.equal(statusSchema.safeParse(st).success, true);
  } finally { env.close(); }
});
