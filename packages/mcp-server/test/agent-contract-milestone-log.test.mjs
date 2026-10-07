import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTsaContractAnchor } from "../dist/agent-contract/anchor.js";
import { canonicalDigest, canonicalJson } from "../dist/agent-contract/canonical.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import {
  MILESTONES, MILESTONE_LOG_SCHEMA, closeMilestones, createMilestoneTracker, milestoneReferenceId,
  observeMilestoneReceipt, renderMilestones,
} from "../dist/agent-contract/milestone-log.js";
import { checkConfig } from "../scripts/agent-contract/check-config.mjs";
import {
  HOST_ROOTS, POLICY, bindPair, boot, fakeAnchor, keys, makeApproval, signMandate, signedSubmit,
  statusSchema, uuid, waitFor,
} from "./n4b9-harness.mjs";

// Milestone log (MILESTONE-TIMELINE.md §4 Option A; docs/agent-contract/MILESTONE-LOG.md):
// six chained per-milestone entries written by the contract server behind
// CONTRACT_MILESTONE_LOG=1 (default off).

// ============================================================================
// Unit: attribution, sealing and the entry chain (pure tracker).
// ============================================================================

const RUN = "11111111-2222-4333-8444-555555555555";
let seq = 0;
const T0 = Date.parse("2026-10-06T12:00:00.000Z");
const rid = () => `0x${(++seq).toString(16).padStart(64, "0")}`;
const rcpt = (tool, outcome = "ok", surface = "business") => ({ receiptId: rid(), tool, outcome, surface, ts: T0 + seq * 1000 });

/** Feed receipts; returns every entry sealed along the way. */
function feed(t, steps, { terminalAt = -1 } = {}) {
  const sealed = [];
  steps.forEach(([r, approvals = []], i) => {
    sealed.push(...observeMilestoneReceipt(t, RUN, r, approvals, i === terminalAt));
  });
  return sealed;
}

test("unit: a negotiated, settled deal seals six chained entries at their transitions", () => {
  const t = createMilestoneTracker();
  const bindB = rcpt("contract_bind");
  const bindP = rcpt("contract_bind");
  const mPrep = rcpt("mandate_prepare");
  const mSub = rcpt("mandate_submit");
  assert.deepEqual(feed(t, [[bindB], [bindP], [mPrep]]), [], "binds alone do not complete discover");
  const afterMandate = feed(t, [[mSub]]);
  assert.deepEqual(afterMandate.map((e) => e.milestone), ["discover"]);
  assert.deepEqual(afterMandate[0].payload.receiptIds, [bindB, bindP, mPrep, mSub].map((r) => r.receiptId).sort());

  const quote = rcpt("catalog_quote");
  const oPrep = rcpt("offer_prepare");
  const oSub = rcpt("offer_submit");
  const afterOffer = feed(t, [[quote], [oPrep], [oSub]]);
  assert.deepEqual(afterOffer.map((e) => e.milestone), ["proposal"], "the first offer completes proposal");

  const cPrep = rcpt("offer_prepare");
  const cSub = rcpt("offer_submit");
  const poll = rcpt("contract_status");
  const aPrep = rcpt("offer_accept_prepare");
  const aSub = rcpt("offer_accept_submit");
  const afterAccept = feed(t, [[cPrep], [cSub], [poll], [aPrep], [aSub]]);
  assert.deepEqual(afterAccept.map((e) => e.milestone), ["negotiation", "agreement"]);
  assert.deepEqual(afterAccept[0].payload.receiptIds, [cPrep, cSub, poll].map((r) => r.receiptId).sort(),
    "a counter after the first offer and a status poll in that stage are negotiation");

  const bPrep = rcpt("booking_prepare");
  const bExec = rcpt("booking_execute");
  const vPrep = rcpt("verification_prepare");
  const vSub = rcpt("verification_submit");
  const bookApproval = `0x${"b0".repeat(32)}`;
  const afterVerify = feed(t, [[bPrep], [bExec, [bookApproval]], [vPrep], [vSub]]);
  assert.deepEqual(afterVerify.map((e) => e.milestone), ["execution"]);
  assert.deepEqual(afterVerify[0].payload.approvalDigests, [bookApproval]);

  const sPrep = rcpt("settlement_prepare");
  const sAuth = rcpt("settlement_authorize");
  const settleApproval = `0x${"5e".repeat(32)}`;
  const afterSettle = feed(t, [[sPrep], [sAuth, [settleApproval]]], { terminalAt: 1 });
  assert.deepEqual(afterSettle.map((e) => e.milestone), ["settlement"]);
  assert.equal(t.closed, true);

  // The chain: index order, reference ids, prevEntryDigest links, digest == sha256(canonicalJson(payload)).
  let prev = null;
  t.entries.forEach((e, i) => {
    assert.equal(e.index, i + 1);
    assert.equal(e.milestone, MILESTONES[i]);
    assert.equal(e.referenceId, `ac-milestone:${RUN}:${i + 1}-${MILESTONES[i]}`);
    assert.equal(e.payload.schema, MILESTONE_LOG_SCHEMA);
    assert.equal(e.payload.prevEntryDigest, prev);
    assert.equal(e.digest, `0x${createHash("sha256").update(canonicalJson(e.payload), "utf8").digest("hex")}`);
    assert.match(e.payload.firstTs, /^2026-10-06T12:/);
    assert.equal(e.status, "anchoring");
    prev = e.digest;
  });
  assert.deepEqual(Object.keys(t.entries[0].payload).sort(), [
    "approvalDigests", "firstTs", "index", "lastTs", "milestone", "prevEntryDigest", "receiptIds", "runId", "schema",
  ]);
  // Nothing more is attributed once closed.
  assert.deepEqual(feed(t, [[rcpt("contract_status")]]), []);
});

test("unit: accepting the first offer seals negotiation EMPTY, still chained", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [rcpt("mandate_submit")], [rcpt("offer_submit")]]);
  const sealed = feed(t, [[rcpt("offer_accept_prepare")], [rcpt("offer_accept_submit")]]);
  assert.deepEqual(sealed.map((e) => e.milestone), ["negotiation", "agreement"]);
  const neg = sealed[0];
  assert.deepEqual(neg.payload.receiptIds, []);
  assert.equal(neg.payload.firstTs, null);
  assert.equal(neg.payload.lastTs, null);
  assert.equal(neg.payload.prevEntryDigest, t.entries[1].digest);
  assert.equal(sealed[1].payload.prevEntryDigest, neg.digest);
});

test("unit: a provider offer before the mandate is held; the mandate seals discover then proposal", () => {
  const t = createMilestoneTracker();
  const pOffer = rcpt("offer_submit");
  const sealedEarly = feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [pOffer]]);
  assert.deepEqual(sealedEarly, []);
  const mandate = rcpt("mandate_submit");
  const sealed = feed(t, [[mandate]]);
  assert.deepEqual(sealed.map((e) => e.milestone), ["discover", "proposal"]);
  assert.ok(sealed[0].payload.receiptIds.includes(mandate.receiptId));
  assert.deepEqual(sealed[1].payload.receiptIds, [pOffer.receiptId]);
});

test("unit: refusals are members but never transitions; late fixed-class calls go to the open milestone", () => {
  const t = createMilestoneTracker();
  const refused = rcpt("mandate_submit", "MANDATE_INVALID");
  assert.deepEqual(feed(t, [[rcpt("contract_bind")], [refused]]), []);
  feed(t, [[rcpt("mandate_submit")], [rcpt("offer_submit")]]);
  const lateQuote = rcpt("catalog_quote");
  const lateMandatePrep = rcpt("mandate_prepare");
  feed(t, [[lateQuote], [lateMandatePrep]]);
  const negBucket = t.buckets[MILESTONES.indexOf("negotiation")];
  assert.deepEqual(negBucket.receiptIds, [lateQuote.receiptId, lateMandatePrep.receiptId]);
  assert.ok(t.entries[0].payload.receiptIds.includes(refused.receiptId));
});

test("unit: anchoring-surface receipts are never milestone members", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind")], [rcpt("anchor", "anchor_anchored", "anchoring")], [rcpt("telemetry_close", "telemetry_close_delivered", "anchoring")]]);
  assert.equal(t.buckets[0].receiptIds.length, 1);
});

test("unit: a walk-away during negotiation seals through negotiation; the rest is not-reached", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [rcpt("mandate_submit")], [rcpt("offer_submit")], [rcpt("offer_reject")]]);
  const sealed = feed(t, [[rcpt("contract_withdraw")]], { terminalAt: 0 });
  assert.deepEqual(sealed.map((e) => e.milestone), ["negotiation"]);
  const rows = renderMilestones(RUN, t, true);
  assert.deepEqual(rows.map((r) => r.status), ["anchoring", "anchoring", "anchoring", "not-reached", "not-reached", "not-reached"]);
  assert.equal(rows[3].assetReferenceId, milestoneReferenceId(RUN, "agreement"));
  assert.equal(rows[3].payload, null);
});

test("unit: render — open while live, lost when a terminal job never closed", () => {
  const t = createMilestoneTracker();
  assert.deepEqual(renderMilestones(RUN, t, false).map((r) => r.status), Array(6).fill("open"));
  assert.deepEqual(renderMilestones(RUN, undefined, false).map((r) => r.status), Array(6).fill("open"));
  assert.deepEqual(renderMilestones(RUN, { closed: false, entries: [] }, true).map((r) => r.status), Array(6).fill("lost"));
  // An empty close (sweep of a run that only ever bound) writes discover only.
  feed(t, [[rcpt("contract_bind")]]);
  assert.deepEqual(closeMilestones(t, RUN).map((e) => e.milestone), ["discover"]);
});

// ============================================================================
// Fake anchoring gateway: a stateful ClockchainClient stub behind the
// PRODUCTION adapter (createTsaContractAnchor) — the same stub-client pattern
// as N4b-9 F17. Records land pending (blockHeight null) or confirmed.
// ============================================================================

function fakeGateway({ pending = false, failMilestoneLog = false } = {}) {
  const records = [];
  const logCalls = [];
  const searches = [];
  const reads = [];
  let n = 0;
  const view = (r) => ({ ...r });
  return {
    records, logCalls, searches, reads,
    milestoneWrites: () => logCalls.filter((c) => c.assetReferenceId.startsWith("ac-milestone:")),
    confirmAll() {
      for (const r of records) if (r.blockHeight === null) r.blockHeight = String(900 + Number(r.ledgerId.split("-")[1]));
    },
    async log(req) {
      logCalls.push(req);
      if (failMilestoneLog && req.assetReferenceId.startsWith("ac-milestone:")) throw new Error("gateway unreachable (fake)");
      n += 1;
      const rec = {
        ledgerId: `ledger-${n}`, assetReferenceId: req.assetReferenceId, assetHash: req.assetHash,
        additionalInfo: req.additionalInfo, blockHeight: pending ? null : String(100 + n),
        createdTimestamp: `2026-10-06T12:00:${String(n).padStart(2, "0")}Z`,
      };
      records.push(rec);
      return view(rec);
    },
    async searchAsset(ref) {
      searches.push(ref);
      return records.filter((r) => r.assetReferenceId === ref).map(view);
    },
    async getLedgerEntry(ledgerId) {
      reads.push(ledgerId);
      const r = records.find((x) => x.ledgerId === ledgerId);
      if (r === undefined) throw new Error("no such ledger entry (fake)");
      return view(r);
    },
  };
}

test("adapter: log writes the bare digest under the reference; a re-issue finds it and never writes twice", async () => {
  const gw = fakeGateway({ pending: true });
  const anchor = createTsaContractAnchor(gw);
  const ref = `ac-milestone:${RUN}:1-discover`;
  const digest = `0x${"ab".repeat(32)}`;
  const first = await anchor.log({ referenceId: ref, digestHex: digest, additionalInfo: "agent contract milestone discover" });
  assert.equal(first.anchorId, ref);
  assert.equal(first.eventHash, digest);
  assert.equal(first.anchor.status, "pending");
  assert.equal(gw.logCalls.length, 1);
  assert.equal(gw.logCalls[0].assetHash, "ab".repeat(32), "the gateway gets bare lower hex");
  assert.equal(gw.logCalls[0].additionalInfo, "agent contract milestone discover");

  const again = await anchor.log({ referenceId: ref, digestHex: digest, additionalInfo: "agent contract milestone discover" });
  assert.equal(gw.logCalls.length, 1, "idempotent per (reference, digest)");
  assert.equal(again.anchor.ledgerId, first.anchor.ledgerId);

  gw.confirmAll();
  const confirmed = await anchor.confirmLog(first.anchor.ledgerId);
  assert.equal(confirmed.status, "anchored");
  assert.notEqual(confirmed.blockHeight, null);

  // A different digest under the same reference is a new write (never silently "found").
  await anchor.log({ referenceId: ref, digestHex: `0x${"cd".repeat(32)}`, additionalInfo: "x" });
  assert.equal(gw.logCalls.length, 2);
  await assert.rejects(anchor.log({ referenceId: ref, digestHex: "0x1234", additionalInfo: "x" }), /malformed/);
});

// ============================================================================
// Integration: the full contract server over HTTP with the fake gateway.
// ============================================================================

/** bind → mandate → buyer offer → provider counter → buyer accepts → book → verify → settle. */
async function negotiatedSettledRun(env, n) {
  const runId = await bindPair(env, uuid(n), "tb1", "tp1");
  const prepM = await env.callTool("tb1", "mandate_prepare", signMandate());
  await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  await env.callTool("tp1", "catalog_quote", {});
  const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  const offered = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  const prepC = await env.callTool("tp1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 12_000 });
  const countered = await signedSubmit(env, { token: "tp1", role: "provider", prepared: prepC, submitTool: "offer_submit" });
  assert.equal(countered.state, "offered", JSON.stringify(countered));
  await env.callTool("tb1", "contract_status", {});
  const prepA = await env.callTool("tb1", "offer_accept_prepare", { offerId: countered.offerId });
  const accepted = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  const prepB = await env.callTool("tp1", "booking_prepare", { agreementId: accepted.agreementId });
  const bookApproval = makeApproval({ envelope: prepB.envelope, role: "provider", action: "booking", tool: "booking_execute", key: keys.providerApproval });
  const booked = await signedSubmit(env, { token: "tp1", role: "provider", prepared: prepB, submitTool: "booking_execute", extraArgs: { approval: bookApproval } });
  assert.ok(booked.orderRef, JSON.stringify(booked));
  const prepV = await env.callTool("tb1", "verification_prepare", { orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}` });
  await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
  const prepS = await env.callTool("tb1", "settlement_prepare", {});
  const settleApproval = makeApproval({ envelope: prepS.envelope, role: "buyer", action: "settlement", tool: "settlement_authorize", key: keys.buyerApproval });
  const settled = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepS, submitTool: "settlement_authorize", extraArgs: { approval: settleApproval } });
  assert.equal(settled.status, "released", JSON.stringify(settled));
  return runId;
}

test("integration: flag on — six chained entries, written in order through the gateway and reported in contract_status", async () => {
  const gw = fakeGateway();
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    assert.equal(env.service.milestoneLog, true);
    const runId = await negotiatedSettledRun(env, 701);
    await waitFor(() => gw.milestoneWrites().length === 6 && env.service.runFor(runId)?.milestoneLog?.entries.every((e) => e.status === "anchored"));
    assert.deepEqual(gw.milestoneWrites().map((c) => c.assetReferenceId),
      MILESTONES.map((m, i) => `ac-milestone:${runId}:${i + 1}-${m}`), "one write per milestone, in index order");

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    const rows = st.anchors.milestones;
    assert.equal(rows.length, 6);
    let prev = null;
    for (const [i, row] of rows.entries()) {
      assert.equal(row.status, "anchored", `${row.milestone}: ${row.error}`);
      assert.equal(row.anchorId, row.assetReferenceId);
      // Anyone can recompute the anchored hash from the published preimage.
      const recomputed = canonicalDigest(row.payload);
      assert.equal(row.digest, recomputed);
      assert.equal(gw.milestoneWrites()[i].assetHash, recomputed.slice(2));
      assert.equal(row.payload.prevEntryDigest, prev);
      assert.equal(row.ledger.blockHeight !== null, true);
      prev = row.digest;
    }

    // Membership against the signed receipt feed.
    const feedOut = env.service.receiptFeed(runId);
    const byTool = (tool) => feedOut.receipts.filter((r) => r.tool === tool).map((r) => r.receiptId);
    const [discover, proposal, negotiation, agreement, execution, settlement] = rows.map((r) => r.payload);
    for (const id of [...byTool("contract_bind"), ...byTool("mandate_prepare"), ...byTool("mandate_submit")]) {
      assert.ok(discover.receiptIds.includes(id), "binds and mandate are discover");
    }
    assert.equal(byTool("contract_bind").length, 2);
    assert.ok(byTool("catalog_quote").every((id) => proposal.receiptIds.includes(id)));
    const [firstOffer, counter] = byTool("offer_submit");
    assert.ok(proposal.receiptIds.includes(firstOffer));
    assert.ok(negotiation.receiptIds.includes(counter));
    assert.ok(byTool("offer_accept_submit").every((id) => agreement.receiptIds.includes(id)));
    assert.ok(byTool("verification_submit").every((id) => execution.receiptIds.includes(id)));
    assert.ok(byTool("settlement_authorize").every((id) => settlement.receiptIds.includes(id)),
      "the terminal call's own receipt is in settlement");
    // Approval digests are the feed's receipt-linked approval digests.
    const approvals = feedOut.approvalRecords;
    assert.deepEqual(execution.approvalDigests, approvals.filter((a) => a.action === "booking").map((a) => a.digest));
    assert.deepEqual(settlement.approvalDigests, approvals.filter((a) => a.action === "settlement").map((a) => a.digest));
    // No secret or business value rides the payload.
    const text = JSON.stringify(rows.map((r) => r.payload));
    for (const leak of ["IT-QW-ONESTOP", "12000", "kb1", "tb1", "orderRef", "Minor"]) assert.equal(text.includes(leak), false, leak);

    // Unchained: no extra receipt names the milestone log.
    assert.equal(feedOut.receipts.some((r) => /milestone/.test(r.tool)), false);
    // The durable job carries the closed log.
    const job = env.service.terminalJobFor(runId);
    assert.equal(job.milestoneLog.closed, true);
    assert.deepEqual(job.milestoneLog.entries.map((e) => e.status), Array(6).fill("anchored"));
  } finally { env.close(); }
});

test("integration: a pending write is re-confirmed to anchored; a failed write is honest and never blocks the deal", async () => {
  const gw = fakeGateway({ pending: true });
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 20, anchorConfirmMaxAttempts: 50 });
  try {
    const runId = await negotiatedSettledRun(env, 702);
    await waitFor(() => env.service.runFor(runId)?.milestoneLog?.entries.length === 6);
    const pend = await env.callTool("tb1", "contract_status", {});
    assert.ok(pend.anchors.milestones.every((r) => r.status === "pending" || r.status === "anchoring"), JSON.stringify(pend.anchors.milestones.map((r) => r.status)));
    assert.equal(statusSchema.safeParse(pend).success, true);
    gw.confirmAll();
    const ok = await waitFor(() => env.service.runFor(runId)?.milestoneLog?.entries.every((e) => e.status === "anchored"));
    assert.ok(ok, "confirmLog resolved every pending entry");
    assert.ok(gw.reads.length > 0, "confirmed by ledger read, not by re-writing");
    assert.equal(gw.milestoneWrites().length, 6);
  } finally { env.close(); }

  const gw2 = fakeGateway({ failMilestoneLog: true });
  const env2 = await boot({ anchor: createTsaContractAnchor(gw2), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const runId = await negotiatedSettledRun(env2, 703);
    await waitFor(() => env2.service.runFor(runId)?.milestoneLog?.entries.filter((e) => e.status === "failed").length === 6);
    const st = await env2.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "settled");
    assert.ok(st.anchors.milestones.every((r) => r.status === "failed" && /gateway unreachable/.test(r.error)));
    // The contract's own anchors are untouched by milestone failures.
    assert.equal(st.anchors.agreement.status, "anchored");
  } finally { env2.close(); }
});

test("integration: boot recovery re-drives a pending entry from the terminal job without a second write", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "milestone-log-"));
  const gw = fakeGateway({ pending: true });
  const env = await boot({ stateDir, anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  let runId;
  try {
    runId = await negotiatedSettledRun(env, 704);
    await waitFor(() => env.service.terminalJobFor(runId)?.milestoneLog?.entries.filter((e) => e.status === "pending").length === 6);
  } finally { env.close(); }
  assert.equal(gw.milestoneWrites().length, 6);
  gw.confirmAll();

  const env2 = await boot({ stateDir, anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const done = await waitFor(() => env2.service.terminalJobFor(runId)?.milestoneLog?.entries.every((e) => e.status === "anchored"));
    assert.ok(done, JSON.stringify(env2.service.terminalJobFor(runId)?.milestoneLog?.entries.map((e) => e.status)));
    assert.equal(gw.milestoneWrites().length, 6, "recovery found the records by reference + hash");
    // Post-restart contract_status renders from the durable job.
    const st = await env2.callTool("tb1", "contract_status", {});
    assert.equal(st.priorRun, true);
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    assert.deepEqual(st.anchors.milestones.map((r) => r.status), Array(6).fill("anchored"));
  } finally { env2.close(); }
});

test("integration: a TTL sweep closes an unfinished run; only reached milestones are written", async () => {
  let clock = Date.now();
  const gw = fakeGateway();
  const env = await boot({
    anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0,
    now: () => clock, runTtlMs: 60_000, expireAtTtl: true,
  });
  try {
    const runId = await bindPair(env, uuid(705), "tb1", "tp1");
    const prepM = await env.callTool("tb1", "mandate_prepare", signMandate());
    await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
    await waitFor(() => gw.milestoneWrites().length === 1);
    clock += 61_000;
    env.service.runFor(runId); // the sweep ends it "expired"
    await waitFor(() => env.service.runFor(runId)?.milestoneLog?.closed === true);
    const rows = (await env.callTool("tb1", "contract_status", {})).anchors.milestones;
    assert.deepEqual(rows.map((r) => r.status), ["anchored", ...Array(5).fill("not-reached")]);
    assert.equal(gw.milestoneWrites().length, 1);
  } finally { env.close(); }
});

// ============================================================================
// Flag off (default): every existing behaviour unchanged.
// ============================================================================

test("flag off: no milestone state, no write, contract_status unchanged — even with a log-capable anchor", async () => {
  const snap = async (opts) => {
    const gw = fakeGateway();
    const env = await boot({ anchor: createTsaContractAnchor(gw), anchorConfirmDelayMs: 0, ...opts });
    try {
      const runId = await negotiatedSettledRun(env, 710);
      await waitFor(() => env.service.terminalJobFor(runId)?.anchors?.terminal?.status === "anchored");
      const st = await env.callTool("tb1", "contract_status", {});
      return { env, gw, runId, st, job: env.service.terminalJobFor(runId), run: env.service.runFor(runId) };
    } finally { env.close(); }
  };
  const off = await snap({});
  const explicitOff = await snap({ milestoneLog: false });
  for (const r of [off, explicitOff]) {
    assert.equal(r.env.service.milestoneLog, false);
    assert.equal(r.gw.milestoneWrites().length, 0);
    assert.equal(r.gw.searches.some((s) => s.startsWith("ac-milestone:")), false);
    assert.equal(r.run.milestoneLog, undefined);
    assert.equal("milestoneLog" in r.job, false);
    assert.equal("milestones" in r.st.anchors, false);
    assert.deepEqual(Object.keys(r.st.anchors).sort(), ["agreement", "terminal"]);
  }
  // Identical status shape and anchor kinds either way.
  const shape = (st) => JSON.stringify(st, (k, v) => (typeof v === "string" ? typeof v : v));
  assert.equal(shape(off.st), shape(explicitOff.st));
  assert.deepEqual(off.gw.logCalls.map((c) => c.additionalInfo), explicitOff.gw.logCalls.map((c) => c.additionalInfo));

  // A plain anchor without `log` (every pre-existing fake) keeps the log inert even when asked.
  const env = await boot({ anchor: fakeAnchor(), milestoneLog: true });
  try {
    assert.equal(env.service.milestoneLog, false);
  } finally { env.close(); }
});

// ============================================================================
// Config: CONTRACT_MILESTONE_LOG.
// ============================================================================

const SERVER_SEED = Buffer.alloc(32, 9);
const baseEnv = (extra = {}) => ({
  CONTRACT_MCP_ENABLED: "1",
  CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
  CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
  CONTRACT_SERVER_ED25519_SEED: SERVER_SEED.toString("base64"),
  CONTRACT_SERVER_KEY_ID: "contract-server-milestones",
  CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
  CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
  CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "milestone-cfg-")),
  ...extra,
});

test("config: CONTRACT_MILESTONE_LOG is a strict 0|1 switch, live only with the anchor enabled", async () => {
  for (const [value, expected] of [[undefined, false], ["", false], ["0", false], ["1", false]]) {
    const cfg = loadContractConfig(baseEnv(value === undefined ? {} : { CONTRACT_MILESTONE_LOG: value }));
    assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
    try { assert.equal(cfg.service.milestoneLog, expected, `CONTRACT_MILESTONE_LOG=${value} without the anchor`); }
    finally { cfg.service.close(); }
  }
  const on = loadContractConfig(baseEnv({ CONTRACT_MILESTONE_LOG: "1", CONTRACT_ANCHOR_ENABLED: "1" }));
  try { assert.equal(on.service.milestoneLog, true); } finally { on.service.close(); }
  const offWithAnchor = loadContractConfig(baseEnv({ CONTRACT_ANCHOR_ENABLED: "1" }));
  try { assert.equal(offWithAnchor.service.milestoneLog, false); } finally { offWithAnchor.service.close(); }

  for (const bad of ["true", "on", "2"]) {
    const cfg = loadContractConfig(baseEnv({ CONTRACT_MILESTONE_LOG: bad }));
    assert.equal(cfg.kind, "misconfigured");
    assert.match(cfg.reason, /CONTRACT_MILESTONE_LOG wants 0 or 1/);
  }

  const warned = await checkConfig(baseEnv({ CONTRACT_MILESTONE_LOG: "1" }));
  assert.equal(warned.exitCode, 0, JSON.stringify(warned.report));
  assert.equal(warned.report.features.milestoneLog, "on");
  assert.match(warned.report.warnings.join("\n"), /CONTRACT_MILESTONE_LOG=1 without CONTRACT_ANCHOR_ENABLED=1/);
  const ready = await checkConfig(baseEnv({ CONTRACT_MILESTONE_LOG: "1", CONTRACT_ANCHOR_ENABLED: "1" }));
  assert.deepEqual(ready.report.warnings, []);
  const off = await checkConfig(baseEnv());
  assert.equal(off.report.features.milestoneLog, "off");
});
