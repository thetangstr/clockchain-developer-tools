import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTsaContractAnchor } from "../dist/agent-contract/anchor.js";
import { canonicalDigest, canonicalJson } from "../dist/agent-contract/canonical.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import {
  MILESTONES, MILESTONE_LOG_SCHEMA, anchorRefFor, closeMilestones, createMilestoneTracker, milestoneReferenceId,
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
// Unit: attribution, sealing, index-over-anchors and the entry chain (pure tracker).
// ============================================================================

const RUN = "11111111-2222-4333-8444-555555555555";
let seq = 0;
const T0 = Date.parse("2026-10-06T12:00:00.000Z");
const rid = () => `0x${(++seq).toString(16).padStart(64, "0")}`;
const rcpt = (tool, outcome = "ok", surface = "business") => ({ receiptId: rid(), tool, outcome, surface, ts: T0 + seq * 1000 });
const D = (c) => `0x${c.repeat(64)}`;

/** Feed receipts; `steps` are [receipt, approvals?, {bothBound?, terminal?}?]. Returns every entry sealed. */
function feed(t, steps, { anchors = {}, finalAnchors = false } = {}) {
  const sealed = [];
  for (const [r, approvals = [], run = {}] of steps) {
    sealed.push(...observeMilestoneReceipt(t, r, approvals,
      { bothBound: run.bothBound ?? true, terminal: run.terminal ?? false },
      { runId: RUN, now: T0, anchors, finalAnchors }));
  }
  return sealed;
}

test("unit: a negotiated, settled deal seals six chained entries at their transitions", () => {
  const t = createMilestoneTracker();
  const bindB = rcpt("contract_bind");
  const bindP = rcpt("contract_bind");
  assert.deepEqual(feed(t, [[bindB, [], { bothBound: false }]]), [], "one bind does not complete discover");
  const afterBinds = feed(t, [[bindP]]);
  assert.deepEqual(afterBinds.map((e) => e.milestone), ["discover"], "both binds complete discover");
  assert.deepEqual(afterBinds[0].payload.receiptIds, [bindB, bindP].map((r) => r.receiptId).sort());

  const mPrep = rcpt("mandate_prepare");
  const mSub = rcpt("mandate_submit");
  const quote = rcpt("catalog_quote");
  const poll1 = rcpt("contract_status");
  const oPrep = rcpt("offer_prepare");
  const oSub = rcpt("offer_submit");
  const afterOffer = feed(t, [[mPrep], [mSub], [quote], [poll1], [oPrep], [oSub]]);
  assert.deepEqual(afterOffer.map((e) => e.milestone), ["proposal"], "the first offer completes proposal");
  assert.deepEqual(afterOffer[0].payload.receiptIds, [mPrep, mSub, quote, oPrep, oSub].map((r) => r.receiptId).sort(),
    "the mandate is proposal; the poll is not a member");
  assert.equal(afterOffer[0].payload.pollCount, 1);

  const cPrep = rcpt("offer_prepare");
  const cSub = rcpt("offer_submit");
  const poll = rcpt("contract_status");
  const aPrep = rcpt("offer_accept_prepare");
  const aSub = rcpt("offer_accept_submit");
  const afterAccept = feed(t, [[cPrep], [cSub], [poll], [rcpt("settlement_status")], [aPrep], [aSub]]);
  assert.deepEqual(afterAccept.map((e) => e.milestone), ["negotiation", "agreement"]);
  assert.deepEqual(afterAccept[0].payload.receiptIds, [cPrep, cSub].map((r) => r.receiptId).sort());
  assert.equal(afterAccept[0].payload.pollCount, 2);

  const bookApproval = D("b");
  const afterVerify = feed(t, [[rcpt("booking_prepare")], [rcpt("booking_execute"), [bookApproval]], [rcpt("verification_prepare")], [rcpt("verification_submit")]]);
  assert.deepEqual(afterVerify.map((e) => e.milestone), ["execution"]);
  assert.deepEqual(afterVerify[0].payload.approvalDigests, [bookApproval]);

  const settleApproval = D("5");
  const afterSettle = feed(t, [[rcpt("settlement_prepare")], [rcpt("settlement_authorize"), [settleApproval], { terminal: true }]]);
  assert.deepEqual(afterSettle.map((e) => e.milestone), ["settlement"]);
  assert.equal(t.closed, true);

  let prev = null;
  t.entries.forEach((e, i) => {
    assert.equal(e.index, i + 1);
    assert.equal(e.milestone, MILESTONES[i]);
    assert.equal(e.referenceId, `ac-milestone:${RUN}:${i + 1}-${MILESTONES[i]}`);
    assert.equal(e.payload.schema, MILESTONE_LOG_SCHEMA);
    assert.equal(e.payload.prevEntryDigest, prev);
    assert.equal(e.digest, `0x${createHash("sha256").update(canonicalJson(e.payload), "utf8").digest("hex")}`);
    assert.equal(e.source, "own-write", "no server anchors were recorded");
    assert.equal(e.payload.anchorRef, null);
    assert.equal(e.sealedAt, new Date(T0).toISOString());
    prev = e.digest;
  });
  assert.deepEqual(Object.keys(t.entries[0].payload).sort(), [
    "anchorRef", "approvalDigests", "firstTs", "index", "lastTs", "milestone", "pollCount", "prevEntryDigest", "receiptIds", "runId", "schema",
  ]);
  assert.deepEqual(feed(t, [[rcpt("contract_status")]]), [], "nothing is attributed once closed");
});

test("unit: index over anchors — terms covers discover, agreement covers agreement, final covers settlement", () => {
  const t = createMilestoneTracker();
  const anchors = { terms: { digest: D("1") }, agreement: { digest: D("2") } };
  const opts = { anchors, finalAnchors: true };
  feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [rcpt("offer_submit")], [rcpt("offer_accept_submit")],
    [rcpt("verification_submit")], [rcpt("settlement_authorize"), [], { terminal: true }]], opts);
  assert.deepEqual(t.entries.map((e) => e.source),
    ["track-b-anchor", "own-write", "own-write", "track-b-anchor", "own-write", "track-b-anchor"]);
  assert.deepEqual(t.entries[0].payload.anchorRef, { kind: "terms", digest: D("1") });
  assert.deepEqual(t.entries[3].payload.anchorRef, { kind: "agreement", digest: D("2") });
  assert.deepEqual(t.entries[5].payload.anchorRef, { kind: "final", digest: null });
  // The chain still runs through every entry.
  for (let i = 1; i < 6; i++) assert.equal(t.entries[i].payload.prevEntryDigest, t.entries[i - 1].digest);
  // Without CONTRACT_SERVER_ANCHORS: no terms, no final → own writes.
  assert.equal(anchorRefFor("discover", { agreement: { digest: D("2") } }, false), null);
  assert.equal(anchorRefFor("settlement", {}, false), null);
  assert.deepEqual(anchorRefFor("discover", { brief: { digest: D("3") } }, true), { kind: "brief", digest: D("3") });

  // Render: a referenced row takes the referenced anchor's state.
  const ledger = { ledgerId: "L-7", blockHeight: "77", time: "2026-10-06T12:01:00Z", status: "anchored" };
  const rows = renderMilestones(RUN, t, {
    terms: { status: "anchored", digest: D("1"), anchorId: "tsa:t", eventHash: D("a"), ledger },
    agreement: { status: "failed", digest: D("2"), error: "boom" },
  });
  assert.equal(rows[0].status, "anchored");
  assert.equal(rows[0].assetHash, D("a"));
  assert.equal(rows[0].ledgerId, "L-7");
  assert.equal(rows[0].anchoredAt, ledger.time);
  assert.equal(rows[3].status, "failed");
  assert.equal(rows[3].error, "boom");
  assert.equal(rows[5].status, "awaiting-anchor", "final not fired yet");
  assert.equal(rows[1].assetHash, rows[1].digest, "an own write's asset hash is its digest");
});

test("unit: accepting the first offer seals negotiation EMPTY, still chained", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [rcpt("mandate_submit")], [rcpt("offer_submit")]]);
  const sealed = feed(t, [[rcpt("offer_accept_prepare")], [rcpt("offer_accept_submit")]]);
  assert.deepEqual(sealed.map((e) => e.milestone), ["negotiation", "agreement"]);
  const neg = sealed[0];
  assert.deepEqual(neg.payload.receiptIds, []);
  assert.equal(neg.payload.firstTs, null);
  assert.equal(neg.payload.prevEntryDigest, t.entries[1].digest);
  assert.equal(sealed[1].payload.prevEntryDigest, neg.digest);
});

test("unit: refusals are members but never transitions; late fixed-class calls go to the open milestone", () => {
  const t = createMilestoneTracker();
  const refused = rcpt("contract_bind", "CERTIFICATE_INVALID");
  assert.deepEqual(feed(t, [[refused]]), []);
  feed(t, [[rcpt("contract_bind")], [rcpt("offer_submit")]]);
  const lateQuote = rcpt("catalog_quote");
  const lateMandatePrep = rcpt("mandate_prepare");
  feed(t, [[lateQuote], [lateMandatePrep]]);
  assert.deepEqual(t.buckets[MILESTONES.indexOf("negotiation")].receiptIds, [lateQuote.receiptId, lateMandatePrep.receiptId]);
  assert.ok(t.entries[0].payload.receiptIds.includes(refused.receiptId));
});

test("unit: anchoring-surface receipts are never members or polls", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind"), [], { bothBound: false }], [rcpt("anchor", "anchor_anchored", "anchoring")], [rcpt("telemetry_close", "telemetry_close_delivered", "anchoring")]]);
  assert.equal(t.buckets[0].receiptIds.length, 1);
  assert.equal(t.buckets[0].pollCount, 0);
});

test("unit: a walk-away during negotiation seals through negotiation; the rest is not-reached", () => {
  const t = createMilestoneTracker();
  feed(t, [[rcpt("contract_bind")], [rcpt("contract_bind")], [rcpt("mandate_submit")], [rcpt("offer_submit")], [rcpt("offer_reject")]]);
  const sealed = feed(t, [[rcpt("contract_withdraw"), [], { terminal: true }]]);
  assert.deepEqual(sealed.map((e) => e.milestone), ["negotiation"]);
  const rows = renderMilestones(RUN, t, {});
  assert.deepEqual(rows.map((r) => r.status), ["anchoring", "anchoring", "anchoring", "not-reached", "not-reached", "not-reached"]);
  assert.equal(rows[3].assetReferenceId, milestoneReferenceId(RUN, "agreement"));
  assert.equal(rows[3].payload, null);
});

test("unit: render — open while live, interrupted when the run was lost", () => {
  const t = createMilestoneTracker();
  assert.deepEqual(renderMilestones(RUN, t, {}).map((r) => r.status), Array(6).fill("open"));
  assert.deepEqual(renderMilestones(RUN, undefined, undefined).map((r) => r.status), Array(6).fill("open"));
  assert.deepEqual(renderMilestones(RUN, { ...t, closed: true, interrupted: true }, {}).map((r) => r.status), Array(6).fill("interrupted"));
  feed(t, [[rcpt("contract_bind"), [], { bothBound: false }]]);
  assert.deepEqual(closeMilestones(t, { runId: RUN, now: T0, anchors: {}, finalAnchors: false }).map((e) => e.milestone), ["discover"]);
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

const OWN_WITHOUT_SERVER_ANCHORS = ["discover", "proposal", "negotiation", "execution", "settlement"];
const ownRefs = (runId, names) => names.map((m) => `ac-milestone:${runId}:${MILESTONES.indexOf(m) + 1}-${m}`);
const ownEntries = (t) => (t?.entries ?? []).filter((e) => e.source === "own-write");

test("integration: flag on — six chained entries; agreement indexed to its anchor, the rest written in order", async () => {
  const gw = fakeGateway();
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    assert.equal(env.service.milestoneLog, true);
    const runId = await negotiatedSettledRun(env, 701);
    await waitFor(() => gw.milestoneWrites().length === 5 && ownEntries(env.service.runFor(runId)?.milestoneLog).every((e) => e.status === "anchored"));
    assert.deepEqual(gw.milestoneWrites().map((c) => c.assetReferenceId), ownRefs(runId, OWN_WITHOUT_SERVER_ANCHORS),
      "one write per uncovered milestone, in index order");

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    const rows = st.anchors.milestones;
    assert.equal(rows.length, 6);
    let prev = null;
    for (const row of rows) {
      assert.equal(row.status, "anchored", `${row.milestone}: ${row.error}`);
      assert.equal(row.digest, canonicalDigest(row.payload), "anyone can recompute the chain digest");
      assert.equal(row.payload.prevEntryDigest, prev);
      assert.ok(row.ledgerId && row.blockHeight && row.sealedAt && row.anchoredAt, JSON.stringify(row));
      prev = row.digest;
    }
    const own = rows.filter((r) => r.source === "own-write");
    assert.deepEqual(own.map((r) => r.milestone), OWN_WITHOUT_SERVER_ANCHORS);
    own.forEach((row, i) => {
      assert.equal(row.anchorId, row.assetReferenceId);
      assert.equal(row.assetHash, row.digest);
      assert.equal(gw.milestoneWrites()[i].assetHash, row.digest.slice(2));
    });
    const agreementRow = rows[3];
    assert.equal(agreementRow.source, "track-b-anchor");
    assert.deepEqual(agreementRow.anchorRef, { kind: "agreement", digest: st.anchors.agreement.digest });
    assert.equal(agreementRow.assetHash, st.anchors.agreement.eventHash);
    assert.equal(agreementRow.ledgerId, st.anchors.agreement.ledger.ledgerId);

    // Membership against the signed receipt feed.
    const feedOut = env.service.receiptFeed(runId);
    const byTool = (tool) => feedOut.receipts.filter((r) => r.tool === tool).map((r) => r.receiptId);
    const [discover, proposal, negotiation, agreement, execution, settlement] = rows.map((r) => r.payload);
    assert.deepEqual(discover.receiptIds, [...byTool("contract_bind")].sort(), "discover is exactly the two binds");
    for (const id of [...byTool("mandate_prepare"), ...byTool("mandate_submit"), ...byTool("catalog_quote")]) {
      assert.ok(proposal.receiptIds.includes(id), "the mandate and the quote are proposal");
    }
    const [firstOffer, counter] = byTool("offer_submit");
    assert.ok(proposal.receiptIds.includes(firstOffer));
    assert.ok(negotiation.receiptIds.includes(counter));
    assert.equal(negotiation.pollCount, 1, "the status poll is counted, not a member");
    assert.ok(byTool("contract_status").every((id) => !rows.some((r) => r.payload.receiptIds.includes(id))));
    assert.ok(byTool("offer_accept_submit").every((id) => agreement.receiptIds.includes(id)));
    assert.ok(byTool("verification_submit").every((id) => execution.receiptIds.includes(id)));
    assert.ok(byTool("settlement_authorize").every((id) => settlement.receiptIds.includes(id)),
      "the terminal call's own receipt is in settlement");
    const approvals = feedOut.approvalRecords;
    assert.deepEqual(execution.approvalDigests, approvals.filter((a) => a.action === "booking").map((a) => a.digest));
    assert.deepEqual(settlement.approvalDigests, approvals.filter((a) => a.action === "settlement").map((a) => a.digest));
    const text = JSON.stringify(rows.map((r) => r.payload));
    for (const leak of ["IT-QW-ONESTOP", "12000", "kb1", "tb1", "orderRef", "Minor"]) assert.equal(text.includes(leak), false, leak);
    assert.equal(feedOut.receipts.some((r) => /milestone/.test(r.tool)), false, "unchained");

    // Clockchain calls: agreement + terminal tsa writes, 5 milestone writes, 5 milestone lookups.
    assert.deepEqual(st.anchors.clockchainCalls, { writes: 7, lookups: 5 });
    assert.ok(st.anchors.clockchainCalls.writes + st.anchors.clockchainCalls.lookups <= 12);
    const job = env.service.terminalJobFor(runId);
    assert.equal(job.milestoneLog.closed, true);
    assert.deepEqual(job.clockchainCalls, { writes: 7, lookups: 5 });
  } finally { env.close(); }
});

test("integration: with CONTRACT_SERVER_ANCHORS terms covers discover and final covers settlement — 3 own writes", async () => {
  const gw = fakeGateway();
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, serverAnchors: true, anchorConfirmDelayMs: 0 });
  try {
    const runId = await negotiatedSettledRun(env, 706);
    await waitFor(() => env.service.runFor(runId)?.anchors?.final?.status === "anchored" && gw.milestoneWrites().length === 3);
    assert.deepEqual(gw.milestoneWrites().map((c) => c.assetReferenceId), ownRefs(runId, ["proposal", "negotiation", "execution"]));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    const rows = st.anchors.milestones;
    assert.deepEqual(rows.map((r) => r.source), ["track-b-anchor", "own-write", "own-write", "track-b-anchor", "own-write", "track-b-anchor"]);
    assert.ok(rows.every((r) => r.status === "anchored"), JSON.stringify(rows.map((r) => [r.milestone, r.status])));
    assert.deepEqual(rows[0].anchorRef, { kind: "terms", digest: st.anchors.terms.digest });
    assert.equal(rows[0].assetHash, st.anchors.terms.eventHash);
    assert.deepEqual(rows[5].anchorRef, { kind: "final", digest: st.anchors.final.digest }, "final's subject is filled in once it fires");
    assert.equal(rows[5].payload.anchorRef.digest, null);
    assert.equal(rows[5].ledgerId, st.anchors.final.ledger.ledgerId);
    // terms + agreement + terminal + final writes, 3 milestone writes + 3 lookups.
    assert.deepEqual(st.anchors.clockchainCalls, { writes: 7, lookups: 3 });
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
    const ok = await waitFor(() => ownEntries(env.service.runFor(runId)?.milestoneLog).every((e) => e.status === "anchored"));
    assert.ok(ok, "confirmLog resolved every pending entry");
    assert.ok(gw.reads.length > 0, "confirmed by ledger read, not by re-writing");
    assert.equal(gw.milestoneWrites().length, 5);
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(st.anchors.clockchainCalls.lookups > 5, "confirm reads are counted");
  } finally { env.close(); }

  const gw2 = fakeGateway({ failMilestoneLog: true });
  const env2 = await boot({ anchor: createTsaContractAnchor(gw2), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const runId = await negotiatedSettledRun(env2, 703);
    await waitFor(() => ownEntries(env2.service.runFor(runId)?.milestoneLog).filter((e) => e.status === "failed").length === 5);
    const st = await env2.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "settled");
    const own = st.anchors.milestones.filter((r) => r.source === "own-write");
    assert.ok(own.every((r) => r.status === "failed" && /gateway unreachable/.test(r.error)));
    assert.equal(st.anchors.milestones[3].status, "anchored", "the referenced agreement anchor is unaffected");
    assert.equal(st.anchors.agreement.status, "anchored");
  } finally { env2.close(); }
});

test("integration: boot recovery re-drives pending entries from the terminal job without a second write", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "milestone-log-"));
  const gw = fakeGateway({ pending: true });
  const env = await boot({ stateDir, anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  let runId;
  try {
    runId = await negotiatedSettledRun(env, 704);
    await waitFor(() => ownEntries(env.service.terminalJobFor(runId)?.milestoneLog).filter((e) => e.status === "pending").length === 5);
  } finally { env.close(); }
  assert.equal(gw.milestoneWrites().length, 5);
  gw.confirmAll();

  const env2 = await boot({ stateDir, anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const done = await waitFor(() => {
      const job = env2.service.terminalJobFor(runId);
      return ownEntries(job?.milestoneLog).every((e) => e.status === "anchored") && job?.anchors?.agreement?.status === "anchored";
    });
    assert.ok(done, JSON.stringify(env2.service.terminalJobFor(runId)?.milestoneLog?.entries.map((e) => e.status)));
    assert.equal(gw.milestoneWrites().length, 5, "recovery found the records by reference + hash");
    const st = await env2.callTool("tb1", "contract_status", {});
    assert.equal(st.priorRun, true);
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    assert.deepEqual(st.anchors.milestones.map((r) => r.status), Array(6).fill("anchored"));
    assert.ok(st.anchors.clockchainCalls.writes >= 7, "counts survive the restart");
  } finally { env2.close(); }
});

/** Copy the durable terminal-jobs file as it is NOW — the disk a crash at this instant leaves. */
function crashCopy(stateDir) {
  const dir = mkdtempSync(path.join(tmpdir(), "milestone-crash-"));
  copyFileSync(path.join(stateDir, "terminal-jobs.json"), path.join(dir, "terminal-jobs.json"));
  return dir;
}

test("integration: crash between the terminal transition and the seal — a restart seals and writes it, nothing lost", async () => {
  const gw = fakeGateway();
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  let runId;
  let crashDir;
  let lastOfferId;
  try {
    runId = await bindPair(env, uuid(707), "tb1", "tp1");
    const prepM = await env.callTool("tb1", "mandate_prepare", signMandate());
    await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
    const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
    await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
    await waitFor(() => gw.milestoneWrites().length === 2);
    // The run ends (a harness_error) — and the process dies before the close macrotask runs.
    const run = env.service.runFor(runId);
    env.service.endRun(run, "harness_error");
    crashDir = crashCopy(env.stateDir);
    lastOfferId = run.receipts.at(-1).receiptId;
  } finally { env.close(); }
  const onDisk = JSON.parse(readFileSync(path.join(crashDir, "terminal-jobs.json"), "utf8")).jobs.find((j) => j.runId === runId);
  assert.equal(onDisk.terminalState, "harness_error");
  assert.equal(onDisk.milestoneLog.closed, false, "the crash landed before the close");
  assert.equal(onDisk.milestoneLog.sealed, 2);

  const gw2 = fakeGateway();
  const env2 = await boot({ stateDir: crashDir, anchor: createTsaContractAnchor(gw2), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const closed = await waitFor(() => env2.service.terminalJobFor(runId)?.milestoneLog?.closed === true &&
      ownEntries(env2.service.terminalJobFor(runId).milestoneLog).every((e) => e.status === "anchored"));
    assert.ok(closed);
    const rows = (await env2.callTool("tb1", "contract_status", {})).anchors.milestones;
    // The offer was the last evidence: proposal was already sealed, so the close seals nothing new;
    // nothing reads "lost" or "interrupted" — the unreached ones are not-reached.
    assert.deepEqual(rows.map((r) => r.status), ["anchored", "anchored", ...Array(4).fill("not-reached")]);
    assert.ok(rows[1].payload.receiptIds.includes(lastOfferId));
  } finally { env2.close(); }
});

test("integration: crash after evidence accumulated past the last seal — the restart seals it from the persisted buckets", async () => {
  const gw = fakeGateway();
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  let runId;
  let crashDir;
  let rejectId;
  try {
    runId = await bindPair(env, uuid(708), "tb1", "tp1");
    const prepM = await env.callTool("tb1", "mandate_prepare", signMandate());
    await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
    const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
    const offered = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
    const rejected = await env.callTool("tp1", "offer_reject", { offerId: offered.offerId });
    assert.ok(!rejected.error, JSON.stringify(rejected));
    await waitFor(() => gw.milestoneWrites().length === 2);
    const run = env.service.runFor(runId);
    rejectId = run.receipts.at(-1).receiptId;
    env.service.endRun(run, "no_agreement");
    crashDir = crashCopy(env.stateDir);
  } finally { env.close(); }

  const gw2 = fakeGateway();
  const env2 = await boot({ stateDir: crashDir, anchor: createTsaContractAnchor(gw2), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    await waitFor(() => ownEntries(env2.service.terminalJobFor(runId)?.milestoneLog).length === 3 &&
      ownEntries(env2.service.terminalJobFor(runId).milestoneLog).every((e) => e.status === "anchored"));
    assert.deepEqual(gw2.milestoneWrites().map((c) => c.assetReferenceId), ownRefs(runId, ["negotiation"]),
      "only the entry the crash left unsealed is written; sealed ones were already on the ledger");
    const rows = (await env2.callTool("tb1", "contract_status", {})).anchors.milestones;
    assert.deepEqual(rows.map((r) => r.status), ["anchored", "anchored", "anchored", "not-reached", "not-reached", "not-reached"]);
    assert.deepEqual(rows[2].payload.receiptIds, [rejectId]);
    assert.equal(rows[2].payload.prevEntryDigest, rows[1].digest);
  } finally { env2.close(); }
});

test("integration: a live run lost to a restart is interrupted — its sealed entries still land", async () => {
  const gw = fakeGateway({ pending: true });
  const env = await boot({ anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  let runId;
  let crashDir;
  try {
    runId = await bindPair(env, uuid(709), "tb1", "tp1");
    await waitFor(() => env.service.terminalJobFor(runId)?.milestoneLog?.entries[0]?.status === "pending");
    crashDir = crashCopy(env.stateDir);
  } finally { env.close(); }
  gw.confirmAll();
  const env2 = await boot({ stateDir: crashDir, anchor: createTsaContractAnchor(gw), milestoneLog: true, anchorConfirmDelayMs: 0 });
  try {
    const ok = await waitFor(() => env2.service.terminalJobFor(runId)?.milestoneLog?.entries[0]?.status === "anchored");
    assert.ok(ok);
    const ml = env2.service.terminalJobFor(runId).milestoneLog;
    assert.equal(ml.interrupted, true);
    assert.equal(gw.milestoneWrites().length, 1, "re-driven without a second write");
    assert.equal(env2.service.pendingTerminalJobs().some((j) => j.runId === runId), false, "the job is finished");
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
    await waitFor(() => env.service.runFor(runId)?.milestoneLog?.closed === true && gw.milestoneWrites().length === 2);
    const rows = (await env.callTool("tb1", "contract_status", {})).anchors.milestones;
    assert.deepEqual(rows.map((r) => r.status), ["anchored", "anchored", ...Array(4).fill("not-reached")]);
    assert.ok(rows[1].payload.receiptIds.length >= 2, "the mandate is proposal evidence");
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
    assert.deepEqual(Object.keys(r.st.anchors).sort(), ["agreement", "terminal"], "no milestones, no clockchainCalls");
    assert.equal(r.env.service.clockchainCallsFor(r.runId), undefined);
    assert.equal("clockchainCalls" in r.job, false);
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
