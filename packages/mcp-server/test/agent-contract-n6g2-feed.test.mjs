import assert from "node:assert/strict";
import test from "node:test";

import { guidanceDigests } from "../dist/agent-contract/tools-list.js";

import {
  boot, agreePair, signedSubmit, makeApproval, keys, uuid,
} from "./n4b9-harness.mjs";

// N6g-2 observer-feed follow-up coverage for the kept hunks: settlement
// approval binding, deny-record retention, and strict guidance equality.
// (R12 booking/cancel binding + H1 simLabels live in
// agent-contract-n6g2-r12.test.mjs.)

test("N6g-2: settlement_authorize approval binds to the settlement_prepare receipt", async () => {
  const env = await boot();
  try {
    const { runId, agreementId } = await agreePair(env, uuid(700), "tb1", "tp1");

    const prepB = await env.callTool("tp1", "booking_prepare", { agreementId });
    const bookApproval = makeApproval({
      envelope: prepB.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
    });
    const booked = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared: prepB,
      submitTool: "booking_execute", extraArgs: { approval: bookApproval },
    });
    assert.ok(booked.orderRef, JSON.stringify(booked));

    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
    });
    const verified = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    assert.equal(verified.flagged, false, JSON.stringify(verified));

    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS.envelope, JSON.stringify(prepS));
    const settleApproval = makeApproval({
      envelope: prepS.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const settled = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize", extraArgs: { approval: settleApproval },
    });
    assert.ok(settled.settlementRef ?? settled.receipt ?? settled.ok !== false, JSON.stringify(settled));

    const feed = env.service.receiptFeed(runId);
    const settlePrepReceipt = feed.receipts.find((r) => r.tool === "settlement_prepare" && r.outcome === "ok");
    assert.ok(settlePrepReceipt);
    const settleRec = feed.approvalRecords?.find((a) => a.action === "settlement" && a.role === "buyer");
    assert.ok(settleRec, "settlement approval retained");
    assert.equal(settleRec.digest, settlePrepReceipt.responseDigest,
      "settlement approval binds to the settlement_prepare receipt");

    // H1: the settlement_prepare envelope receipt is SIMULATED-labelled too.
    assert.ok(feed.simLabels.some((l) => l.receiptId === settlePrepReceipt.receiptId && l.simulated === true));
  } finally { env.close(); }
});

test("N6g-2: a deny submission retains the verified deny record bound to the prepare receipt", async () => {
  const env = await boot();
  try {
    const { runId, agreementId } = await agreePair(env, uuid(701), "tb2", "tp2");

    const prepB = await env.callTool("tp2", "booking_prepare", { agreementId });
    const denyApproval = makeApproval({
      envelope: prepB.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval, decision: "deny",
    });
    // D11: envelope + signed deny, NO role signature → blocked_by_policy.
    const denied = await env.callTool("tp2", "booking_execute", {
      envelope: prepB.envelope, approval: denyApproval,
    });
    assert.equal(denied.error, "POLICY_DENIED", JSON.stringify(denied));

    const feed = env.service.receiptFeed(runId);
    const prepReceipt = feed.receipts.find((r) => r.tool === "booking_prepare" && r.outcome === "ok");
    const denyRec = feed.approvalRecords?.find((a) => a.action === "booking" && a.decision === "deny");
    assert.ok(denyRec, "the signed deny is retained like any verified verdict");
    assert.equal(denyRec.digest, prepReceipt.responseDigest,
      "deny record binds to the prepare receipt's responseDigest");
    assert.equal(denyRec.approverKeyId, keys.providerApproval.keyId);
    assert.equal(feed.runId, runId);
  } finally { env.close(); }
});

test("N6g-2: feed guidance digests equal the published per-role values exactly", async () => {
  const env = await boot();
  try {
    const { runId } = await agreePair(env, uuid(702), "tb1", "tp1");
    const feed = env.service.receiptFeed(runId);
    assert.deepEqual(feed.guidance?.buyer, guidanceDigests("buyer"));
    assert.deepEqual(feed.guidance?.provider, guidanceDigests("provider"));
  } finally { env.close(); }
});
