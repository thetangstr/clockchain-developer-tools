import assert from "node:assert/strict";
import test from "node:test";

import {
  boot, bookPair, signedSubmit, makeApproval, signRoleSig,
  keys, uuid,
} from "./n4b9-harness.mjs";

// N4b-9 — F15 (spec D11): the deny submission — server prepare envelope +
// signed `deny` approval, no role signature → blocked_by_policy.

test("F15: a deny submission on settlement_authorize ends blocked_by_policy through the real MCP", async () => {
  const terminalCalls = [];
  const env = await boot({
    onTerminalRun: (run, terminalState) => terminalCalls.push({ runId: run.runId, terminalState }),
  });
  try {
    const { runId, booked } = await bookPair(env, uuid(504), "tb1", "tp1");
    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"cc".repeat(32)}`,
    });
    const verified = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    assert.equal(verified.outcome, "match", JSON.stringify(verified));

    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS.envelope, JSON.stringify(prepS));
    const deny = makeApproval({
      envelope: prepS.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval, decision: "deny",
    });
    // D11: envelope + signed deny + NO signatureHex.
    const out = await env.callTool("tb1", "settlement_authorize", { envelope: prepS.envelope, approval: deny });
    assert.equal(out.error, "POLICY_DENIED", JSON.stringify(out));
    assert.deepEqual(terminalCalls.map((c) => c.terminalState), ["blocked_by_policy"]);
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "blocked_by_policy");
    assert.equal(env.service.runFor(runId).settlement, undefined, "the transfer never ran");
  } finally { env.close(); }
});


test("D11 addendum: booking_cancel_submit refuses a deny approval — deny submissions are execute/authorize-only", async () => {
  const env = await boot();
  try {
    const { runId } = await bookPair(env, uuid(505), "tb1", "tp1");
    const prepC = await env.callTool("tp1", "booking_cancel_prepare", { reason: "mutual_withdrawal" });
    assert.ok(prepC.envelope, JSON.stringify(prepC));
    const deny = makeApproval({
      envelope: prepC.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval, decision: "deny",
    });
    // Signature-free deny submission: signatureHex is mandatory on cancel —
    // refused at the args gate; the cancel never happens.
    const noSig = await env.callTool("tp1", "booking_cancel_submit", {
      envelope: prepC.envelope, approval: deny,
    });
    assert.ok(noSig.error !== undefined || noSig.rpcError !== undefined,
      `a deny submission on cancel is refused, got ${JSON.stringify(noSig)}`);
    assert.notEqual(noSig.status, "CANCELLED");
    // Deny + role signature: the verified deny refuses the cancel with
    // POLICY_DENIED and never ends the run.
    const e = prepC.envelope;
    const sig = signRoleSig(keys.providerSigner.priv, {
      runId: e.runId, role: "provider", tool: e.tool, nonce: e.nonce, payloadDigest: e.payloadDigest,
    });
    const withSig = await env.callTool("tp1", "booking_cancel_submit", {
      envelope: e, signatureHex: sig, approval: deny,
    });
    assert.equal(withSig.error, "POLICY_DENIED", JSON.stringify(withSig));
    const run = env.service.runFor(runId);
    assert.equal(run.cancellation, undefined, "the deny never cancelled");
    assert.equal(run.terminalState, null, "the run stays live");
    // The verified deny record is still retained, bound to the
    // booking_cancel_prepare receipt (R12).
    const feed = env.service.receiptFeed(runId);
    const cancelPrep = feed.receipts.find((r) => r.tool === "booking_cancel_prepare");
    const denyRec = feed.approvalRecords?.find((a) => a.decision === "deny");
    assert.ok(denyRec, "the signed deny is retained as a verified verdict");
    assert.equal(denyRec.digest, cancelPrep.responseDigest);
  } finally { env.close(); }
});
