import assert from "node:assert/strict";
import test from "node:test";

import {
  boot, bookPair, signedSubmit, makeApproval,
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

