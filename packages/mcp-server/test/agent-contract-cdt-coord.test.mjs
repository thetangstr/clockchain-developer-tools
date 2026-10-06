import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { eip191SignDigest32 } from "../dist/agent-contract/eip191.js";
import { createRunRouter } from "../dist/agent-contract/run-routing.js";
import {
  createPolicyRegistry, policyRegistrationDigest,
} from "../dist/agent-contract/policy-registry.js";
import { parseContractBriefs } from "../dist/agent-contract/server-anchors.js";
import {
  boot, agreePair, bookPair, signedSubmit, makeApproval, fakeAnchor, waitFor,
  statusSchema, keys, uuid, SIGNER, serverPubKey, PRINCIPAL_ADDRESS, POLICY_DIGEST,
} from "./n4b9-harness.mjs";

// cdt-coord (mcp-coordination-design.md): O-3 routing by (keyId,
// mcpSessionId) with a per-keyId cap, contract_register_policy (mandates
// without a restart), and the server-side terms / brief / final anchors.

/** The env bound to one named MCP session per token (`<token>#<suffix>`). */
const viaSession = (env, suffix) => ({
  ...env,
  callTool: (token, name, args = {}) => env.callTool(token, name, args, `${token}#${suffix}`),
});

// ============================================================================
// O-3 — live runs keyed by (keyId, mcpSessionId), per-keyId cap.
// ============================================================================

test("O-3: the run router keeps the shared slot at cap 1 and per-session slots above it", () => {
  const one = createRunRouter(undefined);
  assert.equal(one.cap, 1);
  assert.equal(one.slotFor("s-a"), "*");
  assert.equal(one.chainKey("kb1", "s-a"), "kb1");
  one.set("kb1", "*", "run-x");
  assert.equal(one.get("kb1", "s-b"), "run-x", "cap 1: every session of the key reaches the run");

  const two = createRunRouter(2);
  two.set("kb1", two.slotFor("s-a"), "run-x");
  two.set("kb1", two.slotFor("s-b"), "run-y");
  assert.equal(two.get("kb1", "s-a"), "run-x");
  assert.equal(two.get("kb1", "s-b"), "run-y");
  assert.equal(two.get("kb1", "s-c"), undefined);
  assert.notEqual(two.chainKey("kb1", "s-a"), two.chainKey("kb1", "s-b"));
  assert.deepEqual(two.runIds("kb1").sort(), ["run-x", "run-y"]);
  two.dropRun("run-x");
  assert.deepEqual(two.runIds("kb1"), ["run-y"]);
  assert.throws(() => createRunRouter(0));
  assert.throws(() => createRunRouter(65));
});

test("O-3: two concurrent sessions of one buyer key under cap=2 stay isolated", async () => {
  const env = await boot({ maxRunsPerKey: 2 });
  try {
    const a = viaSession(env, "A");
    const b = viaSession(env, "B");
    const x = await agreePair(a, uuid(901), "tb1", "tp1");
    const y = await agreePair(b, uuid(902), "tb1", "tp2");
    assert.notEqual(x.runId, y.runId);

    const sidA = env.sessionIdOf("tb1#A");
    const sidB = env.sessionIdOf("tb1#B");
    assert.equal(env.service.runIdForPrincipal("kb1", sidA), x.runId);
    assert.equal(env.service.runIdForPrincipal("kb1", sidB), y.runId);

    // Each session's calls land on its own run chain only.
    await a.callTool("tb1", "contract_status", {});
    await b.callTool("tb1", "contract_status", {});
    const feedX = env.service.receiptFeed(x.runId).receipts;
    const feedY = env.service.receiptFeed(y.runId).receipts;
    const buyerSessions = (feed) => new Set(feed.filter((r) => r.principal.keyId === "kb1").map((r) => r.mcpSessionId));
    assert.deepEqual([...buyerSessions(feedX)], [sidA]);
    assert.deepEqual([...buyerSessions(feedY)], [sidB]);
    const keys = { [SIGNER.keyId]: serverPubKey };
    assert.equal(verifyChain(feedX, keys).ok, true);
    assert.equal(verifyChain(feedY, keys).ok, true);

    // Each run's agreement is visible only through its own session.
    const gotA = await a.callTool("tb1", "agreement_get", {});
    const gotB = await b.callTool("tb1", "agreement_get", {});
    assert.equal(gotA.anchor?.runId, x.runId, JSON.stringify(gotA));
    assert.equal(gotB.anchor?.runId, y.runId, JSON.stringify(gotB));
    assert.notEqual(gotA.anchor.agreementDigest, gotB.anchor.agreementDigest);

    // The cap holds: a third concurrent session of the key is refused.
    const c = viaSession(env, "C");
    await assert.rejects(agreePair(c, uuid(903), "tb1", "tp1"), /STATE_REFUSED/);
  } finally { env.close(); }
});

test("O-3: at the default cap=1 a second session of the key is still refused", async () => {
  const env = await boot();
  try {
    const x = await agreePair(viaSession(env, "A"), uuid(911), "tb1", "tp1");
    await assert.rejects(agreePair(viaSession(env, "B"), uuid(912), "tb1", "tp2"), /STATE_REFUSED/);
    // Today's behaviour: every session of the key routes to the one live run.
    const sidB = env.sessionIdOf("tb1#B");
    assert.equal(env.service.runIdForPrincipal("kb1", sidB), x.runId);
    const st = await viaSession(env, "B").callTool("tb1", "agreement_get", {});
    assert.equal(st.anchor?.runId, x.runId, JSON.stringify(st));
  } finally { env.close(); }
});

// ============================================================================
// contract_register_policy — mandates without a restart.
// ============================================================================

const POLICY_D = `0x${"5a".repeat(32)}`;
const inHours = (h) => new Date(Date.now() + h * 3600_000).toISOString();

function signPolicy({ tokenKeyId = "kb1", digest = POLICY_D, expiresAt = inHours(1), priv = keys.principal.priv } = {}) {
  const d = policyRegistrationDigest({ tokenKeyId, digest, expiresAt });
  return {
    role: "buyer", digest, expiresAt,
    principalSig: eip191SignDigest32(Buffer.from(d.slice(2), "hex"), priv),
  };
}

test("register_policy: wrong signer, expired, too-long, replayed and provider callers are refused", async () => {
  const env = await boot();
  try {
    const wrong = await env.callTool("tb1", "contract_register_policy", signPolicy({ priv: keys.buyerSigner.priv }));
    assert.equal(wrong.error, "SIGNATURE_INVALID", JSON.stringify(wrong));

    // Signed for a different keyId: the recovered digest does not match.
    const otherKey = await env.callTool("tb1", "contract_register_policy", signPolicy({ tokenKeyId: "kb2" }));
    assert.equal(otherKey.error, "SIGNATURE_INVALID");

    const expired = await env.callTool("tb1", "contract_register_policy",
      signPolicy({ expiresAt: new Date(Date.now() - 1000).toISOString() }));
    assert.equal(expired.error, "PAYLOAD_INVALID", JSON.stringify(expired));
    const tooLong = await env.callTool("tb1", "contract_register_policy", signPolicy({ expiresAt: inHours(25) }));
    assert.equal(tooLong.error, "PAYLOAD_INVALID");

    const signed = signPolicy();
    const first = await env.callTool("tb1", "contract_register_policy", signed);
    assert.equal(first.registered, true, JSON.stringify(first));
    assert.equal(first.digest, POLICY_D);
    assert.match(first.registrationId, /^0x[0-9a-f]{64}$/);
    const replay = await env.callTool("tb1", "contract_register_policy", signed);
    assert.equal(replay.error, "NONCE_REUSED", JSON.stringify(replay));

    const provider = await env.callTool("tp1", "contract_register_policy", signPolicy());
    assert.equal(provider.error, "ROLE_REFUSED");

    // Every call — refusals included — is receipted on the caller's pre-bind chain.
    const feed = env.service.preBindFeed("kb1");
    const regs = feed.receipts.filter((r) => r.tool === "contract_register_policy");
    assert.equal(regs.length, 6);
    assert.equal(regs.filter((r) => r.outcome === "ok").length, 1);
  } finally { env.close(); }
});

test("register_policy: the per-role 64-digest cap counts env pins plus live registrations", async () => {
  const env = await boot();
  try {
    // The env pins one buyer digest; 63 registrations fill the cap.
    for (let i = 1; i <= 63; i += 1) {
      const digest = `0x${i.toString(16).padStart(64, "0")}`;
      const r = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ digest }));
      assert.equal(r.ok, true, `registration ${i}`);
    }
    const over = await env.callTool("tb1", "contract_register_policy", signPolicy({ digest: `0x${"ee".repeat(32)}` }));
    assert.equal(over.error, "RATE_LIMITED", JSON.stringify(over));
    // An already-allowed digest is not "new" — re-registering it stays under the cap.
    const again = await env.callTool("tb1", "contract_register_policy", signPolicy({ digest: POLICY_DIGEST }));
    assert.equal(again.registered, true, JSON.stringify(again));
  } finally { env.close(); }
});

test("register_policy: a registered digest authorizes an approval without a restart, survives one, and expires", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-coord-policy-"));
  const env = await boot({ stateDir });
  let envOpen = true;
  let env2;
  try {
    const { orderRef } = await bookPair(env, uuid(921), "tb1", "tp1").then((r) => ({ orderRef: r.booked.orderRef }));
    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
    });
    const verified = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    assert.equal(verified.flagged, false, JSON.stringify(verified));

    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS.envelope, JSON.stringify(prepS));
    const approvalFor = (prepared) => makeApproval({
      envelope: prepared.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval, policyDigest: POLICY_D,
    });
    // Before registration the unknown policy digest is refused.
    const refused = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize", extraArgs: { approval: approvalFor(prepS) },
    });
    assert.notEqual(refused.status, "released", JSON.stringify(refused));
    assert.ok(refused.error, JSON.stringify(refused));

    const reg = await env.callTool("tb1", "contract_register_policy", signPolicy());
    assert.equal(reg.registered, true, JSON.stringify(reg));

    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS2.envelope, JSON.stringify(prepS2));
    const settled = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS2,
      submitTool: "settlement_authorize", extraArgs: { approval: approvalFor(prepS2) },
    });
    assert.equal(settled.status, "released", JSON.stringify(settled));
    env.close();
    envOpen = false;

    // Durable: a restart keeps the registration and its replay guard.
    env2 = await boot({ stateDir });
    const replay = await env2.callTool("tb1", "contract_register_policy", signPolicy({ expiresAt: reg.expiresAt }));
    assert.equal(replay.error, "NONCE_REUSED", JSON.stringify(replay));
  } finally {
    if (envOpen) env.close();
    env2?.close();
  }

  // Expiry: pruned from the live set once expiresAt passes.
  let t = Date.parse("2026-10-06T00:00:00.000Z");
  const registry = createPolicyRegistry({
    envBuyer: new Set([POLICY_DIGEST]),
    principals: new Map([["kb1", PRINCIPAL_ADDRESS]]),
    maxPerRole: 64,
    now: () => t,
  });
  const expiresAt = new Date(t + 60_000).toISOString();
  assert.equal(registry.register({ keyId: "kb1" }, signPolicy({ expiresAt })).ok, true);
  assert.equal(registry.buyer.has(POLICY_D), true);
  t += 60_001;
  assert.equal(registry.buyer.has(POLICY_D), false, "expired registration leaves the allowed set");
  assert.equal(registry.buyer.has(POLICY_DIGEST), true, "env pins never expire");
});

// ============================================================================
// Server-side anchors — terms, brief, final.
// ============================================================================

/** fakeAnchor whose `final` issues settle only after `delayMs`. */
function slowFinalAnchor(delayMs) {
  const base = fakeAnchor();
  return {
    ...base,
    calls: base.calls,
    async anchor(input) {
      if (input.kind === "final") await new Promise((r) => setTimeout(r, delayMs));
      return base.anchor(input);
    },
  };
}

function briefFixture() {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-coord-briefs-"));
  const text = "# Family travel brief\n\nBook within the signed mandate only.\n";
  writeFileSync(path.join(dir, "family-travel.md"), text);
  const digest = `0x${createHash("sha256").update(text).digest("hex")}`;
  return { dir, text, digest };
}

test("anchors/terms: the creating bind anchors the certificate's statementDigest, unchained", async () => {
  const anchor = fakeAnchor();
  const env = await boot({ anchor });
  try {
    const { runId } = await agreePair(env, uuid(931), "tb1", "tp1");
    await waitFor(() => env.service.runFor(runId)?.anchors?.terms?.status === "anchored");
    const terms = env.service.runFor(runId).anchors.terms;
    assert.equal(terms.digest, `0x${"f".repeat(64)}`);
    assert.equal(anchor.calls.filter((c) => c.kind === "terms").length, 1, "one terms anchor per run, not per bind");
    assert.equal(anchor.calls.find((c) => c.kind === "terms").runId, runId);

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.anchors.terms.status, "anchored");
    assert.equal(st.anchors.terms.anchorId, terms.anchorId);
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));
    // Never a chained receipt: only the agreement anchor outcome is receipted.
    const anchorReceipts = env.service.receiptFeed(runId).receipts.filter((r) => r.tool === "anchor");
    assert.equal(anchorReceipts.length, 1);
  } finally { env.close(); }
});

test("anchors/brief: a pinned brief is anchored before it returns and carried onto the run", async () => {
  const fx = briefFixture();
  const briefs = parseContractBriefs(`family-travel:${fx.digest}`, fx.dir);
  assert.throws(() => parseContractBriefs(`family-travel:0x${"0".repeat(64)}`, fx.dir), /pinned digest/);
  assert.throws(() => parseContractBriefs(`missing:${fx.digest}`, fx.dir), /no brief file/);

  const anchor = fakeAnchor();
  const env = await boot({ anchor, briefs });
  try {
    const got = await env.callTool("tb1", "contract_get_brief", { name: "family-travel" });
    assert.equal(got.text, fx.text);
    assert.equal(got.digest, fx.digest);
    assert.equal(got.anchor.status, "anchored", JSON.stringify(got));
    assert.match(got.anchor.anchorId, /^tsa:fake-brief-/);
    // Write-once per scope: a second serve does not re-anchor.
    const again = await env.callTool("tb1", "contract_get_brief", { name: "family-travel" });
    assert.equal(again.anchor.anchorId, got.anchor.anchorId);
    assert.equal(anchor.calls.filter((c) => c.kind === "brief").length, 1);
    const missing = await env.callTool("tb1", "contract_get_brief", { name: "nope" });
    assert.equal(missing.error, "NOT_FOUND");
    // The serve is receipted on the pre-bind chain (its responseDigest covers the anchor id).
    const pre = env.service.preBindFeed("kb1").receipts.filter((r) => r.tool === "contract_get_brief");
    assert.equal(pre.length, 3);
    assert.equal(pre[0].responseDigest, canonicalDigest(got));

    const { runId } = await agreePair(env, uuid(932), "tb1", "tp1");
    const run = env.service.runFor(runId);
    assert.equal(run.anchors.brief.anchorId, got.anchor.anchorId, "the seat's pre-bind brief anchor is the run's");
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.anchors.brief.digest, fx.digest);
  } finally { env.close(); }

  // Without an anchor the brief is still served — anchor:null, never a fake id.
  const plain = await boot({ briefs });
  try {
    const got = await plain.callTool("tb1", "contract_get_brief", { name: "family-travel" });
    assert.equal(got.text, fx.text);
    assert.equal(got.anchor, null);
  } finally { plain.close(); }
});

test("anchors/final: covers the post-terminal receipts, recorded on the job, awaited before status reports", async () => {
  const anchor = slowFinalAnchor(150);
  let env;
  env = await boot({
    anchor,
    // A close emitter stand-in: delivery lands after the terminal anchor.
    onTerminalRun: (run, _state, _p, receipt) => {
      setTimeout(() => {
        env.service.persistTerminalClose(run.runId, { status: "delivered", attempts: 1, deliveredAt: new Date().toISOString() });
        env.service.recordTerminalOutcome(run.runId, "delivered", { receiptDigest: canonicalDigest(receipt), attempts: 1 });
      }, 30);
    },
  });
  try {
    const { runId, booked } = await bookPair(env, uuid(933), "tb1", "tp1");
    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "mismatch", findingsDigest: `0x${"bb".repeat(32)}`,
    });
    const verified = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    assert.equal(verified.terminalState, "verification_failed");

    // Wait for the close outcome, then ask for status immediately: the final
    // anchor (slow) is awaited before the terminal state is reported.
    await waitFor(() => env.service.receiptFeed(runId).receipts.some((r) => r.tool === "telemetry_close"));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "verification_failed");
    assert.equal(st.anchors.final?.status, "anchored", JSON.stringify(st.anchors));
    assert.equal(statusSchema.safeParse(st).success, true, JSON.stringify(statusSchema.safeParse(st).error));

    const receipts = env.service.receiptFeed(runId).receipts;
    const n = st.anchors.final.receiptCount;
    assert.equal(st.anchors.final.digest, canonicalDigest(receipts[n - 1]), "final = chain head over the first n receipts");
    const terminalAnchorAt = receipts.findIndex((r) => r.tool === "anchor" &&
      r.argsDigest === canonicalDigest({ runId, kind: "terminal", digest: st.anchors.terminal.digest }));
    const closeAt = receipts.findIndex((r) => r.tool === "telemetry_close");
    assert.ok(terminalAnchorAt >= 0 && closeAt >= 0);
    assert.ok(n > terminalAnchorAt && n > closeAt, "final covers the terminal anchor outcome and the close receipt");
    // Recorded on the job; never a chained receipt (agreement + terminal only).
    assert.equal(env.service.terminalJobFor(runId).anchors.final.status, "anchored");
    assert.equal(receipts.filter((r) => r.tool === "anchor").length, 2);
    assert.equal(anchor.calls.filter((c) => c.kind === "final").length, 1);
  } finally { env.close(); }
});

test("anchors/final: an in-flight final persisted at shutdown is re-driven at boot", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-coord-final-"));
  const base = fakeAnchor();
  const hanging = {
    ...base,
    async anchor(input) {
      if (input.kind === "final") return new Promise(() => {});
      return base.anchor(input);
    },
  };
  const envA = await boot({ stateDir, anchor: hanging, finalAnchorAwaitMs: 50 });
  let runId;
  try {
    const r = await bookPair(envA, uuid(934), "tb1", "tp1");
    runId = r.runId;
    const prepV = await envA.callTool("tb1", "verification_prepare", {
      orderRef: r.booked.orderRef, result: "mismatch", findingsDigest: `0x${"bb".repeat(32)}`,
    });
    await signedSubmit(envA, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    await waitFor(() => envA.service.terminalJobFor(runId)?.anchors?.final?.status === "anchoring");
    const st = await envA.callTool("tb1", "contract_status", {});
    assert.equal(st.anchors.final.status, "anchoring", "the bounded wait never hangs status");
  } finally { envA.close(); }

  const anchorB = fakeAnchor();
  const envB = await boot({ stateDir, anchor: anchorB });
  try {
    const done = await waitFor(() => envB.service.terminalJobFor(runId)?.anchors?.final?.status === "anchored");
    assert.ok(done, "boot recovery re-drove the final anchor");
    const job = envB.service.terminalJobFor(runId);
    assert.equal(anchorB.calls.find((c) => c.kind === "final").digestHex, job.anchors.final.digest);
    // Unchained: recovery minted no anchor evidence for it.
    assert.equal(job.evidence.filter((r) => r.tool === "anchor" &&
      r.argsDigest === canonicalDigest({ runId, kind: "final", digest: job.anchors.final.digest })).length, 0);
  } finally { envB.close(); }
});
