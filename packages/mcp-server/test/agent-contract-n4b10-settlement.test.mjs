import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { StripeTestRailError } from "../dist/agent-contract/settlement-rail.js";

import {
  boot, agreePair, bookPair, signedSubmit, makeApproval, signRoleSig, keys, uuid, statusSchema,
} from "./n4b9-harness.mjs";

// N4b-10 (spec D13): business integration of the Stripe TEST-mode
// settlement rail. The rail is a FAKE implementing the SettlementRail
// interface — no transport, no keys; ordering (match-gate →
// unconfirmed create → signature → approval → confirm) and the
// awaiting/refused/failed/replay surfaces are what these tests pin.

function fakeRail({ keyStatus = "configured", createFails = null, confirmFails = null } = {}) {
  const calls = { keyStatus: 0, create: 0, confirm: 0, retrieve: 0, lastCreate: null, lastConfirm: null };
  const intents = new Map();
  const rail = {
    railId: "stripe_test_mode",
    async keyStatus() {
      calls.keyStatus += 1;
      return rail.nextKeyStatus;
    },
    nextKeyStatus: keyStatus,
    async createPaymentIntent(input) {
      calls.create += 1;
      calls.lastCreate = input;
      if (createFails !== null) throw createFails;
      const intent = { id: `pi_test_${String(calls.create).padStart(3, "0")}`, status: "requires_confirmation" };
      intents.set(intent.id, intent);
      return { ...intent };
    },
    async confirmPaymentIntent(input) {
      calls.confirm += 1;
      calls.lastConfirm = input;
      if (confirmFails !== null) throw confirmFails;
      const intent = intents.get(input.paymentIntentId);
      if (intent !== undefined) intent.status = "succeeded";
      return { id: input.paymentIntentId, status: "succeeded" };
    },
    async retrievePaymentIntent(input) {
      calls.retrieve += 1;
      const intent = intents.get(input.paymentIntentId);
      if (intent === undefined) {
        throw new StripeTestRailError("STRIPE_RAIL_HTTP", "no such intent");
      }
      return { ...intent };
    },
    intents,
  };
  return { rail, calls, intents };
}

/** Drive a pair to match-verified; returns {runId, orderRef}. */
async function verifiedPair(env, sessionId, buyer = "tb1", provider = "tp1") {
  const { runId, agreementId } = await agreePair(env, sessionId, buyer, provider);
  const prepB = await env.callTool(provider, "booking_prepare", { agreementId });
  const bookApproval = makeApproval({
    envelope: prepB.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit(env, {
    token: provider, role: "provider", prepared: prepB,
    submitTool: "booking_execute", extraArgs: { approval: bookApproval },
  });
  assert.ok(booked.orderRef, JSON.stringify(booked));
  const prepV = await env.callTool(buyer, "verification_prepare", {
    orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
  });
  const verified = await signedSubmit(env, {
    token: buyer, role: "buyer", prepared: prepV, submitTool: "verification_submit",
  });
  assert.equal(verified.flagged, false, JSON.stringify(verified));
  return { runId, orderRef: booked.orderRef, buyer };
}

async function prepareAndAuthorize(env, { buyer, approval = null, signFn = null }) {
  const prepS = await env.callTool(buyer, "settlement_prepare", {});
  if (prepS.envelope === undefined) return { prepS, settled: null };
  const settleApproval = approval ?? makeApproval({
    envelope: prepS.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval,
  });
  const settled = signFn === null
    ? await signedSubmit(env, {
        token: buyer, role: "buyer", prepared: prepS,
        submitTool: "settlement_authorize", extraArgs: { approval: settleApproval },
      })
    : await signFn(prepS, settleApproval);
  return { prepS, settled, settleApproval };
}

test("D13: prepare creates the UNCONFIRMED intent; the signed payload names it", async () => {
  const { rail, calls } = fakeRail();
  const env = await boot({ settlementRail: rail });
  try {
    await verifiedPair(env, uuid(801));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS.envelope, JSON.stringify(prepS));
    assert.equal(calls.create, 1);
    assert.equal(calls.confirm, 0, "prepare must NOT confirm — sign-then-release");
    assert.equal(calls.lastCreate.idempotencyKey.length > 0, true);
    const { paymentRail, paymentIntentId, simulated } = prepS.envelope.payload;
    assert.equal(paymentRail, "stripe_test_mode");
    assert.equal(paymentIntentId, "pi_test_001");
    assert.equal(simulated, true);
    // The provenance triple rides in the intent's metadata.
    assert.equal(calls.lastCreate.metadata.verificationDigest.length > 0, true);
    assert.equal(calls.lastCreate.metadata.agreementDigest.length > 0, true);
  } finally { env.close(); }
});

test("D13: authorize confirms ONLY after signature + approval; result is labelled", async () => {
  const { rail, calls } = fakeRail();
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(802));
    const { prepS, settled } = await prepareAndAuthorize(env, { buyer: "tb1" });
    assert.equal(calls.confirm, 1);
    assert.equal(calls.lastConfirm.paymentIntentId, "pi_test_001");
    assert.equal(settled.status, "released", JSON.stringify(settled));
    assert.equal(settled.transferId, "pi_test_001");
    assert.equal(settled.paymentRail, "stripe_test_mode");
    assert.equal(settled.paymentIntentId, "pi_test_001");
    assert.equal(settled.stripeStatus, "succeeded");
    assert.equal(settled.simulated, true);
    assert.equal(settled.commercialTransfer, false);
    assert.equal(settled.label, "Stripe TEST mode — no real money");
    assert.ok(prepS.envelope.payload.paymentIntentId === "pi_test_001");
    const status = await env.callTool("tb1", "contract_status", {});
    assert.equal(status.terminalState, "settled");
    const st = await env.callTool("tb1", "settlement_status", {});
    assert.equal(st.state, "released");
    assert.equal(st.paymentRail, "stripe_test_mode");
    assert.equal(st.paymentIntentId, "pi_test_001");
    assert.equal(st.stripeStatus, "succeeded");
  } finally { env.close(); }
});

test("D13: a bad signature, a deny submission, or an ambiguous deny+sig never reaches confirm", async () => {
  for (const [name, kind, buyer, provider] of [
    ["badSig", "badSig", "tb1", "tp1"],
    ["denied", "deny", "tb2", "tp2"],
    ["denySig", "deny", "tb1", "tp1"],
  ]) {
    const { rail, calls } = fakeRail();
    const env = await boot({ settlementRail: rail });
    try {
      await verifiedPair(env, uuid(809), buyer, provider);
      const prepS = await env.callTool(buyer, "settlement_prepare", {});
      const approval = makeApproval({
        envelope: prepS.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval,
        decision: kind === "deny" ? "deny" : "allow",
      });
      const e = prepS.envelope;
      const signatureHex = kind === "badSig"
        ? `0x${"ab".repeat(65)}`
        : kind === "denySig"
          ? signRoleSig(keys.buyerSigner.priv, {
              runId: e.runId, role: "buyer", tool: e.tool, nonce: e.nonce, payloadDigest: e.payloadDigest,
            })
          : undefined;
      const res = await env.callTool(buyer, "settlement_authorize", {
        envelope: e, approval,
        ...(signatureHex !== undefined ? { signatureHex } : {}),
      });
      if (kind === "badSig") assert.equal(res.error, "SIGNATURE_INVALID", JSON.stringify(res));
      else if (kind === "denySig") {
        // D11: deny + role signature is ambiguous — refused, never terminal.
        assert.equal(res.error, "APPROVAL_INVALID", JSON.stringify(res));
        const cs = await env.callTool(buyer, "contract_status", {});
        assert.equal(cs.terminalState, null, "an ambiguous deny ends nothing");
      } else assert.equal(res.error, "POLICY_DENIED", JSON.stringify(res));
      assert.equal(calls.confirm, 0, `${name}: confirm must not run`);
    } finally { env.close(); }
  }
});

// Adversarial review H1 (repro ported from /tmp/review-deny-then-pay.test.mjs):
// settlement_authorize sits in TERMINAL_REPLAY_TOOLS, so a deny submission on
// envelope E1 ending the run blocked_by_policy must ALSO refuse an authorize
// on the second envelope E2 — a settled replay is the only terminal bypass.
test("H1: deny on E1 ends blocked_by_policy — authorize on E2 is ALREADY_TERMINAL (both rails)", async () => {
  for (const railSpec of [undefined, fakeRail().rail]) {
    const terms = [];
    const env = await boot({ settlementRail: railSpec, onTerminalRun: (r, s) => terms.push(s) });
    try {
      await verifiedPair(env, uuid(813), "tb1", "tp1");
      const e1 = await env.callTool("tb1", "settlement_prepare", {});
      const e2 = await env.callTool("tb1", "settlement_prepare", {});
      assert.ok(e1.envelope !== undefined && e2.envelope !== undefined, JSON.stringify({ e1, e2 }));
      assert.notEqual(e1.envelope.nonce, e2.envelope.nonce);
      const deny = makeApproval({
        envelope: e1.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval, decision: "deny",
      });
      const d = await env.callTool("tb1", "settlement_authorize", {
        envelope: e1.envelope, approval: deny,
      });
      assert.equal(d.error, "POLICY_DENIED", JSON.stringify(d));
      const run = env.service.runFor(e1.envelope.runId);
      assert.equal(run.terminalState, "blocked_by_policy");
      const allow = makeApproval({
        envelope: e2.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval,
      });
      const paid = await signedSubmit(env, {
        token: "tb1", role: "buyer", prepared: e2,
        submitTool: "settlement_authorize", extraArgs: { approval: allow },
      });
      // The settle-after-deny hole: on the Stripe rail this CONFIRMED a
      // PaymentIntent after a policy deny. It must refuse.
      assert.equal(paid.error, "ALREADY_TERMINAL", JSON.stringify(paid));
      assert.equal(run.settlement, undefined, "a denied run can never settle");
      assert.deepEqual(terms, ["blocked_by_policy"]);
    } finally { env.close(); }
  }
});

// L2 (adversarial review): the mandate cap must run BEFORE the rail —
// a cap-failing agreement never mints a PaymentIntent (nor probes the key).
// A cap-below-total mandate can never get here (booking refuses it first),
// so the reachable cap-fail at settle is mandate EXPIRY: verified at t,
// then the clock jumps past mandate.expiresAt.
test("L2: an expired mandate refuses settlement_prepare before ANY rail call", async () => {
  const { rail, calls } = fakeRail();
  // Offset clock: real time during setup (approvals must not read as
  // future-dated), then jump past the mandate's expiresAt before settle.
  let offset = 0;
  const env = await boot({ settlementRail: rail, now: () => Date.now() + offset });
  try {
    const { runId } = await verifiedPair(env, uuid(814));
    offset = 601_000; // mandate expiresAt is signing-time + 600s
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.error, "MANDATE_REFUSED", JSON.stringify(prepS));
    assert.equal(calls.keyStatus, 0, "key probe must not run");
    assert.equal(calls.create, 0, "no PaymentIntent on a cap failure");
    assert.equal(env.service.runFor(runId).settlementIntent, undefined);
  } finally { env.close(); }
});

test("D13: absent key → awaiting_stripe_test_key; no intent; honest status", async () => {
  const { rail, calls } = fakeRail({ keyStatus: "absent" });
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(803));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.status, "awaiting_stripe_test_key", JSON.stringify(prepS));
    assert.equal(prepS.paymentRail, "stripe_test_mode");
    assert.equal(prepS.simulated, true);
    assert.equal(prepS.label, "Stripe TEST mode — no real money");
    assert.equal(calls.create, 0, "no PaymentIntent may exist while the key is absent");
    const st = await env.callTool("tb1", "settlement_status", {});
    assert.equal(st.state, "awaiting_stripe_test_key");
    const cs = await env.callTool("tb1", "contract_status", {});
    assert.equal(cs.settlement.paymentRail, "stripe_test_mode");
    assert.equal(cs.settlement.awaitingStripeTestKey, true);
    assert.ok(statusSchema.safeParse(cs).success, "contract_status stays schema-valid");
    // Key lands → the next prepare creates the intent and clears the flag.
    rail.nextKeyStatus = "configured";
    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS2.envelope, JSON.stringify(prepS2));
    assert.equal(calls.create, 1);
    const cs2 = await env.callTool("tb1", "contract_status", {});
    assert.equal(cs2.settlement.awaitingStripeTestKey, false);
    assert.equal(cs2.settlement.paymentIntentId, "pi_test_001");
  } finally { env.close(); }
});

test("D13: a refused (non-test) key fails closed — generic refusal, no intent", async () => {
  const { rail, calls } = fakeRail({ keyStatus: "refused" });
  const env = await boot({ settlementRail: rail });
  try {
    await verifiedPair(env, uuid(804));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.error, "CONTRACT_UNAVAILABLE", JSON.stringify(prepS));
    assert.equal(calls.create, 0);
  } finally { env.close(); }
});

test("D13: the settle replay is idempotent; a different call on a settled run is refused", async () => {
  const { rail, calls } = fakeRail();
  const env = await boot({ settlementRail: rail });
  try {
    await verifiedPair(env, uuid(805));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    const approval = makeApproval({
      envelope: prepS.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const e = prepS.envelope;
    const sig = signRoleSig(keys.buyerSigner.priv, {
      runId: e.runId, role: "buyer", tool: e.tool, nonce: e.nonce, payloadDigest: e.payloadDigest,
    });
    const args = { envelope: e, signatureHex: sig, approval };
    const first = await env.callTool("tb1", "settlement_authorize", args);
    assert.equal(first.status, "released", JSON.stringify(first));
    const replay = await env.callTool("tb1", "settlement_authorize", args);
    assert.equal(replay.transferId, first.transferId, "replay returns the recorded result");
    assert.equal(replay.paymentIntentId, "pi_test_001");
    assert.equal(calls.confirm, 1, "a replay never re-confirms");
    const different = await env.callTool("tb1", "settlement_authorize", {
      envelope: e, signatureHex: `0x${"ab".repeat(65)}`, approval,
    });
    assert.equal(different.error, "STATE_REFUSED", JSON.stringify(different));
    assert.equal(calls.confirm, 1);
  } finally { env.close(); }
});

test("D13: a create failure answers a code-only failed body — retryable, receipted", async () => {
  const { rail, calls } = fakeRail({
    createFails: new StripeTestRailError("STRIPE_RAIL_HTTP", "synthetic"),
  });
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(806));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.status, "failed", JSON.stringify(prepS));
    assert.equal(prepS.error, "STRIPE_RAIL_HTTP");
    assert.equal(prepS.simulated, true);
    // Receipted as an ok tool outcome (the failure is data, not a refusal).
    const feed = env.service.receiptFeed(runId);
    const rec = feed.receipts.find((r) => r.tool === "settlement_prepare");
    assert.ok(rec, "the failed prepare is receipted");
    // Retry works — no intent was persisted.
    rail.nextKeyStatus = "configured";
    rail.createPaymentIntent = async (input) => ({ id: "pi_test_retry", status: "requires_confirmation" });
    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS2.envelope.payload.paymentIntentId, "pi_test_retry", JSON.stringify(prepS2));
  } finally { env.close(); }
});

test("D13: a confirm failure answers code-only — run stays live, authorize retryable", async () => {
  const { rail, calls } = fakeRail({
    confirmFails: new StripeTestRailError("STRIPE_RAIL_HTTP", "synthetic"),
  });
  const env = await boot({ settlementRail: rail });
  try {
    await verifiedPair(env, uuid(807));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    const approval = makeApproval({
      envelope: prepS.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const res = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize", extraArgs: { approval },
    });
    assert.equal(res.status, "failed", JSON.stringify(res));
    assert.equal(res.error, "STRIPE_RAIL_HTTP");
    assert.equal(res.paymentIntentId, "pi_test_001");
    assert.equal(res.commercialTransfer, false);
    const cs = await env.callTool("tb1", "contract_status", {});
    assert.notEqual(cs.terminalState, "settled");
    // L1 (adversarial review): the failed attempt CONSUMED its nonce —
    // retrying the SAME envelope is refused; recovery requires a fresh
    // settlement_prepare (which reuses the stored intent).
    const sameEnvRetry = await env.callTool("tb1", "settlement_authorize", {
      envelope: prepS.envelope,
      signatureHex: signRoleSig(keys.buyerSigner.priv, {
        runId: prepS.envelope.runId, role: "buyer", tool: prepS.envelope.tool,
        nonce: prepS.envelope.nonce, payloadDigest: prepS.envelope.payloadDigest,
      }),
      approval,
    });
    assert.equal(sameEnvRetry.error, "NONCE_REUSED", JSON.stringify(sameEnvRetry));
    // Recover: a fresh prepare reuses the stored intent (no second
    // create), mints a new-nonce envelope, and its authorize confirms.
    rail.confirmPaymentIntent = async ({ paymentIntentId }) => {
      calls.confirm += 1;
      return { id: paymentIntentId, status: "succeeded" };
    };
    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(calls.create, 1, "the created intent is reused — no duplicate create");
    assert.equal(prepS2.envelope.payload.paymentIntentId, "pi_test_001");
    const approval2 = makeApproval({
      envelope: prepS2.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const retry = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS2,
      submitTool: "settlement_authorize", extraArgs: { approval: approval2 },
    });
    assert.equal(retry.status, "released", JSON.stringify(retry));
    assert.equal(calls.confirm, 2);
  } finally { env.close(); }
});

// L4 (adversarial review): two concurrent authorizes must serialize —
// without the per-run lock both could pass verification and race to
// overwrite settlementRequest. A gated confirm makes the interleave real.
test("L4: concurrent settlement_authorize serialize — exactly one confirm, settlementRequest not overwritten", async () => {
  let releaseGate;
  const gate = new Promise((r) => { releaseGate = r; });
  const { rail, calls } = fakeRail();
  rail.confirmPaymentIntent = async ({ paymentIntentId }) => {
    calls.confirm += 1;
    await gate;
    return { id: paymentIntentId, status: "succeeded" };
  };
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(815));
    const e1 = await env.callTool("tb1", "settlement_prepare", {});
    const e2 = await env.callTool("tb1", "settlement_prepare", {});
    const sign = (env_) => signRoleSig(keys.buyerSigner.priv, {
      runId: env_.runId, role: "buyer", tool: env_.tool,
      nonce: env_.nonce, payloadDigest: env_.payloadDigest,
    });
    const approve = (env_) => makeApproval({
      envelope: env_, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const app1 = approve(e1.envelope); // approvals carry ts — reuse the SAME
    const app2 = approve(e2.envelope); // bytes for a byte-identical replay
    const a1 = env.callTool("tb1", "settlement_authorize", {
      envelope: e1.envelope, signatureHex: sign(e1.envelope), approval: app1,
    });
    const a2 = env.callTool("tb1", "settlement_authorize", {
      envelope: e2.envelope, signatureHex: sign(e2.envelope), approval: app2,
    });
    await new Promise((r) => setTimeout(r, 60)); // let the winner reach confirm
    releaseGate();
    const [r1, r2] = await Promise.all([a1, a2]);
    const outcomes = [r1, r2].map((r) => (r.error ?? r.status)).sort();
    assert.deepEqual(outcomes, ["STATE_REFUSED", "released"], JSON.stringify({ r1, r2 }));
    assert.equal(calls.confirm, 1, "the serialized loser never reaches the rail");
    const run = env.service.runFor(runId);
    assert.equal(run.terminalState, "settled");
    assert.ok(run.settlementRequest !== undefined);
    // The recorded request replays byte-identically — the winner's result.
    const winner = r1.status === "released" ? { e: e1, r: r1, a: app1 } : { e: e2, r: r2, a: app2 };
    const replay = await env.callTool("tb1", "settlement_authorize", {
      envelope: winner.e.envelope, signatureHex: sign(winner.e.envelope), approval: winner.a,
    });
    assert.equal(replay.status, "released");
    assert.equal(replay.transferId, winner.r.transferId);
  } finally { env.close(); }
});

// M2 (adversarial review): a confirm response that isn't `succeeded` —
// or names a different intent — is a code-only failure, NEVER settled.
// (The real rail also validates amount/currency/metadata echoes; this is
// the business-layer belt behind it — a fake rail bypassing them still
// cannot settle.)
test("M2: a non-succeeded or wrong-id confirm response never settles", async () => {
  for (const [name, confirmResult] of [
    ["requiresAction", { id: "pi_test_001", status: "requires_action" }],
    ["wrongId", { id: "pi_test_OTHER", status: "succeeded" }],
  ]) {
    const { rail, calls } = fakeRail();
    rail.confirmPaymentIntent = async () => {
      calls.confirm += 1;
      return confirmResult;
    };
    const env = await boot({ settlementRail: rail });
    try {
      const { runId } = await verifiedPair(env, uuid(816), name === "wrongId" ? "tb2" : "tb1", name === "wrongId" ? "tp2" : "tp1");
      const prepS = await env.callTool(name === "wrongId" ? "tb2" : "tb1", "settlement_prepare", {});
      const buyer = name === "wrongId" ? "tb2" : "tb1";
      const approval = makeApproval({
        envelope: prepS.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval,
      });
      const res = await signedSubmit(env, {
        token: buyer, role: "buyer", prepared: prepS,
        submitTool: "settlement_authorize", extraArgs: { approval },
      });
      assert.equal(res.status, "failed", `${name}: ${JSON.stringify(res)}`);
      assert.equal(res.error, "STRIPE_RAIL_BAD_RESPONSE");
      assert.equal(res.commercialTransfer, false);
      const run = env.service.runFor(runId);
      assert.equal(run.settlement, undefined, `${name}: never settled`);
      assert.equal(run.terminalState, null, `${name}: run stays live`);
    } finally { env.close(); }
  }
});

test("D13: no PaymentIntent without a match verification — the gate precedes the rail", async () => {
  const { rail, calls } = fakeRail();
  const env = await boot({ settlementRail: rail });
  try {
    // Bound + agreed but never verified — the rail must stay silent.
    await agreePair(env, uuid(810), "tb1", "tp1");
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.error, "STATE_REFUSED", JSON.stringify(prepS));
    assert.equal(calls.create, 0);
    assert.equal(calls.confirm, 0);
  } finally { env.close(); }
});

test("D13: the feed's settlement sim-labels name the rail and 'no real money'", async () => {
  const { rail } = fakeRail();
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(811));
    const { prepS, settled } = await prepareAndAuthorize(env, { buyer: "tb1" });
    assert.equal(settled.status, "released");
    const feed = env.service.receiptFeed(runId);
    const labels = feed.simLabels.filter((l) => {
      const rec = feed.receipts.find((r) => r.receiptId === l.receiptId);
      return rec !== undefined && rec.tool.startsWith("settlement");
    });
    assert.ok(labels.length >= 2, "prepare + authorize both labelled");
    for (const l of labels) {
      assert.equal(l.simulated, true);
      // D13 clarification: `simulated:true` stays on the Stripe rail — the
      // rail is decided from paymentRail, never from simulated.
      assert.equal(l.paymentRail, "stripe_test_mode");
      assert.match(l.label, /no real money/);
    }
    assert.equal(prepS.envelope.payload.paymentRail, "stripe_test_mode");
    assert.equal(prepS.envelope.payload.simulated, true, "simulated:true coexists with the stripe rail");
    assert.equal(settled.simulated, true, "the released body stays simulated:true");
    assert.equal(settled.paymentRail, "stripe_test_mode");
    // The run's recorded settlement decides the rail, not the flag.
    const cs = await env.callTool("tb1", "contract_status", {});
    assert.equal(cs.settlement.paymentRail, "stripe_test_mode");
  } finally { env.close(); }
});

test("D13: on the simulated rail the same labels read 'simulated' — paymentRail is the discriminator", async () => {
  const env = await boot();
  try {
    const { runId } = await verifiedPair(env, uuid(812));
    const { settled } = await prepareAndAuthorize(env, { buyer: "tb1" });
    assert.equal(settled.status, "released");
    assert.equal(settled.simulated, true);
    const feed = env.service.receiptFeed(runId);
    const labels = feed.simLabels.filter((l) => {
      const rec = feed.receipts.find((r) => r.receiptId === l.receiptId);
      return rec !== undefined && rec.tool.startsWith("settlement");
    });
    assert.ok(labels.length >= 2);
    for (const l of labels) {
      assert.equal(l.simulated, true, "simulated:true on BOTH rails — it never discriminates");
      assert.equal(l.paymentRail, "simulated");
      assert.match(l.label, /no real money/);
    }
    const cs = await env.callTool("tb1", "contract_status", {});
    assert.equal(cs.settlement.paymentRail, "simulated");
  } finally { env.close(); }
});

test("D13: the default rail stays 'simulated' — payload labels it, no intent", async () => {
  const env = await boot();
  try {
    await verifiedPair(env, uuid(808));
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.equal(prepS.envelope.payload.paymentRail, "simulated");
    assert.equal(prepS.envelope.payload.paymentIntentId, undefined);
    const settled = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize",
      extraArgs: {
        approval: makeApproval({
          envelope: prepS.envelope, role: "buyer", action: "settlement",
          tool: "settlement_authorize", key: keys.buyerApproval,
        }),
      },
    });
    assert.equal(settled.paymentRail, "simulated");
    assert.equal(settled.simulated, true);
    assert.equal(settled.commercialTransfer, false);
    const st = await env.callTool("tb1", "settlement_status", {});
    assert.equal(st.state, "released");
    assert.equal(st.paymentRail, "simulated");
  } finally { env.close(); }
});

// N4b-11 (adversarial M3 follow-up): settlement/cancellation are written
// BEFORE endRun — if the durable terminal enqueue fails, the client sees
// CONTRACT_UNAVAILABLE but the run keeps settlement set with
// terminalState null. A byte-identical replay must COMPLETE the
// transition (endRun) before answering — never answer "released" for a
// run with no durable job, close, or anchor.
test("M3-follow-up: a failed durable write during authorize leaves a live run — the byte-identical retry settles it durably FIRST (both rails)", async () => {
  for (const railSpec of [undefined, fakeRail().rail]) {
    const stateDir = mkdtempSync(path.join(tmpdir(), "n4b11-settleheal-"));
    const terms = [];
    const env = await boot({
      stateDir, settlementRail: railSpec,
      onTerminalRun: (_r, s) => terms.push(s),
    });
    let denied = false;
    const denyWrites = () => { chmodSync(stateDir, 0o555); denied = true; };
    const allowWrites = () => { if (denied) { chmodSync(stateDir, 0o700); denied = false; } };
    try {
      const { runId } = await verifiedPair(env, uuid(817), "tb1", "tp1");
      const prepS = await env.callTool("tb1", "settlement_prepare", {});
      const approval = makeApproval({
        envelope: prepS.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval,
      });
      const args = {
        envelope: prepS.envelope,
        signatureHex: signRoleSig(keys.buyerSigner.priv, {
          runId: prepS.envelope.runId, role: "buyer", tool: prepS.envelope.tool,
          nonce: prepS.envelope.nonce, payloadDigest: prepS.envelope.payloadDigest,
        }),
        approval,
      };
      // The authorize records settlement, then its durable enqueue throws.
      denyWrites();
      const first = await env.callTool("tb1", "settlement_authorize", args);
      assert.equal(first.error, "CONTRACT_UNAVAILABLE", JSON.stringify(first));
      const run = env.service.runFor(runId);
      assert.ok(run.settlement !== undefined, "settlement was recorded before the failed enqueue");
      assert.equal(run.terminalState, null, "the transition was NOT acknowledged");
      assert.equal(terms.length, 0, "no terminal callback fired");
      // While writes stay denied, a byte-identical replay CANNOT quietly
      // answer released — the heal attempt fails closed again.
      const stillDenied = await env.callTool("tb1", "settlement_authorize", args);
      assert.equal(stillDenied.error, "CONTRACT_UNAVAILABLE", JSON.stringify(stillDenied));
      assert.equal(run.terminalState, null);
      // Restore durability: the SAME bytes now complete the transition
      // and only then return the recorded result.
      allowWrites();
      const retry = await env.callTool("tb1", "settlement_authorize", args);
      assert.equal(retry.status, "released", JSON.stringify(retry));
      assert.equal(run.terminalState, "settled");
      assert.deepEqual(terms, ["settled"], "exactly one terminal transition");
      const jobs = JSON.parse(readFileSync(path.join(stateDir, "terminal-jobs.json"), "utf8")).jobs;
      assert.equal(jobs.find((j) => j.runId === runId).terminalState, "settled");
      // Once terminal, the replay is a normal recorded replay again.
      const again = await env.callTool("tb1", "settlement_authorize", args);
      assert.equal(again.status, "released");
    } finally { allowWrites(); env.close(); }
  }
});

test("M3-follow-up: the cancel replay also completes a failed terminal transition before answering", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n4b11-cancelheal-"));
  const terms = [];
  const env = await boot({ stateDir, onTerminalRun: (_r, s) => terms.push(s) });
  let denied = false;
  const denyWrites = () => { chmodSync(stateDir, 0o555); denied = true; };
  const allowWrites = () => { if (denied) { chmodSync(stateDir, 0o700); denied = false; } };
  try {
    const { runId } = await bookPair(env, uuid(818), "tb1", "tp1");
    const prep = await env.callTool("tp1", "booking_cancel_prepare", { reason: "mutual_withdrawal" });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const args = {
      envelope: prep.envelope,
      signatureHex: signRoleSig(keys.providerSigner.priv, {
        runId: prep.envelope.runId, role: "provider", tool: prep.envelope.tool,
        nonce: prep.envelope.nonce, payloadDigest: prep.envelope.payloadDigest,
      }),
      approval,
    };
    denyWrites();
    const first = await env.callTool("tp1", "booking_cancel_submit", args);
    assert.equal(first.error, "CONTRACT_UNAVAILABLE", JSON.stringify(first));
    const run = env.service.runFor(runId);
    assert.ok(run.cancellation !== undefined, "the cancellation was recorded before the failed enqueue");
    assert.equal(run.terminalState, null);
    assert.equal(terms.length, 0);
    allowWrites();
    const retry = await env.callTool("tp1", "booking_cancel_submit", args);
    assert.equal(retry.status, "CANCELLED", JSON.stringify(retry));
    assert.equal(retry.terminalState, "cancelled");
    assert.equal(run.terminalState, "cancelled");
    assert.deepEqual(terms, ["cancelled"]);
  } finally { allowWrites(); env.close(); }
});

// N4b-11 (adversarial LOW): a confirm that times out may still have
// landed upstream. Before reporting "failed" the authorize reconciles
// via the read-only retrieve; and a later deny must look the intent up
// first — blocking a PAID run as blocked_by_policy is never allowed.
test("LOW: a confirm that lands after its deadline settles via reconcile — a later deny cannot block a paid run", async () => {
  const { rail, calls, intents } = fakeRail();
  // The confirm "times out" (deadline error) but the upstream intent
  // flips to succeeded shortly after — the classic ambiguous outcome.
  rail.confirmPaymentIntent = async ({ paymentIntentId }) => {
    calls.confirm += 1;
    const intent = intents.get(paymentIntentId);
    setTimeout(() => { intent.status = "succeeded"; }, 60);
    throw new StripeTestRailError("STRIPE_RAIL_HTTP", "request deadline exceeded");
  };
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(819), "tb1", "tp1");
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    const res = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize",
      extraArgs: {
        approval: makeApproval({
          envelope: prepS.envelope, role: "buyer", action: "settlement",
          tool: "settlement_authorize", key: keys.buyerApproval,
        }),
      },
    });
    // The inline reconcile ran before the upstream flip — honest failure.
    assert.equal(res.status, "failed", JSON.stringify(res));
    assert.equal(res.error, "STRIPE_RAIL_HTTP");
    assert.equal(calls.retrieve, 1, "the ambiguous confirm was looked up, not trusted dead");
    assert.equal(env.service.runFor(runId).terminalState, null);
    // Upstream lands after the deadline — the intent is now PAID.
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(intents.get("pi_test_001").status, "succeeded");
    // A buyer deny now would end the run blocked_by_policy on a PAID
    // intent without the lookup. Reconcile refuses that: the run settles.
    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    const denied = await env.callTool("tb1", "settlement_authorize", {
      envelope: prepS2.envelope,
      approval: makeApproval({
        envelope: prepS2.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval, decision: "deny",
      }),
    });
    assert.equal(denied.error, "ALREADY_TERMINAL", JSON.stringify(denied));
    const run = env.service.runFor(runId);
    assert.equal(run.terminalState, "settled", "the paid intent wins — never blocked_by_policy");
    assert.ok(run.settlement !== undefined);
    assert.equal(run.settlement.paymentIntentId, "pi_test_001");
    assert.equal(calls.confirm, 1, "no second confirm — truth came from the lookup");
  } finally { env.close(); }
});

test("LOW: an intent already succeeded upstream at confirm-catch settles inline — never reported failed", async () => {
  const { rail, calls, intents } = fakeRail();
  // The deadline fired, but the intent is ALREADY succeeded when the
  // reconcile lookup runs — the authorize must answer released.
  rail.confirmPaymentIntent = async ({ paymentIntentId }) => {
    calls.confirm += 1;
    intents.get(paymentIntentId).status = "succeeded";
    throw new StripeTestRailError("STRIPE_RAIL_HTTP", "request deadline exceeded");
  };
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(820), "tb1", "tp1");
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    const res = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize",
      extraArgs: {
        approval: makeApproval({
          envelope: prepS.envelope, role: "buyer", action: "settlement",
          tool: "settlement_authorize", key: keys.buyerApproval,
        }),
      },
    });
    assert.equal(res.status, "released", JSON.stringify(res));
    assert.equal(res.paymentIntentId, "pi_test_001");
    assert.equal(calls.retrieve, 1);
    assert.equal(env.service.runFor(runId).terminalState, "settled");
  } finally { env.close(); }
});

test("LOW: a deny when the intent's truth is unresolvable fails closed — run stays live", async () => {
  const { rail, calls } = fakeRail();
  rail.retrievePaymentIntent = async () => {
    calls.retrieve += 1;
    throw new StripeTestRailError("STRIPE_RAIL_HTTP", "lookup down");
  };
  const env = await boot({ settlementRail: rail });
  try {
    const { runId } = await verifiedPair(env, uuid(821), "tb1", "tp1");
    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    const denied = await env.callTool("tb1", "settlement_authorize", {
      envelope: prepS.envelope,
      approval: makeApproval({
        envelope: prepS.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval, decision: "deny",
      }),
    });
    // Cannot prove the intent unpaid → the deny is NOT accepted.
    assert.equal(denied.error, "CONTRACT_UNAVAILABLE", JSON.stringify(denied));
    const run = env.service.runFor(runId);
    assert.equal(run.terminalState, null, "the run stays live — the deny is retryable");
    assert.equal(run.settlement, undefined);
    assert.equal(calls.retrieve, 1);
  } finally { env.close(); }
});
