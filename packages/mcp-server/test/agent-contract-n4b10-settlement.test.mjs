import assert from "node:assert/strict";
import test from "node:test";

import { StripeTestRailError } from "../dist/agent-contract/settlement-rail.js";

import {
  boot, agreePair, signedSubmit, makeApproval, signRoleSig, keys, uuid, statusSchema,
} from "./n4b9-harness.mjs";

// N4b-10 (spec D13): business integration of the Stripe TEST-mode
// settlement rail. The rail is a FAKE implementing the SettlementRail
// interface — no transport, no keys; ordering (match-gate →
// unconfirmed create → signature → approval → confirm) and the
// awaiting/refused/failed/replay surfaces are what these tests pin.

function fakeRail({ keyStatus = "configured", createFails = null, confirmFails = null } = {}) {
  const calls = { keyStatus: 0, create: 0, confirm: 0, lastCreate: null, lastConfirm: null };
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
      return { id: `pi_test_${String(calls.create).padStart(3, "0")}`, status: "requires_confirmation" };
    },
    async confirmPaymentIntent(input) {
      calls.confirm += 1;
      calls.lastConfirm = input;
      if (confirmFails !== null) throw confirmFails;
      return { id: input.paymentIntentId, status: "succeeded" };
    },
  };
  return { rail, calls };
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
