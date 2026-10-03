import assert from "node:assert/strict";
import test from "node:test";

import { guidanceDigests, toolsListForRole } from "../dist/agent-contract/tools-list.js";
import {
  boot, bindPair, agreePair, bookPair, signedSubmit, signMandate, signRoleSig, makeApproval,
  statusSchema, keys, uuid,
} from "./n4b9-harness.mjs";

// AGENT-TOOLS-BY-REFERENCE S1 + S2: contract_status gains read-only,
// caller-scoped views of the run's offers (with the one offer the caller may
// accept), the agreement, the booking orderRef and a cancellation — so an AI
// buyer can learn the provider's offerId and orderRef without any channel
// other than its own run. No write path changes.

const OFFER_KEYS = [
  "by", "currency", "fareMinor", "feeMinor", "inReplyTo", "itineraryId", "kind",
  "note", "offerId", "state", "submittedAt", "totalMinor",
];

function assertNoLongValues(value, where = "status") {
  // Nothing opaque comes back: no digest, signature, key or envelope-sized
  // string in the new fields (the offer note is bounded authored text).
  if (typeof value === "string") {
    assert.ok(!/^0x[0-9a-f]{64,}$/i.test(value), `${where} carries a hex digest/signature`);
    return;
  }
  if (Array.isArray(value)) value.forEach((v, i) => assertNoLongValues(v, `${where}[${i}]`));
  else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) assertNoLongValues(v, `${where}.${k}`);
  }
}

async function mandate(env, buyerToken) {
  const prepM = await env.callTool(buyerToken, "mandate_prepare", signMandate());
  const m = await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  assert.match(m.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(m));
}

async function offer(env, token, role, args) {
  const prep = await env.callTool(token, "offer_prepare", args);
  const out = await signedSubmit(env, { token, role, prepared: prep, submitTool: "offer_submit" });
  assert.equal(out.state, "offered", JSON.stringify(out));
  return out.offerId;
}

test("S1: before any offer the negotiation view is empty and nothing is acceptable", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(901), "tb1", "tp1");
    for (const token of ["tb1", "tp1"]) {
      const s = await env.callTool(token, "contract_status", {});
      assert.equal(statusSchema.safeParse(s).success, true, JSON.stringify(s));
      assert.deepEqual(s.negotiation, { acceptable: null, offers: [] });
      assert.equal(s.agreement, null);
      assert.equal(s.booking, null);
      assert.equal(s.cancellation, null);
    }
  } finally {
    env.close();
  }
});

test("S1: both roles see the run's offers newest first; acceptable is the counterparty's latest live offer", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(902), "tb1", "tp1");
    await mandate(env, "tb1");
    const b1 = await offer(env, "tb1", "buyer", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000, note: "first" });
    const p1 = await offer(env, "tp1", "provider", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_000 });

    const buyer = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(buyer).success, true, JSON.stringify(buyer));
    // The buyer may accept the provider's counter — never its own offer.
    assert.equal(buyer.negotiation.acceptable, p1);
    assert.deepEqual(buyer.negotiation.offers.map((o) => o.offerId), [p1, b1]);
    const counter = buyer.negotiation.offers[0];
    assert.deepEqual(counter, {
      offerId: p1, by: "provider", kind: "counter", inReplyTo: b1,
      itineraryId: "IT-QW-ONESTOP", currency: "USD",
      fareMinor: 429_000, feeMinor: 9_000, totalMinor: 438_000,
      note: null, state: "live", submittedAt: counter.submittedAt,
    });
    assert.match(counter.submittedAt, /^\d{4}-\d{2}-\d{2}T/);
    const first = buyer.negotiation.offers[1];
    assert.equal(first.by, "buyer");
    assert.equal(first.kind, "offer");
    assert.equal(first.inReplyTo, null);
    assert.equal(first.note, "first");
    assert.equal(first.state, "live");
    for (const o of buyer.negotiation.offers) assert.deepEqual(Object.keys(o).sort(), OFFER_KEYS);

    // The provider sees the same offers; its acceptable is the buyer's offer.
    const provider = await env.callTool("tp1", "contract_status", {});
    assert.equal(statusSchema.safeParse(provider).success, true, JSON.stringify(provider));
    assert.equal(provider.negotiation.acceptable, b1);
    assert.deepEqual(provider.negotiation.offers, buyer.negotiation.offers);

    // A new buyer offer supersedes its first; the provider's acceptable moves.
    const b2 = await offer(env, "tb1", "buyer", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_500 });
    const p = await env.callTool("tp1", "contract_status", {});
    assert.equal(p.negotiation.acceptable, b2);
    assert.equal(p.negotiation.offers.find((o) => o.offerId === b1).state, "superseded");
    const b = await env.callTool("tb1", "contract_status", {});
    // The provider's counter replied to b1, which is now superseded — a
    // counter stays live until its own party supersedes it.
    assert.equal(b.negotiation.acceptable, p1);

    // Nothing about the mandate cap is exposed, and nothing opaque.
    const text = JSON.stringify(b);
    assert.ok(!/cap/i.test(text), `cap leaked: ${text}`);
    assertNoLongValues({ negotiation: b.negotiation, agreement: b.agreement, booking: b.booking });
  } finally {
    env.close();
  }
});

test("S1: a rejected offer is listed as rejected and is no longer acceptable", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(903), "tb1", "tp1");
    await mandate(env, "tb1");
    const p1 = await offer(env, "tp1", "provider", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_000 });
    const before = await env.callTool("tb1", "contract_status", {});
    assert.equal(before.negotiation.acceptable, p1);
    const rejected = await env.callTool("tb1", "offer_reject", { offerId: p1 });
    assert.equal(rejected.state, "rejected", JSON.stringify(rejected));
    const after = await env.callTool("tb1", "contract_status", {});
    assert.equal(after.negotiation.acceptable, null);
    assert.equal(after.negotiation.offers[0].state, "rejected");
  } finally {
    env.close();
  }
});

test("S1: the offer list is capped at the 8 newest", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(904), "tb1", "tp1");
    await mandate(env, "tb1");
    const ids = [];
    for (let i = 0; i < 10; i += 1) {
      const [token, role] = i % 2 === 0 ? ["tb1", "buyer"] : ["tp1", "provider"];
      ids.push(await offer(env, token, role, { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 - i * 100 }));
    }
    const s = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(s).success, true, JSON.stringify(s));
    assert.equal(s.negotiation.offers.length, 8);
    assert.deepEqual(s.negotiation.offers.map((o) => o.offerId), ids.slice(2).reverse());
    assert.equal(s.negotiation.acceptable, ids[9]);
  } finally {
    env.close();
  }
});

test("S1 + S2: agreement and booking are visible to both roles; nothing is acceptable once agreed", async () => {
  const env = await boot();
  try {
    const { agreementId, booked } = await bookPair(env, uuid(905), "tb1", "tp1");
    assert.match(booked.orderRef, /^ORD-/, JSON.stringify(booked));
    for (const token of ["tb1", "tp1"]) {
      const s = await env.callTool(token, "contract_status", {});
      assert.equal(statusSchema.safeParse(s).success, true, JSON.stringify(s));
      assert.equal(s.negotiation.acceptable, null);
      assert.equal(s.negotiation.offers[0].state, "accepted");
      assert.deepEqual(s.agreement, {
        agreementId, offerId: s.negotiation.offers[0].offerId,
        itineraryId: "IT-QW-ONESTOP", currency: "USD", totalMinor: 439_000,
        formedAt: s.agreement.formedAt,
      });
      assert.match(s.agreement.formedAt, /^\d{4}-\d{2}-\d{2}T/);
      assert.deepEqual(s.booking, {
        orderRef: booked.orderRef, pnr: booked.pnr, ticketCount: booked.tickets.length,
        bookedAt: s.booking.bookedAt, simulated: true,
      });
      assert.equal(s.cancellation, null);
      assertNoLongValues({ negotiation: s.negotiation, agreement: s.agreement, booking: s.booking });
    }
    // The buyer can use the orderRef it read from contract_status.
    const s = await env.callTool("tb1", "contract_status", {});
    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: s.booking.orderRef });
    assert.equal(looked.observation.status, "ISSUED", JSON.stringify(looked));
  } finally {
    env.close();
  }
});

test("S2: a cancelled booking surfaces the cancellation", async () => {
  const env = await boot();
  try {
    const { booked } = await bookPair(env, uuid(906), "tb1", "tp1");
    const prep = await env.callTool("tp1", "booking_cancel_prepare", { reason: "mutual_withdrawal" });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const cancelled = await env.callTool("tp1", "booking_cancel_submit", {
      envelope: prep.envelope,
      signatureHex: signRoleSig(keys.providerSigner.priv, {
        runId: prep.envelope.runId, role: "provider", tool: prep.envelope.tool,
        nonce: prep.envelope.nonce, payloadDigest: prep.envelope.payloadDigest,
      }),
      approval,
    });
    assert.equal(cancelled.orderRef, booked.orderRef, JSON.stringify(cancelled));
    const s = await env.callTool("tb1", "contract_status", {});
    assert.equal(statusSchema.safeParse(s).success, true, JSON.stringify(s));
    assert.equal(s.terminalState, "cancelled");
    assert.deepEqual(s.cancellation, { orderRef: booked.orderRef, cancelledAt: s.cancellation.cancelledAt });
    assert.equal(s.booking.orderRef, booked.orderRef);
  } finally {
    env.close();
  }
});

test("S1: a terminal run without an agreement offers nothing acceptable", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(907), "tb1", "tp1");
    await mandate(env, "tb1");
    const p1 = await offer(env, "tp1", "provider", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_000 });
    const w = await env.callTool("tb1", "contract_withdraw", {});
    assert.equal(w.state, "withdrawn", JSON.stringify(w));
    const s = await env.callTool("tb1", "contract_status", {});
    assert.equal(s.terminalState, "no_agreement");
    assert.equal(s.negotiation.acceptable, null);
    assert.deepEqual(s.negotiation.offers.map((o) => o.offerId), [p1]);
  } finally {
    env.close();
  }
});

test("caller scoping: each caller sees only its own run's offers and booking", async () => {
  const env = await boot();
  try {
    const one = await bookPair(env, uuid(908), "tb1", "tp1");
    const two = await agreePair(env, uuid(909), "tb2", "tp2", { feeMinor: 8_000 });
    const s1 = await env.callTool("tb1", "contract_status", {});
    const s2 = await env.callTool("tb2", "contract_status", {});
    assert.equal(s1.agreement.agreementId, one.agreementId);
    assert.equal(s2.agreement.agreementId, two.agreementId);
    assert.equal(s1.booking.orderRef, one.booked.orderRef);
    assert.equal(s2.booking, null);
    assert.equal(s2.negotiation.offers.length, 1);
    assert.equal(s2.negotiation.offers[0].feeMinor, 8_000);
    assert.ok(s1.negotiation.offers.every((o) => o.feeMinor === 10_000));
  } finally {
    env.close();
  }
});

test("pre-bind status carries no negotiation, agreement or booking fields", async () => {
  const env = await boot();
  try {
    const s = await env.callTool("tb1", "contract_status", {});
    assert.equal(s.stage, "rendezvous");
    assert.equal(statusSchema.safeParse(s).success, true, JSON.stringify(s));
    for (const k of ["negotiation", "agreement", "booking", "cancellation"]) assert.ok(!(k in s), k);
  } finally {
    env.close();
  }
});

test("the read fields are output-only: contract_status input stays empty in tools/list", () => {
  for (const role of ["buyer", "provider"]) {
    const t = toolsListForRole(role).tools.find((x) => x.name === "contract_status");
    assert.deepEqual(t.inputSchema, { type: "object", properties: {}, additionalProperties: false });
    assert.match(guidanceDigests(role).toolsListDigest, /^0x[0-9a-f]{64}$/);
  }
});

test("the amount-bearing status is receipted with a salted responseDigest (observer feed can't brute-force terms)", async () => {
  const env = await boot();
  try {
    const runId = await bindPair(env, uuid(910), "tb1", "tp1");
    await env.callTool("tb1", "contract_status", {});
    await offer(env, "tp1", "provider", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_000 });
    await env.callTool("tb1", "contract_status", {});
    const statusReceipts = env.service.receiptFeed(runId).receipts
      .filter((r) => r.tool === "contract_status" && r.principal.keyId === "kb1");
    assert.equal(statusReceipts.length, 2);
    // No offer yet: no amount in the body, plain canonical digest as before.
    assert.equal(statusReceipts[0].responseDigestScheme, "canonical");
    assert.equal(statusReceipts[1].responseDigestScheme, "hmac-sha256");
  } finally {
    env.close();
  }
});
