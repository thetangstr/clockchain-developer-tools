import assert from "node:assert/strict";
import test from "node:test";

import {
  boot, bookPair, bindPair, signedSubmit, signMandate, signMandateFields,
  uuid,
} from "./n4b9-harness.mjs";

// N4b-9 — F16 (spec D12): the principal-signed partySize drives
// travellers → ticketCount; verification recomputes match.

test("F16: Rome family of 4 — partySize issues 4 tickets and verification recomputes match", async () => {
  const env = await boot();
  try {
    const { booked } = await bookPair(env, uuid(505), "tb1", "tp1", {
      itineraryId: "IT-ROME-ZX118-ECON", feeMinor: 10_000,
      mandateOverrides: { partySize: 4, capMinor: 700_000 },
    });
    assert.equal(booked.tickets.length, 4, "one ticket per partySize traveller");

    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
    assert.equal(looked.observation.ticketCount, 4);
    // the booking's own party size (the principal-signed mandate's), so a buyer compares like with like
    assert.equal(looked.observation.travellers, 4);
    // never a caller input: the lookup schema is strict
    const forged = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef, travellers: 9 });
    assert.equal(forged.rpcError?.code, -32602, JSON.stringify(forged));
    assert.equal(forged.observation, undefined);

    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
    });
    const verified = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    assert.equal(verified.outcome, "match", JSON.stringify(verified));
    assert.equal(verified.flagged, false);
  } finally { env.close(); }
});

test("F16: a short booking can never verify as match — the model's match is flagged", async () => {
  const sessionId = uuid(506);
  // The sim fault issues partySize+1 tickets (the only injectable count
  // drift; the check is ticketCount === partySize, so either direction fails).
  const env = await boot({ simFaults: { [sessionId]: { issueMismatch: "travellers" } } });
  try {
    const { booked } = await bookPair(env, sessionId, "tb1", "tp1", {
      mandateOverrides: { partySize: 4, capMinor: 700_000 },
    });
    assert.equal(booked.tickets.length, 5);
    // the observation keeps the booked party size apart from what was issued: 4 booked, 5 tickets
    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
    assert.equal(looked.observation.travellers, 4);
    assert.equal(looked.observation.ticketCount, 5);

    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"ee".repeat(32)}`,
    });
    const verified = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    // ticketCount (5) !== partySize (4) → observed mismatch; the claimed
    // match is flagged and the run ends verification_failed.
    assert.equal(verified.outcome, "match");
    assert.equal(verified.flagged, true);
    assert.equal(verified.terminalState, "verification_failed");
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "verification_failed");
  } finally { env.close(); }
});

test("F16: a mandate without partySize is refused (v2.2 makes it required)", async () => {
  const env = await boot();
  try {
    await bindPair(env, uuid(507), "tb1", "tp1");
    const legacy = signMandate();
    delete legacy.mandate.partySize;
    // Re-sign the v2-shaped mandate itself — the refusal must be the missing
    // field, not a stale signature.
    const signed = signMandateFields(legacy.mandate);
    const prep = await env.callTool("tb1", "mandate_prepare", signed);
    assert.equal(prep.error, "MANDATE_INVALID", JSON.stringify(prep));
  } finally { env.close(); }
});
