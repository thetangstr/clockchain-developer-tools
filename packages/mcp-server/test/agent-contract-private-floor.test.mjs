import assert from "node:assert/strict";
import test from "node:test";

import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import {
  boot, bindPair, bookPair, signedSubmit, signMandateFields, makeApproval,
  statusSchema, keys, uuid,
} from "./n4b9-harness.mjs";

// CONTRACT_PRIVATE_FLOOR (founder 2026-10-07): all-in pricing. The buyer may
// counter at any total up to its signed cap; no catalog fare is shown to or
// enforced against the buyer. The catalog fare is the agency's private cost;
// the provider's OWN offers/accepts below floorBps of it are refused
// (provider-side backstop). Off = today's fare + fee pricing.

const USD = (n) => n * 100;
const FUTURE = () => new Date(Date.now() + 600_000).toISOString();
const TRIP = { origin: "SFO", destination: "NAS", partySize: 3, budgetMinor: USD(5_000) };

function v3Mandate() {
  return signMandateFields({
    kind: "mandate", mandateVersion: 3, mandateId: `mnd3-${Math.floor(Math.random() * 1e9)}`,
    maxCapMinor: USD(5_000), currency: "USD", partyMin: 1, partyMax: 8,
    allowedItineraryIds: [], expiresAt: FUTURE(),
  });
}

async function mandated(env, sessionId) {
  await bindPair(env, sessionId, "tb1", "tp1");
  const prep = await env.callTool("tb1", "mandate_prepare", v3Mandate());
  const sub = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prep, submitTool: "mandate_submit", extraArgs: { trip: TRIP } });
  assert.equal(sub.bound, true, JSON.stringify(sub));
  const quote = await env.callTool("tp1", "catalog_quote", { origin: TRIP.origin, destination: TRIP.destination });
  return quote.itineraries[0];
}

async function offer(env, token, role, args) {
  const prep = await env.callTool(token, "offer_prepare", args);
  if (!prep.envelope) return { prep };
  const sub = await signedSubmit(env, { token, role, prepared: prep, submitTool: "offer_submit" });
  return { prep, sub };
}

async function accept(env, token, role, offerId) {
  const prep = await env.callTool(token, "offer_accept_prepare", { offerId });
  if (!prep.envelope) return { prep };
  return { prep, sub: await signedSubmit(env, { token, role, prepared: prep, submitTool: "offer_accept_submit" }) };
}

const floorOf = (fare, bps = 9000) => Math.ceil((fare * bps) / 10_000);

test("off (default): offers still price fare + fee — the buyer cannot go below the catalog fare", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const it = await mandated(env, uuid(1000 + Math.floor(Math.random() * 9000)));
    const { prep, sub } = await offer(env, "tb1", "buyer", { itineraryId: it.itineraryId, feeMinor: 0 });
    assert.equal(prep.quote.fareMinor, it.fareMinor);
    assert.equal(prep.quote.totalMinor, it.fareMinor);
    assert.equal(sub.state, "offered");
  } finally { env.close(); }
});

test("on: a real first offer, a buyer counter 10% under the catalog fare, the agency counters back above its floor, buyer accepts, books, verifies", async () => {
  const env = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  try {
    const it = await mandated(env, uuid(1000 + Math.floor(Math.random() * 9000)));
    const fare = it.fareMinor;
    const first = fare + Math.round(fare * 0.08);
    // provider: a real first offer, all-in (fee = the whole price)
    const p1 = await offer(env, "tp1", "provider", { itineraryId: it.itineraryId, feeMinor: first });
    assert.deepEqual(p1.prep.quote, { fareMinor: 0, feeMinor: first, totalMinor: first, currency: "USD" });
    assert.equal(p1.sub.state, "offered", JSON.stringify(p1.sub));

    // buyer: what the buyer sees names no fare
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success, JSON.stringify(st));
    for (const o of st.negotiation.offers) assert.equal(o.fareMinor, 0, "no catalog fare in the buyer's view");
    assert.ok(!JSON.stringify(st).includes(String(fare)), "the catalog fare never appears in the buyer's status");

    // buyer counters 10% under the catalog fare (rounded down) — accepted into the negotiation
    const low = Math.floor((fare * 0.9) / 100) * 100;
    assert.ok(low < floorOf(fare));
    const b1 = await offer(env, "tb1", "buyer", { itineraryId: it.itineraryId, feeMinor: low });
    assert.equal(b1.prep.quote.totalMinor, low);
    assert.equal(b1.sub.state, "offered", JSON.stringify(b1.sub));
    assert.equal(b1.sub.offerId, "off-0002");

    // provider cannot accept below its private floor (provider-side only)
    const pa = await accept(env, "tp1", "provider", b1.sub.offerId);
    assert.equal(pa.prep.error, "MANDATE_REFUSED", JSON.stringify(pa.prep));
    // nor counter below it
    const pLow = await offer(env, "tp1", "provider", { itineraryId: it.itineraryId, feeMinor: floorOf(fare) - 1 });
    assert.equal(pLow.prep.error, "MANDATE_REFUSED", JSON.stringify(pLow.prep));
    // it counters back at its floor
    const p2 = await offer(env, "tp1", "provider", { itineraryId: it.itineraryId, feeMinor: floorOf(fare) });
    assert.equal(p2.sub.state, "offered", JSON.stringify(p2.sub));

    // buyer accepts the agency's counter
    const ba = await accept(env, "tb1", "buyer", p2.sub.offerId);
    assert.equal(ba.sub.agreementFormed, true, JSON.stringify(ba.sub));

    const prepB = await env.callTool("tp1", "booking_prepare", { agreementId: ba.sub.agreementId });
    assert.equal(prepB.envelope.payload.totalMinor, floorOf(fare));
    const approval = makeApproval({ envelope: prepB.envelope, role: "provider", action: "booking", tool: "booking_execute", key: keys.providerApproval });
    const booked = await signedSubmit(env, { token: "tp1", role: "provider", prepared: prepB, submitTool: "booking_execute", extraArgs: { approval } });
    assert.ok(booked.orderRef, JSON.stringify(booked));

    const prepV = await env.callTool("tb1", "verification_prepare", { orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}` });
    const verified = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    assert.equal(verified.result ?? verified.verification?.result ?? "match", "match", JSON.stringify(verified));
    const lookup = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
    assert.equal(lookup.observation.totalMinor, floorOf(fare));
    assert.equal(lookup.observation.ticketCount, 3);
  } finally { env.close(); }
});

test("on: the provider may accept a buyer counter at or above its floor (still below the catalog fare)", async () => {
  const env = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  try {
    const it = await mandated(env, uuid(1000 + Math.floor(Math.random() * 9000)));
    const p1 = await offer(env, "tp1", "provider", { itineraryId: it.itineraryId, feeMinor: it.fareMinor + 15_000 });
    assert.equal(p1.sub.state, "offered");
    const at = floorOf(it.fareMinor);
    const b1 = await offer(env, "tb1", "buyer", { itineraryId: it.itineraryId, feeMinor: at });
    assert.equal(b1.sub.state, "offered");
    const pa = await accept(env, "tp1", "provider", b1.sub.offerId);
    assert.equal(pa.sub.agreementFormed, true, JSON.stringify(pa));
  } finally { env.close(); }
});

test("on: the buyer's signed cap still binds — a counter over the cap is refused, with no fare floor anywhere", async () => {
  const env = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  try {
    const it = await mandated(env, uuid(1000 + Math.floor(Math.random() * 9000)));
    const over = await offer(env, "tb1", "buyer", { itineraryId: it.itineraryId, feeMinor: USD(5_000) + 1 });
    assert.equal(over.prep.error, "MANDATE_REFUSED");
    const tiny = await offer(env, "tb1", "buyer", { itineraryId: it.itineraryId, feeMinor: 100 });
    assert.equal(tiny.sub.state, "offered", "a buyer lowball is the agency's to answer, not a server refusal");
  } finally { env.close(); }
});

test("on: a v2 (Rome) run keeps fare + fee pricing byte for byte — the flag applies to v3 runs only", async () => {
  const pf = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  const off = await boot({ flexPolicy: true });
  try {
    const sid = uuid(1000 + Math.floor(Math.random() * 9000));
    const a = await bookPair(pf, sid, "tb1", "tp1");
    const b = await bookPair(off, sid, "tb1", "tp1");
    assert.ok(a.booked.orderRef && b.booked.orderRef, JSON.stringify([a.booked, b.booked]));
    const ga = await pf.callTool("tb1", "agreement_get", {});
    const gb = await off.callTool("tb1", "agreement_get", {});
    assert.ok(ga.agreement.fareMinor > 0);
    assert.equal(ga.agreement.fareMinor, gb.agreement.fareMinor);
    assert.equal(ga.agreement.totalMinor, gb.agreement.totalMinor);
  } finally { pf.close(); off.close(); }
});

test("on: a provider offer before the buyer's mandate is refused STATE_REFUSED (pricing model not yet known)", async () => {
  const env = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  try {
    await bindPair(env, uuid(1000 + Math.floor(Math.random() * 9000)), "tb1", "tp1");
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "NAS" });
    const r = await env.callTool("tp1", "offer_prepare", { itineraryId: q.itineraries[0].itineraryId, feeMinor: 500_000 });
    assert.equal(r.error, "STATE_REFUSED", JSON.stringify(r));
  } finally { env.close(); }
});

test("on: tools/list is byte-identical with the flag on and off", async () => {
  const list = async (opts) => {
    const env = await boot(opts);
    try {
      const init = await fetch(env.baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer tb1" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
      });
      const sid = init.headers.get("mcp-session-id");
      await init.text();
      const res = await fetch(env.baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer tb1", "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      const text = await res.text();
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      return JSON.stringify(JSON.parse(data ? data.slice(5) : text).result);
    } finally { env.close(); }
  };
  const off = await list({ flexPolicy: true });
  const on = await list({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  assert.ok(off.includes("offer_prepare"));
  assert.equal(on, off);
});

test("sim: bookOrder with a stated fare checks total = stated fare + fee and records it; absent = the catalog fare as before", () => {
  const run = createSimWorld({}).forRun("pf");
  run.setParty(3);
  const it = run.quote({ origin: "SFO", destination: "NAS" }).itineraries[0];
  assert.equal(run.bookOrder({ agreementId: "agr-1", itineraryId: it.itineraryId, feeMinor: 100, totalMinor: 100 }).code, "FARE_MISMATCH");
  const ok = run.bookOrder({ agreementId: "agr-2", itineraryId: it.itineraryId, feeMinor: 100, totalMinor: 100, fareMinor: 0 });
  assert.ok(ok.orderRef, JSON.stringify(ok));
  assert.equal(run.bookOrder({ agreementId: "agr-3", itineraryId: it.itineraryId, feeMinor: 100, totalMinor: 101, fareMinor: 0 }).code, "FARE_MISMATCH");
});

test("config: CONTRACT_PRIVATE_FLOOR is a strict 0|1 switch, off by default; BPS defaults to 9000 and is range-checked", async () => {
  const { loadContractConfig } = await import("../dist/agent-contract/config.js");
  const { HOST_ROOTS, POLICY } = await import("./n4b9-harness.mjs");
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const path = await import("node:path");
  const baseEnv = (extra = {}) => ({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 9).toString("base64"),
    CONTRACT_SERVER_KEY_ID: "contract-server-pf",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "pf-cfg-")),
    ...extra,
  });
  for (const v of [undefined, "", "0", "1"]) {
    const cfg = loadContractConfig(baseEnv(v === undefined ? {} : { CONTRACT_PRIVATE_FLOOR: v }));
    assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
    cfg.service.close();
  }
  for (const bad of [{ CONTRACT_PRIVATE_FLOOR: "true" }, { CONTRACT_PRIVATE_FLOOR: "1", CONTRACT_PRIVATE_FLOOR_BPS: "10001" }, { CONTRACT_PRIVATE_FLOOR_BPS: "abc" }]) {
    const cfg = loadContractConfig(baseEnv(bad));
    assert.equal(cfg.kind, "misconfigured", JSON.stringify(bad));
  }
});
