import assert from "node:assert/strict";
import test from "node:test";

import { eip191SignDigest32 } from "../dist/agent-contract/eip191.js";
import { policyRegistrationDigest } from "../dist/agent-contract/policy-registry.js";
import { CONTRACT_TOOL_DEFS } from "../dist/agent-contract/schemas.js";
import { contractRefusalSchema } from "../dist/agent-contract/refusals.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import {
  boot, bindPair, signedSubmit, signMandate, signMandateFields, makeApproval,
  statusSchema, keys, uuid, SIGNER,
} from "./n4b9-harness.mjs";

// Flexible family policy (mandate v3): a principal-signed RANGE (ceiling, party
// range, optional allowlist) plus a per-run, unsigned trip statement. v2
// mandates and the Rome behaviour must stay byte-identical (the rest of the
// suite covers v2; the Rome regression here pins the numbers).

const USD = (n) => n * 100;
const FUTURE = () => new Date(Date.now() + 600_000).toISOString();

function v3Mandate(overrides = {}) {
  return signMandateFields({
    kind: "mandate",
    mandateVersion: 3,
    mandateId: `mnd3-${Math.floor(Math.random() * 1e9)}`,
    maxCapMinor: USD(20_000),
    currency: "USD",
    partyMin: 1,
    partyMax: 8,
    allowedItineraryIds: [],
    expiresAt: FUTURE(),
    ...overrides,
  });
}

/** bind + mandate_prepare (does NOT submit). */
async function prepareMandate(env, sessionId, signed) {
  await bindPair(env, sessionId, "tb1", "tp1");
  return env.callTool("tb1", "mandate_prepare", signed);
}

async function submitMandate(env, prep, trip) {
  return signedSubmit(env, {
    token: "tb1", role: "buyer", prepared: prep, submitTool: "mandate_submit",
    extraArgs: trip === undefined ? {} : { trip },
  });
}

/**
 * Full flow for a v3 mandate: bind, mandate (with trip), provider quote,
 * cheapest-itinerary offer, accept, book. Returns what the tests need.
 */
async function flexBook(env, sessionId, { mandate, trip, pick = (its) => its[0], feeMinor = 10_000, mutateOffer } = {}) {
  const prep = await prepareMandate(env, sessionId, v3Mandate(mandate));
  assert.ok(prep.envelope, JSON.stringify(prep));
  const sub = await submitMandate(env, prep, trip);
  assert.equal(sub.bound, true, JSON.stringify(sub));
  const quote = await env.callTool("tp1", "catalog_quote", { origin: trip.origin, destination: trip.destination });
  const itinerary = pick(quote.itineraries);
  const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: itinerary.itineraryId, feeMinor });
  if (!prepO.envelope) return { quote, itinerary, offerPrep: prepO };
  const offered = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  const prepA = await env.callTool("tp1", "offer_accept_prepare", { offerId: offered.offerId });
  const accepted = await signedSubmit(env, { token: "tp1", role: "provider", prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  const prepB = await env.callTool("tp1", "booking_prepare", { agreementId: accepted.agreementId });
  const approval = makeApproval({
    envelope: prepB.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit(env, {
    token: "tp1", role: "provider", prepared: prepB, submitTool: "booking_execute", extraArgs: { approval },
  });
  return { quote, itinerary, offered, accepted, booked };
}

async function verify(env, orderRef) {
  const prepV = await env.callTool("tb1", "verification_prepare", {
    orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
  });
  return signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
}

// ---- sim ---------------------------------------------------------------------

test("sim: Rome canonical ids reprice to the same totals for a party of 4 and scale per person otherwise", () => {
  const world = createSimWorld({});
  const legacy = world.forRun("legacy-run").quote({ origin: "SFO", destination: "FCO" });
  const legacyById = new Map(legacy.itineraries.map((i) => [i.itineraryId, i]));
  assert.equal(legacyById.get("IT-ROME-ZX118-ECON").fareMinor, 481800);
  assert.equal(legacyById.get("IT-ROME-ZX118-ECON").farePerPersonMinor, undefined, "v2/pre-party rows carry no per-person field");

  const r4 = world.forRun("party-4");
  assert.equal(r4.setParty(4), true);
  const q4 = new Map(r4.quote({ origin: "SFO", destination: "FCO" }).itineraries.map((i) => [i.itineraryId, i]));
  for (const id of ["IT-ROME-ZX118-ECON", "IT-ROME-ZX118-PREM", "IT-ROME-QW-ONESTOP", "IT-ROME-2STOP-A", "IT-ROME-2STOP-B"]) {
    assert.equal(q4.get(id).fareMinor, legacyById.get(id).fareMinor, `${id} total at party 4`);
  }
  assert.equal(q4.get("IT-ROME-ZX118-ECON").farePerPersonMinor, 120450);

  const r2 = world.forRun("party-2");
  r2.setParty(2);
  assert.equal(r2.itinerary("IT-ROME-ZX118-ECON").fareMinor, 240900);
  assert.equal(r2.setParty(3), false, "party is write-once");
  assert.equal(r2.setParty(2), true, "same party is idempotent");
  assert.equal(world.forRun("bad").setParty(0), false);
});

test("sim: generated ids never change; v3 boards are per person with economy / premium / one-stop labels", () => {
  const world = createSimWorld({});
  const before = world.forRun("a").quote({ origin: "SFO", destination: "NAS" });
  // the documented pre-change ids and fares for SFO-NAS
  assert.deepEqual(before.itineraries.map((i) => [i.itineraryId, i.fareMinor]), [
    ["IT-E06FA7", 395500], ["IT-16D161", 510100], ["IT-28E699", 587800],
  ]);
  assert.match(before.itineraries[0].summary, /option A$/);

  const run = world.forRun("b");
  run.setParty(2);
  const after = run.quote({ origin: "SFO", destination: "NAS" });
  assert.deepEqual(after.itineraries.map((i) => i.itineraryId), before.itineraries.map((i) => i.itineraryId));
  assert.match(after.itineraries[0].summary, /economy, nonstop/);
  assert.match(after.itineraries[1].summary, /premium economy/);
  assert.match(after.itineraries[2].summary, /1 stop/);
  for (const i of after.itineraries) {
    assert.equal(i.fareMinor, i.farePerPersonMinor * 2);
    assert.ok(i.farePerPersonMinor >= 40_000 && i.farePerPersonMinor <= 150_000, String(i.farePerPersonMinor));
  }
  assert.ok(after.itineraries[1].farePerPersonMinor > after.itineraries[0].farePerPersonMinor);
  assert.ok(after.itineraries[2].farePerPersonMinor < after.itineraries[0].farePerPersonMinor);
});

// ---- mandate v3 / trip --------------------------------------------------------

test("v3: Bahamas 2 under $4,000 — books, 2 tickets, verifies, status shows the policy", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "NAS", partySize: 2, budgetMinor: USD(4_000) };
    const r = await flexBook(env, uuid(801), { trip });
    assert.equal(r.itinerary.fareMinor, r.itinerary.farePerPersonMinor * 2);
    assert.equal(r.booked.tickets.length, 2);
    assert.equal(r.accepted.agreementFormed, true);

    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: r.booked.orderRef });
    assert.equal(looked.observation.travellers, 2);
    assert.equal(looked.observation.ticketCount, 2);
    const verified = await verify(env, r.booked.orderRef);
    assert.equal(verified.outcome, "match", JSON.stringify(verified));
    assert.equal(verified.flagged, false);

    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success, JSON.stringify(st));
    assert.deepEqual(st.policy, {
      mandateVersion: 3, maxCapMinor: USD(20_000), currency: "USD", partyMin: 1, partyMax: 8,
      destinations: "any", trip,
    });
    // the provider sees route + party only: never the cap or the budget
    const pst = await env.callTool("tp1", "contract_status", {});
    assert.deepEqual(pst.policy, {
      mandateVersion: 3, trip: { origin: "SFO", destination: "NAS", partySize: 2 },
    });
  } finally { env.close(); }
});

test("v3: Tokyo 5 under $15,000 — 5 tickets and the booking payload carries travellers 5", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "HND", partySize: 5, budgetMinor: USD(15_000) };
    const r = await flexBook(env, uuid(802), { trip, pick: (its) => its[1] });
    assert.equal(r.booked.tickets.length, 5);
    assert.equal(r.itinerary.fareMinor, r.itinerary.farePerPersonMinor * 5);
    assert.ok(r.offered.state === "offered");
    const verified = await verify(env, r.booked.orderRef);
    assert.equal(verified.outcome, "match");
    assert.equal(verified.flagged, false);
  } finally { env.close(); }
});

test("v3: Rome 4 regression — canonical Rome ids price at the unchanged party-of-4 totals", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(6_800) };
    const r = await flexBook(env, uuid(803), {
      mandate: { maxCapMinor: 700_000, partyMin: 4, partyMax: 4, allowedItineraryIds: ["IT-ROME-ZX118-ECON"] },
      trip, pick: (its) => its.find((i) => i.itineraryId === "IT-ROME-ZX118-ECON"),
    });
    assert.equal(r.itinerary.fareMinor, 481800);
    assert.equal(r.booked.tickets.length, 4);
    const verified = await verify(env, r.booked.orderRef);
    assert.equal(verified.outcome, "match");
  } finally { env.close(); }
});

test("v3: an allowlist still binds — an itinerary outside it is refused MANDATE_REFUSED", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(6_800) };
    const r = await flexBook(env, uuid(804), {
      mandate: { allowedItineraryIds: ["IT-ROME-ZX118-ECON"] },
      trip, pick: (its) => its.find((i) => i.itineraryId === "IT-ROME-QW-ONESTOP"),
    });
    assert.equal(r.offerPrep.error, "MANDATE_REFUSED", JSON.stringify(r.offerPrep));
  } finally { env.close(); }
});

test("v3: an itinerary on another route than the stated trip is refused", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const prep = await prepareMandate(env, uuid(805), v3Mandate());
    const sub = await submitMandate(env, prep, { origin: "SFO", destination: "NAS", partySize: 2, budgetMinor: USD(4_000) });
    assert.equal(sub.bound, true);
    // IT-ROME-ZX118-ECON is canonical (always known) but is SFO-FCO
    const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: "IT-ROME-ZX118-ECON", feeMinor: 10_000 });
    assert.equal(prepO.error, "MANDATE_REFUSED", JSON.stringify(prepO));
  } finally { env.close(); }
});

test("v3: over the maxCap — an offer whose total exceeds the ceiling is refused MANDATE_REFUSED", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "NAS", partySize: 8, budgetMinor: USD(1_000) };
    // ceiling $1,000: 8 people on any NAS option is far above it
    const r = await flexBook(env, uuid(806), { mandate: { maxCapMinor: USD(1_000) }, trip });
    assert.equal(r.offerPrep.error, "MANDATE_REFUSED", JSON.stringify(r.offerPrep));
  } finally { env.close(); }
});

test("v3: ticket-count mismatch — a short/over-issued booking can never verify as match", async () => {
  const sessionId = uuid(807);
  const env = await boot({ flexPolicy: true, simFaults: { [sessionId]: { issueMismatch: "travellers" } } });
  try {
    const trip = { origin: "SFO", destination: "NAS", partySize: 2, budgetMinor: USD(4_000) };
    const r = await flexBook(env, sessionId, { trip });
    assert.equal(r.booked.tickets.length, 3, "fault issues party+1 tickets");
    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: r.booked.orderRef });
    assert.equal(looked.observation.travellers, 2);
    assert.equal(looked.observation.ticketCount, 3);
    const verified = await verify(env, r.booked.orderRef);
    assert.equal(verified.flagged, true, JSON.stringify(verified));
    assert.equal(verified.terminalState, "verification_failed");
  } finally { env.close(); }
});

test("trip refusals: out-of-range party, over-cap budget, missing and malformed trips use distinct codes and change no state", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const prep = await prepareMandate(env, uuid(808), v3Mandate({ maxCapMinor: USD(5_000), partyMin: 2, partyMax: 6 }));
    assert.ok(prep.envelope, JSON.stringify(prep));
    const base = { origin: "SFO", destination: "NAS", partySize: 3, budgetMinor: USD(3_000) };

    assert.equal((await submitMandate(env, prep, undefined)).error, "TRIP_REQUIRED");
    assert.equal((await submitMandate(env, prep, { ...base, partySize: 1 })).error, "PARTY_OUT_OF_RANGE");
    assert.equal((await submitMandate(env, prep, { ...base, partySize: 7 })).error, "PARTY_OUT_OF_RANGE");
    assert.equal((await submitMandate(env, prep, { ...base, budgetMinor: USD(5_001) })).error, "BUDGET_OVER_CAP");
    assert.equal((await submitMandate(env, prep, { ...base, budgetMinor: 0 })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, { ...base, budgetMinor: -5 })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, { ...base, partySize: 2.5 })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, { ...base, origin: "sfo" })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, { ...base, destination: "SFO" })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, { ...base, extra: 1 })).error, "TRIP_INVALID");

    // no state change: the SAME prepared envelope and signature still bind with a valid trip
    const ok = await submitMandate(env, prep, base);
    assert.equal(ok.bound, true, JSON.stringify(ok));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.stage, "mandated");
    assert.equal(st.policy.trip.partySize, 3);
    // write-once: a second submit of the same envelope is refused, never a second bind
    assert.ok((await submitMandate(env, prep, base)).error);
  } finally { env.close(); }
});

test("v3 shape: a malformed or v2-mixed mandate is MANDATE_INVALID", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    await bindPair(env, uuid(809), "tb1", "tp1");
    const good = {
      kind: "mandate", mandateVersion: 3, mandateId: "mnd3-shape", maxCapMinor: 100, currency: "USD",
      partyMin: 1, partyMax: 8, allowedItineraryIds: [], expiresAt: FUTURE(),
    };
    for (const bad of [
      { ...good, partyMin: 5, partyMax: 2 },
      { ...good, partyMax: 9 },
      { ...good, partyMin: 0 },
      { ...good, maxCapMinor: 0 },
      { ...good, capMinor: 100 },
      { ...good, partySize: 2 },
      { ...good, mandateVersion: 2 },
      { ...good, mandateVersion: 4 },
    ]) {
      const r = await env.callTool("tb1", "mandate_prepare", signMandateFields(bad));
      assert.equal(r.error, "MANDATE_INVALID", JSON.stringify(bad));
    }
    // a v3 mandate that carries v2 keys only is not v3: strict v2 refuses the v3 keys
    const mixed = signMandate({ maxCapMinor: 5 });
    assert.equal((await env.callTool("tb1", "mandate_prepare", mixed)).error, "MANDATE_INVALID");
    assert.ok((await env.callTool("tb1", "mandate_prepare", signMandateFields(good))).envelope);
  } finally { env.close(); }
});

test("v2 stays as is: no trip needed, no policy block, fares and travellers unchanged", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    await bindPair(env, uuid(810), "tb1", "tp1");
    const prepM = await env.callTool("tb1", "mandate_prepare", signMandate({
      capMinor: 700_000, partySize: 4, allowedItineraryIds: ["IT-ROME-ZX118-ECON"],
    }));
    const m = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
    assert.equal(m.bound, true, JSON.stringify(m));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.policy, undefined, "a v2 run without a trip has no policy block");
    assert.equal(st.stage, "mandated");
  } finally { env.close(); }
});

test("v2 with an optional trip: validated against the signed party and cap, then recorded", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const mk = () => signMandate({ capMinor: 700_000, partySize: 4, allowedItineraryIds: ["IT-ROME-ZX118-ECON"] });
    const prep = await prepareMandate(env, uuid(811), mk());
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: 680_000 };
    assert.equal((await submitMandate(env, prep, { ...trip, partySize: 3 })).error, "PARTY_OUT_OF_RANGE");
    assert.equal((await submitMandate(env, prep, { ...trip, budgetMinor: 700_001 })).error, "BUDGET_OVER_CAP");
    const ok = await submitMandate(env, prep, trip);
    assert.equal(ok.bound, true, JSON.stringify(ok));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.policy.mandateVersion, 2);
    assert.equal(st.policy.maxCapMinor, 700_000);
    assert.deepEqual(st.policy.trip, trip);
    assert.deepEqual(st.policy.destinations, ["IT-ROME-ZX118-ECON"]);
  } finally { env.close(); }
});

test("mandate_submit input schema accepts an optional trip; the new refusal codes are in the refusal enum", () => {
  const def = CONTRACT_TOOL_DEFS.find((d) => d.name === "mandate_submit");
  assert.ok("trip" in def.schema);
  assert.equal(def.schema.trip.isOptional(), true);
  for (const code of ["TRIP_REQUIRED", "TRIP_INVALID", "PARTY_OUT_OF_RANGE", "BUDGET_OVER_CAP"]) {
    assert.equal(contractRefusalSchema.safeParse({ error: code, retryable: false }).success, true, code);
  }
});

// ---- listings ----------------------------------------------------------------

test("listings: a not-route-locked listing (terms {} or {origin/destination:'any'}) matches any search; locked ones still filter", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    await bindPair(env, uuid(812), "tb1", "tp1");
    const publish = async (title, terms) => env.callTool("tp1", "rendezvous_publish_listing", {
      title, summary: "any trip", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`, ...(terms === undefined ? {} : { terms }),
    });
    const open = await publish("Open desk", {});
    const found = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "NAS" });
    assert.ok(found.listings.some((l) => l.listingId === open.listingId), "terms {} matches");

    const any = await publish("Any-route desk", { origin: "any", destination: "any", routes: "any" });
    const found2 = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "HND" });
    assert.ok(found2.listings.some((l) => l.listingId === any.listingId), "'any' matches");

    const rome = await publish("Rome desk", { origin: "SFO", destination: "FCO" });
    const found3 = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "NAS" });
    assert.ok(!found3.listings.some((l) => l.listingId === rome.listingId), "a Rome-locked listing does not match NAS");
    const found4 = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "FCO" });
    assert.ok(found4.listings.some((l) => l.listingId === rome.listingId), "Rome listings keep matching");
  } finally { env.close(); }
});

// ---- policy registry ----------------------------------------------------------

test("policy registry: a registered digest authorizes a v3 run's settlement without a restart", async () => {
  const REG = `0x${"6b".repeat(32)}`;
  const env = await boot({ flexPolicy: true, policyRegistration: true });
  try {
    const trip = { origin: "SFO", destination: "NAS", partySize: 2, budgetMinor: USD(4_000) };
    const r = await flexBook(env, uuid(813), { trip });
    const verified = await verify(env, r.booked.orderRef);
    assert.equal(verified.flagged, false, JSON.stringify(verified));

    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const d = policyRegistrationDigest({ audience: SIGNER.keyId, chainId: null, tokenKeyId: "kb1", digest: REG, expiresAt });
    const reg = await env.callTool("tb1", "contract_register_policy", {
      role: "buyer", digest: REG, expiresAt,
      principalSig: eip191SignDigest32(Buffer.from(d.slice(2), "hex"), keys.principal.priv),
    });
    assert.equal(reg.registered, true, JSON.stringify(reg));

    const prepS = await env.callTool("tb1", "settlement_prepare", {});
    assert.ok(prepS.envelope, JSON.stringify(prepS));
    const denied = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS, submitTool: "settlement_authorize",
      extraArgs: { approval: makeApproval({ envelope: prepS.envelope, role: "buyer", action: "settlement", tool: "settlement_authorize", key: keys.buyerApproval, policyDigest: `0x${"11".repeat(32)}` }) },
    });
    assert.ok(denied.error, "an unregistered digest is refused");
    const prepS2 = await env.callTool("tb1", "settlement_prepare", {});
    const settled = await signedSubmit(env, {
      token: "tb1", role: "buyer", prepared: prepS2, submitTool: "settlement_authorize",
      extraArgs: { approval: makeApproval({ envelope: prepS2.envelope, role: "buyer", action: "settlement", tool: "settlement_authorize", key: keys.buyerApproval, policyDigest: REG }) },
    });
    assert.equal(settled.status, "released", JSON.stringify(settled));
  } finally { env.close(); }
});

// ---- default off ---------------------------------------------------------------

test("default off: no v3 mandate, no trip argument, no 'any' listing wildcard, v2 untouched", async () => {
  const env = await boot();
  try {
    assert.equal(env.service.features.flexPolicy, undefined);
    await bindPair(env, uuid(820), "tb1", "tp1");
    assert.equal((await env.callTool("tb1", "mandate_prepare", v3Mandate())).error, "MANDATE_INVALID");

    const prepM = await env.callTool("tb1", "mandate_prepare", signMandate());
    assert.ok(prepM.envelope);
    const withTrip = await submitMandate(env, prepM, { origin: "SFO", destination: "NAS", partySize: 2, budgetMinor: 1000 });
    assert.equal(withTrip.rpcError?.code, -32602, "the flag-off surface has no trip argument");
    const ok = await submitMandate(env, prepM, undefined);
    assert.equal(ok.bound, true, JSON.stringify(ok));

    const any = await env.callTool("tp1", "rendezvous_publish_listing", {
      title: "Any desk", summary: "x", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`, terms: { origin: "any", destination: "any" },
    });
    const found = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "NAS" });
    assert.ok(!found.listings.some((l) => l.listingId === any.listingId), "'any' is not a wildcard while the flag is off");
  } finally { env.close(); }
});

test("config: CONTRACT_FLEX_POLICY is a strict 0|1 switch, off by default", async () => {
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
    CONTRACT_SERVER_KEY_ID: "contract-server-flex",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "flex-cfg-")),
    ...extra,
  });
  for (const [value, expected] of [[undefined, undefined], ["", undefined], ["0", undefined], ["1", true]]) {
    const cfg = loadContractConfig(baseEnv(value === undefined ? {} : { CONTRACT_FLEX_POLICY: value }));
    assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
    try { assert.equal(cfg.service.features.flexPolicy, expected, `CONTRACT_FLEX_POLICY=${value}`); }
    finally { cfg.service.close(); }
  }
  for (const bad of ["true", "on", "2"]) {
    const cfg = loadContractConfig(baseEnv({ CONTRACT_FLEX_POLICY: bad }));
    assert.equal(cfg.kind, "misconfigured");
    assert.match(cfg.reason, /CONTRACT_FLEX_POLICY wants 0 or 1/);
  }
});
