import assert from "node:assert/strict";
import test from "node:test";

import {
  createSimWorld, simFareLines, SIM_FARE_RULE, SIM_TAXES_PER_TRAVELLER_MINOR,
} from "../dist/agent-contract/sim/index.js";
import {
  boot, bindPair, signedSubmit, signMandate, signMandateFields, makeApproval,
  statusSchema, keys, uuid,
} from "./n4b9-harness.mjs";

// D1459 trip detail: a family trip statement that carries dates (and the
// travellers' make-up) turns the run into a "dated run". The sim then serves
// a dated board with a simulated ZX schedule, every offer and the agreement
// carry per-traveller fare lines that add up to the offer total, and the
// booking record echoes dates, flights, travellers (synthetic initials),
// record locator and ticketing status. Undated runs are untouched.

const USD = (n) => n * 100;
const FUTURE = () => new Date(Date.now() + 600_000).toISOString();
const DAY = 86_400_000;
/** `YYYY-MM-DD`, `days` after the server's UTC today. */
const inDays = (days) => new Date(Date.parse(`${new Date().toISOString().slice(0, 10)}T00:00:00Z`) + days * DAY).toISOString().slice(0, 10);

const ROME_IDS = ["IT-349482", "IT-DE1D13", "IT-652630", "IT-EC313C"];
const ROME_PER_PERSON = [90600, 140400, 74300, 96000];
const FAMILY = { adults: 2, childAges: [12, 9] };
const ROME_DATES = { departDate: "2027-03-27", returnDate: "2027-04-03" };

function v3Mandate(overrides = {}) {
  return signMandateFields({
    kind: "mandate", mandateVersion: 3, mandateId: `mnd3-${Math.floor(Math.random() * 1e9)}`,
    maxCapMinor: USD(20_000), currency: "USD", partyMin: 1, partyMax: 8,
    allowedItineraryIds: [], expiresAt: FUTURE(), ...overrides,
  });
}

async function prepareMandate(env, sessionId, signed = v3Mandate()) {
  await bindPair(env, sessionId, "tb1", "tp1");
  return env.callTool("tb1", "mandate_prepare", signed);
}

function submitMandate(env, prep, trip) {
  return signedSubmit(env, {
    token: "tb1", role: "buyer", prepared: prep, submitTool: "mandate_submit",
    extraArgs: trip === undefined ? {} : { trip },
  });
}

async function offer(env, token, role, args) {
  const prep = await env.callTool(token, "offer_prepare", args);
  assert.ok(prep.envelope, JSON.stringify(prep));
  const sub = await signedSubmit(env, { token, role, prepared: prep, submitTool: "offer_submit" });
  assert.equal(sub.state, "offered", JSON.stringify(sub));
  return sub;
}

async function acceptAndBook(env, offerId, { acceptToken = "tp1", acceptRole = "provider" } = {}) {
  const prepA = await env.callTool(acceptToken, "offer_accept_prepare", { offerId });
  assert.ok(prepA.envelope, JSON.stringify(prepA));
  const accepted = await signedSubmit(env, { token: acceptToken, role: acceptRole, prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  const prepB = await env.callTool("tp1", "booking_prepare", { agreementId: accepted.agreementId });
  const approval = makeApproval({
    envelope: prepB.envelope, role: "provider", action: "booking", tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit(env, {
    token: "tp1", role: "provider", prepared: prepB, submitTool: "booking_execute", extraArgs: { approval },
  });
  assert.ok(booked.orderRef, JSON.stringify(booked));
  return { accepted, booked };
}

function assertFareLines(lines, totalMinor, adults, childAges) {
  assert.equal(lines.length, adults + childAges.length);
  assert.equal(lines.reduce((s, l) => s + l.totalMinor, 0), totalMinor, `fare lines sum to ${totalMinor}`);
  lines.forEach((l, i) => {
    const child = i >= adults;
    assert.equal(l.traveller, child ? `CHD${i - adults + 1}` : `ADT${i + 1}`);
    assert.equal(l.type, child ? "child" : "adult");
    if (child) assert.equal(l.age, childAges[i - adults]); else assert.equal("age" in l, false);
    assert.equal(l.taxesMinor, Math.min(SIM_TAXES_PER_TRAVELLER_MINOR, l.totalMinor));
    assert.equal(l.baseMinor, l.totalMinor - l.taxesMinor);
    assert.ok(l.baseMinor >= 0 && l.totalMinor >= 0, JSON.stringify(l));
  });
}

function datedSim(runId, { dates = ROME_DATES, family = FAMILY } = {}) {
  const world = createSimWorld({ now: () => Date.parse("2026-10-25T12:00:00Z") });
  const run = world.forRun(runId);
  assert.equal(run.setParty(family.adults + family.childAges.length), true);
  assert.equal(run.setTrip({ ...dates, ...family }), true);
  return run;
}

const segs = (detail) => detail.segments.map((s) =>
  `${s.direction} ${s.carrierCode}/${s.flightNumber} ${s.origin} ${s.departureLocal} -> ${s.destination} ${s.arrivalLocal} ${s.durationMinutes}m ${s.cabin}`);

// ---- trip validation -------------------------------------------------------------

test("trip validation: dates both-or-neither, real and in order, inside today..+400 days; adults+childAges both-or-neither and = partySize", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const prep = await prepareMandate(env, uuid(1459));
    assert.ok(prep.envelope, JSON.stringify(prep));
    const base = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(4_200) };
    const dates = { departDate: inDays(150), returnDate: inDays(157) };
    const bad = [
      { ...base, departDate: dates.departDate },                          // depart without return
      { ...base, returnDate: dates.returnDate },                          // return without depart
      { ...base, departDate: dates.returnDate, returnDate: dates.departDate }, // return before depart
      { ...base, departDate: dates.departDate, returnDate: dates.departDate }, // same day
      { ...base, departDate: "2027-02-30", returnDate: "2027-03-05" },    // not a calendar date
      { ...base, departDate: "2027-3-27", returnDate: "2027-04-03" },     // not YYYY-MM-DD
      { ...base, departDate: inDays(-1), returnDate: inDays(6) },         // before the server's today
      { ...base, departDate: inDays(401), returnDate: inDays(408) },      // more than 400 days ahead
      { ...base, ...dates, adults: 2 },                                   // adults without childAges
      { ...base, ...dates, childAges: [12, 9] },                          // childAges without adults
      { ...base, ...dates, adults: 2, childAges: [12] },                  // 2 + 1 != 4
      { ...base, ...dates, adults: 3, childAges: [12, 9] },               // 3 + 2 != 4
      { ...base, ...dates, adults: 0, childAges: [12, 9, 7, 5] },         // adults >= 1
      { ...base, ...dates, adults: 2, childAges: [1, 9] },                // ages 2..17
      { ...base, ...dates, adults: 2, childAges: [18, 9] },
      { ...base, ...dates, adults: 2, childAges: [12.5, 9] },
      { ...base, ...dates, adults: 2, childAges: "12,9" },
    ];
    for (const trip of bad) {
      assert.equal((await submitMandate(env, prep, trip)).error, "TRIP_INVALID", JSON.stringify(trip));
    }
    // a well-formed family of 9 against partyMax 8 is a party-range refusal, not a trip-shape one
    assert.equal((await submitMandate(env, prep, {
      ...base, partySize: 9, ...dates, adults: 1, childAges: [2, 3, 4, 5, 6, 7, 8, 9],
    })).error, "PARTY_OUT_OF_RANGE");
    // more than 8 child ages is TRIP_INVALID
    assert.equal((await submitMandate(env, prep, {
      ...base, partySize: 9, ...dates, adults: 1, childAges: [2, 3, 4, 5, 6, 7, 8, 9, 10],
    })).error, "TRIP_INVALID");

    // the window edges are inclusive: today and today + 400 both pass the shape check
    // (the prepared envelope is still unclaimed — every refusal above changed no state)
    const st0 = await env.callTool("tb1", "contract_status", {});
    assert.equal(st0.stage, "bound");
    const ok = await submitMandate(env, prep, { ...base, departDate: inDays(400), returnDate: inDays(410), ...FAMILY });
    assert.equal(ok.bound, true, JSON.stringify(ok));
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success, JSON.stringify(st));
    assert.deepEqual(st.policy.trip, { ...base, departDate: inDays(400), returnDate: inDays(410), ...FAMILY });
  } finally { env.close(); }
});

test("trip validation: departDate = the server's UTC today is accepted; dates without adults/childAges mean all adults", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const prep = await prepareMandate(env, uuid(1460));
    const trip = { origin: "SFO", destination: "FCO", partySize: 3, budgetMinor: USD(4_000), departDate: inDays(0), returnDate: inDays(5) };
    const ok = await submitMandate(env, prep, trip);
    assert.equal(ok.bound, true, JSON.stringify(ok));
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "FCO" });
    const o = await offer(env, "tb1", "buyer", { itineraryId: q.itineraries[0].itineraryId, feeMinor: 10_000 });
    const st = await env.callTool("tb1", "contract_status", {});
    const lines = st.negotiation.offers.find((x) => x.offerId === o.offerId).itinerary.fareLines;
    assertFareLines(lines, q.itineraries[0].fareMinor + 10_000, 3, []);
    assert.deepEqual(lines.map((l) => l.traveller), ["ADT1", "ADT2", "ADT3"]);
  } finally { env.close(); }
});

// ---- the dated board (sim) ---------------------------------------------------------

test("sim: a dated SFO-FCO board is the three flex rows (same ids, same per-person fares) plus the later-return row, each with its ZX schedule", () => {
  // the undated flex board for comparison
  const undated = createSimWorld({}).forRun("undated");
  undated.setParty(4);
  const flex = undated.quote({ origin: "SFO", destination: "FCO" }).itineraries.filter((i) => /^IT-[0-9A-F]{6}$/.test(i.itineraryId));
  assert.deepEqual(flex.map((i) => i.itineraryId), ROME_IDS.slice(0, 3));

  const run = datedSim("dated-board");
  const q = run.quote({ origin: "SFO", destination: "FCO" });
  assert.equal(q.itineraries.length, 4);
  assert.deepEqual(q.itineraries.map((i) => i.itineraryId), ROME_IDS);
  assert.deepEqual(q.itineraries.map((i) => i.farePerPersonMinor), ROME_PER_PERSON);
  for (const [n, i] of q.itineraries.entries()) {
    assert.equal(i.fareMinor, i.farePerPersonMinor * 4);
    assert.equal(i.departDate, "2027-03-27");
    assert.equal(i.returnDate, "2027-04-03");
    if (n < 3) {
      assert.equal(i.farePerPersonMinor, flex[n].farePerPersonMinor, "same per-person fare as the flex row");
      assert.equal(i.summary, flex[n].summary);
    }
  }
  // later return: economy x 1.06 rounded to $1 (906.00 x 1.06 = 960.36 -> $960)
  assert.equal(q.itineraries[3].farePerPersonMinor, Math.round((ROME_PER_PERSON[0] * 1.06) / 100) * 100);
  assert.match(q.itineraries[3].summary, /economy, nonstop, later return/);

  const [econ, prem, oneStop, later] = q.itineraries.map((i) => i.detail);
  // DST: SFO is on PDT since 2027-03-14; Rome switches to CEST at 01:00Z on 2027-03-28 (mid-flight)
  assert.deepEqual(segs(econ), [
    "outbound ZX/ZX118 SFO 2027-03-27T09:40 -> FCO 2027-03-28T06:30 710m economy",
    "return ZX/ZX119 FCO 2027-04-03T10:30 -> SFO 2027-04-03T14:35 785m economy",
  ]);
  assert.deepEqual(segs(prem), [
    "outbound ZX/ZX118 SFO 2027-03-27T09:40 -> FCO 2027-03-28T06:30 710m premium economy",
    "return ZX/ZX119 FCO 2027-04-03T10:30 -> SFO 2027-04-03T14:35 785m premium economy",
  ]);
  assert.deepEqual(segs(oneStop), [
    "outbound ZX/ZX2204 SFO 2027-03-27T07:15 -> JFK 2027-03-27T15:45 330m economy",
    "outbound ZX/ZX2207 JFK 2027-03-27T17:45 -> FCO 2027-03-28T08:25 520m economy",
    "return ZX/ZX2210 FCO 2027-04-03T11:05 -> JFK 2027-04-03T14:50 585m economy",
    "return ZX/ZX2213 JFK 2027-04-03T16:40 -> SFO 2027-04-03T20:15 395m economy",
  ]);
  assert.deepEqual(segs(later), [
    "outbound ZX/ZX118 SFO 2027-03-27T09:40 -> FCO 2027-03-28T06:30 710m economy",
    "return ZX/ZX121 FCO 2027-04-03T14:20 -> SFO 2027-04-03T18:30 790m economy",
  ]);
  assert.deepEqual([econ.stops, prem.stops, oneStop.stops, later.stops], [0, 0, 1, 0]);
  assert.deepEqual([econ.cabin, prem.cabin, oneStop.cabin, later.cabin], ["economy", "premium economy", "economy", "economy"]);
  assert.deepEqual(econ.baggage, { carryOn: 1, checkedBagsPerTraveller: 1, checkedBagMaxKg: 23 });
  assert.deepEqual(prem.baggage, { carryOn: 1, checkedBagsPerTraveller: 2, checkedBagMaxKg: 23 });
  for (const d of [econ, prem, oneStop, later]) {
    assert.equal(d.simulated, true);
    assert.deepEqual(d.changeTerms, { changeable: true, changeFeePerTravellerMinor: 15000, changeDeadline: "2027-03-20" });
    assert.deepEqual(d.cancelTerms, {
      refundable: false, travelCredit: true, cancelFeePerTravellerMinor: 20000,
      summary: "Non-refundable; cancel before the change deadline for a travel credit minus $200 per traveller.",
    });
    for (const s of d.segments) assert.equal(s.carrierCode, "ZX");
  }
  // no real carrier and no canonical rows on a dated board
  assert.ok(!JSON.stringify(q).includes("QW"), "canonical QW rows are not on the dated board");
  // detail is the same through itineraryDetail
  assert.deepEqual(run.itineraryDetail(ROME_IDS[0]), econ);
});

test("sim: local times follow each airport's own DST (US and EU switch on different dates)", () => {
  // 2027-03-20: SFO already on PDT (UTC-7), Rome still on CET (UTC+1) -> arrive 05:30, not 06:30
  const gap = datedSim("dst-gap", { dates: { departDate: "2027-03-20", returnDate: "2027-03-25" } });
  const q = gap.quote({ origin: "SFO", destination: "FCO" });
  assert.deepEqual(segs(q.itineraries[0].detail), [
    "outbound ZX/ZX118 SFO 2027-03-20T09:40 -> FCO 2027-03-21T05:30 710m economy",
    "return ZX/ZX119 FCO 2027-03-25T10:30 -> SFO 2027-03-25T15:35 785m economy",
  ]);
  assert.equal(q.itineraries[0].detail.changeTerms.changeDeadline, "2027-03-13");
  // winter: both on standard time (PST UTC-8, CET UTC+1)
  const winter = datedSim("dst-winter", { dates: { departDate: "2027-01-15", returnDate: "2027-01-31" } });
  assert.deepEqual(segs(winter.quote({ origin: "SFO", destination: "FCO" }).itineraries[0].detail), [
    "outbound ZX/ZX118 SFO 2027-01-15T09:40 -> FCO 2027-01-16T06:30 710m economy",
    "return ZX/ZX119 FCO 2027-01-31T10:30 -> SFO 2027-01-31T14:35 785m economy",
  ]);
  // a change deadline crossing a month/year boundary
  assert.equal(winter.itineraryDetail(ROME_IDS[0]).changeTerms.changeDeadline, "2027-01-08");
  const jan = datedSim("jan-2", { dates: { departDate: "2027-01-02", returnDate: "2027-01-09" } });
  jan.quote({ origin: "SFO", destination: "FCO" });
  assert.equal(jan.itineraryDetail(ROME_IDS[0]).changeTerms.changeDeadline, "2026-12-26");
});

test("sim: a route outside the schedule table gets the four-row dated board without detail", () => {
  const run = datedSim("nas-dated", { family: { adults: 2, childAges: [] } });
  const q = run.quote({ origin: "SFO", destination: "NAS" });
  assert.equal(q.itineraries.length, 4);
  assert.deepEqual(q.itineraries.slice(0, 3).map((i) => i.itineraryId), ["IT-E06FA7", "IT-16D161", "IT-28E699"]);
  for (const i of q.itineraries) assert.equal("detail" in i, false);
  const it = run.offerItinerary(q.itineraries[0].itineraryId, 123_456);
  assert.equal("detail" in it, false);
  assertFareLines(it.fareLines, 123_456, 2, []);
  assert.equal(it.fareRule, SIM_FARE_RULE);
});

test("sim: quotes default to the trip dates; other dates are stamped but carry no schedule; a pre-trip quote is not reused", () => {
  const world = createSimWorld({});
  const run = world.forRun("quote-dates");
  run.setParty(4);
  const before = run.quote({ origin: "SFO", destination: "FCO" });
  assert.equal(before.itineraries.length, 8, "undated: canonical + generated rows");
  assert.equal(run.setTrip({ ...ROME_DATES, ...FAMILY }), true);
  const after = run.quote({ origin: "SFO", destination: "FCO" });
  assert.equal(after.itineraries.length, 4, "the memoized undated board is not reused once the trip is set");
  assert.ok(after.itineraries.every((i) => i.detail !== undefined));
  const explicit = run.quote({ origin: "SFO", destination: "FCO", ...ROME_DATES });
  assert.deepEqual(explicit.itineraries.map((i) => i.detail), after.itineraries.map((i) => i.detail));
  const other = run.quote({ origin: "SFO", destination: "FCO", departDate: "2027-05-01", returnDate: "2027-05-08" });
  assert.equal(other.itineraries.length, 4);
  for (const i of other.itineraries) {
    assert.equal(i.departDate, "2027-05-01");
    assert.equal("detail" in i, false, "the sim only schedules the trip's own dates");
  }
  // the offer view still reads the trip's schedule for the id
  assert.deepEqual(run.offerItinerary(ROME_IDS[0], 400_000).detail, after.itineraries[0].detail);
});

test("sim: setTrip is write-once, needs the party first and must match it", () => {
  const world = createSimWorld({});
  const r = world.forRun("set-trip");
  assert.equal(r.setTrip({ ...ROME_DATES }), false, "no party yet");
  assert.equal(r.trip, undefined);
  r.setParty(4);
  assert.equal(r.setTrip({ ...ROME_DATES, adults: 2, childAges: [12] }), false, "2 + 1 != 4");
  assert.equal(r.setTrip({ ...ROME_DATES, adults: 2 }), false, "adults without childAges");
  assert.equal(r.setTrip({ ...ROME_DATES, childAges: [12, 9] }), false, "childAges without adults");
  assert.equal(r.setTrip({ departDate: "2027-04-03", returnDate: "2027-03-27", ...FAMILY }), false);
  assert.equal(r.setTrip({ departDate: "2027-02-29", returnDate: "2027-03-03", ...FAMILY }), false, "2027 is not a leap year");
  assert.equal(r.setTrip({ ...ROME_DATES, adults: 2, childAges: [1, 9] }), false);
  assert.equal(r.trip, undefined, "a refused setTrip changes nothing");
  assert.equal(r.setTrip({ ...ROME_DATES, ...FAMILY }), true);
  assert.equal(r.setTrip({ ...ROME_DATES, ...FAMILY }), true, "the same trip is idempotent");
  assert.equal(r.setTrip({ ...ROME_DATES, adults: 3, childAges: [12] }), false, "a different trip is refused");
  assert.deepEqual(r.trip, { ...ROME_DATES, ...FAMILY });
});

// ---- fare lines ---------------------------------------------------------------------

test("fare lines: 2 adults + children 12 and 9 split exactly at $3,914, $3,799 and $4,100.01", () => {
  assert.deepEqual(simFareLines(391_400, 2, [12, 9]), [
    { traveller: "ADT1", type: "adult", baseMinor: 93_190, taxesMinor: 18_640, totalMinor: 111_830 },
    { traveller: "ADT2", type: "adult", baseMinor: 93_188, taxesMinor: 18_640, totalMinor: 111_828 },
    { traveller: "CHD1", type: "child", age: 12, baseMinor: 65_231, taxesMinor: 18_640, totalMinor: 83_871 },
    { traveller: "CHD2", type: "child", age: 9, baseMinor: 65_231, taxesMinor: 18_640, totalMinor: 83_871 },
  ]);
  // $3,799: unitAdult 108542, child round(81406.5) = 81407, remainder 2 -> ADT1
  assert.deepEqual(simFareLines(379_900, 2, [12, 9]).map((l) => l.totalMinor), [108_544, 108_542, 81_407, 81_407]);
  // $4,100.01: unitAdult 117143, child round(87857.25) = 87857, remainder 1 -> ADT1
  assert.deepEqual(simFareLines(410_001, 2, [12, 9]).map((l) => l.totalMinor), [117_144, 117_143, 87_857, 87_857]);
  for (const total of [391_400, 379_900, 410_001, 362_400, 1, 0, 18_639, 74_560, 999_999_999]) {
    assertFareLines(simFareLines(total, 2, [12, 9]), total, 2, [12, 9]);
  }
});

test("fare lines: odd party mixes always sum exactly to the offer total", () => {
  const mixes = [
    [1, []], [3, []], [9, []], [1, [5]], [1, [2, 3, 4, 5, 6, 7, 8, 9]], [5, [17, 2, 10]],
    [2, [12, 9, 7]], [4, [16]], [1, [17, 17]], [7, [3, 4]],
  ];
  const totals = [0, 1, 7, 99, 100, 18_640, 37_281, 123_457, 391_400, 410_001, 1_234_567, 87_654_321];
  for (const [adults, childAges] of mixes) {
    for (const total of totals) {
      assertFareLines(simFareLines(total, adults, childAges), total, adults, childAges);
    }
  }
  // the child weight is 0.75 of the adult unit (round), ADT2.. carry exactly the unit
  const lines = simFareLines(500_000, 3, [10, 6]);
  const unit = Math.floor(500_000 / 4.5);
  assert.equal(lines[1].totalMinor, unit);
  assert.equal(lines[2].totalMinor, unit);
  assert.equal(lines[3].totalMinor, Math.round(0.75 * unit));
  assert.equal(lines[4].totalMinor, Math.round(0.75 * unit));
});

// ---- booking record (sim) -----------------------------------------------------------

test("sim: the booking observation gains the trip block — dates, segments, travellers with synthetic initials, recordLocator = pnr, ticketing", () => {
  const run = datedSim("booking-trip");
  const q = run.quote({ origin: "SFO", destination: "FCO" });
  const row = q.itineraries[3];
  const booked = run.bookOrder({ agreementId: "agr-0001", itineraryId: row.itineraryId, feeMinor: 10_000, totalMinor: row.fareMinor + 10_000, travelerCount: 4 });
  assert.equal(booked.ok, true);
  const pending = run.lookupOrder({ orderRef: booked.orderRef });
  assert.equal(pending.trip.ticketing.status, "PENDING");
  assert.deepEqual(pending.trip.ticketing.ticketNumbers, []);
  const issued = run.issueTickets({ orderRef: booked.orderRef });
  const obs = run.lookupOrder({ orderRef: booked.orderRef });
  const t = obs.trip;
  assert.equal(t.simulated, true);
  assert.equal(t.departDate, "2027-03-27");
  assert.equal(t.returnDate, "2027-04-03");
  assert.deepEqual(t.segments, row.detail.segments);
  assert.equal(t.cabin, "economy");
  assert.deepEqual(t.baggage, row.detail.baggage);
  assert.deepEqual(t.changeTerms, row.detail.changeTerms);
  assert.deepEqual(t.cancelTerms, row.detail.cancelTerms);
  assert.equal(t.recordLocator, booked.pnr);
  assert.equal(t.recordLocator, obs.pnr);
  assert.deepEqual(t.ticketing, { status: "ISSUED", simulated: true, ticketNumbers: issued.tickets.map((x) => x.ticketNumber) });
  assert.deepEqual(t.travellers.map(({ initials: _i, ...rest }) => rest), [
    { ref: "ADT1", type: "adult" }, { ref: "ADT2", type: "adult" },
    { ref: "CHD1", type: "child", age: 12 }, { ref: "CHD2", type: "child", age: 9 },
  ]);
  for (const p of t.travellers) assert.match(p.initials, /^[A-Z]\.[A-Z]\.$/);
  assert.equal(new Set(t.travellers.map((p) => p.initials.slice(2))).size, 1, "one shared family letter");
  assert.equal(new Set(t.travellers.map((p) => p.initials[0])).size, 4, "distinct first initials");
  // deterministic per runId: a second world replays the same initials
  const again = datedSim("booking-trip");
  again.quote({ origin: "SFO", destination: "FCO" });
  const b2 = again.bookOrder({ agreementId: "agr-0001", itineraryId: row.itineraryId, feeMinor: 10_000, totalMinor: row.fareMinor + 10_000, travelerCount: 4 });
  assert.deepEqual(again.bookingTrip(b2.orderRef).travellers, t.travellers);
  assert.deepEqual(run.bookingTrip(booked.orderRef), t);
  // cancellation shows through
  run.cancelOrder({ orderRef: booked.orderRef });
  assert.equal(run.lookupOrder({ orderRef: booked.orderRef }).trip.ticketing.status, "CANCELLED");
  // NOT_FOUND carries no trip
  assert.equal("trip" in run.lookupOrder({ orderRef: "ORD-NOPE0000" }), false);
});

test("sim: undated runs are unchanged — no trip, no detail, no fare lines, no 4th row", () => {
  const world = createSimWorld({ now: () => Date.parse("2026-10-25T12:00:00Z") });
  for (const party of [undefined, 4]) {
    const run = world.forRun(`undated-${party}`);
    if (party !== undefined) run.setParty(party);
    const q = run.quote({ origin: "SFO", destination: "FCO", departDate: "2027-03-27", returnDate: "2027-04-03" });
    assert.equal(q.itineraries.length, 8);
    assert.ok(q.itineraries.every((i) => !("detail" in i)));
    assert.ok(!q.itineraries.some((i) => i.itineraryId === ROME_IDS[3]));
    assert.equal(run.trip, undefined);
    assert.equal(run.itineraryDetail(ROME_IDS[0]), undefined);
    assert.equal(run.offerItinerary(ROME_IDS[0], 400_000), undefined);
    const it = q.itineraries[0];
    const b = run.bookOrder({ agreementId: "agr-0001", itineraryId: it.itineraryId, feeMinor: 0, totalMinor: it.fareMinor, travelerCount: 4 });
    run.issueTickets({ orderRef: b.orderRef });
    const obs = run.lookupOrder({ orderRef: b.orderRef });
    assert.deepEqual(Object.keys(obs), [
      "orderRef", "status", "pnr", "agreementId", "itineraryId", "totalMinor", "currency", "travellers", "ticketCount", "observedAt", "simulated",
    ]);
    assert.equal(run.bookingTrip(b.orderRef), undefined);
  }
});

// ---- end to end through /contract/mcp ------------------------------------------------

test("dated run end to end: provider view shows dates and ages (never budget/cap); offers, agreement and booking carry the trip detail", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const dates = { departDate: inDays(150), returnDate: inDays(157) };
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(4_200), ...dates, ...FAMILY };
    const prep = await prepareMandate(env, uuid(1461));
    const sub = await submitMandate(env, prep, trip);
    assert.equal(sub.bound, true, JSON.stringify(sub));

    // policy views
    const bst = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(bst).success, JSON.stringify(bst));
    assert.deepEqual(bst.policy.trip, trip, "the buyer sees its whole trip");
    const pst = await env.callTool("tp1", "contract_status", {});
    assert.ok(statusSchema.safeParse(pst).success, JSON.stringify(pst));
    assert.deepEqual(pst.policy, {
      mandateVersion: 3,
      trip: { origin: "SFO", destination: "FCO", partySize: 4, ...dates, adults: 2, childAges: [12, 9] },
    });
    assert.ok(!/budgetMinor|maxCapMinor|420000|2000000/.test(JSON.stringify(pst.policy)), "never the budget or the cap");

    // the provider quotes without dates: the trip's dates and the dated board
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "FCO" });
    assert.equal(q.simulated, true);
    assert.deepEqual(q.itineraries.map((i) => i.itineraryId), ROME_IDS);
    for (const i of q.itineraries) {
      assert.equal(i.departDate, dates.departDate);
      assert.equal(i.returnDate, dates.returnDate);
      assert.equal(i.detail.simulated, true);
      assert.equal(i.detail.segments[0].departureLocal.slice(0, 10), dates.departDate);
      assert.equal(i.detail.segments.at(-1).departureLocal.slice(0, 10), dates.returnDate);
    }

    // buyer offers on the later-return row; provider counters; buyer accepts
    const row = q.itineraries[3];
    const o1 = await offer(env, "tb1", "buyer", { itineraryId: row.itineraryId, feeMinor: 5_000 });
    const o2 = await offer(env, "tp1", "provider", { itineraryId: row.itineraryId, feeMinor: 12_000 });
    for (const [token, role] of [["tb1", "buyer"], ["tp1", "provider"]]) {
      const st = await env.callTool(token, "contract_status", {});
      assert.ok(statusSchema.safeParse(st).success, `${role}: ${JSON.stringify(statusSchema.safeParse(st).error?.issues)}`);
      assert.equal(st.negotiation.offers.length, 2);
      for (const o of st.negotiation.offers) {
        assert.deepEqual(o.itinerary.detail, row.detail, `${role} sees the row's schedule`);
        assertFareLines(o.itinerary.fareLines, o.totalMinor, 2, [12, 9]);
        assert.equal(o.itinerary.fareRule, SIM_FARE_RULE);
      }
      assert.deepEqual(st.negotiation.offers.map((o) => o.offerId), [o2.offerId, o1.offerId]);
    }
    const { accepted, booked } = await acceptAndBook(env, o2.offerId, { acceptToken: "tb1", acceptRole: "buyer" });

    // agreement: contract_status and agreement_get carry the same itinerary
    const ag = await env.callTool("tb1", "agreement_get", {});
    assert.equal(ag.agreement.agreementId, accepted.agreementId);
    assertFareLines(ag.agreement.itinerary.fareLines, ag.agreement.totalMinor, 2, [12, 9]);
    assert.deepEqual(ag.agreement.itinerary.detail, row.detail);
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success, JSON.stringify(statusSchema.safeParse(st).error?.issues));
    assert.deepEqual(st.agreement.itinerary, ag.agreement.itinerary);

    // booking record
    assert.equal(booked.tickets.length, 4);
    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
    const t = looked.observation.trip;
    assert.equal(t.simulated, true);
    assert.equal(t.departDate, dates.departDate);
    assert.equal(t.returnDate, dates.returnDate);
    assert.deepEqual(t.segments, row.detail.segments);
    assert.deepEqual(t.segments.map((s) => s.flightNumber), ["ZX118", "ZX121"]);
    assert.equal(t.recordLocator, booked.pnr);
    assert.deepEqual(t.ticketing, { status: "ISSUED", simulated: true, ticketNumbers: booked.tickets.map((x) => x.ticketNumber) });
    assert.deepEqual(t.travellers.map((p) => [p.ref, p.type, p.age]), [
      ["ADT1", "adult", undefined], ["ADT2", "adult", undefined], ["CHD1", "child", 12], ["CHD2", "child", 9],
    ]);
    for (const p of t.travellers) assert.match(p.initials, /^[A-Z]\.[A-Z]\.$/);
    assert.deepEqual(st.booking.trip, t, "contract_status booking carries the same trip block");
    const pst2 = await env.callTool("tp1", "contract_status", {});
    assert.ok(statusSchema.safeParse(pst2).success);
    assert.deepEqual(pst2.booking.trip, t);

    // verification is unchanged by the extra block
    const prepV = await env.callTool("tb1", "verification_prepare", {
      orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
    });
    const verified = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    assert.equal(verified.outcome, "match", JSON.stringify(verified));
    assert.equal(verified.flagged, false);
  } finally { env.close(); }
});

test("dated run under CONTRACT_PRIVATE_FLOOR: an all-in $3,914 offer splits 1118.30 / 1118.28 / 838.71 / 838.71 and the buyer never sees the catalog fare", async () => {
  const env = await boot({ flexPolicy: true, privateFloor: { floorBps: 9000 } });
  try {
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(4_200), departDate: inDays(120), returnDate: inDays(127), ...FAMILY };
    const prep = await prepareMandate(env, uuid(1462));
    assert.equal((await submitMandate(env, prep, trip)).bound, true);
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "FCO" });
    const row = q.itineraries[0];
    assert.equal(row.fareMinor, 362_400);
    const o = await offer(env, "tp1", "provider", { itineraryId: row.itineraryId, feeMinor: 391_400 });
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success, JSON.stringify(statusSchema.safeParse(st).error?.issues));
    const mine = st.negotiation.offers.find((x) => x.offerId === o.offerId);
    assert.equal(mine.fareMinor, 0);
    assert.equal(mine.totalMinor, 391_400);
    assert.deepEqual(mine.itinerary.fareLines.map((l) => [l.traveller, l.baseMinor, l.taxesMinor, l.totalMinor]), [
      ["ADT1", 93_190, 18_640, 111_830], ["ADT2", 93_188, 18_640, 111_828],
      ["CHD1", 65_231, 18_640, 83_871], ["CHD2", 65_231, 18_640, 83_871],
    ]);
    assert.ok(!JSON.stringify(st).includes(String(row.fareMinor)), "the catalog fare never appears in the buyer's status");
    assert.ok(!JSON.stringify(st).includes(String(row.farePerPersonMinor)), "nor the per-person catalog fare");
  } finally { env.close(); }
});

test("undated runs through /contract/mcp are unchanged: no detail, no itinerary, no trip block, provider trip is route + party", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: USD(6_000) };
    const prep = await prepareMandate(env, uuid(1463));
    assert.equal((await submitMandate(env, prep, trip)).bound, true);
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "FCO" });
    assert.equal(q.itineraries.length, 8);
    assert.ok(q.itineraries.every((i) => !("detail" in i) && !("departDate" in i)));
    const row = q.itineraries.find((i) => i.itineraryId === "IT-349482");
    const o = await offer(env, "tb1", "buyer", { itineraryId: row.itineraryId, feeMinor: 10_000 });
    const { booked } = await acceptAndBook(env, o.offerId);
    const st = await env.callTool("tb1", "contract_status", {});
    assert.ok(statusSchema.safeParse(st).success);
    assert.deepEqual(Object.keys(st.negotiation.offers[0]), [
      "offerId", "by", "kind", "inReplyTo", "itineraryId", "currency", "fareMinor", "feeMinor", "totalMinor", "note", "state", "submittedAt",
    ]);
    assert.deepEqual(Object.keys(st.agreement), ["agreementId", "offerId", "itineraryId", "currency", "totalMinor", "formedAt"]);
    assert.deepEqual(Object.keys(st.booking), ["orderRef", "pnr", "ticketCount", "bookedAt", "simulated"]);
    assert.deepEqual(st.policy.trip, trip);
    const pst = await env.callTool("tp1", "contract_status", {});
    assert.deepEqual(pst.policy.trip, { origin: "SFO", destination: "FCO", partySize: 4 });
    const ag = await env.callTool("tb1", "agreement_get", {});
    assert.equal("itinerary" in ag.agreement, false);
    const looked = await env.callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
    assert.equal("trip" in looked.observation, false);
  } finally { env.close(); }
});

test("a v2 mandate's dated trip is validated and shown in the policy, but the sim board stays undated", async () => {
  const env = await boot({ flexPolicy: true });
  try {
    const prep = await prepareMandate(env, uuid(1464), signMandate({ capMinor: 700_000, partySize: 4, allowedItineraryIds: ["IT-ROME-ZX118-ECON"] }));
    const trip = { origin: "SFO", destination: "FCO", partySize: 4, budgetMinor: 680_000, departDate: inDays(90), returnDate: inDays(97), ...FAMILY };
    assert.equal((await submitMandate(env, prep, { ...trip, adults: 3 })).error, "TRIP_INVALID");
    assert.equal((await submitMandate(env, prep, trip)).bound, true);
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.policy.mandateVersion, 2);
    assert.deepEqual(st.policy.trip, trip);
    const q = await env.callTool("tp1", "catalog_quote", { origin: "SFO", destination: "FCO" });
    assert.ok(q.itineraries.every((i) => !("detail" in i)));
  } finally { env.close(); }
});
