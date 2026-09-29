import assert from "node:assert/strict";
import test from "node:test";

import { createSimWorld } from "../dist/agent-contract/sim/index.js";

/**
 * N4b-5 — sim-only scope.
 *
 *   Item 1: the Rome pairing-route board (IT-ROME-*, SFO→FCO, USD). Fares are
 *   the old travel MVP inventory's family totals (RUNBOOK-ROME-P4): nonstop
 *   economy 481800, nonstop premium 596000, one-stop 431000, two-stop
 *   398800/404800 — the two-stop rows are deliberately non-qualifying (the
 *   mandate's allowedItineraryIds excludes them). Existing ZRH→JFK rows and
 *   the frozen v2/v2.1 vectors must stay byte-identical.
 *
 *   Item 2: a run-scoped, configuration-only sim fault for adverse case A2 —
 *   `createSimWorld({ faults: { [runId]: { issueMismatch: "fare" |
 *   "travellers" } } })`. `issueTickets` deviates from the booked order,
 *   `lookupOrder` exposes the deviation, the applied fault is recorded on the
 *   run's sim state, and no tool/agent argument can enable it.
 */

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const DAY_MS = 24 * 60 * 60 * 1000;

function makeWorld(options = {}) {
  let now = T0;
  const world = createSimWorld({ now: () => now, ttlMs: DAY_MS, ...options });
  return { world, advance: (ms) => { now += ms; } };
}

const ROME_QUOTE = { origin: "SFO", destination: "FCO", travelers: 4 };

// --- Item 1: the Rome board ---------------------------------------------------

const EXPECTED_ROME_ROWS = [
  {
    itineraryId: "IT-ROME-ZX118-ECON",
    origin: "SFO",
    destination: "FCO",
    fareMinor: 481800,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-ZX118-PREM",
    origin: "SFO",
    destination: "FCO",
    fareMinor: 596000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-QW-ONESTOP",
    origin: "SFO",
    destination: "FCO",
    fareMinor: 431000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-2STOP-A",
    origin: "SFO",
    destination: "FCO",
    fareMinor: 398800,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-2STOP-B",
    origin: "SFO",
    destination: "FCO",
    fareMinor: 404800,
    currency: "USD",
  },
];

test("the Rome board quotes the five IT-ROME-* rows for SFO→FCO", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-rome-board");
  const quote = run.quote(ROME_QUOTE);
  assert.equal(quote.simulated, true);
  assert.equal(quote.origin, "SFO");
  assert.equal(quote.destination, "FCO");

  const romeRows = quote.itineraries.filter((i) => i.itineraryId.startsWith("IT-ROME-"));
  assert.equal(romeRows.length, 5);
  for (const expected of EXPECTED_ROME_ROWS) {
    const row = romeRows.find((i) => i.itineraryId === expected.itineraryId);
    assert.ok(row, `missing ${expected.itineraryId}`);
    assert.equal(row.origin, expected.origin);
    assert.equal(row.destination, expected.destination);
    assert.equal(row.fareMinor, expected.fareMinor);
    assert.equal(row.currency, expected.currency);
    assert.match(row.summary, /\S/);
  }
  // The two-stop routings are flagged non-qualifying in their summaries.
  for (const id of ["IT-ROME-2STOP-A", "IT-ROME-2STOP-B"]) {
    assert.match(
      romeRows.find((i) => i.itineraryId === id).summary,
      /2 stop/i,
      `${id} summary must disclose the two-stop routing`,
    );
  }
});

test("Rome rows are bookable: board fare is the ground-truth fare", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-rome-book");
  run.quote(ROME_QUOTE); // register the rows
  const result = run.bookOrder({
    agreementId: "agr-rome-1",
    itineraryId: "IT-ROME-QW-ONESTOP",
    feeMinor: 10000,
    totalMinor: 441000, // 431000 + 10000
    travelerCount: 4,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.fareMinor, 431000);
  assert.equal(result.currency, "USD");
  assert.equal(result.simulated, true);
  // A fare that doesn't match the board is still refused.
  const bad = run.bookOrder({
    agreementId: "agr-rome-2",
    itineraryId: "IT-ROME-2STOP-A",
    feeMinor: 10000,
    totalMinor: 399999,
    travelerCount: 4,
  });
  assert.deepEqual(bad, { ok: false, code: "FARE_MISMATCH" });
});

test("the ZRH→JFK board is unchanged by the Rome rows", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-zrh-check");
  const quote = run.quote({ origin: "ZRH", destination: "JFK", travelers: 2 });
  const canonical = Object.fromEntries(
    quote.itineraries
      .filter((i) => !i.itineraryId.startsWith("IT-ROME-"))
      .map((i) => [i.itineraryId, i]),
  );
  // Frozen-vector rows: id, route, fare, currency byte-for-byte as before.
  assert.equal(canonical["IT-QW-ONESTOP"].fareMinor, 429000);
  assert.equal(canonical["IT-QW-ONESTOP"].origin, "ZRH");
  assert.equal(canonical["IT-QW-ONESTOP"].destination, "JFK");
  assert.equal(canonical["IT-QW-ONESTOP"].currency, "USD");
  assert.equal(canonical["IT-ZX118-ECON"].fareMinor, 481800);
  assert.equal(canonical["IT-ZX118-PREM"].fareMinor, 596000);
  // No Rome row leaks into the ZRH→JFK quote.
  assert.ok(quote.itineraries.every((i) => i.origin === "ZRH" && i.destination === "JFK"));
});

// --- Item 2: run-scoped, config-only sim fault (adverse case A2) -------------

function bookPaired(run, agreementId = "agr-a2-1") {
  const result = run.bookOrder({
    agreementId,
    itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000,
    totalMinor: 439000,
    travelerCount: 2,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  return result;
}

test("A2 'fare' fault: issueTickets drifts the order fare; lookup exposes it", () => {
  const { world } = makeWorld({ faults: { "run-a2-fare": { issueMismatch: "fare" } } });
  const run = world.forRun("run-a2-fare");
  // The applied fault is recorded on the run's sim state.
  assert.deepEqual(run.faults, { issueMismatch: "fare" });

  const booked = bookPaired(run);
  const issued = run.issueTickets({ orderRef: booked.orderRef });
  assert.equal(issued.ok, true);
  assert.equal(issued.simulated, true);
  assert.equal(issued.tickets.length, 2); // the fare fault doesn't touch travellers

  const lookup = run.lookupOrder({ orderRef: booked.orderRef });
  assert.equal(lookup.simulated, true);
  assert.equal(lookup.status, "ISSUED");
  // The issued order deviates from the booked total — buyer verification sees it.
  assert.equal(lookup.totalMinor, booked.totalMinor + 9600);
  assert.notEqual(lookup.totalMinor, booked.totalMinor);

  // Deterministic: replayed issuance and re-lookup report the same deviation.
  assert.deepEqual(run.issueTickets({ orderRef: booked.orderRef }), issued);
  assert.equal(run.lookupOrder({ orderRef: booked.orderRef }).totalMinor, lookup.totalMinor);
});

test("A2 'travellers' fault: issueTickets emits a deviating ticket count", () => {
  const { world } = makeWorld({ faults: { "run-a2-pax": { issueMismatch: "travellers" } } });
  const run = world.forRun("run-a2-pax");
  assert.deepEqual(run.faults, { issueMismatch: "travellers" });

  const booked = bookPaired(run); // travelerCount 2
  const issued = run.issueTickets({ orderRef: booked.orderRef });
  assert.equal(issued.ok, true);
  assert.equal(issued.simulated, true);
  assert.equal(issued.tickets.length, 3); // one more ticket than the order booked

  const lookup = run.lookupOrder({ orderRef: booked.orderRef });
  assert.equal(lookup.simulated, true);
  assert.equal(lookup.ticketCount, 3);
  // The fare itself is untouched by this fault.
  assert.equal(lookup.totalMinor, booked.totalMinor);
});

test("the fault is run-scoped: sibling runs on the same world are unaffected", () => {
  const { world } = makeWorld({ faults: { "run-a2-only": { issueMismatch: "fare" } } });
  const clean = world.forRun("run-clean");
  assert.equal(clean.faults, undefined);

  const booked = bookPaired(clean);
  const issued = clean.issueTickets({ orderRef: booked.orderRef });
  assert.equal(issued.tickets.length, 2);
  const lookup = clean.lookupOrder({ orderRef: booked.orderRef });
  assert.equal(lookup.totalMinor, booked.totalMinor);
  assert.equal(lookup.ticketCount, 2);
});

test("a fault can never be enabled by a tool/agent argument", () => {
  const { world } = makeWorld(); // no faults configured at all
  const run = world.forRun("run-no-fault");
  assert.equal(run.faults, undefined);

  // Strict input schemas reject any injected fault key — nothing is smuggled in.
  const badBook = run.bookOrder({
    agreementId: "agr-evil",
    itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000,
    totalMinor: 439000,
    travelerCount: 2,
    faults: { issueMismatch: "fare" },
  });
  assert.deepEqual(badBook, { ok: false, code: "REQUEST_INVALID" });

  const booked = bookPaired(run);
  const badIssue = run.issueTickets({ orderRef: booked.orderRef, issueMismatch: "fare" });
  assert.deepEqual(badIssue, { ok: false, code: "REQUEST_INVALID" });
  const badLookup = run.lookupOrder({ orderRef: booked.orderRef, issueMismatch: "fare" });
  assert.equal(badLookup.status, "NOT_FOUND"); // invalid input → unknown-order observation

  // The order issued normally — no deviation leaked in through the arguments.
  const issued = run.issueTickets({ orderRef: booked.orderRef });
  assert.equal(issued.tickets.length, 2);
  const lookup = run.lookupOrder({ orderRef: booked.orderRef });
  assert.equal(lookup.totalMinor, booked.totalMinor);
  assert.equal(lookup.ticketCount, 2);
  assert.equal(run.faults, undefined);
});
