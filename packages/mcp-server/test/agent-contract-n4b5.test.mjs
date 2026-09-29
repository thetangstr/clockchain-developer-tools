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
