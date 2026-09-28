import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";

/**
 * N4b-2 parallel lane: pure run-scoped sim modules (ticketing sim + simulated
 * payment rail). Covers quote/order/ticket/lookup/cancel/payment, idempotency,
 * run isolation, TTL, `simulated: true`, and the no-network/no-real-payments
 * guarantee. No routes, services, or signer code — those are other slices.
 */

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** A world whose clock the test controls via the returned `advance` fn. */
function makeWorld() {
  let now = T0;
  const world = createSimWorld({ now: () => now, ttlMs: DAY_MS });
  return { world, setNow: (ms) => { now = ms; }, advance: (ms) => { now += ms; } };
}

const QUOTE_REQ = {
  origin: "ZRH",
  destination: "JFK",
  departDate: "2030-03-01",
  returnDate: "2030-03-08",
  travelers: 2,
};

test("quote returns a deterministic simulated board for the route", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-q-1");
  const quote = run.quote(QUOTE_REQ);
  assert.equal(quote.simulated, true);
  assert.ok(Array.isArray(quote.itineraries));
  assert.ok(quote.itineraries.length >= 2, "board should offer multiple options");
  for (const itin of quote.itineraries) {
    assert.match(itin.itineraryId, /^IT-[0-9A-Z]+/);
    assert.equal(typeof itin.fareMinor, "number");
    assert.ok(Number.isSafeInteger(itin.fareMinor) && itin.fareMinor > 0);
    assert.equal(itin.currency, "USD");
    assert.equal(itin.origin, "ZRH");
    assert.equal(itin.destination, "JFK");
  }
  // The canonical pairing-route itinerary the frozen offer vector prices.
  const canonical = quote.itineraries.find((i) => i.itineraryId === "IT-QW-ONESTOP");
  assert.ok(canonical, "canonical board must include IT-QW-ONESTOP");
  assert.equal(canonical.fareMinor, 429000);
});

test("quote is memoized: identical request replays byte-for-byte", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-q-2");
  const a = run.quote(QUOTE_REQ);
  const b = run.quote(QUOTE_REQ);
  assert.deepEqual(b, a);
  // A different route gets a different (still deterministic) board.
  const other = run.quote({ origin: "SFO", destination: "NRT" });
  assert.notDeepEqual(other.itineraries.map((i) => i.itineraryId), a.itineraries.map((i) => i.itineraryId));
});

function bookedOrder(run, agreementId = "agr-0001") {
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

test("bookOrder issues a deterministic orderRef + PNR and is idempotent per agreement", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-b-1");
  const order = bookedOrder(run);
  assert.match(order.orderRef, /^ORD-[0-9A-Z]{8}$/);
  assert.match(order.pnr, /^[0-9A-Z]{6}$/);
  assert.equal(order.status, "PENDING");
  assert.equal(order.agreementId, "agr-0001");
  assert.equal(order.itineraryId, "IT-QW-ONESTOP");
  assert.equal(order.totalMinor, 439000);
  assert.equal(order.simulated, true);

  // Identical replay returns the SAME order (idempotent per agreementId).
  const replay = run.bookOrder({
    agreementId: "agr-0001",
    itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000,
    totalMinor: 439000,
    travelerCount: 2,
  });
  assert.deepEqual(replay, order);

  // A different agreement gets a different order.
  const other = run.bookOrder({
    agreementId: "agr-0002",
    itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000,
    totalMinor: 439000,
    travelerCount: 1,
  });
  assert.equal(other.ok, true);
  assert.notEqual(other.orderRef, order.orderRef);
});

test("bookOrder refuses fare mismatches, unknown itineraries, and agreement conflicts", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-b-2");

  assert.equal(
    run.bookOrder({ agreementId: "agr-x", itineraryId: "IT-QW-ONESTOP", feeMinor: 1, totalMinor: 1 }).code,
    "FARE_MISMATCH",
  );
  assert.equal(
    run.bookOrder({ agreementId: "agr-x", itineraryId: "IT-NOPE", feeMinor: 0, totalMinor: 1 }).code,
    "ITINERARY_UNKNOWN",
  );

  bookedOrder(run, "agr-conflict");
  const conflict = run.bookOrder({
    agreementId: "agr-conflict",
    itineraryId: "IT-ZX118-ECON",
    feeMinor: 10000,
    totalMinor: 491800,
  });
  assert.equal(conflict.ok, false);
  assert.equal(conflict.code, "AGREEMENT_CONFLICT");
});

test("issueTickets emits deterministic ticket records and replays identically", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-t-1");
  const order = bookedOrder(run);

  const issued = run.issueTickets({ orderRef: order.orderRef });
  assert.equal(issued.ok, true);
  assert.equal(issued.simulated, true);
  assert.equal(issued.orderRef, order.orderRef);
  assert.equal(issued.pnr, order.pnr);
  assert.equal(issued.status, "ISSUED");
  assert.equal(issued.tickets.length, 2);
  for (const ticket of issued.tickets) {
    assert.match(ticket.ticketNumber, /^TKT[0-9]{13}$/);
    assert.match(ticket.travelerId, /^PAX-[0-9]+$/);
  }

  const replay = run.issueTickets({ orderRef: order.orderRef });
  assert.deepEqual(replay, issued);

  assert.equal(run.issueTickets({ orderRef: "ORD-ZZZZZZZZ" }).code, "ORDER_NOT_FOUND");
});

test("lookupOrder observes PENDING → ISSUED → CANCELLED and NOT_FOUND", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-l-1");
  const order = bookedOrder(run);

  const pending = run.lookupOrder({ orderRef: order.orderRef });
  assert.equal(pending.simulated, true);
  assert.equal(pending.status, "PENDING");
  assert.equal(pending.pnr, order.pnr);
  assert.equal(pending.ticketCount, 0);

  const issued = run.issueTickets({ orderRef: order.orderRef });
  const issuedObs = run.lookupOrder({ orderRef: order.orderRef });
  assert.equal(issuedObs.status, "ISSUED");
  assert.equal(issuedObs.ticketCount, issued.tickets.length);

  run.cancelOrder({ orderRef: order.orderRef });
  const cancelledObs = run.lookupOrder({ orderRef: order.orderRef });
  assert.equal(cancelledObs.status, "CANCELLED");
  assert.equal(cancelledObs.simulated, true);

  const missing = run.lookupOrder({ orderRef: "ORD-ZZZZZZZZ" });
  assert.equal(missing.status, "NOT_FOUND");
  assert.equal(missing.simulated, true);
});

test("cancelOrder cancels visibly and replays the same record", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-c-1");
  const order = bookedOrder(run);

  const cancelled = run.cancelOrder({ orderRef: order.orderRef });
  assert.equal(cancelled.ok, true);
  assert.equal(cancelled.simulated, true);
  assert.equal(cancelled.status, "CANCELLED");
  assert.equal(cancelled.cancelledAt, new Date(T0).toISOString());

  const replay = run.cancelOrder({ orderRef: order.orderRef });
  assert.deepEqual(replay, cancelled);

  assert.equal(run.cancelOrder({ orderRef: "ORD-ZZZZZZZZ" }).code, "ORDER_NOT_FOUND");
});

const PAYMENT_REQ = {
  agreementId: "agr-0001",
  agreementDigest: "0x" + "a".repeat(64),
  verificationDigest: "0x" + "b".repeat(64),
  payerPartyId: "buyer-agent",
  providerPartyId: "provider-agent",
  beneficiaryDigest: "0x" + "c".repeat(64),
  amountMinor: 439000,
  currency: "USD",
};

test("simulated payment executes, replays idempotently, and conflicts on reuse", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-p-1");

  const first = run.payments.execute(PAYMENT_REQ);
  assert.equal(first.ok, true, JSON.stringify(first));
  const receipt = first.receipt;
  assert.match(receipt.transferId, /^sandbox-transfer:[0-9a-f]{16,64}$/);
  assert.equal(receipt.status, "COMPLETED");
  assert.equal(receipt.commercialTransfer, false);
  assert.equal(receipt.simulated, true);
  assert.equal(receipt.amountMinor, 439000);
  assert.equal(receipt.currency, "USD");
  assert.equal(receipt.agreementId, "agr-0001");

  // Byte-identical replay returns the original receipt.
  const replay = run.payments.execute(PAYMENT_REQ);
  assert.deepEqual(replay, first);

  // Same transferId with different payload → idempotency conflict.
  const conflict = run.payments.execute({ ...PAYMENT_REQ, transferId: receipt.transferId, amountMinor: 1 });
  assert.equal(conflict.ok, false);
  assert.equal(conflict.code, "PAYMENT_IDEMPOTENCY_CONFLICT");

  // Reads: known transfer resolves, unknown does not.
  assert.deepEqual(run.payments.read(receipt.transferId), receipt);
  assert.equal(run.payments.read("sandbox-transfer:deadbeef"), null);
});

test("payment status reports none → released for the run", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-p-2");
  assert.deepEqual(run.payments.status(), { state: "none" });
  const executed = run.payments.execute(PAYMENT_REQ);
  assert.deepEqual(run.payments.status(), {
    state: "released",
    transferId: executed.receipt.transferId,
  });
});

test("runs are fully isolated: orders, tickets, and payments never leak", () => {
  const { world } = makeWorld();
  const runA = world.forRun("run-iso-a");
  const runB = world.forRun("run-iso-b");

  const orderA = bookedOrder(runA);
  // Same input sequence in run B produces DIFFERENT identifiers (seeded per runId).
  const orderB = bookedOrder(runB);
  assert.notEqual(orderB.orderRef, orderA.orderRef);
  assert.notEqual(orderB.pnr, orderA.pnr);

  assert.equal(runB.lookupOrder({ orderRef: orderA.orderRef }).status, "NOT_FOUND");
  assert.equal(runB.cancelOrder({ orderRef: orderA.orderRef }).code, "ORDER_NOT_FOUND");

  const payA = runA.payments.execute(PAYMENT_REQ);
  assert.equal(payA.ok, true);
  assert.equal(runB.payments.read(payA.receipt.transferId), null);
  assert.deepEqual(runB.payments.status(), { state: "none" });
});

test("two worlds with the same runId and call sequence produce identical results", () => {
  const a = makeWorld().world.forRun("run-det");
  const b = makeWorld().world.forRun("run-det");

  const quoteA = a.quote(QUOTE_REQ);
  const quoteB = b.quote(QUOTE_REQ);
  assert.deepEqual(quoteB, quoteA);

  const orderA = bookedOrder(a);
  const orderB = bookedOrder(b);
  assert.deepEqual(orderB, orderA);

  assert.deepEqual(
    b.issueTickets({ orderRef: orderB.orderRef }),
    a.issueTickets({ orderRef: orderA.orderRef }),
  );
  assert.deepEqual(b.payments.execute(PAYMENT_REQ), a.payments.execute(PAYMENT_REQ));
});

test("run state expires ttlMs after the terminal mark; sweep purges it", () => {
  const { world, setNow, advance } = makeWorld();
  const run = world.forRun("run-ttl");
  const order = bookedOrder(run);

  world.markTerminal("run-ttl");
  // Within TTL the record still resolves.
  advance(DAY_MS - 1);
  assert.equal(world.getRun("run-ttl")?.lookupOrder({ orderRef: order.orderRef }).status, "PENDING");

  // Past TTL the run's state is gone — lookups observe nothing.
  advance(2);
  assert.equal(world.getRun("run-ttl"), undefined);
  assert.equal(world.forRun("run-ttl").lookupOrder({ orderRef: order.orderRef }).status, "NOT_FOUND");

  // A run that never went terminal does not expire.
  const live = world.forRun("run-live");
  const liveOrder = bookedOrder(live);
  setNow(T0 + 365 * DAY_MS);
  assert.equal(world.getRun("run-live")?.lookupOrder({ orderRef: liveOrder.orderRef }).status, "PENDING");

  // sweep() removes only expired runs and reports the count.
  const { world: w2, setNow: setNow2 } = makeWorld();
  w2.forRun("a").quote(QUOTE_REQ);
  w2.forRun("b").quote(QUOTE_REQ);
  w2.markTerminal("a");
  setNow2(T0 + DAY_MS + 1);
  assert.equal(w2.sweep(), 1);
  assert.equal(w2.getRun("a"), undefined);
  assert.ok(w2.getRun("b") !== undefined);
});

test("sim modules are pure: no network imports or fetch usage", () => {
  const simDir = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..", "dist", "agent-contract", "sim",
  );
  const files = readdirSync(simDir).filter((f) => f.endsWith(".js"));
  assert.ok(files.length > 0, "sim dist files must exist");
  const banned = /node:http|node:https|node:net|node:dgram|\bfetch\(|undici|\baxios\b|\bws\b/;
  for (const file of files) {
    const source = readFileSync(path.join(simDir, file), "utf8");
    assert.equal(banned.test(source), false, `${file} reaches the network`);
  }
});

test("deterministic IDs derive from the run seed, not wall clock or global state", () => {
  // Fresh world, same runId, called LATER in the sequence must still yield the
  // same orderRef as an earlier world — the seed is runId, not call history of
  // unrelated methods? No: orderRef derives from the PRNG stream, so identical
  // call sequences are what must match. Two disjoint runIds on one world must
  // not perturb each other's streams.
  const { world } = makeWorld();
  const a1 = world.forRun("det-a");
  const orderA1 = a1.bookOrder({
    agreementId: "agr-x1", itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000, totalMinor: 439000,
  });
  assert.equal(orderA1.ok, true);
  // Interleave activity on another run — must not shift det-b's stream.
  world.forRun("det-x").quote(QUOTE_REQ);
  const b1 = world.forRun("det-b");

  const { world: world2 } = makeWorld();
  const b2 = world2.forRun("det-b");
  const orderB2 = b2.bookOrder({
    agreementId: "agr-x1", itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000, totalMinor: 439000,
  });
  const orderB1 = b1.bookOrder({
    agreementId: "agr-x1", itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000, totalMinor: 439000,
  });
  assert.equal(orderB1.orderRef, orderB2.orderRef);
  // Sanity: det-a and det-b seeds differ.
  assert.notEqual(orderA1.orderRef, orderB1.orderRef);
});

test("booking total must equal board fare + offered fee", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-fare");
  // IT-QW-ONESTOP fares 429000; fee 10000 → total 439000.
  assert.equal(
    run.bookOrder({ agreementId: "agr-f1", itineraryId: "IT-QW-ONESTOP", feeMinor: 0, totalMinor: 439000 }).code,
    "FARE_MISMATCH",
  );
  const ok = run.bookOrder({
    agreementId: "agr-f1", itineraryId: "IT-QW-ONESTOP",
    feeMinor: 10000, totalMinor: 439000,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.fareMinor, 429000);
  assert.equal(ok.feeMinor, 10000);
});

test("booked and paid state feeds canonicalDigest-stable responses", () => {
  const { world } = makeWorld();
  const run = world.forRun("run-digest");
  const order = bookedOrder(run);
  const obs = run.lookupOrder({ orderRef: order.orderRef });
  // The observation is plain JSON — digestable and stable across worlds.
  const other = makeWorld().world.forRun("run-digest");
  bookedOrder(other);
  const obs2 = other.lookupOrder({ orderRef: order.orderRef });
  assert.equal(canonicalDigest(obs2), canonicalDigest(obs));
});
