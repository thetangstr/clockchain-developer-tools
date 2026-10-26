import { z } from "zod";

import { canonicalDigest } from "../canonical.js";
import { createSimPaymentRail, type SimPaymentRail } from "./payment-rail.js";
import { mulberry32, seedFromName } from "./prng.js";

/**
 * Deterministic ticketing simulator — pure, run-scoped port of the travel
 * repo's `src/lib/travel/simulator/booking-simulator.ts` for N4b-2.
 *
 *   - Every run gets its own closed world: a mulberry32 stream seeded by
 *     `seedFromName("agent-contract-sim:" + runId)`, so two worlds that replay
 *     the same runId + call sequence produce identical identifiers, and two
 *     different runIds on one world can never see each other's state (CX-05).
 *   - Idempotency mirrors the source: quotes are memoized per input digest,
 *     orders are idempotent per `agreementId`, ticket issuance and
 *     cancellation replay their original record.
 *   - Fares come only from the deterministic offer board; the tool layer's
 *     "fare = board fare" check holds because the board is the ground truth.
 *   - Nothing here touches the network, the filesystem, or wall-clock state
 *     except the injected `now` — and no commercial transfer is possible.
 *
 * TTL (LLD §3): run state lives until `markTerminal`, then expires `ttlMs`
 * after that mark. `getRun` treats an expired run as absent; `sweep` drops it.
 */

export type SimFailureCode =
  | "ITINERARY_UNKNOWN"
  | "FARE_MISMATCH"
  | "AGREEMENT_CONFLICT"
  | "ORDER_NOT_FOUND"
  | "ORDER_NOT_PENDING"
  | "REQUEST_INVALID";

export interface SimRefusal {
  ok: false;
  code: SimFailureCode;
}

export interface SimItinerary {
  itineraryId: string;
  origin: string;
  destination: string;
  departDate?: string;
  returnDate?: string;
  summary: string;
  fareMinor: number;
  /**
   * Flexible-policy (mandate v3): present only once the run's party is known
   * (`SimRun.setParty`). `fareMinor` is then `farePerPersonMinor * party`.
   * Absent on every v2 / pre-party quote, which stay byte-identical.
   */
  farePerPersonMinor?: number;
  currency: string;
  /** D1459: a dated-board row quoted for the trip's dates (absent otherwise — every undated quote is unchanged). */
  detail?: SimItineraryDetail;
}

export interface SimQuoteResult {
  origin: string;
  destination: string;
  itineraries: SimItinerary[];
  quotedAt: string;
  simulated: true;
}

export type SimOrderStatus = "PENDING" | "ISSUED" | "CANCELLED";

export interface SimBookResult {
  ok: true;
  orderRef: string;
  pnr: string;
  agreementId: string;
  itineraryId: string;
  fareMinor: number;
  feeMinor: number;
  totalMinor: number;
  currency: string;
  travelerCount: number;
  status: "PENDING";
  bookedAt: string;
  simulated: true;
}

export interface SimTicket {
  travelerId: string;
  ticketNumber: string;
}

export interface SimIssueResult {
  ok: true;
  orderRef: string;
  pnr: string;
  status: "ISSUED";
  tickets: SimTicket[];
  issuedAt: string;
  simulated: true;
}

export interface SimOrderObservation {
  orderRef: string;
  status: SimOrderStatus | "NOT_FOUND";
  pnr?: string;
  agreementId?: string;
  itineraryId?: string;
  totalMinor?: number;
  currency?: string;
  /**
   * The party size the order was booked for — the server's own order record
   * (the principal-signed mandate's partySize, never a caller input). Distinct
   * from `ticketCount`, what was actually issued: a buyer compares the two.
   * Absent on NOT_FOUND and when the order was booked without a signed party size (legacy mandate).
   */
  travellers?: number;
  ticketCount: number;
  /** D1459: present only on a dated run (`SimRun.setTrip`) — the booking record's trip block. */
  trip?: SimBookingTrip;
  observedAt: string;
  simulated: true;
}

// -- D1459 trip detail (dated runs only) -------------------------------------
//
// Active only once `SimRun.setTrip` has been called (mandate_submit with a trip
// that carries departDate). An undated run never reaches any of this, so every
// output stays byte-identical. Everything here is simulated and deterministic:
// the carrier "ZX" (Zephyr Air) is fictional and its schedule is the sim's own.

/** The run's travel dates and travellers, fixed once by `setTrip`. */
export interface SimTrip {
  departDate: string;
  returnDate: string;
  adults: number;
  childAges: number[];
}

export type SimCabin = "economy" | "premium economy";

export interface SimSegment {
  direction: "outbound" | "return";
  origin: string;
  destination: string;
  carrierCode: "ZX";
  flightNumber: string;
  /** Local wall time at the departure airport, `YYYY-MM-DDTHH:MM`. */
  departureLocal: string;
  /** Local wall time at the arrival airport, `YYYY-MM-DDTHH:MM`. */
  arrivalLocal: string;
  durationMinutes: number;
  cabin: SimCabin;
}

export interface SimItineraryDetail {
  simulated: true;
  cabin: SimCabin;
  /** Outbound first, then return. */
  segments: SimSegment[];
  stops: 0 | 1;
  baggage: { carryOn: 1; checkedBagsPerTraveller: number; checkedBagMaxKg: 23 };
  changeTerms: { changeable: true; changeFeePerTravellerMinor: number; changeDeadline: string };
  cancelTerms: { refundable: false; travelCredit: true; cancelFeePerTravellerMinor: number; summary: string };
}

export interface SimFareLine {
  traveller: string;
  type: "adult" | "child";
  age?: number;
  baseMinor: number;
  taxesMinor: number;
  totalMinor: number;
}

/** What an offer (or the agreement) shows on a dated run. */
export interface SimOfferItinerary {
  /** Absent for a row with no schedule (a route outside SIM_ROUTE_SCHEDULES, or a canonical row). */
  detail?: SimItineraryDetail;
  fareLines: SimFareLine[];
  fareRule: string;
}

export interface SimTripTraveller {
  ref: string;
  type: "adult" | "child";
  age?: number;
  /** Synthetic — drawn from the run's seeded PRNG, never from any input. */
  initials: string;
}

/** The booking record's trip block (booking_lookup observation, contract_status booking). */
export interface SimBookingTrip {
  simulated: true;
  departDate: string;
  returnDate: string;
  segments?: SimSegment[];
  cabin?: SimCabin;
  baggage?: SimItineraryDetail["baggage"];
  changeTerms?: SimItineraryDetail["changeTerms"];
  cancelTerms?: SimItineraryDetail["cancelTerms"];
  travellers: SimTripTraveller[];
  /** The order's PNR. */
  recordLocator: string;
  ticketing: { status: SimOrderStatus; simulated: true; ticketNumbers: string[] };
}

/** Per-traveller taxes and carrier fees on a dated run's fare lines (minor units). */
export const SIM_TAXES_PER_TRAVELLER_MINOR = 18_640;
export const SIM_FARE_RULE =
  "Simulated: the offer total is split across the travellers, a child's fare is 75% of an adult's; taxes and carrier fees are 18640 minor per traveller.";
const CHANGE_FEE_PER_TRAVELLER_MINOR = 15_000;
const CANCEL_FEE_PER_TRAVELLER_MINOR = 20_000;
const CANCEL_SUMMARY =
  "Non-refundable; cancel before the change deadline for a travel credit minus $200 per traveller.";
/** Days before departure the change deadline falls. */
const CHANGE_DEADLINE_DAYS = 7;

/** IANA zone of every airport a schedule names (local times are computed with Intl, so DST is right). */
export const SIM_AIRPORT_ZONES: Readonly<Record<string, string>> = Object.freeze({
  SFO: "America/Los_Angeles",
  FCO: "Europe/Rome",
  JFK: "America/New_York",
});

/** The four rows of a dated board, in board order (the first three are the flex rows). */
export type SimDatedTier = "economy-nonstop" | "premium-nonstop" | "economy-1stop" | "economy-nonstop-later-return";
const DATED_TIERS: readonly SimDatedTier[] = Object.freeze([
  "economy-nonstop", "premium-nonstop", "economy-1stop", "economy-nonstop-later-return",
]);

interface ScheduleLeg {
  flightNumber: string;
  from: string;
  to: string;
  /** Block time. */
  blockMinutes: number;
  /** Ground time after the previous leg's arrival (every leg but the first). */
  connectionMinutes?: number;
}

interface ScheduleJourney {
  /** Local departure time of the first leg, `HH:MM`, on the travel date. */
  departs: string;
  legs: readonly ScheduleLeg[];
}

interface TierSchedule {
  cabin: SimCabin;
  outbound: ScheduleJourney;
  return: ScheduleJourney;
}

const ZX118: ScheduleJourney = { departs: "09:40", legs: [{ flightNumber: "ZX118", from: "SFO", to: "FCO", blockMinutes: 710 }] };
const ZX119: ScheduleJourney = { departs: "10:30", legs: [{ flightNumber: "ZX119", from: "FCO", to: "SFO", blockMinutes: 785 }] };

/**
 * The sim's own schedule (fictional carrier ZX), keyed `ORIGIN-DESTINATION`,
 * one entry per dated-board row. Add a route here (and its airports to
 * SIM_AIRPORT_ZONES) to give its dated board `detail`; a route absent here
 * keeps its rows without detail.
 */
export const SIM_ROUTE_SCHEDULES: Readonly<Record<string, Readonly<Record<SimDatedTier, TierSchedule>>>> = Object.freeze({
  "SFO-FCO": {
    "economy-nonstop": { cabin: "economy", outbound: ZX118, return: ZX119 },
    "premium-nonstop": { cabin: "premium economy", outbound: ZX118, return: ZX119 },
    "economy-1stop": {
      cabin: "economy",
      outbound: {
        departs: "07:15",
        legs: [
          { flightNumber: "ZX2204", from: "SFO", to: "JFK", blockMinutes: 330 },
          { flightNumber: "ZX2207", from: "JFK", to: "FCO", blockMinutes: 520, connectionMinutes: 120 },
        ],
      },
      return: {
        departs: "11:05",
        legs: [
          { flightNumber: "ZX2210", from: "FCO", to: "JFK", blockMinutes: 585 },
          { flightNumber: "ZX2213", from: "JFK", to: "SFO", blockMinutes: 395, connectionMinutes: 110 },
        ],
      },
    },
    "economy-nonstop-later-return": {
      cabin: "economy",
      outbound: ZX118,
      return: { departs: "14:20", legs: [{ flightNumber: "ZX121", from: "FCO", to: "SFO", blockMinutes: 790 }] },
    },
  },
});

const zoneFormatters = new Map<string, Intl.DateTimeFormat>();
function zoneFormatter(zone: string): Intl.DateTimeFormat {
  let f = zoneFormatters.get(zone);
  if (f === undefined) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone: zone, hourCycle: "h23",
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    zoneFormatters.set(zone, f);
  }
  return f;
}

/** The wall-clock fields of `utcMs` in `zone`. */
function wallFields(utcMs: number, zone: string): { y: number; mo: number; d: number; h: number; mi: number; s: number } {
  const parts: Record<string, number> = {};
  for (const p of zoneFormatter(zone).formatToParts(new Date(utcMs))) {
    if (p.type !== "literal") parts[p.type] = Number(p.value);
  }
  return { y: parts.year, mo: parts.month, d: parts.day, h: parts.hour === 24 ? 0 : parts.hour, mi: parts.minute, s: parts.second };
}

/** `zone`'s UTC offset at the instant `utcMs` (ms; local = utc + offset). */
function zoneOffsetMs(utcMs: number, zone: string): number {
  const w = wallFields(utcMs, zone);
  return Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s) - utcMs;
}

/** The UTC instant of a local wall time (`YYYY-MM-DD`, `HH:MM`) in `zone`. */
function zonedToUtc(date: string, time: string, zone: string): number {
  const [y, mo, d] = date.split("-").map(Number);
  const [h, mi] = time.split(":").map(Number);
  const wall = Date.UTC(y, mo - 1, d, h, mi);
  const first = zoneOffsetMs(wall, zone);
  let utc = wall - first;
  const second = zoneOffsetMs(utc, zone);
  if (second !== first) utc = wall - second; // the guess straddled a DST change
  return utc;
}

const pad2 = (n: number): string => String(n).padStart(2, "0");

/** `utcMs` as a local `YYYY-MM-DDTHH:MM` in `zone`. */
function utcToLocal(utcMs: number, zone: string): string {
  const w = wallFields(utcMs, zone);
  return `${w.y}-${pad2(w.mo)}-${pad2(w.d)}T${pad2(w.h)}:${pad2(w.mi)}`;
}

/** A real calendar date `YYYY-MM-DD` (2027-02-30 is not). */
export function isCalendarDate(s: unknown): s is string {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, mo, d] = s.split("-").map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

/** `date` plus `days` (may be negative), as `YYYY-MM-DD`. */
function addDays(date: string, days: number): string {
  const [y, mo, d] = date.split("-").map(Number);
  return new Date(Date.UTC(y, mo - 1, d + days)).toISOString().slice(0, 10);
}

function zoneOf(airport: string): string {
  const zone = SIM_AIRPORT_ZONES[airport];
  if (zone === undefined) throw new Error(`ticketing-sim: no zone for ${airport}`);
  return zone;
}

function journeySegments(
  direction: SimSegment["direction"], journey: ScheduleJourney, date: string, cabin: SimCabin,
): SimSegment[] {
  const out: SimSegment[] = [];
  let arrivalUtc = 0;
  journey.legs.forEach((leg, i) => {
    const departUtc = i === 0
      ? zonedToUtc(date, journey.departs, zoneOf(leg.from))
      : arrivalUtc + (leg.connectionMinutes ?? 0) * 60_000;
    arrivalUtc = departUtc + leg.blockMinutes * 60_000;
    out.push({
      direction,
      origin: leg.from,
      destination: leg.to,
      carrierCode: "ZX",
      flightNumber: leg.flightNumber,
      departureLocal: utcToLocal(departUtc, zoneOf(leg.from)),
      arrivalLocal: utcToLocal(arrivalUtc, zoneOf(leg.to)),
      durationMinutes: leg.blockMinutes,
      cabin,
    });
  });
  return out;
}

/** A dated row's detail: deterministic from the schedule row and the trip's dates. */
function buildDetail(schedule: TierSchedule, departDate: string, returnDate: string): SimItineraryDetail {
  const segments = [
    ...journeySegments("outbound", schedule.outbound, departDate, schedule.cabin),
    ...journeySegments("return", schedule.return, returnDate, schedule.cabin),
  ];
  return {
    simulated: true,
    cabin: schedule.cabin,
    segments,
    stops: schedule.outbound.legs.length > 1 || schedule.return.legs.length > 1 ? 1 : 0,
    baggage: { carryOn: 1, checkedBagsPerTraveller: schedule.cabin === "premium economy" ? 2 : 1, checkedBagMaxKg: 23 },
    changeTerms: {
      changeable: true,
      changeFeePerTravellerMinor: CHANGE_FEE_PER_TRAVELLER_MINOR,
      changeDeadline: addDays(departDate, -CHANGE_DEADLINE_DAYS),
    },
    cancelTerms: {
      refundable: false,
      travelCredit: true,
      cancelFeePerTravellerMinor: CANCEL_FEE_PER_TRAVELLER_MINOR,
      summary: CANCEL_SUMMARY,
    },
  };
}

/**
 * Split an offer total across the travellers (D1459 §3), exactly: weight adult
 * 1, child 0.75; `unitAdult = floor(total / (adults + 0.75 * children))`; each
 * child `round(0.75 * unitAdult)`; each adult `unitAdult`; the remainder goes
 * to ADT1, so the lines always sum to `totalMinor`. Taxes are
 * SIM_TAXES_PER_TRAVELLER_MINOR each, capped at the traveller's total.
 */
export function simFareLines(totalMinor: number, adults: number, childAges: readonly number[]): SimFareLine[] {
  const children = childAges.length;
  // floor(total / (a + 0.75c)) in integers: floor(4 * total / (4a + 3c))
  const unitAdult = Math.floor((4 * totalMinor) / (4 * adults + 3 * children));
  let child = Math.round((3 * unitAdult) / 4);
  let first = totalMinor - (adults - 1) * unitAdult - children * child;
  if (first < 0) {
    // only for absurdly small totals: rounding every child up overshot — round down instead
    child = Math.floor((3 * unitAdult) / 4);
    first = totalMinor - (adults - 1) * unitAdult - children * child;
  }
  const line = (traveller: string, type: SimFareLine["type"], total: number, age?: number): SimFareLine => {
    const taxesMinor = Math.min(SIM_TAXES_PER_TRAVELLER_MINOR, Math.max(0, total));
    return {
      traveller,
      type,
      ...(age !== undefined ? { age } : {}),
      baseMinor: total - taxesMinor,
      taxesMinor,
      totalMinor: total,
    };
  };
  return [
    ...Array.from({ length: adults }, (_, i) => line(`ADT${i + 1}`, "adult", i === 0 ? first : unitAdult)),
    ...childAges.map((age, i) => line(`CHD${i + 1}`, "child", child, age)),
  ];
}

export interface SimCancelResult {
  ok: true;
  orderRef: string;
  status: "CANCELLED";
  cancelledAt: string;
  simulated: true;
}

/**
 * Adverse-case injection (A2), seeded per runId by server config or the
 * l-stack — never by a tool call (every input schema is `.strict()`, so an
 * injected key is just REQUEST_INVALID). `issueMismatch` makes
 * `issueTickets` deviate from the booked order; `lookupOrder` then exposes
 * the deviation so buyer verification can detect it:
 *   "fare"       → the issued order's fareMinor/totalMinor drift by
 *                  ISSUE_MISMATCH_FARE_DELTA_MINOR
 *   "travellers" → one more ticket is issued than the order's travelerCount
 */
export interface SimFaults {
  issueMismatch?: "fare" | "travellers";
}

/** Deterministic fare drift applied by `issueMismatch: "fare"` (minor units). */
export const ISSUE_MISMATCH_FARE_DELTA_MINOR = 9_600;

export interface SimRun {
  quote(input: unknown): SimQuoteResult;
  bookOrder(input: unknown): SimBookResult | SimRefusal;
  issueTickets(input: unknown): SimIssueResult | SimRefusal;
  lookupOrder(input: unknown): SimOrderObservation;
  cancelOrder(input: unknown): SimCancelResult | SimRefusal;
  /**
   * The deterministic offer board — canonical rows plus quoted generated ones.
   * Priced for the run's party once `setParty` has been called.
   */
  itinerary(itineraryId: string): SimItinerary | undefined;
  /**
   * Flexible-policy (mandate v3): fix the run's party. Write-once; returns
   * false (and changes nothing) when a different party is already set or the
   * count is invalid. Before this call (and for every v2 run) fares are the
   * legacy fixed board totals.
   */
  setParty(partySize: number): boolean;
  /** The run's party once set, else undefined. */
  readonly party: number | undefined;
  /**
   * D1459: fix the run's travel dates and travellers (a "dated run").
   * Write-once like `setParty` and only after it: returns false (changing
   * nothing) when the party is unset, the dates or ages are invalid,
   * `adults + childAges.length` is not the party, or a different trip is
   * already set. Absent adults/childAges = every traveller an adult. From
   * then on the route's board is the dated board and offers, agreement and
   * booking carry the trip detail. Undated runs never change.
   */
  setTrip(trip: { departDate: string; returnDate: string; adults?: number; childAges?: readonly number[] }): boolean;
  /** The run's trip once set (a copy), else undefined. */
  readonly trip: SimTrip | undefined;
  /** D1459: a dated-board row's detail; undefined on an undated run or a row with no schedule. */
  itineraryDetail(itineraryId: string): SimItineraryDetail | undefined;
  /** D1459: an offer's itinerary block (detail + fare lines) at `totalMinor`; undefined on an undated run. */
  offerItinerary(itineraryId: string, totalMinor: number): SimOfferItinerary | undefined;
  /** D1459: the booking record's trip block for an order; undefined on an undated run or an unknown order. */
  bookingTrip(orderRef: string): SimBookingTrip | undefined;
  /** Config-seeded fault active on this run (undefined when none). */
  readonly faults: SimFaults | undefined;
  readonly payments: SimPaymentRail;
}

export interface SimWorld {
  /** Get (or lazily create) the closed world for a run. Expired runs are purged first. */
  forRun(runId: string): SimRun;
  /** The run's world, or undefined if absent or TTL-expired. */
  getRun(runId: string): SimRun | undefined;
  /** Start the TTL clock on a run (the contract run reached a terminal state). */
  markTerminal(runId: string): void;
  /** Drop every TTL-expired run; returns how many were removed. */
  sweep(): number;
  runIds(): string[];
}

const quoteInputSchema = z
  .object({
    origin: z.string().min(2).max(64),
    destination: z.string().min(2).max(64),
    departDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
    returnDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
    travelers: z.number().int().min(1).max(9).optional(),
  })
  .strict();

const bookInputSchema = z
  .object({
    agreementId: z.string().min(4).max(64),
    itineraryId: z.string().min(4).max(64),
    feeMinor: z.number().int().nonnegative().max(10_000_000),
    totalMinor: z.number().int().nonnegative(),
    travelerCount: z.number().int().min(1).max(9).optional(),
    // CONTRACT_PRIVATE_FLOOR (all-in pricing): the agreement's stated fare
    // component (0) — the agreed total is the price, the catalog fare is the
    // agency's private cost. Absent = the catalog fare, as before.
    fareMinor: z.number().int().nonnegative().optional(),
  })
  .strict();

const orderRefInputSchema = z
  .object({ orderRef: z.string().min(4).max(32) })
  .strict();

/**
 * The canonical pairing-route boards. ZRH→JFK: `IT-QW-ONESTOP` prices the
 * frozen prepare-envelope offer vector (fare 429000 + fee 10000 = 439000);
 * `IT-ZX118-ECON` prices the family bundle used elsewhere in the suite.
 * SFO→FCO: the Rome family scenario (RUNBOOK-ROME-P4) — fares are the old
 * inventory's family totals; the two-stop routings are deliberately
 * non-qualifying (a mandate's allowedItineraryIds excludes them).
 * Fares are fixed — they are the deterministic ground truth offers bind to.
 */
const CANONICAL_BOARD: readonly SimItinerary[] = Object.freeze([
  {
    itineraryId: "IT-QW-ONESTOP",
    origin: "ZRH",
    destination: "JFK",
    summary: "QW 404 via FRA — 1 stop, arrives next day",
    fareMinor: 429000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ZX118-ECON",
    origin: "ZRH",
    destination: "JFK",
    summary: "ZX 118 nonstop — economy bundle",
    fareMinor: 481800,
    currency: "USD",
  },
  {
    itineraryId: "IT-ZX118-PREM",
    origin: "ZRH",
    destination: "JFK",
    summary: "ZX 118 nonstop — premium economy",
    fareMinor: 596000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-ZX118-ECON",
    origin: "SFO",
    destination: "FCO",
    summary: "ZX 118/119 nonstop — economy family bundle",
    fareMinor: 481800,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-ZX118-PREM",
    origin: "SFO",
    destination: "FCO",
    summary: "ZX 118/119 nonstop — premium economy family bundle",
    fareMinor: 596000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-QW-ONESTOP",
    origin: "SFO",
    destination: "FCO",
    summary: "QW 2204/2207 via JFK — 1 stop, arrives next day",
    fareMinor: 431000,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-2STOP-A",
    origin: "SFO",
    destination: "FCO",
    summary: "QW 2210/2211/2212 via JFK+LHR — 2 stops, overnight (non-qualifying)",
    fareMinor: 398800,
    currency: "USD",
  },
  {
    itineraryId: "IT-ROME-2STOP-B",
    origin: "SFO",
    destination: "FCO",
    summary: "QW 2220/2221/2222 via ORD+LHR — 2 stops, overnight (non-qualifying)",
    fareMinor: 404800,
    currency: "USD",
  },
]);

/** Deterministic generated board for routes outside the canonical table. */
function generatedBoard(origin: string, destination: string): SimItinerary[] {
  const digest = canonicalDigest({ origin, destination, kind: "SIM_BOARD" }).slice(2);
  const byte = (i: number) => parseInt(digest.slice(i * 2, i * 2 + 2), 16);
  return [0, 1, 2].map((i) => ({
    itineraryId: `IT-${digest.slice(i * 6, i * 6 + 6).toUpperCase()}`,
    origin,
    destination,
    summary: `${origin}→${destination} option ${String.fromCharCode(65 + i)}`,
    fareMinor: 150_000 + ((byte(i * 4) * 256 + byte(i * 4 + 1)) % 5000) * 100,
    currency: "USD",
  }));
}

/**
 * The canonical rows' fares are family totals for a party of 4 (the Rome
 * scenario). Per person = total / 4 (every canonical fare divides evenly), so
 * a run whose party is 4 reprices to the identical total.
 */
const CANONICAL_BASE_PARTY = 4;

/**
 * Per-person board for a generated route (mandate v3). Same ids as
 * `generatedBoard` (ids never change); economy / premium economy / one-stop
 * labels; deterministic per-person fares from the same digest.
 */
function boardDigest(origin: string, destination: string): string {
  return canonicalDigest({ origin, destination, kind: "SIM_BOARD" }).slice(2);
}

/** The flex economy per-person fare for a route ($550..$949). */
function flexEconomyPerPerson(digest: string): number {
  const byte = (i: number) => parseInt(digest.slice(i * 2, i * 2 + 2), 16);
  return 55_000 + ((byte(12) * 256 + byte(13)) % 400) * 100;
}

/**
 * D1459: the dated board's fourth row — "economy, nonstop, later return",
 * id from the next digest slice, per-person fare = economy x 1.06 rounded to $1.
 * Only ever on a dated run's board.
 */
function laterReturnRow(origin: string, destination: string): SimItinerary {
  const digest = boardDigest(origin, destination);
  const perPerson = Math.round((flexEconomyPerPerson(digest) * 106) / 10_000) * 100;
  return {
    itineraryId: `IT-${digest.slice(18, 24).toUpperCase()}`,
    origin,
    destination,
    summary: `${origin}→${destination} economy, nonstop, later return (fare is per person)`,
    fareMinor: perPerson,
    farePerPersonMinor: perPerson,
    currency: "USD",
  };
}

/** D1459: which dated-board row an id is on its route (undefined for any other id). */
function datedTierOf(origin: string, destination: string, itineraryId: string): SimDatedTier | undefined {
  const digest = boardDigest(origin, destination);
  const i = DATED_TIERS.findIndex((_, n) => itineraryId === `IT-${digest.slice(n * 6, n * 6 + 6).toUpperCase()}`);
  return i < 0 ? undefined : DATED_TIERS[i];
}

function flexGeneratedBoard(origin: string, destination: string): SimItinerary[] {
  const digest = boardDigest(origin, destination);
  const economy = flexEconomyPerPerson(digest); // $550..$949 per person
  const round100 = (n: number) => Math.round(n / 100) * 100;
  const tiers: Array<{ label: string; perPerson: number }> = [
    { label: "economy, nonstop", perPerson: economy },
    { label: "premium economy, nonstop", perPerson: round100(economy * 1.55) },
    { label: "economy, 1 stop (longer journey)", perPerson: round100(economy * 0.82) },
  ];
  return tiers.map((t, i) => ({
    itineraryId: `IT-${digest.slice(i * 6, i * 6 + 6).toUpperCase()}`,
    origin,
    destination,
    summary: `${origin}→${destination} ${t.label} (fare is per person)`,
    fareMinor: t.perPerson,
    farePerPersonMinor: t.perPerson,
    currency: "USD",
  }));
}

/** Reprice a legacy row for a party: canonical rows by their per-person share, generated rows by flex. */
function pricedForParty(row: SimItinerary, party: number): SimItinerary {
  const perPerson = row.farePerPersonMinor ?? row.fareMinor / CANONICAL_BASE_PARTY;
  return { ...row, farePerPersonMinor: perPerson, fareMinor: perPerson * party };
}

const ID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

interface OrderRecord {
  orderRef: string;
  pnr: string;
  agreementId: string;
  itineraryId: string;
  fareMinor: number;
  feeMinor: number;
  totalMinor: number;
  currency: string;
  travelerCount: number;
  /** The party size came from the principal-signed mandate (not the default of 1): only then is it observable. */
  partySizeKnown: boolean;
  status: SimOrderStatus;
  bookedAt: string;
  cancelledAt?: string;
  tickets: SimTicket[];
}

interface RunEntry {
  sim: SimRun;
  terminalAtMs: number | null;
}

function createSimRun(
  runId: string,
  deps: { now: () => number; faults?: SimFaults },
): SimRun {
  const now = deps.now;
  const draw = mulberry32(seedFromName(`agent-contract-sim:${runId}`));

  const pick = (n: number): string =>
    Array.from({ length: n }, () => ID_ALPHABET[Math.floor(draw() * ID_ALPHABET.length)]).join("");

  /** Itineraries this run can book: canonical rows plus quoted generated ones. */
  const knownItineraries = new Map<string, SimItinerary>(
    CANONICAL_BOARD.map((i) => [i.itineraryId, i]),
  );
  /** Generated rows' per-person (v3) pricing and labels, keyed by the (unchanged) itinerary id. */
  const flexKnown = new Map<string, SimItinerary>();
  /** Flexible-policy party (mandate v3); undefined = legacy fixed board totals. */
  let party: number | undefined;
  /** An itinerary as this run prices it: legacy totals, or per-person x party once the party is set. */
  function priced(id: string): SimItinerary | undefined {
    const legacy = knownItineraries.get(id);
    if (legacy === undefined || party === undefined) return legacy;
    const flex = flexKnown.get(id);
    return pricedForParty(
      flex === undefined ? legacy : { ...legacy, summary: flex.summary, farePerPersonMinor: flex.farePerPersonMinor },
      party,
    );
  }
  /** D1459: the run's trip (dates + travellers); undefined = an undated run, unchanged behaviour. */
  let trip: SimTrip | undefined;
  /** D1459: the travellers with their synthetic initials, drawn once at setTrip. */
  let travellers: SimTripTraveller[] = [];
  const detailMemo = new Map<string, SimItineraryDetail | null>();

  /** D1459: the detail of a dated-board row, from the schedule table and the trip's dates (pure, memoized). */
  function detailOf(id: string): SimItineraryDetail | undefined {
    if (trip === undefined) return undefined;
    const memo = detailMemo.get(id);
    if (memo !== undefined) return memo ?? undefined;
    const row = knownItineraries.get(id);
    if (row === undefined) return undefined; // not on any board this run has quoted (yet): never memoized
    const tier = datedTierOf(row.origin, row.destination, id);
    const schedule = tier === undefined ? undefined : SIM_ROUTE_SCHEDULES[`${row.origin}-${row.destination}`]?.[tier];
    const detail = schedule === undefined ? undefined : buildDetail(schedule, trip.departDate, trip.returnDate);
    detailMemo.set(id, detail ?? null);
    return detail;
  }

  function bookingTripOf(order: OrderRecord): SimBookingTrip | undefined {
    if (trip === undefined) return undefined;
    const detail = detailOf(order.itineraryId);
    return {
      simulated: true,
      departDate: trip.departDate,
      returnDate: trip.returnDate,
      ...(detail !== undefined
        ? {
            segments: detail.segments,
            cabin: detail.cabin,
            baggage: detail.baggage,
            changeTerms: detail.changeTerms,
            cancelTerms: detail.cancelTerms,
          }
        : {}),
      travellers: travellers.map((t) => ({ ...t })),
      recordLocator: order.pnr,
      ticketing: { status: order.status, simulated: true, ticketNumbers: order.tickets.map((t) => t.ticketNumber) },
    };
  }

  const quoteMemo = new Map<string, SimQuoteResult>();
  const orders = new Map<string, OrderRecord>();
  /** agreementId → digest of the first accepted booking input (idempotency). */
  const agreements = new Map<string, string>();
  /** agreementId → orderRef of the order it produced. */
  const agreementOrder = new Map<string, string>();
  /** orderRef → issue result once emitted (idempotent replay). */
  const issueMemo = new Map<string, SimIssueResult>();
  /** orderRef → cancel result once emitted (idempotent replay). */
  const cancelMemo = new Map<string, SimCancelResult>();

  const isoNow = () => new Date(now()).toISOString();

  function toBookResult(record: OrderRecord): SimBookResult {
    const { tickets: _tickets, cancelledAt: _c, status: _s, ...rest } = record;
    return { ok: true, ...rest, status: "PENDING", simulated: true };
  }

  return {
    quote(input) {
      const parsed = quoteInputSchema.safeParse(input);
      if (!parsed.success) {
        // A malformed quote request yields an empty board — never a throw.
        return {
          origin: "", destination: "", itineraries: [], quotedAt: isoNow(), simulated: true,
        };
      }
      // D1459: a dated run's quote without dates uses the trip's dates.
      const departDate = parsed.data.departDate ?? trip?.departDate;
      const returnDate = parsed.data.returnDate ?? trip?.returnDate;
      const origin = parsed.data.origin.toUpperCase();
      const destination = parsed.data.destination.toUpperCase();
      const key = canonicalDigest({
        ...parsed.data, origin, destination,
        ...(party !== undefined ? { party } : {}),
        ...(trip !== undefined ? { trip: { departDate: trip.departDate, returnDate: trip.returnDate } } : {}),
      });
      const memoized = quoteMemo.get(key);
      if (memoized !== undefined) return structuredClone(memoized);

      // D1459: a dated run's board is the three flex rows plus the later-return
      // row (canonical rows stay bookable by id but are not on it).
      const rows = trip === undefined
        ? [...CANONICAL_BOARD, ...generatedBoard(origin, destination)].filter(
            (i) => i.origin === origin && i.destination === destination,
          )
        : [...generatedBoard(origin, destination), laterReturnRow(origin, destination)];
      const itineraries = rows.map((i) => ({
        ...i,
        ...(departDate !== undefined ? { departDate } : {}),
        ...(returnDate !== undefined ? { returnDate } : {}),
      }));
      for (const itin of itineraries) knownItineraries.set(itin.itineraryId, itin);
      // The generated rows' per-person view (same ids as the legacy generated rows).
      for (const f of flexGeneratedBoard(origin, destination)) flexKnown.set(f.itineraryId, f);
      if (trip !== undefined) {
        const later = laterReturnRow(origin, destination);
        flexKnown.set(later.itineraryId, later);
      }
      // D1459: rows carry the schedule only when quoted for the trip's own dates.
      const tripDates = trip !== undefined && departDate === trip.departDate && returnDate === trip.returnDate;
      const withDetail = (row: SimItinerary): SimItinerary => {
        const detail = tripDates ? detailOf(row.itineraryId) : undefined;
        return detail === undefined ? row : { ...row, detail: structuredClone(detail) };
      };

      const result: SimQuoteResult = {
        origin,
        destination,
        itineraries: party === undefined ? itineraries : itineraries.map((i) => withDetail(priced(i.itineraryId)!)),
        quotedAt: isoNow(),
        simulated: true,
      };
      quoteMemo.set(key, result);
      return structuredClone(result);
    },

    bookOrder(input) {
      const parsed = bookInputSchema.safeParse(input);
      if (!parsed.success) return { ok: false, code: "REQUEST_INVALID" };
      const req = parsed.data;
      const inputDigest = canonicalDigest({ runId, method: "bookOrder", input: req });

      const prior = agreements.get(req.agreementId);
      if (prior !== undefined) {
        if (prior === inputDigest) {
          const record = orders.get(agreementOrder.get(req.agreementId)!)!;
          return toBookResult(record);
        }
        return { ok: false, code: "AGREEMENT_CONFLICT" };
      }

      const itinerary = priced(req.itineraryId);
      if (itinerary === undefined) return { ok: false, code: "ITINERARY_UNKNOWN" };
      const statedFareMinor = req.fareMinor ?? itinerary.fareMinor;
      if (req.totalMinor !== statedFareMinor + req.feeMinor) {
        return { ok: false, code: "FARE_MISMATCH" };
      }

      const record: OrderRecord = {
        orderRef: `ORD-${pick(8)}`,
        pnr: pick(6),
        agreementId: req.agreementId,
        itineraryId: req.itineraryId,
        fareMinor: statedFareMinor,
        feeMinor: req.feeMinor,
        totalMinor: req.totalMinor,
        currency: itinerary.currency,
        travelerCount: req.travelerCount ?? 1,
        partySizeKnown: req.travelerCount !== undefined,
        status: "PENDING",
        bookedAt: isoNow(),
        tickets: [],
      };
      orders.set(record.orderRef, record);
      agreementOrder.set(req.agreementId, record.orderRef);
      agreements.set(req.agreementId, inputDigest);
      return toBookResult(record);
    },

    issueTickets(input) {
      const parsed = orderRefInputSchema.safeParse(input);
      if (!parsed.success) return { ok: false, code: "REQUEST_INVALID" };
      const memoized = issueMemo.get(parsed.data.orderRef);
      if (memoized !== undefined) return structuredClone(memoized);

      const order = orders.get(parsed.data.orderRef);
      if (order === undefined) return { ok: false, code: "ORDER_NOT_FOUND" };
      if (order.status !== "PENDING") return { ok: false, code: "ORDER_NOT_PENDING" };

      // A2 fault: the issued record deviates from the booked order. The
      // mutation lands on the order record so `lookupOrder` exposes it to
      // buyer verification.
      if (deps.faults?.issueMismatch === "fare") {
        order.fareMinor += ISSUE_MISMATCH_FARE_DELTA_MINOR;
        order.totalMinor += ISSUE_MISMATCH_FARE_DELTA_MINOR;
      }
      const ticketCount =
        deps.faults?.issueMismatch === "travellers" ? order.travelerCount + 1 : order.travelerCount;

      const tickets: SimTicket[] = Array.from({ length: ticketCount }, (_, i) => ({
        travelerId: `PAX-${i + 1}`,
        ticketNumber: `TKT${Array.from({ length: 13 }, () => Math.floor(draw() * 10)).join("")}`,
      }));
      order.tickets = tickets;
      order.status = "ISSUED";
      const result: SimIssueResult = {
        ok: true,
        orderRef: order.orderRef,
        pnr: order.pnr,
        status: "ISSUED",
        tickets,
        issuedAt: isoNow(),
        simulated: true,
      };
      issueMemo.set(order.orderRef, result);
      return structuredClone(result);
    },

    lookupOrder(input) {
      const parsed = orderRefInputSchema.safeParse(input);
      const orderRef = parsed.success ? parsed.data.orderRef : "";
      const order = parsed.success ? orders.get(parsed.data.orderRef) : undefined;
      if (order === undefined) {
        return { orderRef, status: "NOT_FOUND", ticketCount: 0, observedAt: isoNow(), simulated: true };
      }
      return {
        orderRef: order.orderRef,
        status: order.status,
        pnr: order.pnr,
        agreementId: order.agreementId,
        itineraryId: order.itineraryId,
        totalMinor: order.totalMinor,
        currency: order.currency,
        // only a party size the principal signed — a legacy mandate without one books the default of 1,
        // which is not a claim (contract_status/bookingPayload and verification_submit omit it the same way)
        ...(order.partySizeKnown ? { travellers: order.travelerCount } : {}),
        ticketCount: order.tickets.length,
        // D1459: dated runs only — an undated observation is unchanged.
        ...(trip !== undefined ? { trip: structuredClone(bookingTripOf(order)!) } : {}),
        observedAt: isoNow(),
        simulated: true,
      };
    },

    cancelOrder(input) {
      const parsed = orderRefInputSchema.safeParse(input);
      if (!parsed.success) return { ok: false, code: "REQUEST_INVALID" };
      const memoized = cancelMemo.get(parsed.data.orderRef);
      if (memoized !== undefined) return structuredClone(memoized);

      const order = orders.get(parsed.data.orderRef);
      if (order === undefined) return { ok: false, code: "ORDER_NOT_FOUND" };

      order.status = "CANCELLED";
      order.cancelledAt = isoNow();
      const result: SimCancelResult = {
        ok: true,
        orderRef: order.orderRef,
        status: "CANCELLED",
        cancelledAt: order.cancelledAt,
        simulated: true,
      };
      cancelMemo.set(order.orderRef, result);
      return structuredClone(result);
    },

    itinerary(itineraryId) {
      return priced(itineraryId);
    },
    setParty(partySize) {
      if (!Number.isInteger(partySize) || partySize < 1 || partySize > 9) return false;
      if (party !== undefined) return party === partySize;
      party = partySize;
      return true;
    },
    get party() {
      return party;
    },
    setTrip(input) {
      if (party === undefined) return false;
      const adults = input.adults ?? (input.childAges === undefined ? party : undefined);
      const childAges = input.childAges ?? (input.adults === undefined ? [] : undefined);
      if (
        !isCalendarDate(input.departDate) || !isCalendarDate(input.returnDate) ||
        input.returnDate <= input.departDate ||
        adults === undefined || childAges === undefined ||
        !Number.isInteger(adults) || adults < 1 ||
        !Array.isArray(childAges) || childAges.length > 8 ||
        !childAges.every((a) => Number.isInteger(a) && a >= 2 && a <= 17) ||
        adults + childAges.length !== party
      ) {
        return false;
      }
      const next: SimTrip = {
        departDate: input.departDate, returnDate: input.returnDate, adults, childAges: [...childAges],
      };
      if (trip !== undefined) return canonicalDigest(trip) === canonicalDigest(next);
      trip = next;
      // Synthetic initials from the run's seeded stream: one family letter, then
      // a distinct first initial per traveller, in trip order. Never from input.
      const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const family = LETTERS[Math.floor(draw() * LETTERS.length)];
      const free = [...LETTERS];
      const firstInitial = (): string => free.splice(Math.floor(draw() * free.length), 1)[0];
      travellers = [
        ...Array.from({ length: adults }, (_, i): SimTripTraveller => ({
          ref: `ADT${i + 1}`, type: "adult", initials: `${firstInitial()}.${family}.`,
        })),
        ...next.childAges.map((age, i): SimTripTraveller => ({
          ref: `CHD${i + 1}`, type: "child", age, initials: `${firstInitial()}.${family}.`,
        })),
      ];
      return true;
    },
    get trip() {
      return trip === undefined ? undefined : structuredClone(trip);
    },
    itineraryDetail(itineraryId) {
      const detail = detailOf(itineraryId);
      return detail === undefined ? undefined : structuredClone(detail);
    },
    offerItinerary(itineraryId, totalMinor) {
      if (trip === undefined || !Number.isInteger(totalMinor) || totalMinor < 0) return undefined;
      const detail = detailOf(itineraryId);
      return {
        ...(detail !== undefined ? { detail: structuredClone(detail) } : {}),
        fareLines: simFareLines(totalMinor, trip.adults, trip.childAges),
        fareRule: SIM_FARE_RULE,
      };
    },
    bookingTrip(orderRef) {
      const order = orders.get(orderRef);
      if (order === undefined) return undefined;
      const block = bookingTripOf(order);
      return block === undefined ? undefined : structuredClone(block);
    },
    faults: deps.faults,
    payments: createSimPaymentRail({ runId, now }),
  };
}

export function createSimWorld(options: {
  now?: () => number;
  /** Post-terminal-state retention (LLD §3: 24 h). */
  ttlMs?: number;
  /**
   * Config-only fault seeds keyed by runId (A2 adverse cases). Supplied by
   * server config or the l-stack — there is deliberately no tool/agent path.
   */
  faults?: Readonly<Record<string, SimFaults>>;
}): SimWorld {
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? 24 * 60 * 60 * 1000;
  const faults = options.faults ?? {};
  const entries = new Map<string, RunEntry>();
  const runIdSchema = z.string().min(1).max(128);

  const expired = (entry: RunEntry): boolean =>
    entry.terminalAtMs !== null && now() >= entry.terminalAtMs + ttlMs;

  function getRun(runId: string): SimRun | undefined {
    const entry = entries.get(runId);
    if (entry === undefined) return undefined;
    if (expired(entry)) {
      entries.delete(runId);
      return undefined;
    }
    return entry.sim;
  }

  return {
    forRun(runId) {
      runIdSchema.parse(runId);
      const existing = getRun(runId);
      if (existing !== undefined) return existing;
      const entry: RunEntry = { sim: createSimRun(runId, { now, faults: faults[runId] }), terminalAtMs: null };
      entries.set(runId, entry);
      return entry.sim;
    },
    getRun,
    markTerminal(runId) {
      const entry = entries.get(runId);
      if (entry !== undefined) entry.terminalAtMs = now();
    },
    sweep() {
      let removed = 0;
      for (const [runId, entry] of entries) {
        if (expired(entry)) {
          entries.delete(runId);
          removed += 1;
        }
      }
      return removed;
    },
    runIds() {
      for (const runId of [...entries.keys()]) getRun(runId); // purge expired lazily
      return [...entries.keys()];
    },
  };
}
