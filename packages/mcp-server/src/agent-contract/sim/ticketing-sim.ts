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
  currency: string;
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
  ticketCount: number;
  observedAt: string;
  simulated: true;
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
  /** The deterministic offer board — canonical rows plus quoted generated ones. */
  itinerary(itineraryId: string): SimItinerary | undefined;
  /** Config-seeded fault active on this run (undefined when none). */
  readonly faults: SimFaults | undefined;
  /**
   * A2 live (CONTRACT_SIM_FAULTS_BY_MANDATE): attach a config-seeded fault
   * after the run exists. Refused (false) once `bookOrder` has run, or when a
   * DIFFERENT fault is already active; re-setting the same fault is a no-op
   * true. Server-internal only — no tool reaches it.
   */
  setFaults(faults: SimFaults): boolean;
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
  /** The active fault — read at issue time, so a late (pre-booking) set applies. */
  let faults: SimFaults | undefined = deps.faults;
  let bookAttempted = false;

  const pick = (n: number): string =>
    Array.from({ length: n }, () => ID_ALPHABET[Math.floor(draw() * ID_ALPHABET.length)]).join("");

  /** Itineraries this run can book: canonical rows plus quoted generated ones. */
  const knownItineraries = new Map<string, SimItinerary>(
    CANONICAL_BOARD.map((i) => [i.itineraryId, i]),
  );
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
      const { departDate, returnDate } = parsed.data;
      const origin = parsed.data.origin.toUpperCase();
      const destination = parsed.data.destination.toUpperCase();
      const key = canonicalDigest({ ...parsed.data, origin, destination });
      const memoized = quoteMemo.get(key);
      if (memoized !== undefined) return structuredClone(memoized);

      const rows = [...CANONICAL_BOARD, ...generatedBoard(origin, destination)].filter(
        (i) => i.origin === origin && i.destination === destination,
      );
      const itineraries = rows.map((i) => ({
        ...i,
        ...(departDate !== undefined ? { departDate } : {}),
        ...(returnDate !== undefined ? { returnDate } : {}),
      }));
      for (const itin of itineraries) knownItineraries.set(itin.itineraryId, itin);

      const result: SimQuoteResult = {
        origin,
        destination,
        itineraries,
        quotedAt: isoNow(),
        simulated: true,
      };
      quoteMemo.set(key, result);
      return structuredClone(result);
    },

    bookOrder(input) {
      bookAttempted = true;
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

      const itinerary = knownItineraries.get(req.itineraryId);
      if (itinerary === undefined) return { ok: false, code: "ITINERARY_UNKNOWN" };
      if (req.totalMinor !== itinerary.fareMinor + req.feeMinor) {
        return { ok: false, code: "FARE_MISMATCH" };
      }

      const record: OrderRecord = {
        orderRef: `ORD-${pick(8)}`,
        pnr: pick(6),
        agreementId: req.agreementId,
        itineraryId: req.itineraryId,
        fareMinor: itinerary.fareMinor,
        feeMinor: req.feeMinor,
        totalMinor: req.totalMinor,
        currency: itinerary.currency,
        travelerCount: req.travelerCount ?? 1,
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
      if (faults?.issueMismatch === "fare") {
        order.fareMinor += ISSUE_MISMATCH_FARE_DELTA_MINOR;
        order.totalMinor += ISSUE_MISMATCH_FARE_DELTA_MINOR;
      }
      const ticketCount =
        faults?.issueMismatch === "travellers" ? order.travelerCount + 1 : order.travelerCount;

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
        ticketCount: order.tickets.length,
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
      return knownItineraries.get(itineraryId);
    },
    get faults() {
      return faults;
    },
    setFaults(next) {
      if (bookAttempted) return false;
      if (faults !== undefined) return faults.issueMismatch === next.issueMismatch;
      faults = { ...next };
      return true;
    },
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
