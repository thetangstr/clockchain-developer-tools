import { createPublicKey, type KeyObject } from "node:crypto";

import { z } from "zod";

import { canonicalDigest, saltedCanonicalDigest } from "./canonical.js";
import {
  signEnvelope, verifyEnvelope, type ContractSigner, type PrepareEnvelope,
} from "./envelope.js";
import {
  eip191RecoverPublicKey, publicKeyToAddress, verifyRoleSignature,
} from "./eip191.js";
import { checkApprovalRecord, verifyApprovalRecord } from "./approval.js";
import { StripeTestRailError, type SettlementRail } from "./settlement-rail.js";
import { sealedBoxSchema, type ApprovalRecord, type ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";
import type {
  AgreementRecord, ContractPrincipal, ContractRun, OfferRecord,
} from "./service.js";
import type { SimWorld } from "./sim/index.js";

/**
 * The `/contract/mcp` business semantics (N4b-2b, LLD §3/§13 + rev 6.5):
 * every catalogued tool except `contract_bind`/`contract_status`
 * (service-owned).
 *
 * The rules that make this deterministic rather than runner-driven:
 *  - every `*_prepare` returns a server-signed envelope whose PAYLOAD is
 *    server-derived (board fare, agreement digest, booking/settlement
 *    amounts) — the agent chooses which operation to call, never the
 *    consequential values;
 *  - every `*_submit`/`execute`/`authorize` verifies the envelope against the
 *    pinned server key, claims its nonce per-run, verifies the EIP-191 role
 *    signature against the signer key bound at contract_bind, and re-checks
 *    the payload against live state;
 *  - the mandate is the family PRINCIPAL's signed statement (rev 6.5),
 *    verified against `CONTRACT_PRINCIPALS`, write-once per run;
 *  - the agreement is WRITE-ONCE: once formed, every offer/accept path is
 *    closed; before it forms, a new offer supersedes the same party's live
 *    offers and only the counterparty's LATEST live offer can be accepted;
 *  - booking/settlement additionally require a §13 approval record verified
 *    against the bound approval key AND the configured per-role policy
 *    digest (`CONTRACT_POLICY_DIGESTS`);
 *  - booking touches the run's closed ticketing sim, settlement the run's
 *    payment rail — every sim-derived output carries `simulated: true`.
 */

/**
 * D8: how a delivered invitation's senderAgentId was established at
 * delivery time — the static token's pin, the certificate party resolved
 * by a late bind, or nothing (the rendezvous precedes the handshake, so
 * an unbound `*` sender is authenticated only by what comes later).
 */
export type SenderProof = "token-pinned" | "certificate-bound" | "unproven-pre-bind";

export type BusinessOutcome =
  | {
      ok: true;
      result: Record<string, unknown>;
      /** Extra server-derived fields the call's receipt must carry. */
      receiptFields?: { senderProof?: SenderProof };
    }
  | { ok: false; code: ContractRefusalCode };

interface Listing {
  listingId: string;
  providerKeyId: string;
  title: string;
  summary: string;
  sealedBoxPublicKeyHex: string;
  terms?: Record<string, unknown>;
  publishedAtMs: number;
  expiresAtMs: number;
  /**
   * The listing is consumed ONLY when the provider acts — binds the
   * handshake that came from one of its pending deliveries. A delivered
   * invitation (even junk) never burns the listing for other senders.
   */
  consumed: boolean;
  /** Pending sealed deliveries — at most one per sender keyId (a resend
   *  replaces the sender's old one), at most 16 per listing. */
  pending: Map<string, InboxMessage>;
}

interface InboxMessage {
  messageId: string;
  kind: "handshake_invitation" | "business_message";
  /**
   * LOW (N4b-3): the sender's token-pinned identity — the provider's signer
   * can check the delivered handshake names THIS agentId, not just any
   * caller who could deliver a sealed blob. D8: `null` when the sender
   * hadn't proven an agentId yet (unbound `*` token, pre-handshake).
   */
  senderKeyId: string;
  senderAgentId: string | null;
  /** D8: how senderAgentId was established — see SenderProof. */
  senderProof: SenderProof;
  listingId?: string;
  sealedPayload?: Record<string, unknown>;
  body?: unknown;
  receivedAt: string;
}

export interface BusinessOps {
  /**
   * Synchronous for every tool except the two Stripe-rail settlement
   * calls — `settlement_prepare`/`settlement_authorize` under
   * CONTRACT_SETTLEMENT_RAIL=stripe_test_mode resolve their rail calls
   * and return a Promise. Callers must `await` the union.
   */
  dispatch(
    principal: ContractPrincipal,
    run: ContractRun | undefined,
    tool: string,
    args: Record<string, unknown>,
    serverNonce: string,
  ): BusinessOutcome | Promise<BusinessOutcome>;
  /**
   * Non-mutating probe (LOW, N4b-3): is `listingId` a live listing owned by
   * this provider? Used to refuse a provider bind that names a foreign,
   * unknown or already-consumed listing BEFORE any bind state is claimed.
   */
  consumableListing(providerKeyId: string, listingId: string): boolean;
  /**
   * The provider acted on ONE delivery — consumes only the listing it came
   * through (LOW, N4b-3): other listings stay live. Called at the bind
   * commit point, after every other check has passed. Idempotent on an
   * already-consumed listing (the early probe is the gate; a duplicate
   * consume is a no-op).
   */
  consumeListing(providerKeyId: string, listingId: string): boolean;
}

const iso = (ms: number): string => new Date(ms).toISOString();
const ok = (result: Record<string, unknown>): BusinessOutcome => ({ ok: true, result });
const refuse = (code: ContractRefusalCode): BusinessOutcome => ({ ok: false, code });

const AGREEMENT_DOMAIN = "agent-contract.agreement/v1";
const MANDATE_DOMAIN = "agent-contract.mandate/v1";

/** N4b-10 (D13): the sim-label every Stripe-rail response carries. */
const STRIPE_RAIL_LABEL = "Stripe TEST mode — no real money";

/** rev 6.5: the mandate is the family principal's statement — all fields required. */
const mandateSchema = z.object({
  kind: z.literal("mandate"),
  mandateId: z.string().min(4).max(64),
  capMinor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  currency: z.string().regex(/^[A-Z]{3}$/),
  allowedItineraryIds: z.array(z.string().min(1).max(64)).min(1).max(64),
  // N4b-9 (F16 → D12): the traveller count is principal-signed, never
  // model-supplied (v2.2). Required — a v2 mandate without it is refused
  // MANDATE_INVALID like every other shape failure.
  partySize: z.number().int().min(1).max(9),
  expiresAt: z.string().datetime({ offset: false }),
}).strict();
type Mandate = z.infer<typeof mandateSchema>;

const LISTING_TTL_MS = 60 * 60_000;
/** Global safety cap — the real quota is per-provider. */
const MAX_LISTINGS = 512;
/** Superseded listing ids remembered (for a clear refusal) at most. */
const MAX_SUPERSEDED = 1024;
/** Pending sealed deliveries a single listing holds at once. */
const MAX_PENDING_PER_LISTING = 16;
const MAX_INBOX_MESSAGES = 256;
const MAX_DELIVERIES_PER_MINUTE = 12;

function pad4(n: number): string {
  return String(n).padStart(4, "0");
}

/** The counterparty's LATEST live offer — the only acceptable one. */
export function latestCounterpartyOffer(run: ContractRun, role: ContractRole): OfferRecord | undefined {
  let latest: OfferRecord | undefined;
  for (const offer of run.offers.values()) {
    if (offer.state === "live" && offer.role !== role &&
      (latest === undefined || offer.seq > latest.seq)) {
      latest = offer;
    }
  }
  return latest;
}

/** Offers `contract_status` lists, newest first. */
export const STATUS_MAX_OFFERS = 8;

/**
 * AGENT-TOOLS-BY-REFERENCE S1 + S2: the read-only negotiation, agreement,
 * booking and cancellation views `contract_status` adds for a bound caller.
 * Scoped to the caller's own run (the run is resolved from its token) and
 * role (`acceptable` is the counterparty's latest live offer — exactly what
 * `offer_accept_prepare` would take, with no cap check, so it never hints at
 * the mandate cap). Short typed values only: no envelopes, digests,
 * signatures, payload objects or ticket details.
 */
export function contractStatusReadView(run: ContractRun, role: ContractRole): Record<string, unknown> {
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  const offers = [...run.offers.values()]
    .sort((a, b) => b.seq - a.seq)
    .slice(0, STATUS_MAX_OFFERS)
    .map((o) => ({
      offerId: o.offerId,
      by: o.role,
      kind: o.payload.kind === "counter" ? "counter" : "offer",
      inReplyTo: str(o.payload.inReplyTo),
      itineraryId: str(o.payload.itineraryId),
      currency: str(o.payload.currency),
      fareMinor: o.payload.fareMinor,
      feeMinor: o.payload.feeMinor,
      totalMinor: o.payload.totalMinor,
      note: str(o.payload.note),
      state: o.state,
      submittedAt: o.submittedAt,
    }));
  const open = run.terminalState === null && run.agreement === undefined;
  const a = run.agreement;
  const b = run.booking;
  return {
    negotiation: {
      acceptable: open ? latestCounterpartyOffer(run, role)?.offerId ?? null : null,
      offers,
    },
    agreement: a === undefined ? null : {
      agreementId: a.agreementId,
      offerId: a.offerId,
      itineraryId: a.itineraryId,
      currency: a.currency,
      totalMinor: a.totalMinor,
      formedAt: a.formedAt,
    },
    booking: b === undefined ? null : {
      orderRef: b.orderRef,
      pnr: b.pnr,
      ticketCount: b.tickets.length,
      bookedAt: b.bookedAt,
      simulated: true,
    },
    cancellation: run.cancellation === undefined ? null : {
      orderRef: run.cancellation.orderRef,
      cancelledAt: run.cancellation.cancelledAt,
    },
  };
}

export function createBusinessOps(options: {
  signer: ContractSigner;
  now?: () => number;
  sim: SimWorld;
  /**
   * N4b-4 key validity at the source: when the published key's `validUntil`
   * has passed this returns false — no envelope may be signed, so dispatch
   * refuses outright (the receipted caller can never reach it anyway).
   */
  signingOpen?: () => boolean;
  /** Required per-role §13 policy pins (`CONTRACT_POLICY_DIGESTS`). */
  policyDigests: Readonly<Record<ContractRole, ReadonlySet<string>>>;
  /** `CONTRACT_PRINCIPALS`: buyer keyId → pinned family-principal address. */
  principals?: ReadonlyMap<string, string>;
  /**
   * Single-use mandate ledger (N4B2B-CHANGES-2 §3): claims
   * `mandateId` for a family principal — durable when the service has a
   * state dir. The claim persists BEFORE the run's mandate record commits.
   * Absent this hook an in-memory ledger still enforces single-use.
   */
  claimMandate?(principalAddress: string, mandateId: string, runId: string, expiresAtMs: number): "ok" | "used" | "unavailable";
  endRun: (run: ContractRun, terminalState: string, principal?: ContractPrincipal) => void;
  /**
   * N4b-8 (gap 4): anchor a run subject — called with "agreement" right
   * after the agreement record commits. The service owns the async anchor
   * and the outcome receipt; business only fires it.
   */
  anchorRun?: (run: ContractRun, kind: "agreement" | "terminal") => void;
  /**
   * N4b-8 (gap 2): CONTRACT_LEVEL=L only — legacy unbound v:2 boxes still
   * deliver. At S|P only the listing-bound v:4 wire is accepted; the server
   * carries every box opaque either way.
   */
  allowLegacySealV2?: boolean;
  /**
   * N4b-10 (spec D13): the Stripe TEST-mode settlement rail
   * (CONTRACT_SETTLEMENT_RAIL=stripe_test_mode). Absent = the default
   * simulated rail — the settlement payload then reads
   * paymentRail:"simulated". Only the settlement_prepare/authorize cases
   * touch this; its async calls make dispatch return a Promise there.
   */
  settlementRail?: SettlementRail;
}): BusinessOps {
  const now = options.now ?? Date.now;
  const sim = options.sim;
  const signingOpen = options.signingOpen ?? (() => true);
  const principals = options.principals ?? new Map<string, string>();
  // In-memory fallback ledger (no state dir): keeps the mandate's expiry so
  // entries past expiresAt can be pruned — same rule as the durable ledger,
  // without the grace window (which is a persistence-safety margin).
  const localMandates = new Map<string, number>();
  const claimMandate = options.claimMandate ?? ((principalAddress: string, mandateId: string, _runId: string, expiresAtMs: number): "ok" | "used" => {
    const key = `${principalAddress.toLowerCase()}:${mandateId}`;
    for (const [k, exp] of localMandates) {
      if (now() > exp) localMandates.delete(k);
    }
    if (localMandates.has(key)) return "used";
    localMandates.set(key, expiresAtMs);
    return "ok";
  });
  const serverPublicKeys = { [options.signer.keyId]: publicKeyOf(options.signer.privateKey) };
  const listings = new Map<string, Listing>();
  /**
   * Listing ids superseded by a newer publish from the same provider keyId
   * (live run p6-l-2026-10-01-8), kept until their original expiry so a late
   * invitation is refused LISTING_UNAVAILABLE ("re-search") rather than
   * NOT_FOUND. Bounded: superseded ids never count toward the listing caps.
   */
  const superseded = new Map<string, number>();
  const inbox = new Map<string, InboxMessage[]>();
  /** Deliveries per sender per rolling minute (rendezvous abuse cap). */
  const deliveries = new Map<string, number[]>();

  function publicKeyOf(privateKey: ContractSigner["privateKey"]): KeyObject | string | Buffer {
    try {
      return createPublicKey(privateKey as KeyObject);
    } catch {
      return privateKey;
    }
  }

  /** Read-only tools stay observable after a terminal state (LLD §3). */
  const READ_ONLY_TOOLS = new Set([
    "catalog_quote", "booking_lookup", "agreement_get", "settlement_status",
  ]);
  /**
   * N4b-4: the cancel pair stays reachable after terminalState — a booked
   * order may still be cancelled after a claimed mismatch ends the run
   * (verification_failed), and a replayed submit must land on the recorded
   * cancellation for a deterministic result.
   * N4b-10 (D13): settlement_authorize joins the set — a settled run is
   * terminal, but a replayed authorize must reach the recorded outcome
   * (idempotent replay), and a non-replay call still refuses
   * STATE_REFUSED on the digest check. Settled runs can still never be
   * cancelled.
   */
  const TERMINAL_REPLAY_TOOLS = new Set([
    "booking_cancel_prepare", "booking_cancel_submit", "settlement_authorize",
  ]);

  /**
   * L4 (adversarial review): settlement_authorize resolves rail I/O
   * asynchronously — two in-flight authorizes on the same run could both
   * pass verification and race to overwrite settlementRequest (the replay
   * anchor). Serialize per runId: an authorize runs strictly after the
   * previous one settles; the loser then hits the recorded-settlement
   * replay/refusal check instead of mutating. The map entry self-cleans
   * once the chain drains.
   */
  const authorizeLocks = new Map<string, Promise<void>>();
  const serialized = <T>(runId: string, fn: () => T | Promise<T>): Promise<T> => {
    const prev = authorizeLocks.get(runId) ?? Promise.resolve();
    const next = prev.then(fn);
    const tail: Promise<void> = next.then(() => undefined, () => undefined);
    authorizeLocks.set(runId, tail);
    void tail.then(() => {
      if (authorizeLocks.get(runId) === tail) authorizeLocks.delete(runId);
    });
    return next;
  };

  /** Both seats must be occupied before any business step runs. */
  function requireRun(run: ContractRun | undefined, tool: string): BusinessOutcome | null {
    if (run === undefined || run.bound.buyer === undefined || run.bound.provider === undefined) {
      return refuse("STATE_REFUSED");
    }
    if (
      run.terminalState !== null &&
      !READ_ONLY_TOOLS.has(tool) &&
      !TERMINAL_REPLAY_TOOLS.has(tool)
    ) {
      return refuse("ALREADY_TERMINAL");
    }
    return null;
  }

  /**
   * The envelope half of submit-side verification: server-signed envelope
   * pinned to this run/tool/role with a fresh nonce. The caller adds its
   * authorization check — a role signature for an authorized submit, or
   * (D11, N4b-9) a bound deny verdict for a deny submission, which never
   * carries a role signature.
   */
  function verifySubmitEnvelope(
    run: ContractRun,
    role: ContractRole,
    tool: string,
    envelope: unknown,
  ): { ok: true; envelope: PrepareEnvelope } | { ok: false; code: ContractRefusalCode } {
    const verdict = verifyEnvelope(envelope, serverPublicKeys, {
      nowMs: now(),
      nonceSeen: (runId, nonce) => run.runId === runId && run.claimedNonces.has(nonce),
    });
    if (!verdict.ok) return { ok: false, code: verdict.code as ContractRefusalCode };
    const env = verdict.envelope;
    if (env.runId !== run.runId || env.tool !== tool || env.role !== role) {
      return { ok: false, code: "ENVELOPE_INVALID" };
    }
    return { ok: true, envelope: env };
  }

  /**
   * The submit-side verification shared by every signed step: server-signed
   * envelope → pinned to this run/tool/role → fresh nonce claimed → EIP-191
   * role signature recovers to the bound signer key.
   */
  function verifySubmission(
    run: ContractRun,
    role: ContractRole,
    tool: string,
    envelope: unknown,
    signatureHex: string,
  ): { ok: true; envelope: PrepareEnvelope } | { ok: false; code: ContractRefusalCode } {
    const checked = verifySubmitEnvelope(run, role, tool, envelope);
    if (!checked.ok) return checked;
    const env = checked.envelope;
    const signerKey = run.bound[role]?.signerKey;
    if (
      signerKey === undefined ||
      !verifyRoleSignature({
        runId: run.runId,
        role,
        tool: env.tool,
        nonce: env.nonce,
        payloadDigest: env.payloadDigest,
        signatureHex,
        expectedPublicKeyHex: signerKey.publicKeyHex,
      })
    ) {
      return { ok: false, code: "SIGNATURE_INVALID" };
    }
    run.claimedNonces.add(env.nonce);
    return { ok: true, envelope: env };
  }

  /**
   * N6g-2 (observer R12): locate the receipted `*_prepare` response that
   * carried THIS envelope — each candidate receipt's responseDigest is
   * recomputed over `{envelope, serverNonce}` under the receipt's own
   * scheme (the envelope schema is strict, so the parsed envelope digests
   * to the same bytes the response carried). Returns that receipt's
   * responseDigest — the digest the approval record is bound to in feed
   * evidence — or undefined when no matching receipt exists.
   */
  function prepareReceiptDigestFor(
    run: ContractRun,
    role: ContractRole,
    prepareTool: "booking_prepare" | "booking_cancel_prepare" | "settlement_prepare",
    envelope: PrepareEnvelope,
  ): string | undefined {
    const tool = prepareTool;
    for (const r of run.receipts) {
      if (r.tool !== tool || r.outcome !== "ok" || r.principal.role !== role) {
        continue;
      }
      const body = { envelope, serverNonce: r.serverNonce };
      const digest =
        r.responseDigestScheme === "hmac-sha256"
          ? saltedCanonicalDigest(run.runSalt, body)
          : canonicalDigest(body);
      if (digest === r.responseDigest) return r.responseDigest;
    }
    return undefined;
  }

  /**
   * N6g-2: retain a cryptographically VERIFIED approval record for the
   * observer feed — allow and deny decisions alike (a signed deny is a
   * policy verdict). The record is stored verbatim; `boundDigest` carries
   * the receipt linkage R12 cites.
   */
  function recordApproval(
    run: ContractRun,
    role: ContractRole,
    prepareTool: "booking_prepare" | "booking_cancel_prepare" | "settlement_prepare",
    envelope: PrepareEnvelope,
    approval: ApprovalRecord,
  ): void {
    (run.approvalRecords ??= []).push({
      record: structuredClone(approval),
      boundDigest: prepareReceiptDigestFor(run, role, prepareTool, envelope),
    });
  }

  /**
   * The principal-signed mandate (rev 6.5): strict schema, live expiry, and
   * an EIP-191 signature over `canonicalDigest({domain, ...mandate})` that
   * recovers to the buyer's pinned family-principal address. Every failure
   * is the same generic MANDATE_INVALID.
   */
  function verifyMandate(principal: ContractPrincipal, mandate: unknown, mandateSignature: unknown): Mandate | ContractRefusalCode {
    const parsed = mandateSchema.safeParse(mandate);
    if (!parsed.success) return "MANDATE_INVALID";
    if (Date.parse(parsed.data.expiresAt) <= now()) return "MANDATE_INVALID";
    const pinned = principals.get(principal.keyId);
    if (pinned === undefined || typeof mandateSignature !== "string") return "MANDATE_INVALID";
    const digest = canonicalDigest({ domain: MANDATE_DOMAIN, ...parsed.data });
    const recovered = eip191RecoverPublicKey(Buffer.from(digest.slice(2), "hex"), mandateSignature);
    if (recovered === null) return "MANDATE_INVALID";
    if (publicKeyToAddress(recovered).toLowerCase() !== pinned.toLowerCase()) return "MANDATE_INVALID";
    return parsed.data;
  }

  /**
   * Buyer mandate checks — one identical MANDATE_REFUSED whatever the cap
   * (cap values must never ride the refusal, refusals.ts comment).
   */
  function capCheck(run: ContractRun, totalMinor: number, currency: string, itineraryId: string): BusinessOutcome | null {
    const m = run.mandate;
    if (m === undefined) return refuse("STATE_REFUSED");
    if (Date.parse(m.expiresAt) <= now()) return refuse("MANDATE_REFUSED");
    if (totalMinor > m.capMinor) return refuse("MANDATE_REFUSED");
    if (currency !== m.currency) return refuse("MANDATE_REFUSED");
    if (!m.allowedItineraryIds.includes(itineraryId)) return refuse("MANDATE_REFUSED");
    return null;
  }

  function prepare(run: ContractRun, role: ContractRole, tool: string, payload: Record<string, unknown>): PrepareEnvelope {
    return signEnvelope(
      { payload, runId: run.runId, tool, role, nowMs: now() },
      options.signer,
    );
  }

  /** The offer terms the v2 accept/booking/settlement payloads flatten. */
  function flatTerms(offer: OfferRecord): Record<string, unknown> {
    return {
      itineraryId: offer.payload.itineraryId,
      currency: offer.payload.currency,
      fareMinor: offer.payload.fareMinor,
      feeMinor: offer.payload.feeMinor,
      totalMinor: offer.payload.totalMinor,
    };
  }

  /** v2 accept payload: the full offer verbatim plus the flat terms. */
  function acceptPayload(offer: OfferRecord): Record<string, unknown> {
    return {
      kind: "accept",
      offer: offer.payload,
      offerId: offer.offerId,
      offerDigest: canonicalDigest(offer.payload),
      ...flatTerms(offer),
    };
  }

  /**
   * `agreementDigest = canonicalDigest({domain:"agent-contract.agreement/v1",
   * runId, offerDigest})` — the exact v2 tuple the signers reproduce (the
   * signer records it from the accept it signs; the server checks it twice).
   */
  function agreementDigest(runId: string, offerDigest: string): string {
    return canonicalDigest({ domain: AGREEMENT_DOMAIN, runId, offerDigest });
  }

  /**
   * Booking payload — server-derived from the agreement (and, for a v2.2
   * mandate, the principal-signed partySize → `travellers`). A fabricated
   * or legacy run without partySize emits the byte-identical v2 payload —
   * the frozen v2 vectors stay exact.
   */
  function bookingPayload(run: ContractRun): Record<string, unknown> {
    const agreement = run.agreement!;
    return {
      kind: "booking",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      itineraryId: agreement.itineraryId,
      currency: agreement.currency,
      totalMinor: agreement.totalMinor,
      ...(run.mandate?.partySize !== undefined ? { travellers: run.mandate.partySize } : {}),
    };
  }

  /**
   * Settlement payload — server-derived from agreement + verification.
   * v2.3 (D13) adds `paymentRail`: "simulated" on the default rail;
   * "stripe_test_mode" plus the rail-created `paymentIntentId` on the
   * Stripe rail. `simulated: true` stays on both — on the Stripe rail it
   * means NO commercial transfer (D13 clarification).
   */
  function settlementPayload(run: ContractRun): Record<string, unknown> | null {
    const agreement = run.agreement;
    const verification = run.verification;
    if (agreement === undefined || verification === undefined) return null;
    return {
      kind: "settlement",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      verificationDigest: verification.verificationDigest,
      itineraryId: agreement.itineraryId,
      currency: agreement.currency,
      amountMinor: agreement.totalMinor,
      simulated: true,
      paymentRail: options.settlementRail === undefined ? "simulated" : options.settlementRail.railId,
      ...(run.settlementIntent !== undefined
        ? { paymentIntentId: run.settlementIntent.paymentIntentId }
        : {}),
    };
  }

  /**
   * v2 cancel payload (N4b-4) — server-derived from the live booking; the
   * agent supplies only the free-text reason, which the signed envelope
   * then binds.
   */
  function cancelPayload(run: ContractRun, reason: string): Record<string, unknown> {
    const agreement = run.agreement!;
    const booking = run.booking!;
    return {
      kind: "cancel",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      bookingRef: booking.pnr,
      reason,
    };
  }

  /**
   * The cancel reason must match the run's actual state (rev 6.7):
   * `mutual_withdrawal` only before any verification, `verification_mismatch`
   * only with a recorded claimed mismatch, `verification_failed` only once
   * the run has ended that way. Checked at BOTH prepare and submit — a
   * prepared envelope may go stale if verification lands in between.
   */
  function cancelReasonAllowed(run: ContractRun, reason: unknown): boolean {
    switch (reason) {
      case "mutual_withdrawal":
        return run.verification === undefined;
      case "verification_mismatch":
        return run.verification?.result === "mismatch";
      case "verification_failed":
        return run.terminalState === "verification_failed";
      default:
        return false;
    }
  }

  function samePayload(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
    return canonicalDigest(a) === canonicalDigest(b);
  }

  // -- rendezvous state maintenance -----------------------------------------

  function purgeListings(): void {
    const t = now();
    for (const [id, l] of listings) if (t >= l.expiresAtMs) listings.delete(id);
    for (const [id, exp] of superseded) if (t >= exp) superseded.delete(id);
    for (const [k, ts] of deliveries) {
      const fresh = ts.filter((x) => t - x < 60_000);
      if (fresh.length === 0) deliveries.delete(k); else deliveries.set(k, fresh);
    }
  }

  function removeFromInbox(providerKeyId: string, messageId: string): void {
    const list = inbox.get(providerKeyId);
    if (list === undefined) return;
    const i = list.findIndex((m) => m.messageId === messageId);
    if (i >= 0) list.splice(i, 1);
  }

  /** Is `listingId` a live (unconsumed) listing owned by this provider? */
  function consumableListing(providerKeyId: string, listingId: string): boolean {
    const listing = listings.get(listingId);
    return listing !== undefined && listing.providerKeyId === providerKeyId && !listing.consumed;
  }

  /**
   * The provider acted on a delivery — THAT listing is consumed (closed to
   * new deliveries) and its pending deliveries are cleared from the inbox
   * (N4B2B-CHANGES-2 §1 + N4b-3 LOW: consumption happens only on a provider
   * action, and only on the listing the delivery came through).
   */
  function consumeListing(providerKeyId: string, listingId: string): boolean {
    const listing = listings.get(listingId);
    if (listing === undefined || listing.providerKeyId !== providerKeyId) return false;
    if (listing.consumed) return true; // already consumed — idempotent
    listing.consumed = true;
    for (const message of listing.pending.values()) {
      removeFromInbox(providerKeyId, message.messageId);
    }
    listing.pending.clear();
    return true;
  }

  /** A listing matches a filter only if its terms don't contradict it. */
  function listingMatches(l: Listing, args: Record<string, unknown>): boolean {
    const terms = l.terms ?? {};
    const eq = (key: string, want: unknown) => {
      if (want === undefined) return true;
      const have = terms[key];
      if (have === undefined) return true; // undeclared term can't contradict
      if (Array.isArray(have)) return have.includes(want);
      return have === want;
    };
    return eq("origin", args.origin) && eq("destination", args.destination)
      && eq("departDate", args.departDate) && eq("departDates", args.departDate)
      && eq("returnDate", args.returnDate) && eq("returnDates", args.returnDate);
  }

  function dispatch(
    principal: ContractPrincipal,
    run: ContractRun | undefined,
    tool: string,
    args: Record<string, unknown>,
    serverNonce: string,
  ): BusinessOutcome | Promise<BusinessOutcome> {
    // N4b-4: a signer past its published validUntil signs nothing — no
    // envelope, no receipt — so no business call can dispatch at all.
    if (!signingOpen()) return refuse("CONTRACT_UNAVAILABLE");
    switch (tool) {
      // -- rendezvous / discovery (pre-run) -----------------------------------
      case "rendezvous_publish_listing": {
        purgeListings();
        const listingId = `lst-${canonicalDigest({
          kind: "listing", providerKeyId: principal.keyId,
          title: args.title, sealedBoxPublicKeyHex: args.sealedBoxPublicKeyHex,
        }).slice(2, 14)}`;
        const existing = listings.get(listingId);
        if (existing !== undefined && existing.providerKeyId !== principal.keyId) {
          // Only the listing's owner may republish/reset it.
          return refuse("LISTING_UNAVAILABLE");
        }
        if (existing === undefined) {
          // Live run p6-l-2026-10-01-8: a NEW listing from this provider keyId
          // SUPERSEDES every listing it published before. Each run's signer
          // holds a fresh seal key (→ a new listing id), so an older listing
          // is sealed to a key the provider no longer holds: search must not
          // offer it, and invitations sealed to it can never be opened. They
          // are dropped from the inbox (not kept "deliverable" — nobody can
          // open them) and any later send/bind on that id is refused
          // LISTING_UNAVAILABLE, telling the buyer to search again.
          for (const [id, l] of listings) {
            if (l.providerKeyId !== principal.keyId) continue;
            for (const message of l.pending.values()) {
              removeFromInbox(principal.keyId, message.messageId);
            }
            listings.delete(id);
            superseded.set(id, l.expiresAtMs);
          }
          while (superseded.size > MAX_SUPERSEDED) {
            const oldest = superseded.keys().next().value as string;
            superseded.delete(oldest);
          }
          // Global safety cap (the provider now holds zero live listings).
          if (listings.size >= MAX_LISTINGS) {
            return refuse("RATE_LIMITED");
          }
        }
        const t = now();
        listings.set(listingId, {
          listingId,
          providerKeyId: principal.keyId,
          title: args.title as string,
          summary: args.summary as string,
          sealedBoxPublicKeyHex: args.sealedBoxPublicKeyHex as string,
          // Republishing without terms keeps the existing ones — a refresh is
          // not a wipe.
          ...(args.terms !== undefined || existing?.terms !== undefined
            ? { terms: (args.terms ?? existing?.terms) as Record<string, unknown> }
            : {}),
          publishedAtMs: existing?.publishedAtMs ?? t,
          expiresAtMs: t + LISTING_TTL_MS,
          // Republishing never clears pendings and never resurrects a
          // consumed listing.
          consumed: existing?.consumed ?? false,
          pending: existing?.pending ?? new Map(),
        });
        return ok({ listingId, publishedAt: iso(existing?.publishedAtMs ?? t), serverNonce });
      }

      case "rendezvous_search": {
        purgeListings();
        const out = [...listings.values()]
          .filter((l) => listingMatches(l, args))
          .map((l) => ({
            listingId: l.listingId,
            title: l.title,
            summary: l.summary,
            sealedBoxPublicKeyHex: l.sealedBoxPublicKeyHex,
            publishedAt: iso(l.publishedAtMs),
          }));
        return ok({ listings: out, serverNonce });
      }

      case "rendezvous_send_invitation": {
        purgeListings();
        // D8 (N4b-7): the rendezvous PRECEDES the handshake — an unbound `*`
        // buyer must be able to deliver. The delivery is stamped
        // senderAgentId: null / senderProof: "unproven-pre-bind" so the
        // provider knows this sender is authenticated only by the later
        // handshake + bind. A bound `*` stamps the certificate-resolved
        // agentId; a static token keeps its pin.
        const boundAgentId = run?.bound[principal.role]?.agentId;
        const senderAgentId: string | null = principal.agentId === "*"
          ? (boundAgentId ?? null)
          : principal.agentId;
        const senderProof: SenderProof = principal.agentId === "*"
          ? (boundAgentId !== undefined ? "certificate-bound" : "unproven-pre-bind")
          : "token-pinned";
        // A delivery that doesn't parse as a real seal is refused WITHOUT
        // burning the listing. v:4 is the listing-bound wire; v:2 (legacy,
        // unbound) is accepted only where CONTRACT_LEVEL=L still allows it.
        const seal = sealedBoxSchema.safeParse(args.sealedInvitation);
        if (!seal.success) return refuse("PAYLOAD_INVALID");
        if (seal.data.v === 2 && options.allowLegacySealV2 !== true) {
          return refuse("PAYLOAD_INVALID");
        }
        // Per-sender delivery rate limit.
        const t = now();
        const sent = (deliveries.get(principal.keyId) ?? []).filter((x) => t - x < 60_000);
        if (sent.length >= MAX_DELIVERIES_PER_MINUTE) return refuse("RATE_LIMITED");
        const listing = listings.get(args.listingId as string);
        if (listing === undefined) {
          return refuse(superseded.has(args.listingId as string) ? "LISTING_UNAVAILABLE" : "NOT_FOUND");
        }
        if (listing.consumed) return refuse("LISTING_UNAVAILABLE");
        // One pending delivery per sender: a resend REPLACES the sender's old
        // one (and its inbox entry) rather than stacking.
        const replaced = listing.pending.get(principal.keyId);
        if (replaced !== undefined) {
          removeFromInbox(listing.providerKeyId, replaced.messageId);
          listing.pending.delete(principal.keyId);
        }
        if (listing.pending.size >= MAX_PENDING_PER_LISTING) {
          return refuse("LISTING_UNAVAILABLE");
        }
        sent.push(t);
        deliveries.set(principal.keyId, sent);
        const receivedAt = iso(t);
        const message: InboxMessage = {
          messageId: `msg-${canonicalDigest({ kind: "inbox", listingId: listing.listingId, receivedAt, seal: canonicalDigest(seal.data) }).slice(2, 14)}`,
          kind: "handshake_invitation",
          senderKeyId: principal.keyId,
          senderAgentId,
          senderProof,
          listingId: listing.listingId,
          sealedPayload: seal.data,
          receivedAt,
        };
        listing.pending.set(principal.keyId, message);
        const list = inbox.get(listing.providerKeyId) ?? [];
        list.push(message);
        if (list.length > MAX_INBOX_MESSAGES) list.splice(0, list.length - MAX_INBOX_MESSAGES);
        inbox.set(listing.providerKeyId, list);
        return {
          ok: true,
          result: { delivered: true, deliveredAt: receivedAt, senderAgentId, senderProof, serverNonce },
          // D8: the delivery's receipt discloses the same sender proof.
          receiptFields: { senderProof },
        };
      }

      case "rendezvous_inbox": {
        const sinceMs = args.since !== undefined ? Date.parse(args.since as string) : undefined;
        const messages = (inbox.get(principal.keyId) ?? []).filter(
          (m) => sinceMs === undefined || Date.parse(m.receivedAt) > sinceMs,
        );
        return ok({ messages: structuredClone(messages), serverNonce });
      }

      default:
        break;
    }

    // Half-bound run release: the one party that DID bind may withdraw its
    // own run while the counterparty never bound — otherwise its token stays
    // seated until the bind deadline. `run` is the caller's own run
    // (principalRuns), and the seat must be this principal's: no one can
    // release another principal's seat.
    if (
      tool === "contract_withdraw" && run !== undefined && run.terminalState === null &&
      (run.bound.buyer === undefined || run.bound.provider === undefined) &&
      run.bound[principal.role]?.principalKeyId === principal.keyId
    ) {
      options.endRun(run, "no_agreement", principal);
      return ok({ state: "withdrawn", serverNonce });
    }

    // -- everything below needs a fully-bound live run -------------------------
    const gate = requireRun(run, tool);
    if (gate !== null) return gate;
    const liveRun = run!;

    // The agreement is WRITE-ONCE: once formed, every offer/accept path is
    // closed — a stale accept can never rewrite the booked agreement.
    if (liveRun.agreement !== undefined && tool.startsWith("offer_")) {
      return refuse("STATE_REFUSED");
    }

    switch (tool) {
      case "catalog_quote": {
        const quote = liveRun.simRun!.quote(args);
        return ok({ itineraries: quote.itineraries, simulated: true, serverNonce });
      }

      case "mandate_prepare": {
        // The mandate is presented, not created — verify the principal
        // signature eagerly so a bad mandate never even gets an envelope.
        const mandate = verifyMandate(principal, args.mandate, args.mandateSignature);
        if (typeof mandate === "string") return refuse(mandate);
        const mandateDigest = canonicalDigest({ domain: MANDATE_DOMAIN, ...mandate });
        // CONTRACT-PAYLOADS-v2 §Mandate: the signed payload IS the flat
        // mandate — the role signature (and the signer's policy check
        // `canonicalDigest(payload) === policy mandate`) covers exactly the
        // bytes the family principal signed. The principal signature rides
        // run state pinned to this envelope's nonce, never inside the
        // payload itself.
        const envelope = prepare(liveRun, "buyer", "mandate_prepare", { ...mandate });
        liveRun.mandatePrepared = {
          nonce: envelope.nonce,
          mandateSignature: args.mandateSignature as string,
        };
        return ok({ envelope, mandateDigest, serverNonce });
      }

      case "mandate_submit": {
        // Envelope verification first so a REPLAYED nonce reports NONCE_REUSED
        // precisely; a fresh-envelope resubmission then hits the write-once
        // guard as STATE_REFUSED.
        const submitted = verifySubmission(liveRun, "buyer", "mandate_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (liveRun.mandate !== undefined) return refuse("STATE_REFUSED"); // write-once
        // The payload is the flat mandate; the principal signature verified
        // at prepare rides run state, pinned to this exact envelope's nonce.
        const prepared = liveRun.mandatePrepared;
        const payload = submitted.envelope.payload;
        const mandate =
          prepared !== undefined && prepared.nonce === submitted.envelope.nonce
            ? verifyMandate(principal, payload, prepared.mandateSignature)
            : "MANDATE_INVALID";
        if (payload.kind !== "mandate" || typeof mandate === "string") {
          return refuse("MANDATE_INVALID");
        }
        delete liveRun.mandatePrepared;
        const mandateDigest = canonicalDigest({ domain: MANDATE_DOMAIN, ...mandate });
        // Single-use per family principal (N4B2B-CHANGES-2 §3): the ledger
        // claim persists BEFORE the run's mandate record commits. A reused
        // id reports the same generic MANDATE_INVALID — no policy leak.
        const claim = claimMandate(
          principals.get(principal.keyId)!, mandate.mandateId, liveRun.runId,
          Date.parse(mandate.expiresAt),
        );
        if (claim === "used") return refuse("MANDATE_INVALID");
        if (claim === "unavailable") return refuse("CONTRACT_UNAVAILABLE");
        liveRun.mandate = {
          digest: mandateDigest,
          mandateId: mandate.mandateId,
          capMinor: mandate.capMinor,
          currency: mandate.currency,
          allowedItineraryIds: [...mandate.allowedItineraryIds],
          partySize: mandate.partySize,
          expiresAt: mandate.expiresAt,
          principalAddress: principals.get(principal.keyId)!,
          submittedAt: iso(now()),
        };
        if (liveRun.stage === "bound" || liveRun.stage === "handshake") liveRun.stage = "mandated";
        return ok({ bound: true, mandateDigest, serverNonce });
      }

      case "offer_prepare": {
        // A mandate must be in force before ANY buyer offer or accept.
        if (principal.role === "buyer" && liveRun.mandate === undefined) {
          return refuse("STATE_REFUSED");
        }
        const itineraryId = args.itineraryId as string;
        const itinerary = liveRun.simRun!.itinerary(itineraryId);
        if (itinerary === undefined) return refuse("NOT_FOUND");
        const feeMinor = args.feeMinor as number;
        const fareMinor = itinerary.fareMinor;
        const totalMinor = fareMinor + feeMinor;
        if (principal.role === "buyer") {
          const cap = capCheck(liveRun, totalMinor, itinerary.currency, itineraryId);
          if (cap !== null) return cap;
        }
        const counterparty = latestCounterpartyOffer(liveRun, principal.role);
        const offerId = `off-${pad4(liveRun.offerSeq + 1)}`;
        const payload: Record<string, unknown> = {
          kind: counterparty === undefined ? "offer" : "counter",
          offerId,
          itineraryId,
          currency: itinerary.currency,
          fareMinor,
          feeMinor,
          totalMinor,
          ...(counterparty !== undefined ? { inReplyTo: counterparty.offerId } : {}),
          ...(args.note !== undefined ? { note: args.note } : {}),
        };
        const envelope = prepare(liveRun, principal.role, "offer_prepare", payload);
        return ok({
          envelope,
          quote: { fareMinor, feeMinor, totalMinor, currency: itinerary.currency },
          serverNonce,
        });
      }

      case "offer_submit": {
        if (principal.role === "buyer" && liveRun.mandate === undefined) {
          return refuse("STATE_REFUSED");
        }
        const submitted = verifySubmission(liveRun, principal.role, "offer_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        const itinerary = liveRun.simRun!.itinerary(payload.itineraryId as string);
        const expectedOfferId = `off-${pad4(liveRun.offerSeq + 1)}`;
        if (
          itinerary === undefined ||
          payload.offerId !== expectedOfferId ||
          payload.fareMinor !== itinerary.fareMinor ||
          payload.currency !== itinerary.currency ||
          payload.totalMinor !== itinerary.fareMinor + (payload.feeMinor as number) ||
          (payload.kind === "counter" &&
            latestCounterpartyOffer(liveRun, principal.role)?.offerId !== payload.inReplyTo) ||
          (payload.kind !== "offer" && payload.kind !== "counter")
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        if (principal.role === "buyer") {
          const cap = capCheck(liveRun, payload.totalMinor as number, itinerary.currency, itinerary.itineraryId);
          if (cap !== null) return cap;
        }
        const offer: OfferRecord = {
          offerId: payload.offerId as string,
          payload,
          role: principal.role,
          principalKeyId: principal.keyId,
          state: "live",
          seq: liveRun.offerSeq + 1,
          submittedAt: iso(now()),
        };
        // A new offer supersedes all earlier live offers FROM THE SAME PARTY.
        for (const prior of liveRun.offers.values()) {
          if (prior.state === "live" && prior.role === principal.role) prior.state = "superseded";
        }
        liveRun.offers.set(offer.offerId, offer);
        liveRun.offerSeq += 1;
        if (liveRun.stage === "mandated" || liveRun.stage === "bound" || liveRun.stage === "handshake") {
          liveRun.stage = "negotiating";
        }
        return ok({ offerId: offer.offerId, state: "offered", serverNonce });
      }

      case "offer_accept_prepare": {
        const offer = liveRun.offers.get(args.offerId as string);
        if (offer === undefined) return refuse("NOT_FOUND");
        if (offer.state !== "live" || offer.role === principal.role) return refuse("STATE_REFUSED");
        // Only the counterparty's LATEST live offer can be accepted.
        if (latestCounterpartyOffer(liveRun, principal.role)?.offerId !== offer.offerId) {
          return refuse("STATE_REFUSED");
        }
        if (principal.role === "buyer") {
          if (liveRun.mandate === undefined) return refuse("STATE_REFUSED");
          const cap = capCheck(
            liveRun, offer.payload.totalMinor as number,
            offer.payload.currency as string, offer.payload.itineraryId as string,
          );
          if (cap !== null) return cap;
        }
        const envelope = prepare(liveRun, principal.role, "offer_accept_prepare", acceptPayload(offer));
        return ok({ envelope, serverNonce });
      }

      case "offer_accept_submit": {
        const submitted = verifySubmission(liveRun, principal.role, "offer_accept_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        const offer = liveRun.offers.get(payload.offerId as string);
        if (offer === undefined) return refuse("NOT_FOUND");
        if (offer.state !== "live" || offer.role === principal.role) return refuse("STATE_REFUSED");
        if (latestCounterpartyOffer(liveRun, principal.role)?.offerId !== offer.offerId) {
          return refuse("STATE_REFUSED");
        }
        if (
          payload.kind !== "accept" ||
          payload.offerDigest !== canonicalDigest(offer.payload) ||
          !samePayload(payload.offer as Record<string, unknown>, offer.payload) ||
          !samePayload(
            {
              itineraryId: payload.itineraryId, currency: payload.currency,
              fareMinor: payload.fareMinor, feeMinor: payload.feeMinor,
              totalMinor: payload.totalMinor,
            },
            flatTerms(offer),
          )
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        if (principal.role === "buyer") {
          if (liveRun.mandate === undefined) return refuse("STATE_REFUSED");
          const cap = capCheck(
            liveRun, offer.payload.totalMinor as number,
            offer.payload.currency as string, offer.payload.itineraryId as string,
          );
          if (cap !== null) return cap;
        }
        offer.state = "accepted";
        const agreementId = `agr-${pad4(liveRun.offerSeq)}`;
        const digest = agreementDigest(liveRun.runId, canonicalDigest(offer.payload));
        liveRun.agreement = {
          agreementId,
          offerId: offer.offerId,
          offerDigest: canonicalDigest(offer.payload),
          agreementDigest: digest,
          offerPayload: offer.payload,
          acceptPayload: payload,
          itineraryId: offer.payload.itineraryId as string,
          currency: offer.payload.currency as string,
          fareMinor: offer.payload.fareMinor as number,
          feeMinor: offer.payload.feeMinor as number,
          totalMinor: offer.payload.totalMinor as number,
          formedAt: iso(now()),
        };
        liveRun.stage = "agreed";
        // N4b-8 (gap 4): anchor the agreement digest — async, outcome
        // receipted; a failure lands on run.anchors, never silently.
        try { options.anchorRun?.(liveRun, "agreement"); } catch { /* anchor dispatch must not break formation */ }
        return ok({ agreementFormed: true, agreementId, serverNonce });
      }

      case "offer_reject": {
        const offer = liveRun.offers.get(args.offerId as string);
        if (offer === undefined) return refuse("NOT_FOUND");
        if (offer.state !== "live" || offer.role === principal.role) return refuse("STATE_REFUSED");
        offer.state = "rejected";
        return ok({ state: "rejected", serverNonce });
      }

      case "contract_withdraw": {
        // After the booking is on the sim ledger there is no withdrawal —
        // the run ends only through the explicit terminal path.
        if (liveRun.booking !== undefined) return refuse("STATE_REFUSED");
        options.endRun(liveRun, "no_agreement", principal);
        return ok({ state: "withdrawn", serverNonce });
      }

      case "agreement_get": {
        const agreement = liveRun.agreement;
        const a = liveRun.anchors?.agreement;
        return ok({
          agreement: agreement === undefined ? null : structuredClone(agreement),
          anchor: agreement === undefined ? null : {
            runId: liveRun.runId,
            agreementDigest: agreement.agreementDigest,
            formedAt: agreement.formedAt,
            // N4b-8 (gap 4): the tsa anchor record for this agreement digest
            // (anchorId = tsa:<commitmentId>); a failure is carried openly.
            status: a?.status ?? (options.anchorRun === undefined ? "disabled" : "unanchored"),
            anchorId: a?.anchorId ?? null,
            eventHash: a?.eventHash ?? null,
            ledger: a?.ledger ?? null,
            error: a?.error ?? null,
          },
          serverNonce,
        });
      }

      case "booking_prepare": {
        const agreement = liveRun.agreement;
        if (agreement === undefined || agreement.agreementId !== args.agreementId) {
          return refuse("NOT_FOUND");
        }
        if (liveRun.booking !== undefined) return refuse("STATE_REFUSED");
        const envelope = prepare(liveRun, "provider", "booking_prepare", bookingPayload(liveRun));
        return ok({ envelope, serverNonce });
      }

      case "booking_execute": {
        const agreement = liveRun.agreement;
        if (agreement === undefined) return refuse("STATE_REFUSED");
        if (liveRun.booking !== undefined) {
          // N4b-8 (gap 6): idempotent replay — the SAME call (same envelope,
          // signature and approval, digested as one request) returns the
          // recorded result verbatim, like booking_cancel_submit: never a
          // nonce error, never a second booking. A different approval or
          // args is refused.
          const replayDigest = canonicalDigest({
            envelope: args.envelope,
            signatureHex: args.signatureHex,
            approval: args.approval,
          });
          if (replayDigest !== liveRun.booking.requestDigest) return refuse("STATE_REFUSED");
          return ok({
            orderRef: liveRun.booking.orderRef,
            pnr: liveRun.booking.pnr,
            tickets: liveRun.booking.tickets,
            simulated: true,
            serverNonce,
          });
        }
        if (args.signatureHex === undefined) {
          // N4b-9 (F15 → D11): deny submission — the server's prepare
          // envelope plus a signed `deny` approval, and NO role signature.
          // A refusing signer can never produce a role signature for the
          // denied action, yet blocked_by_policy must remain reachable.
          // This path authenticates the envelope and the deny verdict only;
          // it can never execute the booking.
          const envCheck = verifySubmitEnvelope(liveRun, "provider", "booking_prepare", args.envelope);
          if (!envCheck.ok) return envCheck;
          if (!samePayload(envCheck.envelope.payload, bookingPayload(liveRun))) {
            return refuse("ENVELOPE_INVALID");
          }
          const denyDecision = checkApprovalRecord({
            approval: args.approval as ApprovalRecord,
            runId: liveRun.runId,
            role: "provider",
            tool: "booking_execute",
            action: "booking",
            nonce: envCheck.envelope.nonce,
            envelopeDigest: canonicalDigest(envCheck.envelope),
            expiresAt: envCheck.envelope.expiresAt,
            approvalKey: liveRun.bound.provider!.approvalKey,
            expectedPolicyDigest: options.policyDigests.provider,
            nowMs: now(),
          });
          if (denyDecision === null) return refuse("APPROVAL_INVALID");
          // An `allow` without the role signature is no authorization —
          // it can neither execute nor end the run as a policy verdict.
          if (denyDecision !== "deny") return refuse("SIGNATURE_INVALID");
          liveRun.claimedNonces.add(envCheck.envelope.nonce);
          recordApproval(liveRun, "provider", "booking_prepare", envCheck.envelope, args.approval as ApprovalRecord);
          options.endRun(liveRun, "blocked_by_policy", principal);
          return refuse("POLICY_DENIED");
        }
        const submitted = verifySubmission(liveRun, "provider", "booking_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (!samePayload(submitted.envelope.payload, bookingPayload(liveRun))) {
          return refuse("ENVELOPE_INVALID");
        }
        const approvalKey = liveRun.bound.provider!.approvalKey;
        const decision = checkApprovalRecord({
          approval: args.approval as ApprovalRecord,
          runId: liveRun.runId,
          role: "provider",
          tool: "booking_execute",
          action: "booking",
          nonce: submitted.envelope.nonce,
          envelopeDigest: canonicalDigest(submitted.envelope),
          expiresAt: submitted.envelope.expiresAt,
          approvalKey,
          expectedPolicyDigest: options.policyDigests.provider,
          nowMs: now(),
        });
        if (decision === null) return refuse("APPROVAL_INVALID");
        // N6g-2 (R12): keep the verified record for the observer feed —
        // bound to the receipted booking_prepare response carrying this
        // exact envelope.
        recordApproval(liveRun, "provider", "booking_prepare", submitted.envelope, args.approval as ApprovalRecord);
        if (decision === "deny") {
          // N4b-9 (F15 → D11): a deny approval carrying a role signature is
          // ambiguous — refused, NOT terminal. The reachable policy terminal
          // is the signature-free deny submission above.
          return refuse("APPROVAL_INVALID");
        }
        const booked = liveRun.simRun!.bookOrder({
          agreementId: agreement.agreementId,
          itineraryId: agreement.itineraryId,
          feeMinor: agreement.feeMinor,
          totalMinor: agreement.totalMinor,
          // N4b-9 (F16 → D12): the traveller count is the principal-signed
          // mandate's partySize — never a model argument.
          travelerCount: liveRun.mandate?.partySize,
        });
        if (!booked.ok) return refuse("STATE_REFUSED");
        const issued = liveRun.simRun!.issueTickets({ orderRef: booked.orderRef });
        if (!issued.ok) return refuse("STATE_REFUSED");
        liveRun.booking = {
          orderRef: booked.orderRef,
          pnr: issued.pnr,
          tickets: issued.tickets,
          bookedAt: iso(now()),
          // N4b-8 (gap 6): the request digest a replay must reproduce.
          requestDigest: canonicalDigest({
            envelope: args.envelope,
            signatureHex: args.signatureHex,
            approval: args.approval,
          }),
        };
        liveRun.stage = "booked";
        return ok({
          orderRef: booked.orderRef,
          pnr: issued.pnr,
          tickets: issued.tickets,
          simulated: true,
          serverNonce,
        });
      }

      case "booking_lookup": {
        const observation = liveRun.simRun!.lookupOrder({ orderRef: args.orderRef });
        return ok({ observation, simulated: true, serverNonce });
      }

      case "booking_cancel_prepare": {
        // A settled run can never be cancelled — the money already moved.
        if (liveRun.settlement !== undefined || liveRun.terminalState === "settled") {
          return refuse("ALREADY_TERMINAL");
        }
        if (
          liveRun.booking === undefined || liveRun.agreement === undefined ||
          liveRun.cancellation !== undefined ||
          !cancelReasonAllowed(liveRun, args.reason)
        ) {
          return refuse("STATE_REFUSED");
        }
        const envelope = prepare(liveRun, "provider", "booking_cancel_prepare",
          cancelPayload(liveRun, args.reason as string));
        return ok({ envelope, serverNonce });
      }

      case "booking_cancel_submit": {
        // Idempotent replay: the recorded cancellation is returned verbatim —
        // never a nonce error — even though the envelope's nonce is claimed.
        if (liveRun.cancellation !== undefined) {
          // N4b-11 (adversarial M3 follow-up): if a previous submit wrote
          // the cancellation but its durable terminal enqueue FAILED,
          // the run kept cancellation set with terminalState null — and
          // this replay would answer CANCELLED for a run with no durable
          // job, no close, no anchor. Complete the transition FIRST; a
          // repeat persist failure propagates to CONTRACT_UNAVAILABLE.
          if (liveRun.terminalState === null) {
            options.endRun(liveRun, "cancelled", principal);
          }
          return ok({
            orderRef: liveRun.cancellation.orderRef,
            status: "CANCELLED",
            cancelledAt: liveRun.cancellation.cancelledAt,
            // N4b-9 (F11): report the run's ACTUAL terminal state — a cleanup
            // cancel after verification_failed did not move it.
            terminalState: liveRun.terminalState ?? "cancelled",
            simulated: true,
            serverNonce,
          });
        }
        if (liveRun.settlement !== undefined || liveRun.terminalState === "settled") {
          return refuse("ALREADY_TERMINAL");
        }
        if (liveRun.booking === undefined || liveRun.agreement === undefined) {
          return refuse("STATE_REFUSED");
        }
        const submitted = verifySubmission(liveRun, "provider", "booking_cancel_prepare",
          args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        // Server-derived fields must match the live run exactly; only the
        // reason is the caller's own (bound by its signature either way) —
        // and the enum reason must still match the CURRENT run state.
        if (
          !cancelReasonAllowed(liveRun, submitted.envelope.payload.reason)
        ) {
          return refuse("STATE_REFUSED");
        }
        if (
          !samePayload(
            submitted.envelope.payload,
            cancelPayload(liveRun, submitted.envelope.payload.reason as string),
          )
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        const cancelDecision = checkApprovalRecord({
          approval: args.approval as ApprovalRecord,
          runId: liveRun.runId,
          role: "provider",
          tool: "booking_cancel_submit",
          action: "booking",
          nonce: submitted.envelope.nonce,
          envelopeDigest: canonicalDigest(submitted.envelope),
          expiresAt: submitted.envelope.expiresAt,
          approvalKey: liveRun.bound.provider!.approvalKey,
          expectedPolicyDigest: options.policyDigests.provider,
          nowMs: now(),
        });
        if (cancelDecision === null) return refuse("APPROVAL_INVALID");
        // R12 review fix (from N6g-2 request): the cancel envelope was issued
        // by booking_cancel_prepare — bind to THAT receipt, never to a
        // booking_prepare receipt from a different envelope.
        recordApproval(liveRun, "provider", "booking_cancel_prepare", submitted.envelope, args.approval as ApprovalRecord);
        if (cancelDecision === "deny") {
          // N4b-8 (gap 5): a signed deny on the cancel gate refuses the cancel
          // but does NOT end the run — cancel can fire post-terminal
          // (verification_failed), and a second endRun would double-close.
          return refuse("POLICY_DENIED");
        }
        // The order ref comes from the server's own booking record — nothing
        // consequential is agent-selected.
        const cancelled = liveRun.simRun!.cancelOrder({ orderRef: liveRun.booking.orderRef });
        if (!cancelled.ok) return refuse("STATE_REFUSED");
        liveRun.cancellation = { orderRef: cancelled.orderRef, cancelledAt: cancelled.cancelledAt };
        options.endRun(liveRun, "cancelled", principal);
        return ok({
          orderRef: cancelled.orderRef,
          status: "CANCELLED",
          cancelledAt: cancelled.cancelledAt,
          // N4b-9 (F11): the write-once terminal state — "cancelled" for a
          // clean cancel, the pre-existing state for a post-failure cleanup.
          terminalState: liveRun.terminalState ?? "cancelled",
          simulated: true,
          serverNonce,
        });
      }

      case "verification_prepare": {
        if (liveRun.verification !== undefined) return refuse("STATE_REFUSED"); // write-once
        if (
          liveRun.booking === undefined || liveRun.agreement === undefined ||
          liveRun.booking.orderRef !== args.orderRef
        ) {
          return refuse("NOT_FOUND");
        }
        const agreement = liveRun.agreement;
        const payload: Record<string, unknown> = {
          kind: "verification",
          agreementId: agreement.agreementId,
          agreementDigest: agreement.agreementDigest,
          bookingRef: liveRun.booking.pnr,
          result: args.result,
          findingsDigest: args.findingsDigest,
        };
        const envelope = prepare(liveRun, "buyer", "verification_prepare", payload);
        return ok({ envelope, serverNonce });
      }

      case "verification_submit": {
        if (liveRun.verification !== undefined) return refuse("STATE_REFUSED"); // write-once
        if (liveRun.booking === undefined || liveRun.agreement === undefined) {
          return refuse("STATE_REFUSED");
        }
        const submitted = verifySubmission(liveRun, "buyer", "verification_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        if (
          payload.kind !== "verification" ||
          payload.agreementId !== liveRun.agreement.agreementId ||
          payload.agreementDigest !== liveRun.agreement.agreementDigest ||
          payload.bookingRef !== liveRun.booking.pnr ||
          (payload.result !== "match" && payload.result !== "mismatch")
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        // Independent check: the server's own observation of the order decides
        // truth — a claimed result that disagrees is flagged, not trusted.
        const observation = liveRun.simRun!.lookupOrder({ orderRef: liveRun.booking.orderRef });
        // N4b-9 (F16 → D12): the server recomputes match — a short booking
        // (ticketCount < the principal-signed partySize) is never a match,
        // so a model's `match` over it lands flagged. A legacy/fabricated
        // mandate without partySize keeps the v2 field checks only.
        const expectedTravellers = liveRun.mandate?.partySize;
        const observed = (
          observation.status === "ISSUED" &&
          observation.itineraryId === liveRun.agreement.itineraryId &&
          observation.totalMinor === liveRun.agreement.totalMinor &&
          (expectedTravellers === undefined || observation.ticketCount === expectedTravellers)
        ) ? "match" : "mismatch";
        const claimed = payload.result as "match" | "mismatch";
        const verificationDigest = canonicalDigest(payload);
        liveRun.verification = {
          result: claimed,
          verificationDigest,
          findingsDigest: payload.findingsDigest as string,
          agreementId: liveRun.agreement.agreementId,
          agreementDigest: liveRun.agreement.agreementDigest,
          orderRef: liveRun.booking.orderRef,
          bookingRef: liveRun.booking.pnr,
          flagged: claimed !== observed,
          submittedAt: iso(now()),
        };
        // A claimed mismatch is TERMINAL (N4B2B-CHANGES-2 §2): the run ends
        // verification_failed whether or not the server's observation agrees
        // (the disagreement is the `flagged` bit). No settlement can follow.
        const failed = claimed === "mismatch" || observed === "mismatch";
        if (failed) {
          options.endRun(liveRun, "verification_failed", principal);
        } else {
          liveRun.stage = "verified";
        }
        return ok({
          outcome: claimed,
          verificationDigest,
          flagged: claimed !== observed,
          ...(failed ? { terminalState: "verification_failed" } : {}),
          serverNonce,
        });
      }

      case "settlement_prepare": {
        if (
          liveRun.verification === undefined ||
          liveRun.verification.result !== "match" ||
          liveRun.verification.flagged ||
          liveRun.verification.agreementDigest !== liveRun.agreement?.agreementDigest ||
          liveRun.verification.orderRef !== liveRun.booking?.orderRef
        ) {
          return refuse("STATE_REFUSED");
        }
        const rail = options.settlementRail;
        if (rail !== undefined) {
          // N4b-10 (D13): the Stripe rail creates the UNCONFIRMED
          // PaymentIntent at prepare time — sign-then-release. The match
          // gate above runs BEFORE any rail call, so no PaymentIntent can
          // exist without a match verification. The envelope then signs a
          // payload naming the intent id. Async → dispatch returns a
          // Promise for this branch only.
          return (async (): Promise<BusinessOutcome> => {
            // L2 (adversarial review): the mandate cap runs BEFORE any
            // rail interaction — a cap-failing agreement must never mint a
            // PaymentIntent, and shouldn't even probe the key.
            const capFirst = capCheck(liveRun, liveRun.agreement!.totalMinor as number,
              liveRun.agreement!.currency as string, liveRun.agreement!.itineraryId);
            if (capFirst !== null) return capFirst;
            const status = await rail.keyStatus();
            if (status === "refused") {
              // A non-test key resolved — fail closed, generic refusal.
              return refuse("CONTRACT_UNAVAILABLE");
            }
            if (status === "absent") {
              // Honest stop, NO PaymentIntent created — contract_status
              // surfaces awaitingStripeTestKey.
              liveRun.awaitingStripeTestKey = true;
              return ok({
                status: "awaiting_stripe_test_key",
                paymentRail: rail.railId,
                simulated: true,
                label: STRIPE_RAIL_LABEL,
                serverNonce,
              });
            }
            if (liveRun.settlementIntent === undefined) {
              let intent;
              try {
                intent = await rail.createPaymentIntent({
                  amountAtomic: String(liveRun.agreement!.totalMinor),
                  currency: liveRun.agreement!.currency.toLowerCase(),
                  idempotencyKey: liveRun.agreement!.agreementDigest,
                  metadata: {
                    runId: liveRun.runId,
                    agreementDigest: liveRun.agreement!.agreementDigest,
                    verificationDigest: liveRun.verification!.verificationDigest,
                  },
                });
              } catch (err) {
                // Code-only, receipted; no intent created — retryable.
                return ok({
                  status: "failed",
                  paymentRail: rail.railId,
                  error: err instanceof StripeTestRailError ? err.code : "STRIPE_RAIL_HTTP",
                  simulated: true,
                  label: STRIPE_RAIL_LABEL,
                  serverNonce,
                });
              }
              liveRun.settlementIntent = { paymentIntentId: intent.id, status: intent.status };
            }
            liveRun.awaitingStripeTestKey = false;
            const payload = settlementPayload(liveRun);
            if (payload === null) return refuse("STATE_REFUSED");
            liveRun.settlementPrepared = true;
            const envelope = prepare(liveRun, "buyer", "settlement_prepare", payload);
            return ok({ envelope, serverNonce });
          })();
        }
        const payload = settlementPayload(liveRun);
        if (payload === null) return refuse("STATE_REFUSED");
        const cap = capCheck(liveRun, payload.amountMinor as number, payload.currency as string, liveRun.agreement!.itineraryId);
        if (cap !== null) return cap;
        liveRun.settlementPrepared = true;
        const envelope = prepare(liveRun, "buyer", "settlement_prepare", payload);
        return ok({ envelope, serverNonce });
      }

      case "settlement_authorize":
        // L4: the whole case runs under the per-run lock — verification,
        // nonce claim, rail confirm and the settlementRequest write are
        // one serialized unit per run.
        return serialized(liveRun.runId, (): BusinessOutcome | Promise<BusinessOutcome> => {
        // Adversarial review (H1): this tool is in TERMINAL_REPLAY_TOOLS so
        // a settled run's byte-identical replay can reach the recorded
        // result — but that bypass is for SETTLED runs only. A run that
        // ended any other way (a deny submission's blocked_by_policy,
        // verification_failed, cancelled, ...) has settlement === undefined;
        // letting a second prepare envelope authorize after a policy deny
        // would CONFIRM a PaymentIntent post-deny on the Stripe rail.
        // ALREADY_TERMINAL whenever terminal && !settlement.
        if (liveRun.terminalState !== null && liveRun.settlement === undefined) {
          return refuse("ALREADY_TERMINAL");
        }
        const expected = settlementPayload(liveRun);
        if (expected === null || liveRun.settlementPrepared !== true) {
          return refuse("STATE_REFUSED");
        }
        if (liveRun.settlement !== undefined) {
          // N4b-10 (D13): idempotent replay — the SAME call (same
          // envelope, signature and approval, digested as one request)
          // returns the recorded result verbatim; a different call on a
          // settled run is refused. Mirrors booking_execute (N4b-8 gap 6).
          const replayDigest = canonicalDigest({
            envelope: args.envelope,
            signatureHex: args.signatureHex,
            approval: args.approval,
          });
          if (replayDigest !== liveRun.settlementRequest?.digest) return refuse("STATE_REFUSED");
          // N4b-11 (adversarial M3 follow-up): a prior authorize could
          // record settlement and then lose the durable terminal enqueue
          // — leaving terminalState null. Answering "released" here would
          // return a settled claim for a run with NO durable job, close
          // or anchor. Retry the transition FIRST; a repeat persist
          // failure propagates to CONTRACT_UNAVAILABLE and the run
          // stays live-but-unanswered.
          if (liveRun.terminalState === null) {
            options.endRun(liveRun, "settled", principal);
          }
          return ok({ ...liveRun.settlementRequest!.result, serverNonce });
        }
        if (
          liveRun.verification === undefined ||
          liveRun.verification.result !== "match" ||
          liveRun.verification.flagged ||
          liveRun.verification.agreementDigest !== liveRun.agreement?.agreementDigest ||
          liveRun.verification.orderRef !== liveRun.booking?.orderRef
        ) {
          return refuse("STATE_REFUSED");
        }
        if (args.signatureHex === undefined) {
          // N4b-9 (F15 → D11): deny submission — the server's prepare
          // envelope plus a signed `deny` approval, no role signature.
          // Authenticates the envelope and the deny verdict; can never
          // authorize the transfer.
          const envCheck = verifySubmitEnvelope(liveRun, "buyer", "settlement_prepare", args.envelope);
          if (!envCheck.ok) return envCheck;
          if (!samePayload(envCheck.envelope.payload, expected)) {
            return refuse("ENVELOPE_INVALID");
          }
          const denyDecision = checkApprovalRecord({
            approval: args.approval as ApprovalRecord,
            runId: liveRun.runId,
            role: "buyer",
            tool: "settlement_authorize",
            action: "settlement",
            nonce: envCheck.envelope.nonce,
            envelopeDigest: canonicalDigest(envCheck.envelope),
            expiresAt: envCheck.envelope.expiresAt,
            approvalKey: liveRun.bound.buyer!.approvalKey,
            expectedPolicyDigest: options.policyDigests.buyer,
            nowMs: now(),
          });
          if (denyDecision === null) return refuse("APPROVAL_INVALID");
          if (denyDecision !== "deny") return refuse("SIGNATURE_INVALID");
          const finishDeny = (): BusinessOutcome => {
            liveRun.claimedNonces.add(envCheck.envelope.nonce);
            recordApproval(liveRun, "buyer", "settlement_prepare", envCheck.envelope, args.approval as ApprovalRecord);
            options.endRun(liveRun, "blocked_by_policy", principal);
            return refuse("POLICY_DENIED");
          };
          const denyRail = options.settlementRail;
          if (
            denyRail?.retrievePaymentIntent !== undefined &&
            liveRun.settlementIntent !== undefined
          ) {
            // N4b-11 (LOW follow-up): a prior confirm may have TIMED OUT
            // yet landed upstream — accepting this deny blind could end a
            // run blocked_by_policy while Stripe already moved the money.
            // Look the intent up FIRST (a GET — never a re-confirm, which
            // would release an unconfirmed intent the caller is denying).
            // Unresolvable truth fails the deny closed; a succeeded intent
            // settles the run instead of blocking it.
            return (async (): Promise<BusinessOutcome> => {
              let intent;
              try {
                intent = await denyRail.retrievePaymentIntent!({
                  paymentIntentId: liveRun.settlementIntent!.paymentIntentId,
                  expected: {
                    amountAtomic: String(expected.amountMinor),
                    currency: expected.currency as string,
                    runId: liveRun.runId,
                    agreementDigest: expected.agreementDigest as string,
                  },
                });
              } catch {
                return refuse("CONTRACT_UNAVAILABLE");
              }
              if (
                intent.id === liveRun.settlementIntent!.paymentIntentId &&
                intent.status === "succeeded"
              ) {
                liveRun.settlementIntent = { paymentIntentId: intent.id, status: intent.status };
                liveRun.settlement = {
                  transferId: intent.id, status: "released",
                  paymentRail: denyRail.railId, paymentIntentId: intent.id,
                };
                options.endRun(liveRun, "settled", principal);
                return refuse("ALREADY_TERMINAL");
              }
              liveRun.settlementIntent = {
                paymentIntentId: intent.id, status: intent.status,
              };
              return finishDeny();
            })();
          }
          return finishDeny();
        }
        const submitted = verifySubmission(liveRun, "buyer", "settlement_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (!samePayload(submitted.envelope.payload, expected)) {
          return refuse("ENVELOPE_INVALID");
        }
        const cap = capCheck(liveRun, expected.amountMinor as number, expected.currency as string, liveRun.agreement!.itineraryId);
        if (cap !== null) return cap;
        const approvalKey = liveRun.bound.buyer!.approvalKey;
        const settleDecision = checkApprovalRecord({
          approval: args.approval as ApprovalRecord,
          runId: liveRun.runId,
          role: "buyer",
          tool: "settlement_authorize",
          action: "settlement",
          nonce: submitted.envelope.nonce,
          envelopeDigest: canonicalDigest(submitted.envelope),
          expiresAt: submitted.envelope.expiresAt,
          approvalKey,
          expectedPolicyDigest: options.policyDigests.buyer,
          nowMs: now(),
        });
        if (settleDecision === null) return refuse("APPROVAL_INVALID");
        recordApproval(liveRun, "buyer", "settlement_prepare", submitted.envelope, args.approval as ApprovalRecord);
        if (settleDecision === "deny") {
          // N4b-9 (F15 → D11): deny + role signature is ambiguous — refused,
          // NOT terminal. The reachable policy terminal is the
          // signature-free deny submission above.
          return refuse("APPROVAL_INVALID");
        }
        // N4b-10 (D13): signature AND approval verified — only now may the
        // rail release. Confirm runs strictly after every auth check.
        const rail = options.settlementRail;
        if (rail !== undefined) {
          return (async (): Promise<BusinessOutcome> => {
            const paymentIntentId = liveRun.settlementIntent?.paymentIntentId;
            if (paymentIntentId === undefined) return refuse("STATE_REFUSED");
            const expectedTerms = {
              amountAtomic: String(expected.amountMinor),
              currency: expected.currency as string,
              runId: liveRun.runId,
              agreementDigest: expected.agreementDigest as string,
            };
            let intent;
            try {
              intent = await rail.confirmPaymentIntent({
                paymentIntentId,
                idempotencyKey: `${expected.agreementDigest}:confirm`,
                // M2: pin the agreement terms — a confirmed intent that
                // disagrees is a rail failure, never a settlement.
                expected: expectedTerms,
              });
            } catch (err) {
              // N4b-11 (LOW follow-up): a deadline/transport failure does
              // NOT prove the confirm failed — it may have landed upstream
              // after the race. Reconcile against the READ-ONLY lookup
              // before reporting failure; a `succeeded` intent settles
              // through the normal path below, anything else is the same
              // code-only failed body as before.
              let recovered;
              if (rail.retrievePaymentIntent !== undefined) {
                try {
                  recovered = await rail.retrievePaymentIntent({
                    paymentIntentId, expected: expectedTerms,
                  });
                } catch {
                  recovered = undefined; // truth unresolvable — report the failure
                }
              }
              if (recovered !== undefined && recovered.id === paymentIntentId) {
                liveRun.settlementIntent = {
                  paymentIntentId, status: recovered.status,
                };
                if (recovered.status === "succeeded") intent = recovered;
              }
              if (intent === undefined) {
                // Code-only, receipted; the run stays NON-settled. The nonce
                // is already consumed — the retry path is a FRESH
                // settlement_prepare (reusing the stored intent), not a
                // same-envelope retry.
                return ok({
                  status: "failed",
                  paymentRail: rail.railId,
                  paymentIntentId,
                  error: err instanceof StripeTestRailError ? err.code : "STRIPE_RAIL_HTTP",
                  simulated: true,
                  commercialTransfer: false,
                  label: STRIPE_RAIL_LABEL,
                  serverNonce,
                });
              }
            }
            // M2 belt-and-suspenders behind the rail's own validation: a
            // confirm result that is not `succeeded` or names a different
            // intent id is a code-only failure — NEVER settled.
            if (intent.id !== paymentIntentId || intent.status !== "succeeded") {
              return ok({
                status: "failed",
                paymentRail: rail.railId,
                paymentIntentId,
                error: "STRIPE_RAIL_BAD_RESPONSE",
                simulated: true,
                commercialTransfer: false,
                label: STRIPE_RAIL_LABEL,
                serverNonce,
              });
            }
            const result = {
              transferId: intent.id,
              status: "released" as const,
              paymentRail: rail.railId,
              paymentIntentId: intent.id,
              stripeStatus: intent.status,
              simulated: true,
              // Test mode — no commercial transfer ever occurred.
              commercialTransfer: false,
              label: STRIPE_RAIL_LABEL,
            };
            liveRun.settlementIntent = { paymentIntentId: intent.id, status: intent.status };
            liveRun.settlement = {
              transferId: intent.id,
              status: "released",
              paymentRail: rail.railId,
              paymentIntentId: intent.id,
            };
            liveRun.settlementRequest = {
              digest: canonicalDigest({
                envelope: args.envelope,
                signatureHex: args.signatureHex,
                approval: args.approval,
              }),
              result,
            };
            options.endRun(liveRun, "settled", principal);
            return ok({ ...result, serverNonce });
          })();
        }
        const transfer = liveRun.simRun!.payments.execute({
          agreementId: expected.agreementId,
          agreementDigest: expected.agreementDigest,
          verificationDigest: expected.verificationDigest,
          payerPartyId: liveRun.bound.buyer!.agentId,
          providerPartyId: liveRun.bound.provider!.agentId,
          amountMinor: expected.amountMinor,
          currency: expected.currency,
        });
        if (!transfer.ok) return refuse("STATE_REFUSED");
        liveRun.settlement = { transferId: transfer.receipt.transferId, status: "released", paymentRail: "simulated" };
        const simResult = {
          transferId: transfer.receipt.transferId,
          status: "released" as const,
          paymentRail: "simulated" as const,
          simulated: true,
          // The rail is a simulation: no commercial transfer ever occurred.
          commercialTransfer: false,
        };
        liveRun.settlementRequest = {
          digest: canonicalDigest({
            envelope: args.envelope,
            signatureHex: args.signatureHex,
            approval: args.approval,
          }),
          result: simResult,
        };
        options.endRun(liveRun, "settled", principal);
        return ok({ ...simResult, serverNonce });
        });

      case "settlement_status": {
        const rail = options.settlementRail;
        const railStatus = liveRun.simRun!.payments.status();
        const stripeReleased = liveRun.settlement?.paymentRail === "stripe_test_mode" && liveRun.settlement.status === "released";
        const state =
          railStatus.state === "released" || stripeReleased ? "released"
          : liveRun.awaitingStripeTestKey === true ? "awaiting_stripe_test_key"
          : liveRun.settlementPrepared === true ? "prepared"
          : "none";
        return ok({
          state,
          ...(railStatus.state === "released" ? { transferId: railStatus.transferId } : {}),
          ...(stripeReleased ? { transferId: liveRun.settlement!.transferId } : {}),
          // D13 clarification: the rail is reported from the recorded
          // paymentRail evidence first — `simulated: true` is never the
          // discriminator (it stays true on BOTH rails).
          paymentRail: liveRun.settlement?.paymentRail
            ?? (liveRun.settlementIntent !== undefined || liveRun.awaitingStripeTestKey === true
              ? "stripe_test_mode" : rail?.railId ?? "simulated"),
          ...(liveRun.settlementIntent !== undefined
            ? { paymentIntentId: liveRun.settlementIntent.paymentIntentId, stripeStatus: liveRun.settlementIntent.status }
            : {}),
          simulated: true,
          ...(rail !== undefined ? { label: STRIPE_RAIL_LABEL } : {}),
          serverNonce,
        });
      }

      default:
        return refuse("NOT_FOUND");
    }
  }

  return { dispatch, consumableListing, consumeListing };
}
