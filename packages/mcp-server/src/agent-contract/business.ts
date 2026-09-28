import { createPublicKey, type KeyObject } from "node:crypto";

import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import {
  signEnvelope, verifyEnvelope, type ContractSigner, type PrepareEnvelope,
} from "./envelope.js";
import { verifyRoleSignature } from "./eip191.js";
import { verifyApprovalRecord } from "./approval.js";
import type { ApprovalRecord, ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";
import type {
  AgreementRecord, ContractPrincipal, ContractRun, OfferRecord,
} from "./service.js";
import type { SimWorld } from "./sim/index.js";

/**
 * The `/contract/mcp` business semantics (N4b-2b, LLD §3/§13): every
 * catalogued tool except `contract_bind`/`contract_status` (service-owned).
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
 *  - buyer-side priced operations re-check the mandate caps; every cap
 *    refusal is the identical generic MANDATE_REFUSED body;
 *  - booking/settlement additionally require a §13 approval record verified
 *    against the bound approval key;
 *  - booking touches the run's closed ticketing sim, settlement the run's
 *    payment rail — every sim-derived output carries `simulated: true`.
 */

export type BusinessOutcome =
  | { ok: true; result: Record<string, unknown> }
  | { ok: false; code: ContractRefusalCode };

interface Listing {
  listingId: string;
  providerKeyId: string;
  title: string;
  summary: string;
  sealedBoxPublicKeyHex: string;
  terms?: Record<string, unknown>;
  publishedAt: string;
  invitationDelivered: boolean;
}

interface InboxMessage {
  messageId: string;
  kind: "handshake_invitation" | "business_message";
  listingId?: string;
  sealedPayload?: Record<string, unknown>;
  body?: unknown;
  receivedAt: string;
}

export interface BusinessOps {
  dispatch(
    principal: ContractPrincipal,
    run: ContractRun | undefined,
    tool: string,
    args: Record<string, unknown>,
    serverNonce: string,
  ): BusinessOutcome;
}

const iso = (ms: number): string => new Date(ms).toISOString();
const ok = (result: Record<string, unknown>): BusinessOutcome => ({ ok: true, result });
const refuse = (code: ContractRefusalCode): BusinessOutcome => ({ ok: false, code });

const AGREEMENT_DOMAIN = "agent-contract.agreement/v1";

/** Lenient cap extraction — the mandate blob is agent-authored (N5-owned shape). */
const mandateCapsSchema = z.object({
  capMinor: z.number().int().nonnegative().optional(),
  maxTotalMinor: z.number().int().nonnegative().optional(),
  currency: z.string().min(3).max(8).optional(),
  itineraryIds: z.array(z.string().min(1).max(64)).max(64).optional(),
}).passthrough();

function pad4(n: number): string {
  return String(n).padStart(4, "0");
}

export function createBusinessOps(options: {
  signer: ContractSigner;
  now?: () => number;
  sim: SimWorld;
  expectedPolicyDigest?: string;
  endRun: (run: ContractRun, terminalState: string) => void;
}): BusinessOps {
  const now = options.now ?? Date.now;
  const sim = options.sim;
  const serverPublicKeys = { [options.signer.keyId]: publicKeyOf(options.signer.privateKey) };
  const listings = new Map<string, Listing>();
  const inbox = new Map<string, InboxMessage[]>();

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

  /** Both seats must be occupied before any business step runs. */
  function requireRun(run: ContractRun | undefined, tool: string): BusinessOutcome | null {
    if (run === undefined || run.bound.buyer === undefined || run.bound.provider === undefined) {
      return refuse("STATE_REFUSED");
    }
    if (run.terminalState !== null && !READ_ONLY_TOOLS.has(tool)) return refuse("ALREADY_TERMINAL");
    return null;
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
    const verdict = verifyEnvelope(envelope, serverPublicKeys, {
      nowMs: now(),
      nonceSeen: (runId, nonce) => run.runId === runId && run.claimedNonces.has(nonce),
    });
    if (!verdict.ok) return { ok: false, code: verdict.code as ContractRefusalCode };
    const env = verdict.envelope;
    if (env.runId !== run.runId || env.tool !== tool || env.role !== role) {
      return { ok: false, code: "ENVELOPE_INVALID" };
    }
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
   * Buyer mandate caps — one identical MANDATE_REFUSED whatever the cap
   * (cap values must never ride the refusal, refusals.ts comment).
   */
  function capCheck(run: ContractRun, totalMinor: number, currency: string, itineraryId: string): BusinessOutcome | null {
    const m = run.mandate;
    if (m === undefined) return refuse("STATE_REFUSED");
    if (m.capMinor !== undefined && totalMinor > m.capMinor) return refuse("MANDATE_REFUSED");
    if (m.currency !== undefined && currency !== m.currency) return refuse("MANDATE_REFUSED");
    if (m.itineraryIds !== undefined && !m.itineraryIds.includes(itineraryId)) {
      return refuse("MANDATE_REFUSED");
    }
    return null;
  }

  function prepare(run: ContractRun, role: ContractRole, tool: string, payload: Record<string, unknown>): PrepareEnvelope {
    return signEnvelope(
      { payload, runId: run.runId, tool, role, nowMs: now() },
      options.signer,
    );
  }

  /** The counterparty's latest live offer — the offer a counter replies to. */
  function latestCounterpartyOffer(run: ContractRun, role: ContractRole): OfferRecord | undefined {
    let latest: OfferRecord | undefined;
    for (const offer of run.offers.values()) {
      if (offer.state === "live" && offer.role !== role) latest = offer;
    }
    return latest;
  }

  function bookingPayload(run: ContractRun, agreement: AgreementRecord): Record<string, unknown> {
    return {
      kind: "booking",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      itineraryId: agreement.itineraryId,
      currency: agreement.currency,
      fareMinor: agreement.fareMinor,
      feeMinor: agreement.feeMinor,
      totalMinor: agreement.totalMinor,
    };
  }

  function settlementPayload(run: ContractRun): Record<string, unknown> | null {
    const agreement = run.agreement;
    const verification = run.verification;
    const buyer = run.bound.buyer;
    const provider = run.bound.provider;
    if (agreement === undefined || verification === undefined || buyer === undefined || provider === undefined) {
      return null;
    }
    return {
      kind: "settlement",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      verificationDigest: verification.verificationDigest,
      amountMinor: agreement.totalMinor,
      currency: agreement.currency,
      payerPartyId: buyer.agentId,
      providerPartyId: provider.agentId,
    };
  }

  function samePayload(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
    return canonicalDigest(a) === canonicalDigest(b);
  }

  function dispatch(
    principal: ContractPrincipal,
    run: ContractRun | undefined,
    tool: string,
    args: Record<string, unknown>,
    serverNonce: string,
  ): BusinessOutcome {
    switch (tool) {
      // -- rendezvous / discovery (pre-run) -----------------------------------
      case "rendezvous_publish_listing": {
        const listingId = `lst-${canonicalDigest({
          kind: "listing", providerKeyId: principal.keyId,
          title: args.title, sealedBoxPublicKeyHex: args.sealedBoxPublicKeyHex,
        }).slice(2, 14)}`;
        listings.set(listingId, {
          listingId,
          providerKeyId: principal.keyId,
          title: args.title as string,
          summary: args.summary as string,
          sealedBoxPublicKeyHex: args.sealedBoxPublicKeyHex as string,
          ...(args.terms !== undefined ? { terms: args.terms as Record<string, unknown> } : {}),
          publishedAt: iso(now()),
          invitationDelivered: false,
        });
        return ok({ listingId, publishedAt: iso(now()), serverNonce });
      }

      case "rendezvous_search": {
        const out = [...listings.values()].map((l) => ({
          listingId: l.listingId,
          title: l.title,
          summary: l.summary,
          sealedBoxPublicKeyHex: l.sealedBoxPublicKeyHex,
        }));
        return ok({ listings: out, serverNonce });
      }

      case "rendezvous_send_invitation": {
        const listing = listings.get(args.listingId as string);
        if (listing === undefined) return refuse("NOT_FOUND");
        if (listing.invitationDelivered) return refuse("LISTING_UNAVAILABLE");
        listing.invitationDelivered = true;
        const receivedAt = iso(now());
        const message: InboxMessage = {
          messageId: `msg-${canonicalDigest({ kind: "inbox", listingId: listing.listingId, receivedAt }).slice(2, 14)}`,
          kind: "handshake_invitation",
          listingId: listing.listingId,
          sealedPayload: args.sealedInvitation as Record<string, unknown>,
          receivedAt,
        };
        const list = inbox.get(listing.providerKeyId) ?? [];
        list.push(message);
        inbox.set(listing.providerKeyId, list);
        return ok({ delivered: true, deliveredAt: receivedAt, serverNonce });
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

    // -- everything below needs a fully-bound live run -------------------------
    const gate = requireRun(run, tool);
    if (gate !== null) return gate;
    const liveRun = run!;

    switch (tool) {
      case "catalog_quote": {
        const quote = liveRun.simRun!.quote(args);
        return ok({ itineraries: quote.itineraries, simulated: true, serverNonce });
      }

      case "mandate_prepare": {
        const mandate = args.mandate as Record<string, unknown>;
        const caps = mandateCapsSchema.safeParse(mandate);
        if (!caps.success) return refuse("MANDATE_REFUSED");
        const mandateDigest = canonicalDigest({ domain: "agent-contract.mandate/v1", runId: liveRun.runId, mandate });
        const envelope = prepare(liveRun, "buyer", "mandate_prepare", {
          kind: "mandate",
          mandate,
          mandateDigest,
        });
        return ok({ envelope, mandateDigest, serverNonce });
      }

      case "mandate_submit": {
        const submitted = verifySubmission(liveRun, "buyer", "mandate_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        const mandate = payload.mandate;
        if (payload.kind !== "mandate" || mandate === null || typeof mandate !== "object") {
          return refuse("ENVELOPE_INVALID");
        }
        const caps = mandateCapsSchema.safeParse(mandate);
        if (!caps.success) return refuse("MANDATE_REFUSED");
        const mandateDigest = canonicalDigest({ domain: "agent-contract.mandate/v1", runId: liveRun.runId, mandate });
        if (payload.mandateDigest !== mandateDigest) return refuse("ENVELOPE_INVALID");
        const capMinor = caps.data.capMinor ?? caps.data.maxTotalMinor;
        liveRun.mandate = {
          digest: mandateDigest,
          submittedAt: iso(now()),
          ...(capMinor !== undefined ? { capMinor } : {}),
          ...(caps.data.currency !== undefined ? { currency: caps.data.currency } : {}),
          ...(caps.data.itineraryIds !== undefined ? { itineraryIds: caps.data.itineraryIds } : {}),
        };
        if (liveRun.stage === "bound" || liveRun.stage === "handshake") liveRun.stage = "mandated";
        return ok({ bound: true, mandateDigest, serverNonce });
      }

      case "offer_prepare": {
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
          submittedAt: iso(now()),
        };
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
        if (principal.role === "buyer") {
          const cap = capCheck(
            liveRun, offer.payload.totalMinor as number,
            offer.payload.currency as string, offer.payload.itineraryId as string,
          );
          if (cap !== null) return cap;
        }
        const payload: Record<string, unknown> = {
          kind: "accept",
          offerId: offer.offerId,
          offerDigest: canonicalDigest(offer.payload),
          agreedTerms: {
            itineraryId: offer.payload.itineraryId,
            currency: offer.payload.currency,
            fareMinor: offer.payload.fareMinor,
            feeMinor: offer.payload.feeMinor,
            totalMinor: offer.payload.totalMinor,
          },
        };
        const envelope = prepare(liveRun, principal.role, "offer_accept_prepare", payload);
        return ok({ envelope, serverNonce });
      }

      case "offer_accept_submit": {
        const submitted = verifySubmission(liveRun, principal.role, "offer_accept_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        const offer = liveRun.offers.get(payload.offerId as string);
        if (offer === undefined) return refuse("NOT_FOUND");
        if (offer.state !== "live" || offer.role === principal.role) return refuse("STATE_REFUSED");
        if (
          payload.kind !== "accept" ||
          payload.offerDigest !== canonicalDigest(offer.payload) ||
          !samePayload(payload.agreedTerms as Record<string, unknown>, {
            itineraryId: offer.payload.itineraryId,
            currency: offer.payload.currency,
            fareMinor: offer.payload.fareMinor,
            feeMinor: offer.payload.feeMinor,
            totalMinor: offer.payload.totalMinor,
          })
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        if (principal.role === "buyer") {
          const cap = capCheck(
            liveRun, offer.payload.totalMinor as number,
            offer.payload.currency as string, offer.payload.itineraryId as string,
          );
          if (cap !== null) return cap;
        }
        offer.state = "accepted";
        const agreementId = `agr-${pad4(liveRun.offerSeq)}`;
        const agreementDigest = canonicalDigest({
          domain: AGREEMENT_DOMAIN,
          runId: liveRun.runId,
          agreementId,
          offerDigest: canonicalDigest(offer.payload),
          acceptedBy: principal.role,
        });
        liveRun.agreement = {
          agreementId,
          offerId: offer.offerId,
          offerDigest: canonicalDigest(offer.payload),
          agreementDigest,
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
        options.endRun(liveRun, "no_agreement");
        return ok({ state: "withdrawn", serverNonce });
      }

      case "agreement_get": {
        const agreement = liveRun.agreement;
        return ok({
          agreement: agreement === undefined ? null : structuredClone(agreement),
          anchor: agreement === undefined ? null : {
            runId: liveRun.runId,
            agreementDigest: agreement.agreementDigest,
            formedAt: agreement.formedAt,
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
        const envelope = prepare(liveRun, "provider", "booking_prepare", bookingPayload(liveRun, agreement));
        return ok({ envelope, serverNonce });
      }

      case "booking_execute": {
        const agreement = liveRun.agreement;
        if (agreement === undefined) return refuse("STATE_REFUSED");
        if (liveRun.booking !== undefined) return refuse("STATE_REFUSED");
        const submitted = verifySubmission(liveRun, "provider", "booking_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (!samePayload(submitted.envelope.payload, bookingPayload(liveRun, agreement))) {
          return refuse("ENVELOPE_INVALID");
        }
        const approvalKey = liveRun.bound.provider!.approvalKey;
        if (
          !verifyApprovalRecord({
            approval: args.approval as ApprovalRecord,
            runId: liveRun.runId,
            role: "provider",
            tool: "booking_execute",
            action: "booking",
            nonce: submitted.envelope.nonce,
            envelopeDigest: canonicalDigest(submitted.envelope),
            expiresAt: submitted.envelope.expiresAt,
            approvalPublicKeyHex: approvalKey.publicKeyHex,
            ...(options.expectedPolicyDigest !== undefined ? { expectedPolicyDigest: options.expectedPolicyDigest } : {}),
          })
        ) {
          return refuse("APPROVAL_INVALID");
        }
        const booked = liveRun.simRun!.bookOrder({
          agreementId: agreement.agreementId,
          itineraryId: agreement.itineraryId,
          feeMinor: agreement.feeMinor,
          totalMinor: agreement.totalMinor,
        });
        if (!booked.ok) return refuse("STATE_REFUSED");
        const issued = liveRun.simRun!.issueTickets({ orderRef: booked.orderRef });
        if (!issued.ok) return refuse("STATE_REFUSED");
        liveRun.booking = {
          orderRef: booked.orderRef,
          pnr: issued.pnr,
          tickets: issued.tickets,
          bookedAt: iso(now()),
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

      case "verification_prepare": {
        if (liveRun.booking === undefined || liveRun.booking.orderRef !== args.orderRef) {
          return refuse("NOT_FOUND");
        }
        const agreement = liveRun.agreement!;
        const payload: Record<string, unknown> = {
          kind: "verification",
          orderRef: args.orderRef,
          bookingRef: liveRun.booking.pnr,
          agreementDigest: agreement.agreementDigest,
          result: args.result,
          findingsDigest: canonicalDigest({ findings: args.findings ?? "" }),
        };
        const envelope = prepare(liveRun, "buyer", "verification_prepare", payload);
        return ok({ envelope, serverNonce });
      }

      case "verification_submit": {
        if (liveRun.booking === undefined || liveRun.agreement === undefined) {
          return refuse("STATE_REFUSED");
        }
        const submitted = verifySubmission(liveRun, "buyer", "verification_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        const payload = submitted.envelope.payload;
        if (
          payload.kind !== "verification" ||
          payload.orderRef !== liveRun.booking.orderRef ||
          payload.bookingRef !== liveRun.booking.pnr ||
          payload.agreementDigest !== liveRun.agreement.agreementDigest ||
          (payload.result !== "match" && payload.result !== "mismatch")
        ) {
          return refuse("ENVELOPE_INVALID");
        }
        // Independent check: the server's own observation of the order decides
        // truth — a claimed result that disagrees is flagged, not trusted.
        const observation = liveRun.simRun!.lookupOrder({ orderRef: liveRun.booking.orderRef });
        const observed = (
          observation.status === "ISSUED" &&
          observation.itineraryId === liveRun.agreement.itineraryId &&
          observation.totalMinor === liveRun.agreement.totalMinor
        ) ? "match" : "mismatch";
        const claimed = payload.result as "match" | "mismatch";
        const verificationDigest = canonicalDigest({
          domain: "agent-contract.verification/v1",
          runId: liveRun.runId,
          orderRef: liveRun.booking.orderRef,
          claimed,
          observed,
        });
        liveRun.verification = {
          result: claimed,
          verificationDigest,
          findingsDigest: payload.findingsDigest as string,
          flagged: claimed !== observed,
          submittedAt: iso(now()),
        };
        if (observed === "mismatch") {
          options.endRun(liveRun, "verification_failed");
        } else if (claimed === "match" && observed === "match") {
          liveRun.stage = "verified";
        }
        return ok({ outcome: claimed, verificationDigest, flagged: claimed !== observed, serverNonce });
      }

      case "settlement_prepare": {
        if (liveRun.verification === undefined || liveRun.verification.result !== "match" || liveRun.verification.flagged) {
          return refuse("STATE_REFUSED");
        }
        const payload = settlementPayload(liveRun);
        if (payload === null) return refuse("STATE_REFUSED");
        const cap = capCheck(liveRun, payload.amountMinor as number, payload.currency as string, liveRun.agreement!.itineraryId);
        if (cap !== null) return cap;
        liveRun.settlementPrepared = true;
        const envelope = prepare(liveRun, "buyer", "settlement_prepare", payload);
        return ok({ envelope, serverNonce });
      }

      case "settlement_authorize": {
        const expected = settlementPayload(liveRun);
        if (expected === null || liveRun.settlementPrepared !== true || liveRun.settlement !== undefined) {
          return refuse("STATE_REFUSED");
        }
        if (liveRun.verification === undefined || liveRun.verification.result !== "match" || liveRun.verification.flagged) {
          return refuse("STATE_REFUSED");
        }
        const submitted = verifySubmission(liveRun, "buyer", "settlement_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (!samePayload(submitted.envelope.payload, expected)) {
          return refuse("ENVELOPE_INVALID");
        }
        const cap = capCheck(liveRun, expected.amountMinor as number, expected.currency as string, liveRun.agreement!.itineraryId);
        if (cap !== null) return cap;
        const approvalKey = liveRun.bound.buyer!.approvalKey;
        if (
          !verifyApprovalRecord({
            approval: args.approval as ApprovalRecord,
            runId: liveRun.runId,
            role: "buyer",
            tool: "settlement_authorize",
            action: "settlement",
            nonce: submitted.envelope.nonce,
            envelopeDigest: canonicalDigest(submitted.envelope),
            expiresAt: submitted.envelope.expiresAt,
            approvalPublicKeyHex: approvalKey.publicKeyHex,
            ...(options.expectedPolicyDigest !== undefined ? { expectedPolicyDigest: options.expectedPolicyDigest } : {}),
          })
        ) {
          return refuse("APPROVAL_INVALID");
        }
        const transfer = liveRun.simRun!.payments.execute({
          agreementId: expected.agreementId,
          agreementDigest: expected.agreementDigest,
          verificationDigest: expected.verificationDigest,
          payerPartyId: expected.payerPartyId,
          providerPartyId: expected.providerPartyId,
          amountMinor: expected.amountMinor,
          currency: expected.currency,
        });
        if (!transfer.ok) return refuse("STATE_REFUSED");
        liveRun.settlement = { transferId: transfer.receipt.transferId, status: "released" };
        options.endRun(liveRun, "settled");
        return ok({
          transferId: transfer.receipt.transferId,
          status: "released",
          simulated: true,
          serverNonce,
        });
      }

      case "settlement_status": {
        const railStatus = liveRun.simRun!.payments.status();
        const state =
          railStatus.state === "released" ? "released"
          : liveRun.settlementPrepared === true ? "prepared"
          : "none";
        return ok({
          state,
          ...(railStatus.state === "released" ? { transferId: railStatus.transferId } : {}),
          simulated: true,
          serverNonce,
        });
      }

      default:
        return refuse("NOT_FOUND");
    }
  }

  return { dispatch };
}
