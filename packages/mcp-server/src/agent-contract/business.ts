import { createPublicKey, type KeyObject } from "node:crypto";

import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import {
  signEnvelope, verifyEnvelope, type ContractSigner, type PrepareEnvelope,
} from "./envelope.js";
import {
  eip191RecoverPublicKey, publicKeyToAddress, verifyRoleSignature,
} from "./eip191.js";
import { verifyApprovalRecord } from "./approval.js";
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
  dispatch(
    principal: ContractPrincipal,
    run: ContractRun | undefined,
    tool: string,
    args: Record<string, unknown>,
    serverNonce: string,
  ): BusinessOutcome;
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

/** rev 6.5: the mandate is the family principal's statement — all fields required. */
const mandateSchema = z.object({
  kind: z.literal("mandate"),
  mandateId: z.string().min(4).max(64),
  capMinor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  currency: z.string().regex(/^[A-Z]{3}$/),
  allowedItineraryIds: z.array(z.string().min(1).max(64)).min(1).max(64),
  expiresAt: z.string().datetime({ offset: false }),
}).strict();
type Mandate = z.infer<typeof mandateSchema>;

const LISTING_TTL_MS = 60 * 60_000;
/** Global safety cap — the real quota is per-provider. */
const MAX_LISTINGS = 512;
/** One provider can hold at most this many live listings. */
const MAX_LISTINGS_PER_PROVIDER = 32;
/** Pending sealed deliveries a single listing holds at once. */
const MAX_PENDING_PER_LISTING = 16;
const MAX_INBOX_MESSAGES = 256;
const MAX_DELIVERIES_PER_MINUTE = 12;

function pad4(n: number): string {
  return String(n).padStart(4, "0");
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
  policyDigests: Readonly<Record<ContractRole, string>>;
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
   * N4b-8 (gap 2): CONTRACT_LEVEL=L only — legacy unbound v:2 boxes still
   * deliver. At S|P only the listing-bound v:4 wire is accepted; the server
   * carries every box opaque either way.
   */
  allowLegacySealV2?: boolean;
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
   * cancellation for a deterministic result. The cases below still refuse
   * ALREADY_TERMINAL once a settlement has authorized (settled runs can
   * never be cancelled).
   */
  const TERMINAL_REPLAY_TOOLS = new Set(["booking_cancel_prepare", "booking_cancel_submit"]);

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

  /** The counterparty's LATEST live offer — the only acceptable one. */
  function latestCounterpartyOffer(run: ContractRun, role: ContractRole): OfferRecord | undefined {
    let latest: OfferRecord | undefined;
    for (const offer of run.offers.values()) {
      if (offer.state === "live" && offer.role !== role &&
        (latest === undefined || offer.seq > latest.seq)) {
        latest = offer;
      }
    }
    return latest;
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

  /** v2 booking payload — server-derived from the agreement only. */
  function bookingPayload(agreement: AgreementRecord): Record<string, unknown> {
    return {
      kind: "booking",
      agreementId: agreement.agreementId,
      agreementDigest: agreement.agreementDigest,
      itineraryId: agreement.itineraryId,
      currency: agreement.currency,
      totalMinor: agreement.totalMinor,
    };
  }

  /** v2 settlement payload — server-derived from agreement + verification. */
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
  ): BusinessOutcome {
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
          // Per-provider quota first, then the global safety cap — one
          // provider can never lock the others out.
          let mine = 0;
          for (const l of listings.values()) {
            if (l.providerKeyId === principal.keyId) mine += 1;
          }
          if (mine >= MAX_LISTINGS_PER_PROVIDER || listings.size >= MAX_LISTINGS) {
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
        if (listing === undefined) return refuse("NOT_FOUND");
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
        const envelope = prepare(liveRun, "buyer", "mandate_prepare", {
          kind: "mandate",
          mandate,
          mandateSignature: args.mandateSignature,
          mandateDigest,
        });
        return ok({ envelope, mandateDigest, serverNonce });
      }

      case "mandate_submit": {
        // Envelope verification first so a REPLAYED nonce reports NONCE_REUSED
        // precisely; a fresh-envelope resubmission then hits the write-once
        // guard as STATE_REFUSED.
        const submitted = verifySubmission(liveRun, "buyer", "mandate_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (liveRun.mandate !== undefined) return refuse("STATE_REFUSED"); // write-once
        const payload = submitted.envelope.payload;
        const mandate = verifyMandate(principal, payload.mandate, payload.mandateSignature);
        if (payload.kind !== "mandate" || typeof mandate === "string") {
          return refuse("MANDATE_INVALID");
        }
        const mandateDigest = canonicalDigest({ domain: MANDATE_DOMAIN, ...mandate });
        if (payload.mandateDigest !== mandateDigest) return refuse("ENVELOPE_INVALID");
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
        const envelope = prepare(liveRun, "provider", "booking_prepare", bookingPayload(agreement));
        return ok({ envelope, serverNonce });
      }

      case "booking_execute": {
        const agreement = liveRun.agreement;
        if (agreement === undefined) return refuse("STATE_REFUSED");
        if (liveRun.booking !== undefined) return refuse("STATE_REFUSED");
        const submitted = verifySubmission(liveRun, "provider", "booking_prepare", args.envelope, args.signatureHex as string);
        if (!submitted.ok) return submitted;
        if (!samePayload(submitted.envelope.payload, bookingPayload(agreement))) {
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
            approvalKey,
            expectedPolicyDigest: options.policyDigests.provider,
            nowMs: now(),
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
          return ok({
            orderRef: liveRun.cancellation.orderRef,
            status: "CANCELLED",
            cancelledAt: liveRun.cancellation.cancelledAt,
            terminalState: "cancelled",
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
        if (
          !verifyApprovalRecord({
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
          })
        ) {
          return refuse("APPROVAL_INVALID");
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
          terminalState: "cancelled",
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
        const observed = (
          observation.status === "ISSUED" &&
          observation.itineraryId === liveRun.agreement.itineraryId &&
          observation.totalMinor === liveRun.agreement.totalMinor
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
        if (
          liveRun.verification === undefined ||
          liveRun.verification.result !== "match" ||
          liveRun.verification.flagged ||
          liveRun.verification.agreementDigest !== liveRun.agreement?.agreementDigest ||
          liveRun.verification.orderRef !== liveRun.booking?.orderRef
        ) {
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
            approvalKey,
            expectedPolicyDigest: options.policyDigests.buyer,
            nowMs: now(),
          })
        ) {
          return refuse("APPROVAL_INVALID");
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
        liveRun.settlement = { transferId: transfer.receipt.transferId, status: "released" };
        options.endRun(liveRun, "settled", principal);
        return ok({
          transferId: transfer.receipt.transferId,
          status: "released",
          simulated: true,
          // The rail is a simulation: no commercial transfer ever occurred.
          commercialTransfer: false,
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

  return { dispatch, consumableListing, consumeListing };
}
