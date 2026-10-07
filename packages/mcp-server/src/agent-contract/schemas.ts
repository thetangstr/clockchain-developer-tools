import { z } from "zod";

import { prepareEnvelopeSchema } from "./envelope.js";

/**
 * Input and output zod schemas for every `/contract/mcp` tool in the pairing
 * LLD §3 (rev 5), with role scoping. Schemas are strict: unknown keys are
 * rejected, and no input can smuggle fields the deterministic checks would
 * ignore. Outputs that touch the ticketing or settlement sim carry
 * `simulated: true` (LLD §3, H1); every output carries the per-call
 * `serverNonce` the receipt chain also records (R8/R13).
 *
 * Semantics — board lookups, cap enforcement, signature verification, sim
 * calls — are N4b. This file freezes only the wire contract.
 */

export type ContractRole = "buyer" | "provider";
export type ContractToolRoleScope = ContractRole | "both";

const digestHex = z.string().regex(/^0x[0-9a-f]{64}$/);
/** 64-byte ed25519 or 65-byte secp256k1 — the role signature scheme is N5's choice. */
const signatureHex = z.string().regex(/^0x[0-9a-fA-F]{128,130}$/);
const publicKeyHex = z.string().regex(/^0x[0-9a-fA-F]{64,132}$/);
const keyId = z.string().min(1).max(64);
const serverNonce = z.string().regex(/^0x[0-9a-f]{32}$/);
const isoDateTime = z.string().datetime({ offset: false });
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const opaqueRecord = z.record(z.string(), z.unknown());
const listingId = z.string().min(4).max(64);
/** O-2: a `CONTRACT_DIRECTORY` name (lowercase slug) — see directory.ts. */
const directoryName = z.string().regex(/^[a-z0-9][a-z0-9-]{1,63}$/);
const orderRef = z.string().min(4).max(32);
const offerId = z.string().min(4).max(64);
const agreementId = z.string().min(4).max(64);

const registeredKey = z.object({
  keyId,
  publicKeyHex,
}).strict();

/**
 * The rendezvous seal (N5 `sealTo`, CONTRACT-PAYLOADS-v2 §Seal wire):
 * ephemeral-x25519 → HKDF → AES-256-GCM, all fields 0x-hex — epk 32B,
 * iv 12B, tag 16B. The server carries the box OPAQUE — it cannot open it.
 * v:2 is the legacy unbound profile; v:4 binds the box to the listingId
 * (HKDF info + GCM AAD, signer side). Malformed anything refuses at the
 * schema, so a bad delivery can never reach — let alone burn — a listing.
 * v:2 wire acceptance is additionally gated at dispatch by CONTRACT_LEVEL.
 */
const sealBoxFields = {
  epk: z.string().regex(/^0x[0-9a-f]{64}$/),
  iv: z.string().regex(/^0x[0-9a-f]{24}$/),
  ct: z.string().regex(/^0x(?:[0-9a-f]{2}){1,8192}$/),
  tag: z.string().regex(/^0x[0-9a-f]{32}$/),
} as const;
export const sealedBoxV2Schema = z.object({ v: z.literal(2), ...sealBoxFields }).strict();
export const sealedBoxV4Schema = z.object({ v: z.literal(4), ...sealBoxFields }).strict();
const sealedBox = z.discriminatedUnion("v", [sealedBoxV2Schema, sealedBoxV4Schema]);
export const sealedBoxSchema = sealedBox;

/**
 * DRAFT (N4b-7): the bind-statement wire shape. The audit agent owns the
 * final schema (PR #159); the service verifies it in one function so the
 * final schema is a one-place change. `domain` is pinned here so a foreign
 * statement never reaches dispatch.
 */
const bindStatementSchema = z.object({
  domain: z.literal("agent-contract.bind/v1"),
  runId: z.string().min(4).max(128),
  side: z.enum(["initiator", "responder"]),
  tokenKeyId: keyId,
  serverKeyId: keyId,
  challenge: z.string().regex(/^[0-9a-f]{64}$/),
  issuedAt: isoDateTime,
}).strict();

/**
 * The signed consequential-action approval record (LLD §13, T0
 * `ApprovalRecord`). Produced deterministically by the role's local signer
 * policy and verified against the approval key bound at contract time.
 */
export const approvalRecordSchema = z.object({
  role: z.enum(["buyer", "provider"]),
  action: z.string().min(1).max(64),
  digest: digestHex,
  policyDigest: digestHex,
  // The spec decision word is "allow" (CONTRACT-PAYLOADS-v2 §13) — "approve"
  // is not a legal record.
  decision: z.enum(["allow", "deny"]),
  ts: z.number().int().positive(),
  approverKeyId: keyId,
  signature: signatureHex,
}).strict();
export type ApprovalRecord = z.infer<typeof approvalRecordSchema>;

export const CONTRACT_TERMINAL_STATES = Object.freeze([
  "settled",
  "no_agreement",
  "verification_failed",
  "blocked_by_policy",
  "budget_exhausted",
  "harness_error",
  "cancelled",
  // Half-bound run release: a run still missing a party once its handshake
  // certificate can no longer verify (validUntil + grace) can never complete.
  "expired_unbound",
] as const);

const terminalState = z.enum(CONTRACT_TERMINAL_STATES);

const inboxMessage = z.object({
  messageId: z.string().min(4).max(64),
  kind: z.enum(["handshake_invitation", "business_message"]),
  // LOW (N4b-3): the sender's token-pinned identity, so the provider's signer
  // can check the delivered handshake names that buyer's agentId.
  senderKeyId: z.string().min(1).max(64).optional(),
  // D8: null when the sender hadn't proven an agentId yet (unbound `*`).
  senderAgentId: z.string().min(1).max(32).nullable().optional(),
  senderProof: z.enum(["token-pinned", "certificate-bound", "unproven-pre-bind"]).optional(),
  listingId: listingId.optional(),
  sealedPayload: sealedBox.optional(),
  body: z.unknown().optional(),
  receivedAt: isoDateTime,
}).strict();

const simItinerary = opaqueRecord;
const ticketRecord = opaqueRecord;

export interface ContractToolDef {
  readonly name: string;
  readonly role: ContractToolRoleScope;
  /** Input schema as a zod raw shape (registerTool-compatible). */
  readonly schema: z.ZodRawShape;
  /** Success-output schema. Refusals use `contractRefusalSchema`. */
  readonly outputSchema: z.ZodTypeAny;
  readonly readOnly: boolean;
  /** Sim-backed outputs must carry `simulated: true`. */
  readonly simulated: boolean;
  /**
   * M5 (default off): a tool that exists only while this feature is on.
   * Off, it is absent from tools/list and its name is NOT_FOUND.
   */
  readonly feature?: ContractFeature;
  /**
   * M5: input fields of `schema` that exist only while a feature is on. Off,
   * they are absent from the wire schema and refused as unknown keys.
   */
  readonly featureFields?: Readonly<Partial<Record<ContractFeature, readonly string[]>>>;
}

/**
 * M5: env-gated surface features. Every one is off unless its env is set, and
 * with all off the served surface (tools/list, guidance digests, accepted
 * arguments) is byte-identical to b04059e.
 * - `directory`: CONTRACT_DIRECTORY (O-2 directory names, standing listings,
 *   inbox long-poll, rendezvous_ack).
 * - `policyRegistration`: CONTRACT_POLICY_REGISTRATION=1.
 * - `briefs`: CONTRACT_BRIEFS.
 */
export type ContractFeature = "directory" | "policyRegistration" | "briefs";
export type ContractFeatures = Readonly<Partial<Record<ContractFeature, boolean>>>;
export const NO_CONTRACT_FEATURES: ContractFeatures = Object.freeze({});
export const ALL_CONTRACT_FEATURES: ContractFeatures = Object.freeze({
  directory: true, policyRegistration: true, briefs: true,
});

const envelopeOut = { envelope: prepareEnvelopeSchema, serverNonce } as const;

/** A server-side anchor outcome (terms / brief / final) as contract_status and the brief result report it. */
const serverAnchorState = z.object({
  status: z.enum(["anchoring", "pending", "anchored", "failed"]),
  digest: digestHex,
  anchorId: z.string().min(1).max(160).nullable(),
  eventHash: digestHex.nullable(),
  ledger: z.object({
    ledgerId: z.string(),
    blockHeight: z.string().nullable(),
    time: z.string().nullable(),
    status: z.string(),
  }).strict().nullable(),
  error: z.string().nullable(),
}).strict();

export const CONTRACT_TOOL_DEFS: readonly ContractToolDef[] = Object.freeze<ContractToolDef[]>([
  // -- rendezvous / discovery ------------------------------------------------
  {
    name: "rendezvous_publish_listing",
    role: "provider",
    schema: {
      title: z.string().min(4).max(128),
      summary: z.string().min(1).max(1024),
      sealedBoxPublicKeyHex: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
      terms: opaqueRecord.optional(),
      // O-2: claim a directory name pinned to this keyId (CONTRACT_DIRECTORY);
      // `standing` (directory listings only) is never consumed by a bind.
      directoryName: directoryName.optional(),
      standing: z.boolean().optional(),
    },
    featureFields: { directory: ["directoryName", "standing"] },
    outputSchema: z.object({
      listingId,
      publishedAt: isoDateTime,
      // O-2: directory listings only.
      directoryName: directoryName.optional(),
      standing: z.boolean().optional(),
      expiresAt: isoDateTime.optional(),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "rendezvous_search",
    role: "buyer",
    schema: {
      origin: z.string().min(2).max(64),
      destination: z.string().min(2).max(64),
      departDate: isoDate.optional(),
      returnDate: isoDate.optional(),
      // O-2: only the listing the pinned provider published under this name.
      name: directoryName.optional(),
    },
    featureFields: { directory: ["name"] },
    outputSchema: z.object({
      listings: z.array(z.object({
        listingId,
        title: z.string(),
        summary: z.string(),
        sealedBoxPublicKeyHex: z.string(),
        /** When this listing was first published — at most one live listing
         *  per provider (a newer publish supersedes the old one). */
        publishedAt: isoDateTime,
        // O-2: present on directory-pinned listings only.
        directoryName: directoryName.optional(),
        standing: z.boolean().optional(),
      }).strict()),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
  {
    name: "rendezvous_send_invitation",
    role: "buyer",
    schema: {
      listingId,
      sealedInvitation: sealedBox,
    },
    outputSchema: z.object({
      delivered: z.literal(true),
      deliveredAt: isoDateTime,
      // D8: the stamped identity and how it was proven — null/unproven when
      // an unbound `*` principal delivered pre-handshake.
      senderAgentId: z.string().min(1).max(32).nullable(),
      senderProof: z.enum(["token-pinned", "certificate-bound", "unproven-pre-bind"]),
      invitationExpiresAt: isoDateTime.optional(),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "rendezvous_inbox",
    role: "both",
    schema: {
      since: isoDateTime.optional(),
      // O-2 long-poll: hold the read up to this long for a delivery.
      waitMs: z.number().int().min(0).max(25_000).optional(),
    },
    featureFields: { directory: ["waitMs"] },
    outputSchema: z.object({
      messages: z.array(inboxMessage),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
  {
    // O-2: consume delivered inbox messages one by one (standing listings).
    name: "rendezvous_ack",
    role: "provider",
    feature: "directory",
    schema: {
      messageIds: z.array(z.string().min(4).max(64)).min(1).max(64),
    },
    outputSchema: z.object({
      acked: z.number().int().nonnegative(),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  // -- binding / mandate -----------------------------------------------------
  {
    // N4b-7 (P-GAP): issues the single-use, short-TTL challenge a caller
    // signs into its DRAFT bindStatement to prove it possesses the handshake
    // session key of the certificate side it claims.
    name: "contract_bind_challenge",
    role: "both",
    schema: {},
    outputSchema: z.object({
      challenge: z.string().regex(/^[0-9a-f]{64}$/),
      expiresAt: isoDateTime,
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "contract_bind",
    role: "both",
    schema: {
      /**
       * By reference (preferred): the handshake session id. The server
       * resolves that session's closing certificate itself and verifies it
       * exactly as a presented one — the caller never carries the signed
       * object. At least one of handshakeSessionId / certificate is required;
       * when both are given they must name the same certificate.
       */
      handshakeSessionId: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/).optional(),
      /** Legacy: the full certificate envelope, byte-for-byte. */
      certificate: opaqueRecord.optional(),
      signerKey: registeredKey,
      approvalKey: registeredKey,
      /** LOW (N4b-3): providers name the listing the handshake came through —
       *  only that listing is consumed, not every listing they own. */
      listingId: listingId.optional(),
      /**
       * DRAFT (N4b-7 P-GAP hook): optional session-key possession proof.
       * The statement binds domain/runId/side/tokenKeyId/serverKeyId plus a
       * single-use `contract_bind_challenge` nonce; `bindStatementSignature`
       * is the party's EIP-191 signature over canonicalDigest(statement) and
       * must recover to the certificate party's `sessionKeyAddress`. The
       * audit agent owns the final schema (PR #159) — verification lives in
       * one function so this shape is a one-place change.
       */
      bindStatement: bindStatementSchema.optional(),
      bindStatementSignature: signatureHex.optional(),
    },
    outputSchema: z.object({
      runId: z.string().min(4).max(128),
      role: z.enum(["buyer", "provider"]),
      bound: z.literal(true),
      boundAt: isoDateTime,
      side: z.enum(["initiator", "responder"]).optional(),
      serverNonce,
      bindMode: z.enum(["static", "late"]).optional(),
      bindStatement: z.enum(["verified", "absent"]).optional(),
      bindAssurance: z.enum([
        "agentId-pinned-token",
        "late-certificate-party",
        "session-key-possession",
      ]).optional(),
      idempotent: z.literal(true).optional(),
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "mandate_prepare",
    role: "buyer",
    schema: {
      // The mandate is the family principal's statement (rev 6.5): the buyer
      // agent PRESENTS it plus the principal's EIP-191 signature; it can
      // neither create nor alter it.
      mandate: opaqueRecord,
      mandateSignature: signatureHex,
    },
    outputSchema: z.object({
      ...envelopeOut,
      mandateDigest: digestHex,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "mandate_submit",
    role: "buyer",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
    },
    outputSchema: z.object({
      bound: z.literal(true),
      mandateDigest: digestHex,
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  // -- catalog / negotiation ---------------------------------------------------
  {
    name: "catalog_quote",
    role: "provider",
    schema: {
      origin: z.string().min(2).max(64),
      destination: z.string().min(2).max(64),
      departDate: isoDate.optional(),
      returnDate: isoDate.optional(),
    },
    outputSchema: z.object({
      itineraries: z.array(simItinerary),
      simulated: z.literal(true),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: true,
  },
  {
    name: "offer_prepare",
    role: "both",
    schema: {
      itineraryId: z.string().min(4).max(64),
      feeMinor: z.number().int().nonnegative().max(10_000_000),
      note: z.string().max(280).optional(),
    },
    outputSchema: z.object({
      ...envelopeOut,
      quote: z.object({
        fareMinor: z.number().int().nonnegative(),
        feeMinor: z.number().int().nonnegative(),
        totalMinor: z.number().int().nonnegative(),
        currency: z.string().min(3).max(8),
      }).strict(),
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "offer_submit",
    role: "both",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
    },
    outputSchema: z.object({
      offerId,
      state: z.literal("offered"),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "offer_accept_prepare",
    role: "both",
    schema: {
      offerId,
    },
    outputSchema: z.object({ ...envelopeOut }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "offer_accept_submit",
    role: "both",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
    },
    outputSchema: z.object({
      agreementFormed: z.boolean(),
      agreementId: agreementId.optional(),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "offer_reject",
    role: "both",
    schema: {
      offerId,
      reason: z.string().max(512).optional(),
    },
    outputSchema: z.object({
      state: z.literal("rejected"),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "contract_withdraw",
    role: "both",
    schema: {
      reason: z.string().max(512).optional(),
    },
    outputSchema: z.object({
      state: z.literal("withdrawn"),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "agreement_get",
    role: "both",
    schema: {},
    outputSchema: z.object({
      agreement: opaqueRecord.nullable(),
      anchor: opaqueRecord.nullable(),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
  // -- booking / verification / settlement -------------------------------------
  {
    name: "booking_prepare",
    role: "provider",
    schema: {
      agreementId,
    },
    outputSchema: z.object({ ...envelopeOut }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "booking_execute",
    role: "provider",
    schema: {
      envelope: prepareEnvelopeSchema,
      // N4b-9 (F15 → D11): absent = a deny submission (envelope + signed
      // deny approval only); present = an authorized submit.
      signatureHex: signatureHex.optional(),
      approval: approvalRecordSchema,
    },
    outputSchema: z.object({
      orderRef,
      pnr: z.string().min(4).max(16),
      tickets: z.array(ticketRecord),
      simulated: z.literal(true),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: true,
  },
  {
    name: "booking_lookup",
    role: "buyer",
    schema: {
      orderRef,
    },
    outputSchema: z.object({
      observation: opaqueRecord,
      simulated: z.literal(true),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: true,
  },
  {
    // N4b-4: provider-side cancel before settlement — prepare → local sign →
    // submit (v2 payload kind "cancel"), gated by a booking-class approval.
    name: "booking_cancel_prepare",
    role: "provider",
    schema: {
      // Frozen enum (CONTRACT-PAYLOADS-v2 §Cancel, rev 6.7) — never free text;
      // the run-state match is enforced in business.dispatch.
      reason: z.enum(["verification_mismatch", "verification_failed", "mutual_withdrawal"]),
    },
    outputSchema: z.object({ ...envelopeOut }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "booking_cancel_submit",
    role: "provider",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
      approval: approvalRecordSchema,
    },
    outputSchema: z.object({
      orderRef,
      status: z.literal("CANCELLED"),
      cancelledAt: isoDateTime,
      // N4b-9 (F11): the run's true terminal state — "cancelled" for a clean
      // cancel; a cleanup cancel after verification_failed reports that.
      terminalState,
      simulated: z.literal(true),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: true,
  },
  {
    name: "verification_prepare",
    role: "buyer",
    schema: {
      orderRef,
      result: z.enum(["match", "mismatch"]),
      // The agent supplies the digest of its own findings document (v2).
      findingsDigest: digestHex,
    },
    outputSchema: z.object({ ...envelopeOut }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "verification_submit",
    role: "buyer",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
    },
    outputSchema: z.object({
      outcome: z.enum(["match", "mismatch"]),
      verificationDigest: digestHex,
      flagged: z.boolean(),
      // Present when the verification ended the run (any mismatch is terminal).
      terminalState: z.literal("verification_failed").optional(),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "settlement_prepare",
    role: "buyer",
    schema: {},
    // N4b-10 (D13): the Stripe rail may answer a non-envelope status body —
    // awaiting_stripe_test_key (honest stop, no intent created) or a
    // code-only failed creation. Either is receipted and terminal-neutral.
    outputSchema: z.union([
      z.object({ ...envelopeOut }).strict(),
      z.object({
        status: z.enum(["awaiting_stripe_test_key", "failed"]),
        paymentRail: z.enum(["simulated", "stripe_test_mode"]),
        error: z.string().min(1).max(160).optional(),
        label: z.string().min(1).max(128).optional(),
        simulated: z.literal(true),
        serverNonce,
      }).strict(),
    ]),
    readOnly: false,
    simulated: false,
  },
  {
    name: "settlement_authorize",
    role: "buyer",
    schema: {
      envelope: prepareEnvelopeSchema,
      // N4b-9 (F15 → D11): absent = a deny submission (envelope + signed
      // deny approval only); present = an authorized submit.
      signatureHex: signatureHex.optional(),
      approval: approvalRecordSchema,
    },
    outputSchema: z.object({
      // N4b-10 (D13): transferId absent on a code-only rail failure.
      transferId: z.string().min(4).max(64).optional(),
      status: z.enum(["authorized", "released", "failed"]),
      paymentRail: z.enum(["simulated", "stripe_test_mode"]).optional(),
      paymentIntentId: z.string().min(4).max(128).optional(),
      stripeStatus: z.string().min(1).max(64).optional(),
      error: z.string().min(1).max(160).optional(),
      label: z.string().min(1).max(128).optional(),
      simulated: z.literal(true),
      commercialTransfer: z.literal(false),
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: true,
  },
  {
    name: "settlement_status",
    role: "both",
    schema: {},
    outputSchema: z.object({
      state: z.enum([
        "none", "prepared", "authorized", "released", "failed",
        // N4b-10 (D13): the Stripe rail is configured but unkeyed — the
        // honest stop, no PaymentIntent exists.
        "awaiting_stripe_test_key",
      ]),
      transferId: z.string().min(4).max(64).optional(),
      paymentRail: z.enum(["simulated", "stripe_test_mode"]).optional(),
      paymentIntentId: z.string().min(4).max(128).optional(),
      stripeStatus: z.string().min(1).max(64).optional(),
      label: z.string().min(1).max(128).optional(),
      simulated: z.literal(true),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: true,
  },
  {
    name: "contract_status",
    role: "both",
    schema: {},
    outputSchema: z.object({
      stage: z.enum([
        "rendezvous",
        "handshake",
        "bound",
        "mandated",
        "negotiating",
        "agreed",
        "booked",
        "verified",
        "settled",
        "terminal",
      ]),
      terminalState: terminalState.nullable(),
      // PR #180 F4: present (true) only when the status is read pre-bind
      // from an ENDED run — that run is the caller's PRIOR run, and the
      // caller may bind a new one.
      priorRun: z.literal(true).optional(),
      canBind: z.literal(true).optional(),
      // N4b-10 (D13): settlement rail visibility — absent on pre-bind and
      // recovered-terminal statuses (the durable job carries no rail state).
      settlement: z.object({
        paymentRail: z.enum(["simulated", "stripe_test_mode"]),
        awaitingStripeTestKey: z.boolean(),
        paymentIntentId: z.string().min(4).max(128).optional(),
        stripeStatus: z.string().min(1).max(64).optional(),
      }).strict().optional(),
      // N4b-8 (gap 3): telemetry close delivery state — null until the run
      // reaches a terminal state; "failed" stays visible forever.
      telemetryClose: z.object({
        status: z.enum(["delivering", "delivered", "failed"]),
        attempts: z.number().int().nonnegative(),
        lastError: z.string().nullable(),
        deliveredAt: z.string().nullable(),
        receiptDigest: digestHex,
      }).strict().nullable(),
      // N4b-8 (gap 4): anchor summary — "failed" surfaces an anchoring
      // failure (never silent), "disabled" when no anchor is configured.
      anchor: z.enum(["disabled", "ok", "pending", "failed"]).nullable(),
      anchors: z.object({
        agreement: z.object({
          // N4b-9 (F13): "pending" = write resolved but block/time not yet
          // confirmed — NOT anchored.
          status: z.enum(["anchoring", "pending", "anchored", "failed"]),
          digest: digestHex,
          anchorId: z.string().min(1).max(160).nullable(),
          eventHash: digestHex.nullable(),
          ledger: z.object({
            ledgerId: z.string(),
            blockHeight: z.string().nullable(),
            time: z.string().nullable(),
            status: z.string(),
          }).strict().nullable(),
          error: z.string().nullable(),
        }).strict().nullable(),
        terminal: z.object({
          status: z.enum(["anchoring", "pending", "anchored", "failed"]),
          digest: digestHex,
          anchorId: z.string().min(1).max(160).nullable(),
          eventHash: digestHex.nullable(),
          ledger: z.object({
            ledgerId: z.string(),
            blockHeight: z.string().nullable(),
            time: z.string().nullable(),
            status: z.string(),
          }).strict().nullable(),
          error: z.string().nullable(),
        }).strict().nullable(),
        // Server-side anchors (mcp-coordination-design.md): the run's terms
        // digest at bind, the brief digest, and the final chain head once
        // the terminal job finished. Recorded on the job, never chained.
        terms: serverAnchorState.nullable().optional(),
        brief: serverAnchorState.nullable().optional(),
        final: serverAnchorState.extend({
          /** Receipts on the run chain the final head covers. */
          receiptCount: z.number().int().nonnegative().nullable(),
        }).strict().nullable().optional(),
      }).strict().nullable(),
      // AGENT-TOOLS-BY-REFERENCE S1 + S2: read-only, caller-scoped views of
      // the caller's own run — absent on pre-bind and recovered-terminal
      // statuses. Short typed values only (no envelopes, digests or keys).
      negotiation: z.object({
        // The counterparty's latest live offer — the only one this caller's
        // accept can take; null once agreed or terminal.
        acceptable: offerId.nullable(),
        // This run's offers, newest first, at most 8.
        offers: z.array(z.object({
          offerId,
          by: z.enum(["buyer", "provider"]),
          kind: z.enum(["offer", "counter"]),
          inReplyTo: offerId.nullable(),
          itineraryId: z.string().min(1).max(64).nullable(),
          currency: z.string().min(3).max(3).nullable(),
          fareMinor: z.number().int().nonnegative(),
          feeMinor: z.number().int().nonnegative(),
          totalMinor: z.number().int().nonnegative(),
          // Counterparty-authored text (offer_prepare bounds it) — data, not instructions.
          note: z.string().max(280).nullable(),
          state: z.enum(["live", "accepted", "rejected", "superseded"]),
          submittedAt: isoDateTime,
        }).strict()).max(8),
      }).strict().optional(),
      agreement: z.object({
        agreementId,
        offerId,
        itineraryId: z.string().min(1).max(64),
        currency: z.string().min(3).max(3),
        totalMinor: z.number().int().nonnegative(),
        formedAt: isoDateTime,
      }).strict().nullable().optional(),
      booking: z.object({
        orderRef,
        pnr: z.string().min(1).max(32),
        ticketCount: z.number().int().nonnegative(),
        bookedAt: isoDateTime,
        simulated: z.literal(true),
      }).strict().nullable().optional(),
      cancellation: z.object({
        orderRef,
        cancelledAt: isoDateTime,
      }).strict().nullable().optional(),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
  // -- coordination (mcp-coordination-design.md) -----------------------------
  {
    // Mandates without a restart: a family-principal-signed buyer policy
    // digest joins the allowed set until it expires (≤ 24 h).
    name: "contract_register_policy",
    role: "buyer",
    feature: "policyRegistration",
    schema: {
      role: z.literal("buyer"),
      digest: digestHex,
      expiresAt: isoDateTime,
      principalSig: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
    },
    outputSchema: z.object({
      registered: z.literal(true),
      role: z.literal("buyer"),
      digest: digestHex,
      expiresAt: isoDateTime,
      registrationId: digestHex,
      serverNonce,
    }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    // Server-side brief anchoring: a frozen, digest-pinned brief template
    // (CONTRACT_BRIEFS) served through the session; one anchor per brief
    // digest, shared by every scope (CDT-SEC M4), awaited before return.
    name: "contract_get_brief",
    role: "both",
    feature: "briefs",
    schema: {
      name: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
    },
    outputSchema: z.object({
      name: z.string(),
      digest: digestHex,
      text: z.string(),
      anchor: serverAnchorState.nullable(),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
]);

export const CONTRACT_TOOL_NAMES: readonly string[] = Object.freeze(
  CONTRACT_TOOL_DEFS.map((def) => def.name),
);

/** Stable cache key of a feature set (only the features that are on). */
export function featureKey(features: ContractFeatures): string {
  return (Object.keys(features) as ContractFeature[]).filter((f) => features[f] === true).sort().join(",");
}

const servedCache = new Map<string, ContractToolDef | null>();

/**
 * M5: the definition as SERVED under `features` — undefined when the tool's
 * feature is off; otherwise the def with every off-feature field removed.
 */
function servedDef(def: ContractToolDef, features: ContractFeatures): ContractToolDef | undefined {
  const key = `${def.name}|${featureKey(features)}`;
  const hit = servedCache.get(key);
  if (hit !== undefined) return hit ?? undefined;
  let out: ContractToolDef | null = def;
  if (def.feature !== undefined && features[def.feature] !== true) {
    out = null;
  } else if (def.featureFields !== undefined) {
    const drop = new Set<string>();
    for (const [f, keys] of Object.entries(def.featureFields) as [ContractFeature, readonly string[]][]) {
      if (features[f] !== true) for (const k of keys) drop.add(k);
    }
    if (drop.size > 0) {
      const schema: z.ZodRawShape = {};
      for (const [k, v] of Object.entries(def.schema)) if (!drop.has(k)) schema[k] = v;
      out = Object.freeze({ ...def, schema });
    }
  }
  servedCache.set(key, out);
  return out ?? undefined;
}

/**
 * The tools one role may see and call under `features` (default: none on —
 * the b04059e surface): its own tools plus shared ones.
 */
export function toolDefsForRole(
  role: ContractRole,
  features: ContractFeatures = NO_CONTRACT_FEATURES,
): readonly ContractToolDef[] {
  return CONTRACT_TOOL_DEFS
    .filter((def) => def.role === "both" || def.role === role)
    .map((def) => servedDef(def, features))
    .filter((def): def is ContractToolDef => def !== undefined);
}

const toolIndex = new Map(CONTRACT_TOOL_DEFS.map((def) => [def.name, def]));

/**
 * Without `features`: the catalogue entry (every feature's fields). With
 * `features`: the served definition, undefined when its feature is off.
 */
export function contractToolDef(name: string, features?: ContractFeatures): ContractToolDef | undefined {
  const def = toolIndex.get(name);
  if (def === undefined || features === undefined) return def;
  return servedDef(def, features);
}
