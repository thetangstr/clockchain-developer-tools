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
const orderRef = z.string().min(4).max(32);
const offerId = z.string().min(4).max(64);
const agreementId = z.string().min(4).max(64);

const registeredKey = z.object({
  keyId,
  publicKeyHex,
}).strict();

/**
 * The real v2 rendezvous seal (N5 `sealTo`, CONTRACT-PAYLOADS-v2 §Seal):
 * ephemeral-x25519 → HKDF → AES-256-GCM, all fields 0x-hex — epk 32B,
 * iv 12B, tag 16B. Anything else refuses at the schema, so a malformed
 * delivery can never reach — let alone burn — a listing.
 */
const sealedBox = z.object({
  v: z.literal(2),
  epk: z.string().regex(/^0x[0-9a-f]{64}$/),
  iv: z.string().regex(/^0x[0-9a-f]{24}$/),
  ct: z.string().regex(/^0x(?:[0-9a-f]{2}){1,8192}$/),
  tag: z.string().regex(/^0x[0-9a-f]{32}$/),
}).strict();
export const sealedBoxV2Schema = sealedBox;

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
] as const);

const terminalState = z.enum(CONTRACT_TERMINAL_STATES);

const inboxMessage = z.object({
  messageId: z.string().min(4).max(64),
  kind: z.enum(["handshake_invitation", "business_message"]),
  // LOW (N4b-3): the sender's token-pinned identity, so the provider's signer
  // can check the delivered handshake names that buyer's agentId.
  senderKeyId: z.string().min(1).max(64).optional(),
  senderAgentId: z.string().min(1).max(32).optional(),
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
}

const envelopeOut = { envelope: prepareEnvelopeSchema, serverNonce } as const;

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
    },
    outputSchema: z.object({
      listingId,
      publishedAt: isoDateTime,
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
    },
    outputSchema: z.object({
      listings: z.array(z.object({
        listingId,
        title: z.string(),
        summary: z.string(),
        sealedBoxPublicKeyHex: z.string(),
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
    },
    outputSchema: z.object({
      messages: z.array(inboxMessage),
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
  // -- binding / mandate -----------------------------------------------------
  {
    name: "contract_bind",
    role: "both",
    schema: {
      certificate: opaqueRecord,
      signerKey: registeredKey,
      approvalKey: registeredKey,
      /** LOW (N4b-3): providers name the listing the handshake came through —
       *  only that listing is consumed, not every listing they own. */
      listingId: listingId.optional(),
    },
    outputSchema: z.object({
      runId: z.string().min(4).max(128),
      role: z.enum(["buyer", "provider"]),
      bound: z.literal(true),
      boundAt: isoDateTime,
      serverNonce,
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
      signatureHex,
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
      reason: z.string().min(1).max(512),
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
      terminalState: z.literal("cancelled"),
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
    outputSchema: z.object({ ...envelopeOut }).strict(),
    readOnly: false,
    simulated: false,
  },
  {
    name: "settlement_authorize",
    role: "buyer",
    schema: {
      envelope: prepareEnvelopeSchema,
      signatureHex,
      approval: approvalRecordSchema,
    },
    outputSchema: z.object({
      transferId: z.string().min(4).max(64),
      status: z.enum(["authorized", "released", "failed"]),
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
      state: z.enum(["none", "prepared", "authorized", "released", "failed"]),
      transferId: z.string().min(4).max(64).optional(),
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
      serverNonce,
    }).strict(),
    readOnly: true,
    simulated: false,
  },
]);

export const CONTRACT_TOOL_NAMES: readonly string[] = Object.freeze(
  CONTRACT_TOOL_DEFS.map((def) => def.name),
);

/** The tools one role may see and call: its own tools plus shared ones. */
export function toolDefsForRole(role: ContractRole): readonly ContractToolDef[] {
  return CONTRACT_TOOL_DEFS.filter((def) => def.role === "both" || def.role === role);
}

const toolIndex = new Map(CONTRACT_TOOL_DEFS.map((def) => [def.name, def]));

export function contractToolDef(name: string): ContractToolDef | undefined {
  return toolIndex.get(name);
}
