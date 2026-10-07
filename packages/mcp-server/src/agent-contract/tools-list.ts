import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import {
  CONTRACT_TOOL_DEFS, NO_CONTRACT_FEATURES, featureKey, toolDefsForRole,
  type ContractFeature, type ContractFeatures, type ContractRole,
} from "./schemas.js";

/**
 * Role-scoped `tools/list` payloads and server instructions for
 * `/contract/mcp` (LLD §3 "Server guidance must be uniform", §9 R10).
 *
 * `toolsListForRole` returns the exact JSON structure the transport serves —
 * including the JSON Schema of each input — so `guidanceDigests` digests the
 * wire form itself and the verifier can recompute it from what an agent
 * actually received. The HTTP layer (N4b) must serve these payloads verbatim.
 *
 * Descriptions and instructions state the workflow in prose — what exists and
 * what each stage requires — never a numbered order of calls (R10), and no
 * description names another tool.
 */

/** Minimal deterministic zod→JSON-Schema renderer covering only the zod subset this module uses. */
export function toWireSchema(t: z.ZodTypeAny): Record<string, unknown> {
  const def = t._def as Record<string, unknown>;
  switch (def.typeName) {
    case "ZodString": {
      const out: Record<string, unknown> = { type: "string" };
      for (const check of (def.checks ?? []) as { kind: string; value?: number; regex?: RegExp }[]) {
        if (check.kind === "min") out.minLength = check.value;
        else if (check.kind === "max") out.maxLength = check.value;
        else if (check.kind === "regex") out.pattern = check.regex!.source;
        else if (check.kind === "datetime") out.format = "date-time";
      }
      return out;
    }
    case "ZodNumber": {
      const out: Record<string, unknown> = { type: "integer" };
      for (const check of (def.checks ?? []) as { kind: string; value?: number; inclusive?: boolean }[]) {
        if (check.kind === "int") out.type = "integer";
        else if (check.kind === "min") {
          out[check.inclusive === false ? "exclusiveMinimum" : "minimum"] = check.value;
        } else if (check.kind === "max") {
          out[check.inclusive === false ? "exclusiveMaximum" : "maximum"] = check.value;
        }
      }
      return out;
    }
    case "ZodBoolean":
      return { type: "boolean" };
    case "ZodLiteral":
      return { const: def.value };
    case "ZodEnum":
      return { enum: [...(def.values as string[])] };
    case "ZodOptional":
    case "ZodNullable":
      return toWireSchema(def.innerType as z.ZodTypeAny);
    case "ZodArray": {
      const out: Record<string, unknown> = { type: "array", items: toWireSchema(def.type as z.ZodTypeAny) };
      const min = def.minLength as { value: number } | null;
      const max = def.maxLength as { value: number } | null;
      if (min) out.minItems = min.value;
      if (max) out.maxItems = max.value;
      return out;
    }
    case "ZodRecord":
      return { type: "object", additionalProperties: toWireSchema(def.valueType as z.ZodTypeAny) };
    case "ZodObject": {
      const shape = (def.shape as () => z.ZodRawShape)();
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const key of Object.keys(shape)) {
        properties[key] = toWireSchema(shape[key]);
        if (!(shape[key] instanceof z.ZodOptional)) required.push(key);
      }
      const out: Record<string, unknown> = { type: "object", properties };
      if (required.length > 0) out.required = required;
      out.additionalProperties = false;
      return out;
    }
    case "ZodUnion":
    case "ZodDiscriminatedUnion":
      return { anyOf: (def.options as z.ZodTypeAny[]).map((o) => toWireSchema(o)) };
    case "ZodUnknown":
    case "ZodAny":
      return {};
    default:
      throw new Error(`toWireSchema: unsupported zod type ${String(def.typeName)}`);
  }
}

interface ContractToolDescriptor {
  readonly name: string;
  readonly title: string;
  /** The b04059e description — served verbatim while every feature is off. */
  readonly description: string;
  /** M5: sentences appended (in feature order) only while that feature is on. */
  readonly featureDescription?: Readonly<Partial<Record<ContractFeature, string>>>;
}

const FEATURE_ORDER: readonly ContractFeature[] = ["directory", "policyRegistration", "briefs"];

function describe(descriptor: ContractToolDescriptor, features: ContractFeatures): string {
  const extra = FEATURE_ORDER
    .filter((f) => features[f] === true && descriptor.featureDescription?.[f] !== undefined)
    .map((f) => descriptor.featureDescription![f]!);
  return [descriptor.description, ...extra].join(" ");
}

/**
 * Descriptions state purpose and preconditions in prose. They name no other
 * tool and give no ordered steps — the test suite enforces both.
 */
const CONTRACT_TOOL_DESCRIPTORS: readonly ContractToolDescriptor[] = Object.freeze([
  { name: "rendezvous_publish_listing", title: "Publish a service listing", description: "Advertise this provider's service as a listing other parties can find, and accept sealed handshake invitations delivered to it. A provider holds one live listing: publishing a new listing (e.g. under a fresh seal key) supersedes this provider's previous listing(s), drops invitations still pending on them, and later deliveries to a superseded listing are refused LISTING_UNAVAILABLE. Requires a caller key bound to a registered identity.", featureDescription: { directory: "Optional directoryName claims a directory name; only the provider key the service pins to that name may use it. Optional standing (directory listings only) keeps the listing live across binds so it can serve many travelers; republish it before its expiresAt to renew it." } },
  { name: "rendezvous_search", title: "Search provider listings", description: "Search published provider listings for a route. Returns only each provider's latest listing, with its publishedAt time; an invitation to a superseded listing is refused LISTING_UNAVAILABLE — search again.", featureDescription: { directory: "Optional name returns only the listing published under that directory name by the provider pinned to it." } },
  { name: "rendezvous_send_invitation", title: "Deliver a sealed invitation", description: "Deliver a sealed Clockchain handshake responder invitation to one listing. The payload is sealed to the listing's public key, so this service can carry it but never open it. A listing holds pending invitations from multiple senders until the provider acts on one. Each delivery is stamped senderAgentId + senderProof: 'token-pinned' or 'certificate-bound' proves the sender's agentId now; 'unproven-pre-bind' (senderAgentId null) means the sender used a late-binding token before binding — authenticate them through the handshake and bind that follow, not by this stamp." },
  { name: "rendezvous_inbox", title: "Read your inbox", description: "Read sealed invitations and business messages addressed to this caller. Each message carries senderAgentId + senderProof — 'unproven-pre-bind' means the sender's agentId was not yet proven at delivery; trust it only after the handshake and bind complete.", featureDescription: { directory: "Optional waitMs, at most 25000 ms, holds the read until a delivery arrives or the wait ends, which returns an empty list." } },
  { name: "rendezvous_ack", title: "Acknowledge inbox messages", description: "Consume delivered inbox messages by messageId once they are handled. Each acknowledged message leaves this caller's inbox and frees its sender's pending slot on the listing; unknown ids are ignored. Deliveries to a standing listing that are never acknowledged expire after five minutes." },
  { name: "contract_bind_challenge", title: "Get a bind challenge", description: "Issue a single-use, short-lived challenge nonce to sign into a bind statement. The statement proves the caller possesses the handshake session key of the certificate side it claims (DRAFT schema)." },
  { name: "contract_bind", title: "Bind to a handshake session", description: "Bind this caller's business signing and approval keys to a closed, verified Clockchain handshake and join the contract session it names. Identify the handshake by its session id; the server resolves and verifies that session's closing certificate itself, so never copy or rebuild the certificate. A certificate may still be supplied, but it must match the resolved one exactly. Refused CERTIFICATE_NOT_READY (retryable) until the handshake has closed. Optionally carries a DRAFT bind statement — signed over a server-issued challenge — proving possession of the claimed side's handshake session key; its runId is the same session id." },
  { name: "mandate_prepare", title: "Prepare the mandate", description: "Prepare the family principal's signed mandate — caps, dates, travellers — for validation. Returns a server-signed envelope carrying the canonical mandate bytes." },
  { name: "mandate_submit", title: "Submit the mandate", description: "Submit a local signature over a prepared mandate envelope to bind the mandate's caps to this contract session. The principal signature inside the mandate is validated; caps are parsed and enforced from then on, but never disclosed." },
  { name: "catalog_quote", title: "Read the offer board", description: "Read the simulated offer board for a route: itineraries, fares and the fixed service fee. SIMULATED data." },
  { name: "offer_prepare", title: "Prepare an offer or counter", description: "Prepare an offer or counter-offer on a board itinerary with a service fee and an optional note. Returns a server-signed envelope quoting the board fare and the resulting total." },
  { name: "offer_submit", title: "Submit an offer", description: "Submit a local signature over a prepared offer envelope to make the offer live for the counterparty." },
  { name: "offer_accept_prepare", title: "Prepare an acceptance", description: "Prepare acceptance of the counterparty's live offer. Returns a server-signed envelope; the offer must still be live, the accepter must not be the offerer, and a buyer-side acceptance must still be within the buyer's mandate." },
  { name: "offer_accept_submit", title: "Submit an acceptance", description: "Submit a local signature over a prepared acceptance envelope. When both roles have signed, a binding agreement forms." },
  { name: "offer_reject", title: "Reject an offer", description: "Refuse a live offer. Negotiation may continue unless the contract is withdrawn." },
  { name: "contract_withdraw", title: "Withdraw from the contract", description: "Walk away from this contract session. Terminal for the negotiation." },
  { name: "agreement_get", title: "Read the agreement", description: "Read the formed agreement — both role signatures, its terms and its ledger anchor — if one exists." },
  { name: "booking_prepare", title: "Prepare the booking", description: "Prepare booking the agreed itinerary on the simulated ticketing system. Returns a server-signed envelope; execution additionally requires a signed approval record for the consequential action." },
  { name: "booking_execute", title: "Execute the booking", description: "Execute a prepared booking on the simulated ticketing system with a local signature and a signed approval record. Idempotent per agreement. SIMULATED booking." },
  { name: "booking_lookup", title: "Look up an order", description: "Look up an order's PNR and tickets directly in the simulated ticketing system. SIMULATED data." },
  { name: "booking_cancel_prepare", title: "Prepare a cancellation", description: "Prepare cancellation of the booked order on the simulated ticketing system. Returns a server-signed envelope; execution additionally requires a signed approval record. Available until the settlement authorizes." },
  { name: "booking_cancel_submit", title: "Submit a cancellation", description: "Submit a local signature over a prepared cancellation envelope with a signed approval record. Cancels the order on the simulated ticketing system and ends this contract session; a repeat submission returns the same outcome. SIMULATED cancellation." },
  { name: "verification_prepare", title: "Prepare a verification", description: "Prepare a verification result — match, or mismatch with findings — over the booked order. Returns a server-signed envelope; the service recomputes the result and flags disagreement." },
  { name: "verification_submit", title: "Submit a verification", description: "Submit a local signature over a prepared verification envelope. A mismatch blocks settlement." },
  { name: "settlement_prepare", title: "Prepare the settlement", description: "Prepare authorization of the simulated payment for exactly the agreement total. Returns a server-signed envelope; authorization additionally requires a signed approval record and a match verification. SIMULATED payment." },
  { name: "settlement_authorize", title: "Authorize the settlement", description: "Authorize the prepared simulated settlement with a local signature and a signed approval record. Requires a match verification and an amount equal to the agreement total. SIMULATED payment." },
  { name: "settlement_status", title: "Read settlement status", description: "Read the simulated settlement state for this contract session. SIMULATED." },
  { name: "contract_status", title: "Read contract status", description: "Read overall contract progress and terminal state. This is the resume anchor for both roles." },
  { name: "contract_register_policy", title: "Register a policy digest", description: "Register an approval policy digest for this buyer without a service restart. The registration must carry the family principal's signature over this server's signing key id and chain, this caller's key id, the digest and its expiry; the expiry may be at most a day ahead. A registration is single-use, counts for this caller's key id only, and stays capped per key." },
  { name: "contract_get_brief", title: "Read a brief", description: "Read a frozen brief template by name, with its pinned digest. The service anchors each brief digest once, the first time any caller is served it, and reports that anchor's outcome with the brief." },
]);

const descriptorIndex = new Map(CONTRACT_TOOL_DESCRIPTORS.map((d) => [d.name, d]));

for (const def of CONTRACT_TOOL_DEFS) {
  if (!descriptorIndex.has(def.name)) throw new Error(`tools-list: missing descriptor for ${def.name}`);
}

/**
 * Server instructions: uniform prose for every caller (R10). Describes what
 * the surface carries and what each stage requires — no tool names, no
 * ordered steps.
 */
export const CONTRACT_SERVER_INSTRUCTIONS = [
  "This surface carries the full travel Agent Contract workflow between two parties who each completed a Clockchain handshake.",
  "One party acts as buyer, the other as provider. Each sees only the operations its role can use, plus the shared read operations.",
  "Discovery happens through provider listings on this surface; a buyer delivers the handshake responder invitation to a listing as a sealed payload the service can carry but not open.",
  "A contract session begins when both parties bind their keys to the same verified handshake certificate.",
  "The buyer presents the family principal's signed mandate; its caps are enforced by this service and never disclosed.",
  "Negotiation is signed offers and counters over itineraries from the simulated offer board; a signed acceptance by the counterparty forms a binding agreement.",
  "Every mutating operation is a prepare step that returns a server-signed envelope, followed by a submit carrying the caller's local signature over exactly those bytes.",
  "Consequential actions — the simulated booking and the simulated settlement — additionally require a signed approval record from the caller's local policy.",
  "Ticketing and settlement are simulated and labelled as such in every response.",
  "Every call produces a signed, hash-chained receipt; the chain head is anchored at run end.",
].join(" ");

export interface ContractToolsListEntry {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: { readOnlyHint: boolean; openWorldHint: false };
}

export interface ContractToolsListPayload {
  tools: ContractToolsListEntry[];
}

/**
 * The exact role-scoped `tools/list` result the transport must serve
 * verbatim under `features` (default none — the b04059e payload).
 */
export function toolsListForRole(
  role: ContractRole,
  features: ContractFeatures = NO_CONTRACT_FEATURES,
): ContractToolsListPayload {
  return {
    tools: toolDefsForRole(role, features).map((def) => {
      const descriptor = descriptorIndex.get(def.name)!;
      return {
        name: def.name,
        title: descriptor.title,
        description: describe(descriptor, features),
        inputSchema: toWireSchema(z.object(def.schema).strict()),
        annotations: { readOnlyHint: def.readOnly, openWorldHint: false },
      };
    }),
  };
}

export interface GuidanceDigests {
  toolsListDigest: string;
  instructionsDigest: string;
}

const digestCache = new Map<string, GuidanceDigests>();

/**
 * Digests of this role's published guidance — the wire `tools/list` payload
 * and the instructions text — recorded per run (R10) and published on the
 * server card.
 */
export function guidanceDigests(
  role: ContractRole,
  features: ContractFeatures = NO_CONTRACT_FEATURES,
): GuidanceDigests {
  const cacheKey = `${role}|${featureKey(features)}`;
  const cached = digestCache.get(cacheKey);
  if (cached) return cached;
  const digests: GuidanceDigests = {
    toolsListDigest: canonicalDigest(toolsListForRole(role, features)),
    instructionsDigest: canonicalDigest({ instructions: CONTRACT_SERVER_INSTRUCTIONS }),
  };
  digestCache.set(cacheKey, digests);
  return digests;
}
