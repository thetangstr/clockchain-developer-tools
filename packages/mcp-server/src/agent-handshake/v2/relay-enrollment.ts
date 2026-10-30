// H-REQ-01: sender enrollments bind each relay role to exactly one sender key.
//
// A relay envelope's role label is a statement by whoever signed it. The
// coordinator, which mints and redeems the session's invitation, says which
// key speaks for each role with a sender enrollment: an Ed25519 signature,
// under the coordinator's enrollment key, over the canonical bytes of
//
//   {schema, protocol, sessionId, role, senderKey, statementDigest,
//    sessionDeadlineMs, invitationDigest, claimExpiresAtMs,
//    event, eventAtMs, issuedAtMs, externalBusinessActionPerformed}
//
// The initiator is enrolled at the mint (event "minted"), the responder at the
// redemption (event "redeemed"); both name the same invitationDigest and
// claimExpiresAtMs. The enrollment is the body of the role's FIRST relay
// message (kind agent_v2_sender_enrollment), signed by the key it enrolls.
//
// This is the coordinator-side port of the handshake repo's
// src/agent-handshake/v2/relay-enrollment.mjs (signSenderEnrollment and the
// enrollment validation it applies before signing). The bytes are pinned by
// test/fixtures/agent-handshake-v2-sender-enrollment.json: UTF-8 JSON, keys
// sorted by code unit, no whitespace, millisecond values as decimal strings.
import { createPrivateKey, sign, type KeyObject } from "node:crypto";

import { canonicalBytes } from "../../handshake/protocol.js";

export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND = "agent_v2_sender_enrollment";
export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA = "clockchain.agent-handshake-sender-enrollment/v1";
export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_EVENTS = Object.freeze({
  initiator: "minted",
  responder: "redeemed",
} as const);

export type V2SenderEnrollmentKey = Readonly<{ kid: string; privateKeyPem: string }>;
type JsonRecord = Record<string, any>;

const PROTOCOL = "clockchain.agent-handshake/v2";
const ROLES = ["initiator", "responder"];
const ENROLLMENT_KEYS = Object.freeze([
  "schema", "protocol", "sessionId", "role", "senderKey", "statementDigest",
  "sessionDeadlineMs", "invitationDigest", "claimExpiresAtMs", "event",
  "eventAtMs", "issuedAtMs", "externalBusinessActionPerformed",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export class AgentHandshakeV2SenderEnrollmentError extends Error {
  constructor() {
    super("Agent handshake v2 sender enrollment verification failed.");
    this.name = "AgentHandshakeV2SenderEnrollmentError";
  }
}

function invalid(): never {
  throw new AgentHandshakeV2SenderEnrollmentError();
}

function exact(value: unknown, keys: readonly string[]): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
  const result: JsonRecord = {};
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function rawKey(value: unknown): string {
  if (typeof value !== "string" || !BASE64.test(value)) invalid();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== value) invalid();
  return value;
}

function milliseconds(value: unknown): number {
  if (typeof value !== "string" || !DECIMAL.test(value)) invalid();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) invalid();
  return parsed;
}

export function validateSenderEnrollment(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ENROLLMENT_KEYS);
  if (
    item.schema !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA ||
    item.protocol !== PROTOCOL ||
    typeof item.sessionId !== "string" || !UUID.test(item.sessionId) ||
    !ROLES.includes(item.role) ||
    item.event !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_EVENTS[item.role as "initiator" | "responder"] ||
    typeof item.statementDigest !== "string" || !DIGEST.test(item.statementDigest) ||
    typeof item.invitationDigest !== "string" || !DIGEST.test(item.invitationDigest) ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  rawKey(item.senderKey);
  const sessionDeadlineMs = milliseconds(item.sessionDeadlineMs);
  const claimExpiresAtMs = milliseconds(item.claimExpiresAtMs);
  const eventAtMs = milliseconds(item.eventAtMs);
  const issuedAtMs = milliseconds(item.issuedAtMs);
  if (
    eventAtMs > issuedAtMs ||
    issuedAtMs >= sessionDeadlineMs ||
    (item.event === "minted" && claimExpiresAtMs <= eventAtMs)
  ) invalid();
  return Object.freeze(item);
}

// The signed relay message body: {enrollment, coordinatorSignature,
// externalBusinessActionPerformed}, Ed25519 over canonicalBytes(enrollment),
// base64 with padding.
export function signSenderEnrollment(input: { enrollment: unknown; keyId: string; privateKeyPem: string }): Readonly<JsonRecord> {
  const enrollment = validateSenderEnrollment(input.enrollment);
  if (typeof input.keyId !== "string" || !KID.test(input.keyId)) invalid();
  let privateKey: KeyObject;
  try { privateKey = createPrivateKey(input.privateKeyPem); } catch { invalid(); }
  if (privateKey.asymmetricKeyType !== "ed25519") invalid();
  return Object.freeze({
    enrollment,
    coordinatorSignature: Object.freeze({
      algorithm: "ed25519",
      keyId: input.keyId,
      signature: sign(null, canonicalBytes(enrollment), privateKey).toString("base64"),
    }),
    externalBusinessActionPerformed: false,
  });
}
