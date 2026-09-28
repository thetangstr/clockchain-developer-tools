import { canonicalBytes, digestHex } from "../handshake/protocol.js";

export const STANDALONE_HANDSHAKE_PROTOCOL = "clockchain.standalone-handshake/v1";
export const STANDALONE_CHAIN_ID = "eip155:11155111";
export const STANDALONE_REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const MESSAGE_KINDS = ["question", "proposal", "evidence", "note"] as const;
export const DATA_HANDLING_CLASSES = ["public", "confidential", "restricted"] as const;
// Bumped whenever the rules an agent must follow change (tools, playbook, flows). Every tool
// response carries it, so an agent running from an old script learns to re-read the rules.
// 1: handshake_next/readiness_prepare. 2: supervised sessions. 3: self-describing invitations.
export const STANDALONE_PLAYBOOK_VERSION = 3;
export const STANDALONE_DEFAULT_ENDPOINT = "https://mcp.clockchain.network/connect/mcp";
// v2 invitations are readable at a glance: "chs2." + base64url(JSON).
export const INVITATION_V2_PREFIX = "chs2.";

type JsonRecord = Record<string, any>;

// ADDRESS and SIGNATURE accept mixed-case hex on input (EIP-55 checksummed
// addresses, uppercase signatures), but the stored and signed form is always
// canonical lowercase: normalizeStandaloneReadiness lowercases sessionKeyAddress
// before the authority record is rebuilt, so a signer must sign the record built
// from the lowercase address. readiness_prepare serves those exact bytes.
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE = /^[ -~]+$/;
const IDENTITY_MODES = ["required_fresh", "required_existing_or_fresh", "not_required"];
const ROLES = ["initiator", "responder"];

export class StandaloneHandshakeValidationError extends Error {
  constructor() {
    super("Standalone handshake validation failed.");
    this.name = "StandaloneHandshakeValidationError";
  }
}

function invalid(): never {
  throw new StandaloneHandshakeValidationError();
}

export { ADDRESS, DECIMAL, DIGEST, SIGNATURE, UUID, ROLES };

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

function printable(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && value.trim() === value && PRINTABLE.test(value);
}

function decimalWithin(value: unknown, min: bigint, max: bigint): value is string {
  return typeof value === "string" && DECIMAL.test(value) && BigInt(value) >= min && BigInt(value) <= max;
}

// The pinned registry is matched case-insensitively on input but always stored in
// its canonical lowercase form so digests are stable regardless of checksum casing.
function canonicalRegistryAddress(value: unknown): string | undefined {
  return typeof value === "string" && value.toLowerCase() === STANDALONE_REGISTRY_ADDRESS ? STANDALONE_REGISTRY_ADDRESS : undefined;
}

function identityPolicy(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["erc8004", "chainId", "registryAddress"]);
  if (!IDENTITY_MODES.includes(item.erc8004)) invalid();
  if (item.erc8004 === "not_required") {
    if (item.chainId !== null || item.registryAddress !== null) invalid();
    return Object.freeze(item);
  }
  const registryAddress = canonicalRegistryAddress(item.registryAddress);
  if (item.chainId !== STANDALONE_CHAIN_ID || registryAddress === undefined) invalid();
  return Object.freeze({ erc8004: item.erc8004, chainId: item.chainId, registryAddress });
}

export function normalizeStandaloneTerms(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["reference", "purpose", "channelLimits", "identityPolicy"]);
  if (!printable(item.reference, 128) || !printable(item.purpose, 256)) invalid();
  const limits = exact(item.channelLimits, ["durationSeconds", "messageKinds", "maxMessageBytes"]);
  if (!decimalWithin(limits.durationSeconds, 60n, 86400n)) invalid();
  if (!decimalWithin(limits.maxMessageBytes, 1n, 16384n)) invalid();
  if (!Array.isArray(limits.messageKinds) || limits.messageKinds.length === 0) invalid();
  const kinds = [...limits.messageKinds];
  if (kinds.some((kind) => !MESSAGE_KINDS.includes(kind)) || new Set(kinds).size !== kinds.length) invalid();
  return Object.freeze({
    reference: item.reference,
    purpose: item.purpose,
    channelLimits: Object.freeze({ durationSeconds: limits.durationSeconds, messageKinds: Object.freeze(kinds), maxMessageBytes: limits.maxMessageBytes }),
    identityPolicy: identityPolicy(item.identityPolicy),
  });
}

function registration(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["agentId", "chainId", "registryAddress"]);
  const registryAddress = canonicalRegistryAddress(item.registryAddress);
  if (typeof item.agentId !== "string" || !DECIMAL.test(item.agentId) || item.chainId !== STANDALONE_CHAIN_ID || registryAddress === undefined) invalid();
  return Object.freeze({ agentId: item.agentId, chainId: item.chainId, registryAddress });
}

export function normalizeStandaloneReadiness(value: unknown, policyMode: string): Readonly<JsonRecord> {
  if (!IDENTITY_MODES.includes(policyMode)) invalid();
  const item = exact(value, ["sessionKeyAddress", "identity", "authorityStatement", "authoritySignatureHex", "capabilityManifest"]);
  if (!ADDRESS.test(item.sessionKeyAddress) || !SIGNATURE.test(item.authoritySignatureHex)) invalid();
  const identity = policyMode === "not_required" ? (item.identity === null ? null : invalid()) : item.identity === null ? invalid() : registration(item.identity);
  const authority = exact(item.authorityStatement, ["accountableParty", "statement"]);
  if (!printable(authority.accountableParty, 128) || !printable(authority.statement, 512)) invalid();
  const manifest = exact(item.capabilityManifest, ["dataHandlingClass", "purpose"]);
  if (!DATA_HANDLING_CLASSES.includes(manifest.dataHandlingClass) || !printable(manifest.purpose, 256)) invalid();
  return Object.freeze({
    // Hex fields normalize to lowercase so canonical digests and the exact-match
    // against the recovered EIP-191 address never depend on casing.
    sessionKeyAddress: item.sessionKeyAddress.toLowerCase(),
    identity,
    authorityStatement: Object.freeze({ accountableParty: authority.accountableParty, statement: authority.statement }),
    authoritySignatureHex: item.authoritySignatureHex.toLowerCase(),
    capabilityManifest: Object.freeze({ dataHandlingClass: manifest.dataHandlingClass, purpose: manifest.purpose }),
  });
}

export function standaloneAuthorityRecord(readiness: Readonly<JsonRecord>): Readonly<JsonRecord> {
  return Object.freeze({
    schema: "clockchain.standalone-handshake-authority/v1",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    sessionKeyAddress: readiness.sessionKeyAddress,
    accountableParty: readiness.authorityStatement.accountableParty,
    statement: readiness.authorityStatement.statement,
  });
}

/**
 * Something the caller signs locally: the structured record, its exact canonical
 * bytes as a UTF-8 string (what EIP-191 personal_sign is applied to) and the sha256
 * of those bytes. The signer re-derives bytes and digest from `record` before signing;
 * the server's copy is a convenience, never an authority.
 */
export interface StandaloneSigningPayload {
  record: Readonly<JsonRecord>;
  bytes: string;
  bytesSha256: string;
}

export function standaloneSigningPayload(record: Readonly<JsonRecord>): StandaloneSigningPayload {
  const bytes = canonicalBytes(record);
  return Object.freeze({ record, bytes: bytes.toString("utf8"), bytesSha256: digestHex(record) });
}

/**
 * The authority record a party signs for its readiness package, built from the
 * canonical lowercase session-key address exactly as the checklist rebuilds it.
 */
export function prepareStandaloneAuthority(value: unknown): StandaloneSigningPayload {
  const item = exact(value, ["sessionKeyAddress", "accountableParty", "statement"]);
  if (typeof item.sessionKeyAddress !== "string" || !ADDRESS.test(item.sessionKeyAddress)) invalid();
  if (!printable(item.accountableParty, 128) || !printable(item.statement, 512)) invalid();
  return standaloneSigningPayload(standaloneAuthorityRecord({
    sessionKeyAddress: item.sessionKeyAddress.toLowerCase(),
    authorityStatement: { accountableParty: item.accountableParty, statement: item.statement },
  }));
}

export function buildStandaloneConsentRecord(input: { sessionId: string; role: string; termsDigest: string; checklistDigest: string }): Readonly<JsonRecord> {
  const item = exact(input, ["sessionId", "role", "termsDigest", "checklistDigest"]);
  if (!UUID.test(item.sessionId) || !ROLES.includes(item.role) || !DIGEST.test(item.termsDigest) || !DIGEST.test(item.checklistDigest)) invalid();
  return Object.freeze({
    schema: "clockchain.standalone-handshake-consent/v1",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    sessionId: item.sessionId,
    role: item.role,
    termsDigest: item.termsDigest,
    checklistDigest: item.checklistDigest,
  });
}

export function normalizeStandaloneClosure(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["schema", "protocol", "sessionId", "outcome", "byRole", "closedAtMs", "externalBusinessActionPerformed"]);
  if (item.schema !== "clockchain.standalone-handshake-closure/v1" || item.protocol !== STANDALONE_HANDSHAKE_PROTOCOL) invalid();
  if (!UUID.test(item.sessionId) || !["closed", "revoked"].includes(item.outcome)) invalid();
  if (!ROLES.includes(item.byRole)) invalid();
  if (!decimalWithin(item.closedAtMs, 0n, 99999999999999n)) invalid();
  if (item.externalBusinessActionPerformed !== false) invalid();
  return Object.freeze(item);
}

export function standaloneCanonicalRecord(value: unknown): Readonly<{ bytesHex: string; digest: string }> {
  const bytes = canonicalBytes(value);
  return Object.freeze({ bytesHex: bytes.toString("hex"), digest: digestHex(value) });
}

/**
 * Invitation envelope. Only `secret` authorizes anything; `endpoint` and `next` are
 * non-secret hints so an agent that is handed the string alone knows where to go and
 * what to call first. v2 is "chs2." + base64url(JSON); bare base64url v1 still decodes.
 */
export function encodeStandaloneInvitation(input: { sessionId: string; secret: string; endpoint: string }): string {
  const envelope = { v: 2, sessionId: input.sessionId, secret: input.secret, endpoint: input.endpoint, next: "handshake_preview_invitation" };
  return INVITATION_V2_PREFIX + Buffer.from(JSON.stringify(envelope)).toString("base64url");
}

export function decodeStandaloneInvitation(invitation: unknown): { v: 1 | 2; sessionId: string; secret: string; endpoint?: string } | undefined {
  if (typeof invitation !== "string" || invitation.length < 80 || invitation.length > 4096) return undefined;
  const v2 = invitation.startsWith(INVITATION_V2_PREFIX);
  try {
    const decoded = JSON.parse(Buffer.from(v2 ? invitation.slice(INVITATION_V2_PREFIX.length) : invitation, "base64url").toString("utf8"));
    if (typeof decoded?.sessionId !== "string" || typeof decoded.secret !== "string") return undefined;
    if (v2 && decoded.v === 2 && typeof decoded.endpoint === "string") return { v: 2, sessionId: decoded.sessionId, secret: decoded.secret, endpoint: decoded.endpoint };
    if (!v2 && decoded.v === 1) return { v: 1, sessionId: decoded.sessionId, secret: decoded.secret };
    return undefined;
  } catch {
    return undefined;
  }
}
