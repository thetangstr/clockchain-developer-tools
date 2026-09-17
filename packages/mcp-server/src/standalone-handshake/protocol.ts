import { canonicalBytes, digestHex } from "../handshake/protocol.js";

export const STANDALONE_HANDSHAKE_PROTOCOL = "clockchain.standalone-handshake/v1";
export const STANDALONE_CHAIN_ID = "eip155:11155111";
export const STANDALONE_REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const MESSAGE_KINDS = ["question", "proposal", "evidence", "note"] as const;
export const DATA_HANDLING_CLASSES = ["public", "confidential", "restricted"] as const;

type JsonRecord = Record<string, any>;

// ADDRESS and SIGNATURE accept mixed-case hex (EIP-55 checksummed addresses,
// uppercase signatures). Values are stored verbatim — the authority record must
// byte-match what the signer signed — and every comparison lowercases both sides.
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
