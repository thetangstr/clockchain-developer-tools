import { canonicalBytes, digestHex } from "../../handshake/protocol.js";

export const AGENT_HANDSHAKE_V2_PROTOCOL = "clockchain.agent-handshake/v2";
export const AGENT_HANDSHAKE_V2_MCP_ORIGIN = "https://mcp.clockchain.network";
export const AGENT_HANDSHAKE_V2_CHAIN_ID = "eip155:11155111";
export const AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS =
  "0x8004a818bfb912233c491871b3d84c89a494bd9e";

type JsonRecord = Record<string, any>;

const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const TRANSACTION = /^0x[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE = /^[ -~]+$/;
const IDENTITY_MODES = ["required_fresh", "required_existing_or_fresh", "not_required"];
const ROLES = ["initiator", "responder"];

export class AgentHandshakeV2ValidationError extends Error {
  constructor() {
    super("Agent handshake v2 validation failed.");
    this.name = "AgentHandshakeV2ValidationError";
  }
}

function invalid(): never {
  throw new AgentHandshakeV2ValidationError();
}

function exact(value: unknown, keys: readonly string[]): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const own = Reflect.ownKeys(value);
  if (
    own.length !== keys.length ||
    own.some((key) => typeof key !== "string" || !keys.includes(key))
  ) invalid();
  const result: JsonRecord = {};
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function printable(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max &&
    value.trim() === value && PRINTABLE.test(value);
}

function identityPolicy(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["erc8004", "chainId", "registryAddress"]);
  if (!IDENTITY_MODES.includes(item.erc8004)) invalid();
  if (item.erc8004 === "not_required") {
    if (item.chainId !== null || item.registryAddress !== null) invalid();
  } else if (
    item.chainId !== AGENT_HANDSHAKE_V2_CHAIN_ID ||
    item.registryAddress !== AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS
  ) invalid();
  return Object.freeze(item);
}

export function normalizeV2Terms(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["reference", "statement", "validForSeconds", "identityPolicy"]);
  if (
    !printable(item.reference, 128) || !printable(item.statement, 512) ||
    typeof item.validForSeconds !== "string" || !DECIMAL.test(item.validForSeconds) ||
    BigInt(item.validForSeconds) < 1n || BigInt(item.validForSeconds) > 90n
  ) invalid();
  return Object.freeze({ ...item, identityPolicy: identityPolicy(item.identityPolicy) });
}

export function normalizeV2Policy(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, [
    "schema", "protocol", "role", "mcpOrigin", "reference", "statementDigest",
    "maxValidForSeconds", "identityPolicy", "externalBusinessActionsAllowed",
  ]);
  if (
    item.schema !== "clockchain.agent-handshake-policy/v1" ||
    item.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL || !ROLES.includes(item.role) ||
    item.mcpOrigin !== AGENT_HANDSHAKE_V2_MCP_ORIGIN || !printable(item.reference, 128) ||
    !DIGEST.test(item.statementDigest) || typeof item.maxValidForSeconds !== "string" ||
    !DECIMAL.test(item.maxValidForSeconds) || BigInt(item.maxValidForSeconds) < 1n ||
    BigInt(item.maxValidForSeconds) > 90n || item.externalBusinessActionsAllowed !== false
  ) invalid();
  return Object.freeze({ ...item, identityPolicy: identityPolicy(item.identityPolicy) });
}

function registration(value: unknown, policy: JsonRecord): Readonly<JsonRecord> {
  const item = exact(value, [
    "agentId", "chainId", "registryAddress", "reference", "registrationTx", "registrationBlock",
  ]);
  if (
    typeof item.agentId !== "string" || !DECIMAL.test(item.agentId) ||
    item.chainId !== policy.chainId || item.registryAddress !== policy.registryAddress ||
    item.reference !== `${item.chainId}:${item.registryAddress}:${item.agentId}` ||
    typeof item.registrationTx !== "string" || !TRANSACTION.test(item.registrationTx) ||
    typeof item.registrationBlock !== "string" || !DECIMAL.test(item.registrationBlock)
  ) invalid();
  return Object.freeze(item);
}

export function normalizeV2Party(value: unknown, rawPolicy: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["sessionKeyAddress", "policyDigest", "erc8004"]);
  const policy = identityPolicy(rawPolicy);
  if (!ADDRESS.test(item.sessionKeyAddress) || !DIGEST.test(item.policyDigest)) invalid();
  const erc8004 = policy.erc8004 === "not_required"
    ? item.erc8004 === null ? null : invalid()
    : item.erc8004 === null ? invalid() : registration(item.erc8004, policy);
  return Object.freeze({ ...item, erc8004 });
}

export function normalizeV2IdentityClaim(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, [
    "schema", "protocol", "sessionId", "repositorySha", "role", "sessionKeyAddress",
    "policyDigest", "statementDigest", "externalBusinessActionPerformed",
  ]);
  if (
    item.schema !== "clockchain.agent-handshake-identity-claim/v2" ||
    item.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL || !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) || !ROLES.includes(item.role) ||
    !ADDRESS.test(item.sessionKeyAddress) || !DIGEST.test(item.policyDigest) ||
    !DIGEST.test(item.statementDigest) || item.externalBusinessActionPerformed !== false
  ) invalid();
  return Object.freeze(item);
}

function agreement(value: unknown, kind: "proposal" | "acceptance"): Readonly<JsonRecord> {
  const keys = [
    "schema", "protocol", "sessionId", "repositorySha", "reference", "statementDigest",
    "identityPolicy", "initiator", "responder",
    ...(kind === "acceptance" ? ["proposalDigest", "decision"] : []),
    "issuedAtMs", "expiresAtMs", "externalBusinessActionPerformed",
  ];
  const item = exact(value, keys);
  const policy = identityPolicy(item.identityPolicy);
  const initiator = normalizeV2Party(item.initiator, policy);
  const responder = normalizeV2Party(item.responder, policy);
  if (
    item.schema !== `clockchain.agent-handshake-${kind}/v2` ||
    item.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL || !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) || !printable(item.reference, 128) ||
    !DIGEST.test(item.statementDigest) || typeof item.issuedAtMs !== "string" ||
    !DECIMAL.test(item.issuedAtMs) || typeof item.expiresAtMs !== "string" ||
    !DECIMAL.test(item.expiresAtMs) || BigInt(item.issuedAtMs) >= BigInt(item.expiresAtMs) ||
    item.externalBusinessActionPerformed !== false ||
    initiator.sessionKeyAddress === responder.sessionKeyAddress ||
    initiator.policyDigest === responder.policyDigest
  ) invalid();
  if (
    policy.erc8004 !== "not_required" &&
    initiator.erc8004.agentId === responder.erc8004.agentId
  ) invalid();
  if (kind === "acceptance" && (!DIGEST.test(item.proposalDigest) || item.decision !== "ACCEPTED")) invalid();
  return Object.freeze({ ...item, identityPolicy: policy, initiator, responder });
}

export function normalizeV2Proposal(value: unknown): Readonly<JsonRecord> {
  return agreement(value, "proposal");
}

export function normalizeV2Acceptance(value: unknown): Readonly<JsonRecord> {
  return agreement(value, "acceptance");
}

const SIGNATURE = /^0x[0-9a-f]{130}$/;

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

// H-REQ-02: a proposal envelope is used only once it verifies — the exact
// envelope shape, this session, repository and terms, a window exactly
// validForSeconds wide with nowMs inside it, and an EIP-191 signature over the
// payload's canonical bytes that recovers to the initiator it names. Mirrors
// the helper's verifyAgentHandshakeV2Proposal; signer recovery is a function
// the caller supplies, and its own errors (for example an unreachable RPC)
// propagate unchanged.
export async function verifyV2ProposalEnvelope(input: {
  envelope: unknown;
  expectedSessionId: string;
  expectedRepositorySha: string;
  expectedTerms: unknown;
  nowMs: number;
  recoverEip191Address(input: { bytes: Buffer; signatureHex: string }): Promise<string>;
}): Promise<Readonly<JsonRecord>> {
  const item = exact(input.envelope, ["payload", "schema", "signature"]);
  const payload = normalizeV2Proposal(item.payload);
  const signature = exact(item.signature, ["address", "algorithm", "value"]);
  const terms = normalizeV2Terms(input.expectedTerms);
  if (
    item.schema !== "clockchain.agent-handshake-proposal-envelope/v2" ||
    typeof signature.address !== "string" || !ADDRESS.test(signature.address) ||
    signature.algorithm !== "eip191" ||
    typeof signature.value !== "string" || !SIGNATURE.test(signature.value) ||
    !Number.isSafeInteger(input.nowMs) ||
    payload.sessionId !== input.expectedSessionId ||
    payload.repositorySha !== input.expectedRepositorySha ||
    payload.reference !== terms.reference ||
    payload.statementDigest !== digestHex(terms) ||
    !sameCanonical(payload.identityPolicy, terms.identityPolicy) ||
    BigInt(payload.expiresAtMs) !== BigInt(payload.issuedAtMs) + BigInt(terms.validForSeconds) * 1000n ||
    BigInt(input.nowMs) < BigInt(payload.issuedAtMs) ||
    BigInt(input.nowMs) >= BigInt(payload.expiresAtMs) ||
    signature.address !== payload.initiator.sessionKeyAddress
  ) invalid();
  const recovered = await input.recoverEip191Address({ bytes: canonicalBytes(payload), signatureHex: signature.value });
  if (typeof recovered !== "string" || recovered.toLowerCase() !== payload.initiator.sessionKeyAddress) invalid();
  return Object.freeze({ payload, schema: item.schema, signature: Object.freeze(signature) });
}

// H-REQ-02: what an acceptance must share with the proposal it accepts — the
// proposal's digest, session, repository, reference, statement, expiry,
// identity policy and both parties — issued no earlier than the proposal and
// before the shared expiry. Mirrors the helper's
// assertAgentHandshakeV2AcceptanceBinding; both arguments are payloads.
export function assertV2AcceptanceBinding(input: { acceptance: unknown; proposal: unknown }): Readonly<JsonRecord> {
  const accepted = normalizeV2Acceptance(input.acceptance);
  const proposed = normalizeV2Proposal(input.proposal);
  if (
    accepted.proposalDigest !== digestHex(proposed) ||
    accepted.sessionId !== proposed.sessionId ||
    accepted.repositorySha !== proposed.repositorySha ||
    accepted.reference !== proposed.reference ||
    accepted.statementDigest !== proposed.statementDigest ||
    accepted.expiresAtMs !== proposed.expiresAtMs ||
    !sameCanonical(accepted.identityPolicy, proposed.identityPolicy) ||
    !sameCanonical(accepted.initiator, proposed.initiator) ||
    !sameCanonical(accepted.responder, proposed.responder) ||
    BigInt(proposed.issuedAtMs) > BigInt(accepted.issuedAtMs) ||
    BigInt(accepted.issuedAtMs) >= BigInt(accepted.expiresAtMs)
  ) invalid();
  return accepted;
}

export function normalizeV2EvidenceResult(value: unknown, rawPolicy: unknown): Readonly<JsonRecord> {
  const item = exact(value, [
    "externalBusinessActionPerformed", "party", "policyDigest", "reference", "repositorySha",
    "role", "schema", "sessionDigest", "statementDigest", "transitionDigests",
  ]);
  const party = normalizeV2Party(item.party, rawPolicy);
  if (
    item.externalBusinessActionPerformed !== false ||
    item.schema !== "clockchain.agent-handshake-party-result/v2" || !ROLES.includes(item.role) ||
    !printable(item.reference, 128) || !SHA.test(item.repositorySha) ||
    !DIGEST.test(item.policyDigest) || item.policyDigest !== party.policyDigest ||
    !DIGEST.test(item.sessionDigest) || !DIGEST.test(item.statementDigest) ||
    !Array.isArray(item.transitionDigests) || item.transitionDigests.length !== 3 ||
    item.transitionDigests.some((entry: unknown) => typeof entry !== "string" || !DIGEST.test(entry))
  ) invalid();
  return Object.freeze({ ...item, party, transitionDigests: Object.freeze([...item.transitionDigests]) });
}

function rawEd25519PublicKey(value: unknown): value is string {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  return Buffer.from(value, "base64").length === 32;
}

export function normalizeV2Descriptor(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, [
    "agreementExpiresAtMs", "externalBusinessActionPerformed", "hostSessionKeyCertificateDigest",
    "identityPolicy", "initiator", "operatorPublicKey", "protocol", "reference",
    "repositorySha", "responder", "schema", "sessionId", "sessionOpenedAtMs",
    "sessionOpenedBlock", "statementDigest",
  ]);
  const policy = identityPolicy(item.identityPolicy);
  const initiator = normalizeV2Party(item.initiator, policy);
  const responder = normalizeV2Party(item.responder, policy);
  if (
    item.schema !== "clockchain.agent-handshake-descriptor/v2" ||
    item.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL || !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) || !printable(item.reference, 128) ||
    !DIGEST.test(item.statementDigest) || !DIGEST.test(item.hostSessionKeyCertificateDigest) ||
    !rawEd25519PublicKey(item.operatorPublicKey) ||
    typeof item.sessionOpenedAtMs !== "string" || !DECIMAL.test(item.sessionOpenedAtMs) ||
    typeof item.sessionOpenedBlock !== "string" || !DECIMAL.test(item.sessionOpenedBlock) ||
    typeof item.agreementExpiresAtMs !== "string" || !DECIMAL.test(item.agreementExpiresAtMs) ||
    BigInt(item.agreementExpiresAtMs) <= BigInt(item.sessionOpenedAtMs) ||
    item.externalBusinessActionPerformed !== false ||
    initiator.sessionKeyAddress === responder.sessionKeyAddress
  ) invalid();
  return Object.freeze({ ...item, identityPolicy: policy, initiator, responder });
}

function anchor(value: unknown, index: number): Readonly<JsonRecord> {
  const item = exact(value, ["blockHeight", "blockTimeRaw", "digest", "kind", "ledgerId"]);
  if (
    item.kind !== ["proposal", "acceptance", "acknowledgment"][index] ||
    typeof item.blockHeight !== "string" || !DECIMAL.test(item.blockHeight) ||
    !printable(item.blockTimeRaw, 64) || !DIGEST.test(item.digest) || !UUID.test(item.ledgerId)
  ) invalid();
  return Object.freeze(item);
}

export function normalizeV2Result(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, [
    "anchors", "externalBusinessActionPerformed", "hostSessionKeyCertificateDigest", "identityPolicy",
    "issuedAtMs", "outcome", "parties", "policyDigests", "reference", "schema", "sessionDigest",
    "sessionId", "statementDigest", "subjectRun",
  ]);
  const policy = identityPolicy(item.identityPolicy);
  const parties = exact(item.parties, ["initiator", "responder"]);
  const initiator = normalizeV2Party(parties.initiator, policy);
  const responder = normalizeV2Party(parties.responder, policy);
  const policyDigests = exact(item.policyDigests, ["initiator", "responder"]);
  if (
    item.schema !== "clockchain.agent-handshake-result/v2" ||
    !["VERIFIED", "FAILED"].includes(item.outcome) ||
    typeof item.externalBusinessActionPerformed !== "boolean" ||
    !DIGEST.test(item.hostSessionKeyCertificateDigest) || typeof item.issuedAtMs !== "string" ||
    !DECIMAL.test(item.issuedAtMs) || !printable(item.reference, 128) ||
    !DIGEST.test(item.sessionDigest) || !UUID.test(item.sessionId) ||
    !DIGEST.test(item.statementDigest) || item.subjectRun !== "stakeholder" ||
    policyDigests.initiator !== initiator.policyDigest ||
    policyDigests.responder !== responder.policyDigest ||
    !Array.isArray(item.anchors) || item.anchors.length !== 3
  ) invalid();
  return Object.freeze({
    ...item,
    anchors: Object.freeze(item.anchors.map(anchor)),
    identityPolicy: policy,
    parties: Object.freeze({ initiator, responder }),
    policyDigests: Object.freeze(policyDigests),
  });
}

export function v2CanonicalRecord(value: unknown): Readonly<{ bytesHex: string; digest: string }> {
  const bytes = canonicalBytes(value);
  return Object.freeze({ bytesHex: bytes.toString("hex"), digest: digestHex(value) });
}
