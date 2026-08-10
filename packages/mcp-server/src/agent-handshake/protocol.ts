import {
  canonicalBytes,
  digestHex,
} from "../handshake/protocol.js";
import { createPublicKey, verify } from "node:crypto";

export { canonicalBytes, digestHex } from "../handshake/protocol.js";

export const AGENT_HANDSHAKE_PROTOCOL = "clockchain.agent-handshake/v1";
export const AGENT_HANDSHAKE_PROPOSAL_SCHEMA = "clockchain.agent-handshake-proposal/v1";
export const AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA = "clockchain.agent-handshake-proposal-envelope/v1";
export const AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA = "clockchain.agent-handshake-acceptance/v1";
export const AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA = "clockchain.agent-handshake-acceptance-envelope/v1";
export const AGENT_HANDSHAKE_TRANSITION_SCHEMA = "clockchain.agent-handshake-transition/v1";
export const AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA = "clockchain.agent-handshake-party-result/v1";
export const AGENT_HANDSHAKE_EVIDENCE_SCHEMA = "clockchain.agent-handshake-evidence/v1";
export const AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA = "clockchain.agent-handshake-descriptor/v1";
export const AGENT_HANDSHAKE_RESULT_SCHEMA = "clockchain.agent-handshake-result/v1";

type JsonObject = Record<string, any>;
export type AgentHandshakeRole = "initiator" | "responder";
export type AgentHandshakeTerms = Readonly<{
  reference: string;
  statement: string;
  validForMinutes: string;
}>;
export type AgentHandshakeParty = Readonly<{ address: string; agentId: string }>;

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class AgentHandshakeProtocolError extends Error {
  constructor(readonly code = "AGENT_HANDSHAKE_PROTOCOL_INVALID") {
    super(`${code}: Agent handshake protocol validation failed.`);
    this.name = "AgentHandshakeProtocolError";
  }
}

function invalid(code?: string): never {
  throw new AgentHandshakeProtocolError(code);
}

function exact(value: unknown, keys: readonly string[], code?: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(code);
  const own = Reflect.ownKeys(value);
  if (
    own.length !== keys.length ||
    own.some((key) => typeof key !== "string" || !keys.includes(key)) ||
    keys.some((key) => {
      const property = Object.getOwnPropertyDescriptor(value, key);
      return property?.enumerable !== true || !Object.hasOwn(property, "value");
    })
  ) invalid(code);
  return value as JsonObject;
}

function printable(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && value.trim() === value && PRINTABLE_PATTERN.test(value);
}

export function normalizeAgentHandshakeTerms(value: unknown): AgentHandshakeTerms {
  const terms = exact(value, ["reference", "statement", "validForMinutes"]);
  const minutes = typeof terms.validForMinutes === "number"
    ? terms.validForMinutes
    : Number(terms.validForMinutes);
  if (
    !printable(terms.reference, 128) ||
    !printable(terms.statement, 256) ||
    !Number.isSafeInteger(minutes) ||
    minutes < 1 ||
    minutes > 60 ||
    (typeof terms.validForMinutes === "string" && String(minutes) !== terms.validForMinutes)
  ) invalid("AGENT_HANDSHAKE_TERMS_INVALID");
  return Object.freeze({
    reference: terms.reference,
    statement: terms.statement,
    validForMinutes: String(minutes),
  });
}

export function agentHandshakeStatementDigest(value: unknown): string {
  return digestHex(normalizeAgentHandshakeTerms(value));
}

function party(value: unknown): AgentHandshakeParty {
  const verified = exact(value, ["address", "agentId"]);
  if (!ADDRESS_PATTERN.test(verified.address) || !DECIMAL_PATTERN.test(verified.agentId)) invalid();
  return Object.freeze({ address: verified.address, agentId: verified.agentId });
}

export function buildAgentProposal(input: {
  expiresAtMs: string;
  initiator: AgentHandshakeParty;
  issuedAtMs: string;
  repositorySha: string;
  responder: AgentHandshakeParty;
  sessionId: string;
  terms: AgentHandshakeTerms;
}): Readonly<JsonObject> {
  const terms = normalizeAgentHandshakeTerms(input.terms);
  const initiator = party(input.initiator);
  const responder = party(input.responder);
  if (
    !DECIMAL_PATTERN.test(input.issuedAtMs) ||
    !DECIMAL_PATTERN.test(input.expiresAtMs) ||
    BigInt(input.expiresAtMs) !== BigInt(input.issuedAtMs) + BigInt(terms.validForMinutes) * 60_000n ||
    !SHA_PATTERN.test(input.repositorySha) ||
    !UUID_PATTERN.test(input.sessionId) ||
    initiator.address === responder.address
  ) invalid();
  return Object.freeze({
    expiresAtMs: input.expiresAtMs,
    externalActionPerformed: false,
    initiator,
    issuedAtMs: input.issuedAtMs,
    protocol: AGENT_HANDSHAKE_PROTOCOL,
    reference: terms.reference,
    repositorySha: input.repositorySha,
    responder,
    schema: AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
    sessionId: input.sessionId,
    statement: terms.statement,
    statementDigest: agentHandshakeStatementDigest(terms),
    subjectRun: "stakeholder",
    validForMinutes: terms.validForMinutes,
  });
}

export function validateAgentProposal(value: unknown): Readonly<JsonObject> {
  const proposal = exact(value, [
    "expiresAtMs", "externalActionPerformed", "initiator", "issuedAtMs", "protocol",
    "reference", "repositorySha", "responder", "schema", "sessionId", "statement",
    "statementDigest", "subjectRun", "validForMinutes",
  ]);
  const rebuilt = buildAgentProposal({
    expiresAtMs: proposal.expiresAtMs,
    initiator: party(proposal.initiator),
    issuedAtMs: proposal.issuedAtMs,
    repositorySha: proposal.repositorySha,
    responder: party(proposal.responder),
    sessionId: proposal.sessionId,
    terms: {
      reference: proposal.reference,
      statement: proposal.statement,
      validForMinutes: proposal.validForMinutes,
    },
  });
  if (digestHex(rebuilt) !== digestHex(proposal)) invalid();
  return rebuilt;
}

function signature(value: unknown): Readonly<JsonObject> {
  const verified = exact(value, ["address", "algorithm", "value"]);
  if (!ADDRESS_PATTERN.test(verified.address) || verified.algorithm !== "eip191" || !SIGNATURE_PATTERN.test(verified.value)) invalid();
  return Object.freeze({ ...verified });
}

export function sealAgentProposal(value: unknown, signatureValue: string): Readonly<JsonObject> {
  const proposal = validateAgentProposal(value);
  return Object.freeze({
    proposal,
    schema: AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA,
    signature: signature({ address: proposal.initiator.address, algorithm: "eip191", value: signatureValue }),
  });
}

export function validateAgentProposalEnvelope(value: unknown): Readonly<JsonObject> {
  const envelope = exact(value, ["proposal", "schema", "signature"]);
  if (envelope.schema !== AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA) invalid();
  const proposal = validateAgentProposal(envelope.proposal);
  const verifiedSignature = signature(envelope.signature);
  if (verifiedSignature.address !== proposal.initiator.address) invalid();
  return Object.freeze({ proposal, schema: envelope.schema, signature: verifiedSignature });
}

export function agentProposalDigest(value: unknown): string {
  return digestHex(validateAgentProposalEnvelope(value).proposal);
}

export function buildAgentAcceptance(input: {
  issuedAtMs: string;
  proposalEnvelope: JsonObject;
}): Readonly<JsonObject> {
  const envelope = validateAgentProposalEnvelope(input.proposalEnvelope);
  const proposal = envelope.proposal;
  if (!DECIMAL_PATTERN.test(input.issuedAtMs) || BigInt(input.issuedAtMs) < BigInt(proposal.issuedAtMs) || BigInt(input.issuedAtMs) >= BigInt(proposal.expiresAtMs)) invalid();
  return Object.freeze({
    decision: "ACCEPTED",
    expiresAtMs: proposal.expiresAtMs,
    externalActionPerformed: false,
    initiator: proposal.initiator,
    issuedAtMs: input.issuedAtMs,
    proposalDigest: agentProposalDigest(envelope),
    protocol: AGENT_HANDSHAKE_PROTOCOL,
    reference: proposal.reference,
    repositorySha: proposal.repositorySha,
    responder: proposal.responder,
    schema: AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
    sessionId: proposal.sessionId,
    statementDigest: proposal.statementDigest,
    subjectRun: "stakeholder",
  });
}

export function validateAgentAcceptance(value: unknown): Readonly<JsonObject> {
  const acceptance = exact(value, [
    "decision", "expiresAtMs", "externalActionPerformed", "initiator", "issuedAtMs",
    "proposalDigest", "protocol", "reference", "repositorySha", "responder", "schema",
    "sessionId", "statementDigest", "subjectRun",
  ]);
  if (
    acceptance.decision !== "ACCEPTED" || acceptance.externalActionPerformed !== false ||
    acceptance.protocol !== AGENT_HANDSHAKE_PROTOCOL || acceptance.schema !== AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA ||
    acceptance.subjectRun !== "stakeholder" || !DECIMAL_PATTERN.test(acceptance.issuedAtMs) ||
    !DECIMAL_PATTERN.test(acceptance.expiresAtMs) || !DIGEST_PATTERN.test(acceptance.proposalDigest) ||
    !DIGEST_PATTERN.test(acceptance.statementDigest) || !SHA_PATTERN.test(acceptance.repositorySha) ||
    !UUID_PATTERN.test(acceptance.sessionId) || !printable(acceptance.reference, 128)
  ) invalid();
  party(acceptance.initiator); party(acceptance.responder);
  return Object.freeze({ ...acceptance, initiator: party(acceptance.initiator), responder: party(acceptance.responder) });
}

export function sealAgentAcceptance(value: unknown, signatureValue: string): Readonly<JsonObject> {
  const acceptance = validateAgentAcceptance(value);
  return Object.freeze({
    acceptance,
    schema: AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA,
    signature: signature({ address: acceptance.responder.address, algorithm: "eip191", value: signatureValue }),
  });
}

export function validateAgentAcceptanceEnvelope(value: unknown, proposalEnvelope?: JsonObject): Readonly<JsonObject> {
  const envelope = exact(value, ["acceptance", "schema", "signature"]);
  if (envelope.schema !== AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA) invalid();
  const acceptance = validateAgentAcceptance(envelope.acceptance);
  const verifiedSignature = signature(envelope.signature);
  if (verifiedSignature.address !== acceptance.responder.address) invalid();
  if (proposalEnvelope) {
    const proposal = validateAgentProposalEnvelope(proposalEnvelope).proposal;
    if (
      acceptance.proposalDigest !== agentProposalDigest(proposalEnvelope) ||
      acceptance.sessionId !== proposal.sessionId || acceptance.repositorySha !== proposal.repositorySha ||
      acceptance.reference !== proposal.reference || acceptance.statementDigest !== proposal.statementDigest ||
      digestHex(acceptance.initiator) !== digestHex(proposal.initiator) ||
      digestHex(acceptance.responder) !== digestHex(proposal.responder)
    ) invalid();
  }
  return Object.freeze({ acceptance, schema: envelope.schema, signature: verifiedSignature });
}

type TransitionBase = {
  expiresAtMs: string;
  initiator: AgentHandshakeParty;
  reference: string;
  responder: AgentHandshakeParty;
  sessionDigest: string;
  statementDigest: string;
};

function transition(base: TransitionBase, kind: string, sequence: string, predecessor: string | null): Readonly<JsonObject> {
  if (
    !DECIMAL_PATTERN.test(base.expiresAtMs) || !printable(base.reference, 128) ||
    !DIGEST_PATTERN.test(base.sessionDigest) || !DIGEST_PATTERN.test(base.statementDigest) ||
    (predecessor !== null && !DIGEST_PATTERN.test(predecessor))
  ) invalid();
  return Object.freeze({
    expiresAtMs: base.expiresAtMs,
    externalActionPerformed: false,
    initiator: party(base.initiator),
    kind,
    predecessor,
    protocol: AGENT_HANDSHAKE_PROTOCOL,
    reference: base.reference,
    responder: party(base.responder),
    schema: AGENT_HANDSHAKE_TRANSITION_SCHEMA,
    sequence,
    sessionDigest: base.sessionDigest,
    statementDigest: base.statementDigest,
  });
}

export function buildAgentProposalTransition(base: TransitionBase): Readonly<JsonObject> {
  return transition(base, "PROPOSED", "1", null);
}

export function buildAgentAcceptanceTransition(base: TransitionBase, proposed: JsonObject): Readonly<JsonObject> {
  if (proposed.kind !== "PROPOSED") invalid();
  return transition(base, "ACCEPTED", "2", agentTransitionDigest(proposed));
}

export function buildAgentAcknowledgment(base: TransitionBase, accepted: JsonObject): Readonly<JsonObject> {
  if (accepted.kind !== "ACCEPTED") invalid();
  return transition(base, "ACKNOWLEDGED", "3", agentTransitionDigest(accepted));
}

export function agentTransitionDigest(value: unknown): string {
  return digestHex(value);
}

export function buildAgentEvidenceResult(input: {
  party: AgentHandshakeParty;
  reference: string;
  repositorySha: string;
  role: AgentHandshakeRole;
  sessionDigest: string;
  statementDigest: string;
  transitionDigests: string[];
}): Readonly<JsonObject> {
  if (
    !["initiator", "responder"].includes(input.role) || !printable(input.reference, 128) ||
    !SHA_PATTERN.test(input.repositorySha) || !DIGEST_PATTERN.test(input.sessionDigest) ||
    !DIGEST_PATTERN.test(input.statementDigest) || input.transitionDigests.length !== 3 ||
    input.transitionDigests.some((value) => !DIGEST_PATTERN.test(value))
  ) invalid();
  return Object.freeze({
    externalActionPerformed: false,
    party: party(input.party),
    reference: input.reference,
    repositorySha: input.repositorySha,
    role: input.role,
    schema: AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
    sessionDigest: input.sessionDigest,
    statementDigest: input.statementDigest,
    transitionDigests: Object.freeze([...input.transitionDigests]),
  });
}

export function sealAgentEvidence(result: JsonObject, signatureValue: string): Readonly<JsonObject> {
  return Object.freeze({
    result,
    schema: AGENT_HANDSHAKE_EVIDENCE_SCHEMA,
    signature: signature({ address: result.party.address, algorithm: "eip191", value: signatureValue }),
  });
}

export function verifyAgentDescriptorEnvelope(value: unknown, expectedPublicKey: string): Readonly<JsonObject> {
  const envelope = exact(value, ["descriptor", "operator"]);
  const descriptor = exact(envelope.descriptor, [
    "chainId", "expiresAtMs", "externalActionPerformed", "initiator", "operatorPublicKey",
    "protocol", "reference", "registryAddress", "repositorySha", "responder", "schema",
    "sessionId", "statementDigest",
  ]);
  const operator = exact(envelope.operator, ["algorithm", "keyId", "publicKey", "signature"]);
  if (
    descriptor.schema !== AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA || descriptor.protocol !== AGENT_HANDSHAKE_PROTOCOL ||
    descriptor.chainId !== "11155111" || descriptor.registryAddress !== "0x8004a818bfb912233c491871b3d84c89a494bd9e" ||
    descriptor.externalActionPerformed !== false || !DECIMAL_PATTERN.test(descriptor.expiresAtMs) ||
    !printable(descriptor.reference, 128) || !SHA_PATTERN.test(descriptor.repositorySha) ||
    !UUID_PATTERN.test(descriptor.sessionId) || !DIGEST_PATTERN.test(descriptor.statementDigest) ||
    operator.algorithm !== "ed25519" || typeof operator.keyId !== "string" ||
    typeof operator.publicKey !== "string" || typeof operator.signature !== "string" ||
    descriptor.operatorPublicKey !== operator.publicKey || operator.publicKey !== expectedPublicKey
  ) invalid("AGENT_HANDSHAKE_DESCRIPTOR_INVALID");
  party(descriptor.initiator); party(descriptor.responder);
  let accepted = false;
  try {
    const raw = Buffer.from(operator.publicKey, "base64");
    const signatureBytes = Buffer.from(operator.signature, "base64");
    if (raw.length !== 32 || signatureBytes.length !== 64) invalid("AGENT_HANDSHAKE_DESCRIPTOR_INVALID");
    accepted = verify(
      null,
      canonicalBytes(descriptor),
      createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" }),
      signatureBytes,
    );
  } catch (error) {
    if (error instanceof AgentHandshakeProtocolError) throw error;
  }
  if (!accepted) invalid("AGENT_HANDSHAKE_DESCRIPTOR_INVALID");
  return Object.freeze({ descriptor: Object.freeze({ ...descriptor }), operator: Object.freeze({ ...operator }) });
}

export function agentDescriptorDigest(value: unknown): string {
  return digestHex(exact(value, [
    "chainId", "expiresAtMs", "externalActionPerformed", "initiator", "operatorPublicKey",
    "protocol", "reference", "registryAddress", "repositorySha", "responder", "schema",
    "sessionId", "statementDigest",
  ]));
}

export function verifyAgentResultEnvelope(value: unknown, input: {
  expectedParty: AgentHandshakeParty;
  expectedPublicKey: string;
  expectedRole: AgentHandshakeRole;
  expectedSessionDigest: string;
  expectedSessionId: string;
}): Readonly<JsonObject> {
  const envelope = exact(value, ["result", "signer"]);
  const result = exact(envelope.result, [
    "anchors", "externalActionPerformed", "issuedAtMs", "outcome", "parties", "reference",
    "schema", "sessionDigest", "sessionId", "statementDigest", "subjectRun",
  ]);
  const signer = exact(envelope.signer, ["algorithm", "keyId", "publicKey", "signature"]);
  const parties = exact(result.parties, ["initiator", "responder"]);
  const selected = exact(parties[input.expectedRole], ["address", "agentId", "chainId", "reference", "registryAddress"]);
  if (
    result.schema !== AGENT_HANDSHAKE_RESULT_SCHEMA || result.externalActionPerformed !== false ||
    result.outcome !== "VERIFIED" || result.subjectRun !== "stakeholder" ||
    result.sessionId !== input.expectedSessionId || result.sessionDigest !== input.expectedSessionDigest ||
    !DIGEST_PATTERN.test(result.statementDigest) || !DECIMAL_PATTERN.test(result.issuedAtMs) ||
    selected.address !== input.expectedParty.address || selected.agentId !== input.expectedParty.agentId ||
    selected.chainId !== "11155111" || selected.registryAddress !== "0x8004a818bfb912233c491871b3d84c89a494bd9e" ||
    selected.reference !== `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${selected.agentId}` ||
    signer.algorithm !== "ed25519" || signer.publicKey !== input.expectedPublicKey ||
    !Array.isArray(result.anchors) || result.anchors.length !== 3
  ) invalid("AGENT_HANDSHAKE_RESULT_INVALID");
  let accepted = false;
  try {
    const raw = Buffer.from(signer.publicKey, "base64");
    const signatureBytes = Buffer.from(signer.signature, "base64");
    if (raw.length !== 32 || signatureBytes.length !== 64) invalid("AGENT_HANDSHAKE_RESULT_INVALID");
    accepted = verify(
      null,
      canonicalBytes(result),
      createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" }),
      signatureBytes,
    );
  } catch (error) {
    if (error instanceof AgentHandshakeProtocolError) throw error;
  }
  if (!accepted) invalid("AGENT_HANDSHAKE_RESULT_INVALID");
  return Object.freeze({ result: Object.freeze({ ...result }), signer: Object.freeze({ ...signer }) });
}
