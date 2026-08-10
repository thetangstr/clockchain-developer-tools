import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import {
  type HandshakeKey,
  type HandshakeRecord,
  type HandshakeStateStore,
  createHandshakeStateStore,
} from "../handshake/state.js";
import { generateRelayKeyPair } from "../handshake/protocol.js";
import { createHandshakeRelayClient } from "../handshake/relay.js";
import {
  recoverEip191Address as recoverEip191AddressFromRpc,
  resolveOwnedAgentId as resolveOwnedAgentIdFromRpc,
} from "../handshake/evm.js";
import {
  type AgentHandshakeParty,
  type AgentHandshakeRole,
  type AgentHandshakeTerms,
  buildAgentAcceptance,
  buildAgentAcceptanceTransition,
  buildAgentAcknowledgment,
  buildAgentEvidenceResult,
  buildAgentProposal,
  buildAgentProposalTransition,
  agentDescriptorDigest,
  agentTransitionDigest,
  canonicalBytes,
  normalizeAgentHandshakeTerms,
  sealAgentAcceptance,
  sealAgentEvidence,
  sealAgentProposal,
  validateAgentAcceptanceEnvelope,
  validateAgentProposalEnvelope,
  verifyAgentDescriptorEnvelope,
  verifyAgentResultEnvelope,
} from "./protocol.js";

type JsonObject = Record<string, any>;
type SigningEncoding = "gzip-base64url" | "hex";
type RelayClient = {
  fetchDiscovery(sessionId?: string): Promise<JsonObject>;
  getMessages(input: { after?: string; sessionId: string }): Promise<{ messages: readonly JsonObject[] }>;
  postMessage(input: {
    body: unknown;
    kind: string;
    privateKeyPem: string;
    role: string;
    senderKey: string;
    sessionId: string;
  }): Promise<unknown>;
  getResult(input: { sessionId: string }): Promise<unknown>;
};
type CoordinatorData = JsonObject & {
  acceptanceEnvelope?: JsonObject;
  agentId?: string;
  certificateVerified?: boolean;
  counterpart?: AgentHandshakeParty & { senderKey: string };
  descriptorEnvelope?: JsonObject;
  discovery?: JsonObject;
  evidenceUploaded?: boolean;
  identityAddress?: string;
  pending?: { kind: "acceptance" | "evidence" | "proposal"; value: JsonObject } | null;
  proposalEnvelope?: JsonObject;
  relay?: { senderKey: string };
  sessionDigest?: string;
  terms?: AgentHandshakeTerms;
  testTransitions?: JsonObject[];
  transitions?: JsonObject[];
};
type ClockchainClient = {
  getBlock(height: string | number): Promise<JsonObject>;
  getChainRecord(blockHeight: string | number, ledgerId: string): Promise<JsonObject | null>;
  getLedgerEntry(ledgerId: string): Promise<JsonObject>;
  log(input: { additionalInfo?: string; assetHash: string; assetReferenceId: string }): Promise<JsonObject>;
  searchAsset(assetReferenceId: string): Promise<JsonObject[]>;
};
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;

export class AgentHandshakeCoordinatorError extends Error {
  constructor(readonly code = "AGENT_HANDSHAKE_COORDINATOR_ERROR") {
    super(`${code}: Agent handshake coordination failed.`);
    this.name = "AgentHandshakeCoordinatorError";
  }
}

function fail(code?: string): never {
  throw new AgentHandshakeCoordinatorError(code);
}

function role(value: string): AgentHandshakeRole {
  if (value !== "initiator" && value !== "responder") fail("AGENT_HANDSHAKE_ROLE_INVALID");
  return value;
}

function key(principal: string, session: string, roleValue: AgentHandshakeRole): HandshakeKey {
  return { principal, role: roleValue, session };
}

function data(record: HandshakeRecord | null): CoordinatorData {
  return (record?.data ?? {}) as CoordinatorData;
}

function merge(current: HandshakeRecord | null, keyValue: HandshakeKey, patch: CoordinatorData): HandshakeRecord {
  return {
    ...(current ?? { ...keyValue, status: "active" }),
    data: { ...data(current), ...patch },
    status: patch.certificateVerified ? "complete" : "active",
  };
}

function stringField(value: JsonObject, field: string, code: string): string {
  if (typeof value?.[field] !== "string" || value[field].length === 0) fail(code);
  return value[field];
}

function normalizeAddress(value: string): string {
  const address = value.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) fail("AGENT_HANDSHAKE_ADDRESS_INVALID");
  return address;
}

function signature(value: string): string {
  if (!/^0x[0-9a-f]{130}$/.test(value)) fail("AGENT_HANDSHAKE_SIGNATURE_INVALID");
  return value;
}

function signRequest(action: string, bytes: Buffer, extra: JsonObject, encoding: SigningEncoding): JsonObject {
  const bytesSha256 = createHash("sha256").update(bytes).digest("hex");
  if (encoding === "gzip-base64url") {
    return {
      action,
      bytesEncoding: "gzip-base64url",
      bytesSha256,
      bytesToSignGzipBase64Url: gzipSync(bytes).toString("base64url"),
      ...extra,
    };
  }
  return { action, bytesEncoding: "hex", bytesSha256, bytesToSignHex: bytes.toString("hex"), ...extra };
}

function signingEncoding(value: string): SigningEncoding {
  if (value === "hex" || value === "gzip-base64url") return value;
  fail("AGENT_HANDSHAKE_SIGNING_ENCODING_INVALID");
}

function identityBytes(sessionId: string, roleValue: AgentHandshakeRole, principal: string): Buffer {
  return canonicalBytes({
    nonce: createHash("sha256").update(`${principal}:${sessionId}:${roleValue}`).digest("hex"),
    protocol: "clockchain.agent-handshake/v1",
    role: roleValue,
    sessionId,
  });
}

async function messages(relay: RelayClient, sessionId: string): Promise<readonly JsonObject[]> {
  return (await relay.getMessages({ sessionId })).messages;
}

function findMessage(entries: readonly JsonObject[], kind: string, roleValue: string): JsonObject | undefined {
  return [...entries].reverse().find((entry) => entry?.kind === kind && entry?.role === roleValue);
}

function funding(entries: readonly JsonObject[], roleValue: AgentHandshakeRole, address: string): boolean {
  return entries.some((entry) =>
    entry?.kind === "funding_record" && entry?.role === "host" &&
    entry?.body?.role === roleValue && normalizeAddress(entry.body.funded) === address,
  );
}

async function post(
  relay: RelayClient,
  store: HandshakeStateStore,
  keyValue: HandshakeKey,
  kind: string,
  roleValue: AgentHandshakeRole,
  body: unknown,
): Promise<void> {
  const record = await store.get(keyValue);
  const senderKey = data(record).relay?.senderKey;
  if (!record?.relayEd25519Pem || !senderKey) fail("AGENT_HANDSHAKE_RELAY_KEY_MISSING");
  const existing = findMessage(await messages(relay, keyValue.session), kind, roleValue);
  if (existing && JSON.stringify(existing.body) === JSON.stringify(body)) return;
  await relay.postMessage({
    body,
    kind,
    privateKeyPem: record.relayEd25519Pem,
    role: roleValue,
    senderKey,
    sessionId: keyValue.session,
  });
}

async function refresh(
  relay: RelayClient,
  store: HandshakeStateStore,
  keyValue: HandshakeKey,
): Promise<HandshakeRecord> {
  const record = await store.get(keyValue);
  if (!record) fail("AGENT_HANDSHAKE_NOT_JOINED");
  const current = data(record);
  const entries = await messages(relay, keyValue.session);
  const other: AgentHandshakeRole = keyValue.role === "initiator" ? "responder" : "initiator";
  const identity = findMessage(entries, "identity_ready", other);
  const ready = findMessage(entries, "party_ready", other);
  const patch: CoordinatorData = {};
  if (identity && ready && identity.senderKey === ready.senderKey) {
    patch.counterpart = {
      address: normalizeAddress(identity.body.address),
      agentId: String(ready.body.agentId),
      senderKey: identity.senderKey,
    };
  }
  const proposalMessage = findMessage(entries, "agent_proposal", "initiator");
  if (proposalMessage?.body?.proposalEnvelope && !current.proposalEnvelope) {
    patch.proposalEnvelope = validateAgentProposalEnvelope(proposalMessage.body.proposalEnvelope) as JsonObject;
  }
  const acceptanceMessage = findMessage(entries, "agent_acceptance", "responder");
  if (acceptanceMessage?.body?.acceptanceEnvelope && !current.acceptanceEnvelope) {
    patch.acceptanceEnvelope = validateAgentAcceptanceEnvelope(
      acceptanceMessage.body.acceptanceEnvelope,
      (patch.proposalEnvelope ?? current.proposalEnvelope) as JsonObject,
    ) as JsonObject;
  }
  const descriptor = findMessage(entries, "agent_handshake_required", "host");
  if (descriptor?.body?.descriptorEnvelope) {
    patch.descriptorEnvelope = descriptor.body.descriptorEnvelope;
    patch.sessionDigest = descriptor.body.sessionDigest;
  }
  return await store.update(keyValue, (value) => merge(value, keyValue, patch)) as HandshakeRecord;
}

function anchorReference(sessionDigest: string, kind: string): string {
  return `agent-handshake:${sessionDigest}:${kind}`;
}

async function anchorTransition(
  clockchain: ClockchainClient,
  message: JsonObject,
  kind: string,
  canWrite: boolean,
): Promise<JsonObject | null> {
  const assetHash = agentTransitionDigest(message);
  const assetReferenceId = anchorReference(message.sessionDigest, kind);
  const found = (await clockchain.searchAsset(assetReferenceId)).filter((entry) =>
    entry.assetReferenceId === assetReferenceId && entry.assetHash === assetHash,
  );
  if (found.length > 1) fail("AGENT_HANDSHAKE_ANCHOR_DUPLICATE");
  let record = found[0];
  if (!record && canWrite) {
    record = await clockchain.log({ additionalInfo: `agent handshake ${kind}`, assetHash, assetReferenceId });
  }
  if (!record) return null;
  const ledgerId = String(record.ledgerId ?? "");
  if (!UUID_PATTERN.test(ledgerId)) fail("AGENT_HANDSHAKE_ANCHOR_INVALID");
  const ledger = await clockchain.getLedgerEntry(ledgerId);
  if (
    !DECIMAL_PATTERN.test(String(ledger.blockHeight)) || ledger.ledgerId !== ledgerId ||
    ledger.assetHash !== assetHash || ledger.assetReferenceId !== assetReferenceId
  ) fail("AGENT_HANDSHAKE_ANCHOR_INVALID");
  const chain = await clockchain.getChainRecord(String(ledger.blockHeight), ledgerId);
  if (
    !chain || chain.assetHash !== assetHash || chain.assetReferenceId !== assetReferenceId ||
    String(chain.blockHeight) !== String(ledger.blockHeight)
  ) fail("AGENT_HANDSHAKE_ANCHOR_INVALID");
  const block = await clockchain.getBlock(String(ledger.blockHeight));
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  if (!blockTimeRaw) fail("AGENT_HANDSHAKE_ANCHOR_INVALID");
  return Object.freeze({
    blockTimeRaw,
    digest: assetHash,
    message,
    onChain: Object.freeze({ blockHeight: String(ledger.blockHeight), ledgerId }),
  });
}

async function advanceRuntimeTransitions(
  clockchain: ClockchainClient,
  input: { data: CoordinatorData; role: AgentHandshakeRole },
): Promise<JsonObject[]> {
  const discoveryKey = input.data.discovery?.operatorPublicKey;
  if (!input.data.descriptorEnvelope || typeof discoveryKey !== "string") {
    fail("AGENT_HANDSHAKE_DESCRIPTOR_REQUIRED");
  }
  const descriptorEnvelope = verifyAgentDescriptorEnvelope(input.data.descriptorEnvelope, discoveryKey);
  const descriptor = descriptorEnvelope.descriptor;
  const sessionDigest = agentDescriptorDigest(descriptor);
  if (sessionDigest !== input.data.sessionDigest) fail("AGENT_HANDSHAKE_DESCRIPTOR_INVALID");
  const base = {
    expiresAtMs: descriptor.expiresAtMs,
    initiator: descriptor.initiator,
    reference: descriptor.reference,
    responder: descriptor.responder,
    sessionDigest,
    statementDigest: descriptor.statementDigest,
  };
  const transitions: JsonObject[] = [];
  const proposal = buildAgentProposalTransition(base);
  const anchoredProposal = await anchorTransition(clockchain, proposal as JsonObject, "proposal", input.role === "initiator");
  if (!anchoredProposal) return transitions;
  transitions.push(anchoredProposal);
  const acceptance = buildAgentAcceptanceTransition(base, proposal as JsonObject);
  const anchoredAcceptance = await anchorTransition(clockchain, acceptance as JsonObject, "acceptance", input.role === "responder");
  if (!anchoredAcceptance) return transitions;
  transitions.push(anchoredAcceptance);
  const acknowledgment = buildAgentAcknowledgment(base, acceptance as JsonObject);
  const anchoredAcknowledgment = await anchorTransition(clockchain, acknowledgment as JsonObject, "acknowledgment", input.role === "initiator");
  if (!anchoredAcknowledgment) return transitions;
  transitions.push(anchoredAcknowledgment);
  return transitions;
}

export function createRuntimeAgentHandshakeCoordinator(options: {
  clockchain: ClockchainClient;
  env?: Record<string, string | undefined>;
  principal: string;
  registryAddress?: string;
  relay?: RelayClient;
  relayUrl?: string;
  rpcUrl?: string;
  stateStore?: HandshakeStateStore;
}) {
  const env = options.env ?? process.env;
  const relay = options.relay ?? createHandshakeRelayClient({
    relayUrl: options.relayUrl ?? env.HANDSHAKE_RELAY,
  }) as unknown as RelayClient;
  return createAgentHandshakeCoordinator({
    advanceTransitions: (input) => advanceRuntimeTransitions(options.clockchain, input),
    principal: options.principal,
    recoverEip191Address: async ({ bytes, signatureHex }) => {
      const rpcUrl = options.rpcUrl ?? env.EVM_RPC_URL;
      if (!rpcUrl) fail("AGENT_HANDSHAKE_RPC_MISSING");
      return recoverEip191AddressFromRpc({ bytes, rpcUrl, signatureHex });
    },
    relay,
    resolveOwnedAgentId: async ({ address }) => {
      const rpcUrl = options.rpcUrl ?? env.EVM_RPC_URL;
      const registryAddress = options.registryAddress ?? env.ERC8004_REGISTRY_ADDRESS;
      if (!rpcUrl || !registryAddress) fail("AGENT_HANDSHAKE_IDENTITY_CONFIG_MISSING");
      return resolveOwnedAgentIdFromRpc({ address, registryAddress, rpcUrl });
    },
    stateStore: options.stateStore,
  });
}

export function createAgentHandshakeCoordinator(options: {
  advanceTransitions(input: { data: CoordinatorData; role: AgentHandshakeRole; sessionId: string }): Promise<JsonObject[]>;
  now?: () => number;
  principal: string;
  recoverEip191Address(input: { bytes: Buffer; signatureHex: string }): Promise<string>;
  relay: RelayClient;
  resolveOwnedAgentId(input: { address: string }): Promise<string | null>;
  stateStore?: HandshakeStateStore;
}) {
  const store = options.stateStore ?? createHandshakeStateStore();
  const now = options.now ?? Date.now;

  return Object.freeze({
    async status(sessionId?: string): Promise<JsonObject> {
      const records = (await store.list()).filter((entry) =>
        entry.principal === options.principal && (!sessionId || entry.session === sessionId),
      );
      return { sessions: records.map((entry) => ({ role: entry.role, sessionId: entry.session, stage: data(entry).stage ?? "joined" })) };
    },

    async join(roleInput: string, invitationId?: string, termsInput?: unknown): Promise<JsonObject> {
      const roleValue = role(roleInput);
      const terms = normalizeAgentHandshakeTerms(termsInput);
      const discovery = await options.relay.fetchDiscovery(invitationId);
      const sessionId = stringField(discovery, "sessionId", "AGENT_HANDSHAKE_DISCOVERY_INVALID");
      const keyValue = key(options.principal, sessionId, roleValue);
      const existing = await store.get(keyValue);
      if (existing?.data?.terms && JSON.stringify(existing.data.terms) !== JSON.stringify(terms)) {
        fail("AGENT_HANDSHAKE_TERMS_CONFLICT");
      }
      const relayKey = existing?.relayEd25519Pem && data(existing).relay
        ? { privateKeyPem: existing.relayEd25519Pem, senderKey: data(existing).relay!.senderKey }
        : generateRelayKeyPair();
      await store.update(keyValue, (current) => ({
        ...merge(current, keyValue, { discovery, relay: { senderKey: relayKey.senderKey }, terms }),
        relayEd25519Pem: relayKey.privateKeyPem,
      }));
      return {
        operatorPublicKey: stringField(discovery, "operatorPublicKey", "AGENT_HANDSHAKE_DISCOVERY_INVALID"),
        repositorySha: stringField(discovery, "repositorySha", "AGENT_HANDSHAKE_DISCOVERY_INVALID"),
        role: roleValue,
        sessionId,
        stage: existing?.data?.identityAddress ? "joined" : "sign_identity",
      };
    },

    async next(sessionId: string, roleInput: string, signingEncodingInput = "hex"): Promise<JsonObject> {
      const roleValue = role(roleInput);
      const encoding = signingEncoding(signingEncodingInput);
      const keyValue = key(options.principal, sessionId, roleValue);
      let record = await refresh(options.relay, store, keyValue);
      let current = data(record);
      if (!current.identityAddress) {
        return signRequest("sign_identity", identityBytes(sessionId, roleValue, options.principal), { role: roleValue, sessionId }, encoding);
      }
      if (!current.agentId) {
        const entries = await messages(options.relay, sessionId);
        if (!funding(entries, roleValue, current.identityAddress)) {
          return { needed: "funding_record", role: roleValue, sessionId, stage: "awaiting_funding" };
        }
        const agentId = await options.resolveOwnedAgentId({ address: current.identityAddress });
        if (!agentId) return { needed: "erc8004_identity", role: roleValue, sessionId, stage: "awaiting_identity_registration" };
        await post(options.relay, store, keyValue, "party_ready", roleValue, {
          address: current.identityAddress,
          agentId,
          externalActionPerformed: false,
        });
        await store.update(keyValue, (value) => merge(value, keyValue, { agentId, stage: "party_ready" }));
        return { agentId, needed: null, role: roleValue, sessionId, stage: "party_ready" };
      }
      record = await refresh(options.relay, store, keyValue);
      current = data(record);
      if (!current.counterpart?.agentId) {
        return { needed: "counterpart_identity", role: roleValue, sessionId, stage: "awaiting_counterpart" };
      }
      if (!current.identityAddress || !current.agentId) fail("AGENT_HANDSHAKE_IDENTITY_INVALID");
      const own: AgentHandshakeParty = { address: current.identityAddress, agentId: current.agentId };
      const counterpart: AgentHandshakeParty = {
        address: current.counterpart.address,
        agentId: current.counterpart.agentId,
      };
      const parties = roleValue === "initiator"
        ? { initiator: own, responder: counterpart }
        : { initiator: counterpart, responder: own };
      if (roleValue === "initiator" && !current.proposalEnvelope) {
        if (current.pending?.kind === "proposal") {
          return signRequest("sign_proposal", canonicalBytes(current.pending.value), { role: roleValue, sessionId }, encoding);
        }
        const issuedAtMs = String(now());
        const proposal = buildAgentProposal({
          expiresAtMs: String(BigInt(issuedAtMs) + BigInt(current.terms!.validForMinutes) * 60_000n),
          initiator: parties.initiator,
          issuedAtMs,
          repositorySha: current.discovery!.repositorySha,
          responder: parties.responder,
          sessionId,
          terms: current.terms!,
        });
        await store.update(keyValue, (value) => merge(value, keyValue, { pending: { kind: "proposal", value: proposal } }));
        return signRequest("sign_proposal", canonicalBytes(proposal), { role: roleValue, sessionId }, encoding);
      }
      if (roleValue === "responder" && !current.acceptanceEnvelope) {
        if (!current.proposalEnvelope) return { needed: "proposal", role: roleValue, sessionId, stage: "awaiting_proposal" };
        const proposal = validateAgentProposalEnvelope(current.proposalEnvelope).proposal;
        if (
          proposal.reference !== current.terms!.reference || proposal.statement !== current.terms!.statement ||
          proposal.validForMinutes !== current.terms!.validForMinutes || proposal.repositorySha !== current.discovery!.repositorySha ||
          proposal.responder.address !== own.address || proposal.responder.agentId !== own.agentId
        ) fail("AGENT_HANDSHAKE_PROPOSAL_MISMATCH");
        if (current.pending?.kind === "acceptance") {
          return signRequest("sign_acceptance", canonicalBytes(current.pending.value), { role: roleValue, sessionId }, encoding);
        }
        const acceptance = buildAgentAcceptance({ issuedAtMs: String(now()), proposalEnvelope: current.proposalEnvelope });
        await store.update(keyValue, (value) => merge(value, keyValue, { pending: { kind: "acceptance", value: acceptance } }));
        return signRequest("sign_acceptance", canonicalBytes(acceptance), { role: roleValue, sessionId }, encoding);
      }
      record = await refresh(options.relay, store, keyValue);
      current = data(record);
      if (!current.descriptorEnvelope || !current.sessionDigest) {
        return { needed: "descriptor", role: roleValue, sessionId, stage: "awaiting_descriptor" };
      }
      const descriptorEnvelope = verifyAgentDescriptorEnvelope(
        current.descriptorEnvelope,
        current.discovery!.operatorPublicKey,
      );
      const descriptor = descriptorEnvelope.descriptor;
      if (
        agentDescriptorDigest(descriptor) !== current.sessionDigest ||
        descriptor.sessionId !== sessionId || descriptor.repositorySha !== current.discovery!.repositorySha ||
        descriptor.reference !== current.terms!.reference || descriptor.statementDigest !== current.proposalEnvelope!.proposal.statementDigest ||
        descriptor.initiator.address !== parties.initiator.address || descriptor.initiator.agentId !== parties.initiator.agentId ||
        descriptor.responder.address !== parties.responder.address || descriptor.responder.agentId !== parties.responder.agentId
      ) fail("AGENT_HANDSHAKE_DESCRIPTOR_INVALID");
      const transitions = await options.advanceTransitions({ data: current, role: roleValue, sessionId });
      await store.update(keyValue, (value) => merge(value, keyValue, { transitions }));
      if (transitions.length !== 3) {
        return { needed: "counterpart_transition", role: roleValue, sessionId, stage: "awaiting_anchors" };
      }
      if (roleValue === "initiator") {
        await post(options.relay, store, keyValue, "agent_anchor_report", roleValue, { transitions });
      }
      if (current.evidenceUploaded) return { needed: "certificate", role: roleValue, sessionId, stage: "awaiting_certificate" };
      const evidenceResult = buildAgentEvidenceResult({
        party: own,
        reference: current.terms!.reference,
        repositorySha: current.discovery!.repositorySha,
        role: roleValue,
        sessionDigest: current.sessionDigest,
        statementDigest: current.proposalEnvelope!.proposal.statementDigest,
        transitionDigests: transitions.map((entry) => entry.digest),
      });
      await store.update(keyValue, (value) => merge(value, keyValue, { pending: { kind: "evidence", value: evidenceResult } }));
      return signRequest("sign_party_result", canonicalBytes(evidenceResult), { role: roleValue, sessionId }, encoding);
    },

    async submit(sessionId: string, roleInput: string, signatureHex: string): Promise<JsonObject> {
      const roleValue = role(roleInput);
      const signatureValue = signature(signatureHex);
      const keyValue = key(options.principal, sessionId, roleValue);
      const record = await store.get(keyValue);
      if (!record) fail("AGENT_HANDSHAKE_NOT_JOINED");
      const current = data(record);
      if (!current.identityAddress) {
        const recovered = normalizeAddress(await options.recoverEip191Address({
          bytes: identityBytes(sessionId, roleValue, options.principal),
          signatureHex: signatureValue,
        }));
        await post(options.relay, store, keyValue, "identity_ready", roleValue, { address: recovered });
        await store.update(keyValue, (value) => merge(value, keyValue, { identityAddress: recovered, stage: "identity_ready" }));
        return { role: roleValue, sessionId, stage: "identity_ready" };
      }
      if (!current.pending) fail("AGENT_HANDSHAKE_NO_PENDING_SIGNATURE");
      const recovered = normalizeAddress(await options.recoverEip191Address({
        bytes: canonicalBytes(current.pending.value),
        signatureHex: signatureValue,
      }));
      if (recovered !== current.identityAddress) fail("AGENT_HANDSHAKE_SIGNATURE_ROLE_MISMATCH");
      if (current.pending.kind === "proposal") {
        const proposalEnvelope = sealAgentProposal(current.pending.value, signatureValue) as JsonObject;
        await post(options.relay, store, keyValue, "agent_proposal", roleValue, { proposalEnvelope });
        await store.update(keyValue, (value) => merge(value, keyValue, { pending: null, proposalEnvelope, stage: "proposal_posted" }));
        return { role: roleValue, sessionId, stage: "proposal_posted" };
      }
      if (current.pending.kind === "acceptance") {
        const acceptanceEnvelope = sealAgentAcceptance(current.pending.value, signatureValue) as JsonObject;
        await post(options.relay, store, keyValue, "agent_acceptance", roleValue, { acceptanceEnvelope });
        await store.update(keyValue, (value) => merge(value, keyValue, { acceptanceEnvelope, pending: null, stage: "acceptance_posted" }));
        return { role: roleValue, sessionId, stage: "acceptance_posted" };
      }
      const evidenceEnvelope = sealAgentEvidence(current.pending.value, signatureValue);
      await post(options.relay, store, keyValue, "agent_evidence", roleValue, { evidenceEnvelope });
      await store.update(keyValue, (value) => merge(value, keyValue, { evidenceUploaded: true, pending: null, stage: "evidence_uploaded" }));
      return { role: roleValue, sessionId, stage: "evidence_uploaded" };
    },

    async getCertificate(sessionId: string): Promise<JsonObject> {
      const records = (await store.list()).filter((entry) => entry.principal === options.principal && entry.session === sessionId);
      const record = records.find((entry) => data(entry).evidenceUploaded);
      if (!record) fail("AGENT_HANDSHAKE_EVIDENCE_REQUIRED");
      let certificate: unknown;
      try {
        certificate = await options.relay.getResult({ sessionId });
      } catch {
        return { needed: "certificate", retryAfterMs: 5000, sessionId, stage: "awaiting_certificate" };
      }
      try {
        const current = data(record);
        if (!current.identityAddress || !current.agentId || !current.sessionDigest) {
          fail("AGENT_HANDSHAKE_CERTIFICATE_INVALID");
        }
        verifyAgentResultEnvelope(certificate, {
          expectedParty: { address: current.identityAddress, agentId: current.agentId },
          expectedPublicKey: current.discovery!.operatorPublicKey,
          expectedRole: role(record.role),
          expectedSessionDigest: current.sessionDigest,
          expectedSessionId: sessionId,
        });
        await store.update(key(options.principal, sessionId, role(record.role)), (value) =>
          merge(value, key(options.principal, sessionId, role(record.role)), {
            certificateVerified: true,
            stage: "certificate_verified",
          }),
        );
        return { certificate };
      } catch {
        fail("AGENT_HANDSHAKE_CERTIFICATE_INVALID");
      }
    },
  });
}
