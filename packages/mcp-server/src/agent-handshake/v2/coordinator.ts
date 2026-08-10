import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";

import { generateRelayKeyPair, canonicalBytes, digestHex } from "../../handshake/protocol.js";
import type { HandshakeKey, HandshakeRecord, HandshakeStateStore } from "../../handshake/state.js";
import { createHandshakeStateStore, createIsolatedHandshakeStateStore } from "../../handshake/state.js";
import { createHandshakeRelayClient, normalizeRelayBaseUrl } from "../../handshake/relay.js";
import { recoverEip191Address, resolveOwnedAgentRegistration } from "../../handshake/evm.js";
import { authorizeV2RoleAccess, verifyV2RoleAccess, type V2AccessKey, type V2Role } from "./access.js";
import type { V2InvitationMetadata } from "./invitation-store.js";
import { createV2InvitationService, createV2InvitationStore } from "./invitation-store.js";
import {
  normalizeV2Acceptance,
  normalizeV2Descriptor,
  normalizeV2EvidenceResult,
  normalizeV2IdentityClaim,
  normalizeV2Party,
  normalizeV2Policy,
  normalizeV2Proposal,
  normalizeV2Result,
  normalizeV2Terms,
  v2CanonicalRecord,
} from "./protocol.js";

type JsonObject = Record<string, any>;
type InvitationService = Readonly<{
  create(input: { sessionId: string; statementDigest: string; nbfMs: string | number; expMs: string | number; metadata?: V2InvitationMetadata }): Promise<{ initiatorAccess: string; responderInvitation: string }>;
  accept(input: { invitation: string }): Promise<{ claimedAtMs: string | null; responderAccess: string; metadata: V2InvitationMetadata | null }>;
}>;
type Relay = Readonly<{
  fetchDiscovery(sessionId?: string): Promise<unknown>;
  getMessages(input: { sessionId: string; after?: string }): Promise<{ messages: readonly JsonObject[] }>;
  postMessage(input: { body: unknown; kind: string; privateKeyPem: string; role: V2Role; senderKey: string; sessionId: string }): Promise<unknown>;
  getResult(input: { sessionId: string }): Promise<unknown>;
}>;
type CoordinatorData = JsonObject & {
  discovery: JsonObject;
  terms: JsonObject;
  policyDigest?: string;
  sessionKeyAddress?: string;
  party?: JsonObject;
  counterpart?: JsonObject;
  pending?: { operation: "identity_claim" | "proposal" | "acceptance" | "evidence"; payload: JsonObject } | null;
  proposalEnvelope?: JsonObject;
  acceptanceEnvelope?: JsonObject;
  descriptorEnvelope?: JsonObject;
  sessionDigest?: string;
  transitions?: JsonObject[];
  evidenceUploaded?: boolean;
  certificateVerified?: boolean;
  relay?: { senderKey: string };
  stage?: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

export class V2CoordinatorError extends Error {
  constructor() { super("Agent handshake coordination failed safely."); this.name = "V2CoordinatorError"; }
}
function fail(): never { throw new V2CoordinatorError(); }

function exact(value: unknown, keys: readonly string[]): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const item = value as JsonObject;
  if (Object.keys(item).sort().join(",") !== [...keys].sort().join(",")) fail();
  return item;
}

function discovery(value: unknown): JsonObject {
  const item = exact(value, [
    "schema", "protocol", "sessionId", "repositorySha", "kitRepoUrl", "relayUrl",
    "createdAtMs", "invitationExpiresAtMs", "sessionDeadlineMs", "hostSessionKeyCertificate",
    "sessionOpenedBlock", "externalBusinessActionPerformed",
  ]);
  if (
    item.schema !== "clockchain.agent-handshake-discovery/v2" ||
    item.protocol !== "clockchain.agent-handshake/v2" || !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) || typeof item.kitRepoUrl !== "string" ||
    typeof item.relayUrl !== "string" || !DECIMAL.test(item.createdAtMs) ||
    !DECIMAL.test(item.invitationExpiresAtMs) || !DECIMAL.test(item.sessionDeadlineMs) ||
    !DECIMAL.test(item.sessionOpenedBlock) ||
    BigInt(item.createdAtMs) >= BigInt(item.invitationExpiresAtMs) ||
    BigInt(item.invitationExpiresAtMs) > BigInt(item.sessionDeadlineMs) ||
    item.hostSessionKeyCertificate === null || typeof item.hostSessionKeyCertificate !== "object" ||
    item.externalBusinessActionPerformed !== false
  ) fail();
  return Object.freeze(JSON.parse(JSON.stringify(item)));
}

function key(principal: string, session: string, role: V2Role): HandshakeKey { return { principal, session, role }; }
function data(record: HandshakeRecord | null): CoordinatorData { return (record?.data ?? {}) as CoordinatorData; }
function merge(current: HandshakeRecord | null, keyValue: HandshakeKey, patch: Partial<CoordinatorData>): HandshakeRecord {
  return {
    ...(current ?? { ...keyValue, status: "active" }),
    data: { ...data(current), ...patch },
    status: patch.certificateVerified ? "complete" : "active",
  };
}

function localPolicy(terms: JsonObject, role: V2Role): JsonObject {
  return normalizeV2Policy({
    schema: "clockchain.agent-handshake-policy/v1",
    protocol: "clockchain.agent-handshake/v2",
    role,
    mcpOrigin: "https://mcp.clockchain.network",
    reference: terms.reference,
    statementDigest: v2CanonicalRecord(terms).digest,
    maxValidForSeconds: terms.validForSeconds,
    identityPolicy: terms.identityPolicy,
    externalBusinessActionsAllowed: false,
  }) as JsonObject;
}

function metadataFrom(discoveryValue: JsonObject, terms: JsonObject): V2InvitationMetadata {
  return Object.freeze({
    terms,
    repositorySha: discoveryValue.repositorySha,
    hostSessionKeyCertificate: discoveryValue.hostSessionKeyCertificate,
    invitationExpiresAtMs: discoveryValue.invitationExpiresAtMs,
    sessionDeadlineMs: discoveryValue.sessionDeadlineMs,
    createdAtMs: discoveryValue.createdAtMs,
    sessionOpenedBlock: discoveryValue.sessionOpenedBlock,
  });
}

function signRequest(current: CoordinatorData, role: V2Role, operation: string, payload: JsonObject): JsonObject {
  const bytes = canonicalBytes(payload);
  return Object.freeze({
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: "2.1.0",
    operation,
    role,
    sessionId: current.discovery.sessionId,
    repositorySha: current.discovery.repositorySha,
    sessionDeadlineMs: current.discovery.sessionDeadlineMs,
    hostSessionKeyCertificate: current.discovery.hostSessionKeyCertificate,
    terms: current.terms,
    policyDigest: current.policyDigest,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
    externalBusinessActionPerformed: false,
  });
}

function signatureEnvelope(kind: "proposal" | "acceptance", payload: JsonObject, address: string, signatureHex: string): JsonObject {
  return Object.freeze({
    payload,
    schema: `clockchain.agent-handshake-${kind}-envelope/v2`,
    signature: Object.freeze({ address, algorithm: "eip191", value: signatureHex }),
  });
}

function evidenceEnvelope(result: JsonObject, address: string, signatureHex: string): JsonObject {
  return Object.freeze({
    result,
    schema: "clockchain.agent-handshake-evidence/v2",
    signature: Object.freeze({ address, algorithm: "eip191", value: signatureHex }),
  });
}

function find(entries: readonly JsonObject[], kind: string, role?: string): JsonObject | undefined {
  return [...entries].reverse().find((entry) => entry?.kind === kind && (role === undefined || entry?.role === role));
}

function funded(entries: readonly JsonObject[], role: V2Role, address: string): boolean {
  return entries.some((entry) => entry?.kind === "agent_v2_funding_record" && entry?.role === "host" && entry?.body?.role === role && entry?.body?.address === address);
}

export function createV2Coordinator(options: {
  accessKeys: readonly V2AccessKey[];
  activeAccessKey: V2AccessKey;
  invitationService: InvitationService;
  relay: Relay;
  stateStore?: HandshakeStateStore;
  now?: () => number;
  recoverEip191Address(input: { bytes: Buffer; signatureHex: string }): Promise<string>;
  resolveRegistration(input: { address: string; fromBlock: string }): Promise<JsonObject | null>;
  advanceTransitions(input: { descriptor: JsonObject; role: V2Role; existing: readonly JsonObject[] }): Promise<JsonObject[]>;
}) {
  const store = options.stateStore ?? createHandshakeStateStore();
  const now = options.now ?? Date.now;

  async function authorize(access: string, tool: string) {
    const verified = authorizeV2RoleAccess(access, { keys: options.accessKeys, nowMs: now(), requiredTool: tool });
    const keyValue = key(verified.principal, verified.payload.sessionId, verified.payload.role);
    const record = await store.get(keyValue);
    if (!record) fail();
    const current = data(record);
    if (v2CanonicalRecord(current.terms).digest !== verified.payload.statementDigest || current.discovery.sessionDeadlineMs !== verified.payload.expMs) fail();
    return { verified, keyValue, record, current };
  }

  async function post(keyValue: HandshakeKey, kind: string, body: unknown): Promise<void> {
    const record = await store.get(keyValue);
    const current = data(record);
    if (!record?.relayEd25519Pem || !current.relay?.senderKey) fail();
    const existing = find((await options.relay.getMessages({ sessionId: keyValue.session })).messages, kind, keyValue.role);
    if (existing && JSON.stringify(existing.body) === JSON.stringify(body)) return;
    await options.relay.postMessage({
      body, kind, privateKeyPem: record.relayEd25519Pem, role: keyValue.role as V2Role,
      senderKey: current.relay.senderKey, sessionId: keyValue.session,
    });
  }

  async function refresh(keyValue: HandshakeKey): Promise<CoordinatorData> {
    const record = await store.get(keyValue);
    if (!record) fail();
    const current = data(record);
    const entries = (await options.relay.getMessages({ sessionId: keyValue.session })).messages;
    const other = keyValue.role === "initiator" ? "responder" : "initiator";
    const ready = find(entries, "agent_v2_party_ready", other);
    const patch: Partial<CoordinatorData> = {};
    if (ready?.body) patch.counterpart = normalizeV2Party(ready.body, current.terms.identityPolicy) as JsonObject;
    const proposal = find(entries, "agent_v2_proposal", "initiator");
    if (proposal?.body?.proposalEnvelope) patch.proposalEnvelope = proposal.body.proposalEnvelope;
    const acceptance = find(entries, "agent_v2_acceptance", "responder");
    if (acceptance?.body?.acceptanceEnvelope) patch.acceptanceEnvelope = acceptance.body.acceptanceEnvelope;
    const descriptorMessage = find(entries, "agent_v2_handshake_required", "host");
    if (descriptorMessage?.body?.descriptorEnvelope?.descriptor) {
      const descriptor = normalizeV2Descriptor(descriptorMessage.body.descriptorEnvelope.descriptor);
      const sessionDigest = v2CanonicalRecord(descriptor).digest;
      if (descriptorMessage.body.sessionDigest !== sessionDigest || descriptor.sessionId !== keyValue.session) fail();
      patch.descriptorEnvelope = descriptorMessage.body.descriptorEnvelope;
      patch.sessionDigest = sessionDigest;
    }
    const updated = await store.update(keyValue, (value) => merge(value, keyValue, patch));
    return data(updated);
  }

  async function storeInitial(access: string, metadata: V2InvitationMetadata, role: V2Role): Promise<HandshakeKey> {
    const certificate = metadata.hostSessionKeyCertificate as JsonObject;
    const verified = verifyV2RoleAccess(access, {
      keys: options.accessKeys, nowMs: now(), expectedSessionId: certificate.certificate?.sessionId,
      expectedRole: role, expectedStatementDigest: v2CanonicalRecord(metadata.terms).digest,
      expectedExpMs: metadata.sessionDeadlineMs, requiredTool: "agent_handshake_join",
    });
    const found = discovery(await options.relay.fetchDiscovery(verified.payload.sessionId));
    if (
      found.repositorySha !== metadata.repositorySha || found.sessionDeadlineMs !== metadata.sessionDeadlineMs ||
      JSON.stringify(found.hostSessionKeyCertificate) !== JSON.stringify(metadata.hostSessionKeyCertificate)
    ) fail();
    const relayKey = generateRelayKeyPair();
    const keyValue = key(verified.principal, verified.payload.sessionId, role);
    await store.update(keyValue, (current) => ({
      ...merge(current, keyValue, { discovery: found, terms: metadata.terms, relay: { senderKey: relayKey.senderKey }, stage: "invited" }),
      relayEd25519Pem: relayKey.privateKeyPem,
    }));
    return keyValue;
  }

  return Object.freeze({
    async invite(value: unknown): Promise<JsonObject> {
      const terms = normalizeV2Terms(value) as JsonObject;
      const found = discovery(await options.relay.fetchDiscovery());
      if (now() >= Number(found.invitationExpiresAtMs)) fail();
      const metadata = metadataFrom(found, terms);
      const created = await options.invitationService.create({
        sessionId: found.sessionId,
        statementDigest: v2CanonicalRecord(terms).digest,
        nbfMs: found.createdAtMs,
        expMs: found.sessionDeadlineMs,
        metadata,
      });
      await storeInitial(created.initiatorAccess, metadata, "initiator");
      return Object.freeze({ ...created, endpoint: "https://mcp.clockchain.network/handshake/mcp", sessionId: found.sessionId, invitationExpiresAtMs: found.invitationExpiresAtMs, sessionDeadlineMs: found.sessionDeadlineMs, terms });
    },

    async acceptInvitation(invitation: string): Promise<JsonObject> {
      const accepted = await options.invitationService.accept({ invitation });
      if (!accepted.metadata || !accepted.claimedAtMs) fail();
      const keyValue = await storeInitial(accepted.responderAccess, accepted.metadata, "responder");
      await post(keyValue, "agent_v2_invitation_claimed", {
        claimedAtMs: accepted.claimedAtMs,
        externalBusinessActionPerformed: false,
      });
      return Object.freeze({ responderAccess: accepted.responderAccess, sessionId: (accepted.metadata.hostSessionKeyCertificate as JsonObject).certificate?.sessionId, terms: accepted.metadata.terms, sessionDeadlineMs: accepted.metadata.sessionDeadlineMs });
    },

    async join(input: { access: string; helperVersion: string; sessionKeyAddress: string; policyDigest: string }): Promise<JsonObject> {
      if (input.helperVersion !== "2.1.0" || !ADDRESS.test(input.sessionKeyAddress) || !DIGEST.test(input.policyDigest)) fail();
      const auth = await authorize(input.access, "agent_handshake_join");
      const expectedPolicy = localPolicy(auth.current.terms, auth.verified.payload.role);
      if (v2CanonicalRecord(expectedPolicy).digest !== input.policyDigest) fail();
      if (auth.current.policyDigest && (auth.current.policyDigest !== input.policyDigest || auth.current.sessionKeyAddress !== input.sessionKeyAddress)) fail();
      const claim = normalizeV2IdentityClaim({
        schema: "clockchain.agent-handshake-identity-claim/v2", protocol: "clockchain.agent-handshake/v2",
        sessionId: auth.keyValue.session, repositorySha: auth.current.discovery.repositorySha,
        role: auth.verified.payload.role, sessionKeyAddress: input.sessionKeyAddress,
        policyDigest: input.policyDigest, statementDigest: v2CanonicalRecord(auth.current.terms).digest,
        externalBusinessActionPerformed: false,
      }) as JsonObject;
      const updated = await store.update(auth.keyValue, (current) => merge(current, auth.keyValue, {
        policyDigest: input.policyDigest, sessionKeyAddress: input.sessionKeyAddress,
        pending: { operation: "identity_claim", payload: claim }, stage: "sign_identity",
      }));
      return Object.freeze({
        role: auth.verified.payload.role, sessionId: auth.keyValue.session,
        hostSessionKeyCertificate: auth.current.discovery.hostSessionKeyCertificate,
        repositorySha: auth.current.discovery.repositorySha, sessionDeadlineMs: auth.current.discovery.sessionDeadlineMs,
        signingRequest: signRequest(data(updated), auth.verified.payload.role, "identity_claim", claim),
      });
    },

    async status(input: { access: string }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_status");
      return Object.freeze({ role: auth.verified.payload.role, sessionId: auth.keyValue.session, stage: auth.current.stage ?? "invited", externalBusinessActionPerformed: false });
    },

    async next(input: { access: string }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_next");
      let current = await refresh(auth.keyValue);
      const role = auth.verified.payload.role;
      if (!current.policyDigest || !current.sessionKeyAddress) fail();
      if (current.pending) return Object.freeze({ stage: current.stage, signingRequest: signRequest(current, role, current.pending.operation, current.pending.payload) });
      const entries = (await options.relay.getMessages({ sessionId: auth.keyValue.session })).messages;
      if (!current.party) {
        if (current.terms.identityPolicy.erc8004 !== "not_required" && !funded(entries, role, current.sessionKeyAddress)) {
          return Object.freeze({ needed: "funding_record", role, sessionId: auth.keyValue.session, stage: "awaiting_funding" });
        }
        let registration = null;
        if (current.terms.identityPolicy.erc8004 !== "not_required") {
          registration = await options.resolveRegistration({ address: current.sessionKeyAddress, fromBlock: current.discovery.sessionOpenedBlock ?? "0" });
          if (!registration) return Object.freeze({
            needed: "erc8004_registration",
            role,
            sessionId: auth.keyValue.session,
            stage: "awaiting_identity_registration",
            identityPolicy: current.terms.identityPolicy,
            localAction: Object.freeze({
              executor: "pinned_helper",
              operation: "register",
              stateDir: "reuse_exact_absolute_state_dir",
              afterSuccess: "call_agent_handshake_next_with_unchanged_role_access",
            }),
          });
          if (current.terms.identityPolicy.erc8004 === "required_fresh" && BigInt(registration.registrationBlock) <= BigInt(current.discovery.sessionOpenedBlock ?? "0")) fail();
        }
        const party = normalizeV2Party({ sessionKeyAddress: current.sessionKeyAddress, policyDigest: current.policyDigest, erc8004: registration }, current.terms.identityPolicy) as JsonObject;
        await post(auth.keyValue, "agent_v2_party_ready", party);
        const updated = await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { party, stage: "party_ready" }));
        return Object.freeze({ needed: null, role, sessionId: auth.keyValue.session, stage: "party_ready", identity: party });
      }
      current = await refresh(auth.keyValue);
      if (!current.counterpart) return Object.freeze({ needed: "counterpart_identity", role, sessionId: auth.keyValue.session, stage: "awaiting_counterpart" });
      const parties = role === "initiator" ? { initiator: current.party, responder: current.counterpart } : { initiator: current.counterpart, responder: current.party };
      if (role === "initiator" && !current.proposalEnvelope) {
        const issuedAtMs = String(now());
        const proposal = normalizeV2Proposal({
          schema: "clockchain.agent-handshake-proposal/v2", protocol: "clockchain.agent-handshake/v2",
          sessionId: auth.keyValue.session, repositorySha: current.discovery.repositorySha,
          reference: current.terms.reference, statementDigest: v2CanonicalRecord(current.terms).digest,
          identityPolicy: current.terms.identityPolicy, initiator: parties.initiator, responder: parties.responder,
          issuedAtMs, expiresAtMs: String(BigInt(issuedAtMs) + BigInt(current.terms.validForSeconds) * 1000n),
          externalBusinessActionPerformed: false,
        }) as JsonObject;
        const updated = await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { pending: { operation: "proposal", payload: proposal }, stage: "sign_proposal" }));
        return Object.freeze({ stage: "sign_proposal", signingRequest: signRequest(data(updated), role, "proposal", proposal) });
      }
      if (role === "responder" && !current.acceptanceEnvelope) {
        if (!current.proposalEnvelope?.payload) return Object.freeze({ needed: "proposal", role, sessionId: auth.keyValue.session, stage: "awaiting_proposal" });
        const proposal = normalizeV2Proposal(current.proposalEnvelope.payload) as JsonObject;
        const acceptance = normalizeV2Acceptance({
          schema: "clockchain.agent-handshake-acceptance/v2", protocol: "clockchain.agent-handshake/v2",
          sessionId: proposal.sessionId, repositorySha: proposal.repositorySha, reference: proposal.reference,
          statementDigest: proposal.statementDigest, identityPolicy: proposal.identityPolicy,
          initiator: proposal.initiator, responder: proposal.responder, proposalDigest: digestHex(proposal),
          decision: "ACCEPTED", issuedAtMs: String(now()), expiresAtMs: proposal.expiresAtMs,
          externalBusinessActionPerformed: false,
        }) as JsonObject;
        const updated = await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { pending: { operation: "acceptance", payload: acceptance }, stage: "sign_acceptance" }));
        return Object.freeze({ stage: "sign_acceptance", signingRequest: signRequest(data(updated), role, "acceptance", acceptance) });
      }
      current = await refresh(auth.keyValue);
      if (!current.descriptorEnvelope?.descriptor || !current.sessionDigest) return Object.freeze({ needed: "descriptor", role, sessionId: auth.keyValue.session, stage: "awaiting_descriptor" });
      const descriptor = normalizeV2Descriptor(current.descriptorEnvelope.descriptor) as JsonObject;
      const transitions = await options.advanceTransitions({ descriptor, role, existing: current.transitions ?? [] });
      if (transitions.length !== 3) {
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { transitions, stage: "awaiting_anchors" }));
        return Object.freeze({ needed: "counterpart_transition", role, sessionId: auth.keyValue.session, stage: "awaiting_anchors" });
      }
      if (role === "initiator") await post(auth.keyValue, "agent_v2_anchor_report", { transitions });
      if (current.evidenceUploaded) return Object.freeze({ needed: "certificate", role, sessionId: auth.keyValue.session, stage: "awaiting_certificate" });
      const evidence = normalizeV2EvidenceResult({
        externalBusinessActionPerformed: false, party: current.party, policyDigest: current.policyDigest,
        reference: current.terms.reference, repositorySha: current.discovery.repositorySha, role,
        schema: "clockchain.agent-handshake-party-result/v2", sessionDigest: current.sessionDigest,
        statementDigest: v2CanonicalRecord(current.terms).digest,
        transitionDigests: transitions.map((entry) => entry.digest),
      }, current.terms.identityPolicy) as JsonObject;
      const updated = await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { transitions, pending: { operation: "evidence", payload: evidence }, stage: "sign_evidence" }));
      return Object.freeze({ stage: "sign_evidence", signingRequest: signRequest(data(updated), role, "evidence", evidence) });
    },

    async submit(input: { access: string; policyDigest: string; signatureHex: string }): Promise<JsonObject> {
      if (!DIGEST.test(input.policyDigest) || !SIGNATURE.test(input.signatureHex)) fail();
      const auth = await authorize(input.access, "agent_handshake_submit");
      const current = auth.current;
      if (!current.pending || current.policyDigest !== input.policyDigest || !current.sessionKeyAddress) fail();
      const bytes = canonicalBytes(current.pending.payload);
      const recovered = (await options.recoverEip191Address({ bytes, signatureHex: input.signatureHex })).toLowerCase();
      if (recovered !== current.sessionKeyAddress) fail();
      if (current.pending.operation === "identity_claim") {
        await post(auth.keyValue, "agent_v2_identity_claim", {
          claim: current.pending.payload,
          signature: { address: recovered, algorithm: "eip191", value: input.signatureHex },
        });
      } else if (current.pending.operation === "proposal") {
        const proposalEnvelope = signatureEnvelope("proposal", current.pending.payload, recovered, input.signatureHex);
        await post(auth.keyValue, "agent_v2_proposal", { proposalEnvelope });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { proposalEnvelope }));
      } else if (current.pending.operation === "acceptance") {
        const acceptanceEnvelope = signatureEnvelope("acceptance", current.pending.payload, recovered, input.signatureHex);
        await post(auth.keyValue, "agent_v2_acceptance", { acceptanceEnvelope });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { acceptanceEnvelope }));
      } else {
        await post(auth.keyValue, "agent_v2_evidence", { evidenceEnvelope: evidenceEnvelope(current.pending.payload, recovered, input.signatureHex) });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { evidenceUploaded: true }));
      }
      const stage = current.pending.operation === "identity_claim" ? "identity_claimed" : `${current.pending.operation}_submitted`;
      await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { pending: null, stage }));
      return Object.freeze({ role: auth.verified.payload.role, sessionId: auth.keyValue.session, stage });
    },

    async getCertificate(input: { access: string }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_get_certificate");
      if (!auth.current.evidenceUploaded) fail();
      let certificate;
      try { certificate = await options.relay.getResult({ sessionId: auth.keyValue.session }); }
      catch { return Object.freeze({ needed: "certificate", retryAfterMs: 5000, sessionId: auth.keyValue.session, stage: "awaiting_certificate" }); }
      const envelope = exact(certificate, ["hostSessionKeyCertificate", "result", "signer"]);
      const result = normalizeV2Result(envelope.result);
      if (
        result.sessionId !== auth.keyValue.session || result.outcome !== "VERIFIED" ||
        result.externalBusinessActionPerformed !== false ||
        result.policyDigests[auth.verified.payload.role] !== auth.current.policyDigest ||
        result.parties[auth.verified.payload.role].sessionKeyAddress !== auth.current.sessionKeyAddress
      ) fail();
      await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { certificateVerified: true, stage: "certificate_available" }));
      return Object.freeze({ certificate: envelope });
    },

    async invoke(name: string, args: JsonObject): Promise<unknown> {
      if (name === "agent_handshake_invite") return this.invite(args);
      if (name === "agent_handshake_accept_invitation") return this.acceptInvitation(args.invitation);
      if (name === "agent_handshake_join") return this.join(args as any);
      if (name === "agent_handshake_status") return this.status(args as any);
      if (name === "agent_handshake_next") return this.next(args as any);
      if (name === "agent_handshake_submit") return this.submit(args as any);
      if (name === "agent_handshake_get_certificate") return this.getCertificate(args as any);
      fail();
    },
  });
}

function accessKeyFromEnvironment(raw: string | undefined): V2AccessKey {
  if (!raw) fail();
  try {
    const parsed = JSON.parse(raw) as { kid?: unknown; secretBase64?: unknown };
    if (typeof parsed.kid !== "string" || typeof parsed.secretBase64 !== "string") fail();
    return Object.freeze({ kid: parsed.kid, secret: Buffer.from(parsed.secretBase64, "base64") });
  } catch { fail(); }
}

async function fetchV2Discovery(relayUrl: string, sessionId?: string): Promise<unknown> {
  const path = sessionId ? `/v1/discovery/${encodeURIComponent(sessionId)}` : "/v1/discovery/current";
  const response = await fetch(`${relayUrl}${path}`, { headers: { accept: "application/json" } });
  if (!response.ok) fail();
  return response.json();
}

function runtimeRelay(relayUrl: string): Relay {
  const base = createHandshakeRelayClient({ relayUrl }) as unknown as Relay;
  return Object.freeze({
    ...base,
    fetchDiscovery: (sessionId?: string) => fetchV2Discovery(relayUrl, sessionId),
  });
}

async function anchorV2(client: any, transition: JsonObject, canWrite: boolean): Promise<JsonObject | null> {
  const digest = v2CanonicalRecord(transition).digest;
  const reference = `agent-handshake-v2:${transition.sessionDigest}:${transition.kind.toLowerCase()}`;
  const found = (await client.searchAsset(reference)).filter((entry: JsonObject) => entry.assetReferenceId === reference && entry.assetHash === digest);
  if (found.length > 1) fail();
  let record = found[0];
  if (!record && canWrite) record = await client.log({ assetHash: digest, assetReferenceId: reference, additionalInfo: `agent handshake v2 ${transition.kind}` });
  if (!record) return null;
  const ledgerId = String(record.ledgerId ?? "");
  if (!UUID.test(ledgerId)) fail();
  const ledger = await client.getLedgerEntry(ledgerId);
  const blockHeight = String(ledger.blockHeight ?? "");
  if (!DECIMAL.test(blockHeight) || ledger.ledgerId !== ledgerId || ledger.assetHash !== digest || ledger.assetReferenceId !== reference) fail();
  const chain = await client.getChainRecord(blockHeight, ledgerId);
  if (!chain || chain.assetHash !== digest || chain.assetReferenceId !== reference || String(chain.blockHeight) !== blockHeight) fail();
  const block = await client.getBlock(blockHeight);
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  if (!blockTimeRaw) fail();
  return Object.freeze({ blockTimeRaw, digest, message: transition, onChain: Object.freeze({ blockHeight, ledgerId }) });
}

async function advanceRuntimeV2(client: any, input: { descriptor: JsonObject; role: V2Role; existing: readonly JsonObject[] }): Promise<JsonObject[]> {
  const descriptor = input.descriptor;
  const sessionDigest = v2CanonicalRecord(descriptor).digest;
  const base = {
    expiresAtMs: descriptor.agreementExpiresAtMs,
    externalBusinessActionPerformed: false,
    initiator: descriptor.initiator,
    protocol: "clockchain.agent-handshake/v2",
    reference: descriptor.reference,
    responder: descriptor.responder,
    schema: "clockchain.agent-handshake-transition/v2",
    sessionDigest,
    statementDigest: descriptor.statementDigest,
  };
  const transitions = [
    { ...base, kind: "PROPOSED", predecessor: null, sequence: "1" },
    { ...base, kind: "ACCEPTED", predecessor: "", sequence: "2" },
    { ...base, kind: "ACKNOWLEDGED", predecessor: "", sequence: "3" },
  ];
  transitions[1].predecessor = v2CanonicalRecord(transitions[0]).digest;
  transitions[2].predecessor = v2CanonicalRecord(transitions[1]).digest;
  const receipts: JsonObject[] = [];
  for (let index = 0; index < transitions.length; index += 1) {
    const owner = index === 1 ? "responder" : "initiator";
    const anchored = await anchorV2(client, transitions[index], input.role === owner);
    if (!anchored) return receipts;
    receipts.push(anchored);
  }
  return receipts;
}

export function createRuntimeV2Coordinator(env: Record<string, string | undefined> = process.env) {
  const activeAccessKey = accessKeyFromEnvironment(env.AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE);
  const accessKeys = [activeAccessKey];
  if (env.AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS) accessKeys.push(accessKeyFromEnvironment(env.AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS));
  const relayUrl = normalizeRelayBaseUrl(env.HANDSHAKE_RELAY ?? "");
  const relay = runtimeRelay(relayUrl);
  const invitationStore = createV2InvitationStore({ path: env.AGENT_HANDSHAKE_V2_INVITATION_FILE });
  const invitationService = createV2InvitationService({ activeKey: activeAccessKey, verificationKeys: accessKeys, store: invitationStore });
  const clockchain = new ClockchainClient(readConfigFromEnv(env));
  const rpcUrl = env.EVM_RPC_URL ?? env.SEPOLIA_RPC_URL;
  if (!rpcUrl) fail();
  return createV2Coordinator({
    accessKeys,
    activeAccessKey,
    invitationService,
    relay,
    stateStore: createIsolatedHandshakeStateStore(env.AGENT_HANDSHAKE_V2_STATE_FILE),
    recoverEip191Address: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl }),
    resolveRegistration: async ({ address, fromBlock }) => {
      const found = await resolveOwnedAgentRegistration({
        address, fromBlock, registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e", rpcUrl,
      });
      return found ? Object.freeze({
        agentId: found.agentId,
        chainId: "eip155:11155111",
        registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${found.agentId}`,
        registrationTx: found.registrationTx,
        registrationBlock: found.registrationBlock,
      }) : null;
    },
    advanceTransitions: (input) => advanceRuntimeV2(clockchain, input),
  });
}
