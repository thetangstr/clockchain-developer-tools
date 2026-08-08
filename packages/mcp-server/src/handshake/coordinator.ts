import { createHash, randomUUID } from "node:crypto";
import {
  buildAcceptance,
  buildAcknowledgment,
  buildEvidencePackage,
  buildProposal,
  canonicalBytes,
  digestHex,
  generateRelayKeyPair,
  partySignatureBytes,
  preparePayerMandate,
  preparePaymentRequest,
  sealPayerMandate,
  sealPaymentRequest,
  sessionKey as protocolSessionKey,
  verifyDescriptorEnvelope,
  verifyResultEnvelope,
} from "./protocol.js";
import {
  createHandshakeStateStore,
  handshakeKeyHash,
  type HandshakeKey,
  type HandshakeRecord,
  type HandshakeStateStore,
} from "./state.js";
import { createHandshakeRelayClient } from "./relay.js";
import {
  recoverEip191Address as recoverEip191AddressFromRpc,
  resolveOwnedAgentId as resolveOwnedAgentIdFromRpc,
} from "./evm.js";

type JsonObject = Record<string, any>;
type PublicRole = "payer" | "requestor";
type EvidenceRole = "payer" | "payee";

type RelayClient = {
  fetchDiscovery(): Promise<JsonObject>;
  getMessages(input: { after?: string; sessionId: string }): Promise<{ messages: readonly JsonObject[] }>;
  postMessage(input: {
    body: unknown;
    kind: string;
    privateKeyPem: string;
    role: PublicRole;
    senderKey: string;
    sessionId: string;
  }): Promise<unknown>;
  putEvidence(input: {
    json: string;
    markdown: string;
    marker: string;
    role: EvidenceRole;
    sessionId: string;
  }): Promise<unknown>;
  getResult(input: { sessionId: string }): Promise<unknown>;
};

type ClockchainClient = {
  getTimestamp?: () => Promise<JsonObject>;
  getPoolHealth?: () => Promise<JsonObject>;
  searchAsset(assetReferenceId: string): Promise<JsonObject[]>;
  log(input: { assetHash: string; assetReferenceId: string; additionalInfo?: string }): Promise<JsonObject>;
  getLedgerEntry(ledgerId: string): Promise<JsonObject>;
  getChainRecord(blockHeight: string | number, ledgerId: string): Promise<JsonObject | null>;
  getBlock(height: string | number): Promise<JsonObject>;
};

type WriteBudget = {
  check?: () => void;
  record?: () => void;
};

type CoordinatorState = JsonObject & {
  agentId?: string;
  certificateVerified?: boolean;
  counterpart?: { address: string; agentId?: string; senderKey?: string };
  discovery?: JsonObject;
  evidenceVerified?: boolean;
  identityAddress?: string;
  identityNonce?: string;
  mandateEnvelope?: JsonObject;
  partySignatureBytesHex?: string;
  pendingArtifact?: JsonObject | null;
  pendingWrite?: { bodyDigest: string; kind: string; role: PublicRole } | null;
  relay?: { senderKey: string } | null;
  requestEnvelope?: JsonObject;
  sessionDigest?: string;
  transitions?: JsonObject[];
};

export class HandshakeCoordinatorError extends Error {
  constructor(message: string, readonly code = "HANDSHAKE_COORDINATOR_ERROR") {
    super(`${code}: ${message}`);
    this.name = new.target.name;
  }
}

export function createRuntimeHandshakeCoordinator(options: {
  budget?: WriteBudget;
  clockchain: ClockchainClient;
  env?: Record<string, string | undefined>;
  principal: string;
  registryAddress?: string;
  relay?: RelayClient;
  relayUrl?: string | (() => string | undefined);
  rpcUrl?: string;
  stateStore?: HandshakeStateStore;
}) {
  const env = options.env ?? process.env;
  const stateStore = options.stateStore ?? createHandshakeStateStore(env);
  const relayForCall = (): RelayClient => {
    if (options.relay) return options.relay;
    const resolvedRelayUrl = typeof options.relayUrl === "function" ? options.relayUrl() : options.relayUrl;
    return createHandshakeRelayClient({ relayUrl: resolvedRelayUrl ?? env.HANDSHAKE_RELAY });
  };
  const coordinatorForCall = () => createHandshakeCoordinator({
    budget: options.budget,
    clockchain: options.clockchain,
    env,
    principal: options.principal,
    recoverEip191Address: async ({ bytes, signatureHex }) => {
      const rpcUrl = options.rpcUrl ?? env.EVM_RPC_URL;
      if (!rpcUrl) throw new HandshakeCoordinatorError("Handshake RPC URL is not configured.", "RPC_URL_MISSING");
      return recoverEip191AddressFromRpc({ bytes, rpcUrl, signatureHex });
    },
    relay: relayForCall(),
    resolveOwnedAgentId: async ({ address }) => {
      const rpcUrl = options.rpcUrl ?? env.EVM_RPC_URL;
      const registryAddress = options.registryAddress ?? env.ERC8004_REGISTRY_ADDRESS;
      if (!rpcUrl || !registryAddress) throw new HandshakeCoordinatorError("Handshake EVM identity lookup is not configured.", "EVM_IDENTITY_CONFIG_MISSING");
      return resolveOwnedAgentIdFromRpc({ address, registryAddress, rpcUrl });
    },
    stateStore,
  });
  return Object.freeze({
    getCertificate: (sessionId: string) => coordinatorForCall().getCertificate(sessionId),
    join: (role: string) => coordinatorForCall().join(role),
    next: (sessionId: string, role: string) => coordinatorForCall().next(sessionId, role),
    status: (sessionId?: string) => coordinatorForCall().status(sessionId),
    submit: (sessionId: string, role: string, signatureHex: string) => coordinatorForCall().submit(sessionId, role, signatureHex),
  });
}

export function createHandshakeCoordinator(options: {
  clockchain: ClockchainClient;
  env?: Record<string, string | undefined>;
  principal: string;
  recoverEip191Address(input: { bytes: Buffer; signatureHex: string }): Promise<string>;
  relay: RelayClient;
  resolveOwnedAgentId(input: { address: string }): Promise<string | null>;
  stateStore?: HandshakeStateStore;
  budget?: WriteBudget;
}) {
  const stateStore = options.stateStore ?? createHandshakeStateStore();
  const env = options.env ?? process.env;
  const principal = options.principal;

  const api = {
    __testDelay: undefined as undefined | (() => Promise<void>),

    async status(sessionId?: string): Promise<JsonObject> {
      const resolvedSessionId = sessionId ?? stringField(await options.relay.fetchDiscovery(), "sessionId", "DISCOVERY_INVALID");
      const filtered = await exactRoleRecords(stateStore, principal, resolvedSessionId);
      return {
        sessions: filtered.map((record) => publicStatus(record)),
      };
    },

    async join(roleInput: string): Promise<JsonObject> {
      const role = publicRole(roleInput);
      const discovery = await options.relay.fetchDiscovery();
      const sessionId = stringField(discovery, "sessionId", "DISCOVERY_INVALID");
      const key = stateKey(principal, sessionId, role);
      return withGlobalLock(key, async () => {
        const current = await ensureRecord(stateStore, key, discovery);
        const ownAddress = typeof current.data?.identityAddress === "string" ? current.data.identityAddress : undefined;
        const messages = await loadMessages(options.relay, sessionId);
        const seat = findSeat(messages, role);
        const ownSenderKey = dataOf(current).relay?.senderKey;
        if (seat && (
          !ownAddress ||
          normalizeAddress(seat.body.address) !== normalizeAddress(ownAddress) ||
          (ownSenderKey && seat.senderKey !== ownSenderKey)
        )) {
          throw new HandshakeCoordinatorError("Handshake role is already bound to another identity.", "ROLE_ALREADY_BOUND");
        }
        const next = await stateStore.update(key, (record) => {
          const currentSenderKey = record ? dataOf(record).relay?.senderKey : undefined;
          const relay = record?.relayEd25519Pem && currentSenderKey
            ? { privateKeyPem: record.relayEd25519Pem, senderKey: currentSenderKey }
            : generateRelayKeyPair();
          return mergeData(key, { ...record, relayEd25519Pem: relay.privateKeyPem } as HandshakeRecord | null, {
            discovery,
            relay: { senderKey: relay.senderKey },
          });
        });
        return {
          relayUrl: discovery.relayUrl,
          repositorySha: discovery.repositorySha,
          sessionId,
          stage: next?.data?.identityAddress ? "joined" : "sign_identity",
        };
      });
    },

    async next(sessionId: string, roleInput: string): Promise<JsonObject> {
      const role = publicRole(roleInput);
      const key = stateKey(principal, sessionId, role);
      return withGlobalLock(key, async () => {
        if (api.__testDelay) await api.__testDelay();
        let record = await requireRecord(stateStore, key);
        record = await refreshFromMailbox(options, stateStore, key, record);
        const data = dataOf(record);

        if (!data.identityAddress) {
          const bytes = identityClaimBytes(sessionId, role, data);
          return signRequest("sign_identity", bytes, {
            role,
            sessionId,
          });
        }

        if (!data.agentId) {
          const funding = fundingFor(await loadMessages(options.relay, sessionId), role, data.identityAddress);
          if (!funding) return { needed: "funding_record", sessionId, stage: "awaiting_funding" };
          const agentId = await options.resolveOwnedAgentId({ address: data.identityAddress });
          if (!agentId) {
            return { needed: "erc8004_identity", sessionId, stage: "awaiting_identity_registration" };
          }
          await postMailboxIdempotent(options.relay, stateStore, key, {
            body: { address: data.identityAddress, agentId, paymentMoved: false },
            kind: "party_ready",
            role,
          });
          record = await stateStore.update(key, (current) => mergeData(key, current, { agentId, stage: "party_ready" })) as HandshakeRecord;
        }

        record = await refreshFromMailbox(options, stateStore, key, record);
        const latest = dataOf(record);

        if (role === "payer" && !latest.mandateEnvelope) {
          if (!latest.counterpart?.address || !latest.counterpart.agentId) {
            return { needed: "requestor_identity_ready", sessionId, stage: "awaiting_counterpart" };
          }
          if (latest.pendingArtifact?.mandate) {
            return signRequest("sign_mandate", canonicalBytes(latest.pendingArtifact.mandate), { sessionId });
          }
          const artifact = await prepareMandate(options.clockchain, latest, sessionId);
          await stateStore.update(key, (current) => mergeData(key, current, { pendingArtifact: artifact, stage: "sign_mandate" }));
          return signRequest("sign_mandate", canonicalBytes(artifact.mandate), { sessionId });
        }

        if (role === "requestor" && !latest.requestEnvelope) {
          if (!latest.mandateEnvelope) {
            return { needed: "payer_mandate", sessionId, stage: "awaiting_mandate" };
          }
          if (latest.pendingArtifact?.request) {
            return signRequest("sign_payment_request", canonicalBytes(latest.pendingArtifact.request), { sessionId });
          }
          const artifact = prepareRequest(latest, sessionId);
          await stateStore.update(key, (current) => mergeData(key, current, { pendingArtifact: artifact, stage: "sign_payment_request" }));
          return signRequest("sign_payment_request", canonicalBytes(artifact.request), { sessionId });
        }

        record = await refreshFromMailbox(options, stateStore, key, record);
        const ready = dataOf(record);
        if (ready.certificateVerified) {
          return { needed: null, sessionId, stage: "certificate_verified" };
        }
        if (ready.evidenceVerified) {
          return { needed: "certificate", sessionId, stage: "awaiting_certificate" };
        }
        if (!ready.sessionDigest) {
          return { needed: "handshake_required", sessionId, stage: "awaiting_descriptor" };
        }

        if (role === "requestor" && !hasMessage(await loadMessages(options.relay, sessionId), "watching", role, ready.relay?.senderKey)) {
          await postMailboxIdempotent(options.relay, stateStore, key, {
            body: { paymentMoved: false },
            kind: "watching",
            role,
          });
        }
        let transitions: JsonObject[];
        try {
          transitions = await advanceTransitions(options.clockchain, stateStore, key, ready, role, env, options.budget);
        } catch (error) {
          if (error instanceof HandshakeCoordinatorError && error.code === "ANCHOR_PENDING") {
            return { needed: "clockchain_confirmation", sessionId, stage: "awaiting_clockchain_confirmation" };
          }
          throw error;
        }
        if (role === "payer" && transitions.length === 3) {
          await postAnchorReport(options.relay, stateStore, key, transitions);
        }
        if ((role === "payer" && transitions.length < 3) || (role === "requestor" && transitions.length < 2)) {
          await stateStore.update(key, (current) => mergeData(key, current, {
            stage: "awaiting_counterpart_transition",
            transitions,
          }));
          return { needed: "counterpart_transition", sessionId, stage: "awaiting_counterpart_transition" };
        }
        const bytes = partySignatureBytes({
          role: evidenceRole(role),
          sessionDigest: ready.sessionDigest,
          transitions,
        });
        await stateStore.update(key, (current) => mergeData(key, current, {
          partySignatureBytesHex: bytes.toString("hex"),
          stage: "sign_party_result",
          transitions,
        }));
        return signRequest("sign_party_result", bytes, { sessionDigest: ready.sessionDigest, sessionId });
      });
    },

    async submit(sessionId: string, roleInput: string, signatureHex: string): Promise<JsonObject> {
      const role = publicRole(roleInput);
      validateEip191Signature(signatureHex);
      const key = stateKey(principal, sessionId, role);
      return withGlobalLock(key, async () => {
        let record = await requireRecord(stateStore, key);
        const data = dataOf(record);
        if (data.evidenceVerified) return publicProgress(record, "evidence_uploaded");
        if (!data.identityAddress) {
          const recovered = normalizeAddress(await options.recoverEip191Address({
            bytes: identityClaimBytes(sessionId, role, data),
            signatureHex,
          }));
          const seat = findSeat(await loadMessages(options.relay, sessionId), role);
          if (seat && normalizeAddress(seat.body.address) !== recovered) {
            throw new HandshakeCoordinatorError("Handshake role is already bound to another identity.", "ROLE_ALREADY_BOUND");
          }
          await postMailboxIdempotent(options.relay, stateStore, key, {
            body: { address: recovered },
            kind: "identity_ready",
            role,
          });
          const updated = await stateStore.update(key, (current) => mergeData(key, current, {
            identityAddress: recovered,
            stage: "identity_ready",
          }));
          return publicProgress(updated, "identity_ready");
        }

        if (data.pendingArtifact && role === "payer" && !data.mandateEnvelope) {
          const recovered = normalizeAddress(await options.recoverEip191Address({
            bytes: canonicalBytes(data.pendingArtifact.mandate),
            signatureHex,
          }));
          if (recovered !== data.identityAddress) throw new HandshakeCoordinatorError("Signature did not recover the payer address.", "SIGNATURE_ROLE_MISMATCH");
          const mandateEnvelope = sealPayerMandate(data.pendingArtifact.mandate, eip191Signature(signatureHex));
          const mandateBody = {
            common: data.pendingArtifact.common,
            expiresAtMs: data.pendingArtifact.mandate.expiresAtMs,
            issuedAtMs: data.pendingArtifact.mandate.issuedAtMs,
            mandateEnvelope,
            paymentMoved: false,
            sessionUuid: data.pendingArtifact.mandate.sessionId,
          };
          await postMailboxIdempotent(options.relay, stateStore, key, {
            body: mandateBody,
            kind: "mandate",
            role,
          });
          const updated = await stateStore.update(key, (current) => mergeData(key, current, {
            mandateBody,
            mandateEnvelope,
            pendingArtifact: null,
            stage: "mandate_posted",
          }));
          return publicProgress(updated, "mandate_posted");
        }

        if (data.pendingArtifact && role === "requestor" && !data.requestEnvelope) {
          const recovered = normalizeAddress(await options.recoverEip191Address({
            bytes: canonicalBytes(data.pendingArtifact.request),
            signatureHex,
          }));
          if (recovered !== data.identityAddress) throw new HandshakeCoordinatorError("Signature did not recover the requestor address.", "SIGNATURE_ROLE_MISMATCH");
          const requestEnvelope = sealPaymentRequest(data.pendingArtifact.request, eip191Signature(signatureHex));
          await postMailboxIdempotent(options.relay, stateStore, key, {
            body: { paymentMoved: false, requestEnvelope },
            kind: "payment_request",
            role,
          });
          const updated = await stateStore.update(key, (current) => mergeData(key, current, {
            pendingArtifact: null,
            requestEnvelope,
            stage: "payment_request_posted",
          }));
          return publicProgress(updated, "payment_request_posted");
        }

        if (data.partySignatureBytesHex) {
          const bytes = Buffer.from(data.partySignatureBytesHex, "hex");
          const recovered = normalizeAddress(await options.recoverEip191Address({ bytes, signatureHex }));
          if (recovered !== data.identityAddress) throw new HandshakeCoordinatorError("Signature did not recover the party address.", "SIGNATURE_ROLE_MISMATCH");
          if (!data.poolHealth) throw new HandshakeCoordinatorError("Observed pool health is required before evidence upload.", "POOL_HEALTH_UNAVAILABLE");
          const evidence = buildEvidencePackage({
            ackObserved: (data.transitions ?? []).length === 3,
            deadlineMs: data.transitions?.[0]?.blockTimeMs ? String(Number(data.transitions[0].blockTimeMs) + 600000) : null,
            localVerdict: "LOCAL_OK",
            paymentMoved: false,
            poolHealth: data.poolHealth,
            promptSha256: data.descriptor?.promptSha256 ?? "0".repeat(64),
            protocolVersion: "1",
            rendezvous: { channel: "derived-reference-id", degradedAtSubmission: Boolean(data.poolHealth.degradedAtSubmission), tenancy: "unknown" },
            repositorySha: data.discovery?.repositorySha,
            role: evidenceRole(role),
            schema: "clockchain.bilateral-party-result/v1",
            sessionDigest: data.sessionDigest,
            signature: { address: recovered, algorithm: "eip191", signature: eip191Signature(signatureHex) },
            transitions: data.transitions ?? [],
          });
          await options.relay.putEvidence({ ...evidence, role: evidenceRole(role), sessionId });
          const updated = await stateStore.update(key, (current) => mergeData(key, current, {
            evidenceVerified: true,
            stage: "evidence_uploaded",
          }));
          return publicProgress(updated, "evidence_uploaded");
        }

        throw new HandshakeCoordinatorError("No pending signature bytes for this handshake.", "NO_PENDING_SIGNATURE");
      });
    },

    async getCertificate(sessionId: string): Promise<JsonObject> {
      const [record] = (await exactRoleRecords(stateStore, principal, sessionId))
        .filter((entry) => entry.data?.evidenceVerified);
      if (!record?.data?.evidenceVerified) {
        throw new HandshakeCoordinatorError("Certificate is unavailable before verified evidence upload.", "CERTIFICATE_EVIDENCE_UNVERIFIED");
      }
      try {
        const role = publicRole(record.role);
        const key = stateKey(principal, sessionId, role);
        let data = record.data as CoordinatorState;
        if (role === "requestor" && (data.transitions ?? []).length === 2) {
          const transitions = await advanceTransitions(options.clockchain, stateStore, key, data, role, env, options.budget);
          if (transitions.length > (data.transitions ?? []).length) {
            await stateStore.update(key, (current) => mergeData(key, current, { transitions }));
            data = { ...data, transitions };
          }
        }
        const envelope = await options.relay.getResult({ sessionId });
        const result = verifyResultEnvelope(envelope as JsonObject, {
          expectedPublicKey: (record.data as JsonObject).discovery.operatorPublicKey,
        });
        if (result.sessionDigest !== data.sessionDigest || result.sessionId !== data.discovery?.sessionId) {
          throw new HandshakeCoordinatorError("Certificate session binding mismatch.", "CERTIFICATE_INVALID");
        }
        if (result.subjectRun !== data.mandateEnvelope?.mandate?.subjectRun) {
          throw new HandshakeCoordinatorError("Certificate subject run does not bind the signed artifacts.", "CERTIFICATE_INVALID");
        }
        validateCertificateBindings(result, data);
        await stateStore.update(key, (current) => mergeData(key, current, {
          certificateVerified: true,
          stage: "certificate_verified",
        }));
        return { certificate: envelope };
      } catch (error) {
        if (error instanceof HandshakeCoordinatorError) throw error;
        throw new HandshakeCoordinatorError("Certificate verification failed.", "CERTIFICATE_INVALID");
      }
    },
  };

  return api;
}

async function exactRoleRecords(store: HandshakeStateStore, principal: string, sessionId: string): Promise<HandshakeRecord[]> {
  const records = await Promise.all(
    (["payer", "requestor"] as const).map((role) => store.get(stateKey(principal, sessionId, role))),
  );
  return records.filter((record): record is HandshakeRecord => record !== null);
}

async function refreshFromMailbox(
  options: {
    relay: RelayClient;
    stateStore?: HandshakeStateStore;
  } & Parameters<typeof createHandshakeCoordinator>[0],
  stateStore: HandshakeStateStore,
  key: HandshakeKey,
  record: HandshakeRecord,
): Promise<HandshakeRecord> {
  const role = publicRole(key.role);
  const data = dataOf(record);
  const messages = await loadMessages(options.relay, key.session);
  const counterpartRole: PublicRole = role === "payer" ? "requestor" : "payer";
  const identity = findSeat(messages, counterpartRole);
  const party = findPartyReady(messages, counterpartRole, identity?.body?.address);
  const patch: CoordinatorState = {};
  if (identity) {
    patch.counterpart = {
      address: normalizeAddress(identity.body.address),
      agentId: party?.body?.agentId,
      senderKey: identity.senderKey,
    };
  }
  if (party && identity && party.senderKey !== identity.senderKey) {
    throw new HandshakeCoordinatorError("Counterpart identity_ready and party_ready sender keys differ.", "COUNTERPART_BINDING_MISMATCH");
  }
  if (party && identity) {
    const resolvedAgentId = await options.resolveOwnedAgentId({ address: normalizeAddress(identity.body.address) });
    if (resolvedAgentId !== party.body.agentId) {
      throw new HandshakeCoordinatorError("Counterpart party_ready does not match on-chain reverse ownership.", "COUNTERPART_BINDING_MISMATCH");
    }
  }
  const payerSeat = findSeat(messages, "payer");
  const mandate = findRoleMessage(messages, "mandate", "payer");
  if (mandate && (!payerSeat || mandate.senderKey !== payerSeat.senderKey)) {
    throw new HandshakeCoordinatorError("Payer mandate did not come from the seated relay sender.", "COUNTERPART_BINDING_MISMATCH");
  }
  if (role === "requestor" && mandate?.body?.mandateEnvelope && !data.mandateEnvelope) {
    const mandateEnvelope = await verifyMandateBody(options, mandate.body, data);
    patch.mandateBody = mandate.body;
    patch.mandateEnvelope = mandateEnvelope;
  }
  const requestorSeat = findSeat(messages, "requestor");
  const request = findRoleMessage(messages, "payment_request", "requestor");
  if (request && (!requestorSeat || request.senderKey !== requestorSeat.senderKey)) {
    throw new HandshakeCoordinatorError("Payment request did not come from the seated relay sender.", "COUNTERPART_BINDING_MISMATCH");
  }
  if (role === "payer" && request?.body?.requestEnvelope && !data.requestEnvelope) {
    patch.requestEnvelope = await verifyRequestBody(options, request.body, data);
  }
  const descriptor = findRoleMessage(messages, "handshake_required", "host");
  if (descriptor?.body && !data.sessionDigest) {
    assertExactObjectKeys(descriptor.body, ["descriptorEnvelope", "paymentMoved", "repositoryPublicKey"], "DESCRIPTOR_BODY_INVALID");
    if (descriptor.body.paymentMoved !== false) {
      throw new HandshakeCoordinatorError("Descriptor body paymentMoved must be false.", "DESCRIPTOR_BODY_INVALID");
    }
    const effectiveData = { ...data, ...patch };
    if (!effectiveData.mandateEnvelope || !effectiveData.requestEnvelope) return Object.keys(patch).length === 0
      ? record
      : await stateStore.update(key, (current) => mergeData(key, current, patch)) as HandshakeRecord;
    const discovery = effectiveData.discovery;
    if (!discovery) throw new HandshakeCoordinatorError("Discovery is not loaded.", "DISCOVERY_INVALID");
    if (descriptor.body.repositoryPublicKey !== discovery?.operatorPublicKey) {
      throw new HandshakeCoordinatorError("Descriptor repository key does not match discovery.", "DESCRIPTOR_KEY_MISMATCH");
    }
    const verified = verifyDescriptorEnvelope(descriptor.body.descriptorEnvelope, {
      repositoryPublicKey: discovery.operatorPublicKey,
    });
    await validateDescriptorBindings(options, verified.descriptor, effectiveData, role);
    patch.descriptor = verified.descriptor;
    patch.sessionDigest = verified.sessionDigest;
  }
  if (Object.keys(patch).length === 0) return record;
  return await stateStore.update(key, (current) => mergeData(key, current, patch)) as HandshakeRecord;
}

async function verifyMandateBody(
  options: Parameters<typeof createHandshakeCoordinator>[0],
  body: JsonObject,
  data: CoordinatorState,
): Promise<JsonObject> {
  assertExactObjectKeys(body, ["common", "expiresAtMs", "issuedAtMs", "mandateEnvelope", "paymentMoved", "sessionUuid"], "MANDATE_BODY_INVALID");
  if (body.paymentMoved !== false) throw new HandshakeCoordinatorError("Mandate body paymentMoved must be false.", "MANDATE_BODY_INVALID");
  const envelope = body.mandateEnvelope;
  const mandate = envelope?.mandate;
  const prepared = preparePayerMandate(mandate);
  if (digestHex(prepared) !== digestHex(mandate)) {
    throw new HandshakeCoordinatorError("Mandate canonical body mismatch.", "MANDATE_BODY_INVALID");
  }
  const canonicalEnvelope = sealPayerMandate(prepared, eip191Signature(envelope?.signature?.value));
  if (digestHex(canonicalEnvelope) !== digestHex(envelope)) {
    throw new HandshakeCoordinatorError("Mandate envelope is not the exact canonical shape.", "MANDATE_BODY_INVALID");
  }
  if (
    body.expiresAtMs !== prepared.expiresAtMs ||
    body.issuedAtMs !== prepared.issuedAtMs ||
    body.sessionUuid !== prepared.sessionId ||
    digestHex(body.common) !== digestHex({
      amount: prepared.amount,
      intakeDigest: prepared.intakeDigest,
      intakeRequestId: prepared.intakeRequestId,
      payee: prepared.payee,
      payer: prepared.payer,
      paymentMoved: false,
      protocol: prepared.protocol,
      purpose: prepared.purpose,
      releaseId: prepared.releaseId,
      repositorySha: prepared.repositorySha,
      sessionId: prepared.sessionId,
      subjectRun: prepared.subjectRun,
    })
  ) {
    throw new HandshakeCoordinatorError("Mandate body bindings mismatch.", "MANDATE_BODY_INVALID");
  }
  if (envelope.signature?.address !== prepared.payer.address) {
    throw new HandshakeCoordinatorError("Mandate signer address does not match payer.", "ARTIFACT_SIGNATURE_MISMATCH");
  }
  const recovered = normalizeAddress(await options.recoverEip191Address({
    bytes: canonicalBytes(prepared),
    signatureHex: eip191Signature(envelope.signature?.value),
  }));
  if (recovered !== prepared.payer.address || (data.counterpart?.address && recovered !== data.counterpart.address)) {
    throw new HandshakeCoordinatorError("Mandate signature did not recover the counterpart payer.", "ARTIFACT_SIGNATURE_MISMATCH");
  }
  return envelope;
}

async function validateDescriptorBindings(
  options: Parameters<typeof createHandshakeCoordinator>[0],
  descriptor: JsonObject,
  data: CoordinatorState,
  role: PublicRole,
): Promise<void> {
  if (!data.mandateEnvelope?.mandate || !data.requestEnvelope?.request) {
    throw new HandshakeCoordinatorError("Descriptor arrived before both signed commercial artifacts.", "DESCRIPTOR_ARTIFACT_MISSING");
  }
  const mandate = data.mandateEnvelope.mandate;
  const request = data.requestEnvelope.request;
  const ownParty = role === "payer" ? descriptor.payer : descriptor.payee;
  const counterpartParty = role === "payer" ? descriptor.payee : descriptor.payer;
  if (data.identityAddress && normalizeAddress(ownParty.address) !== normalizeAddress(data.identityAddress)) {
    throw new HandshakeCoordinatorError("Descriptor does not bind the local identity address.", "DESCRIPTOR_PARTY_MISMATCH");
  }
  if (data.agentId && ownParty.agentId !== data.agentId) {
    throw new HandshakeCoordinatorError("Descriptor does not bind the local agent id.", "DESCRIPTOR_PARTY_MISMATCH");
  }
  if (data.counterpart?.address && normalizeAddress(counterpartParty.address) !== normalizeAddress(data.counterpart.address)) {
    throw new HandshakeCoordinatorError("Descriptor does not bind the counterpart identity address.", "DESCRIPTOR_PARTY_MISMATCH");
  }
  if (data.counterpart?.agentId && counterpartParty.agentId !== data.counterpart.agentId) {
    throw new HandshakeCoordinatorError("Descriptor does not bind the counterpart agent id.", "DESCRIPTOR_PARTY_MISMATCH");
  }
  for (const party of [descriptor.payer, descriptor.payee]) {
    const resolved = await options.resolveOwnedAgentId({ address: party.address });
    if (resolved !== party.agentId) {
      throw new HandshakeCoordinatorError("Descriptor party agent id does not match on-chain reverse ownership.", "DESCRIPTOR_PARTY_MISMATCH");
    }
  }
  if (descriptor.mandateDigest !== digestHex(mandate)) {
    throw new HandshakeCoordinatorError("Descriptor mandate digest does not bind the stored mandate.", "DESCRIPTOR_ARTIFACT_MISMATCH");
  }
  if (descriptor.requestDigest !== digestHex(request)) {
    throw new HandshakeCoordinatorError("Descriptor request digest does not bind the stored request.", "DESCRIPTOR_ARTIFACT_MISMATCH");
  }
  if (
    descriptor.repositorySha !== data.discovery?.repositorySha ||
    descriptor.repositorySha !== mandate.repositorySha ||
    descriptor.repositorySha !== request.repositorySha ||
    descriptor.sessionId !== compactSessionId(mandate.sessionId) ||
    descriptor.sessionId !== compactSessionId(request.sessionId) ||
    descriptor.amountOptions.length !== 1 ||
    digestHex(descriptor.amountOptions[0]) !== digestHex(request.amount) ||
    digestHex({ address: descriptor.payer.address, agentId: descriptor.payer.agentId }) !== digestHex(request.payer) ||
    digestHex({ address: descriptor.payee.address, agentId: descriptor.payee.agentId }) !== digestHex(request.payee)
  ) {
    throw new HandshakeCoordinatorError("Descriptor commercial bindings do not match the signed artifacts.", "DESCRIPTOR_ARTIFACT_MISMATCH");
  }
}

async function verifyRequestBody(
  options: Parameters<typeof createHandshakeCoordinator>[0],
  body: JsonObject,
  data: CoordinatorState,
): Promise<JsonObject> {
  assertExactObjectKeys(body, ["paymentMoved", "requestEnvelope"], "REQUEST_BODY_INVALID");
  if (body.paymentMoved !== false) throw new HandshakeCoordinatorError("Request body paymentMoved must be false.", "REQUEST_BODY_INVALID");
  const envelope = body.requestEnvelope;
  const request = envelope?.request;
  const prepared = preparePaymentRequest(request);
  if (digestHex(prepared) !== digestHex(request)) {
    throw new HandshakeCoordinatorError("Request canonical body mismatch.", "REQUEST_BODY_INVALID");
  }
  const canonicalEnvelope = sealPaymentRequest(prepared, eip191Signature(envelope?.signature?.value));
  if (digestHex(canonicalEnvelope) !== digestHex(envelope)) {
    throw new HandshakeCoordinatorError("Request envelope is not the exact canonical shape.", "REQUEST_BODY_INVALID");
  }
  if (envelope.signature?.address !== prepared.payee.address) {
    throw new HandshakeCoordinatorError("Request signer address does not match payee.", "ARTIFACT_SIGNATURE_MISMATCH");
  }
  const recovered = normalizeAddress(await options.recoverEip191Address({
    bytes: canonicalBytes(prepared),
    signatureHex: eip191Signature(envelope.signature?.value),
  }));
  if (recovered !== prepared.payee.address || (data.counterpart?.address && recovered !== data.counterpart.address)) {
    throw new HandshakeCoordinatorError("Request signature did not recover the counterpart requestor.", "ARTIFACT_SIGNATURE_MISMATCH");
  }
  const mandate = data.mandateEnvelope?.mandate;
  if (!mandate) {
    throw new HandshakeCoordinatorError("Payment request arrived before the payer mandate.", "REQUEST_BODY_INVALID");
  }
  if (
    prepared.mandateDigest !== digestHex(mandate) ||
    prepared.createdAtMs !== mandate.issuedAtMs ||
    prepared.expiresAtMs !== mandate.expiresAtMs ||
    prepared.intakeDigest !== mandate.intakeDigest ||
    prepared.intakeRequestId !== mandate.intakeRequestId ||
    !prepared.invoiceReference.startsWith(mandate.invoiceReferencePrefix) ||
    !sameCanonical(prepared.amount, mandate.amount) ||
    !sameCanonical(prepared.payee, mandate.payee) ||
    !sameCanonical(prepared.payer, mandate.payer) ||
    prepared.purpose !== mandate.purpose ||
    prepared.releaseId !== mandate.releaseId ||
    prepared.repositorySha !== mandate.repositorySha ||
    prepared.sessionId !== mandate.sessionId ||
    prepared.subjectRun !== mandate.subjectRun
  ) {
    throw new HandshakeCoordinatorError("Request commercial fields do not bind to the payer mandate.", "REQUEST_BODY_INVALID");
  }
  return envelope;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return digestHex(left) === digestHex(right);
}

function assertExactObjectKeys(value: unknown, keys: string[], code: string): asserts value is JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HandshakeCoordinatorError("Expected object.", code);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new HandshakeCoordinatorError("Unexpected object shape.", code);
  }
}

async function postMailboxIdempotent(
  relay: RelayClient,
  store: HandshakeStateStore,
  key: HandshakeKey,
  input: { body: unknown; kind: string; role: PublicRole },
): Promise<void> {
  const record = await requireRecord(store, key);
  const senderKey = dataOf(record).relay?.senderKey;
  const privateKeyPem = record.relayEd25519Pem;
  if (!privateKeyPem || !senderKey) {
    throw new HandshakeCoordinatorError("Relay key missing for handshake session.", "RELAY_KEY_MISSING");
  }
  const messages = await loadMessages(relay, key.session);
  const bodyDigest = digestHex(input.body);
  const pending = dataOf(record).pendingWrite;
  const exactMessageExists = hasMessage(messages, input.kind, input.role, senderKey, input.body);
  if (pending) {
    if (pending.bodyDigest !== bodyDigest || pending.kind !== input.kind || pending.role !== input.role) {
      throw new HandshakeCoordinatorError("Stored mailbox write intent does not match the requested message.", "AMBIGUOUS_WRITE");
    }
    if (!exactMessageExists) {
      throw new HandshakeCoordinatorError("Stored mailbox write intent is unreconciled.", "AMBIGUOUS_WRITE");
    }
    await clearPendingMailboxWrite(store, key, input);
    return;
  }
  if (exactMessageExists) return;

  await store.update(key, (current) => mergeData(key, current, {
    pendingWrite: { bodyDigest, kind: input.kind, role: input.role },
  }));
  try {
    await relay.postMessage({
      body: input.body,
      kind: input.kind,
      privateKeyPem,
      role: input.role,
      senderKey,
      sessionId: key.session,
    });
  } catch (error) {
    const reconciled = await loadMessages(relay, key.session);
    if (hasMessage(reconciled, input.kind, input.role, senderKey, input.body)) {
      await store.update(key, (current) => mergeData(key, current, { pendingWrite: null }));
      return;
    }
    throw new HandshakeCoordinatorError("Mailbox write was ambiguous and could not be reconciled.", "AMBIGUOUS_WRITE");
  }
  await store.update(key, (current) => mergeData(key, current, { pendingWrite: null }));
}

async function advanceTransitions(
  clockchain: ClockchainClient,
  store: HandshakeStateStore,
  key: HandshakeKey,
  data: CoordinatorState,
  role: PublicRole,
  env: Record<string, string | undefined>,
  budget?: WriteBudget,
): Promise<JsonObject[]> {
  const descriptor = data.descriptor;
  if (!descriptor || !data.sessionDigest) throw new HandshakeCoordinatorError("Descriptor is not ready.", "DESCRIPTOR_NOT_READY");
  const transitions: JsonObject[] = [...(data.transitions ?? [])];
  if (transitions.length === 0) {
    const proposal = buildProposal({
      amount: descriptor.amountOptions[0],
      descriptor,
      sessionDigest: data.sessionDigest,
    });
    const existing = await readAnchoredTransition(clockchain, data.sessionDigest, "proposal", proposal);
    if (existing) {
      await clearPendingClockWrite(store, key, "proposal", existing);
      transitions.push(existing);
    }
    else if (role === "payer") transitions.push(await writeAnchoredTransition(clockchain, store, key, data.sessionDigest, "proposal", proposal, env, budget));
  }
  if (role === "requestor" && transitions.length === 1) {
    const acceptance = buildAcceptance({
      proposal: transitions[0].message,
      proposalTriple: tripleFor(transitions[0], "proposal"),
    });
    const existing = await readAnchoredTransition(clockchain, data.sessionDigest, "acceptance", acceptance);
    if (existing) {
      await clearPendingClockWrite(store, key, "acceptance", existing);
      transitions.push(existing);
    }
    else transitions.push(await writeAnchoredTransition(clockchain, store, key, data.sessionDigest, "acceptance", acceptance, env, budget));
  }
  if (role === "payer" && transitions.length === 1) {
    const acceptance = buildAcceptance({
      proposal: transitions[0].message,
      proposalTriple: tripleFor(transitions[0], "proposal"),
    });
    const existing = await readAnchoredTransition(clockchain, data.sessionDigest, "acceptance", acceptance);
    if (existing) {
      await clearPendingClockWrite(store, key, "acceptance", existing);
      transitions.push(existing);
    }
  }
  if (role === "payer" && transitions.length === 2) {
    const acknowledgment = buildAcknowledgment({
      acceptance: transitions[1].message,
      acceptanceTriple: tripleFor(transitions[1], "acceptance"),
      proposalTriple: tripleFor(transitions[0], "proposal"),
    });
    const existing = await readAnchoredTransition(clockchain, data.sessionDigest, "acknowledgment", acknowledgment);
    if (existing) {
      await clearPendingClockWrite(store, key, "acknowledgment", existing);
      transitions.push(existing);
    }
    else transitions.push(await writeAnchoredTransition(clockchain, store, key, data.sessionDigest, "acknowledgment", acknowledgment, env, budget));
  }
  if (role === "requestor" && transitions.length === 2) {
    const acknowledgment = buildAcknowledgment({
      acceptance: transitions[1].message,
      acceptanceTriple: tripleFor(transitions[1], "acceptance"),
      proposalTriple: tripleFor(transitions[0], "proposal"),
    });
    const existing = await readAnchoredTransition(clockchain, data.sessionDigest, "acknowledgment", acknowledgment);
    if (existing) {
      await clearPendingClockWrite(store, key, "acknowledgment", existing);
      transitions.push(existing);
    }
  }
  return transitions;
}

async function readAnchoredTransition(
  clockchain: ClockchainClient,
  sessionDigest: string,
  kind: "proposal" | "acceptance" | "acknowledgment",
  message: Readonly<JsonObject>,
): Promise<JsonObject | null> {
  const referenceId = protocolSessionKey(sessionDigest, kind);
  const hash = digestHex(message);
  const records = await clockchain.searchAsset(referenceId);
  const exact = records.filter((record) => record.assetReferenceId === referenceId && record.assetHash === hash);
  const mismatches = records.filter((record) => record.assetReferenceId === referenceId && record.assetHash !== hash);
  if (exact.length > 1 || mismatches.length > 0) {
    throw new HandshakeCoordinatorError("Duplicate or mismatched transition record found.", "DUPLICATE_WRITE_MISMATCH");
  }
  if (exact.length === 0) return null;
  return confirmedTransition(clockchain, message, exact[0]);
}

async function writeAnchoredTransition(
  clockchain: ClockchainClient,
  store: HandshakeStateStore,
  key: HandshakeKey,
  sessionDigest: string,
  kind: "proposal" | "acceptance" | "acknowledgment",
  message: Readonly<JsonObject>,
  env: Record<string, string | undefined>,
  budget?: WriteBudget,
): Promise<JsonObject> {
  const current = await requireRecord(store, key);
  const adopted = await readAnchoredTransition(clockchain, sessionDigest, kind, message);
  const referenceId = protocolSessionKey(sessionDigest, kind);
  const hash = digestHex(message);
  if (adopted) {
    await clearPendingClockWrite(store, key, kind, adopted);
    return adopted;
  }
  const pendingClockWrite = dataOf(current).pendingClockWrite;
  if (pendingClockWrite) {
    if (
      pendingClockWrite.kind !== kind ||
      pendingClockWrite.assetReferenceId !== referenceId ||
      pendingClockWrite.assetHash !== hash
    ) {
      throw new HandshakeCoordinatorError("Stored Clockchain write intent does not match the requested transition.", "AMBIGUOUS_WRITE");
    }
    if (pendingClockWrite.ledgerId) {
      const confirmed = await confirmedTransition(clockchain, message, pendingClockWrite);
      await store.update(key, (current) => mergeData(key, current, { pendingClockWrite: null }));
      return confirmed;
    }
    throw new HandshakeCoordinatorError("Stored Clockchain write intent is unreconciled.", "AMBIGUOUS_WRITE");
  }
  const poolHealth = await assertPoolHealthy(clockchain, env);
  await store.update(key, (current) => mergeData(key, current, { poolHealth }));
  budget?.check?.();
  await store.update(key, (current) => mergeData(key, current, {
    pendingClockWrite: { assetHash: hash, assetReferenceId: referenceId, kind },
  }));
  let logRecord: JsonObject;
  try {
    logRecord = await clockchain.log({
      additionalInfo: `handshake ${kind}`,
      assetHash: hash,
      assetReferenceId: referenceId,
    });
    budget?.record?.();
    await store.update(key, (current) => mergeData(key, current, {
      pendingClockWrite: { assetHash: hash, assetReferenceId: referenceId, kind, ledgerId: logRecord.ledgerId },
    }));
  } catch {
    const reconciled = await readAnchoredTransition(clockchain, sessionDigest, kind, message);
    if (reconciled) {
      await store.update(key, (current) => mergeData(key, current, { pendingClockWrite: null }));
      return reconciled;
    }
    throw new HandshakeCoordinatorError("Clockchain write was ambiguous and could not be reconciled.", "AMBIGUOUS_WRITE");
  }
  const confirmed = await confirmedTransition(clockchain, message, logRecord);
  await store.update(key, (current) => mergeData(key, current, { pendingClockWrite: null }));
  return confirmed;
}

async function confirmedTransition(clockchain: ClockchainClient, message: Readonly<JsonObject>, record: JsonObject): Promise<JsonObject> {
  const ledgerId = String(record.ledgerId ?? "");
  const expectedHash = digestHex(message);
  const expectedReference = protocolSessionKey(message.sessionDigest, message.kind);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(ledgerId) ||
    (record.assetHash !== undefined && record.assetHash !== expectedHash) ||
    (record.assetReferenceId !== undefined && record.assetReferenceId !== expectedReference)
  ) {
    throw new HandshakeCoordinatorError("Clockchain record identifiers do not bind the transition.", "ANCHOR_UNVERIFIED");
  }
  const ledger = await clockchain.getLedgerEntry(ledgerId);
  if (!ledger?.blockHeight) throw new HandshakeCoordinatorError("Clockchain ledger record is not anchored yet.", "ANCHOR_PENDING");
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(String(ledger.blockHeight)) ||
    ledger.ledgerId !== ledgerId ||
    ledger.assetHash !== expectedHash ||
    ledger.assetReferenceId !== expectedReference
  ) {
    throw new HandshakeCoordinatorError("Anchored ledger record does not bind the transition.", "ANCHOR_UNVERIFIED");
  }
  const chain = await clockchain.getChainRecord(ledger.blockHeight, ledgerId);
  if (
    !chain ||
    chain.assetHash !== expectedHash ||
    chain.assetReferenceId !== expectedReference ||
    String(chain.blockHeight) !== String(ledger.blockHeight)
  ) {
    throw new HandshakeCoordinatorError("Immutable chain record did not verify the transition.", "ANCHOR_UNVERIFIED");
  }
  const block = await clockchain.getBlock(String(ledger.blockHeight));
  if (block.blockHeight !== undefined && String(block.blockHeight) !== String(ledger.blockHeight)) {
    throw new HandshakeCoordinatorError("Clockchain block height did not verify the transition.", "ANCHOR_UNVERIFIED");
  }
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  const blockTimeMsNumber = parseBlockTimeMs(blockTimeRaw);
  if (!Number.isFinite(blockTimeMsNumber)) {
    throw new HandshakeCoordinatorError("Clockchain block time is unavailable or invalid.", "BLOCK_TIME_INVALID");
  }
  const blockTimeMs = String(blockTimeMsNumber);
  return {
    blockTimeMs,
    blockTimeRaw,
    digest: digestHex(message),
    message,
    onChain: {
      anchoredHash: String(chain.assetHash),
      blockHeight: String(chain.blockHeight),
      ledgerId,
    },
    upperBoundMs: message.kind === "proposal" ? null : String(Number(blockTimeMs) + 1100),
  };
}

async function clearPendingClockWrite(
  store: HandshakeStateStore,
  key: HandshakeKey,
  kind: "proposal" | "acceptance" | "acknowledgment",
  transition: JsonObject,
): Promise<void> {
  const record = await store.get(key);
  const pending = record?.data?.pendingClockWrite as JsonObject | undefined;
  if (!pending) return;
  if (
    pending.kind === kind &&
    pending.assetHash === transition.digest &&
    (!pending.ledgerId || pending.ledgerId === transition.onChain?.ledgerId)
  ) {
    await store.update(key, (current) => mergeData(key, current, { pendingClockWrite: null }));
  }
}

async function clearPendingMailboxWrite(
  store: HandshakeStateStore,
  key: HandshakeKey,
  input: { body: unknown; kind: string; role: PublicRole },
): Promise<void> {
  const record = await store.get(key);
  const pending = record?.data?.pendingWrite as JsonObject | undefined;
  if (
    pending &&
    pending.kind === input.kind &&
    pending.role === input.role &&
    pending.bodyDigest === digestHex(input.body)
  ) {
    await store.update(key, (current) => mergeData(key, current, { pendingWrite: null }));
  }
}

function parseBlockTimeMs(value: string): number {
  if (/^\d{2}-\d{2}-\d{4}_/.test(value)) return parseClockchainLedgerTime(value);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})Z$/.exec(value);
  if (!match) throw new HandshakeCoordinatorError("Clockchain block time shape is invalid.", "BLOCK_TIME_INVALID");
  const parts = match.slice(1, 7).map(Number);
  const milliseconds = Number(match[7].padEnd(3, "0").slice(0, 3));
  const parsed = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5], milliseconds);
  const roundTrip = new Date(parsed);
  if (
    !Number.isFinite(parsed) ||
    roundTrip.getUTCFullYear() !== parts[0] ||
    roundTrip.getUTCMonth() + 1 !== parts[1] ||
    roundTrip.getUTCDate() !== parts[2] ||
    roundTrip.getUTCHours() !== parts[3] ||
    roundTrip.getUTCMinutes() !== parts[4] ||
    roundTrip.getUTCSeconds() !== parts[5] ||
    roundTrip.getUTCMilliseconds() !== milliseconds
  ) {
    throw new HandshakeCoordinatorError("Clockchain block time value is invalid.", "BLOCK_TIME_INVALID");
  }
  return parsed;
}

function validateCertificateBindings(result: JsonObject, data: CoordinatorState): void {
  const descriptor = data.descriptor;
  const transitions = data.transitions ?? [];
  if (!descriptor || transitions.length < 3) {
    throw new HandshakeCoordinatorError("Certificate cannot be verified before descriptor and transition evidence.", "CERTIFICATE_INVALID");
  }
  assertResultPartyMatches(result.parties?.payer, descriptor.payer, descriptor);
  assertResultPartyMatches(result.parties?.payee, descriptor.payee, descriptor);
  for (const kind of ["proposal", "acceptance", "acknowledgment"] as const) {
    const anchor = (result.anchors as JsonObject[]).find((entry) => entry.kind === kind);
    const transition = transitions.find((entry) => entry.message?.kind === kind);
    if (
      !anchor ||
      !transition ||
      anchor.blockHeight !== transition.onChain?.blockHeight ||
      anchor.ledgerId !== transition.onChain?.ledgerId ||
      anchor.digest !== transition.digest
    ) {
      throw new HandshakeCoordinatorError("Certificate anchor binding mismatch.", "CERTIFICATE_INVALID");
    }
  }
}

function assertResultPartyMatches(resultParty: JsonObject, descriptorParty: JsonObject, descriptor: JsonObject): void {
  const expectedReference = `eip155:${descriptor.chainId}:${descriptor.registry}:${descriptorParty.agentId}`;
  if (
    normalizeAddress(resultParty?.address) !== normalizeAddress(descriptorParty.address) ||
    resultParty.agentId !== descriptorParty.agentId ||
    resultParty.reference !== expectedReference
  ) {
    throw new HandshakeCoordinatorError("Certificate party binding mismatch.", "CERTIFICATE_INVALID");
  }
}

async function postAnchorReport(relay: RelayClient, store: HandshakeStateStore, key: HandshakeKey, transitions: JsonObject[]): Promise<void> {
  try {
    const record = await requireRecord(store, key);
    const relayUrl = String(dataOf(record).discovery?.relayUrl ?? "").replace(/\/+$/, "");
    const byKind = Object.fromEntries(transitions.map((entry) => [entry.message.kind, anchorReportEntry(entry, relayUrl)]));
    await postMailboxIdempotent(relay, store, key, {
      body: {
        anchors: byKind,
        paymentMoved: false,
      },
      kind: "anchor_report",
      role: "payer",
    });
  } catch {
    // Anchor reports are narration only; evidence verification remains authoritative.
  }
}

function anchorReportEntry(entry: JsonObject, relayUrl: string): JsonObject {
  const predecessor = entry.message.predecessor?.blockHeight ?? null;
  return {
    blockHeight: entry.onChain.blockHeight,
    blockTime: entry.blockTimeMs,
    explorerUrl: `${relayUrl}/v1/blocks/${entry.onChain.blockHeight}`,
    kind: entry.message.kind,
    ledgerId: entry.onChain.ledgerId,
    receipt: {
      anchoredHash: entry.onChain.anchoredHash,
      blockTimeRaw: entry.blockTimeRaw,
      digest: entry.digest,
    },
    signedBy: entry.message.kind === "acceptance" ? entry.message.payee : entry.message.payer,
    terms: {
      currency: entry.message.amount.currency,
      expirySeconds: entry.message.expirySeconds,
      predecessor,
      sequence: entry.message.sequence,
      sessionDigest: entry.message.sessionDigest,
      value: entry.message.amount.value,
    },
  };
}

function tripleFor(entry: JsonObject, kind: string): JsonObject {
  return {
    anchoredHash: entry.onChain.anchoredHash,
    blockHeight: entry.onChain.blockHeight,
    kind,
    ledgerId: entry.onChain.ledgerId,
  };
}

async function prepareMandate(clockchain: ClockchainClient, data: CoordinatorState, sessionId: string): Promise<JsonObject> {
  const timestamp = await clockchain.getTimestamp?.();
  const issuedAtMs = String(parseClockchainLedgerTime(String(timestamp?.madMarzulloTime ?? "")));
  if (!/^(?:0|[1-9][0-9]*)$/.test(issuedAtMs)) {
    throw new HandshakeCoordinatorError("Clockchain ledger time is unavailable.", "LEDGER_TIME_UNAVAILABLE");
  }
  const sessionUuid = randomUUID();
  const intakeRequestId = randomUUID();
  const intakeDigest = createHash("sha256").update(intakeRequestId, "utf8").digest("hex");
  const mandate = preparePayerMandate({
    amount: { currency: "USD", value: "100" },
    expiresAtMs: String(BigInt(issuedAtMs) + 45n * 60n * 1000n),
    intakeDigest,
    intakeRequestId,
    invoiceReferencePrefix: "INV-",
    issuedAtMs,
    payee: { address: data.counterpart?.address, agentId: data.counterpart?.agentId },
    payer: { address: data.identityAddress, agentId: data.agentId },
    purpose: "Invoice settlement",
    releaseId: "handshake-v6",
    repositorySha: data.discovery?.repositorySha,
    sessionId: sessionUuid,
    subjectRun: "stakeholder",
  });
  return {
    common: {
      amount: mandate.amount,
      intakeDigest: mandate.intakeDigest,
      intakeRequestId: mandate.intakeRequestId,
      payee: mandate.payee,
      payer: mandate.payer,
      paymentMoved: false,
      protocol: mandate.protocol,
      purpose: mandate.purpose,
      releaseId: mandate.releaseId,
      repositorySha: mandate.repositorySha,
      sessionId: mandate.sessionId,
      subjectRun: mandate.subjectRun,
    },
    mandate,
  };
}

function parseClockchainLedgerTime(value: string): number {
  const match = /^(\d{2})-(\d{2})-(\d{4})_(\d{2}):(\d{2}):(\d{2}):(\d{3})$/.exec(value);
  if (!match) throw new HandshakeCoordinatorError("Clockchain ledger time shape is invalid.", "LEDGER_TIME_UNAVAILABLE");
  const [, dd, mm, yyyy, hh, mi, ss, ms] = match;
  const parts = [yyyy, mm, dd, hh, mi, ss, ms].map(Number);
  const parsed = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5], parts[6]);
  const roundTrip = new Date(parsed);
  if (
    !Number.isFinite(parsed) ||
    roundTrip.getUTCFullYear() !== parts[0] ||
    roundTrip.getUTCMonth() + 1 !== parts[1] ||
    roundTrip.getUTCDate() !== parts[2] ||
    roundTrip.getUTCHours() !== parts[3] ||
    roundTrip.getUTCMinutes() !== parts[4] ||
    roundTrip.getUTCSeconds() !== parts[5] ||
    roundTrip.getUTCMilliseconds() !== parts[6]
  ) {
    throw new HandshakeCoordinatorError("Clockchain ledger time value is invalid.", "LEDGER_TIME_UNAVAILABLE");
  }
  return parsed;
}

function prepareRequest(data: CoordinatorState, _sessionId: string): JsonObject {
  const mandate = data.mandateEnvelope?.mandate ?? data.mandateEnvelope;
  return {
    request: preparePaymentRequest({
    amount: mandate.amount,
    createdAtMs: mandate.issuedAtMs,
    expiresAtMs: mandate.expiresAtMs,
    intakeDigest: mandate.intakeDigest,
    intakeRequestId: mandate.intakeRequestId,
    invoiceReference: "INV-0001",
    mandateDigest: digestHex(data.mandateEnvelope?.mandate ?? data.mandateEnvelope),
    payee: { address: data.identityAddress, agentId: data.agentId },
    payer: mandate.payer,
    purpose: mandate.purpose,
    releaseId: mandate.releaseId,
    repositorySha: mandate.repositorySha,
    requestId: randomUUID(),
    sessionId: mandate.sessionId,
    subjectRun: mandate.subjectRun,
    }),
  };
}

async function assertPoolHealthy(clockchain: ClockchainClient, env: Record<string, string | undefined>): Promise<JsonObject> {
  let health: JsonObject | undefined;
  try {
    health = await clockchain.getPoolHealth?.();
  } catch {
    if (env.HANDSHAKE_ALLOW_DEGRADED !== "true") {
      throw new HandshakeCoordinatorError("Clockchain pool health is unavailable.", "POOL_DEGRADED");
    }
  }
  if (health?.degraded === true && env.HANDSHAKE_ALLOW_DEGRADED !== "true") {
    throw new HandshakeCoordinatorError("Clockchain pool health is degraded.", "POOL_DEGRADED");
  }
  return {
    degradedAtSubmission: health?.degraded === true,
    nodeParticipationPct: String(health?.nodeParticipationPct ?? "0"),
    totalNodes: String(health?.totalNodes ?? "0"),
  };
}

async function ensureRecord(store: HandshakeStateStore, key: HandshakeKey, discovery: JsonObject): Promise<HandshakeRecord> {
  const current = await store.get(key);
  if (current) return current;
  const relay = generateRelayKeyPair();
  return await store.put(key, {
    principal: key.principal,
    session: key.session,
    role: key.role,
    relayEd25519Pem: relay.privateKeyPem,
    status: "active",
    data: {
      discovery,
      identityNonce: randomUUID(),
      relay: { senderKey: relay.senderKey },
      stage: "joined",
    },
  });
}

async function requireRecord(store: HandshakeStateStore, key: HandshakeKey): Promise<HandshakeRecord> {
  const record = await store.get(key);
  if (!record) throw new HandshakeCoordinatorError("Handshake session has not been joined.", "SESSION_NOT_JOINED");
  return record;
}

function mergeData(key: HandshakeKey, record: HandshakeRecord | null, patch: CoordinatorState): HandshakeRecord {
  return {
    principal: key.principal,
    session: key.session,
    role: key.role,
    status: "active",
    ...record,
    data: {
      ...(record?.data ?? {}),
      ...patch,
    },
  };
}

function dataOf(record: HandshakeRecord): CoordinatorState {
  return (record.data ?? {}) as CoordinatorState;
}

async function loadMessages(relay: RelayClient, sessionId: string): Promise<readonly JsonObject[]> {
  return (await relay.getMessages({ after: "0", sessionId })).messages;
}

function findSeat(messages: readonly JsonObject[], role: PublicRole): JsonObject | null {
  const candidates = messages.filter((message) => message.kind === "identity_ready" && message.role === role && typeof message.body?.address === "string");
  if (candidates.length === 0) return null;
  const first = candidates[0];
  const address = normalizeAddress(first.body.address);
  if (candidates.some((message) => normalizeAddress(message.body.address) !== address || message.senderKey !== first.senderKey)) {
    throw new HandshakeCoordinatorError("Conflicting identity_ready records exist for one role.", "ROLE_ALREADY_BOUND");
  }
  return first;
}

function findPartyReady(messages: readonly JsonObject[], role: PublicRole, address?: string): JsonObject | null {
  const candidates = messages.filter((message) =>
    message.kind === "party_ready" &&
    message.role === role &&
    typeof message.body?.address === "string" &&
    typeof message.body?.agentId === "string"
  );
  if (candidates.length === 0) return null;
  const first = candidates[0];
  const expectedAddress = normalizeAddress(address ?? first.body.address);
  if (candidates.some((message) =>
    normalizeAddress(message.body.address) !== expectedAddress ||
    message.body.agentId !== first.body.agentId ||
    message.senderKey !== first.senderKey
  )) {
    throw new HandshakeCoordinatorError("Conflicting party_ready records exist for one role.", "COUNTERPART_BINDING_MISMATCH");
  }
  return normalizeAddress(first.body.address) === expectedAddress ? first : null;
}

function findRoleMessage(messages: readonly JsonObject[], kind: string, role: string): JsonObject | null {
  const candidates = messages.filter((message) => message.kind === kind && message.role === role);
  if (candidates.length === 0) return null;
  const first = candidates[0];
  const firstDigest = digestHex(first.body);
  if (candidates.some((message) => message.senderKey !== first.senderKey || digestHex(message.body) !== firstDigest)) {
    throw new HandshakeCoordinatorError(`Conflicting ${kind} records exist.`, "COUNTERPART_BINDING_MISMATCH");
  }
  return first;
}

function fundingFor(messages: readonly JsonObject[], role: PublicRole, address: string): JsonObject | null {
  const ownAddress = normalizeAddress(address);
  for (const message of messages) {
    if (message.kind !== "funding_record" || message.role !== "host") continue;
    const body = message.body;
    if (body?.funded && normalizeAddress(body.funded) === ownAddress) return message;
    if (body?.role && body.role !== role) continue;
    if (!body?.role || body.role === role) {
      throw new HandshakeCoordinatorError("Handshake role is already bound to another funded identity.", "ROLE_ALREADY_BOUND");
    }
  }
  return null;
}

function hasMessage(messages: readonly JsonObject[], kind: string, role: PublicRole, senderKey?: string, body?: unknown): boolean {
  const expectedDigest = body === undefined ? null : digestHex(body);
  return messages.some((message) =>
    message.kind === kind &&
    message.role === role &&
    (!senderKey || message.senderKey === senderKey) &&
    (expectedDigest === null || digestHex(message.body) === expectedDigest)
  );
}

function identityClaimBytes(sessionId: string, role: PublicRole, data: CoordinatorState): Buffer {
  if (!data.identityNonce || !data.discovery) throw new HandshakeCoordinatorError("Identity nonce is missing.", "IDENTITY_NONCE_MISSING");
  return canonicalBytes({
    nonce: data.identityNonce,
    operatorPublicKey: data.discovery.operatorPublicKey,
    paymentMoved: false,
    relayUrl: data.discovery.relayUrl,
    role,
    schema: "clockchain.handshake-identity-claim/v1",
    sessionId,
  });
}

function signRequest(stage: string, bytes: Buffer, context: JsonObject): JsonObject {
  return {
    bytesToSignHex: `0x${bytes.toString("hex")}`,
    context,
    stage,
  };
}

function publicProgress(record: HandshakeRecord | null, stage: string): JsonObject {
  return {
    sessionId: record?.session,
    stage,
  };
}

function publicStatus(record: HandshakeRecord): JsonObject {
  const data = dataOf(record);
  return {
    needed: neededForStatus(record.role, data),
    role: record.role,
    sessionId: record.session || data.discovery?.sessionId,
    stage: data.stage ?? record.status,
  };
}

function neededForStatus(roleInput: string, data: CoordinatorState): string | null {
  const role = publicRole(roleInput);
  if (data.certificateVerified) return null;
  if (data.evidenceVerified) return "certificate";
  if (!data.identityAddress) return "sign_identity";
  if (!data.agentId) return "funding_record";
  if (data.pendingArtifact?.mandate) return "sign_mandate";
  if (data.pendingArtifact?.request) return "sign_payment_request";
  if (role === "payer" && !data.mandateEnvelope) return "requestor_identity_ready";
  if (role === "requestor" && !data.requestEnvelope) return "payer_mandate";
  if (!data.sessionDigest) return "handshake_required";
  if (data.partySignatureBytesHex) return "sign_party_result";
  return "clockchain_transition";
}

function publicRole(role: string): PublicRole {
  if (role === "payer" || role === "requestor") return role;
  throw new HandshakeCoordinatorError("Role must be payer or requestor.", "ROLE_INVALID");
}

function evidenceRole(role: PublicRole): EvidenceRole {
  return role === "requestor" ? "payee" : "payer";
}

function stateKey(principal: string, session: string, role: PublicRole): HandshakeKey {
  return { principal, session, role };
}

function stringField(value: JsonObject, key: string, code: string): string {
  if (typeof value[key] !== "string" || value[key].length === 0) throw new HandshakeCoordinatorError(`${key} is missing.`, code);
  return value[key];
}

function normalizeAddress(address: string): string {
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new HandshakeCoordinatorError("Expected a 20-byte EVM address.", "ADDRESS_INVALID");
  }
  return address.toLowerCase();
}

function eip191Signature(value: string): string {
  validateEip191Signature(value);
  return value.toLowerCase();
}

function validateEip191Signature(value: string): void {
  if (!/^0x[0-9a-fA-F]{130}$/.test(value)) {
    throw new HandshakeCoordinatorError("Expected a 65-byte EIP-191 signature hex string.", "SIGNATURE_INVALID");
  }
}

function compactSessionId(sessionId: string): string {
  return String(sessionId).replaceAll("-", "").toLowerCase();
}

const globalLocks = globalThis as typeof globalThis & {
  __clockchainHandshakeCoordinatorLocks?: Map<string, Promise<unknown>>;
};

function lockMap(): Map<string, Promise<unknown>> {
  globalLocks.__clockchainHandshakeCoordinatorLocks ??= new Map();
  return globalLocks.__clockchainHandshakeCoordinatorLocks;
}

async function withGlobalLock<T>(key: HandshakeKey, work: () => Promise<T>): Promise<T> {
  const locks = lockMap();
  const lockKey = handshakeKeyHash(key);
  const previous = locks.get(lockKey) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => current, () => current);
  locks.set(lockKey, tail);
  await previous.catch(() => undefined);
  try {
    return await work();
  } finally {
    release();
    if (locks.get(lockKey) === tail) locks.delete(lockKey);
  }
}
