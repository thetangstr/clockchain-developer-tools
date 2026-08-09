import assert from "node:assert/strict";
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

import {
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  canonicalBytes,
  digestHex,
  generateRelayKeyPair,
  preparePayerMandate,
  preparePaymentRequest,
  sealPayerMandate,
  sealPaymentRequest,
  sessionKey,
  signRelayEnvelope,
} from "../dist/handshake/protocol.js";
import {
  __resetHandshakeStateStore,
  createHandshakeStateStore,
} from "../dist/handshake/state.js";
import {
  HandshakeCoordinatorError,
  createHandshakeCoordinator,
  createRuntimeHandshakeCoordinator,
} from "../dist/handshake/coordinator.js";
import { HandshakeRelayResultPendingError } from "../dist/handshake/relay.js";

const NOW = 1786190400000;
const SESSION_ID = "123e4567-e89b-42d3-a456-426614174001";
const SESSION_COMPACT = "123e4567e89b42d3a456426614174001";
const RELAY_URL = "https://relay.clockchain.test";
const REPOSITORY_SHA = "b".repeat(40);
const PROMPT_SHA = "a94eb709fb27abb1097000cbd3a43d5ba95444dcc70a5c670f3a2a8c4808e58c";
const INTAKE_DIGEST = "a".repeat(64);
const INTAKE_REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const PAYER = "0x1111111111111111111111111111111111111111";
const REQUESTOR = "0x2222222222222222222222222222222222222222";
const OTHER = "0x3333333333333333333333333333333333333333";
const PAYER_SIG = `0x${"11".repeat(65)}`;
const REQUESTOR_SIG = `0x${"22".repeat(65)}`;
const OTHER_SIG = `0x${"33".repeat(65)}`;

function operatorKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKeyRaw: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
  };
}

function sha256SignedBytes(bytesToSignHex) {
  return createHash("sha256")
    .update(Buffer.from(bytesToSignHex.slice(2), "hex"))
    .digest("hex");
}

function discovery(key = operatorKey()) {
  return {
    schema: "handshake-discovery/v2",
    expiresAtMs: String(NOW + 60 * 60 * 1000),
    issuedAtMs: String(NOW),
    kitRepoUrl: "https://github.com/clockchain/handshake-kit",
    operatorPublicKey: key.publicKeyRaw,
    paymentMoved: false,
    relayUrl: RELAY_URL,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
}

function descriptorEnvelope(key, { payer = PAYER, payee = REQUESTOR, payerAgentId = "101", payeeAgentId = "202" } = {}) {
  const mandate = sealPayerMandate({
    amount: { currency: "USD", value: "25" },
    expiresAtMs: String(NOW + 600000),
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReferencePrefix: "INV-2026-",
    issuedAtMs: String(NOW),
    payee: { address: payee, agentId: payeeAgentId },
    payer: { address: payer, agentId: payerAgentId },
    purpose: "Bilateral test payment",
    releaseId: "release-2026-08-08",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
  }, `0x${"11".repeat(65)}`);
  const request = sealPaymentRequest({
    amount: { currency: "USD", value: "25" },
    createdAtMs: String(NOW),
    expiresAtMs: String(NOW + 600000),
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReference: "INV-2026-202",
    mandateDigest: digestHex(mandate.mandate),
    payee: { address: payee, agentId: payeeAgentId },
    payer: { address: payer, agentId: payerAgentId },
    purpose: "Bilateral test payment",
    releaseId: "release-2026-08-08",
    repositorySha: REPOSITORY_SHA,
    requestId: "123e4567-e89b-42d3-a456-426614174002",
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
  }, `0x${"22".repeat(65)}`);
  return descriptorEnvelopeForArtifacts(key, { mandate, request });
}

function descriptorEnvelopeForArtifacts(key, { mandate, request }) {
  const descriptor = {
    amountOptions: [request.request.amount],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: digestHex(mandate.mandate),
    namespace: "cbv1",
    payee: { ...request.request.payee, displayName: "Payee Agent", role: "payee" },
    payer: { ...request.request.payer, displayName: "Payer Agent", role: "payer" },
    paymentMoved: false,
    promptSha256: PROMPT_SHA,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: request.request.repositorySha,
    requestDigest: digestHex(request.request),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: request.request.sessionId.replaceAll("-", ""),
    settlement: "not-executed",
  };
  return {
    descriptor,
    descriptorEnvelope: {
      descriptor,
      operator: {
        algorithm: "ed25519",
        keyId: "fixture-key",
        publicKey: key.publicKeyRaw,
        signature: sign(null, canonicalBytes(descriptor), createPrivateKey(key.privateKeyPem)).toString("base64"),
      },
    },
    mandate,
    request,
  };
}

function requestEnvelopeForMandate(mandateEnvelope, signature = REQUESTOR_SIG, overrides = {}) {
  const mandate = mandateEnvelope.mandate;
  return sealPaymentRequest(preparePaymentRequest({
    amount: mandate.amount,
    createdAtMs: mandate.issuedAtMs,
    expiresAtMs: mandate.expiresAtMs,
    intakeDigest: mandate.intakeDigest,
    intakeRequestId: mandate.intakeRequestId,
    invoiceReference: `${mandate.invoiceReferencePrefix}0001`,
    mandateDigest: digestHex(mandate),
    payee: mandate.payee,
    payer: mandate.payer,
    purpose: mandate.purpose,
    releaseId: mandate.releaseId,
    repositorySha: mandate.repositorySha,
    requestId: "123e4567-e89b-42d3-a456-426614174002",
    sessionId: mandate.sessionId,
    subjectRun: mandate.subjectRun,
    ...overrides,
  }), signature);
}

function appendHostedArtifacts({ key, mandateEnvelope, messages, requestorRelayKey, seq = 10 }) {
  const requestEnvelope = requestEnvelopeForMandate(mandateEnvelope);
  const fixture = descriptorEnvelopeForArtifacts(key, { mandate: mandateEnvelope, request: requestEnvelope });
  messages.push(
    relayMessage({
      body: { paymentMoved: false, requestEnvelope },
      kind: "payment_request",
      role: "requestor",
      seq: String(seq),
      relayKey: requestorRelayKey,
    }),
  );
  appendHostedDescriptor({ fixture, key, messages, seq: seq + 1 });
  return fixture;
}

function appendHostedDescriptor({ fixture, key, messages, seq = 20 }) {
  messages.push(relayMessage({
    body: { descriptorEnvelope: fixture.descriptorEnvelope, repositoryPublicKey: key.publicKeyRaw, paymentMoved: false },
    kind: "handshake_required",
    role: "host",
    seq: String(seq),
  }));
}

function resultEnvelope(key, sessionDigest, resultOverrides = {}) {
  const result = {
    anchors: [
      { blockHeight: "100", blockTimeRaw: "2026-08-08T12:00:00.000Z", digest: "1".repeat(64), kind: "proposal", ledgerId: "123e4567-e89b-42d3-a456-426614174010" },
      { blockHeight: "101", blockTimeRaw: "2026-08-08T12:00:10.000Z", digest: "2".repeat(64), kind: "acceptance", ledgerId: "123e4567-e89b-42d3-a456-426614174011" },
      { blockHeight: "102", blockTimeRaw: "2026-08-08T12:00:20.000Z", digest: "3".repeat(64), kind: "acknowledgment", ledgerId: "123e4567-e89b-42d3-a456-426614174012" },
    ],
    disclaimer: "Single-validator testnet: anchored and independently re-verifiable; not mainnet, court-grade, consensus-secure, or trustless.",
    issuedAtMs: String(NOW + 30000),
    outcome: "AUTHORIZED",
    parties: {
      payee: { address: REQUESTOR, agentId: "202", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:202" },
      payer: { address: PAYER, agentId: "101", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:101" },
    },
    paymentMoved: false,
    schema: "clockchain.handshake-result/v1",
    sessionDigest,
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
    ...resultOverrides,
  };
  return {
    result,
    signer: {
      algorithm: "ed25519",
      keyId: "fixture-key",
      publicKey: key.publicKeyRaw,
      signature: sign(null, canonicalBytes(result), createPrivateKey(key.privateKeyPem)).toString("base64"),
    },
  };
}

function storedTransition(kind, blockHeight, ledgerId, digest = `${blockHeight}`.padStart(64, "0")) {
  return {
    blockTimeMs: String(NOW + Number(blockHeight)),
    blockTimeRaw: "2026-08-08T12:00:00.000Z",
    digest,
    message: { kind },
    onChain: { anchoredHash: digest, blockHeight: String(blockHeight), ledgerId },
    upperBoundMs: kind === "proposal" ? null : String(NOW + Number(blockHeight) + 1100),
  };
}

function relayMessage({ body, kind, role, sessionId = SESSION_ID, seq = "1", relayKey = generateRelayKeyPair() }) {
  return signRelayEnvelope({
    body,
    kind,
    privateKeyPem: relayKey.privateKeyPem,
    role,
    senderKey: relayKey.senderKey,
    sessionId,
    seq,
  });
}

function canonicalMandateBody({
  amount = { currency: "USD", value: "100" },
  payee = { address: REQUESTOR, agentId: "202" },
  payer = { address: PAYER, agentId: "101" },
  signature = PAYER_SIG,
  sessionId = "123e4567-e89b-42d3-a456-426614174099",
} = {}) {
  const mandate = preparePayerMandate({
    amount,
    expiresAtMs: String(NOW + 45 * 60 * 1000),
    intakeDigest: createHash("sha256").update(INTAKE_REQUEST_ID).digest("hex"),
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReferencePrefix: "INV-",
    issuedAtMs: String(NOW),
    payee,
    payer,
    purpose: "Invoice settlement",
    releaseId: "handshake-v6",
    repositorySha: REPOSITORY_SHA,
    sessionId,
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
    expiresAtMs: mandate.expiresAtMs,
    issuedAtMs: mandate.issuedAtMs,
    mandateEnvelope: sealPayerMandate(mandate, signature),
    paymentMoved: false,
    sessionUuid: mandate.sessionId,
  };
}

function harness({ key = operatorKey(), messages = [], result = null, postImpl = null, env = {}, store = null, reset = true, resolveOwnedAgentId = null, waitTiming = undefined, discoveryDocument = null } = {}) {
  if (reset) __resetHandshakeStateStore();
  store ??= createHandshakeStateStore({});
  const posted = [];
  const intents = [];
  const records = [];
  const clockchain = {
    async getTimestamp() {
      return { madMarzulloTime: "08-08-2026_12:00:00:000", "nodeParticipation%": 100, totalNodes: 3 };
    },
    async getPoolHealth() {
      return { degraded: false, nodeParticipationPct: "100", totalNodes: "3" };
    },
    async searchAsset(assetReferenceId) {
      return records.filter((record) => record.assetReferenceId === assetReferenceId);
    },
    async log({ assetHash, assetReferenceId }) {
      const height = String(100 + records.length);
      const ledgerId = `123e4567-e89b-42d3-a456-4266141740${10 + records.length}`;
      const record = {
        assetHash,
        assetReferenceId,
        blockHeight: height,
        blockTimeRaw: `2026-08-08T12:00:${String(records.length * 10).padStart(2, "0")}.000Z`,
        ledgerId,
      };
      records.push(record);
      return record;
    },
    async getLedgerEntry(ledgerId) {
      return records.find((record) => record.ledgerId === ledgerId) ?? null;
    },
    async getChainRecord(blockHeight, ledgerId) {
      const record = records.find((entry) => entry.blockHeight === String(blockHeight) && entry.ledgerId === ledgerId);
      return record ? { assetHash: record.assetHash, assetReferenceId: record.assetReferenceId, blockHeight: record.blockHeight } : null;
    },
    async getBlock(blockHeight) {
      const record = records.find((entry) => entry.blockHeight === String(blockHeight));
      return { blockHeight: Number(blockHeight), blockTime: record?.blockTimeRaw ?? "2026-08-08T12:00:00.000Z" };
    },
  };
  const relay = {
    async fetchDiscovery() {
      return discoveryDocument ?? discovery(key);
    },
    async getMessages() {
      return { messages };
    },
    async postMessage(input) {
      if (postImpl) return postImpl(input, posted);
      posted.push(input);
        messages.push(signRelayEnvelope({
          body: input.body,
          kind: input.kind,
          privateKeyPem: input.privateKeyPem,
          role: input.role,
          senderKey: input.senderKey,
          sessionId: input.sessionId,
          seq: String(messages.length + 1),
        }));
      return { ok: true, seq: String(messages.length) };
    },
    async putEvidence(input) {
      posted.push({ evidence: input });
      return { ok: true };
    },
    async getResult() {
      if (result === null) {
        throw new HandshakeRelayResultPendingError();
      }
      return result;
    },
  };
  const coordinator = createHandshakeCoordinator({
    clockchain,
    env,
    principal: "did:example:alice",
    relay,
    resolveOwnedAgentId: resolveOwnedAgentId ?? (async ({ address }) => address === PAYER ? "101" : "202"),
    recoverEip191Address: async ({ bytes, signatureHex }) => {
      assert.equal(Buffer.isBuffer(bytes), true);
      assert.match(signatureHex, /^0x[0-9a-fA-F]{130}$/);
      if (signatureHex === PAYER_SIG) return PAYER;
      if (signatureHex === REQUESTOR_SIG) return REQUESTOR;
      if (signatureHex === OTHER_SIG) return OTHER;
      return signatureHex;
    },
    stateStore: store,
    waitTiming,
  });
  return {
    clockchain,
    coordinator,
    intents,
    key,
    messages,
    posted,
    records,
    relay,
    setResult(next) {
      result = next;
    },
    store,
  };
}

async function joinAndIdentify(coordinator, role, signatureHex) {
  const joined = await coordinator.join(role);
  const identity = await coordinator.next(joined.sessionId, role);
  assert.equal(identity.stage, "sign_identity");
  return coordinator.submit(joined.sessionId, role, signatureHex);
}

async function preparePayerWithHostedArtifacts(h, key, requestorRelayKey) {
  await joinAndIdentify(h.coordinator, "payer", PAYER_SIG);
  const signingRequest = await h.coordinator.next(SESSION_ID, "payer");
  assert.equal(signingRequest.stage, "sign_mandate");
  await h.coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  const mandateEnvelope = h.posted.find((entry) => entry.kind === "mandate").body.mandateEnvelope;
  const fixture = appendHostedArtifacts({ key, mandateEnvelope, messages: h.messages, requestorRelayKey });
  return { fixture, mandateEnvelope, signingRequest };
}

async function preparePayerAwaitingAcceptance({
  key = operatorKey(),
  sharedStore = null,
  reset = true,
  waitTiming = undefined,
} = {}) {
  const requestorRelayKey = generateRelayKeyPair();
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202", paymentMoved: false }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: { paymentMoved: false }, kind: "watching", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];
  const h = harness({ key, messages, reset, store: sharedStore, waitTiming });
  const { fixture } = await preparePayerWithHostedArtifacts(h, key, requestorRelayKey);
  const first = await h.coordinator.next(SESSION_ID, "payer");
  assert.deepEqual(first, {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
  const sessionDigest = digestHex(fixture.descriptor);
  const proposalMessage = buildProposal({
    amount: fixture.descriptor.amountOptions[0],
    descriptor: fixture.descriptor,
    sessionDigest,
  });
  const proposalRecord = h.records.find((record) => record.assetReferenceId === sessionKey(sessionDigest, "proposal"));
  const acceptance = buildAcceptance({
    proposal: proposalMessage,
    proposalTriple: {
      anchoredHash: proposalRecord.assetHash,
      blockHeight: proposalRecord.blockHeight,
      kind: "proposal",
      ledgerId: proposalRecord.ledgerId,
    },
  });
  return { acceptance, fixture, h, messages, requestorRelayKey, sessionDigest };
}

function pushAcceptanceRecord(h, sessionDigest, acceptance) {
  h.records.push({
    assetHash: digestHex(acceptance),
    assetReferenceId: sessionKey(sessionDigest, "acceptance"),
    blockHeight: "101",
    blockTimeRaw: "2026-08-08T12:00:10.000Z",
    ledgerId: "123e4567-e89b-42d3-a456-426614174011",
  });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

function hexJson(hex) {
  return JSON.parse(Buffer.from(hex.slice(2), "hex").toString("utf8"));
}

test("rejects roles outside the public payer/requestor surface", async () => {
  const { coordinator } = harness();
  await assert.rejects(coordinator.join("payee"), { code: "ROLE_INVALID" });
  await assert.rejects(coordinator.next(SESSION_ID, "host"), { code: "ROLE_INVALID" });
});

test("join exposes the exact operator public key fetched from discovery", async () => {
  const key = operatorKey();
  const { coordinator } = harness({ key });

  assert.equal((await coordinator.join("payer")).operatorPublicKey, key.publicKeyRaw);
});

test("join rejects discovery with an empty operator public key", async () => {
  const key = operatorKey();
  const { coordinator } = harness({
    discoveryDocument: {
      ...discovery(key),
      operatorPublicKey: "",
    },
  });

  await assert.rejects(coordinator.join("payer"), { code: "DISCOVERY_INVALID" });
});

test("submit rejects non-EIP-191-shaped signatures before recovery", async () => {
  let recovered = false;
  const h = harness();
  h.coordinator = createHandshakeCoordinator({
    clockchain: h.clockchain,
    principal: "did:example:alice",
    relay: h.relay,
    resolveOwnedAgentId: async () => "101",
    recoverEip191Address: async () => {
      recovered = true;
      return PAYER;
    },
    stateStore: h.store,
  });

  await h.coordinator.join("payer");
  await assert.rejects(h.coordinator.submit(SESSION_ID, "payer", "payer-signature"), { code: "SIGNATURE_INVALID" });
  assert.equal(recovered, false);
});

test("payer mandate signing bytes and mailbox body use exact canonical prepared mandate and host common", async () => {
  const requestorRelayKey = generateRelayKeyPair();
  const messages = [
    relayMessage({ body: { address: REQUESTOR, paymentMoved: false }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202", paymentMoved: false }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
  ];
  const { coordinator, posted } = harness({ messages });

  await joinAndIdentify(coordinator, "payer", PAYER_SIG);
  const sign = await coordinator.next(SESSION_ID, "payer");
  assert.equal(sign.stage, "sign_mandate");
  const mandate = hexJson(sign.bytesToSignHex);
  assert.deepEqual(mandate, preparePayerMandate(mandate));
  assert.equal(mandate.amount.value, "100");
  assert.equal(mandate.subjectRun, "stakeholder");
  assert.equal(BigInt(mandate.expiresAtMs) - BigInt(mandate.issuedAtMs), 45n * 60n * 1000n);

  await coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  const postedMandate = posted.find((entry) => entry.kind === "mandate").body;
  assert.deepEqual(Object.keys(postedMandate).sort(), ["common", "expiresAtMs", "issuedAtMs", "mandateEnvelope", "paymentMoved", "sessionUuid"].sort());
  assert.deepEqual(postedMandate.common, {
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
  });
  assert.equal(postedMandate.sessionUuid, mandate.sessionId);
  assert.equal(postedMandate.mandateEnvelope.signature.value, PAYER_SIG);
});

test("status exposes the caller's next required action", async () => {
  const { coordinator } = harness();
  await coordinator.join("payer");
  assert.deepEqual((await coordinator.status(SESSION_ID)).sessions, [{
    needed: "sign_identity",
    role: "payer",
    sessionId: SESSION_ID,
    stage: "joined",
  }]);

  await coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  assert.equal((await coordinator.status(SESSION_ID)).sessions[0].needed, "funding_record");
});

test("repeated next calls return byte-identical pending mandate and request artifacts", async () => {
  const requestorRelayKey = generateRelayKeyPair();
  const payer = harness({
    messages: [
      relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
      relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
      relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    ],
  });
  await joinAndIdentify(payer.coordinator, "payer", PAYER_SIG);
  const firstMandate = await payer.coordinator.next(SESSION_ID, "payer");
  const secondMandate = await payer.coordinator.next(SESSION_ID, "payer");
  assert.equal(secondMandate.bytesToSignHex, firstMandate.bytesToSignHex);
  assert.equal(firstMandate.bytesSha256, sha256SignedBytes(firstMandate.bytesToSignHex));
  assert.equal(secondMandate.bytesSha256, firstMandate.bytesSha256);

  const payerRelayKey = generateRelayKeyPair();
  const requestor = harness({
    messages: [
      relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: payerRelayKey }),
      relayMessage({ body: { address: PAYER, agentId: "101" }, kind: "party_ready", role: "payer", seq: "2", relayKey: payerRelayKey }),
      relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
      relayMessage({ body: canonicalMandateBody(), kind: "mandate", role: "payer", seq: "4", relayKey: payerRelayKey }),
    ],
  });
  await joinAndIdentify(requestor.coordinator, "requestor", REQUESTOR_SIG);
  const firstRequest = await requestor.coordinator.next(SESSION_ID, "requestor");
  const secondRequest = await requestor.coordinator.next(SESSION_ID, "requestor");
  assert.equal(secondRequest.bytesToSignHex, firstRequest.bytesToSignHex);
  assert.equal(firstRequest.bytesSha256, sha256SignedBytes(firstRequest.bytesToSignHex));
  assert.equal(secondRequest.bytesSha256, firstRequest.bytesSha256);
});

test("next can return one compact gzip-base64url signing payload with the same raw-byte digest", async () => {
  const requestorRelayKey = generateRelayKeyPair();
  const { coordinator } = harness({
    messages: [
      relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
      relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
      relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    ],
  });
  await joinAndIdentify(coordinator, "payer", PAYER_SIG);

  const hex = await coordinator.next(SESSION_ID, "payer");
  const compact = await coordinator.next(SESSION_ID, "payer", "gzip-base64url");
  const decoded = gunzipSync(Buffer.from(compact.bytesToSignGzipBase64Url, "base64url"));

  assert.equal(compact.bytesEncoding, "gzip-base64url");
  assert.equal(Object.hasOwn(compact, "bytesToSignHex"), false);
  assert.equal(`0x${decoded.toString("hex")}`, hex.bytesToSignHex);
  assert.equal(compact.bytesSha256, sha256SignedBytes(hex.bytesToSignHex));
  assert.ok(compact.bytesToSignGzipBase64Url.length < hex.bytesToSignHex.length);
  await assert.rejects(coordinator.next(SESSION_ID, "payer", "zip"), { code: "SIGNING_ENCODING_INVALID" });
});

test("runtime coordinator forwards compact signing encoding to the core coordinator", async () => {
  const { clockchain, relay } = harness();
  const coordinator = createRuntimeHandshakeCoordinator({
    clockchain,
    principal: "did:example:alice",
    relay,
    stateStore: createHandshakeStateStore({}),
  });
  const joined = await coordinator.join("payer");
  const compact = await coordinator.next(joined.sessionId, "payer", "gzip-base64url");

  assert.equal(compact.bytesEncoding, "gzip-base64url");
  assert.equal(Object.hasOwn(compact, "bytesToSignHex"), false);
  assert.equal(typeof compact.bytesToSignGzipBase64Url, "string");
});

test("next rejects invalid waitMs values before polling", async () => {
  const { coordinator } = harness();
  await coordinator.join("payer");

  for (const waitMs of [-1, 1.5, 15001, "100"]) {
    await assert.rejects(
      coordinator.next(SESSION_ID, "payer", "hex", waitMs),
      { code: "WAIT_MS_INVALID" },
    );
  }
});

test("default next returns counterpart-transition wait state immediately", async () => {
  const { h } = await preparePayerAwaitingAcceptance();
  let searches = 0;
  const originalSearch = h.clockchain.searchAsset;
  h.clockchain.searchAsset = async (...args) => {
    searches += 1;
    return originalSearch(...args);
  };

  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer"), {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
  assert.equal(searches, 1);
});

test("waitMs polls only the counterpart-transition wait state and returns when it appears", async () => {
  const { acceptance, h, sessionDigest } = await preparePayerAwaitingAcceptance();
  let acceptanceSearches = 0;
  const originalSearch = h.clockchain.searchAsset;
  h.clockchain.searchAsset = async (assetReferenceId) => {
    if (assetReferenceId === sessionKey(sessionDigest, "acceptance")) {
      acceptanceSearches += 1;
      if (acceptanceSearches === 2) pushAcceptanceRecord(h, sessionDigest, acceptance);
    }
    return originalSearch(assetReferenceId);
  };

  const result = await h.coordinator.next(SESSION_ID, "payer", "hex", 300);
  assert.equal(result.stage, "sign_party_result");
  assert.equal(typeof result.bytesToSignHex, "string");
  assert.equal(acceptanceSearches >= 2, true);
});

test("waitMs timeout returns the latest counterpart-transition wait state", async () => {
  const { h } = await preparePayerAwaitingAcceptance();

  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer", "hex", 20), {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
});

test("waitMs uses bounded exponential delay policy without busy-looping", async () => {
  let now = 1000;
  const sleeps = [];
  const waitTiming = {
    now: () => now,
    sleep: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
  };
  const { h } = await preparePayerAwaitingAcceptance({ waitTiming });

  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer", "hex", 1750), {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
  assert.deepEqual(sleeps, [250, 500, 1000]);
});

test("waitMs delay policy caps the first sleep to the remaining deadline", async () => {
  let now = 5000;
  const sleeps = [];
  const waitTiming = {
    now: () => now,
    sleep: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
  };
  const { h } = await preparePayerAwaitingAcceptance({ waitTiming });

  await h.coordinator.next(SESSION_ID, "payer", "hex", 100);
  assert.deepEqual(sleeps, [100]);
});

test("waitMs does not start another poll when sleep reaches the deadline", async () => {
  let now = 5000;
  const waitTiming = {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
  };
  const { h, sessionDigest } = await preparePayerAwaitingAcceptance({ waitTiming });
  let acceptanceSearches = 0;
  const originalSearch = h.clockchain.searchAsset;
  h.clockchain.searchAsset = async (assetReferenceId) => {
    if (assetReferenceId === sessionKey(sessionDigest, "acceptance")) acceptanceSearches += 1;
    return originalSearch(assetReferenceId);
  };

  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer", "hex", 250), {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
  assert.equal(acceptanceSearches, 1);
});

test("waitMs fails closed when injected timing makes no progress", async () => {
  const waitTiming = {
    now: () => 1000,
    sleep: async () => {},
  };
  const { h } = await preparePayerAwaitingAcceptance({ waitTiming });

  await assert.rejects(
    h.coordinator.next(SESSION_ID, "payer", "hex", 1000),
    { code: "WAIT_TIMING_INVALID" },
  );
});

test("waitMs fails closed when injected timing is non-finite", async () => {
  const waitTiming = {
    now: () => Number.NaN,
    sleep: async () => {},
  };
  const { h } = await preparePayerAwaitingAcceptance({ waitTiming });

  await assert.rejects(
    h.coordinator.next(SESSION_ID, "payer", "hex", 1000),
    { code: "WAIT_TIMING_INVALID" },
  );
});

test("waitMs releases the per-session role lock between retries", async () => {
  __resetHandshakeStateStore();
  const sharedStore = createHandshakeStateStore({});
  let now = 10_000;
  const sleepEntered = deferred();
  const releaseSleep = deferred();
  const waitTiming = {
    now: () => now,
    sleep: async (ms) => {
      sleepEntered.resolve(ms);
      await releaseSleep.promise;
      now += ms;
    },
  };

  const { acceptance, h, messages, sessionDigest } = await preparePayerAwaitingAcceptance({ sharedStore, reset: false, waitTiming });
  const waiting = h.coordinator.next(SESSION_ID, "payer", "hex", 1000);
  let waitingSettled = false;
  waiting.then(() => {
    waitingSettled = true;
  });
  assert.equal(await sleepEntered.promise, 250);
  assert.equal(waitingSettled, false);

  const concurrent = harness({ messages, reset: false, store: sharedStore });
  const immediate = await concurrent.coordinator.next(SESSION_ID, "payer");
  assert.deepEqual(immediate, {
    needed: "counterpart_transition",
    sessionId: SESSION_ID,
    stage: "awaiting_counterpart_transition",
  });
  assert.equal(waitingSettled, false);

  pushAcceptanceRecord(h, sessionDigest, acceptance);
  releaseSleep.resolve();
  const completed = await waiting;
  assert.equal(completed.stage, "sign_party_result");
  assert.equal(typeof completed.bytesToSignHex, "string");
});

test("invalid Clockchain calendar timestamps never become mandate signing bytes", async () => {
  const requestorRelayKey = generateRelayKeyPair();
  const h = harness({
    messages: [
      relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
      relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
      relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    ],
  });
  h.clockchain.getTimestamp = async () => ({ madMarzulloTime: "30-02-2026_12:00:00:000" });
  await joinAndIdentify(h.coordinator, "payer", PAYER_SIG);
  await assert.rejects(h.coordinator.next(SESSION_ID, "payer"), { code: "LEDGER_TIME_UNAVAILABLE" });
});

test("invalid block calendar timestamps and mismatched chain references are rejected immediately", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const baseMessages = () => [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: { paymentMoved: false }, kind: "watching", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];

  const badTime = harness({ key, messages: baseMessages() });
  await preparePayerWithHostedArtifacts(badTime, key, requestorRelayKey);
  badTime.clockchain.getBlock = async (height) => ({ blockHeight: Number(height), blockTime: "2026-02-30T12:00:00.000Z" });
  await assert.rejects(badTime.coordinator.next(SESSION_ID, "payer"), { code: "BLOCK_TIME_INVALID" });

  const badReference = harness({ key, messages: baseMessages() });
  await preparePayerWithHostedArtifacts(badReference, key, requestorRelayKey);
  badReference.clockchain.getLedgerEntry = async (ledgerId) => ({
    assetHash: badReference.records.find((record) => record.ledgerId === ledgerId).assetHash,
    assetReferenceId: "wrong-reference",
    blockHeight: "100",
    ledgerId,
  });
  badReference.clockchain.getChainRecord = async (_blockHeight, ledgerId) => ({
    assetHash: badReference.records.find((record) => record.ledgerId === ledgerId).assetHash,
    assetReferenceId: "wrong-reference",
    blockHeight: "100",
  });
  await assert.rejects(badReference.coordinator.next(SESSION_ID, "payer"), { code: "ANCHOR_UNVERIFIED" });
});

test("full payer side advances with only local harness signatures and no secret input or output", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: { paymentMoved: false }, kind: "watching", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];
  const h = harness({ key, messages });
  const { coordinator, posted, records } = h;

  const { fixture, signingRequest: mandate } = await preparePayerWithHostedArtifacts(h, key, requestorRelayKey);

  const waitForAcceptance = await coordinator.next(SESSION_ID, "payer");
  assert.equal(waitForAcceptance.stage, "awaiting_counterpart_transition");
  const sessionDigest = digestHex(fixture.descriptor);
  const proposalMessage = buildProposal({
    amount: fixture.descriptor.amountOptions[0],
    descriptor: fixture.descriptor,
    sessionDigest,
  });
  const proposalRecord = records.find((record) => record.assetReferenceId === sessionKey(sessionDigest, "proposal"));
  const acceptance = buildAcceptance({
    proposal: proposalMessage,
    proposalTriple: {
      anchoredHash: proposalRecord.assetHash,
      blockHeight: proposalRecord.blockHeight,
      kind: "proposal",
      ledgerId: proposalRecord.ledgerId,
    },
  });
  records.push({
    assetHash: digestHex(acceptance),
    assetReferenceId: sessionKey(sessionDigest, "acceptance"),
    blockHeight: "101",
    blockTimeRaw: "2026-08-08T12:00:10.000Z",
    ledgerId: "123e4567-e89b-42d3-a456-426614174011",
  });
  const proposal = await coordinator.next(SESSION_ID, "payer");
  assert.equal(proposal.stage, "sign_party_result");
  assert.equal(typeof proposal.bytesToSignHex, "string");
  await coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  const evidenceUploads = posted.filter((entry) => entry.evidence).length;
  assert.deepEqual(await coordinator.next(SESSION_ID, "payer"), {
    needed: "certificate",
    sessionId: SESSION_ID,
    stage: "awaiting_certificate",
  });
  assert.equal((await coordinator.submit(SESSION_ID, "payer", PAYER_SIG)).stage, "evidence_uploaded");
  assert.equal(posted.filter((entry) => entry.evidence).length, evidenceUploads);

  assert.equal(posted.some((entry) => entry.kind === "identity_ready"), true);
  assert.equal(posted.some((entry) => entry.kind === "party_ready"), true);
  assert.equal(posted.some((entry) => entry.kind === "mandate"), true);
  assert.equal(posted.some((entry) => entry.kind === "anchor_report"), true);
  assert.equal(posted.some((entry) => entry.evidence?.role === "payer"), true);
  assert.doesNotMatch(JSON.stringify([mandate, proposal]), /privateKey|principalHash|keyHash|credential/i);
});

test("join resumes the caller's own seat but rejects another sender in the same role", async () => {
  const { coordinator } = harness();
  await coordinator.join("payer");
  await coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  assert.equal((await coordinator.join("payer")).sessionId, SESSION_ID);

  const collision = harness({
    messages: [relayMessage({ body: { address: OTHER }, kind: "identity_ready", role: "payer" })],
  });
  await assert.rejects(collision.coordinator.join("payer"), { code: "ROLE_ALREADY_BOUND" });
});

test("write intent is persisted before dispatch and same mailbox anchor is adopted", async () => {
  let intentSeenBeforePost = false;
  const { coordinator, posted, store } = harness({
    postImpl: async (input, posted) => {
      const record = await store.get({ principal: "did:example:alice", session: SESSION_ID, role: "payer" });
      intentSeenBeforePost = record.data.pendingWrite?.kind === input.kind;
      posted.push(input);
      return { ok: true, seq: "1" };
    },
  });

  await joinAndIdentify(coordinator, "payer", PAYER_SIG);

  assert.equal(intentSeenBeforePost, true);
  assert.equal(posted.filter((entry) => entry.kind === "identity_ready").length, 1);
});

test("ambiguous write reconciles exactly once, adopts exact records, and never blindly redispatches", async () => {
  let attempts = 0;
  const { coordinator, messages, posted } = harness({
    postImpl: async (input) => {
      attempts += 1;
      if (attempts === 1) {
        messages.push(signRelayEnvelope({
          body: input.body,
          kind: input.kind,
          privateKeyPem: input.privateKeyPem,
          role: input.role,
          senderKey: input.senderKey,
          sessionId: input.sessionId,
          seq: String(messages.length + 1),
        }));
        throw Object.assign(new Error("socket closed"), { code: "RELAY_NETWORK" });
      }
      posted.push(input);
      return { ok: true, seq: "2" };
    },
  });

  await joinAndIdentify(coordinator, "payer", PAYER_SIG);

  assert.equal(attempts, 1);
  assert.equal(posted.length, 0);
});

test("ambiguous write fails closed when reconciliation finds mismatch or no exact record", async () => {
  const absent = harness({
    postImpl: async () => {
      throw Object.assign(new Error("socket closed"), { code: "RELAY_NETWORK" });
    },
  });
  await absent.coordinator.join("payer");
  await assert.rejects(absent.coordinator.submit(SESSION_ID, "payer", PAYER_SIG), { code: "AMBIGUOUS_WRITE" });

  const mismatch = harness({
    postImpl: async (_input, _posted) => {
      mismatch.messages.push(relayMessage({ body: { address: OTHER }, kind: "identity_ready", role: "payer" }));
      throw Object.assign(new Error("socket closed"), { code: "RELAY_NETWORK" });
    },
  });
  await mismatch.coordinator.join("payer");
  await assert.rejects(mismatch.coordinator.submit(SESSION_ID, "payer", PAYER_SIG), { code: "AMBIGUOUS_WRITE" });
});

test("restart never redispatches an unreconciled mailbox write intent", async () => {
  __resetHandshakeStateStore();
  const sharedStore = createHandshakeStateStore({});
  const first = harness({
    reset: false,
    store: sharedStore,
    postImpl: async () => {
      throw Object.assign(new Error("socket closed"), { code: "RELAY_NETWORK" });
    },
  });
  await first.coordinator.join("payer");
  await assert.rejects(first.coordinator.submit(SESSION_ID, "payer", PAYER_SIG), { code: "AMBIGUOUS_WRITE" });

  let restartedPosts = 0;
  const restarted = harness({
    messages: first.messages,
    reset: false,
    store: sharedStore,
    postImpl: async () => {
      restartedPosts += 1;
      return { ok: true };
    },
  });
  await assert.rejects(restarted.coordinator.submit(SESSION_ID, "payer", PAYER_SIG), { code: "AMBIGUOUS_WRITE" });
  assert.equal(restartedPosts, 0);
});

test("durable state resumes after restart and concurrent next calls serialize globally", async () => {
  __resetHandshakeStateStore();
  const sharedStore = createHandshakeStateStore({});
  const first = harness({ reset: false, store: sharedStore });
  await first.coordinator.join("payer");
  await first.coordinator.submit(SESSION_ID, "payer", PAYER_SIG);

  const slow = [];
  const h1 = harness({ reset: false, store: sharedStore });
  const h2 = harness({ reset: false, store: sharedStore });
  h1.coordinator.__testDelay = async () => new Promise((resolve) => slow.push(resolve));
  const results = Promise.all([
    h1.coordinator.next(SESSION_ID, "payer"),
    h2.coordinator.next(SESSION_ID, "payer"),
  ]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(slow.length, 1);
  slow[0]();
  const [a, b] = await results;
  assert.ok(a.stage);
  assert.ok(b.stage);
  assert.equal(sharedStore, sharedStore);
});

test("wrong signature before anchor is rejected", async () => {
  const requestorRelayKey = generateRelayKeyPair();
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
  ];
  const { coordinator } = harness({ messages });
  await joinAndIdentify(coordinator, "payer", PAYER_SIG);
  await coordinator.next(SESSION_ID, "payer");
  await coordinator.next(SESSION_ID, "payer");
  await assert.rejects(coordinator.submit(SESSION_ID, "payer", OTHER_SIG), { code: "SIGNATURE_ROLE_MISMATCH" });
});

test("degraded pool health fails closed unless env override is set", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const baseMessages = () => [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: { paymentMoved: false }, kind: "watching", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];
  const strict = harness({ key, messages: baseMessages() });
  strict.clockchain.getPoolHealth = async () => ({ degraded: true, nodeParticipationPct: "33", totalNodes: "3" });
  await preparePayerWithHostedArtifacts(strict, key, requestorRelayKey);
  await assert.rejects(strict.coordinator.next(SESSION_ID, "payer"), { code: "POOL_DEGRADED" });

  const override = harness({ env: { HANDSHAKE_ALLOW_DEGRADED: "true" }, key, messages: baseMessages() });
  override.clockchain.getPoolHealth = async () => ({ degraded: true, nodeParticipationPct: "33", totalNodes: "3" });
  await preparePayerWithHostedArtifacts(override, key, requestorRelayKey);
  await assert.doesNotReject(override.coordinator.next(SESSION_ID, "payer"));
  assert.equal(override.records.length, 1);
});

test("certificate is unavailable before verified evidence and rejects the wrong operator key", async () => {
  const key = operatorKey();
  const wrong = operatorKey();
  const fixture = descriptorEnvelope(key);
  const digest = digestHex(fixture.descriptor);
  const pending = harness({ key, result: resultEnvelope(key, digest) });
  await pending.coordinator.join("payer");
  await assert.rejects(pending.coordinator.getCertificate(SESSION_ID), { code: "CERTIFICATE_EVIDENCE_UNVERIFIED" });

  const bad = harness({ key, result: resultEnvelope(wrong, digest) });
  await joinAndIdentify(bad.coordinator, "payer", PAYER_SIG);
  await bad.store.update({ principal: "did:example:alice", session: SESSION_ID, role: "payer" }, (record) => ({
    ...record,
    data: {
      ...record.data,
      evidenceVerified: true,
      discovery: discovery(key),
      sessionDigest: digest,
    },
  }));
  await assert.rejects(bad.coordinator.getCertificate(SESSION_ID), { code: "CERTIFICATE_INVALID" });
});

test("certificate fetch treats a not-yet-published host result as normal waiting", async () => {
  const key = operatorKey();
  const pending = harness({ key });
  await pending.coordinator.join("payer");
  await pending.store.update({ principal: "did:example:alice", session: SESSION_ID, role: "payer" }, (record) => ({
    ...record,
    data: {
      ...record.data,
      discovery: discovery(key),
      evidenceVerified: true,
    },
  }));

  assert.deepEqual(await pending.coordinator.getCertificate(SESSION_ID), {
    needed: "certificate",
    retryAfterMs: 5000,
    sessionId: SESSION_ID,
    stage: "awaiting_certificate",
  });
});

test("certificate verifies result parties and anchors against stored descriptor and transitions", async () => {
  const key = operatorKey();
  const fixture = descriptorEnvelope(key);
  const digest = digestHex(fixture.descriptor);
  const transitions = [
    storedTransition("proposal", "100", "123e4567-e89b-42d3-a456-426614174010", "1".repeat(64)),
    storedTransition("acceptance", "101", "123e4567-e89b-42d3-a456-426614174011", "2".repeat(64)),
    storedTransition("acknowledgment", "102", "123e4567-e89b-42d3-a456-426614174012", "3".repeat(64)),
  ];
  const good = harness({ key, result: resultEnvelope(key, digest) });
  await good.coordinator.join("payer");
  await good.store.update({ principal: "did:example:alice", session: SESSION_ID, role: "payer" }, (record) => ({
    ...record,
    data: {
      ...record.data,
      descriptor: fixture.descriptor,
      discovery: discovery(key),
      evidenceVerified: true,
      mandateEnvelope: fixture.mandate,
      requestEnvelope: fixture.request,
      sessionDigest: digest,
      transitions,
    },
  }));

  assert.equal((await good.coordinator.getCertificate(SESSION_ID)).certificate.result.sessionDigest, digest);

  const bad = harness({
    key,
    result: resultEnvelope(key, digest, {
      anchors: [
        { blockHeight: "999", blockTimeRaw: "2026-08-08T12:00:00.000Z", digest: "1".repeat(64), kind: "proposal", ledgerId: "123e4567-e89b-42d3-a456-426614174010" },
        { blockHeight: "101", blockTimeRaw: "2026-08-08T12:00:10.000Z", digest: "2".repeat(64), kind: "acceptance", ledgerId: "123e4567-e89b-42d3-a456-426614174011" },
        { blockHeight: "102", blockTimeRaw: "2026-08-08T12:00:20.000Z", digest: "3".repeat(64), kind: "acknowledgment", ledgerId: "123e4567-e89b-42d3-a456-426614174012" },
      ],
    }),
  });
  await bad.coordinator.join("payer");
  await bad.store.update({ principal: "did:example:alice", session: SESSION_ID, role: "payer" }, (record) => ({
    ...record,
    data: {
      ...record.data,
      descriptor: fixture.descriptor,
      discovery: discovery(key),
      evidenceVerified: true,
      mandateEnvelope: fixture.mandate,
      requestEnvelope: fixture.request,
      sessionDigest: digest,
      transitions,
    },
  }));
  await assert.rejects(bad.coordinator.getCertificate(SESSION_ID), { code: "CERTIFICATE_INVALID" });
});

test("certificate binds the relay session separately from the commercial session", async () => {
  const key = operatorKey();
  const mandateEnvelope = canonicalMandateBody().mandateEnvelope;
  const requestEnvelope = requestEnvelopeForMandate(mandateEnvelope);
  const fixture = descriptorEnvelopeForArtifacts(key, { mandate: mandateEnvelope, request: requestEnvelope });
  const digest = digestHex(fixture.descriptor);
  const transitions = [
    storedTransition("proposal", "100", "123e4567-e89b-42d3-a456-426614174010", "1".repeat(64)),
    storedTransition("acceptance", "101", "123e4567-e89b-42d3-a456-426614174011", "2".repeat(64)),
    storedTransition("acknowledgment", "102", "123e4567-e89b-42d3-a456-426614174012", "3".repeat(64)),
  ];
  const h = harness({ key, result: resultEnvelope(key, digest, { subjectRun: "stakeholder" }) });
  await h.coordinator.join("payer");
  await h.store.update({ principal: "did:example:alice", session: SESSION_ID, role: "payer" }, (record) => ({
    ...record,
    data: {
      ...record.data,
      descriptor: fixture.descriptor,
      discovery: discovery(key),
      evidenceVerified: true,
      mandateEnvelope,
      requestEnvelope,
      sessionDigest: digest,
      transitions,
    },
  }));

  assert.notEqual(fixture.descriptor.sessionId, SESSION_COMPACT);
  assert.equal((await h.coordinator.getCertificate(SESSION_ID)).certificate.result.sessionId, SESSION_ID);
});

test("requestor posts watching before any proposal search or write", async () => {
  const key = operatorKey();
  const payerRelayKey = generateRelayKeyPair();
  const mandateBody = canonicalMandateBody();
  const messages = [
    relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: payerRelayKey }),
    relayMessage({ body: { address: PAYER, agentId: "101", paymentMoved: false }, kind: "party_ready", role: "payer", seq: "2", relayKey: payerRelayKey }),
    relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: mandateBody, kind: "mandate", role: "payer", seq: "4", relayKey: payerRelayKey }),
  ];
  const h = harness({ key, messages });
  h.clockchain.searchAsset = async (assetReferenceId) => {
    assert.ok(h.posted.some((entry) => entry.kind === "watching"), `watching must be posted before ${assetReferenceId}`);
    return h.records.filter((record) => record.assetReferenceId === assetReferenceId);
  };

  await joinAndIdentify(h.coordinator, "requestor", REQUESTOR_SIG);
  const request = await h.coordinator.next(SESSION_ID, "requestor");
  assert.equal(request.stage, "sign_payment_request");
  assert.deepEqual(hexJson(request.bytesToSignHex), preparePaymentRequest(hexJson(request.bytesToSignHex)));
  await h.coordinator.submit(SESSION_ID, "requestor", REQUESTOR_SIG);
  const requestEnvelope = h.posted.find((entry) => entry.kind === "payment_request").body.requestEnvelope;
  appendHostedDescriptor({
    fixture: descriptorEnvelopeForArtifacts(key, { mandate: mandateBody.mandateEnvelope, request: requestEnvelope }),
    key,
    messages,
  });
  await h.coordinator.next(SESSION_ID, "requestor");
});

test("full requestor side uploads payee evidence and fetches the certificate with local signatures only", async () => {
  const key = operatorKey();
  const payerRelayKey = generateRelayKeyPair();
  const mandateBody = canonicalMandateBody();
  const messages = [
    relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: payerRelayKey }),
    relayMessage({ body: { address: PAYER, agentId: "101" }, kind: "party_ready", role: "payer", seq: "2", relayKey: payerRelayKey }),
    relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: mandateBody, kind: "mandate", role: "payer", seq: "4", relayKey: payerRelayKey }),
  ];
  const h = harness({ key, messages });

  await joinAndIdentify(h.coordinator, "requestor", REQUESTOR_SIG);
  const requestSigning = await h.coordinator.next(SESSION_ID, "requestor");
  assert.equal(requestSigning.stage, "sign_payment_request");
  await h.coordinator.submit(SESSION_ID, "requestor", REQUESTOR_SIG);
  const requestEnvelope = h.posted.find((entry) => entry.kind === "payment_request").body.requestEnvelope;
  const fixture = descriptorEnvelopeForArtifacts(key, { mandate: mandateBody.mandateEnvelope, request: requestEnvelope });
  appendHostedDescriptor({ fixture, key, messages });

  const sessionDigest = digestHex(fixture.descriptor);
  const proposal = buildProposal({
    amount: fixture.descriptor.amountOptions[0],
    descriptor: fixture.descriptor,
    sessionDigest,
  });
  h.records.push({
    assetHash: digestHex(proposal),
    assetReferenceId: sessionKey(sessionDigest, "proposal"),
    blockHeight: "100",
    blockTimeRaw: "2026-08-08T12:00:00.000Z",
    ledgerId: "123e4567-e89b-42d3-a456-426614174010",
  });

  const partySigning = await h.coordinator.next(SESSION_ID, "requestor");
  assert.equal(partySigning.stage, "sign_party_result");
  await h.coordinator.submit(SESSION_ID, "requestor", REQUESTOR_SIG);
  assert.equal(h.posted.some((entry) => entry.evidence?.role === "payee"), true);

  const state = await h.store.get({ principal: "did:example:alice", session: SESSION_ID, role: "requestor" });
  const [proposalTransition, acceptanceTransition] = state.data.transitions;
  const acknowledgment = buildAcknowledgment({
    acceptance: acceptanceTransition.message,
    acceptanceTriple: {
      anchoredHash: acceptanceTransition.onChain.anchoredHash,
      blockHeight: acceptanceTransition.onChain.blockHeight,
      kind: "acceptance",
      ledgerId: acceptanceTransition.onChain.ledgerId,
    },
    proposalTriple: {
      anchoredHash: proposalTransition.onChain.anchoredHash,
      blockHeight: proposalTransition.onChain.blockHeight,
      kind: "proposal",
      ledgerId: proposalTransition.onChain.ledgerId,
    },
  });
  h.records.push({
    assetHash: digestHex(acknowledgment),
    assetReferenceId: sessionKey(sessionDigest, "acknowledgment"),
    blockHeight: "102",
    blockTimeRaw: "2026-08-08T12:00:20.000Z",
    ledgerId: "123e4567-e89b-42d3-a456-426614174012",
  });
  h.setResult(resultEnvelope(key, sessionDigest, {
    anchors: [
      { blockHeight: proposalTransition.onChain.blockHeight, blockTimeRaw: proposalTransition.blockTimeRaw, digest: proposalTransition.digest, kind: "proposal", ledgerId: proposalTransition.onChain.ledgerId },
      { blockHeight: acceptanceTransition.onChain.blockHeight, blockTimeRaw: acceptanceTransition.blockTimeRaw, digest: acceptanceTransition.digest, kind: "acceptance", ledgerId: acceptanceTransition.onChain.ledgerId },
      { blockHeight: "102", blockTimeRaw: "2026-08-08T12:00:20.000Z", digest: digestHex(acknowledgment), kind: "acknowledgment", ledgerId: "123e4567-e89b-42d3-a456-426614174012" },
    ],
    subjectRun: "stakeholder",
  }));

  assert.equal((await h.coordinator.getCertificate(SESSION_ID)).certificate.result.sessionDigest, sessionDigest);
  assert.doesNotMatch(JSON.stringify([requestSigning, partySigning]), /privateKey|mnemonic|seed|credential/i);
});

test("malformed inbound mandate is rejected before any Clockchain write", async () => {
  const payerRelayKey = generateRelayKeyPair();
  const badMandate = canonicalMandateBody({ signature: OTHER_SIG });
  const messages = [
    relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: payerRelayKey }),
    relayMessage({ body: { address: PAYER, agentId: "101", paymentMoved: false }, kind: "party_ready", role: "payer", seq: "2", relayKey: payerRelayKey }),
    relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: badMandate, kind: "mandate", role: "payer", seq: "4", relayKey: payerRelayKey }),
  ];
  const h = harness({ messages });

  await assert.rejects(joinAndIdentify(h.coordinator, "requestor", REQUESTOR_SIG), { code: "ARTIFACT_SIGNATURE_MISMATCH" });
  assert.equal(h.records.length, 0);
});

test("inbound mandate requires the exact canonical envelope shape", async () => {
  const payerRelayKey = generateRelayKeyPair();
  const mandateBody = canonicalMandateBody();
  mandateBody.mandateEnvelope = { ...mandateBody.mandateEnvelope, unexpected: "field" };
  const h = harness({
    messages: [
      relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: payerRelayKey }),
      relayMessage({ body: { address: PAYER, agentId: "101" }, kind: "party_ready", role: "payer", seq: "2", relayKey: payerRelayKey }),
      relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
      relayMessage({ body: mandateBody, kind: "mandate", role: "payer", seq: "4", relayKey: payerRelayKey }),
    ],
  });

  await assert.rejects(joinAndIdentify(h.coordinator, "requestor", REQUESTOR_SIG), { code: "MANDATE_BODY_INVALID" });
  assert.equal(h.records.length, 0);
});

test("inbound artifacts must come from the seated relay sender", async () => {
  const seatedPayerKey = generateRelayKeyPair();
  const differentPayerKey = generateRelayKeyPair();
  const h = harness({
    messages: [
      relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: seatedPayerKey }),
      relayMessage({ body: { address: PAYER, agentId: "101" }, kind: "party_ready", role: "payer", seq: "2", relayKey: seatedPayerKey }),
      relayMessage({ body: { funded: REQUESTOR, paymentMoved: false, role: "requestor" }, kind: "funding_record", role: "host", seq: "3" }),
      relayMessage({ body: canonicalMandateBody(), kind: "mandate", role: "payer", seq: "4", relayKey: differentPayerKey }),
    ],
  });

  await assert.rejects(joinAndIdentify(h.coordinator, "requestor", REQUESTOR_SIG), { code: "COUNTERPART_BINDING_MISMATCH" });
});

test("conflicting same-role seat records fail closed", async () => {
  const firstKey = generateRelayKeyPair();
  const secondKey = generateRelayKeyPair();
  const h = harness({
    messages: [
      relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "1", relayKey: firstKey }),
      relayMessage({ body: { address: PAYER }, kind: "identity_ready", role: "payer", seq: "2", relayKey: secondKey }),
    ],
  });
  await h.coordinator.join("requestor");
  await assert.rejects(h.coordinator.next(SESSION_ID, "requestor"), { code: "ROLE_ALREADY_BOUND" });
});

test("malformed inbound request is rejected before any Clockchain write", async () => {
  const key = operatorKey();
  const fixture = descriptorEnvelope(key);
  const requestorRelayKey = generateRelayKeyPair();
  const badRequest = { paymentMoved: false, requestEnvelope: sealPaymentRequest(fixture.request.request, OTHER_SIG) };
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202", paymentMoved: false }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: badRequest, kind: "payment_request", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];
  const h = harness({ key, messages });

  await assert.rejects(joinAndIdentify(h.coordinator, "payer", PAYER_SIG), { code: "ARTIFACT_SIGNATURE_MISMATCH" });
  assert.equal(h.records.length, 0);
});

test("payment request commercial fields must all bind to the payer mandate", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const h = harness({
    key,
    messages: [
      relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
      relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
      relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    ],
  });
  await joinAndIdentify(h.coordinator, "payer", PAYER_SIG);
  await h.coordinator.next(SESSION_ID, "payer");
  await h.coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  const mandateEnvelope = h.posted.find((entry) => entry.kind === "mandate").body.mandateEnvelope;
  h.messages.push(relayMessage({
    body: {
      paymentMoved: false,
      requestEnvelope: requestEnvelopeForMandate(mandateEnvelope, REQUESTOR_SIG, { amount: { currency: "USD", value: "99" } }),
    },
    kind: "payment_request",
    role: "requestor",
    seq: "10",
    relayKey: requestorRelayKey,
  }));

  await assert.rejects(h.coordinator.next(SESSION_ID, "payer"), { code: "REQUEST_BODY_INVALID" });
  assert.equal(h.records.length, 0);
});

test("only the host role can publish the signed descriptor", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const h = harness({
    key,
    messages: [
      relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
      relayMessage({ body: { address: REQUESTOR, agentId: "202" }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
      relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    ],
  });
  await joinAndIdentify(h.coordinator, "payer", PAYER_SIG);
  await h.coordinator.next(SESSION_ID, "payer");
  await h.coordinator.submit(SESSION_ID, "payer", PAYER_SIG);
  const mandateEnvelope = h.posted.find((entry) => entry.kind === "mandate").body.mandateEnvelope;
  const requestEnvelope = requestEnvelopeForMandate(mandateEnvelope);
  const fixture = descriptorEnvelopeForArtifacts(key, { mandate: mandateEnvelope, request: requestEnvelope });
  h.messages.push(
    relayMessage({ body: { paymentMoved: false, requestEnvelope }, kind: "payment_request", role: "requestor", seq: "10", relayKey: requestorRelayKey }),
    relayMessage({
      body: { descriptorEnvelope: fixture.descriptorEnvelope, repositoryPublicKey: key.publicKeyRaw, paymentMoved: false },
      kind: "handshake_required",
      role: "payer",
      seq: "11",
    }),
  );

  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer"), {
    needed: "handshake_required",
    sessionId: SESSION_ID,
    stage: "awaiting_descriptor",
  });
  assert.equal(h.records.length, 0);
});

test("descriptor reverse ownership mismatch is rejected before any Clockchain write", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202", paymentMoved: false }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
  ];
  let payerLookups = 0;
  const h = harness({
    key,
    messages,
    resolveOwnedAgentId: async ({ address }) => {
      if (address !== PAYER) return "202";
      payerLookups += 1;
      return payerLookups === 1 ? "101" : "999";
    },
  });

  await preparePayerWithHostedArtifacts(h, key, requestorRelayKey);
  await assert.rejects(h.coordinator.next(SESSION_ID, "payer"), { code: "DESCRIPTOR_PARTY_MISMATCH" });
  assert.equal(h.records.length, 0);
});

test("pending Clockchain anchors return a waiting stage and do not redispatch on restart", async () => {
  const key = operatorKey();
  const requestorRelayKey = generateRelayKeyPair();
  __resetHandshakeStateStore();
  const sharedStore = createHandshakeStateStore({});
  const messages = [
    relayMessage({ body: { address: REQUESTOR }, kind: "identity_ready", role: "requestor", seq: "1", relayKey: requestorRelayKey }),
    relayMessage({ body: { address: REQUESTOR, agentId: "202", paymentMoved: false }, kind: "party_ready", role: "requestor", seq: "2", relayKey: requestorRelayKey }),
    relayMessage({ body: { funded: PAYER, paymentMoved: false, role: "payer" }, kind: "funding_record", role: "host", seq: "3" }),
    relayMessage({ body: { paymentMoved: false }, kind: "watching", role: "requestor", seq: "4", relayKey: requestorRelayKey }),
  ];
  const h = harness({ key, messages, store: sharedStore, reset: false });
  let logCalls = 0;
  h.clockchain.log = async ({ assetHash, assetReferenceId }) => {
    logCalls += 1;
    const record = { assetHash, assetReferenceId, blockHeight: null, ledgerId: "123e4567-e89b-42d3-a456-426614174099" };
    h.records.push(record);
    return record;
  };

  await preparePayerWithHostedArtifacts(h, key, requestorRelayKey);
  assert.deepEqual(await h.coordinator.next(SESSION_ID, "payer"), {
    needed: "clockchain_confirmation",
    sessionId: SESSION_ID,
    stage: "awaiting_clockchain_confirmation",
  });

  const restarted = harness({ key, messages, store: sharedStore, reset: false });
  restarted.clockchain.log = async () => {
    throw new Error("must not redispatch pending intent");
  };
  restarted.clockchain.searchAsset = h.clockchain.searchAsset;
  restarted.records.push(...h.records);
  assert.deepEqual(await restarted.coordinator.next(SESSION_ID, "payer"), {
    needed: "clockchain_confirmation",
    sessionId: SESSION_ID,
    stage: "awaiting_clockchain_confirmation",
  });
  assert.equal(logCalls, 1);
});
