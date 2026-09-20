import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { gunzipSync } from "node:zlib";
import test from "node:test";

import { createHandshakeStateStore, __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { createV2InvitationService, createV2InvitationStore } from "../dist/agent-handshake/v2/invitation-store.js";
import { readV2RoleAccessPayload } from "../dist/agent-handshake/v2/access.js";
import { generateRelayKeyPair } from "../dist/handshake/protocol.js";
import * as v2CoordinatorModule from "../dist/agent-handshake/v2/coordinator.js";
import { v2CanonicalRecord } from "../dist/agent-handshake/v2/protocol.js";

const { createV2Coordinator } = v2CoordinatorModule;

const terms = {
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
};
const sessionId = randomUUID();
const nowMs = 1786337000000;
const repositorySha = "d".repeat(40);
const verifiedHelperPrefix = "node --verified-helper";
const hostSessionKeyCertificate = {
  certificate: { schema: "clockchain.host-session-key/v1", rootKid: "root-2026-08", sessionId, repositorySha, sessionPublicKey: "ore80hj1AhLMNPybJXCL6XHyJ9OfmaYSXc4SA8Sk2Pw=", validFromMs: String(nowMs), validUntilMs: String(nowMs + 600000) },
  root: { algorithm: "ed25519", keyId: "root-2026-08", publicKey: "6Xgu+IYxQBDx8adVlHHWf9AUYoeo+eqWr8eVQqXrY0Y=", signature: "a".repeat(88) },
};
const discovery = {
  schema: "clockchain.agent-handshake-discovery/v2",
  protocol: "clockchain.agent-handshake/v2",
  sessionId,
  repositorySha,
  kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git",
  relayUrl: "https://relay.example",
  createdAtMs: String(nowMs),
  invitationExpiresAtMs: String(nowMs + 120000),
  sessionDeadlineMs: String(nowMs + 600000),
  sessionOpenedBlock: "6999",
  hostSessionKeyCertificate,
  terms,
  externalBusinessActionPerformed: false,
};

function policy(role) {
  return {
    schema: "clockchain.agent-handshake-policy/v1",
    protocol: "clockchain.agent-handshake/v2",
    role,
    mcpOrigin: "https://mcp.clockchain.network",
    reference: terms.reference,
    statementDigest: v2CanonicalRecord(terms).digest,
    maxValidForSeconds: terms.validForSeconds,
    identityPolicy: terms.identityPolicy,
    externalBusinessActionsAllowed: false,
  };
}

function compactHelperStep(operation, role, command) {
  const commandSha256 = createHash("sha256").update(command).digest("hex");
  return {
    operation,
    role,
    sessionId,
    approvalTool: "mcp__clockchain-local-adapter__authorize_local_action",
    commandLength: Buffer.byteLength(command),
    commandSha256,
    shellCommand: command,
  };
}

function compactPayloadFrom(response, operation) {
  assert.equal(Object.hasOwn(response, "signingRequest"), false);
  assert.equal(response.signingSummary.schema, "clockchain.agent-handshake-signing-summary/v1");
  assert.equal(response.signingSummary.operation, operation);
  assert.equal(response.signingSummary.role, response.localAction.helperStep.role);
  assert.equal(response.signingSummary.sessionId, response.localAction.helperStep.sessionId);
  assert.match(response.signingSummary.bytesSha256, /^[0-9a-f]{64}$/);
  assert.equal(response.localAction.operation, "sign");
  assert.deepEqual(Object.keys(response.localAction.helperStep), [
    "operation", "role", "sessionId", "approvalTool", "commandLength", "commandSha256", "shellCommand",
  ]);
  const command = response.localAction.helperStep.shellCommand;
  assert.equal(response.localAction.helperStep.commandLength, Buffer.byteLength(command));
  assert.equal(response.localAction.helperStep.commandSha256, createHash("sha256").update(command).digest("hex"));
  assert.equal(response.localAction.helperStep.approvalTool, "mcp__clockchain-local-adapter__authorize_local_action");
  const match = command.match(/--payload-base64url\s+([A-Za-z0-9_-]+)$/);
  assert.ok(match);
  const payload = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
  assert.equal(payload.operation, operation);
  assert.equal(payload.role, response.signingSummary.role);
  assert.equal(payload.sessionId, response.signingSummary.sessionId);
  assert.equal(payload.bytesSha256, response.signingSummary.bytesSha256);
  const serialized = JSON.stringify(response);
  assert.equal(serialized.split("--payload-base64url").length - 1, 1);
  assert.equal(serialized.split(match[1]).length - 1, 1);
  assert.equal(serialized.includes("argvAfterVerifiedPrefix"), false);
  assert.equal(serialized.includes("shellCommandSuffix"), false);
  assert.ok(Buffer.byteLength(serialized) < 8192);
  return payload;
}

function compactCertificatePayloadFrom(response, role) {
  assert.equal(Object.hasOwn(response, "certificate"), false);
  assert.equal(response.role, role);
  assert.equal(response.sessionId, sessionId);
  assert.equal(response.certificateSummary.schema, "clockchain.agent-handshake-certificate-summary/v1");
  assert.equal(response.certificateSummary.outcome, "VERIFIED");
  assert.equal(response.certificateSummary.role, role);
  assert.equal(response.certificateSummary.sessionId, sessionId);
  assert.match(response.certificateSummary.resultDigest, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(response.localAction.helperStep), [
    "operation", "role", "sessionId", "approvalTool", "commandLength", "commandSha256", "shellCommand",
  ]);
  const command = response.localAction.helperStep.shellCommand;
  assert.equal(response.localAction.helperStep.operation, "verify-certificate");
  assert.equal(response.localAction.helperStep.role, role);
  assert.equal(response.localAction.helperStep.sessionId, sessionId);
  assert.equal(response.localAction.helperStep.commandLength, Buffer.byteLength(command));
  assert.equal(response.localAction.helperStep.commandSha256, createHash("sha256").update(command).digest("hex"));
  assert.equal(response.localAction.helperStep.approvalTool, "mcp__clockchain-local-adapter__authorize_local_action");
  const match = command.match(/--payload-base64url\s+([A-Za-z0-9_-]+)$/);
  assert.ok(match);
  const payload = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
  assert.equal(payload.role, role);
  assert.equal(payload.sessionId, sessionId);
  const serialized = JSON.stringify(response);
  assert.equal(serialized.split("--payload-base64url").length - 1, 1);
  assert.equal(serialized.split(match[1]).length - 1, 1);
  assert.equal(serialized.includes("argvAfterVerifiedPrefix"), false);
  assert.equal(serialized.includes("shellCommandSuffix"), false);
  assert.ok(Buffer.byteLength(serialized) < 16384);
  return payload;
}

test("an unanchored Clockchain ledger response is retryable instead of a terminal protocol rejection", async () => {
  assert.equal(typeof v2CoordinatorModule.__advanceRuntimeV2, "function");
  const descriptor = {
    agreementExpiresAtMs: String(nowMs + 90_000),
    externalBusinessActionPerformed: false,
    initiator: { sessionKeyAddress: "0x7564105e977516c53be337314c7e53838967bdac" },
    protocol: "clockchain.agent-handshake/v2",
    reference: terms.reference,
    responder: { sessionKeyAddress: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9" },
    schema: "clockchain.agent-handshake-descriptor/v2",
    statementDigest: v2CanonicalRecord(terms).digest,
  };
  const clockchain = {
    searchAsset: async () => [],
    log: async () => ({ ledgerId: "33333333-4444-4555-8666-777777777770" }),
    getLedgerEntry: async () => ({
      ledgerId: "33333333-4444-4555-8666-777777777770",
      blockHeight: null,
      assetHash: "pending",
      assetReferenceId: "pending",
    }),
    getChainRecord: async () => null,
    getBlock: async () => ({}),
  };

  await assert.rejects(
    () => v2CoordinatorModule.__advanceRuntimeV2(clockchain, { descriptor, role: "initiator", existing: [] }),
    (error) => error?.name === "V2TransientCoordinatorError",
  );
});

test("an expired current invitation window is retryable while the host rotates sessions", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const stateStore = createHandshakeStateStore({});
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({
      activeKey: key,
      verificationKeys: [key],
      store: createV2InvitationStore(),
      nowMs: () => nowMs + 120000,
    }),
    relay: {
      fetchDiscovery: async () => discovery,
      getMessages: async () => ({ messages: [] }),
      postMessage: async () => ({ ok: true, seq: "1" }),
    },
    stateStore,
    now: () => nowMs + 120000,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  await assert.rejects(
    () => coordinator.invite(terms),
    (error) => error?.name === "V2TransientCoordinatorError",
  );
  assert.equal((await stateStore.list()).length, 0);
});

test("a near-expiry current invitation window is retryable before any state is minted", async (t) => {
  let createCalls = 0;
  const harness = await createDurableAcceptHarness(t, {
    now: () => nowMs + 120000 - 5_000,
    wrapInvitationService: (service) => Object.freeze({
      ...service,
      create: async (input) => { createCalls += 1; return service.create(input); },
    }),
  });

  await assert.rejects(
    () => harness.coordinator.invite(terms),
    (error) => error?.name === "V2TransientCoordinatorError",
  );
  assert.equal(createCalls, 0);
  assert.equal((await harness.stateStore.list()).length, 0);
});

test("an invite whose clock crosses the invitation runway boundary during create rejects retryably with nothing persisted", async (t) => {
  // 31s of runway passes the precheck; the clock then lands 10s before expiry — still inside the window but
  // below the 30s runway — so the commit-time guard must refuse the write atomically.
  const ticks = [nowMs + 120000 - 31_000, nowMs + 120000 - 10_000];
  let createCalls = 0;
  const attempted = [];
  const innerStore = createV2InvitationStore();
  const harness = await createDurableAcceptHarness(t, {
    invitationStore: Object.freeze({
      ...innerStore,
      put: (value, commitGuard) => {
        attempted.push(value);
        return innerStore.put(value, commitGuard);
      },
    }),
    now: () => (ticks.length > 1 ? ticks.shift() : ticks[0]),
    wrapInvitationService: (service) => Object.freeze({
      ...service,
      create: async (input) => { createCalls += 1; return service.create(input); },
    }),
  });

  await assert.rejects(
    () => harness.coordinator.invite(terms),
    (error) => error?.name === "V2TransientCoordinatorError",
  );
  assert.equal(createCalls, 1);
  assert.equal(attempted.length, 1);
  assert.equal(await innerStore.get(attempted[0].jti), null);
  assert.equal((await harness.stateStore.list()).length, 0);
});

test("an invite whose terms differ from the published host terms is rejected before minting or posting", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const calls = { create: 0, update: 0, post: 0 };
  const store = createHandshakeStateStore({});
  const countingStore = {
    get: (keyValue) => store.get(keyValue),
    put: (keyValue, record) => store.put(keyValue, record),
    list: () => store.list(),
    update: (keyValue, mutate) => { calls.update += 1; return store.update(keyValue, mutate); },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: {
      create: async () => { calls.create += 1; return { initiatorAccess: "", responderInvitation: "" }; },
      accept: async () => { throw new Error("unexpected accept"); },
    },
    relay: {
      fetchDiscovery: async () => discovery,
      getMessages: async () => ({ messages: [] }),
      postMessage: async () => { calls.post += 1; return { ok: true, seq: "1" }; },
    },
    stateStore: countingStore,
    now: () => nowMs + 1,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  await assert.rejects(
    () => coordinator.invite({ ...terms, reference: "NS-2000" }),
    (error) => {
      assert.equal(error?.name, "V2TermsMismatchError");
      assert.deepEqual(error.publishedTerms, terms);
      return true;
    },
  );
  assert.deepEqual(calls, { create: 0, update: 0, post: 0 });
});

test("a discovery record with malformed host terms is rejected", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => nowMs + 1 }),
    relay: {
      fetchDiscovery: async () => ({ ...discovery, terms: { ...terms, validForSeconds: "999" } }),
      getMessages: async () => ({ messages: [] }),
      postMessage: async () => ({ ok: true, seq: "1" }),
    },
    stateStore: createHandshakeStateStore({}),
    now: () => nowMs + 1,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  await assert.rejects(
    () => coordinator.invite(terms),
    (error) => error?.name === "V2CoordinatorError",
  );
});

test("a discovery record with a present but undefined terms property is rejected", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const calls = { create: 0, update: 0, post: 0 };
  const store = createHandshakeStateStore({});
  const countingStore = {
    get: (keyValue) => store.get(keyValue),
    put: (keyValue, record) => store.put(keyValue, record),
    list: () => store.list(),
    update: (keyValue, mutate) => { calls.update += 1; return store.update(keyValue, mutate); },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: {
      create: async () => { calls.create += 1; return { initiatorAccess: "", responderInvitation: "" }; },
      accept: async () => { throw new Error("unexpected accept"); },
    },
    relay: {
      fetchDiscovery: async () => ({ ...discovery, terms: undefined }),
      getMessages: async () => ({ messages: [] }),
      postMessage: async () => { calls.post += 1; return { ok: true, seq: "1" }; },
    },
    stateStore: countingStore,
    now: () => nowMs + 1,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  await assert.rejects(
    () => coordinator.invite(terms),
    (error) => error?.name === "V2CoordinatorError",
  );
  assert.deepEqual(calls, { create: 0, update: 0, post: 0 });
});

test("a legacy discovery record without terms falls back to caller terms with bounded telemetry", async (t) => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const { terms: _publishedTerms, ...legacyDiscovery } = discovery;
  const calls = { create: 0, update: 0, post: 0 };
  const store = createHandshakeStateStore({});
  const countingStore = {
    get: (keyValue) => store.get(keyValue),
    put: (keyValue, record) => store.put(keyValue, record),
    list: () => store.list(),
    update: (keyValue, mutate) => { calls.update += 1; return store.update(keyValue, mutate); },
  };
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (entry) => warnings.push(entry);
  t.after(() => { console.warn = originalWarn; });
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => nowMs + 1 }),
    relay: {
      fetchDiscovery: async () => legacyDiscovery,
      getMessages: async () => ({ messages: [] }),
      postMessage: async () => { calls.post += 1; return { ok: true, seq: "1" }; },
    },
    stateStore: countingStore,
    now: () => nowMs + 1,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite({ ...terms, reference: "NS-2000" });
  assert.equal(invited.terms.reference, "NS-2000");
  assert.deepEqual(calls, { create: 0, update: 1, post: 1 });
  assert.equal(warnings.length, 1);
  const event = JSON.parse(warnings[0]);
  assert.equal(event.event, "agent_handshake_v2_invite_without_host_terms");
  assert.equal(event.sessionId, sessionId);
  assert.deepEqual(Object.keys(event).sort(), ["event", "sessionId"]);
  assert.equal(JSON.stringify(event).includes("statement"), false);
});

async function createDurableAcceptHarness(t, options = {}) {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const acceptanceKey = { kid: "accept-2026-08", secret: randomBytes(32) };
  const messages = [];
  const stateStore = createHandshakeStateStore({});
  let currentDiscovery = options.discovery ?? discovery;
  const invitationStore = options.invitationStore ?? createV2InvitationStore();
  const baseInvitationService = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [acceptanceKey],
    store: invitationStore,
    nowMs: () => nowMs + 1,
  });
  const invitationService = options.wrapInvitationService
    ? options.wrapInvitationService(baseInvitationService)
    : baseInvitationService;
  const relay = {
    fetchDiscovery: async (requested) => {
      assert.ok(requested === undefined || requested === sessionId);
      return currentDiscovery;
    },
    getMessages: async () => ({ messages }),
    postMessage: async (input) => {
      if (options.onPostMessage) await options.onPostMessage(input, messages);
      messages.push({
        body: input.body,
        kind: input.kind,
        role: input.role,
        senderKey: input.senderKey,
        sessionId: input.sessionId,
      });
      return { ok: true, seq: String(messages.length) };
    },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService,
    relay,
    stateStore,
    now: options.now ?? (() => nowMs + 1),
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });
  const warnings = [];
  if (t) {
    const originalWarn = console.warn;
    console.warn = (entry) => warnings.push(entry);
    t.after(() => { console.warn = originalWarn; });
  }
  return {
    coordinator,
    invitationStore,
    messages,
    setDiscovery: (next) => { currentDiscovery = next; },
    stateStore,
    warnings,
  };
}

test("a keyed invitation accept retries after relay post failure with one responder relay identity", async (t) => {
  let failClaimPost = true;
  const harness = await createDurableAcceptHarness(t, {
    onPostMessage: async (input) => {
      if (input.kind === "agent_v2_invitation_claimed" && failClaimPost) {
        failClaimPost = false;
        throw new Error("relay unavailable after state insert");
      }
    },
  });
  const invited = await harness.coordinator.invite(terms);
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, "8ec16f1f-1cf5-4e9a-86c6-a17164d834af"),
    /relay unavailable/,
  );
  const failedState = (await harness.stateStore.list()).find((record) => record.role === "responder");
  assert.ok(failedState);
  const retried = await harness.coordinator.acceptInvitation(invited.responderInvitation, "8ec16f1f-1cf5-4e9a-86c6-a17164d834af");
  const completed = await harness.coordinator.acceptInvitation(invited.responderInvitation, "8ec16f1f-1cf5-4e9a-86c6-a17164d834af");
  const finalState = (await harness.stateStore.list()).find((record) => record.role === "responder");
  assert.equal(retried.responderAccess, completed.responderAccess);
  assert.equal(finalState.relayEd25519Pem, failedState.relayEd25519Pem);
  assert.equal(finalState.data.relay.senderKey, failedState.data.relay.senderKey);
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
});

test("a legacy responder state retries after discovery later publishes matching terms", async (t) => {
  const { terms: _publishedTerms, ...legacyDiscovery } = discovery;
  let failClaimPost = true;
  const harness = await createDurableAcceptHarness(t, {
    discovery: legacyDiscovery,
    onPostMessage: async (input) => {
      if (input.kind === "agent_v2_invitation_claimed" && failClaimPost) {
        failClaimPost = false;
        throw new Error("relay unavailable after legacy state insert");
      }
    },
  });
  const activeTerms = { ...terms, reference: "NS-LEGACY-RETRY" };
  const invited = await harness.coordinator.invite(activeTerms);
  const key = "6d0f29af-1954-4dc3-9541-642e2ea40c0e";
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    /relay unavailable/,
  );
  const failedState = (await harness.stateStore.list()).find((record) => record.role === "responder");
  assert.ok(failedState);
  assert.equal(Object.hasOwn(failedState.data.discovery, "terms"), false);
  harness.setDiscovery({ ...legacyDiscovery, terms: activeTerms });
  const retried = await harness.coordinator.acceptInvitation(invited.responderInvitation, key);
  const finalState = (await harness.stateStore.list()).find((record) => record.role === "responder");
  assert.equal(retried.terms.reference, "NS-LEGACY-RETRY");
  assert.equal(finalState.relayEd25519Pem, failedState.relayEd25519Pem);
  assert.equal(finalState.data.relay.senderKey, failedState.data.relay.senderKey);
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
});

test("accept revalidates refreshed host terms before creating responder state", async (t) => {
  const harness = await createDurableAcceptHarness(t);
  const invited = await harness.coordinator.invite(terms);
  harness.setDiscovery({ ...discovery, terms: { ...terms, reference: "NS-ROTATED" } });
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, "aa31486d-c7f5-4549-8778-184cd98c1a58"),
    (error) => error?.name === "V2CoordinatorError",
  );
  assert.equal((await harness.stateStore.list()).some((record) => record.role === "responder"), false);
  assert.equal(harness.messages.some((message) => message.kind === "agent_v2_invitation_claimed"), false);
});

test("accepting a legacy discovery without host terms emits bounded compatibility telemetry", async (t) => {
  const { terms: _publishedTerms, ...legacyDiscovery } = discovery;
  const harness = await createDurableAcceptHarness(t, { discovery: legacyDiscovery });
  const invited = await harness.coordinator.invite({ ...terms, reference: "NS-LEGACY" });
  harness.warnings.length = 0;
  const accepted = await harness.coordinator.acceptInvitation(invited.responderInvitation, "5c690be0-4490-4806-8890-0f647939ec6d");
  assert.equal(accepted.terms.reference, "NS-LEGACY");
  assert.equal(harness.warnings.length, 1);
  const event = JSON.parse(harness.warnings[0]);
  assert.equal(event.event, "agent_handshake_v2_accept_without_host_terms");
  assert.equal(event.sessionId, sessionId);
  assert.deepEqual(Object.keys(event).sort(), ["event", "sessionId"]);
  assert.equal(JSON.stringify(event).includes("statement"), false);
});

test("same-key accept retries through each durable phase acknowledgement", async (t) => {
  for (const phase of ["initialized", "posted", "completed"]) {
    let failed = false;
    const harness = await createDurableAcceptHarness(t, {
      wrapInvitationService: (service) => ({
        ...service,
        advanceClaim: async (input) => {
          if (input.phase === phase && !failed) {
            failed = true;
            throw new Error(`failed ${phase} acknowledgement`);
          }
          return service.advanceClaim(input);
        },
      }),
    });
    const invited = await harness.coordinator.invite(terms);
    const key = randomUUID();
    await assert.rejects(
      () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
      new RegExp(`failed ${phase}`),
    );
    const retried = await harness.coordinator.acceptInvitation(invited.responderInvitation, key);
    const completed = await harness.coordinator.acceptInvitation(invited.responderInvitation, key);
    assert.equal(retried.responderAccess, completed.responderAccess);
    assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
  }
});

test("a different acceptance idempotency key cannot take over an existing claim", async (t) => {
  const harness = await createDurableAcceptHarness(t);
  const invited = await harness.coordinator.invite(terms);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, "11111111-1111-4111-8111-111111111111");
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, "22222222-2222-4222-8222-222222222222"),
    (error) => error?.name === "V2InvitationError",
  );
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
});

test("a conflicting responder claim duplicate is terminal instead of reposted", async (t) => {
  const harness = await createDurableAcceptHarness(t);
  const invited = await harness.coordinator.invite(terms);
  const key = "33333333-3333-4333-8333-333333333333";
  await harness.coordinator.acceptInvitation(invited.responderInvitation, key);
  const claimed = harness.messages.find((message) => message.kind === "agent_v2_invitation_claimed");
  claimed.body = { ...claimed.body, claimedAtMs: String(nowMs + 99) };
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    (error) => error?.name === "V2CoordinatorError",
  );
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
});

test("a historical conflicting duplicate fails even when a newer exact duplicate exists", async (t) => {
  const harness = await createDurableAcceptHarness(t);
  const invited = await harness.coordinator.invite(terms);
  const key = "55555555-5555-4555-8555-555555555555";
  await harness.coordinator.acceptInvitation(invited.responderInvitation, key);
  const claimedIndex = harness.messages.findIndex((message) => message.kind === "agent_v2_invitation_claimed");
  const claimed = harness.messages[claimedIndex];
  harness.messages.splice(claimedIndex, 0, {
    ...claimed,
    body: { ...claimed.body, claimedAtMs: String(nowMs + 77) },
  });
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    (error) => error?.name === "V2CoordinatorError",
  );
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 2);
});

test("existing responder state must prove relay private key matches the stored sender key", async (t) => {
  let failClaimPost = true;
  let postCalls = 0;
  let advanceAfterMismatch = 0;
  const harness = await createDurableAcceptHarness(t, {
    onPostMessage: async (input) => {
      if (input.kind === "agent_v2_invitation_claimed") {
        postCalls += 1;
        if (failClaimPost) {
          failClaimPost = false;
          throw new Error("relay unavailable after state insert");
        }
      }
    },
    wrapInvitationService: (service) => ({
      ...service,
      advanceClaim: async (input) => {
        if (!failClaimPost) advanceAfterMismatch += 1;
        return service.advanceClaim(input);
      },
    }),
  });
  const invited = await harness.coordinator.invite(terms);
  const key = "66666666-6666-4666-8666-666666666666";
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    /relay unavailable/,
  );
  const responder = (await harness.stateStore.list()).find((record) => record.role === "responder");
  assert.ok(responder);
  const wrongRelayKey = generateRelayKeyPair();
  await harness.stateStore.update(responder, (current) => ({ ...current, relayEd25519Pem: wrongRelayKey.privateKeyPem }));
  advanceAfterMismatch = 0;
  await assert.rejects(
    () => harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    (error) => error?.name === "V2CoordinatorError",
  );
  assert.equal(postCalls, 1);
  assert.equal(advanceAfterMismatch, 0);
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 0);
});

test("concurrent same-key accepts return one responder access and one logical relay message", async (t) => {
  const harness = await createDurableAcceptHarness(t);
  const invited = await harness.coordinator.invite(terms);
  const key = "44444444-4444-4444-8444-444444444444";
  const [left, right] = await Promise.all([
    harness.coordinator.acceptInvitation(invited.responderInvitation, key),
    harness.coordinator.acceptInvitation(invited.responderInvitation, key),
  ]);
  assert.equal(left.responderAccess, right.responderAccess);
  assert.equal(harness.messages.filter((message) => message.kind === "agent_v2_invitation_claimed").length, 1);
});

test("two distinct role capabilities drive the complete v2 local-signing state machine", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const messages = [];
  let result = null;
  const relay = {
    fetchDiscovery: async (requested) => {
      assert.ok(requested === undefined || requested === sessionId);
      return discovery;
    },
    getMessages: async () => ({ messages }),
    postMessage: async (input) => {
      messages.push({ ...input, body: input.body, senderKey: input.senderKey });
      return { ok: true, seq: String(messages.length) };
    },
    getResult: async () => {
      if (!result) throw new Error("pending");
      return result;
    },
  };
  const addresses = {
    initiator: "0x7564105e977516c53be337314c7e53838967bdac",
    responder: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9",
  };
  const registrations = {
    [addresses.initiator]: { agentId: "9452", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9452`, registrationTx: `0x${"a".repeat(64)}`, registrationBlock: "7000" },
    [addresses.responder]: { agentId: "9453", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9453`, registrationTx: `0x${"b".repeat(64)}`, registrationBlock: "7001" },
  };
  const stateStore = createHandshakeStateStore({});
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => nowMs + 1 }),
    relay,
    stateStore,
    now: () => nowMs + 1,
    recoverEip191Address: async ({ signatureHex }) => signatureHex.endsWith("1b") ? addresses.initiator : addresses.responder,
    registrationFundingReady: async () => true,
    resolveRegistration: async ({ address }) => registrations[address] ?? null,
    advanceTransitions: async ({ descriptor }) => ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({
      blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
      digest: String(index + 1).repeat(64),
      message: { kind, sessionDigest: v2CanonicalRecord(descriptor).digest },
      onChain: { blockHeight: String(7010 + index), ledgerId: `33333333-4444-4555-8666-77777777777${index}` },
    })),
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite(terms);
  const invitationCreated = messages.find(
    (message) => message.kind === "agent_v2_invitation_created",
  );
  assert.equal(invitationCreated.role, "initiator");
  assert.deepEqual(invitationCreated.body, {
    createdAtMs: String(nowMs + 1),
    externalBusinessActionPerformed: false,
    statementDigest: v2CanonicalRecord(terms).digest,
    terms,
  });
  const initiatorStateDir = "${TMPDIR%/}/.clockchain/handshakes/" + sessionId + "/initiator";
  assert.deepEqual(invited.localPolicy, policy("initiator"));
  assert.deepEqual(invited.localAction, {
    executor: "pinned_helper",
    operations: ["init", "policy", "inspect"],
    payloadEncoding: "base64url_utf8_json",
    stateDirectoryCommand: `mkdir -p -m 700 "\${TMPDIR%/}/.clockchain/handshakes/${sessionId}/initiator"`,
    helperSteps: [
      compactHelperStep("init", "initiator", `${verifiedHelperPrefix} init --state-dir "${initiatorStateDir}"`),
      compactHelperStep("policy", "initiator", `${verifiedHelperPrefix} policy --state-dir "${initiatorStateDir}" --payload-base64url ${Buffer.from(JSON.stringify(policy("initiator")), "utf8").toString("base64url")}`),
      compactHelperStep("inspect", "initiator", `${verifiedHelperPrefix} inspect --state-dir "${initiatorStateDir}"`),
    ],
    stateDir: "new_private_absolute_state_dir",
    registrationGate: "do_not_register_until_agent_handshake_next_returns_erc8004_registration_after_join_and_funding",
    afterSuccess: "call_agent_handshake_join_with_helper_output",
  });
  const accepted = await coordinator.acceptInvitation(invited.responderInvitation);
  assert.equal(readV2RoleAccessPayload(invited.initiatorAccess).expMs, discovery.sessionDeadlineMs);
  assert.equal(readV2RoleAccessPayload(invited.responderInvitation).expMs, discovery.invitationExpiresAtMs);
  assert.equal(readV2RoleAccessPayload(accepted.responderAccess).expMs, discovery.sessionDeadlineMs);
  assert.deepEqual(accepted.localPolicy, policy("responder"));
  assert.equal(Object.hasOwn(accepted.localAction, "policyPayload"), false);
  const invitationClaimed = messages.find((message) => message.kind === "agent_v2_invitation_claimed");
  assert.equal(invitationClaimed.role, "responder");
  assert.equal(invitationClaimed.body.claimedAtMs, String(nowMs + 1));
  assert.notEqual(invited.initiatorAccess, accepted.responderAccess);
  const accesses = { initiator: invited.initiatorAccess, responder: accepted.responderAccess };
  for (const role of ["initiator", "responder"]) {
    const joinRequired = {
      externalBusinessActionPerformed: false,
      needed: "agent_handshake_join",
      nextAction: "call_agent_handshake_join_now_with_access_and_exact_init_policy_inspect_outputs",
      requiredInputs: ["access", "helperVersion", "sessionKeyAddress", "policyDigest"],
      role,
      sessionId,
      stage: "invited",
      stageMeaning: "this_role_has_not_joined",
    };
    assert.deepEqual(await coordinator.status({ access: accesses[role] }), joinRequired);
    assert.deepEqual(await coordinator.next({ access: accesses[role] }), joinRequired);
    const localPolicy = policy(role);
    const joined = await coordinator.join({ access: accesses[role], helperVersion: "2.1.7", sessionKeyAddress: addresses[role], policyDigest: v2CanonicalRecord(localPolicy).digest });
    const identityRequest = compactPayloadFrom(joined, "identity_claim");
    assert.equal(identityRequest.descriptorEnvelope, null);
    assert.equal(identityRequest.policyDigest, v2CanonicalRecord(localPolicy).digest);
    assert.equal(Object.hasOwn(joined, "hostSessionKeyCertificate"), false);
    await coordinator.submit({ access: accesses[role], policyDigest: v2CanonicalRecord(localPolicy).digest, signatureHex: `0x${"1".repeat(128)}${role === "initiator" ? "1b" : "1c"}` });
  }
  const identityMessages = messages.filter((message) => message.kind === "agent_v2_identity_claim");
  assert.equal(identityMessages.length, 2);
  assert.equal(messages.some((message) => message.kind === "agent_v2_identity_signature"), false);
  assert.deepEqual(
    identityMessages.map((message) => Object.keys(message.body).sort()),
    [["claim", "signature"], ["claim", "signature"]],
  );
  for (const role of ["initiator", "responder"]) {
    const waitingForFunding = await coordinator.next({ access: accesses[role] });
    assert.deepEqual(waitingForFunding, {
      needed: "funding_record",
      nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access",
      retryAfterMs: 3000,
      role,
      selfFundingRequired: false,
      sessionId,
      stage: "awaiting_funding",
      waitingOn: "clockchain_host",
    });
    messages.push({ kind: "agent_v2_funding_record", role: "host", body: { role, address: addresses[role] } });
    const ready = await coordinator.next({ access: accesses[role] });
    assert.equal(ready.stage, "party_ready");
    assert.equal(ready.nextAction, "call_agent_handshake_next_with_unchanged_role_access");
  }
  const proposal = await coordinator.next({ access: accesses.initiator });
  const proposalRequest = compactPayloadFrom(proposal, "proposal");
  assert.equal(proposalRequest.descriptorEnvelope, null);
  const proposalSignatureHex = `0x${"2".repeat(128)}1b`;
  const proposalEnvelope = {
    payload: JSON.parse(gunzipSync(Buffer.from(proposalRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: addresses.initiator, algorithm: "eip191", value: proposalSignatureHex },
  };
  const proposalCheckpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId, role: "initiator", artifactType: "proposal",
    artifactDigest: v2CanonicalRecord(proposalEnvelope).digest, sequence: "1", previousCheckpointDigest: null,
    issuedAtMs: String(nowMs + 1), expiresAtMs: String(nowMs + 90_000), signerAddress: addresses.initiator,
    signature: { address: addresses.initiator, algorithm: "eip191", value: `0x${"6".repeat(128)}1b` },
  };
  await assert.rejects(
    () => coordinator.submit({ access: accesses.initiator, policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: proposalSignatureHex }),
    /coordination failed safely/,
  );
  await assert.rejects(
    () => coordinator.submitCheckpoint({
      access: accesses.initiator,
      artifactSignatureHex: proposalSignatureHex,
      checkpoint: { ...proposalCheckpoint, artifactDigest: "0".repeat(64) },
    }),
    /coordination failed safely/,
  );
  const submittedProposalCheckpoint = await coordinator.submitCheckpoint({ access: accesses.initiator, artifactSignatureHex: proposalSignatureHex, checkpoint: proposalCheckpoint });
  assert.match(submittedProposalCheckpoint.checkpointDigest, /^[0-9a-f]{64}$/);
  await coordinator.submit({ access: accesses.initiator, policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: proposalSignatureHex });
  const acceptance = await coordinator.next({ access: accesses.responder });
  const acceptanceRequest = compactPayloadFrom(acceptance, "acceptance");
  assert.equal(acceptanceRequest.descriptorEnvelope, null);
  assert.deepEqual(acceptance.previousCheckpoint, proposalCheckpoint);
  const acceptanceSignatureHex = `0x${"3".repeat(128)}1c`;
  const acceptanceEnvelope = {
    payload: JSON.parse(gunzipSync(Buffer.from(acceptanceRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
    schema: "clockchain.agent-handshake-acceptance-envelope/v2",
    signature: { address: addresses.responder, algorithm: "eip191", value: acceptanceSignatureHex },
  };
  const acceptanceCheckpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId, role: "responder", artifactType: "acceptance",
    artifactDigest: v2CanonicalRecord(acceptanceEnvelope).digest, sequence: "2",
    previousCheckpointDigest: submittedProposalCheckpoint.checkpointDigest,
    issuedAtMs: String(nowMs + 1), expiresAtMs: String(nowMs + 90_000), signerAddress: addresses.responder,
    signature: { address: addresses.responder, algorithm: "eip191", value: `0x${"7".repeat(128)}1c` },
  };
  await assert.rejects(
    () => coordinator.submit({ access: accesses.responder, policyDigest: v2CanonicalRecord(policy("responder")).digest, signatureHex: acceptanceSignatureHex }),
    /coordination failed safely/,
  );
  await coordinator.submitCheckpoint({ access: accesses.responder, artifactSignatureHex: acceptanceSignatureHex, checkpoint: acceptanceCheckpoint });
  await coordinator.submit({ access: accesses.responder, policyDigest: v2CanonicalRecord(policy("responder")).digest, signatureHex: acceptanceSignatureHex });

  const checkpoints = messages.filter((message) => message.kind === "agent_v2_commitment_checkpoint");
  assert.deepEqual(checkpoints.map((message) => message.role), ["initiator", "responder"]);
  assert.deepEqual(checkpoints.map((message) => message.body.checkpoint.sequence), ["1", "2"]);

  const proposalPayload = messages.find((message) => message.kind === "agent_v2_proposal").body.proposalEnvelope.payload;
  const parties = { initiator: proposalPayload.initiator, responder: proposalPayload.responder };
  const descriptor = {
    agreementExpiresAtMs: proposalPayload.expiresAtMs,
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: "f".repeat(64),
    identityPolicy: terms.identityPolicy,
    initiator: parties.initiator,
    operatorPublicKey: hostSessionKeyCertificate.certificate.sessionPublicKey,
    protocol: "clockchain.agent-handshake/v2",
    reference: terms.reference,
    repositorySha,
    responder: parties.responder,
    schema: "clockchain.agent-handshake-descriptor/v2",
    sessionId,
    sessionOpenedAtMs: String(nowMs),
    sessionOpenedBlock: "6999",
    statementDigest: v2CanonicalRecord(terms).digest,
  };
  messages.push({ kind: "agent_v2_handshake_required", role: "host", body: { descriptorEnvelope: { descriptor, operator: {} }, sessionDigest: v2CanonicalRecord(descriptor).digest } });

  for (const role of ["initiator", "responder"]) {
    const evidence = await coordinator.next({ access: accesses[role] });
    assert.deepEqual(
      compactPayloadFrom(evidence, "evidence").descriptorEnvelope,
      { descriptor, operator: {} },
    );
    await coordinator.submit({ access: accesses[role], policyDigest: v2CanonicalRecord(policy(role)).digest, signatureHex: `0x${"4".repeat(128)}${role === "initiator" ? "1b" : "1c"}` });
  }
  result = { result: {
    anchors: ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({ blockHeight: String(7010 + index), blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`, digest: String(index + 1).repeat(64), kind, ledgerId: `33333333-4444-4555-8666-77777777777${index}` })),
    externalBusinessActionPerformed: false, hostSessionKeyCertificateDigest: "f".repeat(64), identityPolicy: terms.identityPolicy,
    issuedAtMs: String(nowMs + 5000), outcome: "VERIFIED", parties,
    policyDigests: { initiator: parties.initiator.policyDigest, responder: parties.responder.policyDigest },
    reference: terms.reference, schema: "clockchain.agent-handshake-result/v2", sessionDigest: v2CanonicalRecord(descriptor).digest,
    sessionId, statementDigest: v2CanonicalRecord(terms).digest, subjectRun: "stakeholder",
  }, signer: {}, hostSessionKeyCertificate };
  const nextCertificate = await coordinator.next({ access: accesses.initiator });
  const nextCertificatePayload = compactCertificatePayloadFrom(nextCertificate, "initiator");
  assert.deepEqual(nextCertificatePayload.certificate, result);
  const initiatorCertificate = await coordinator.getCertificate({ access: accesses.initiator });
  const responderCertificate = await coordinator.getCertificate({ access: accesses.responder });
  const initiatorCertificatePayload = compactCertificatePayloadFrom(initiatorCertificate, "initiator");
  const responderCertificatePayload = compactCertificatePayloadFrom(responderCertificate, "responder");
  assert.deepEqual(initiatorCertificatePayload.certificate, result);
  assert.deepEqual(responderCertificatePayload.certificate, result);
  const certificateRecords = await stateStore.list();
  assert.equal(certificateRecords.length, 2);
  for (const record of certificateRecords) {
    assert.equal(record.status, "active");
    assert.equal(record.data.stage, "certificate_available");
    assert.equal(record.data.certificateAvailable, true);
    assert.equal(Object.hasOwn(record.data, "certificateVerified"), false);
  }
});

test("join rejects a stale helper version before access authorization and accepts the pinned release", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const relay = {
    fetchDiscovery: async () => discovery,
    getMessages: async () => ({ messages: [] }),
    postMessage: async () => ({ ok: true, seq: "1" }),
    getResult: async () => { throw new Error("pending"); },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => nowMs + 1 }),
    relay,
    stateStore: createHandshakeStateStore({}),
    now: () => nowMs + 1,
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite(terms);
  const localPolicy = policy("initiator");
  const joinInput = {
    access: invited.initiatorAccess,
    sessionKeyAddress: "0x7564105e977516c53be337314c7e53838967bdac",
    policyDigest: v2CanonicalRecord(localPolicy).digest,
  };
  for (const stale of ["2.1.3", "2.1.4", "2.1.5", ""]) {
    await assert.rejects(
      () => coordinator.join({ ...joinInput, helperVersion: stale }),
      /coordination failed safely/,
      `helperVersion ${JSON.stringify(stale)} is rejected`,
    );
  }
  const joined = await coordinator.join({ ...joinInput, helperVersion: "2.1.7" });
  const identityRequest = compactPayloadFrom(joined, "identity_claim");
  assert.equal(identityRequest.policyDigest, joinInput.policyDigest);
});

test("fresh identity registration is returned as an executable pinned-helper action", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const messages = [];
  let fundingVisible = false;
  const address = "0x7564105e977516c53be337314c7e53838967bdac";
  const presentedAddress = "0x7564105E977516c53be337314c7e53838967bdac";
  const relay = {
    fetchDiscovery: async () => discovery,
    getMessages: async () => ({ messages }),
    postMessage: async (input) => {
      messages.push({ ...input, body: input.body, senderKey: input.senderKey });
      return { ok: true, seq: String(messages.length) };
    },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => nowMs + 1 }),
    relay,
    stateStore: createHandshakeStateStore({}),
    now: () => nowMs + 1,
    recoverEip191Address: async () => address,
    registrationFundingReady: async ({ address: requested }) => fundingVisible && requested === address,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite(terms);
  const localPolicy = policy("initiator");
  const digest = v2CanonicalRecord(localPolicy).digest;
  await coordinator.join({
    access: invited.initiatorAccess,
    helperVersion: "2.1.7",
    sessionKeyAddress: presentedAddress,
    policyDigest: digest,
  });
  await coordinator.submit({
    access: invited.initiatorAccess,
    policyDigest: digest,
    signatureHex: `0x${"1".repeat(128)}1b`,
  });
  messages.push({ kind: "agent_v2_funding_record", role: "host", body: { role: "initiator", address } });

  assert.deepEqual(await coordinator.next({ access: invited.initiatorAccess }), {
    needed: "funding_visibility",
    nextAction: "wait_for_clockchain_host_funding_visibility_then_call_agent_handshake_next_with_unchanged_role_access",
    retryAfterMs: 3000,
    role: "initiator",
    selfFundingRequired: false,
    sessionId,
    stage: "awaiting_funding_visibility",
    waitingOn: "clockchain_host",
  });
  fundingVisible = true;

  assert.deepEqual(await coordinator.next({ access: invited.initiatorAccess }), {
    needed: "erc8004_registration",
    role: "initiator",
    sessionId,
    stage: "awaiting_identity_registration",
    identityPolicy: terms.identityPolicy,
    localAction: {
      executor: "pinned_helper",
      operation: "register",
      stateDir: "reuse_exact_absolute_state_dir",
      helperStep: compactHelperStep("register", "initiator", `${verifiedHelperPrefix} register --state-dir "\${TMPDIR%/}/.clockchain/handshakes/${sessionId}/initiator"`),
      afterSuccess: "call_agent_handshake_next_with_unchanged_role_access",
    },
  });
});

async function createBoundedWaitHarness(overrides = {}) {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const addresses = {
    initiator: "0x7564105e977516c53be337314c7e53838967bdac",
    responder: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9",
  };
  const registrations = {
    [addresses.initiator]: { agentId: "9452", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9452`, registrationTx: `0x${"a".repeat(64)}`, registrationBlock: "7000" },
    [addresses.responder]: { agentId: "9453", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9453`, registrationTx: `0x${"b".repeat(64)}`, registrationBlock: "7001" },
  };
  const messages = [];
  const messageCalls = [];
  let clock = overrides.clock ?? nowMs + 1;
  let result = overrides.result ?? null;
  let registrationAvailable = overrides.registrationAvailable ?? true;
  const harness = { onWaitPoll: overrides.onWaitPoll };
  const relay = {
    fetchDiscovery: async () => discovery,
    getMessages: async ({ after = "0", waitMs = 0 } = {}) => {
      messageCalls.push({ after, waitMs });
      if (waitMs > 0) {
        if (harness.onWaitPoll) await harness.onWaitPoll({ clock, messages, poll: messageCalls.filter((call) => call.waitMs > 0).length });
        if (overrides.advanceClockOnWaitPoll) clock += waitMs;
      }
      const page = messages.filter((message) => BigInt(message.seq ?? "0") > BigInt(after));
      const response = { messages: page };
      if (messages.length) response.highestSeq = messages.at(-1).seq;
      return response;
    },
    postMessage: async (input) => {
      messages.push({ seq: String(messages.length + 1), body: input.body, kind: input.kind, role: input.role, senderKey: input.senderKey, sessionId: input.sessionId });
      return { ok: true, seq: String(messages.length) };
    },
    getResult: async () => {
      if (!result) throw new Error("pending");
      return result;
    },
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => clock }),
    relay,
    stateStore: createHandshakeStateStore({}),
    now: () => clock,
    recoverEip191Address: async ({ signatureHex }) => signatureHex.endsWith("1b") ? addresses.initiator : addresses.responder,
    registrationFundingReady: async () => (overrides.registrationFundingReady ? overrides.registrationFundingReady() : true),
    resolveRegistration: async ({ address }) => {
      if (overrides.resolveRegistration) return overrides.resolveRegistration({ address });
      return registrationAvailable ? registrations[address] ?? null : null;
    },
    advanceTransitions: async ({ descriptor }) => (overrides.advanceTransitions ? overrides.advanceTransitions(descriptor) : []),
    nextWaitDefaultMs: overrides.nextWaitDefaultMs,
    verifiedHelperPrefix,
  });
  const invited = await coordinator.invite(terms);
  const accepted = await coordinator.acceptInvitation(invited.responderInvitation);
  Object.assign(harness, {
    accesses: { initiator: invited.initiatorAccess, responder: accepted.responderAccess },
    addresses,
    coordinator,
    fund: (role) => messages.push({ seq: String(messages.length + 1), kind: "agent_v2_funding_record", role: "host", body: { role, address: addresses[role] }, sessionId }),
    join: async (role) => {
      const localPolicy = policy(role);
      await coordinator.join({ access: harness.accesses[role], helperVersion: "2.1.7", sessionKeyAddress: addresses[role], policyDigest: v2CanonicalRecord(localPolicy).digest });
      await coordinator.submit({ access: harness.accesses[role], policyDigest: v2CanonicalRecord(localPolicy).digest, signatureHex: `0x${"1".repeat(128)}${role === "initiator" ? "1b" : "1c"}` });
    },
    messageCalls,
    messages,
    registrations,
    setClock: (value) => { clock = value; },
    setResult: (value) => { result = value; },
  });
  harness.waitPolls = () => messageCalls.filter((call) => call.waitMs > 0);
  return harness;
}

test("agent_handshake_next bridges funding visibility to the registration local action in one call", async () => {
  let fundingReady = false;
  const harness = await createBoundedWaitHarness({
    advanceClockOnWaitPoll: true,
    registrationAvailable: false,
    registrationFundingReady: () => fundingReady,
    onWaitPoll: () => { fundingReady = true; },
  });
  await harness.join("initiator");
  harness.fund("initiator");
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 10_000 });
  assert.equal(outcome.stage, "awaiting_identity_registration");
  assert.equal(outcome.needed, "erc8004_registration");
  assert.equal(outcome.localAction.executor, "pinned_helper");
  assert.equal(outcome.localAction.operation, "register");
  assert.deepEqual(harness.waitPolls().map((poll) => poll.waitMs), [2000]);
});

test("agent_handshake_next bridges counterpart and proposal arrival to sign_acceptance", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  await harness.join("responder");
  harness.fund("initiator");
  harness.fund("responder");
  assert.equal((await harness.coordinator.next({ access: harness.accesses.responder })).stage, "party_ready");
  harness.onWaitPoll = async ({ poll }) => {
    if (poll === 1) {
      assert.equal((await harness.coordinator.next({ access: harness.accesses.initiator })).stage, "party_ready");
      return;
    }
    const proposal = await harness.coordinator.next({ access: harness.accesses.initiator });
    assert.equal(proposal.stage, "sign_proposal");
    const proposalRequest = compactPayloadFrom(proposal, "proposal");
    const proposalEnvelope = {
      payload: JSON.parse(gunzipSync(Buffer.from(proposalRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
      schema: "clockchain.agent-handshake-proposal-envelope/v2",
      signature: { address: harness.addresses.initiator, algorithm: "eip191", value: `0x${"2".repeat(128)}1b` },
    };
    harness.messages.push({ seq: String(harness.messages.length + 1), kind: "agent_v2_proposal", role: "initiator", body: { proposalEnvelope }, sessionId });
  };
  const acceptance = await harness.coordinator.next({ access: harness.accesses.responder, waitMs: 10_000 });
  assert.equal(acceptance.stage, "sign_acceptance");
  assert.equal(acceptance.localAction.operation, "sign");
  assert.deepEqual(harness.waitPolls().map((poll) => poll.waitMs), [2000, 2000]);
});

test("agent_handshake_next returns dependency waits with retryAfterMs and nextAction once the wait budget expires", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 4_500 });
  assert.equal(outcome.stage, "awaiting_funding");
  assert.equal(outcome.needed, "funding_record");
  assert.equal(outcome.retryAfterMs, 3000);
  assert.equal(outcome.nextAction, "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access");
  assert.deepEqual(harness.waitPolls().map((poll) => poll.waitMs), [2000, 2000, 500]);
});

test("agent_handshake_next clamps the wait to the remaining session deadline", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  // Move the injected clock to 150ms before the session deadline; role access
  // (expMs == sessionDeadlineMs) is still valid, but the wait must stop there.
  harness.setClock(Number(discovery.sessionDeadlineMs) - 150);
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 15_000 });
  assert.equal(outcome.stage, "awaiting_funding");
  assert.equal(outcome.retryAfterMs, 3000);
  assert.equal(outcome.nextAction, "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access");
  assert.deepEqual(harness.waitPolls().map((poll) => poll.waitMs), [150]);
});

test("agent_handshake_next returns actionable and terminal outcomes without waiting", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  const joinRequired = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 15_000 });
  assert.equal(joinRequired.needed, "agent_handshake_join");
  assert.equal(harness.waitPolls().length, 0);

  await harness.join("initiator");
  await harness.join("responder");
  harness.fund("initiator");
  harness.fund("responder");
  assert.equal((await harness.coordinator.next({ access: harness.accesses.initiator })).stage, "party_ready");
  assert.equal((await harness.coordinator.next({ access: harness.accesses.responder })).stage, "party_ready");
  const proposal = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 15_000 });
  assert.equal(proposal.stage, "sign_proposal");
  assert.equal(proposal.localAction.operation, "sign");
  assert.equal(harness.waitPolls().length, 0);
  const pending = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 15_000 });
  assert.equal(pending.stage, "sign_proposal");
  assert.equal(pending.localAction.operation, "sign");
  assert.equal(harness.waitPolls().length, 0);
});

test("agent_handshake_next returns the registration local action and terminal errors without waiting", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true, registrationAvailable: false });
  await harness.join("initiator");
  harness.fund("initiator");
  const registration = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 15_000 });
  assert.equal(registration.stage, "awaiting_identity_registration");
  assert.equal(registration.localAction.operation, "register");
  assert.equal(harness.waitPolls().length, 0);

  const broken = await createBoundedWaitHarness({
    advanceClockOnWaitPoll: true,
    resolveRegistration: () => { throw new Error("rpc unavailable"); },
  });
  await broken.join("initiator");
  broken.fund("initiator");
  await assert.rejects(
    () => broken.coordinator.next({ access: broken.accesses.initiator, waitMs: 15_000 }),
    /rpc unavailable|coordination failed safely/,
  );
  assert.equal(broken.waitPolls().length, 0);
});

test("agent_handshake_next applies the bounded default wait when waitMs is omitted", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator });
  assert.equal(outcome.stage, "awaiting_funding");
  assert.equal(outcome.retryAfterMs, 3000);
  // Default budget is 12s in 2s slices.
  assert.deepEqual(harness.waitPolls().map((poll) => poll.waitMs), [2000, 2000, 2000, 2000, 2000, 2000]);
});

test("agent_handshake_next rejects malformed waitMs and clamps oversized waitMs", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  await assert.rejects(() => harness.coordinator.next({ access: harness.accesses.initiator, waitMs: -1 }), /coordination failed safely/);
  await assert.rejects(() => harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 1.5 }), /coordination failed safely/);
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 60_000 });
  assert.equal(outcome.stage, "awaiting_funding");
  // waitMs is clamped to the 15s maximum; each poll slice is at most 2s.
  assert.ok(harness.waitPolls().length <= 8);
  assert.ok(harness.waitPolls().every((poll) => poll.waitMs <= 2000 && poll.waitMs > 0));
});

test("agent_handshake_next long-polls only for relay messages after the observed cursor", async () => {
  const harness = await createBoundedWaitHarness({ advanceClockOnWaitPoll: true });
  await harness.join("initiator");
  const outcome = await harness.coordinator.next({ access: harness.accesses.initiator, waitMs: 4_500 });
  assert.equal(outcome.stage, "awaiting_funding");
  const polls = harness.waitPolls();
  assert.ok(polls.length >= 2);
  const backlogSeq = String(harness.messages.length);
  assert.equal(polls[0].after, backlogSeq);
  assert.ok(polls.every((poll) => poll.after === backlogSeq));
});

test("agent_handshake_next waits across certificate availability in one call", async () => {
  const harness = await createBoundedWaitHarness({
    advanceClockOnWaitPoll: true,
    advanceTransitions: (descriptor) => ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({
      blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
      digest: String(index + 1).repeat(64),
      message: { kind, sessionDigest: v2CanonicalRecord(descriptor).digest },
      onChain: { blockHeight: String(7010 + index), ledgerId: `33333333-4444-4555-8666-77777777777${index}` },
    })),
  });
  const { accesses, addresses, coordinator, messages } = harness;
  await harness.join("initiator");
  await harness.join("responder");
  harness.fund("initiator");
  harness.fund("responder");
  await coordinator.next({ access: accesses.initiator });
  await coordinator.next({ access: accesses.responder });
  const proposal = await coordinator.next({ access: accesses.initiator });
  const proposalRequest = compactPayloadFrom(proposal, "proposal");
  const proposalSignatureHex = `0x${"2".repeat(128)}1b`;
  const proposalEnvelope = {
    payload: JSON.parse(gunzipSync(Buffer.from(proposalRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: addresses.initiator, algorithm: "eip191", value: proposalSignatureHex },
  };
  const proposalCheckpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId, role: "initiator", artifactType: "proposal",
    artifactDigest: v2CanonicalRecord(proposalEnvelope).digest, sequence: "1", previousCheckpointDigest: null,
    issuedAtMs: String(nowMs + 1), expiresAtMs: String(nowMs + 90_000), signerAddress: addresses.initiator,
    signature: { address: addresses.initiator, algorithm: "eip191", value: `0x${"6".repeat(128)}1b` },
  };
  const submittedProposalCheckpoint = await coordinator.submitCheckpoint({ access: accesses.initiator, artifactSignatureHex: proposalSignatureHex, checkpoint: proposalCheckpoint });
  await coordinator.submit({ access: accesses.initiator, policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: proposalSignatureHex });
  const acceptance = await coordinator.next({ access: accesses.responder });
  const acceptanceRequest = compactPayloadFrom(acceptance, "acceptance");
  const acceptanceSignatureHex = `0x${"3".repeat(128)}1c`;
  const acceptanceEnvelope = {
    payload: JSON.parse(gunzipSync(Buffer.from(acceptanceRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
    schema: "clockchain.agent-handshake-acceptance-envelope/v2",
    signature: { address: addresses.responder, algorithm: "eip191", value: acceptanceSignatureHex },
  };
  const acceptanceCheckpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId, role: "responder", artifactType: "acceptance",
    artifactDigest: v2CanonicalRecord(acceptanceEnvelope).digest, sequence: "2",
    previousCheckpointDigest: submittedProposalCheckpoint.checkpointDigest,
    issuedAtMs: String(nowMs + 1), expiresAtMs: String(nowMs + 90_000), signerAddress: addresses.responder,
    signature: { address: addresses.responder, algorithm: "eip191", value: `0x${"7".repeat(128)}1c` },
  };
  await coordinator.submitCheckpoint({ access: accesses.responder, artifactSignatureHex: acceptanceSignatureHex, checkpoint: acceptanceCheckpoint });
  await coordinator.submit({ access: accesses.responder, policyDigest: v2CanonicalRecord(policy("responder")).digest, signatureHex: acceptanceSignatureHex });
  const proposalPayload = messages.find((message) => message.kind === "agent_v2_proposal").body.proposalEnvelope.payload;
  const parties = { initiator: proposalPayload.initiator, responder: proposalPayload.responder };
  const descriptor = {
    agreementExpiresAtMs: proposalPayload.expiresAtMs,
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: "f".repeat(64),
    identityPolicy: terms.identityPolicy,
    initiator: parties.initiator,
    operatorPublicKey: hostSessionKeyCertificate.certificate.sessionPublicKey,
    protocol: "clockchain.agent-handshake/v2",
    reference: terms.reference,
    repositorySha,
    responder: parties.responder,
    schema: "clockchain.agent-handshake-descriptor/v2",
    sessionId,
    sessionOpenedAtMs: String(nowMs),
    sessionOpenedBlock: "6999",
    statementDigest: v2CanonicalRecord(terms).digest,
  };
  messages.push({ seq: String(messages.length + 1), kind: "agent_v2_handshake_required", role: "host", body: { descriptorEnvelope: { descriptor, operator: {} }, sessionDigest: v2CanonicalRecord(descriptor).digest }, sessionId });
  const evidence = await coordinator.next({ access: accesses.initiator });
  assert.equal(evidence.stage, "sign_evidence");
  await coordinator.submit({ access: accesses.initiator, policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: `0x${"4".repeat(128)}1b` });
  harness.onWaitPoll = () => {
    harness.setResult({ result: {
      anchors: ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({ blockHeight: String(7010 + index), blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`, digest: String(index + 1).repeat(64), kind, ledgerId: `33333333-4444-4555-8666-77777777777${index}` })),
      externalBusinessActionPerformed: false, hostSessionKeyCertificateDigest: "f".repeat(64), identityPolicy: terms.identityPolicy,
      issuedAtMs: String(nowMs + 5000), outcome: "VERIFIED", parties,
      policyDigests: { initiator: parties.initiator.policyDigest, responder: parties.responder.policyDigest },
      reference: terms.reference, schema: "clockchain.agent-handshake-result/v2", sessionDigest: v2CanonicalRecord(descriptor).digest,
      sessionId, statementDigest: v2CanonicalRecord(terms).digest, subjectRun: "stakeholder",
    }, signer: {}, hostSessionKeyCertificate });
  };
  const certificate = await coordinator.next({ access: accesses.initiator, waitMs: 10_000 });
  assert.equal(certificate.certificateSummary.schema, "clockchain.agent-handshake-certificate-summary/v1");
  assert.equal(certificate.certificateSummary.outcome, "VERIFIED");
  assert.equal(certificate.localAction.operation, "verify-certificate");
  assert.ok(harness.waitPolls().length >= 1);
});
