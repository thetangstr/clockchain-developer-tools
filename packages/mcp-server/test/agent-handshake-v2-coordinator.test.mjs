import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import test from "node:test";

import { createHandshakeStateStore, __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { createV2InvitationService, createV2InvitationStore } from "../dist/agent-handshake/v2/invitation-store.js";
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
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
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
    "operation", "role", "sessionId", "approvalCommand", "commandLength", "commandSha256", "shellCommand",
  ]);
  const command = response.localAction.helperStep.shellCommand;
  assert.equal(response.localAction.helperStep.commandLength, Buffer.byteLength(command));
  assert.equal(response.localAction.helperStep.commandSha256, createHash("sha256").update(command).digest("hex"));
  assert.equal(response.localAction.helperStep.approvalCommand, `clockchain-agent-authorize ${response.localAction.helperStep.commandSha256}`);
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
  assert.equal(response.certificateSummary.schema, "clockchain.agent-handshake-certificate-summary/v1");
  assert.equal(response.certificateSummary.outcome, "VERIFIED");
  assert.equal(response.certificateSummary.role, role);
  assert.equal(response.certificateSummary.sessionId, sessionId);
  assert.match(response.certificateSummary.resultDigest, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(response.localAction.helperStep), [
    "operation", "role", "sessionId", "approvalCommand", "commandLength", "commandSha256", "shellCommand",
  ]);
  const command = response.localAction.helperStep.shellCommand;
  assert.equal(response.localAction.helperStep.operation, "verify-certificate");
  assert.equal(response.localAction.helperStep.role, role);
  assert.equal(response.localAction.helperStep.sessionId, sessionId);
  assert.equal(response.localAction.helperStep.commandLength, Buffer.byteLength(command));
  assert.equal(response.localAction.helperStep.commandSha256, createHash("sha256").update(command).digest("hex"));
  assert.equal(response.localAction.helperStep.approvalCommand, `clockchain-agent-authorize ${response.localAction.helperStep.commandSha256}`);
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
    stateStore: createHandshakeStateStore({}),
    now: () => nowMs + 120000,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    verifiedHelperPrefix,
  });

  await assert.rejects(
    () => coordinator.invite(terms),
    (error) => error?.name === "V2TransientCoordinatorError",
  );
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
    resolveRegistration: async ({ address }) => registrations[address] ?? null,
    advanceTransitions: async ({ descriptor }) => ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({
      blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
      digest: String(index + 1).repeat(64),
      message: { kind, sessionDigest: v2CanonicalRecord(descriptor).digest },
      onChain: { blockHeight: String(7010 + index), ledgerId: `33333333-4444-4555-8666-77777777777${index}` },
    })),
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite(terms);
  const initiatorStateDir = `$TMPDIR/.clockchain/handshakes/${sessionId}/initiator`;
  assert.deepEqual(invited.localPolicy, policy("initiator"));
  assert.deepEqual(invited.localAction, {
    executor: "pinned_helper",
    operations: ["init", "policy", "inspect"],
    payloadEncoding: "base64url_utf8_json",
    stateDirectoryCommand: `mkdir -p -m 700 "$TMPDIR/.clockchain/handshakes/${sessionId}/initiator"`,
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
  assert.deepEqual(accepted.localPolicy, policy("responder"));
  assert.equal(Object.hasOwn(accepted.localAction, "policyPayload"), false);
  const invitationClaimed = messages.find((message) => message.kind === "agent_v2_invitation_claimed");
  assert.equal(invitationClaimed.role, "responder");
  assert.equal(invitationClaimed.body.claimedAtMs, String(nowMs + 1));
  assert.notEqual(invited.initiatorAccess, accepted.responderAccess);
  const accesses = { initiator: invited.initiatorAccess, responder: accepted.responderAccess };
  for (const role of ["initiator", "responder"]) {
    const localPolicy = policy(role);
    const joined = await coordinator.join({ access: accesses[role], helperVersion: "2.1.2", sessionKeyAddress: addresses[role], policyDigest: v2CanonicalRecord(localPolicy).digest });
    const identityRequest = compactPayloadFrom(joined, "identity_claim");
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
    messages.push({ kind: "agent_v2_funding_record", role: "host", body: { role, address: addresses[role] } });
    const ready = await coordinator.next({ access: accesses[role] });
    assert.equal(ready.stage, "party_ready");
    assert.equal(ready.nextAction, "call_agent_handshake_next_with_unchanged_role_access");
  }
  const proposal = await coordinator.next({ access: accesses.initiator });
  compactPayloadFrom(proposal, "proposal");
  await coordinator.submit({ access: accesses.initiator, policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: `0x${"2".repeat(128)}1b` });
  const acceptance = await coordinator.next({ access: accesses.responder });
  compactPayloadFrom(acceptance, "acceptance");
  await coordinator.submit({ access: accesses.responder, policyDigest: v2CanonicalRecord(policy("responder")).digest, signatureHex: `0x${"3".repeat(128)}1c` });

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
    compactPayloadFrom(evidence, "evidence");
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

test("fresh identity registration is returned as an executable pinned-helper action", async () => {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const messages = [];
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
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    verifiedHelperPrefix,
  });

  const invited = await coordinator.invite(terms);
  const localPolicy = policy("initiator");
  const digest = v2CanonicalRecord(localPolicy).digest;
  await coordinator.join({
    access: invited.initiatorAccess,
    helperVersion: "2.1.2",
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
    needed: "erc8004_registration",
    role: "initiator",
    sessionId,
    stage: "awaiting_identity_registration",
    identityPolicy: terms.identityPolicy,
    localAction: {
      executor: "pinned_helper",
      operation: "register",
      stateDir: "reuse_exact_absolute_state_dir",
      helperStep: compactHelperStep("register", "initiator", `${verifiedHelperPrefix} register --state-dir "$TMPDIR/.clockchain/handshakes/${sessionId}/initiator"`),
      afterSuccess: "call_agent_handshake_next_with_unchanged_role_access",
    },
  });
});
