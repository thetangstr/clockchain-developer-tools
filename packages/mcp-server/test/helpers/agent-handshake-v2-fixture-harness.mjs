// A v2 coordinator harness built on the reviewed canonical fixture
// (fixtures/agent-handshake-v2-canonical.json, a copy of the handshake repo's
// fixture): its session, terms, parties, and signed proposal and
// acceptance. Used by the H-REQ-02 and H-REQ-07 suites.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

import { createHandshakeRelayClient } from "../../dist/handshake/relay.js";
import { createHandshakeStateStore, __resetHandshakeStateStore } from "../../dist/handshake/state.js";
import { createV2InvitationService, createV2InvitationStore } from "../../dist/agent-handshake/v2/invitation-store.js";
import { createV2Coordinator } from "../../dist/agent-handshake/v2/coordinator.js";
import { V2_HELPER_VERSION } from "../../dist/agent-handshake/v2/instructions.js";
import { v2CanonicalRecord } from "../../dist/agent-handshake/v2/protocol.js";

export const fixture = JSON.parse(readFileSync(new URL("../fixtures/agent-handshake-v2-canonical.json", import.meta.url), "utf8"));
export const F = fixture.objects;
export const SESSION_ID = F.proposalEnvelope.payload.sessionId;
export const REPOSITORY_SHA = F.proposalEnvelope.payload.repositorySha;
export const TERMS = F.terms;
export const OPENED_MS = 1786337000000;
export const DEADLINE_MS = 1786337600000;
export const PROPOSAL_ISSUED_MS = Number(F.proposalEnvelope.payload.issuedAtMs);
export const PROPOSAL_EXPIRES_MS = Number(F.proposalEnvelope.payload.expiresAtMs);
export const ACCEPT_AT_MS = Number(F.acceptanceEnvelope.payload.issuedAtMs);
export const ADDRESSES = Object.freeze({
  initiator: F.parties.initiator.sessionKeyAddress,
  responder: F.parties.responder.sessionKeyAddress,
});
// Recovery result for any signature the harness has not been told about: a
// signature over other bytes recovers to an unrelated address.
export const OTHER_ADDRESS = "0x" + "9".repeat(40);
// The released helper's signing-request/v2 key set, in its order
// (REQUEST_KEYS in src/agent-cli/signing-request.mjs of the handshake repo).
export const HELPER_V2_REQUEST_KEYS = Object.freeze([
  "schema", "helperVersion", "operation", "role", "sessionId", "repositorySha",
  "sessionDeadlineMs", "hostSessionKeyCertificate", "terms", "policyDigest",
  "previousCheckpointDigest", "descriptorEnvelope", "proposalEnvelope",
  "bytesGzipBase64Url", "bytesSha256", "externalBusinessActionPerformed",
]);
export const HOST_SESSION_KEY_CERTIFICATE = Object.freeze({
  certificate: {
    schema: "clockchain.host-session-key/v1", rootKid: "root-2026-08", sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA, sessionPublicKey: "ore80hj1AhLMNPybJXCL6XHyJ9OfmaYSXc4SA8Sk2Pw=",
    validFromMs: String(OPENED_MS), validUntilMs: String(DEADLINE_MS),
  },
  root: { algorithm: "ed25519", keyId: "root-2026-08", publicKey: "6Xgu+IYxQBDx8adVlHHWf9AUYoeo+eqWr8eVQqXrY0Y=", signature: "a".repeat(88) },
});
export const DISCOVERY = Object.freeze({
  schema: "clockchain.agent-handshake-discovery/v2",
  protocol: "clockchain.agent-handshake/v2",
  sessionId: SESSION_ID,
  repositorySha: REPOSITORY_SHA,
  kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git",
  relayUrl: "https://relay.example",
  createdAtMs: String(OPENED_MS),
  invitationExpiresAtMs: String(OPENED_MS + 120_000),
  sessionDeadlineMs: String(DEADLINE_MS),
  sessionOpenedBlock: "6999",
  hostSessionKeyCertificate: HOST_SESSION_KEY_CERTIFICATE,
  terms: TERMS,
  externalBusinessActionPerformed: false,
});

// Synthetic signatures for the test keys: `n` picks the artifact, the suffix
// the role. The harness recovers these to their role's address over any bytes.
export function sig(n, role) {
  return `0x${String(n).repeat(128)}${role === "initiator" ? "1b" : "1c"}`;
}
const SYNTHETIC = [1, 2, 3, 4, 6, 7];

export function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function signingRequestOf(response) {
  const match = response.localAction.helperStep.shellCommand.match(/--payload-base64url\s+([A-Za-z0-9_-]+)$/);
  if (!match) throw new Error("no signing request in the response");
  return JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
}

export function signedBytesOf(request) {
  return gunzipSync(Buffer.from(request.bytesGzipBase64Url, "base64url"));
}

export function proposalCheckpointFor(envelope) {
  return {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId: SESSION_ID, role: "initiator", artifactType: "proposal",
    artifactDigest: v2CanonicalRecord(envelope).digest, sequence: "1", previousCheckpointDigest: null,
    issuedAtMs: envelope.payload.issuedAtMs, expiresAtMs: envelope.payload.expiresAtMs, signerAddress: ADDRESSES.initiator,
    signature: { address: ADDRESSES.initiator, algorithm: "eip191", value: sig(6, "initiator") },
  };
}

// With `realRecover`, every signature that is not one of the synthetic test
// signatures is recovered by that function (a real EIP-191 recovery), and the
// recorded known-answer pairs are not consulted.
function createRecoverOracle(hooks, realRecover) {
  const exactPairs = new Map([
    [`${fixture.canonical.proposal.bytesHex}|${F.proposalEnvelope.signature.value}`, ADDRESSES.initiator],
    [`${fixture.canonical.acceptance.bytesHex}|${F.acceptanceEnvelope.signature.value}`, ADDRESSES.responder],
  ]);
  const synthetic = new Map();
  for (const role of ["initiator", "responder"]) for (const n of SYNTHETIC) synthetic.set(sig(n, role), ADDRESSES[role]);
  const calls = [];
  return {
    calls,
    // Record that `address` signed exactly these payload bytes with this signature.
    signs(payload, signatureHex, address) {
      exactPairs.set(`${v2CanonicalRecord(payload).bytesHex}|${signatureHex}`, address);
    },
    async recover({ bytes, signatureHex }) {
      calls.push({ bytesHex: bytes.toString("hex"), signatureHex });
      if (hooks.onRecover) await hooks.onRecover({ bytes, signatureHex });
      if (realRecover) return synthetic.get(signatureHex) ?? realRecover({ bytes, signatureHex });
      return exactPairs.get(`${bytes.toString("hex")}|${signatureHex}`) ?? synthetic.get(signatureHex) ?? OTHER_ADDRESS;
    },
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// Points at which a test can run code while the coordinator awaits that step,
// by setting hooks[point]:
//   onRecover          signer recovery
//   onStateRead        a state-store read
//   onRelayRead        a relay message read by the coordinator
//   onRelayClientRead  the relay client's own sequence read before it posts
//                      (with `productionRelayClient`)
//   onRelayPost        each post attempt through the relay client (with
//                      `productionRelayClient`); returning "conflict" answers
//                      that attempt with a sequence conflict.
//   onStateUpdate      inside a state write, before its change is computed
//                      (synchronous: it adds no await to the write).
async function reach(hooks, point, ...args) {
  return hooks[point] ? hooks[point](...args) : undefined;
}

// The three anchored transitions the harness's ledger stand-in reports for a
// descriptor (the default `advanceTransitions`).
export function fixtureTransitions(descriptor) {
  return ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({
    blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
    digest: String(index + 1).repeat(64),
    message: { kind, sessionDigest: v2CanonicalRecord(descriptor).digest },
    onChain: { blockHeight: String(7010 + index), ledgerId: `33333333-4444-4555-8666-77777777777${index}` },
  }));
}

// With `productionRelayClient`, every relay post goes through the production
// relay client (src/handshake/relay.ts) over an in-memory HTTP stand-in for the
// relay; otherwise posts are appended directly. Either way each send is logged
// in `sends` with the harness clock at the moment it was sent.
// With `helperVersion`, the coordinator is configured with that pinned helper
// version (it selects the signing-request format) and both roles join with
// it; without it, the coordinator's default applies and roles join with
// V2_HELPER_VERSION.
// With `advanceTransitions`, the coordinator anchors through that function
// instead of the default stand-in (fixtureTransitions).
export async function createFixtureHarness(options = {}) {
  __resetHandshakeStateStore();
  const joinHelperVersion = options.helperVersion ?? V2_HELPER_VERSION;
  let clock = OPENED_MS + 1;
  const messages = [];
  const sends = [];
  const hooks = {};
  const oracle = createRecoverOracle(hooks, options.realRecover);
  const registrations = {
    [ADDRESSES.initiator]: F.parties.initiator.erc8004,
    [ADDRESSES.responder]: F.parties.responder.erc8004,
  };
  const append = (input) => {
    messages.push({ seq: String(messages.length + 1), body: clone(input.body), kind: input.kind, role: input.role, senderKey: input.senderKey, sessionId: input.sessionId });
    return { ok: true, seq: String(messages.length) };
  };
  const relay = {
    fetchDiscovery: async () => DISCOVERY,
    getMessages: async ({ after = "0" } = {}) => {
      await reach(hooks, "onRelayRead");
      const page = messages.filter((message) => BigInt(message.seq) > BigInt(after));
      return messages.length ? { highestSeq: messages.at(-1).seq, messages: page } : { messages: page };
    },
    postMessage: async (input) => {
      sends.push({ kind: input.kind, role: input.role, atMs: clock });
      return append(input);
    },
    getResult: async () => { throw new Error("pending"); },
  };
  if (options.productionRelayClient) {
    const client = createHandshakeRelayClient({
      relayUrl: DISCOVERY.relayUrl,
      now: () => clock,
      fetch: async (_url, init = {}) => {
        if ((init.method ?? "GET") === "GET") {
          await reach(hooks, "onRelayClientRead");
          return jsonResponse({ ok: true, messages: [] });
        }
        const envelope = JSON.parse(init.body);
        sends.push({ kind: envelope.kind, role: envelope.role, atMs: clock });
        if (await reach(hooks, "onRelayPost", envelope) === "conflict") {
          return jsonResponse({ ok: false, error: "SEQ_CONFLICT", detail: { expectedSeq: String(BigInt(envelope.seq) + 1n) } }, 409);
        }
        return jsonResponse(append(envelope));
      },
    });
    relay.postMessage = client.postMessage;
  }
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const baseStore = createHandshakeStateStore({});
  const stateStore = {
    get: async (keyValue) => {
      const record = await baseStore.get(keyValue);
      await reach(hooks, "onStateRead");
      return record;
    },
    put: (keyValue, record) => baseStore.put(keyValue, record),
    list: () => baseStore.list(),
    update: (keyValue, mutate) => baseStore.update(keyValue, (value) => {
      hooks.onStateUpdate?.(value);
      return mutate(value);
    }),
  };
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => clock }),
    relay,
    stateStore,
    now: () => clock,
    recoverEip191Address: oracle.recover,
    registrationFundingReady: async () => true,
    resolveRegistration: async ({ address }) => registrations[address] ?? null,
    advanceTransitions: options.advanceTransitions ?? (async ({ descriptor }) => fixtureTransitions(descriptor)),
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix: "node --verified-helper",
    ...(options.helperVersion === undefined ? {} : { helperVersion: options.helperVersion }),
  });
  const invited = await coordinator.invite(TERMS);
  const accepted = await coordinator.acceptInvitation(invited.responderInvitation);
  const accesses = { initiator: invited.initiatorAccess, responder: accepted.responderAccess };
  const harness = {
    accesses,
    coordinator,
    hooks,
    messages,
    sends,
    oracle,
    stateStore,
    now: () => clock,
    setClock(value) { clock = value; },
    // Runs `effect` once, at the first `point` the coordinator reaches after
    // signer recovery; its return value is that point's answer.
    afterRecovery(point, effect) {
      hooks.onRecover = () => {
        delete hooks.onRecover;
        hooks[point] = (...args) => {
          delete hooks[point];
          return effect(...args);
        };
      };
    },
    push(kind, role, body) {
      messages.push({ seq: String(messages.length + 1), kind, role, body: clone(body), senderKey: "test-sender", sessionId: SESSION_ID });
    },
    posted(kind, role) {
      return messages.filter((message) => message.kind === kind && (role === undefined || message.role === role));
    },
    async record(role) {
      return (await stateStore.list()).find((entry) => entry.role === role);
    },
    async join(role) {
      return coordinator.join({ access: accesses[role], helperVersion: joinHelperVersion, sessionKeyAddress: ADDRESSES[role], policyDigest: F.parties[role].policyDigest });
    },
    async submitIdentity(role) {
      return coordinator.submit({ access: accesses[role], policyDigest: F.parties[role].policyDigest, signatureHex: sig(1, role) });
    },
    // Both roles joined, identity-claimed, funded and party_ready.
    async ready() {
      for (const role of ["initiator", "responder"]) {
        await harness.join(role);
        await harness.submitIdentity(role);
      }
      for (const role of ["initiator", "responder"]) {
        harness.push("agent_v2_funding_record", "host", { role, address: ADDRESSES[role] });
        const outcome = await coordinator.next({ access: accesses[role] });
        if (outcome.stage !== "party_ready") throw new Error(`expected party_ready for ${role}, got ${outcome.stage}`);
      }
    },
    // What the initiator's coordinator leaves on the relay once its proposal is released.
    publishProposal(envelope) {
      harness.push("agent_v2_commitment_checkpoint", "initiator", { checkpoint: proposalCheckpointFor(envelope) });
      harness.push("agent_v2_proposal", "initiator", { proposalEnvelope: envelope });
    },
    async submitAcceptance(acceptanceRequest) {
      await harness.checkpointAcceptance(acceptanceRequest);
      return harness.submitAcceptanceSignature();
    },
    submitAcceptanceSignature() {
      return coordinator.submit({ access: accesses.responder, policyDigest: F.parties.responder.policyDigest, signatureHex: sig(3, "responder") });
    },
    async checkpointAcceptance(acceptanceRequest) {
      const payload = JSON.parse(signedBytesOf(acceptanceRequest).toString("utf8"));
      const envelope = {
        payload,
        schema: "clockchain.agent-handshake-acceptance-envelope/v2",
        signature: { address: ADDRESSES.responder, algorithm: "eip191", value: sig(3, "responder") },
      };
      await coordinator.submitCheckpoint({
        access: accesses.responder,
        artifactSignatureHex: sig(3, "responder"),
        checkpoint: {
          schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
          protocol: "clockchain.agent-handshake/v2", sessionId: SESSION_ID, role: "responder", artifactType: "acceptance",
          artifactDigest: v2CanonicalRecord(envelope).digest, sequence: "2",
          previousCheckpointDigest: acceptanceRequest.previousCheckpointDigest,
          issuedAtMs: String(clock), expiresAtMs: payload.expiresAtMs, signerAddress: ADDRESSES.responder,
          signature: { address: ADDRESSES.responder, algorithm: "eip191", value: sig(7, "responder") },
        },
      });
    },
    // The host's descriptor for the agreement on the relay.
    publishDescriptor() {
      const proposal = harness.posted("agent_v2_proposal", "initiator").at(-1).body.proposalEnvelope.payload;
      const descriptor = {
        agreementExpiresAtMs: proposal.expiresAtMs,
        externalBusinessActionPerformed: false,
        hostSessionKeyCertificateDigest: "f".repeat(64),
        identityPolicy: TERMS.identityPolicy,
        initiator: proposal.initiator,
        operatorPublicKey: HOST_SESSION_KEY_CERTIFICATE.certificate.sessionPublicKey,
        protocol: "clockchain.agent-handshake/v2",
        reference: TERMS.reference,
        repositorySha: REPOSITORY_SHA,
        responder: proposal.responder,
        schema: "clockchain.agent-handshake-descriptor/v2",
        sessionId: SESSION_ID,
        sessionOpenedAtMs: String(OPENED_MS),
        sessionOpenedBlock: "6999",
        statementDigest: v2CanonicalRecord(TERMS).digest,
      };
      harness.push("agent_v2_handshake_required", "host", { descriptorEnvelope: { descriptor, operator: {} }, sessionDigest: v2CanonicalRecord(descriptor).digest });
      return descriptor;
    },
  };
  return harness;
}
