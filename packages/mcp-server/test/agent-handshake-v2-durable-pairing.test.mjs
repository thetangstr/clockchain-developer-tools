// Plan step 3 (travel's stand-in for a live v2 pairing): a complete Agent Handshake v2 pairing
// over the public /handshake/mcp tools with durability ON, crash-restarted after acceptance,
// must end with the same certificate, byte for byte, as the identical run without a restart.
//
// Nothing in v2 is changed for this test. Its nondeterminism is controlled from outside: the
// invitation service's UUIDs (its own injection point; they reach role tokens and the
// invitation) and time (fixed). The relay Ed25519 keys (node:crypto generateKeyPairSync) do not
// reach any compared output today; they are seeded anyway (re-exported to ESM importers with
// syncBuiltinESMExports) so the byte comparison stays meaningful if that ever changes. The
// relay, host and chain are stubs, as in the existing v2 tests.
// ccra_ handles stay random: they are compared for identity across the crash, and replaced by
// a placeholder when two separate runs are compared.
import assert from "node:assert/strict";
import crypto, { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import test from "node:test";

import { createIsolatedHandshakeStateStore } from "../dist/handshake/state.js";
import { createV2InvitationService, createV2InvitationStore } from "../dist/agent-handshake/v2/invitation-store.js";
import { createV2Coordinator } from "../dist/agent-handshake/v2/coordinator.js";
import { createV2PublicHttpHandler } from "../dist/agent-handshake/v2/public-server.js";
import { v2CanonicalRecord } from "../dist/agent-handshake/v2/protocol.js";

const nowMs = 1786337000000;
const sessionId = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";
const repositorySha = "d".repeat(40);
const pin = {
  version: "2.1.8",
  sourceCommit: repositorySha,
  manifestDigest: "a".repeat(64),
  allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/",
  hostRoots: [{ kid: "root-2026-08", fingerprint: "b".repeat(64) }],
};
const terms = {
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
};
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
const addresses = {
  initiator: "0x7564105e977516c53be337314c7e53838967bdac",
  responder: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9",
};
const registrations = {
  [addresses.initiator]: { agentId: "9452", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9452`, registrationTx: `0x${"a".repeat(64)}`, registrationBlock: "7000" },
  [addresses.responder]: { agentId: "9453", chainId: terms.identityPolicy.chainId, registryAddress: terms.identityPolicy.registryAddress, reference: `${terms.identityPolicy.chainId}:${terms.identityPolicy.registryAddress}:9453`, registrationTx: `0x${"b".repeat(64)}`, registrationBlock: "7001" },
};
const accessKey = { kid: "role-2026-08", secret: Buffer.alloc(32, 7) };
const sig = (digit, role) => `0x${String(digit).repeat(128)}${role === "initiator" ? "1b" : "1c"}`;

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

// Seeded Ed25519 key generation for every ESM importer of node:crypto, for one run.
function seedEd25519() {
  const original = crypto.generateKeyPairSync;
  let counter = 0;
  crypto.generateKeyPairSync = (type, options) => {
    if (type !== "ed25519") return original(type, options);
    counter += 1;
    const seed = createHash("sha256").update(`v2-durable-pairing-relay-key-${counter}`).digest();
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
  };
  syncBuiltinESMExports();
  return () => {
    crypto.generateKeyPairSync = original;
    syncBuiltinESMExports();
  };
}

const payloadOf = (response) => {
  const command = response.localAction.helperStep.shellCommand;
  return JSON.parse(Buffer.from(command.match(/--payload-base64url\s+([A-Za-z0-9_-]+)$/)[1], "base64url").toString("utf8"));
};

// One full pairing through the public tools. With `crashAfterAccept`, the coordinator, the
// public handler and its HTTP server are dropped right after acceptance (nothing closed or
// flushed) and rebuilt from the same state directory; both roles then carry on with the
// ccra_ handles they already hold.
async function pairing({ crashAfterAccept }) {
  const dir = mkdtempSync(join(tmpdir(), "v2-durable-pairing-"));
  const restore = seedEd25519();
  let uuidCounter = 0;
  const nextUuid = () => {
    const hex = createHash("sha256").update(`v2-durable-pairing-uuid-${++uuidCounter}`).digest("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  };
  // The relay and host are external services: they live across the restart.
  const messages = [];
  let result = null;
  const relay = {
    fetchDiscovery: async () => discovery,
    getMessages: async () => ({ messages }),
    postMessage: async (input) => {
      messages.push({ ...input });
      return { ok: true, seq: String(messages.length) };
    },
    getResult: async () => {
      if (!result) throw new Error("pending");
      return result;
    },
  };
  let live;
  async function boot() {
    const coordinator = createV2Coordinator({
      accessKeys: [accessKey],
      activeAccessKey: accessKey,
      invitationService: createV2InvitationService({
        activeKey: accessKey,
        verificationKeys: [accessKey],
        store: createV2InvitationStore({ path: join(dir, "agent-handshake-v2-invitations.json") }),
        nowMs: () => nowMs + 1,
        randomUUID: nextUuid,
      }),
      relay,
      stateStore: createIsolatedHandshakeStateStore(join(dir, "agent-handshake-v2-state.json")),
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
      verifiedHelperPrefix: "node --verified-helper",
    });
    const handler = createV2PublicHttpHandler({
      pin,
      now: () => nowMs + 1,
      invitePerHour: 100,
      callsPerMinute: 10_000,
      invoke: (name, args) => coordinator.invoke(name, args),
      stateDir: join(dir, "agent-handshake-v2"),
    });
    const server = createServer((req, res) => { void handler(req, res); });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${server.address().port}/handshake/mcp`;
    const rpc = async (method, params = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await response.text();
      return text.split("\n").find((line) => line.startsWith("data:")).slice(5);
    };
    live = { server, rpc };
  }
  function crash() {
    // No close(), no flush: the process is simply gone.
    live.server.closeAllConnections();
    live.server.close();
  }

  const transcript = [];
  async function call(name, args) {
    const raw = await live.rpc("tools/call", { name, arguments: args });
    const parsed = JSON.parse(raw);
    assert.equal(parsed.result.isError, undefined, `${name}: ${raw}`);
    const body = JSON.parse(parsed.result.content[0].text);
    transcript.push({ name, text: parsed.result.content[0].text });
    return body;
  }

  try {
    await boot();
    const toolsBefore = await live.rpc("tools/list");
    const invited = await call("agent_handshake_invite", terms);
    const accepted = await call("agent_handshake_accept_invitation", { invitation: invited.responderInvitation });
    const handles = { initiator: invited.roleAccess, responder: accepted.roleAccess };
    let toolsAfter = toolsBefore;
    if (crashAfterAccept) {
      crash();
      await boot();
      toolsAfter = await live.rpc("tools/list");
    }
    const used = new Set();
    const act = async (name, role, args = {}) => {
      const response = await call(name, { access: handles[role], ...args });
      // The ORIGINAL handle is accepted and echoed: never re-issued after the restart.
      assert.equal(response.roleAccess, handles[role], `${name} for ${role} echoed a different handle`);
      used.add(role);
      return response;
    };

    for (const role of ["initiator", "responder"]) {
      await act("agent_handshake_join", role, { helperVersion: "2.1.8", sessionKeyAddress: addresses[role], policyDigest: v2CanonicalRecord(policy(role)).digest });
      await act("agent_handshake_submit", role, { policyDigest: v2CanonicalRecord(policy(role)).digest, signatureHex: sig(1, role) });
    }
    for (const role of ["initiator", "responder"]) {
      messages.push({ kind: "agent_v2_funding_record", role: "host", body: { role, address: addresses[role] } });
      assert.equal((await act("agent_handshake_next", role, { waitMs: 0 })).stage, "party_ready");
    }

    const proposal = await act("agent_handshake_next", "initiator", { waitMs: 0 });
    const proposalRequest = payloadOf(proposal);
    const proposalSignatureHex = sig(2, "initiator");
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
      signature: { address: addresses.initiator, algorithm: "eip191", value: sig(6, "initiator") },
    };
    const proposalReceipt = await act("agent_handshake_submit_checkpoint", "initiator", { artifactSignatureHex: proposalSignatureHex, checkpoint: proposalCheckpoint });
    await act("agent_handshake_submit", "initiator", { policyDigest: v2CanonicalRecord(policy("initiator")).digest, signatureHex: proposalSignatureHex });

    const acceptance = await act("agent_handshake_next", "responder", { waitMs: 0 });
    const acceptanceRequest = payloadOf(acceptance);
    const acceptanceSignatureHex = sig(3, "responder");
    const acceptanceEnvelope = {
      payload: JSON.parse(gunzipSync(Buffer.from(acceptanceRequest.bytesGzipBase64Url, "base64url")).toString("utf8")),
      schema: "clockchain.agent-handshake-acceptance-envelope/v2",
      signature: { address: addresses.responder, algorithm: "eip191", value: acceptanceSignatureHex },
    };
    const acceptanceCheckpoint = {
      schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
      protocol: "clockchain.agent-handshake/v2", sessionId, role: "responder", artifactType: "acceptance",
      artifactDigest: v2CanonicalRecord(acceptanceEnvelope).digest, sequence: "2",
      previousCheckpointDigest: proposalReceipt.checkpointDigest,
      issuedAtMs: String(nowMs + 1), expiresAtMs: String(nowMs + 90_000), signerAddress: addresses.responder,
      signature: { address: addresses.responder, algorithm: "eip191", value: sig(7, "responder") },
    };
    await act("agent_handshake_submit_checkpoint", "responder", { artifactSignatureHex: acceptanceSignatureHex, checkpoint: acceptanceCheckpoint });
    await act("agent_handshake_submit", "responder", { policyDigest: v2CanonicalRecord(policy("responder")).digest, signatureHex: acceptanceSignatureHex });

    // The host (a stub) asks for evidence over the descriptor built from the proposal.
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
      await act("agent_handshake_next", role, { waitMs: 0 });
      await act("agent_handshake_submit", role, { policyDigest: v2CanonicalRecord(policy(role)).digest, signatureHex: sig(4, role) });
    }
    result = { result: {
      anchors: ["proposal", "acceptance", "acknowledgment"].map((kind, index) => ({ blockHeight: String(7010 + index), blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`, digest: String(index + 1).repeat(64), kind, ledgerId: `33333333-4444-4555-8666-77777777777${index}` })),
      externalBusinessActionPerformed: false, hostSessionKeyCertificateDigest: "f".repeat(64), identityPolicy: terms.identityPolicy,
      issuedAtMs: String(nowMs + 5000), outcome: "VERIFIED", parties,
      policyDigests: { initiator: parties.initiator.policyDigest, responder: parties.responder.policyDigest },
      reference: terms.reference, schema: "clockchain.agent-handshake-result/v2", sessionDigest: v2CanonicalRecord(descriptor).digest,
      sessionId, statementDigest: v2CanonicalRecord(terms).digest, subjectRun: "stakeholder",
    }, signer: {}, hostSessionKeyCertificate };

    const certificates = {};
    for (const role of ["initiator", "responder"]) {
      const response = await act("agent_handshake_get_certificate", role);
      certificates[role] = { response, certificate: JSON.stringify(payloadOf(response).certificate) };
    }
    assert.deepEqual([...used].sort(), ["initiator", "responder"]);
    return { transcript, certificates, handles, toolsBefore, toolsAfter, expected: JSON.stringify(result) };
  } finally {
    live?.server.closeAllConnections();
    live?.server.close();
    restore();
  }
}

// Handles are random per run; everything else must match byte for byte.
const normalized = (text) => text.replace(/ccra_[A-Za-z0-9_-]{22}/g, "ccra_<handle>");

test("v2 pairing with durability on: a crash-restart after acceptance ends in a byte-identical certificate, with the original ccra_ handles", async () => {
  const baseline = await pairing({ crashAfterAccept: false });
  const restarted = await pairing({ crashAfterAccept: true });

  // The certificate each role receives is exactly the host's, and identical to the no-restart run.
  for (const role of ["initiator", "responder"]) {
    assert.equal(restarted.certificates[role].certificate, restarted.expected);
    assert.equal(restarted.certificates[role].certificate, baseline.certificates[role].certificate, `${role} certificate bytes`);
    assert.equal(
      normalized(JSON.stringify(restarted.certificates[role].response)),
      normalized(JSON.stringify(baseline.certificates[role].response)),
      `${role} get_certificate response`,
    );
  }

  // tools/list is byte-identical across the restart and between runs.
  assert.equal(restarted.toolsAfter, restarted.toolsBefore);
  assert.equal(restarted.toolsBefore, baseline.toolsBefore);

  // Every tool response, in order, is byte-identical to the no-restart run once the random
  // handle strings are masked (the handles themselves were checked per call against the
  // originals issued before the crash).
  assert.equal(restarted.transcript.length, baseline.transcript.length);
  for (let index = 0; index < baseline.transcript.length; index += 1) {
    assert.equal(restarted.transcript[index].name, baseline.transcript[index].name);
    assert.equal(normalized(restarted.transcript[index].text), normalized(baseline.transcript[index].text), `response ${index} (${baseline.transcript[index].name})`);
  }
});
