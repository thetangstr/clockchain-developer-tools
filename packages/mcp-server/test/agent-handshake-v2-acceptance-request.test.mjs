// H-REQ-02: an acceptance is signed only against the proposal it accepts. The
// coordinator emits signing-request/v2 whose proposalEnvelope carries that
// proposal verbatim (null for every other operation), and verifies a proposal
// read off the relay before it builds an acceptance from it.
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";

import * as v2Protocol from "../dist/agent-handshake/v2/protocol.js";
import { commitmentCheckpointDigest } from "../dist/agent-handshake/v2/commitment-checkpoint.js";
import {
  ACCEPT_AT_MS,
  ADDRESSES,
  DEADLINE_MS,
  F,
  HELPER_V2_REQUEST_KEYS,
  HOST_SESSION_KEY_CERTIFICATE,
  PROPOSAL_EXPIRES_MS,
  PROPOSAL_ISSUED_MS,
  REPOSITORY_SHA,
  SESSION_ID,
  OTHER_ADDRESS,
  TERMS,
  clone,
  createFixtureHarness,
  fixture,
  proposalCheckpointFor,
  sig,
  signedBytesOf,
  signingRequestOf,
} from "./helpers/agent-handshake-v2-fixture-harness.mjs";

const { v2CanonicalRecord } = v2Protocol;

// ---- protocol: known answers on the reviewed canonical fixture -------------

test("H-REQ-02: the proposal verifier checks the initiator's signature over the fixture's exact canonical bytes", async () => {
  const calls = [];
  const verified = await v2Protocol.verifyV2ProposalEnvelope({
    envelope: clone(F.proposalEnvelope),
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedTerms: TERMS,
    nowMs: ACCEPT_AT_MS,
    recoverEip191Address: async ({ bytes, signatureHex }) => {
      calls.push({ bytesHex: bytes.toString("hex"), signatureHex });
      return ADDRESSES.initiator;
    },
  });
  assert.deepEqual(calls, [{ bytesHex: fixture.canonical.proposal.bytesHex, signatureHex: F.proposalEnvelope.signature.value }]);
  assert.deepEqual(verified.payload, F.proposalEnvelope.payload);
  assert.equal(v2CanonicalRecord(verified.payload).digest, fixture.canonical.proposal.digest);
});

test("H-REQ-02: the proposal verifier refuses each unbound or unsigned proposal", async () => {
  const base = {
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedTerms: TERMS,
    nowMs: ACCEPT_AT_MS,
    recoverEip191Address: async () => ADDRESSES.initiator,
  };
  const withPayload = (patch) => ({ ...clone(F.proposalEnvelope), payload: { ...clone(F.proposalEnvelope.payload), ...patch } });
  const cases = [
    ["recovered signer is not the initiator", { ...base, envelope: clone(F.proposalEnvelope), recoverEip191Address: async () => OTHER_ADDRESS }],
    ["signature address is not the initiator", { ...base, envelope: { ...clone(F.proposalEnvelope), signature: { ...F.proposalEnvelope.signature, address: ADDRESSES.responder } } }],
    ["envelope schema", { ...base, envelope: { ...clone(F.proposalEnvelope), schema: "clockchain.agent-handshake-acceptance-envelope/v2" } }],
    ["extra envelope key", { ...base, envelope: { ...clone(F.proposalEnvelope), extra: true } }],
    ["signature algorithm", { ...base, envelope: { ...clone(F.proposalEnvelope), signature: { ...F.proposalEnvelope.signature, algorithm: "eip712" } } }],
    ["another session", { ...base, expectedSessionId: randomUUID() }],
    ["another repository", { ...base, expectedRepositorySha: "e".repeat(40) }],
    ["other terms", { ...base, expectedTerms: { ...TERMS, statement: `${TERMS.statement} Amended.` } }],
    ["window not exactly validForSeconds wide", { ...base, envelope: withPayload({ expiresAtMs: String(PROPOSAL_EXPIRES_MS + 1) }) }],
    ["before its window opens", { ...base, envelope: clone(F.proposalEnvelope), nowMs: PROPOSAL_ISSUED_MS - 1 }],
    ["at its expiry", { ...base, envelope: clone(F.proposalEnvelope), nowMs: PROPOSAL_EXPIRES_MS }],
  ];
  for (const [name, input] of cases) {
    await assert.rejects(() => v2Protocol.verifyV2ProposalEnvelope(input), (error) => error?.name === "AgentHandshakeV2ValidationError", name);
  }
  // A recovery failure (for example an RPC error) is not turned into a verdict.
  const outage = new Error("rpc down");
  outage.name = "RpcRequestError";
  await assert.rejects(
    () => v2Protocol.verifyV2ProposalEnvelope({ ...base, envelope: clone(F.proposalEnvelope), recoverEip191Address: async () => { throw outage; } }),
    (error) => error === outage,
  );
});

test("H-REQ-02: the acceptance binding accepts the fixture pair and refuses every unbound field", () => {
  const acceptance = F.acceptanceEnvelope.payload;
  const proposal = F.proposalEnvelope.payload;
  assert.deepEqual(v2Protocol.assertV2AcceptanceBinding({ acceptance, proposal }), acceptance);
  const other = (party, fill) => ({ ...party, sessionKeyAddress: "0x" + fill.repeat(40) });
  const mutations = [
    ["proposalDigest", { proposalDigest: "0".repeat(64) }],
    ["sessionId", { sessionId: randomUUID() }],
    ["repositorySha", { repositorySha: "e".repeat(40) }],
    ["reference", { reference: "NS-1848" }],
    ["statementDigest", { statementDigest: "1".repeat(64) }],
    ["expiresAtMs", { expiresAtMs: String(PROPOSAL_EXPIRES_MS + 1) }],
    ["identityPolicy", { identityPolicy: { ...acceptance.identityPolicy, erc8004: "required_existing_or_fresh" } }],
    ["initiator", { initiator: other(acceptance.initiator, "8") }],
    ["responder", { responder: other(acceptance.responder, "8") }],
    ["issued before the proposal", { issuedAtMs: String(PROPOSAL_ISSUED_MS - 1) }],
  ];
  for (const [name, patch] of mutations) {
    assert.throws(() => v2Protocol.assertV2AcceptanceBinding({ acceptance: { ...acceptance, ...patch }, proposal }), (error) => error?.name === "AgentHandshakeV2ValidationError", name);
  }
});

// ---- coordinator: the acceptance signing request ---------------------------
// signing-request/v2 is emitted when the coordinator pins helper 2.3.0 or
// later (agent-handshake-v2-signing-request-mode.test.mjs covers the formats).
const V2_REQUEST_HELPER = "2.3.0";

test("H-REQ-02: with helper 2.3.0 pinned, the acceptance request for a verified proposal is signing-request/v2 and carries the stored proposal envelope verbatim (known answer)", async () => {
  const harness = await createFixtureHarness({ helperVersion: V2_REQUEST_HELPER });
  await harness.ready();
  const envelope = clone(F.proposalEnvelope);
  harness.publishProposal(envelope);
  harness.setClock(ACCEPT_AT_MS);

  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_acceptance");
  const request = signingRequestOf(response);
  assert.deepEqual(Object.keys(request), HELPER_V2_REQUEST_KEYS);
  assert.deepEqual(request, {
    schema: "clockchain.agent-handshake-signing-request/v2",
    helperVersion: V2_REQUEST_HELPER,
    operation: "acceptance",
    role: "responder",
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: String(DEADLINE_MS),
    hostSessionKeyCertificate: HOST_SESSION_KEY_CERTIFICATE,
    terms: TERMS,
    policyDigest: F.parties.responder.policyDigest,
    previousCheckpointDigest: commitmentCheckpointDigest(proposalCheckpointFor(envelope)),
    descriptorEnvelope: null,
    proposalEnvelope: F.proposalEnvelope,
    bytesGzipBase64Url: request.bytesGzipBase64Url,
    bytesSha256: createHash("sha256").update(Buffer.from(fixture.canonical.acceptance.bytesHex, "hex")).digest("hex"),
    externalBusinessActionPerformed: false,
  });
  // The carried envelope is byte-for-byte what the initiator posted, and the
  // acceptance bytes are the reviewed fixture's acceptance bytes.
  const posted = harness.posted("agent_v2_proposal", "initiator").at(-1).body.proposalEnvelope;
  assert.equal(JSON.stringify(request.proposalEnvelope), JSON.stringify(posted));
  assert.equal(JSON.stringify(request.proposalEnvelope), JSON.stringify(F.proposalEnvelope));
  assert.equal(signedBytesOf(request).toString("hex"), fixture.canonical.acceptance.bytesHex);
  // The proposal signature was checked over the fixture's canonical bytes.
  assert.ok(harness.oracle.calls.some((call) =>
    call.bytesHex === fixture.canonical.proposal.bytesHex && call.signatureHex === F.proposalEnvelope.signature.value));

  // A re-poll serves the same stored request, envelope included.
  const again = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.deepEqual(signingRequestOf(again), request);
  // The stored pending acceptance keeps the verified envelope with it.
  const record = await harness.record("responder");
  assert.equal(record.data.pending.operation, "acceptance");
  assert.equal(JSON.stringify(record.data.pending.proposalEnvelope), JSON.stringify(F.proposalEnvelope));
});

test("H-REQ-02: with helper 2.3.0 pinned, every non-acceptance request carries proposalEnvelope null and the acceptance carries the coordinator-relayed proposal", async () => {
  const harness = await createFixtureHarness({ helperVersion: V2_REQUEST_HELPER });
  const joined = await harness.join("initiator");
  const identity = signingRequestOf(joined);
  assert.deepEqual(Object.keys(identity), HELPER_V2_REQUEST_KEYS);
  assert.equal(identity.schema, "clockchain.agent-handshake-signing-request/v2");
  assert.equal(identity.operation, "identity_claim");
  assert.equal(identity.proposalEnvelope, null);
  await harness.submitIdentity("initiator");
  await harness.join("responder");
  await harness.submitIdentity("responder");
  for (const role of ["initiator", "responder"]) {
    harness.push("agent_v2_funding_record", "host", { role, address: ADDRESSES[role] });
    assert.equal((await harness.coordinator.next({ access: harness.accesses[role] })).stage, "party_ready");
  }

  const proposalResponse = await harness.coordinator.next({ access: harness.accesses.initiator });
  assert.equal(proposalResponse.stage, "sign_proposal");
  const proposalRequest = signingRequestOf(proposalResponse);
  assert.deepEqual(Object.keys(proposalRequest), HELPER_V2_REQUEST_KEYS);
  assert.equal(proposalRequest.schema, "clockchain.agent-handshake-signing-request/v2");
  assert.equal(proposalRequest.proposalEnvelope, null);
  const proposalPayload = JSON.parse(signedBytesOf(proposalRequest).toString("utf8"));
  const proposalEnvelope = {
    payload: proposalPayload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: ADDRESSES.initiator, algorithm: "eip191", value: sig(2, "initiator") },
  };
  await harness.coordinator.submitCheckpoint({ access: harness.accesses.initiator, artifactSignatureHex: sig(2, "initiator"), checkpoint: proposalCheckpointFor(proposalEnvelope) });
  await harness.coordinator.submit({ access: harness.accesses.initiator, policyDigest: F.parties.initiator.policyDigest, signatureHex: sig(2, "initiator") });

  harness.setClock(harness.now() + 5_000);
  const acceptanceResponse = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(acceptanceResponse.stage, "sign_acceptance");
  const acceptanceRequest = signingRequestOf(acceptanceResponse);
  const posted = harness.posted("agent_v2_proposal", "initiator").at(-1).body.proposalEnvelope;
  assert.equal(JSON.stringify(acceptanceRequest.proposalEnvelope), JSON.stringify(posted));
  assert.deepEqual(acceptanceRequest.proposalEnvelope, proposalEnvelope);
  const acceptancePayload = JSON.parse(signedBytesOf(acceptanceRequest).toString("utf8"));
  assert.equal(acceptancePayload.proposalDigest, v2CanonicalRecord(proposalPayload).digest);
  await harness.submitAcceptance(acceptanceRequest);

  harness.publishDescriptor();
  for (const role of ["initiator", "responder"]) {
    const evidence = await harness.coordinator.next({ access: harness.accesses[role] });
    assert.equal(evidence.stage, "sign_evidence");
    const evidenceRequest = signingRequestOf(evidence);
    assert.deepEqual(Object.keys(evidenceRequest), HELPER_V2_REQUEST_KEYS);
    assert.equal(evidenceRequest.schema, "clockchain.agent-handshake-signing-request/v2");
    assert.equal(evidenceRequest.proposalEnvelope, null);
  }
});

// ---- coordinator: a proposal read off the relay is verified first ----------

async function assertRefusedWithoutRequest(harness, label) {
  await assert.rejects(
    () => harness.coordinator.next({ access: harness.accesses.responder }),
    (error) => error?.name === "V2CoordinatorError",
    label,
  );
  const record = await harness.record("responder");
  assert.ok(!record.data.pending, `${label}: no pending acceptance may be stored`);
  assert.notEqual(record.data.stage, "sign_acceptance", label);
}

function resigned(harness, patch, signer = ADDRESSES.initiator, signatureHex = sig(8, "initiator")) {
  const payload = { ...clone(F.proposalEnvelope.payload), ...patch };
  harness.oracle.signs(payload, signatureHex, signer);
  return {
    payload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: signer, algorithm: "eip191", value: signatureHex },
  };
}

const thirdParty = {
  sessionKeyAddress: "0x" + "7".repeat(40),
  policyDigest: "7".repeat(64),
  erc8004: { ...F.parties.responder.erc8004, agentId: "9454", reference: `${TERMS.identityPolicy.chainId}:${TERMS.identityPolicy.registryAddress}:9454` },
};
const otherTerms = { ...TERMS, reference: "NS-1848" };

const refusedProposals = [
  ["a payload other than the bytes the initiator's signature covers", () => ({
    ...clone(F.proposalEnvelope),
    payload: { ...clone(F.proposalEnvelope.payload), issuedAtMs: String(PROPOSAL_ISSUED_MS - 1_000), expiresAtMs: String(PROPOSAL_EXPIRES_MS - 1_000) },
  })],
  ["the exact payload signed by a key other than the initiator's", () => ({
    ...clone(F.proposalEnvelope),
    signature: { ...F.proposalEnvelope.signature, value: sig(9, "initiator") },
  })],
  ["a signature block naming an address other than the initiator's", (harness) => {
    harness.oracle.signs(F.proposalEnvelope.payload, F.proposalEnvelope.signature.value, ADDRESSES.initiator);
    return { ...clone(F.proposalEnvelope), signature: { ...F.proposalEnvelope.signature, address: ADDRESSES.responder } };
  }],
  ["a validly signed proposal for another session", (harness) => resigned(harness, { sessionId: randomUUID() })],
  ["a validly signed proposal for another repository", (harness) => resigned(harness, { repositorySha: "e".repeat(40) })],
  ["a validly signed proposal for other terms", (harness) => resigned(harness, { reference: otherTerms.reference, statementDigest: v2CanonicalRecord(otherTerms).digest })],
  ["a validly signed proposal whose window is not exactly validForSeconds wide", (harness) => resigned(harness, { expiresAtMs: String(PROPOSAL_EXPIRES_MS + 1) })],
  ["a validly signed proposal naming another responder", (harness) => resigned(harness, { responder: thirdParty })],
  ["a proposal signed by a third party's key that names that party as initiator", (harness) => resigned(harness, { initiator: thirdParty }, thirdParty.sessionKeyAddress)],
  ["a validly signed proposal issued after the coordinator's clock", (harness) => resigned(harness, {
    issuedAtMs: String(ACCEPT_AT_MS + 1), expiresAtMs: String(ACCEPT_AT_MS + 1 + 90_000),
  })],
];

for (const [name, build] of refusedProposals) {
  test(`H-REQ-02: the responder refuses ${name} on the relay and emits no acceptance request`, async () => {
    const harness = await createFixtureHarness();
    await harness.ready();
    harness.publishProposal(build(harness));
    harness.setClock(ACCEPT_AT_MS);
    await assertRefusedWithoutRequest(harness, name);
  });
}

test("H-REQ-02: a later proposal message whose payload the initiator did not sign is refused, not accepted", async () => {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.push("agent_v2_proposal", "initiator", {
    proposalEnvelope: { ...clone(F.proposalEnvelope), payload: { ...clone(F.proposalEnvelope.payload), responder: thirdParty } },
  });
  harness.setClock(ACCEPT_AT_MS);
  await assertRefusedWithoutRequest(harness, "later proposal message the initiator did not sign");
});

test("H-REQ-02: with no proposal on the relay the responder waits and emits no acceptance request", async () => {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.setClock(ACCEPT_AT_MS);
  const outcome = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(outcome.stage, "awaiting_proposal");
  assert.equal(Object.hasOwn(outcome, "localAction"), false);
});

test("H-REQ-02: a stored pending acceptance without a verified proposal envelope is refused, not re-served", async () => {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(ACCEPT_AT_MS);
  assert.equal((await harness.coordinator.next({ access: harness.accesses.responder })).stage, "sign_acceptance");
  const record = await harness.record("responder");
  const keyValue = { principal: record.principal, session: record.session, role: record.role };

  // A pending acceptance stored with no proposal envelope beside it.
  await harness.stateStore.update(keyValue, (value) => ({
    ...value,
    data: { ...value.data, pending: { operation: "acceptance", payload: value.data.pending.payload } },
  }));
  await assert.rejects(
    () => harness.coordinator.next({ access: harness.accesses.responder }),
    (error) => error?.name === "V2CoordinatorError",
  );

  // A pending acceptance whose stored proposal envelope is not the proposal it accepts.
  const unrelated = clone(F.proposalEnvelope);
  unrelated.payload.issuedAtMs = String(PROPOSAL_ISSUED_MS - 1_000);
  unrelated.payload.expiresAtMs = String(PROPOSAL_EXPIRES_MS - 1_000);
  await harness.stateStore.update(keyValue, (value) => ({
    ...value,
    data: { ...value.data, pending: { operation: "acceptance", payload: value.data.pending.payload, proposalEnvelope: unrelated } },
  }));
  await assert.rejects(
    () => harness.coordinator.next({ access: harness.accesses.responder }),
    (error) => error?.name === "V2CoordinatorError",
  );
});

test("H-REQ-02: a proposal window that lapses while its signature is being verified yields no acceptance request", async () => {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(PROPOSAL_EXPIRES_MS - 1);
  harness.hooks.onRecover = () => { harness.setClock(PROPOSAL_EXPIRES_MS); };
  await assert.rejects(
    () => harness.coordinator.next({ access: harness.accesses.responder }),
    (error) => error?.name === "V2SigningWindowExpiredError",
  );
  const record = await harness.record("responder");
  assert.ok(!record.data.pending);
});

test("H-REQ-02: an expired relay proposal is still reported as a lapsed signing window", async () => {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(PROPOSAL_EXPIRES_MS);
  await assert.rejects(
    () => harness.coordinator.next({ access: harness.accesses.responder }),
    (error) => error?.name === "V2SigningWindowExpiredError",
  );
});
