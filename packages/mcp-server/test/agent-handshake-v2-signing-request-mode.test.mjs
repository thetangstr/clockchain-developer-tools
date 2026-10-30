// The coordinator emits the signing-request format of the helper release it
// is pinned to. Pinned below 2.3.0 it emits signing-request/v1 exactly as the
// coordinator did at 0fd63ab (same schema, keys and key order; no
// proposalEnvelope). Pinned at 2.3.0 or above it emits signing-request/v2,
// whose acceptance request carries the verified proposal envelope. A pinned
// version that is not MAJOR.MINOR.PATCH refuses at creation. The pinned
// version defaults to V2_HELPER_VERSION. In both formats the coordinator
// verifies the proposal before it builds an acceptance.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { V2_HELPER_VERSION } from "../dist/agent-handshake/v2/instructions.js";
import * as h from "./helpers/agent-handshake-v2-fixture-harness.mjs";
import { signingResponses } from "./helpers/agent-handshake-v2-signing-flow.mjs";

// Generated from the coordinator at 0fd63ab running the same signing flow.
const V1_KNOWN_ANSWER = JSON.parse(readFileSync(new URL("./fixtures/agent-handshake-v2-signing-request-v1.json", import.meta.url), "utf8"));
const V1_SCHEMA = "clockchain.agent-handshake-signing-request/v1";
const V2_SCHEMA = "clockchain.agent-handshake-signing-request/v2";
const V1_REQUEST_KEYS = Object.freeze([
  "schema", "helperVersion", "operation", "role", "sessionId", "repositorySha",
  "sessionDeadlineMs", "hostSessionKeyCertificate", "terms", "policyDigest",
  "previousCheckpointDigest", "descriptorEnvelope",
  "bytesGzipBase64Url", "bytesSha256", "externalBusinessActionPerformed",
]);

const isCoordinatorError = (error) => error?.name === "V2CoordinatorError";

function requestBase64UrlOf(response) {
  return response.localAction.helperStep.shellCommand.match(/--payload-base64url\s+([A-Za-z0-9_-]+)$/)[1];
}

function atLeast230(version) {
  const [major, minor] = version.split(".").map(Number);
  return major > 2 || (major === 2 && minor >= 3);
}

// ---- helper 2.1.8 pinned: the v1 request, byte for byte -------------------

test("H-REQ-02: with helper 2.1.8 pinned, every signing response is byte-identical to the coordinator's at 0fd63ab (known answer)", async () => {
  assert.equal(V1_KNOWN_ANSWER.helperVersion, "2.1.8");
  const responses = await signingResponses(h, { helperVersion: "2.1.8" });
  assert.deepEqual(Object.keys(responses), Object.keys(V1_KNOWN_ANSWER.steps));
  for (const [step, response] of Object.entries(responses)) {
    const request = h.signingRequestOf(response);
    assert.equal(request.schema, V1_SCHEMA, step);
    assert.equal(request.helperVersion, "2.1.8", step);
    assert.deepEqual(Object.keys(request), V1_REQUEST_KEYS, step);
    assert.equal(requestBase64UrlOf(response), V1_KNOWN_ANSWER.steps[step].requestBase64Url, `${step}: request bytes`);
    assert.equal(JSON.stringify(response), V1_KNOWN_ANSWER.steps[step].response, `${step}: whole response`);
  }
  // The acceptance of the canonical proposal signs the canonical acceptance bytes.
  const acceptance = h.signingRequestOf(responses.acceptance_of_fixture_proposal);
  assert.equal(h.signedBytesOf(acceptance).toString("hex"), h.fixture.canonical.acceptance.bytesHex);
});

test("H-REQ-02: with no pinned version configured, the coordinator pins V2_HELPER_VERSION and emits that release's request format", async () => {
  const responses = await signingResponses(h);
  const v2 = atLeast230(V2_HELPER_VERSION);
  for (const [step, response] of Object.entries(responses)) {
    const request = h.signingRequestOf(response);
    assert.equal(request.helperVersion, V2_HELPER_VERSION, step);
    assert.equal(request.schema, v2 ? V2_SCHEMA : V1_SCHEMA, step);
    if (!v2) assert.equal(requestBase64UrlOf(response), V1_KNOWN_ANSWER.steps[step].requestBase64Url, step);
  }
});

// ---- helper 2.3.0 pinned: the v2 request ----------------------------------

test("H-REQ-02: with helper 2.3.0 pinned, every request is signing-request/v2 and only the acceptance carries the verified proposal envelope", async () => {
  const responses = await signingResponses(h, { helperVersion: "2.3.0" });
  for (const [step, response] of Object.entries(responses)) {
    const request = h.signingRequestOf(response);
    assert.deepEqual(Object.keys(request), h.HELPER_V2_REQUEST_KEYS, step);
    assert.equal(request.schema, V2_SCHEMA, step);
    assert.equal(request.helperVersion, "2.3.0", step);
    if (step.startsWith("acceptance")) {
      assert.equal(request.proposalEnvelope.schema, "clockchain.agent-handshake-proposal-envelope/v2", step);
    } else {
      assert.equal(request.proposalEnvelope, null, step);
    }
    // Apart from its schema, helperVersion and proposalEnvelope, each request
    // is the v1 request of the same step.
    const v1 = JSON.parse(Buffer.from(V1_KNOWN_ANSWER.steps[step].requestBase64Url, "base64url").toString("utf8"));
    const { proposalEnvelope: _carried, ...rest } = request;
    assert.deepEqual({ ...rest, schema: V1_SCHEMA, helperVersion: "2.1.8" }, v1, step);
  }
  const fixtureAcceptance = h.signingRequestOf(responses.acceptance_of_fixture_proposal);
  assert.equal(JSON.stringify(fixtureAcceptance.proposalEnvelope), JSON.stringify(h.F.proposalEnvelope));
});

test("H-REQ-02: the request format changes at helper 2.3.0, comparing version parts as numbers", async () => {
  for (const [version, schema] of [
    ["1.9.9", V1_SCHEMA], ["2.1.8", V1_SCHEMA], ["2.2.9", V1_SCHEMA], ["2.2.10", V1_SCHEMA],
    ["2.3.0", V2_SCHEMA], ["2.3.1", V2_SCHEMA], ["2.10.0", V2_SCHEMA], ["10.0.0", V2_SCHEMA],
  ]) {
    const harness = await h.createFixtureHarness({ helperVersion: version });
    const request = h.signingRequestOf(await harness.join("initiator"));
    assert.equal(request.schema, schema, version);
    assert.equal(request.helperVersion, version, version);
    assert.equal(Object.hasOwn(request, "proposalEnvelope"), schema === V2_SCHEMA, version);
  }
});

test("H-REQ-02: a coordinator pinned to one helper version accepts a join only from that version", async () => {
  const harness = await h.createFixtureHarness({ helperVersion: "2.3.0" });
  await assert.rejects(
    () => harness.coordinator.join({ access: harness.accesses.initiator, helperVersion: "2.1.8", sessionKeyAddress: h.ADDRESSES.initiator, policyDigest: h.F.parties.initiator.policyDigest }),
    isCoordinatorError,
  );
  assert.equal(h.signingRequestOf(await harness.join("initiator")).helperVersion, "2.3.0");
});

// ---- an unusable pinned version -------------------------------------------

test("H-REQ-02: a pinned helper version that is not MAJOR.MINOR.PATCH refuses when the coordinator is created", async () => {
  for (const version of ["", "2.3", "2.3.0.1", "v2.3.0", "2.3.0-rc.1", "02.3.0", "2.03.0", " 2.3.0", "2.3.x", "2.3.0\n", null, 230]) {
    await assert.rejects(() => h.createFixtureHarness({ helperVersion: version }), isCoordinatorError, JSON.stringify(version));
  }
});

// ---- helper 2.1.8 pinned: the proposal is still verified ------------------

async function pinnedV1WithProposal(envelope) {
  const harness = await h.createFixtureHarness({ helperVersion: "2.1.8" });
  await harness.ready();
  harness.publishProposal(envelope);
  harness.setClock(h.ACCEPT_AT_MS);
  return harness;
}

async function assertNoAcceptanceRequest(harness, label) {
  await assert.rejects(() => harness.coordinator.next({ access: harness.accesses.responder }), isCoordinatorError, label);
  assert.ok(!(await harness.record("responder")).data.pending, `${label}: no pending acceptance`);
}

test("H-REQ-02: with helper 2.1.8 pinned, a proposal that does not match the initiator's signature yields no acceptance request", async () => {
  const thirdParty = { ...h.F.parties.responder, sessionKeyAddress: "0x" + "7".repeat(40) };
  const cases = [
    ["a payload other than the bytes the initiator's signature covers", { ...h.clone(h.F.proposalEnvelope), payload: { ...h.clone(h.F.proposalEnvelope.payload), responder: thirdParty } }],
    ["the payload with a signature from another key", { ...h.clone(h.F.proposalEnvelope), signature: { ...h.F.proposalEnvelope.signature, value: h.sig(9, "initiator") } }],
  ];
  for (const [label, envelope] of cases) {
    await assertNoAcceptanceRequest(await pinnedV1WithProposal(envelope), label);
  }
  // The matching proposal yields the v1 acceptance request.
  const harness = await pinnedV1WithProposal(h.clone(h.F.proposalEnvelope));
  const request = h.signingRequestOf(await harness.coordinator.next({ access: harness.accesses.responder }));
  assert.equal(request.schema, V1_SCHEMA);
  assert.equal(request.operation, "acceptance");
});

test("H-REQ-02: with helper 2.1.8 pinned, a stored pending acceptance without its verified proposal envelope is refused", async () => {
  const harness = await pinnedV1WithProposal(h.clone(h.F.proposalEnvelope));
  assert.equal((await harness.coordinator.next({ access: harness.accesses.responder })).stage, "sign_acceptance");
  const record = await harness.record("responder");
  const keyValue = { principal: record.principal, session: record.session, role: record.role };
  await harness.stateStore.update(keyValue, (value) => ({
    ...value,
    data: { ...value.data, pending: { operation: "acceptance", payload: value.data.pending.payload } },
  }));
  await assert.rejects(() => harness.coordinator.next({ access: harness.accesses.responder }), isCoordinatorError);
});
