// H-REQ-01: the coordinator enrolls each role's relay sender key. At the mint
// it signs the initiator's enrollment, and at the redemption the responder's.
// Each enrollment is posted as that role's FIRST relay message (kind
// agent_v2_sender_enrollment), signed by the key it enrolls, before the
// role's invitation message. The bytes are pinned by the handshake repo's
// known-answer vector (copied to fixtures/agent-handshake-v2-sender-enrollment.json;
// every key in it is a public TEST key).
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createHandshakeStateStore, __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { canonicalBytes, signRelayEnvelope, verifyRelayEnvelope } from "../dist/handshake/protocol.js";
import { HandshakeRelayError } from "../dist/handshake/relay.js";
import { createV2InvitationService, createV2InvitationStore } from "../dist/agent-handshake/v2/invitation-store.js";
import * as coordinatorModule from "../dist/agent-handshake/v2/coordinator.js";
import { v2CanonicalRecord } from "../dist/agent-handshake/v2/protocol.js";
import { readV2RoleAccessPayload } from "../dist/agent-handshake/v2/access.js";
import { V2_HELPER_VERSION } from "../dist/agent-handshake/v2/instructions.js";
import { DISCOVERY, OPENED_MS, SESSION_ID, TERMS } from "./helpers/agent-handshake-v2-fixture-harness.mjs";

const enrollmentModule = await import("../dist/agent-handshake/v2/relay-enrollment.js").catch(() => ({}));
const { createV2Coordinator } = coordinatorModule;

const vector = JSON.parse(readFileSync(new URL("fixtures/agent-handshake-v2-sender-enrollment.json", import.meta.url), "utf8"));
const KIND = "agent_v2_sender_enrollment";
const ROLES = ["initiator", "responder"];

function pemFromSeed(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  }).export({ format: "pem", type: "pkcs8" });
}
function publicKeyFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(raw, "base64")]), format: "der", type: "spki" });
}
const COORDINATOR_KEY = Object.freeze({ kid: vector.keys.coordinator.keyRingEntry.kid, privateKeyPem: pemFromSeed(vector.keys.coordinator.seedHex) });
const COORDINATOR_PUBLIC = publicKeyFromRaw(vector.keys.coordinator.publicKey);
const sha256 = (value) => createHash("sha256").update(value, "utf8").digest("hex");
const clone = (value) => JSON.parse(JSON.stringify(value));

function coordinatorSignatureVerifies(body) {
  return verifySignature(null, canonicalBytes(body.enrollment), COORDINATOR_PUBLIC, Buffer.from(body.coordinatorSignature.signature, "base64"));
}

// ---- known answers --------------------------------------------------------

test("H-REQ-01: signSenderEnrollment reproduces the reference vector's bodies byte for byte", () => {
  for (const role of ROLES) {
    const expected = vector.enrollments[role];
    const body = enrollmentModule.signSenderEnrollment({
      enrollment: clone(expected.enrollment),
      keyId: COORDINATOR_KEY.kid,
      privateKeyPem: COORDINATOR_KEY.privateKeyPem,
    });
    assert.equal(JSON.stringify(body), JSON.stringify(expected.body), role);
    assert.equal(canonicalBytes(body.enrollment).toString("utf8"), expected.canonicalJson, role);
    assert.equal(canonicalBytes(body.enrollment).toString("hex"), expected.canonicalBytesHex, role);
    assert.equal(sha256(canonicalBytes(body.enrollment)), expected.digest, role);
  }
});

test("H-REQ-01: the coordinator's relay envelope signing reproduces the reference vector's enrollment envelopes", () => {
  for (const role of ROLES) {
    const expected = vector.enrollments[role].envelope;
    const envelope = signRelayEnvelope({
      sessionId: expected.sessionId,
      seq: expected.seq,
      role,
      kind: KIND,
      body: clone(expected.body),
      senderKey: vector.keys[role].publicKey,
      privateKeyPem: pemFromSeed(vector.keys[role].seedHex),
    });
    assert.equal(JSON.stringify(envelope), JSON.stringify(expected), role);
    const { senderKey: _senderKey, sig: _sig, ...preimage } = envelope;
    assert.equal(canonicalBytes(preimage).toString("hex"), vector.enrollments[role].envelopeSigningBytesHex, role);
  }
});

test("H-REQ-01: signSenderEnrollment refuses an enrollment the reference would not sign", () => {
  const base = vector.enrollments.initiator.enrollment;
  const sign = (enrollment, keyId = COORDINATOR_KEY.kid, privateKeyPem = COORDINATOR_KEY.privateKeyPem) =>
    () => enrollmentModule.signSenderEnrollment({ enrollment, keyId, privateKeyPem });
  const cases = [
    ["extra key", { ...base, extra: true }],
    ["schema", { ...base, schema: "clockchain.agent-handshake-sender-enrollment/v2" }],
    ["event for the role", { ...base, event: "redeemed" }],
    ["role", { ...base, role: "host" }],
    ["sender key length", { ...base, senderKey: Buffer.alloc(31).toString("base64") }],
    ["sender key padding", { ...base, senderKey: base.senderKey.replace(/=$/, "") }],
    ["invitation digest", { ...base, invitationDigest: "F".repeat(64) }],
    ["number for a millisecond value", { ...base, eventAtMs: Number(base.eventAtMs) }],
    ["issued before the event", { ...base, issuedAtMs: String(Number(base.eventAtMs) - 1) }],
    ["issued at the session deadline", { ...base, issuedAtMs: base.sessionDeadlineMs }],
    ["mint claim window not after the mint", { ...base, claimExpiresAtMs: base.eventAtMs }],
    ["external business action", { ...base, externalBusinessActionPerformed: true }],
  ];
  const refused = (error) => error?.name === "AgentHandshakeV2SenderEnrollmentError";
  for (const [name, enrollment] of cases) assert.throws(sign(enrollment), refused, name);
  assert.throws(sign(base, "Coordinator"), refused, "key id");
  const { privateKey: ecKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  assert.throws(sign(base, COORDINATOR_KEY.kid, ecKey.export({ format: "pem", type: "pkcs8" })), refused, "non-Ed25519 key");
});

// ---- the coordinator posts the enrollments --------------------------------

function relayError(code, status) {
  return new HandshakeRelayError("Handshake relay returned a non-success status.", code, status);
}

async function createEnrollmentHarness({ enrollmentKey = COORDINATOR_KEY, binding = true } = {}) {
  __resetHandshakeStateStore();
  let clock = OPENED_MS + 1_000;
  const envelopes = [];
  const attempts = [];
  const bound = { initiator: null, responder: null };
  const hooks = { beforePost: null, afterPost: null, hideEnrollments: false };
  // A relay that signs exactly as the relay client does and, when `binding`,
  // admits a role's messages the way an opted-in relay session does.
  const relay = {
    fetchDiscovery: async () => DISCOVERY,
    getMessages: async ({ after = "0" } = {}) => {
      const page = envelopes.filter((entry) => BigInt(entry.seq) > BigInt(after))
        .filter((entry) => !(hooks.hideEnrollments && entry.kind === KIND));
      return envelopes.length ? { highestSeq: envelopes.at(-1).seq, messages: page } : { messages: page };
    },
    postMessage: async (input) => {
      const envelope = clone(signRelayEnvelope({ ...input, seq: String(envelopes.length + 1) }));
      attempts.push(envelope);
      if (hooks.beforePost) await hooks.beforePost(envelope);
      if (binding && ROLES.includes(input.role)) {
        if (input.kind === KIND) {
          if (bound[input.role] !== null) {
            hooks.hideEnrollments = false; // the relay's view has caught up
            throw relayError("ROLE_ALREADY_BOUND", 409);
          }
          bound[input.role] = input.senderKey;
        } else if (bound[input.role] !== input.senderKey) {
          throw relayError("BINDING_MISMATCH", 403);
        }
      }
      envelopes.push(envelope);
      if (hooks.afterPost) await hooks.afterPost(envelope);
      return { ok: true, seq: envelope.seq };
    },
    getResult: async () => { throw new Error("pending"); },
  };
  const key = { kid: "role-2026-10", secret: randomBytes(32) };
  const stateStore = createHandshakeStateStore({});
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({
      activeKey: key,
      verificationKeys: [key],
      acceptanceHmacKeys: [{ kid: "accept-2026-10", secret: randomBytes(32) }],
      store: createV2InvitationStore(),
      nowMs: () => clock,
    }),
    relay,
    stateStore,
    now: () => clock,
    recoverEip191Address: async ({ signatureHex }) => (signatureHex.endsWith("1b") ? "0x" + "1".repeat(40) : "0x" + "2".repeat(40)),
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix: "node --verified-helper",
    ...(enrollmentKey ? { enrollmentKey } : {}),
  });
  return {
    attempts,
    bound,
    coordinator,
    envelopes,
    hooks,
    stateStore,
    advance(ms) { clock += ms; },
    now: () => clock,
    of: (role, kind) => envelopes.filter((entry) => entry.role === role && (kind === undefined || entry.kind === kind)),
  };
}

const IDEMPOTENCY_KEY = "8ec16f1f-1cf5-4e9a-86c6-a17164d834af";
const SESSION_KEYS = Object.freeze({ initiator: "0x" + "1".repeat(40), responder: "0x" + "2".repeat(40) });
function policyDigest(role) {
  return v2CanonicalRecord({
    schema: "clockchain.agent-handshake-policy/v1", protocol: "clockchain.agent-handshake/v2", role,
    mcpOrigin: "https://mcp.clockchain.network", reference: TERMS.reference,
    statementDigest: v2CanonicalRecord(TERMS).digest, maxValidForSeconds: TERMS.validForSeconds,
    identityPolicy: TERMS.identityPolicy, externalBusinessActionsAllowed: false,
  }).digest;
}

function assertEnrollmentEnvelope(envelope, role) {
  assert.equal(envelope.kind, KIND);
  assert.equal(envelope.role, role);
  assert.equal(envelope.sessionId, SESSION_ID);
  assert.equal(verifyRelayEnvelope(envelope), true);
  const { body } = envelope;
  assert.deepEqual(Object.keys(body), ["enrollment", "coordinatorSignature", "externalBusinessActionPerformed"]);
  assert.deepEqual(Object.keys(body.enrollment), [
    "schema", "protocol", "sessionId", "role", "senderKey", "statementDigest", "sessionDeadlineMs",
    "invitationDigest", "claimExpiresAtMs", "event", "eventAtMs", "issuedAtMs", "externalBusinessActionPerformed",
  ]);
  assert.deepEqual(Object.keys(body.coordinatorSignature), ["algorithm", "keyId", "signature"]);
  assert.equal(body.externalBusinessActionPerformed, false);
  assert.equal(body.coordinatorSignature.algorithm, "ed25519");
  assert.equal(body.coordinatorSignature.keyId, COORDINATOR_KEY.kid);
  assert.equal(coordinatorSignatureVerifies(body), true, `${role}: coordinator signature`);
  const { enrollment } = body;
  assert.equal(enrollment.schema, "clockchain.agent-handshake-sender-enrollment/v1");
  assert.equal(enrollment.protocol, "clockchain.agent-handshake/v2");
  assert.equal(enrollment.sessionId, SESSION_ID);
  assert.equal(enrollment.role, role);
  // Enrolls the key that signs this very envelope.
  assert.equal(enrollment.senderKey, envelope.senderKey);
  assert.equal(enrollment.statementDigest, v2CanonicalRecord(TERMS).digest);
  assert.equal(enrollment.sessionDeadlineMs, DISCOVERY.sessionDeadlineMs);
  assert.match(enrollment.invitationDigest, /^[0-9a-f]{64}$/);
  assert.equal(enrollment.event, role === "initiator" ? "minted" : "redeemed");
  assert.ok(BigInt(enrollment.issuedAtMs) >= BigInt(enrollment.eventAtMs));
  assert.equal(enrollment.externalBusinessActionPerformed, false);
  return enrollment;
}

test("H-REQ-01: the mint posts the initiator's enrollment first, then invitation_created with the same values", async () => {
  const harness = await createEnrollmentHarness();
  const invited = await harness.coordinator.invite(TERMS);
  const initiator = harness.of("initiator");
  assert.deepEqual(initiator.map((entry) => entry.kind), [KIND, "agent_v2_invitation_created"]);
  const enrollment = assertEnrollmentEnvelope(initiator[0], "initiator");
  const created = initiator[1];
  assert.equal(created.senderKey, enrollment.senderKey);
  assert.equal(created.body.createdAtMs, enrollment.eventAtMs);
  assert.equal(created.body.claimExpiresAtMs, enrollment.claimExpiresAtMs);
  assert.equal(enrollment.invitationDigest, sha256(invited.responderInvitation));
  assert.equal(enrollment.claimExpiresAtMs, readV2RoleAccessPayload(invited.responderInvitation).expMs);
});

test("H-REQ-01: the redemption posts the responder's enrollment first, then invitation_claimed with the same claim time", async () => {
  const harness = await createEnrollmentHarness();
  const invited = await harness.coordinator.invite(TERMS);
  harness.advance(7_000);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);
  const responder = harness.of("responder");
  assert.deepEqual(responder.map((entry) => entry.kind), [KIND, "agent_v2_invitation_claimed"]);
  const enrollment = assertEnrollmentEnvelope(responder[0], "responder");
  assert.equal(responder[1].senderKey, enrollment.senderKey);
  assert.equal(responder[1].body.claimedAtMs, enrollment.eventAtMs);
  assert.equal(enrollment.eventAtMs, String(harness.now()));
  const minted = harness.of("initiator", KIND)[0].body.enrollment;
  assert.equal(enrollment.invitationDigest, minted.invitationDigest);
  assert.equal(enrollment.claimExpiresAtMs, minted.claimExpiresAtMs);
  assert.notEqual(enrollment.senderKey, minted.senderKey);
});

test("H-REQ-01: exactly one enrollment per role, and every later role message uses the enrolled key", async () => {
  const harness = await createEnrollmentHarness();
  const invited = await harness.coordinator.invite(TERMS);
  const accepted = await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);
  const access = { initiator: invited.initiatorAccess, responder: accepted.responderAccess };
  for (const role of ROLES) {
    await harness.coordinator.join({ access: access[role], helperVersion: V2_HELPER_VERSION, sessionKeyAddress: SESSION_KEYS[role], policyDigest: policyDigest(role) });
    await harness.coordinator.submit({ access: access[role], policyDigest: policyDigest(role), signatureHex: `0x${"1".repeat(128)}${role === "initiator" ? "1b" : "1c"}` });
  }
  for (const role of ROLES) assert.equal(harness.of(role, "agent_v2_identity_claim").length, 1, role);
  for (const role of ROLES) {
    assert.equal(harness.of(role, KIND).length, 1, role);
    const enrolled = harness.of(role, KIND)[0].body.enrollment.senderKey;
    assert.ok(harness.of(role).every((entry) => entry.senderKey === enrolled), role);
  }
});

test("H-REQ-01: a retried redemption re-posts identical enrollment bytes and takes a 409 for its own key as success", async () => {
  const harness = await createEnrollmentHarness();
  const invited = await harness.coordinator.invite(TERMS);
  // The relay journals the responder's enrollment but the response is lost,
  // and its next read does not yet show the enrollment.
  let lose = true;
  harness.hooks.afterPost = (envelope) => {
    if (lose && envelope.kind === KIND && envelope.role === "responder") {
      lose = false;
      harness.hooks.hideEnrollments = true;
      throw new Error("relay response lost");
    }
  };
  await assert.rejects(() => harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY), /relay response lost/);
  harness.advance(2_000);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);

  const tried = harness.attempts.filter((entry) => entry.kind === KIND && entry.role === "responder");
  assert.equal(tried.length, 2);
  assert.equal(JSON.stringify(tried[1].body), JSON.stringify(tried[0].body));
  assert.equal(tried[1].senderKey, tried[0].senderKey);
  assert.equal(harness.of("responder", KIND).length, 1);
  const claimed = harness.of("responder", "agent_v2_invitation_claimed");
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].body.claimedAtMs, tried[0].body.enrollment.eventAtMs);
  // The signed enrollment is kept with the role's state.
  const record = (await harness.stateStore.list()).find((entry) => entry.role === "responder");
  assert.equal(JSON.stringify(record.data.senderEnrollment), JSON.stringify(tried[0].body));
});

test("H-REQ-01: a retried redemption that finds its enrollment on the relay does not post it again", async () => {
  const harness = await createEnrollmentHarness();
  const invited = await harness.coordinator.invite(TERMS);
  let fail = true;
  harness.hooks.beforePost = (envelope) => {
    if (fail && envelope.kind === "agent_v2_invitation_claimed") {
      fail = false;
      throw new Error("relay unavailable");
    }
  };
  await assert.rejects(() => harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY), /relay unavailable/);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);
  assert.equal(harness.attempts.filter((entry) => entry.kind === KIND && entry.role === "responder").length, 1);
  assert.equal(harness.of("responder", KIND).length, 1);
  assert.equal(harness.of("responder", "agent_v2_invitation_claimed").length, 1);
});

test("H-REQ-01: a 409 when another key holds the role is an error and nothing more is posted for it", async () => {
  for (const visible of [false, true]) {
    const harness = await createEnrollmentHarness();
    const invited = await harness.coordinator.invite(TERMS);
    // Another key already holds the responder role on the relay.
    const other = generateKeyPairSync("ed25519");
    const otherKey = other.publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64");
    harness.bound.responder = otherKey;
    harness.envelopes.push(clone(signRelayEnvelope({
      sessionId: SESSION_ID, seq: String(harness.envelopes.length + 1), role: "responder", kind: KIND,
      body: { otherKey: true }, senderKey: otherKey,
      privateKeyPem: other.privateKey.export({ format: "pem", type: "pkcs8" }),
    })));
    harness.hooks.hideEnrollments = !visible;
    await assert.rejects(
      () => harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY),
      (error) => error?.name === "V2CoordinatorError",
      visible ? "visible enrollment of another key" : "409 for another key",
    );
    assert.equal(harness.of("responder", "agent_v2_invitation_claimed").length, 0);
  }
});

test("H-REQ-01: a session whose initiator is enrolled by an unfinished mint takes no new invitation", async () => {
  const harness = await createEnrollmentHarness();
  let fail = true;
  harness.hooks.beforePost = (envelope) => {
    if (fail && envelope.kind === "agent_v2_invitation_created") {
      fail = false;
      throw new Error("relay unavailable");
    }
  };
  await assert.rejects(() => harness.coordinator.invite(TERMS), /relay unavailable/);
  await assert.rejects(() => harness.coordinator.invite(TERMS), (error) => error?.name === "V2TransientCoordinatorError");
  assert.equal(harness.attempts.filter((entry) => entry.kind === KIND && entry.role === "initiator").length, 1);
});

test("H-REQ-01: with no enrollment key configured the coordinator posts no enrollment and the invitation messages are unchanged", async () => {
  const harness = await createEnrollmentHarness({ enrollmentKey: null, binding: false });
  const mintAt = harness.now();
  const invited = await harness.coordinator.invite(TERMS);
  harness.advance(7_000);
  await harness.coordinator.acceptInvitation(invited.responderInvitation, IDEMPOTENCY_KEY);
  assert.equal(harness.envelopes.filter((entry) => entry.kind === KIND).length, 0);
  assert.deepEqual(harness.of("initiator").map((entry) => entry.kind), ["agent_v2_invitation_created"]);
  assert.deepEqual(harness.of("responder").map((entry) => entry.kind), ["agent_v2_invitation_claimed"]);
  assert.deepEqual(harness.of("initiator")[0].body, {
    claimExpiresAtMs: String(mintAt + 180_000),
    createdAtMs: String(mintAt),
    externalBusinessActionPerformed: false,
    statementDigest: v2CanonicalRecord(TERMS).digest,
    terms: TERMS,
  });
  assert.deepEqual(harness.of("responder")[0].body, { claimedAtMs: String(harness.now()), externalBusinessActionPerformed: false });
  const records = await harness.stateStore.list();
  assert.ok(records.every((record) => record.data.senderEnrollment === undefined));
});

// ---- configuration ---------------------------------------------------------

test("H-REQ-01: the enrollment key is read by name from AGENT_HANDSHAKE_V2_ENROLLMENT_KEY", () => {
  const read = coordinatorModule.__runtimeV2EnrollmentKey;
  const warnings = [];
  const warn = (line) => warnings.push(line);
  const configured = read({ AGENT_HANDSHAKE_V2_ENROLLMENT_KEY: JSON.stringify(COORDINATOR_KEY) }, warn);
  assert.deepEqual(configured, COORDINATOR_KEY);
  assert.equal(warnings.length, 0);
  // The configured key signs the reference vector's bytes.
  const body = enrollmentModule.signSenderEnrollment({ enrollment: clone(vector.enrollments.initiator.enrollment), keyId: configured.kid, privateKeyPem: configured.privateKeyPem });
  assert.equal(JSON.stringify(body), JSON.stringify(vector.enrollments.initiator.body));
});

test("H-REQ-01: without an enrollment key the coordinator logs once and enrolls nothing", () => {
  const read = coordinatorModule.__runtimeV2EnrollmentKey;
  for (const env of [{}, { AGENT_HANDSHAKE_V2_ENROLLMENT_KEY: "" }]) {
    const warnings = [];
    assert.equal(read(env, (line) => warnings.push(line)), null);
    assert.equal(warnings.length, 1);
    assert.deepEqual(JSON.parse(warnings[0]), { event: "agent_handshake_v2_sender_enrollment_disabled" });
  }
});

test("H-REQ-01: a malformed enrollment key configuration fails at load", () => {
  const read = coordinatorModule.__runtimeV2EnrollmentKey;
  const { privateKey: ecKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const malformed = [
    "-----BEGIN PRIVATE KEY-----",
    JSON.stringify({ kid: COORDINATOR_KEY.kid }),
    JSON.stringify({ ...COORDINATOR_KEY, extra: true }),
    JSON.stringify({ ...COORDINATOR_KEY, kid: "Coordinator Key" }),
    JSON.stringify({ ...COORDINATOR_KEY, privateKeyPem: "not a key" }),
    JSON.stringify({ ...COORDINATOR_KEY, privateKeyPem: ecKey.export({ format: "pem", type: "pkcs8" }) }),
    JSON.stringify({ ...COORDINATOR_KEY, privateKeyPem: createPublicKey(COORDINATOR_KEY.privateKeyPem).export({ format: "pem", type: "spki" }) }),
  ];
  for (const raw of malformed) {
    assert.throws(() => read({ AGENT_HANDSHAKE_V2_ENROLLMENT_KEY: raw }, () => {}), (error) => error?.name === "V2CoordinatorError", raw.slice(0, 40));
  }
});
