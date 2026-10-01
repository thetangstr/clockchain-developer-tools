import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createBusinessOps } from "../dist/agent-contract/business.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import { verifyEnvelope } from "../dist/agent-contract/envelope.js";
import { eip191RecoverPublicKey, publicKeyToAddress, verifyRoleSignature } from "../dist/agent-contract/eip191.js";

import { keys, PRINCIPAL_ADDRESS, POLICY, PRINCIPALS, SIGNER } from "./n4b9-harness.mjs";

const POLICY_DIGESTS = POLICY;

// N4b-10 (spec D13): the frozen v2.3 settlement vectors — byte-identical
// copies at test/fixtures/settlement-{envelope,role-sig}-vectors.v2.3.json.
// Each envelope's payload is reproduced field-for-field on the real
// settlement_prepare path (stripe rail via a fake, simulated rail by
// default); every role-sig tuple digests and EIP-191-recovers.

const ENVELOPE_VECTORS = JSON.parse(readFileSync(
  new URL("./fixtures/settlement-envelope-vectors.v2.3.json", import.meta.url), "utf8",
));
const ROLE_SIG_VECTORS = JSON.parse(readFileSync(
  new URL("./fixtures/settlement-role-sig-vectors.v2.3.json", import.meta.url), "utf8",
));

const LF = ENVELOPE_VECTORS.ledgerFacts;

function fabricatedRun(sim) {
  return {
    runId: LF.runId,
    resultDigest: `0x${"0".repeat(64)}`,
    sessionPublicKey: "x",
    createdAtMs: Date.now(),
    bound: {
      buyer: { principalKeyId: "kb1", agentId: "9452", side: "initiator", signerKey: keys.buyerSigner, approvalKey: keys.buyerApproval, boundAt: "t" },
      provider: { principalKeyId: "kp1", agentId: "9453", side: "responder", signerKey: keys.providerSigner, approvalKey: keys.providerApproval, boundAt: "t" },
    },
    receipts: [],
    receiptsByPrincipal: new Map(),
    simRun: sim.forRun(LF.runId),
    claimedNonces: new Set(),
    mandate: {
      digest: "x", mandateId: "m", capMinor: 10_000_000, currency: "USD",
      allowedItineraryIds: ["IT-QW-ONESTOP"],
      expiresAt: "2099-01-01T00:00:00.000Z", principalAddress: PRINCIPAL_ADDRESS, submittedAt: "t",
    },
    offers: new Map(), offerSeq: 0,
    terminalState: null, stage: "verified",
    agreement: {
      agreementId: "agr-0002", offerId: "off-0002",
      offerDigest: LF.offerDigest, agreementDigest: LF.agreementDigest,
      offerPayload: {}, acceptPayload: {},
      itineraryId: "IT-QW-ONESTOP", currency: "USD",
      fareMinor: 429_000, feeMinor: 8_000, totalMinor: 437_000, formedAt: "t",
    },
    booking: { orderRef: "ORD-X", pnr: "PNR-56VQOC", tickets: [], bookedAt: "t" },
    verification: {
      result: "match", verificationDigest: LF.verificationDigest, findingsDigest: `0x${"dd".repeat(32)}`,
      agreementId: "agr-0002", agreementDigest: LF.agreementDigest,
      orderRef: "ORD-X", bookingRef: "PNR-56VQOC", flagged: false, submittedAt: "t",
    },
  };
}

test("v2.3 vector 0: the Stripe rail's settlement payload reproduces field-for-field", async () => {
  const expected = ENVELOPE_VECTORS.vectors[0].envelope;
  const sim = createSimWorld({ now: Date.now });
  const run = fabricatedRun(sim);
  const fakeRail = {
    railId: "stripe_test_mode",
    keyStatus: async () => "configured",
    createPaymentIntent: async () => ({ id: "pi_3TestOnly0000000000000001", status: "requires_confirmation" }),
    confirmPaymentIntent: async () => { throw new Error("not under test"); },
  };
  const business = createBusinessOps({
    signer: SIGNER, sim, policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    endRun: () => {}, settlementRail: fakeRail,
  });
  const buyer = { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" };
  const out = await business.dispatch(buyer, run, "settlement_prepare", {}, "0xnonce");
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.deepEqual(out.result.envelope.payload, expected.payload);
  assert.equal(canonicalDigest(out.result.envelope.payload), expected.payloadDigest,
    "payloadDigest matches the frozen v2.3 digest exactly");
});

test("v2.3 vector 1: the simulated rail's settlement payload reproduces field-for-field", async () => {
  const expected = ENVELOPE_VECTORS.vectors[1].envelope;
  const sim = createSimWorld({ now: Date.now });
  const run = fabricatedRun(sim);
  const business = createBusinessOps({
    signer: SIGNER, sim, policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    endRun: () => {},
  });
  const buyer = { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" };
  const out = await business.dispatch(buyer, run, "settlement_prepare", {}, "0xnonce");
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.deepEqual(out.result.envelope.payload, expected.payload);
  assert.equal(canonicalDigest(out.result.envelope.payload), expected.payloadDigest);
});

test("the frozen v2.3 envelopes verify under the test-only server key", () => {
  const pub = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(ENVELOPE_VECTORS.testOnlyServerKey.publicKeyHex.slice(2), "hex"),
    ]),
    format: "der", type: "spki",
  });
  for (const v of ENVELOPE_VECTORS.vectors) {
    const verdict = verifyEnvelope(v.envelope, { [ENVELOPE_VECTORS.testOnlyServerKey.keyId]: pub }, { nowMs: 0 });
    assert.equal(verdict.ok, true, v.envelope.tool);
    assert.equal(v.envelope.payload.paymentRail === "stripe_test_mode" || v.envelope.payload.paymentRail === "simulated", true);
    if (v.envelope.payload.paymentRail === "stripe_test_mode") {
      assert.equal(typeof v.envelope.payload.paymentIntentId, "string");
    }
  }
});

test("every frozen v2.3 role-sig tuple digests and recovers to the buyer signer", () => {
  assert.equal(ROLE_SIG_VECTORS.vectors.length, ENVELOPE_VECTORS.vectors.length);
  for (const [i, v] of ROLE_SIG_VECTORS.vectors.entries()) {
    assert.equal(v.tuple.payloadDigest, ENVELOPE_VECTORS.vectors[i].envelope.payloadDigest,
      `vector ${i}: role-sig binds the envelope's payloadDigest`);
    assert.equal(canonicalDigest(v.tuple), v.roleSigDigest, `vector ${i} digest`);
    const pub = eip191RecoverPublicKey(Buffer.from(v.roleSigDigest.slice(2), "hex"), v.signature);
    assert.ok(pub !== null, `vector ${i} recovers`);
    assert.equal(publicKeyToAddress(pub).toLowerCase(), v.signerAddress.toLowerCase());
    assert.equal(
      verifyRoleSignature({
        runId: v.tuple.runId, role: v.tuple.role, tool: v.tuple.tool,
        nonce: v.tuple.nonce, payloadDigest: v.tuple.payloadDigest,
        signatureHex: v.signature, expectedPublicKeyHex: `0x${Buffer.from(pub).toString("hex")}`,
      }),
      true,
      `vector ${i} verifyRoleSignature`,
    );
  }
});
