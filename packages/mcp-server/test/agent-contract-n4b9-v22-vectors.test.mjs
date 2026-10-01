import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

import {
  boot, bindPair, signedSubmit, makeApproval, keys, uuid,
} from "./n4b9-harness.mjs";

// N4b-9 — F16/D12 frozen vectors: mandate-vectors.v2.2.json is an
// orchestrator-generated fixture (independent generator — not N5/N4b
// code). Byte-identical copy of
// docs/travel-mvp/design/vectors/mandate-vectors.v2.2.json. Every vector
// is checked three ways: our canonical digest must equal the frozen
// mandateDigest, the EIP-191 signature is recovered against the
// TEST-ONLY principal, and the vector is driven through the real
// mandate_prepare / mandate_submit path with principals pinned to that
// address.

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/mandate-vectors.v2.2.json", import.meta.url), "utf8"),
);
const TEST_PRINCIPAL = "0x20a8263c419340c3b225646b6262abfc8c93c819";
const VECTOR_PRINCIPALS = new Map(
  ["kb1", "kb2"].map((k) => [k, VECTORS.testOnlyPrincipal.address]),
);

assert.equal(VECTORS.schema, "agent-contract.mandate-vectors/v2.2");
assert.equal(VECTORS.vectors.length, 9);
assert.equal(VECTORS.testOnlyPrincipal.address.toLowerCase(), TEST_PRINCIPAL);

function recoverAddress(mandateDigest, signature) {
  const pub = eip191RecoverPublicKey(Buffer.from(mandateDigest.slice(2), "hex"), signature);
  return pub === null ? null : publicKeyToAddress(pub).toLowerCase();
}

test("v2.2 vectors: every frozen mandateDigest reproduces under our canonical digest", () => {
  for (const v of VECTORS.vectors) {
    const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...v.mandate });
    assert.equal(digest, v.mandateDigest, `${v.name}: canonicalDigest disagreement with the independent generator`);
  }
});

test("v2.2 vectors: signatures recover to the TEST-ONLY principal except the tampered case", () => {
  for (const v of VECTORS.vectors) {
    const addr = recoverAddress(v.mandateDigest, v.signature);
    if (v.name === "tampered-partySize") {
      // The Rome partySize=4 signature replayed over a partySize=2 digest
      // recovers to nobody's pinned principal — never the test key.
      assert.notEqual(addr, TEST_PRINCIPAL);
    } else {
      assert.equal(addr, TEST_PRINCIPAL, `${v.name}: signature should recover to the TEST-ONLY principal`);
    }
  }
});

test("v2.2 vectors: valid mandates bind through the real mandate path, digest-intact", async () => {
  for (const [i, v] of VECTORS.vectors.filter((x) => x.expect === "valid").entries()) {
    // One live run per principal — a fresh service per vector.
    const env = await boot({ principals: VECTOR_PRINCIPALS });
    try {
      await bindPair(env, uuid(600 + i), "tb1", "tp1");
      const prep = await env.callTool("tb1", "mandate_prepare", { mandate: v.mandate, mandateSignature: v.signature });
      assert.equal(prep.error, undefined, `${v.name}: ${JSON.stringify(prep)}`);
      assert.equal(prep.mandateDigest, v.mandateDigest);
      const submitted = await signedSubmit(env, {
        token: "tb1", role: "buyer", prepared: prep, submitTool: "mandate_submit",
      });
      assert.equal(submitted.bound, true, `${v.name}: ${JSON.stringify(submitted)}`);
      assert.equal(submitted.mandateDigest, v.mandateDigest);
    } finally { env.close(); }
  }
});

test("v2.2 vectors: every invalid case refuses MANDATE_INVALID on the real path", async () => {
  for (const [i, v] of VECTORS.vectors.filter((x) => x.expect === "MANDATE_INVALID").entries()) {
    const env = await boot({ principals: VECTOR_PRINCIPALS });
    try {
      await bindPair(env, uuid(610 + i), "tb1", "tp1");
      const prep = await env.callTool("tb1", "mandate_prepare", { mandate: v.mandate, mandateSignature: v.signature });
      assert.equal(prep.error, "MANDATE_INVALID", `${v.name}: ${JSON.stringify(prep)}`);
    } finally { env.close(); }
  }
});

test("v2.2 vectors: rome-family-4 — the frozen mandate books exactly 4 tickets", async () => {
  const v = VECTORS.vectors.find((x) => x.name === "rome-family-4");
  const env = await boot({ principals: VECTOR_PRINCIPALS });
  try {
    await bindPair(env, uuid(620), "tb1", "tp1");
    const prepM = await env.callTool("tb1", "mandate_prepare", { mandate: v.mandate, mandateSignature: v.signature });
    const m = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
    assert.equal(m.bound, true, JSON.stringify(m));

    const prepO = await env.callTool("tb1", "offer_prepare", { itineraryId: "IT-ROME-ZX118-ECON", feeMinor: 10_000 });
    const offered = await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
    assert.equal(offered.state, "offered", JSON.stringify(offered));
    const prepA = await env.callTool("tp1", "offer_accept_prepare", { offerId: offered.offerId });
    const accepted = await signedSubmit(env, { token: "tp1", role: "provider", prepared: prepA, submitTool: "offer_accept_submit" });
    assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));

    const prepB = await env.callTool("tp1", "booking_prepare", { agreementId: accepted.agreementId });
    assert.equal(prepB.envelope.payload.travellers, 4, "booking payload travellers = signed partySize");
    const approval = makeApproval({
      envelope: prepB.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
    });
    const booked = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared: prepB,
      submitTool: "booking_execute", extraArgs: { approval },
    });
    assert.equal(booked.tickets.length, 4, "one ticket per signed partySize traveller");
  } finally { env.close(); }
});
