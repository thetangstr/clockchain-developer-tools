import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import {
  eip191RecoverPublicKey,
  eip191SignDigest32,
  publicKeyToAddress,
  verifyRoleSignature,
} from "../dist/agent-contract/eip191.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const VECTORS = JSON.parse(readFileSync(path.join(FIXTURES, "role-sig-vectors.v2.json"), "utf8"));
const ENVELOPE_VECTORS = JSON.parse(readFileSync(path.join(FIXTURES, "prepare-envelope-vectors.v2.json"), "utf8"));

// The frozen v2 role-sig vectors are the acceptance contract (N4b-2b): every
// tuple must digest to roleSigDigest, and every signature must EIP-191-recover
// to the recorded TEST-ONLY signer address — all locally, no RPC.

test("every frozen v2 role-sig vector digests and recovers to its signer", () => {
  for (const v of VECTORS.vectors) {
    const digest = canonicalDigest(v.tuple);
    assert.equal(digest, v.roleSigDigest, `${v.tool}/${v.role} digest`);
    const pub = eip191RecoverPublicKey(Buffer.from(v.roleSigDigest.slice(2), "hex"), v.signature);
    assert.ok(pub !== null, `${v.tool}/${v.role} recovers`);
    assert.equal(publicKeyToAddress(pub).toLowerCase(), v.signerAddress.toLowerCase(), `${v.tool}/${v.role} address`);
    // verifyRoleSignature accepts the recovered key as the bound signer key.
    const expectedPubHex = "0x" + Buffer.from(pub).toString("hex");
    assert.equal(
      verifyRoleSignature({
        runId: v.tuple.runId, role: v.tuple.role, tool: v.tuple.tool,
        nonce: v.tuple.nonce, payloadDigest: v.tuple.payloadDigest,
        signatureHex: v.signature, expectedPublicKeyHex: expectedPubHex,
      }),
      true,
      `${v.tool}/${v.role} verifyRoleSignature`,
    );
    // a compressed (33B) form of the same key must also verify
    const compressed = "0x" + (pub[64] % 2 === 0 ? "02" : "03") + Buffer.from(pub.subarray(1, 33)).toString("hex");
    assert.equal(
      verifyRoleSignature({
        runId: v.tuple.runId, role: v.tuple.role, tool: v.tuple.tool,
        nonce: v.tuple.nonce, payloadDigest: v.tuple.payloadDigest,
        signatureHex: v.signature, expectedPublicKeyHex: compressed,
      }),
      true,
      `${v.tool}/${v.role} compressed key`,
    );
  }
});

test("the frozen v2 prepare envelopes verify under the test-only server key", async () => {
  const { verifyEnvelope } = await import("../dist/agent-contract/envelope.js");
  const pub = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), // ed25519 SPKI prefix
      Buffer.from(ENVELOPE_VECTORS.testOnlyServerKey.publicKeyHex.slice(2), "hex"),
    ]),
    format: "der",
    type: "spki",
  });
  for (const v of ENVELOPE_VECTORS.vectors) {
    const verdict = verifyEnvelope(v.envelope, { [ENVELOPE_VECTORS.testOnlyServerKey.keyId]: pub }, { nowMs: 0 });
    assert.equal(verdict.ok, true, `${v.envelope.tool}/${v.envelope.role}`);
    // every priced v2 kind carries explicit currency + itineraryId
    // (CONTRACT-PAYLOADS-v2 §1); `verification` is an unpriced kind.
    if (v.envelope.payload.kind !== "verification") {
      assert.equal(typeof v.envelope.payload.currency, "string");
      assert.equal(typeof v.envelope.payload.itineraryId, "string");
    }
  }
});

test("a role sig from another run/tool/nonce is refused", () => {
  const v = VECTORS.vectors[0];
  const pub = eip191RecoverPublicKey(Buffer.from(v.roleSigDigest.slice(2), "hex"), v.signature);
  const expectedPubHex = "0x" + Buffer.from(pub).toString("hex");
  for (const mutation of [
    { runId: "run-other" },
    { tool: "settlement_prepare" },
    { nonce: "0x" + "00".repeat(16) },
    { payloadDigest: "0x" + "00".repeat(32) },
    { role: "provider" },
  ]) {
    assert.equal(
      verifyRoleSignature({
        runId: mutation.runId ?? v.tuple.runId,
        role: mutation.role ?? v.tuple.role,
        tool: mutation.tool ?? v.tuple.tool,
        nonce: mutation.nonce ?? v.tuple.nonce,
        payloadDigest: mutation.payloadDigest ?? v.tuple.payloadDigest,
        signatureHex: v.signature,
        expectedPublicKeyHex: expectedPubHex,
      }),
      false,
      JSON.stringify(mutation),
    );
  }
});

test("eip191SignDigest32 roundtrips through recovery (test-only signing)", () => {
  const kp = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const jwk = kp.privateKey.export({ format: "jwk" });
  const privHex = "0x" + Buffer.from(jwk.d, "base64url").toString("hex");
  const pub = kp.publicKey.export({ format: "der", type: "spki" });
  const pubHex = "0x" + Buffer.from(pub.subarray(-65)).toString("hex");
  const digest = Buffer.alloc(32, 9);
  const sig = eip191SignDigest32(digest, privHex);
  const recovered = eip191RecoverPublicKey(digest, sig);
  assert.ok(recovered !== null);
  assert.equal("0x" + Buffer.from(recovered).toString("hex"), pubHex);
  assert.equal(
    verifyRoleSignature({
      runId: "r", role: "buyer", tool: "t", nonce: "0x" + "0".repeat(32),
      payloadDigest: "0x" + "0".repeat(64),
      signatureHex: sig, // covers a DIFFERENT digest than the tuple → false
      expectedPublicKeyHex: pubHex,
    }),
    false,
  );
});
