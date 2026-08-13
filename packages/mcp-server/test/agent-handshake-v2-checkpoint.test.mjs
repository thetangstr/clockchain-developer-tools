import assert from "node:assert/strict";
import test from "node:test";

import {
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  normalizeV2CommitmentCheckpoint,
} from "../dist/agent-handshake/v2/commitment-checkpoint.js";

const checkpoint = {
  schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
  version: "1",
  protocol: "clockchain.agent-handshake/v2",
  sessionId: "11111111-2222-4333-8444-555555555555",
  role: "initiator",
  artifactType: "proposal",
  artifactDigest: "a".repeat(64),
  sequence: "1",
  previousCheckpointDigest: null,
  issuedAtMs: "1786337000001",
  expiresAtMs: "1786337090000",
  signerAddress: "0x7564105e977516c53be337314c7e53838967bdac",
  signature: {
    address: "0x7564105e977516c53be337314c7e53838967bdac",
    algorithm: "eip191",
    value: `0x${"1".repeat(128)}1b`,
  },
};

test("v2 commitment checkpoint has exact canonical bytes and digest", () => {
  const normalized = normalizeV2CommitmentCheckpoint(checkpoint);
  assert.deepEqual(normalized, checkpoint);
  assert.equal(commitmentCheckpointSigningBytes(normalized).includes(Buffer.from("signature")), false);
  assert.equal(commitmentCheckpointDigest(normalized), "3b9926e75208be65a71ba62bf1a8486f638d5d47fbe50472ffcd2a29b20c7ded");
  assert.equal(commitmentCheckpointDigest({ ...normalized }), commitmentCheckpointDigest(normalized));
});

test("v2 commitment checkpoint rejects a numeric version before relay publication", () => {
  assert.throws(() => normalizeV2CommitmentCheckpoint({ ...checkpoint, version: 1 }), /commitment checkpoint/i);
});

test("v2 commitment checkpoint rejects schema, role, chain, signer, time, and extra-key drift", () => {
  for (const candidate of [
    { ...checkpoint, role: "payer" },
    { ...checkpoint, artifactType: "acknowledgment" },
    { ...checkpoint, sequence: "0" },
    { ...checkpoint, previousCheckpointDigest: "b".repeat(64) },
    { ...checkpoint, expiresAtMs: checkpoint.issuedAtMs },
    { ...checkpoint, signerAddress: checkpoint.signerAddress.toUpperCase() },
    { ...checkpoint, signature: { ...checkpoint.signature, address: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9" } },
    { ...checkpoint, extra: true },
  ]) {
    assert.throws(() => normalizeV2CommitmentCheckpoint(candidate), /commitment checkpoint/i);
  }
});
