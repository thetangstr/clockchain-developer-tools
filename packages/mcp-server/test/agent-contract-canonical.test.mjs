import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { canonicalDigest, canonicalJson } from "../dist/agent-contract/canonical.js";

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "agent-contract-canonical-digest-vectors.json",
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

test("canonical vectors from the travel T0 reproduce byte-for-byte", () => {
  assert.equal(fixture.schema, "agent-contract.canonical-digest-vectors/v1");
  assert.ok(fixture.vectors.length >= 10, "expected the full vector set");
  for (const vector of fixture.vectors) {
    assert.equal(canonicalJson(vector.input), vector.canonical);
    assert.equal(canonicalDigest(vector.input), vector.digest);
  }
});

test("undefined object properties are dropped; unrepresentable values throw", () => {
  assert.equal(canonicalJson({ a: 1, skip: undefined }), '{"a":1}');
  assert.equal(canonicalJson({ a: () => 1 }), "{}");
  assert.throws(() => canonicalJson([undefined]), /unrepresentable/);
  assert.throws(() => canonicalJson(undefined), /unrepresentable/);
  assert.throws(() => canonicalJson(() => 1), /unrepresentable/);
  assert.throws(() => canonicalJson(Number.NaN), /non-finite/);
  assert.throws(() => canonicalJson(Infinity), /non-finite/);
});
