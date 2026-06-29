// Unit tests for self-serve signed tokens (pure, no port binding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mintToken, verifyToken, looksLikeSelfServe } from "../dist/token.js";

const SECRET = "unit-test-secret";

test("a freshly minted token verifies", () => {
  const { token, payload } = mintToken(SECRET, 3600, 1000);
  assert.ok(token.startsWith("cc_"));
  assert.equal(payload.tier, "demo");
  assert.equal(payload.exp, 1000 + 3600);
  const r = verifyToken(SECRET, token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.exp, 4600);
});

test("an expired token is rejected", () => {
  const { token } = mintToken(SECRET, 3600, 1000);
  const r = verifyToken(SECRET, token, 1000 + 3601);
  assert.equal(r.valid, false);
  assert.equal(r.reason, "expired");
});

test("a token signed with a different secret is rejected", () => {
  const { token } = mintToken(SECRET, 3600, 1000);
  const r = verifyToken("other-secret", token, 1000);
  assert.equal(r.valid, false);
  assert.equal(r.reason, "bad signature");
});

test("a tampered payload is rejected (signature no longer matches)", () => {
  const { token } = mintToken(SECRET, 3600, 1000);
  const [seg, sig] = token.slice(3).split(".");
  const forged = "cc_" + seg.slice(0, -2) + "AA" + "." + sig;
  assert.equal(verifyToken(SECRET, forged, 1000).valid, false);
});

test("garbage / wrong-shape inputs are rejected, never throw", () => {
  assert.equal(verifyToken(SECRET, "not-a-token", 1000).valid, false);
  assert.equal(verifyToken(SECRET, "cc_only", 1000).valid, false);
  assert.equal(verifyToken(SECRET, "", 1000).valid, false);
  assert.equal(verifyToken("", "cc_x.y", 1000).valid, false); // signing disabled
});

test("looksLikeSelfServe is a cheap structural pre-check", () => {
  assert.equal(looksLikeSelfServe("cc_abc.def"), true);
  assert.equal(looksLikeSelfServe("cc_no-dot"), false);
  assert.equal(looksLikeSelfServe("team-token"), false);
});

// --- per-user auth: distinct jti + optional sub ----------------------------------

test("each minted token carries a unique jti, so two mints are distinct", () => {
  const a = mintToken(SECRET, 3600, 1000);
  const b = mintToken(SECRET, 3600, 1000); // same secret, same second
  assert.equal(typeof a.payload.jti, "string");
  assert.ok(a.payload.jti.length > 0);
  assert.notEqual(a.payload.jti, b.payload.jti); // distinct identities
  assert.notEqual(a.token, b.token);             // therefore distinct tokens
  // jti survives a round-trip through verify
  const r = verifyToken(SECRET, a.token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.jti, a.payload.jti);
});

test("an injected jti is honored (deterministic for tests)", () => {
  const { payload } = mintToken(SECRET, 3600, 1000, undefined, "fixed-jti");
  assert.equal(payload.jti, "fixed-jti");
});

test("sub is optional: absent by default, embedded and verifiable when set", () => {
  assert.equal(mintToken(SECRET, 3600, 1000).payload.sub, undefined);
  const { token, payload } = mintToken(SECRET, 3600, 1000, "user@example.com");
  assert.equal(payload.sub, "user@example.com");
  const r = verifyToken(SECRET, token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.sub, "user@example.com");
});
