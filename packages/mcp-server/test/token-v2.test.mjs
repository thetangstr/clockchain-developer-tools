// CLO-48: v:2 trial + claim tokens; v:1 demo tokens still work (LLD §5.3/§13/§14).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mintToken,
  verifyToken,
  mintTrialToken,
  verifyTrialToken,
  mintClaim,
  verifyClaim,
} from "../dist/token.js";

const SIGN = "transport-secret";
const PROMOTE = "promote-secret";

test("v:1 demo token still mints + verifies (backward compat, LLD §13)", () => {
  const { token, payload } = mintToken(SIGN, 3600, 1000);
  assert.equal(payload.v, 1);
  assert.equal(payload.tier, "demo");
  const r = verifyToken(SIGN, token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.tier, "demo");
});

test("a v:2 trial token does NOT verify as a v:1 demo token (and vice-versa)", () => {
  const trial = mintTrialToken(SIGN, { eph: "did:clockchain:eph:1", ch: "mcp" }, 3600, 1000);
  assert.equal(verifyToken(SIGN, trial.token, 1000).valid, false); // v1 verifier rejects v2
  const demo = mintToken(SIGN, 3600, 1000);
  assert.equal(verifyTrialToken(SIGN, demo.token, 1000).valid, false); // v2 verifier rejects v1
});

test("v:2 trial token carries eph + channel and verifies", () => {
  const { token, payload } = mintTrialToken(SIGN, { eph: "did:clockchain:eph:abc", ch: "web" }, 3600, 1000);
  assert.equal(payload.v, 2);
  assert.equal(payload.kind, "trial");
  assert.equal(payload.tier, "trial");
  assert.equal(payload.eph, "did:clockchain:eph:abc");
  assert.equal(payload.ch, "web");
  assert.ok(payload.jti);
  const r = verifyTrialToken(SIGN, token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.eph, "did:clockchain:eph:abc");
});

test("v:2 trial token expires", () => {
  const { token } = mintTrialToken(SIGN, { eph: "x", ch: "mcp" }, 100, 1000);
  assert.equal(verifyTrialToken(SIGN, token, 1101).valid, false);
});

test("claim token uses the DISTINCT promote secret (LLD §16)", () => {
  const { token, payload } = mintClaim(PROMOTE, { eph: "did:clockchain:eph:z", ch: "chatbot" }, 3600, 1000);
  assert.equal(payload.kind, "claim");
  assert.equal(verifyClaim(PROMOTE, token, 1000).valid, true);
  // signed with promote secret -> the transport signing secret must NOT verify it
  assert.equal(verifyClaim(SIGN, token, 1000).valid, false);
  // and a claim is not a trial token even under its own secret
  assert.equal(verifyTrialToken(PROMOTE, token, 1000).valid, false);
});

test("claim token round-trips eph + channel + expires + tamper-rejects", () => {
  const { token, payload } = mintClaim(PROMOTE, { eph: "did:clockchain:eph:q", ch: "mcp" }, 3600, 1000);
  const r = verifyClaim(PROMOTE, token, 1000);
  assert.equal(r.valid, true);
  assert.equal(r.payload.eph, payload.eph);
  assert.equal(r.payload.ch, "mcp");
  assert.equal(verifyClaim(PROMOTE, token, 5000).valid, false); // expired
  const forged = token.slice(0, -2) + "AA";
  assert.equal(verifyClaim(PROMOTE, forged, 1000).valid, false); // bad signature
});
