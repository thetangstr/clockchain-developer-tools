import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { ed25519PublicKeyDer, fingerprint, verifySignature } from "../dist/shadow/lib/keys.js";
import { AgentKeyError } from "../dist/agent-keys/book.js";
import { jwtBearerProof } from "../dist/agent-keys/proof.js";
import { jwkThumbprint, makeAgentKey, signJwt } from "./helpers/agent-key.mjs";

const AUD = "https://mcp.clockchain.test/oauth/token";
const NOW = 1_800_000_000;
const proof = jwtBearerProof();
const check = (assertion, audience = AUD, nowSec = NOW) => proof.verify({ assertion, audience, nowSec });
const b64url = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

// Asserts invalid_client, and that the reason echoes no 20-character slice of the assertion.
function refused(assertion, opts = {}) {
  let caught;
  try {
    check(assertion, opts.audience, opts.nowSec);
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof AgentKeyError, `expected AgentKeyError, got ${caught}`);
  assert.equal(caught.code, "invalid_client");
  assert.ok(caught.message.length > 0 && caught.message !== "invalid_client");
  if (typeof assertion === "string") {
    for (let i = 0; i + 20 <= assertion.length; i++) {
      assert.ok(!caught.message.includes(assertion.slice(i, i + 20)), "the reason echoes the assertion");
    }
  }
  return caught;
}

test("a valid assertion yields the agent's canonical public key, jti and exp", () => {
  const agent = makeAgentKey();
  const out = check(agent.assertion(AUD, { iat: NOW, exp: NOW + 300, jti: "jti-0001" }));
  assert.deepEqual(out, { publicKeyPem: agent.publicKeyPem, jti: "jti-0001", exp: NOW + 300 });
  assert.ok(ed25519PublicKeyDer(out.publicKeyPem));
  assert.equal(fingerprint(out.publicKeyPem), agent.fingerprint);
});

test("the helper's thumbprint is the RFC 7638 value and its hash signatures verify", () => {
  // RFC 8037 appendix A.3 test vector.
  assert.equal(
    jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }),
    "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
  );
  const agent = makeAgentKey();
  const hash = "ab".repeat(32);
  const sig = agent.signHash(hash);
  assert.match(sig, /^[A-Za-z0-9+/]{86}==$/);
  assert.equal(verifySignature(agent.publicKeyPem, hash, sig), true);
});

test("accepts aud as an array containing the audience, and clock skew up to 60 s", () => {
  const agent = makeAgentKey();
  check(agent.assertion(AUD, { iat: NOW, claims: { aud: ["https://other.test/token", AUD] } }));
  check(agent.assertion(AUD, { iat: NOW + 60 }));
  check(agent.assertion(AUD, { iat: NOW - 299, exp: NOW + 1 }));
});

test("refuses the wrong audience", () => {
  const agent = makeAgentKey();
  refused(agent.assertion("https://staging.clockchain.test/oauth/token", { iat: NOW }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { aud: ["https://other.test/token"] } }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { aud: `${AUD}/` } }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { aud: undefined } }));
});

test("refuses a lifetime over 300 s, a future iat and an expired assertion", () => {
  const agent = makeAgentKey();
  refused(agent.assertion(AUD, { iat: NOW, exp: NOW + 301 }));
  refused(agent.assertion(AUD, { iat: NOW + 61 }));
  refused(agent.assertion(AUD, { iat: NOW - 300, exp: NOW - 1 }));
  refused(agent.assertion(AUD, { iat: NOW - 300, exp: NOW }));
  refused(agent.assertion(AUD, { iat: NOW, exp: NOW }));
  refused(agent.assertion(AUD, { iat: NOW + 0.5 }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { exp: String(NOW + 300) } }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { iat: undefined } }));
});

test("refuses alg none, HS256 and other algorithms", () => {
  const agent = makeAgentKey();
  const claims = { iss: agent.thumbprint, sub: agent.thumbprint, aud: AUD, iat: NOW, exp: NOW + 300, jti: "jti-0001" };
  const unsigned = `${b64url({ alg: "none", typ: "JWT", jwk: agent.jwk })}.${b64url(claims)}`;
  refused(`${unsigned}.`);
  refused(agent.assertion(AUD, { iat: NOW, header: { alg: "none" } }));
  const hsInput = `${b64url({ alg: "HS256", typ: "JWT", jwk: agent.jwk })}.${b64url(claims)}`;
  refused(`${hsInput}.${createHmac("sha256", agent.jwk.x).update(hsInput).digest("base64url")}`);
  refused(agent.assertion(AUD, { iat: NOW, header: { alg: "HS256" } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { alg: "ES256" } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { alg: undefined } }));
});

test("refuses an iss or sub that is not the key's thumbprint", () => {
  const agent = makeAgentKey();
  const other = makeAgentKey();
  refused(agent.assertion(AUD, { iat: NOW, claims: { iss: other.thumbprint } }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { sub: other.thumbprint } }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { iss: agent.fingerprint, sub: agent.fingerprint } }));
});

test("refuses a tampered payload, a swapped key and a bad signature", () => {
  const agent = makeAgentKey();
  const other = makeAgentKey();
  const good = agent.assertion(AUD, { iat: NOW });
  const [h, , s] = good.split(".");
  const claims = JSON.parse(Buffer.from(good.split(".")[1], "base64url"));
  refused(`${h}.${b64url({ ...claims, jti: "jti-forged" })}.${s}`);
  // The other agent's key in the header, still signed by the first key.
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: other.jwk }, claims: { iss: other.thumbprint, sub: other.thumbprint } }));
  const sig = Buffer.from(s, "base64url");
  sig[0] ^= 1;
  refused(`${h}.${good.split(".")[1]}.${sig.toString("base64url")}`);
});

test("refuses a header without a usable public jwk", () => {
  const agent = makeAgentKey();
  const { privateKey } = generateKeyPairSync("ed25519");
  const privJwk = privateKey.export({ format: "jwk" });
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: undefined } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: { ...agent.jwk, d: privJwk.d } } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: { ...agent.jwk, crv: "X25519" } } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: { ...agent.jwk, kty: "EC" } } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: { ...agent.jwk, x: agent.jwk.x.slice(0, 42) } } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: { ...agent.jwk, x: `${agent.jwk.x}=` } } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { jwk: "not an object" } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { crit: ["exp"] } }));
  refused(agent.assertion(AUD, { iat: NOW, header: { typ: "at+jwt" } }));
});

test("refuses a jti outside 8 to 128 characters", () => {
  const agent = makeAgentKey();
  check(agent.assertion(AUD, { iat: NOW, jti: "x".repeat(8) }));
  check(agent.assertion(AUD, { iat: NOW, jti: "x".repeat(128) }));
  refused(agent.assertion(AUD, { iat: NOW, jti: "x".repeat(7) }));
  refused(agent.assertion(AUD, { iat: NOW, jti: "x".repeat(129) }));
  refused(agent.assertion(AUD, { iat: NOW, claims: { jti: 12345678 } }));
});

test("refuses assertions that do not parse strictly", () => {
  const agent = makeAgentKey();
  const good = agent.assertion(AUD, { iat: NOW });
  const [h, p, s] = good.split(".");
  refused(`${h}.${p}`);
  refused(`${good}.${s}`);
  refused(`${h}=.${p}.${s}`);
  refused(`${h}.${p}.${s}=`);
  refused(`${h.replace(/-/g, "+").replace(/_/g, "/")}+/.${p}.${s}`);
  refused(` ${good}`);
  refused(`${h}.${p}.${s.slice(0, -2)}`);
  refused(agent.signJwt([], { iss: "x" }));
  refused(agent.signJwt({ alg: "EdDSA", typ: "JWT", jwk: agent.jwk }, [1, 2]));
  refused(`${b64url("not json")}.${p}.${s}`);
  refused("");
  refused(`${good}${"A".repeat(16 * 1024)}`);
  for (const bad of [undefined, null, 42, {}]) refused(bad);
  // A signature whose last character differs only in its 4 spare bits decodes to the same bytes; it is still refused.
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const alt = `${s.slice(0, -1)}${ALPHABET[ALPHABET.indexOf(s.at(-1)) ^ 1]}`;
  assert.ok(Buffer.from(alt, "base64url").equals(Buffer.from(s, "base64url")));
  refused(`${h}.${p}.${alt}`);
});

test("a key signed by someone else cannot reuse the signing helper's output", () => {
  // Sanity: a signature by an unrelated private key over correct claims for agent's jwk fails.
  const agent = makeAgentKey();
  const { privateKey } = generateKeyPairSync("ed25519");
  const claims = { iss: agent.thumbprint, sub: agent.thumbprint, aud: AUD, iat: NOW, exp: NOW + 300, jti: "jti-0001" };
  refused(signJwt(privateKey, { alg: "EdDSA", typ: "JWT", jwk: agent.jwk }, claims));
});
