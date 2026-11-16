import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { AgentKeyError } from "../dist/agent-keys/book.js";
import { jwkThumbprintOfPem, verifyDpopProof } from "../dist/agent-keys/dpop.js";
import { jwtBearerProof } from "../dist/agent-keys/proof.js";
import { jwkThumbprint, makeAgentKey, signJwt } from "./helpers/agent-key.mjs";

const HTU = "https://mcp.clockchain.test/shadow/mcp";
const NOW = 1_800_000_000;
const TOKEN = "header.payload.signature-of-an-access-token";
const sha = (s) => createHash("sha256").update(s).digest("base64url");
const check = (proof, opts = {}) => verifyDpopProof({ proof, htm: "POST", htu: HTU, nowSec: NOW, ...opts });

// Asserts invalid_dpop_proof, and that the reason echoes no 20-character slice of the proof.
function refused(proof, opts = {}) {
  let caught;
  try {
    check(proof, opts);
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof AgentKeyError, `expected AgentKeyError, got ${caught}`);
  assert.equal(caught.code, "invalid_dpop_proof");
  assert.ok(caught.message.length > 0 && caught.message !== "invalid_dpop_proof");
  const texts = Array.isArray(proof) ? proof : [proof];
  for (const text of texts) {
    if (typeof text !== "string") continue;
    for (let i = 0; i + 20 <= text.length; i++) assert.ok(!caught.message.includes(text.slice(i, i + 20)), "the reason echoes the proof");
  }
  return caught;
}

test("a valid proof without an access token yields the key's thumbprint, jti, iat and replay entry", () => {
  const agent = makeAgentKey();
  const out = check(agent.dpop("POST", HTU, { iat: NOW, jti: "proof-0001" }));
  assert.equal(out.jkt, jwkThumbprint(agent.jwk));
  assert.equal(out.jkt, agent.thumbprint);
  assert.equal(out.jti, "proof-0001");
  assert.equal(out.iat, NOW);
  assert.equal(out.replayKey, sha(`${agent.thumbprint}:proof-0001`));
  assert.match(out.replayKey, /^[A-Za-z0-9_-]{1,64}$/);
  assert.equal(out.replayExp, NOW + 61);
});

test("a valid proof with an access token needs a matching ath; without one, ath is ignored", () => {
  const agent = makeAgentKey();
  assert.equal(check(agent.dpop("POST", HTU, { iat: NOW, accessToken: TOKEN }), { accessToken: TOKEN }).jkt, agent.thumbprint);
  // At the token endpoint (no access token) a stray ath is ignored.
  check(agent.dpop("POST", HTU, { iat: NOW, claims: { ath: "anything" } }));
  // A nonce is ignored (no DPoP nonces, A4).
  check(agent.dpop("POST", HTU, { iat: NOW, claims: { nonce: "n-1" } }));
});

test("the thumbprint of the agent's PEM is its JWK thumbprint", () => {
  const agent = makeAgentKey();
  assert.equal(jwkThumbprintOfPem(agent.publicKeyPem), agent.thumbprint);
});

test("rule 1: refuses a missing, empty, repeated, non-string or oversized header", () => {
  const agent = makeAgentKey();
  const good = agent.dpop("POST", HTU, { iat: NOW });
  refused(undefined);
  refused("");
  refused([good]);
  refused([good, agent.dpop("POST", HTU, { iat: NOW })]);
  refused(`${good}, ${agent.dpop("POST", HTU, { iat: NOW })}`);
  refused(42);
  refused(agent.dpop("POST", HTU, { iat: NOW, claims: { pad: "x".repeat(8 * 1024) } }));
});

test("rule 2: refuses a proof that is not three canonical base64url segments", () => {
  const agent = makeAgentKey();
  const good = agent.dpop("POST", HTU, { iat: NOW });
  const [h, p, s] = good.split(".");
  refused(`${h}.${p}`);
  refused(`${good}.${s}`);
  refused(`${h}=.${p}.${s}`);
  refused(`${h}.${p}.${s}=`);
  refused(` ${good}`);
  refused(agent.signJwt({ alg: "EdDSA", typ: "dpop+jwt", jwk: agent.jwk }, [1, 2]));
});

test("rule 3: refuses another typ or alg, crit, and a jwk that is not a public Ed25519 key", () => {
  const agent = makeAgentKey();
  const d = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }).d;
  const p = (header) => agent.dpop("POST", HTU, { iat: NOW, header });
  refused(p({ typ: "JWT" }));
  refused(p({ typ: "DPoP+JWT" }));
  refused(p({ typ: undefined }));
  refused(p({ alg: "ES256" }));
  refused(p({ alg: "none" }));
  refused(p({ crit: ["htu"] }));
  refused(p({ jwk: undefined }));
  refused(p({ jwk: { ...agent.jwk, d } }));
  refused(p({ jwk: { ...agent.jwk, crv: "X25519" } }));
  refused(p({ jwk: { ...agent.jwk, kty: "EC" } }));
  refused(p({ jwk: { ...agent.jwk, x: agent.jwk.x.slice(0, 42) } }));
});

test("rule 4: refuses a bad signature, a tampered payload and a key that did not sign", () => {
  const agent = makeAgentKey();
  const other = makeAgentKey();
  const good = agent.dpop("POST", HTU, { iat: NOW });
  const [h, p, s] = good.split(".");
  const sig = Buffer.from(s, "base64url");
  sig[0] ^= 1;
  refused(`${h}.${p}.${sig.toString("base64url")}`);
  const claims = JSON.parse(Buffer.from(p, "base64url"));
  refused(`${h}.${Buffer.from(JSON.stringify({ ...claims, htu: "https://evil.test/" })).toString("base64url")}.${s}`);
  refused(agent.dpop("POST", HTU, { iat: NOW, header: { jwk: other.jwk } }));
  const { privateKey } = generateKeyPairSync("ed25519");
  refused(signJwt(privateKey, { alg: "EdDSA", typ: "dpop+jwt", jwk: agent.jwk }, claims));
});

test("rule 5: refuses a jti outside 8 to 128 characters and another method", () => {
  const agent = makeAgentKey();
  check(agent.dpop("POST", HTU, { iat: NOW, jti: "x".repeat(8) }));
  check(agent.dpop("POST", HTU, { iat: NOW, jti: "x".repeat(128) }));
  refused(agent.dpop("POST", HTU, { iat: NOW, jti: "x".repeat(7) }));
  refused(agent.dpop("POST", HTU, { iat: NOW, jti: "x".repeat(129) }));
  refused(agent.dpop("POST", HTU, { iat: NOW, claims: { jti: 12345678 } }));
  refused(agent.dpop("GET", HTU, { iat: NOW }));
  refused(agent.dpop("post", HTU, { iat: NOW }));
  refused(agent.dpop(undefined, HTU, { iat: NOW }));
});

test("rule 6: htu must be the expected URL, with any query or fragment cut off", () => {
  const agent = makeAgentKey();
  check(agent.dpop("POST", `${HTU}?session=1`, { iat: NOW }));
  check(agent.dpop("POST", `${HTU}#x`, { iat: NOW }));
  refused(agent.dpop("POST", "https://mcp.clockchain.test/mcp", { iat: NOW }));
  refused(agent.dpop("POST", `${HTU}/`, { iat: NOW }));
  refused(agent.dpop("POST", "http://mcp.clockchain.test/shadow/mcp", { iat: NOW }));
  refused(agent.dpop("POST", undefined, { iat: NOW }));
});

test("rule 7: iat must be whole seconds within 60 s of now", () => {
  const agent = makeAgentKey();
  check(agent.dpop("POST", HTU, { iat: NOW - 60 }));
  check(agent.dpop("POST", HTU, { iat: NOW + 60 }));
  refused(agent.dpop("POST", HTU, { iat: NOW - 61 }));
  refused(agent.dpop("POST", HTU, { iat: NOW - 120 }));
  refused(agent.dpop("POST", HTU, { iat: NOW + 61 }));
  refused(agent.dpop("POST", HTU, { iat: NOW + 0.5 }));
  refused(agent.dpop("POST", HTU, { claims: { iat: String(NOW) } }));
});

test("rule 8: with an access token, ath must be its hash", () => {
  const agent = makeAgentKey();
  refused(agent.dpop("POST", HTU, { iat: NOW }), { accessToken: TOKEN });
  refused(agent.dpop("POST", HTU, { iat: NOW, accessToken: `${TOKEN}x` }), { accessToken: TOKEN });
  refused(agent.dpop("POST", HTU, { iat: NOW, claims: { ath: 1 } }), { accessToken: TOKEN });
});

test("a nowSec that is not whole seconds throws, in the DPoP check and the client assertion check", () => {
  const agent = makeAgentKey();
  for (const nowSec of [NaN, NOW + 0.5, undefined]) {
    assert.throws(() => check(agent.dpop("POST", HTU, { iat: NOW }), { nowSec }), (e) => !(e instanceof AgentKeyError) && /whole seconds/.test(e.message));
    assert.throws(
      () => jwtBearerProof().verify({ assertion: agent.assertion(HTU, { iat: NOW }), audience: HTU, nowSec }),
      (e) => !(e instanceof AgentKeyError) && /whole seconds/.test(e.message),
    );
  }
});
