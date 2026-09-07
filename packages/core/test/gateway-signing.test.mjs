// Gateway request-signing scheme: locks the canonical string + HMAC so the signer (ClockchainClient) and the
// verifier (anchoring-gateway/gateway.mjs) can never drift apart. The hardcoded vector below is the shared
// contract — if either side changes the formula, this fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import {
  gatewayCanonical,
  computeGatewaySignature,
  buildGatewaySignatureHeaders,
} from "../dist/gateway-signing.js";

// Fixed vector (independently reproduced by gateway.mjs' formula and selftest.mjs).
const V = {
  secret: "test-secret",
  method: "POST",
  path: "/log",
  ts: "1700000000",
  nonce: "00112233445566778899aabbccddeeff",
  body: '{"a":1}',
  bodyHash: "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862",
  signature: "7Ev9pILEBFhcI99k88ET9pgqj5um5KBhi+ARuSAgvnc=",
};

test("canonical string is METHOD\\nPATH\\nTS\\nNONCE\\nsha256hex(body)", () => {
  assert.equal(
    gatewayCanonical(V.method, V.path, V.ts, V.nonce, V.body),
    `POST\n/log\n${V.ts}\n${V.nonce}\n${V.bodyHash}`,
  );
});

test("signature matches the locked vector", () => {
  assert.equal(
    computeGatewaySignature(V.secret, V.method, V.path, V.ts, V.nonce, V.body),
    V.signature,
  );
});

test("interop: matches an independent replica of the gateway's verify formula", () => {
  // This is exactly what anchoring-gateway/gateway.mjs verifySignature recomputes.
  const bodyHash = createHash("sha256").update(V.body, "utf8").digest("hex");
  const canonical = `${V.method.toUpperCase()}\n${V.path}\n${V.ts}\n${V.nonce}\n${bodyHash}`;
  const gatewayExpected = createHmac("sha256", V.secret).update(canonical, "utf8").digest("base64");
  assert.equal(computeGatewaySignature(V.secret, V.method, V.path, V.ts, V.nonce, V.body), gatewayExpected);
});

test("empty body hashes to the sha256 of the empty string (GETs)", () => {
  const emptyHash = createHash("sha256").update("", "utf8").digest("hex");
  assert.match(gatewayCanonical("GET", "/getTime", V.ts, V.nonce, ""), new RegExp(`${emptyHash}$`));
});

test("tamper: any change to method/path/body/ts/nonce changes the signature", () => {
  const base = computeGatewaySignature(V.secret, V.method, V.path, V.ts, V.nonce, V.body);
  assert.notEqual(base, computeGatewaySignature(V.secret, "GET", V.path, V.ts, V.nonce, V.body));
  assert.notEqual(base, computeGatewaySignature(V.secret, V.method, "/log?x=1", V.ts, V.nonce, V.body));
  assert.notEqual(base, computeGatewaySignature(V.secret, V.method, V.path, V.ts, V.nonce, '{"a":2}'));
  assert.notEqual(base, computeGatewaySignature(V.secret, V.method, V.path, "1700000001", V.nonce, V.body));
  assert.notEqual(base, computeGatewaySignature(V.secret, V.method, V.path, V.ts, "ffffffffffffffffffffffffffffffff", V.body));
  assert.notEqual(base, computeGatewaySignature("other-secret", V.method, V.path, V.ts, V.nonce, V.body));
});

test("buildGatewaySignatureHeaders produces a valid, self-consistent header set", () => {
  const h = buildGatewaySignatureHeaders(V.secret, "kid-1", "POST", "/log", V.body);
  assert.equal(h["x-cc-key-id"], "kid-1");
  assert.match(h["x-cc-nonce"], /^[0-9a-f]{32}$/);
  assert.match(h["x-cc-timestamp"], /^\d+$/);
  const expected = computeGatewaySignature(V.secret, "POST", "/log", h["x-cc-timestamp"], h["x-cc-nonce"], V.body);
  assert.equal(h["x-cc-signature"], expected);
  // Fresh nonce per call.
  const h2 = buildGatewaySignatureHeaders(V.secret, "kid-1", "POST", "/log", V.body);
  assert.notEqual(h["x-cc-nonce"], h2["x-cc-nonce"]);
});
