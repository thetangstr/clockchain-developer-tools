import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";

import {
  AGENT_HANDSHAKE_ROLE_TOOLS,
  mintV2RoleAccess,
  verifyV2RoleAccess,
} from "../dist/agent-handshake/v2/access.js";

const active = { kid: "role-2026-08", secret: randomBytes(32) };
const previous = { kid: "role-2026-07", secret: randomBytes(32) };
const sessionId = randomUUID();
const statementDigest = "a".repeat(64);
const nbfMs = "1786337000000";
const expMs = "1786337600000";

function mint(overrides = {}) {
  return mintV2RoleAccess({
    key: active,
    sessionId,
    role: "initiator",
    statementDigest,
    allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
    nbfMs,
    expMs,
    jti: randomUUID(),
    ...overrides,
  });
}

function verify(access, overrides = {}) {
  return verifyV2RoleAccess(access, {
    keys: [active, previous],
    nowMs: Number(nbfMs) + 1,
    expectedSessionId: sessionId,
    expectedRole: "initiator",
    expectedStatementDigest: statementDigest,
    expectedExpMs: expMs,
    requiredTool: "agent_handshake_join",
    ...overrides,
  });
}

test("role access uses canonical unpadded HS256 capabilities and derives its principal only after verification", () => {
  const access = mint();
  assert.equal(access.split(".").length, 2);
  assert.equal(access.includes("="), false);
  const checked = verify(access);
  assert.equal(checked.payload.alg, "HS256");
  assert.equal(checked.payload.typ, "clockchain-agent-handshake-role-access");
  assert.equal(checked.payload.iss, "https://mcp.clockchain.network");
  assert.equal(checked.payload.aud, "clockchain-agent-handshake");
  assert.equal(checked.payload.expMs, expMs);
  assert.match(checked.principal, /^[0-9a-f]{64}$/);
  assert.deepEqual(checked.payload.allowedTools, AGENT_HANDSHAKE_ROLE_TOOLS);
});

test("access verification enforces key rotation, binding, tool scope, time, and secret strength", () => {
  const access = mint();
  assert.throws(() => verify(access.slice(0, -1) + (access.endsWith("a") ? "b" : "a")));
  const [payloadSegment, signatureSegment] = access.split(".");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const signatureBytes = Buffer.from(signatureSegment, "base64url");
  const alias = [...alphabet]
    .map((character) => signatureSegment.slice(0, -1) + character)
    .find((candidate) => candidate !== signatureSegment && Buffer.from(candidate, "base64url").equals(signatureBytes));
  assert.ok(alias, "fixture must expose a non-canonical base64url alias");
  assert.throws(() => verify(`${payloadSegment}.${alias}`));
  assert.throws(() => verify(`${access}=`));
  assert.throws(() => verify(access, { expectedSessionId: randomUUID() }));
  assert.throws(() => verify(access, { expectedRole: "responder" }));
  assert.throws(() => verify(access, { expectedStatementDigest: "b".repeat(64) }));
  assert.throws(() => verify(access, { expectedExpMs: String(Number(expMs) + 1) }));
  assert.throws(() => verify(access, { requiredTool: "agent_handshake_invite" }));
  assert.throws(() => verify(access, { nowMs: Number(nbfMs) - 1001 }));
  assert.throws(() => verify(access, { nowMs: Number(expMs) }));
  assert.throws(() => verify(access, { keys: [{ kid: active.kid, secret: randomBytes(32) }] }));
  assert.throws(() => mint({ key: { kid: "weak", secret: randomBytes(31) } }));
  assert.throws(() => mint({ allowedTools: [...AGENT_HANDSHAKE_ROLE_TOOLS, "getTime"] }));
});

test("unexpired previous-key capabilities verify but minting requires the active key", () => {
  const access = mint({ key: previous });
  assert.equal(verify(access).payload.kid, previous.kid);
  assert.throws(() => verify(access, { keys: [active] }));
});
