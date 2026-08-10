import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  mintHandshakeInvitation,
  mintHandshakeSessionToken,
  verifyHandshakeInvitation,
  verifyHandshakeSessionToken,
} from "../dist/token.js";
import {
  AgentHandshakeInvitationError,
  createAgentHandshakeInvitationService,
  createAgentHandshakeInvitationStore,
} from "../dist/agent-handshake/invitation-store.js";
import { registerTools } from "../dist/tools.js";

const SECRET = "invitation-secret-for-tests";
const SESSION_ID = "22222222-3333-4444-8555-666666666666";
const DIGEST = "a".repeat(64);
const TERMS = { reference: "NS-1847", statement: "Two agents may communicate about NS-1847.", validForMinutes: "45" };

test("invitation and scoped transport tokens are signed, exact, and distinct", () => {
  const invitation = mintHandshakeInvitation(SECRET, {
    exp: 2000,
    iat: 1000,
    invitationId: SESSION_ID,
    jti: "33333333-4444-4555-8666-777777777777",
    statementDigest: DIGEST,
    terms: TERMS,
  });
  const verified = verifyHandshakeInvitation(SECRET, invitation.token, 1500);
  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload.terms, TERMS);
  assert.equal(verifyHandshakeInvitation(SECRET, `${invitation.token}x`, 1500).valid, false);
  assert.equal(verifyHandshakeInvitation(SECRET, invitation.token, 2000).valid, false);
  assert.equal(invitation.token.includes(SESSION_ID), false);
});

test("an invitation exchanges once for a responder-only principal", async () => {
  const store = createAgentHandshakeInvitationStore();
  const service = createAgentHandshakeInvitationService({
    fetchDiscovery: async () => ({ expiresAtMs: "2000000", sessionId: SESSION_ID }),
    joinBaseUrl: "https://clockchain-research.vercel.app/handshake/join",
    nowSec: () => 1000,
    secret: SECRET,
    store,
  });
  const terms = { reference: "NS-1847", statement: "Two agents may communicate about NS-1847.", validForMinutes: 45 };
  const created = await service.invite(terms);
  assert.match(created.joinUrl, /^https:\/\/clockchain-research\.vercel\.app\/handshake\/join#capability=/);
  const capability = new URL(created.joinUrl).hash.slice("#capability=".length);
  const [first, second] = await Promise.allSettled([
    service.exchange(capability),
    service.exchange(capability),
  ]);
  assert.deepEqual([first.status, second.status].sort(), ["fulfilled", "rejected"]);
  const fulfilled = first.status === "fulfilled" ? first.value : second.value;
  const verified = verifyHandshakeSessionToken(SECRET, fulfilled.token, 1000);
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.role, "responder");
  assert.equal(verified.payload.invitationId, SESSION_ID);
  assert.deepEqual(fulfilled.terms, TERMS);
  assert.notEqual(verified.payload.jti, verifyHandshakeInvitation(SECRET, capability, 1000).payload.jti);
  const rejected = first.status === "rejected" ? first.reason : second.reason;
  assert.ok(rejected instanceof AgentHandshakeInvitationError);
  assert.equal(rejected.code, "INVITATION_UNAVAILABLE");
});

test("consumed invitation hashes survive restart without persisting raw tokens", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-invitations-"));
  const path = join(directory, "invitations.json");
  const store = createAgentHandshakeInvitationStore({ path });
  const service = createAgentHandshakeInvitationService({
    fetchDiscovery: async () => ({ expiresAtMs: "2000000", sessionId: SESSION_ID }),
    joinBaseUrl: "https://example.test/join",
    nowSec: () => 1000,
    secret: SECRET,
    store,
  });
  const created = await service.invite({ reference: "R", statement: "Two agents agree to communicate.", validForMinutes: 30 });
  const capability = new URL(created.joinUrl).hash.slice("#capability=".length);
  await service.exchange(capability);
  const bytes = await readFile(path, "utf8");
  assert.equal(bytes.includes(capability), false);
  assert.equal(bytes.includes("cc_"), false);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const restarted = createAgentHandshakeInvitationService({
    fetchDiscovery: async () => ({ expiresAtMs: "2000000", sessionId: SESSION_ID }),
    joinBaseUrl: "https://example.test/join",
    nowSec: () => 1000,
    secret: SECRET,
    store: createAgentHandshakeInvitationStore({ path }),
  });
  await assert.rejects(() => restarted.exchange(capability), { code: "INVITATION_UNAVAILABLE" });
});

test("exchange rejects wrong current session with one fixed public error", async () => {
  const service = createAgentHandshakeInvitationService({
    fetchDiscovery: async () => ({ expiresAtMs: "2000000", sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }),
    joinBaseUrl: "https://example.test/join",
    nowSec: () => 1000,
    secret: SECRET,
    store: createAgentHandshakeInvitationStore(),
  });
  const invitation = mintHandshakeInvitation(SECRET, {
    exp: 2000, iat: 1000, invitationId: SESSION_ID,
    jti: "33333333-4444-4555-8666-777777777777", statementDigest: DIGEST, terms: TERMS,
  });
  await assert.rejects(() => service.exchange(invitation.token), {
    code: "INVITATION_UNAVAILABLE",
  });
});

test("invite tool delegates exact generic terms without exposing a capability input", async () => {
  const registrations = {};
  const terms = { reference: "NS-1847", statement: "Two agents may communicate about NS-1847.", validForMinutes: 45 };
  let received;
  registerTools(
    { registerTool(name, meta, handler) { registrations[name] = { handler, meta }; } },
    { apiKey: "k", clientId: "c", endpoint: "https://example.test", walletId: "w" },
    {
      agentHandshakeCoordinator: {},
      agentHandshakeInvitationService: { async invite(value) { received = value; return { invitationId: SESSION_ID }; } },
      handshakeCoordinator: {},
    },
  );
  assert.deepEqual(Object.keys(registrations.agent_handshake_invite.meta.inputSchema), ["terms"]);
  const result = await registrations.agent_handshake_invite.handler({ terms });
  assert.deepEqual(received, terms);
  assert.match(result.content[0].text, new RegExp(SESSION_ID));
});

test("a scoped responder credential cannot cross role, statement, session, tool, or invitation boundaries", async () => {
  const registrations = {};
  const calls = [];
  const terms = { reference: "NS-1847", statement: "Two agents may communicate about NS-1847.", validForMinutes: 45 };
  const scope = mintHandshakeSessionToken(SECRET, {
    exp: 2000,
    iat: 1000,
    invitationId: SESSION_ID,
    jti: "44444444-5555-4666-8777-888888888888",
    statementDigest: (await import("../dist/agent-handshake/protocol.js")).agentHandshakeStatementDigest(terms),
  }).payload;
  const agentCoordinator = {
    async status(sessionId) { calls.push(["status", sessionId]); return { ok: true }; },
    async join(role, invitationId, value) { calls.push(["join", role, invitationId, value]); return { ok: true }; },
    async next(sessionId, role) { calls.push(["next", sessionId, role]); return { ok: true }; },
    async submit(sessionId, role) { calls.push(["submit", sessionId, role]); return { ok: true }; },
    async getCertificate(sessionId) { calls.push(["certificate", sessionId]); return { ok: true }; },
  };
  registerTools(
    { registerTool(name, meta, handler) { registrations[name] = { handler, meta }; } },
    { apiKey: "k", clientId: "c", endpoint: "https://example.test", walletId: "w" },
    {
      agentHandshakeCoordinator: agentCoordinator,
      agentHandshakeInvitationService: { async invite() { calls.push(["invite"]); return {}; } },
      agentHandshakeScope: scope,
      handshakeCoordinator: {},
    },
  );

  await registrations.agent_handshake_join.handler({ invitationId: SESSION_ID, role: "responder", terms });
  await registrations.agent_handshake_status.handler({ sessionId: SESSION_ID });
  assert.equal(calls.length, 2);

  const denied = [
    await registrations.agent_handshake_join.handler({ invitationId: SESSION_ID, role: "initiator", terms }),
    await registrations.agent_handshake_join.handler({ invitationId: SESSION_ID, role: "responder", terms: { ...terms, statement: "Different." } }),
    await registrations.agent_handshake_next.handler({ sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", role: "responder" }),
    await registrations.agent_handshake_next.handler({ sessionId: SESSION_ID, role: "initiator" }),
    await registrations.agent_handshake_invite.handler({ terms }),
    await registrations.get_time.handler({}),
  ];
  assert.equal(calls.length, 2);
  for (const result of denied) {
    assert.equal(result.isError, true);
    assert.equal(JSON.parse(result.content[0].text).error, "HANDSHAKE_SCOPE_DENIED");
  }
});
