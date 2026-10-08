import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";

import { createHandshakeStateStore, __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { createV2InvitationService, createV2InvitationStore } from "../dist/agent-handshake/v2/invitation-store.js";
import { createV2Coordinator } from "../dist/agent-handshake/v2/coordinator.js";

// Multi-session hosting: N host containers each open their own ~120 s session on
// the shared relay, staggered. invite() must mint into a FREE session (valid,
// same host build, >= 30 s invitation runway, no initiator invitation yet, not
// reserved by a concurrent invite) instead of only the relay's "current" one.

const terms = {
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
};
const T0 = 1786337000000;
const repositorySha = "d".repeat(40);

function session(openedAtMs, overrides = {}) {
  const sessionId = overrides.sessionId ?? randomUUID();
  const sha = overrides.repositorySha ?? repositorySha;
  return {
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId,
    repositorySha: sha,
    kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git",
    relayUrl: "https://relay.example",
    createdAtMs: String(openedAtMs),
    invitationExpiresAtMs: String(openedAtMs + (overrides.invitationWindowMs ?? 120_000)),
    sessionDeadlineMs: String(openedAtMs + 600_000),
    sessionOpenedBlock: "6999",
    hostSessionKeyCertificate: {
      certificate: { schema: "clockchain.host-session-key/v1", rootKid: overrides.rootKid ?? "root-2026-08", sessionId, repositorySha: sha, sessionPublicKey: "ore80hj1AhLMNPybJXCL6XHyJ9OfmaYSXc4SA8Sk2Pw=", validFromMs: String(openedAtMs), validUntilMs: String(openedAtMs + 600000) },
      rootSignature: "a".repeat(88),
    },
    terms: overrides.terms ?? terms,
    externalBusinessActionPerformed: false,
  };
}

// A relay fake holding several sessions. `current` is the newest (relay rule).
function harness({ sessions, clock, listSessions = true, listThrows = false, delayMessagesMs = 0 }) {
  __resetHandshakeStateStore();
  const key = { kid: "role-2026-08", secret: randomBytes(32) };
  const bySession = new Map(sessions.map((item) => [item.sessionId, item]));
  const messages = new Map(sessions.map((item) => [item.sessionId, []]));
  const fetched = [];
  const state = { clock };
  const newest = () => [...sessions].sort((a, b) => Number(b.createdAtMs) - Number(a.createdAtMs))[0];
  const relay = {
    fetchDiscovery: async (sessionId) => {
      fetched.push(sessionId ?? "current");
      if (sessionId === undefined) return newest();
      const found = bySession.get(sessionId);
      if (!found) throw new Error("DISCOVERY_NOT_SET");
      return found;
    },
    getMessages: async ({ sessionId, after = "0" }) => {
      if (delayMessagesMs) await new Promise((resolve) => setTimeout(resolve, delayMessagesMs));
      const log = messages.get(sessionId) ?? [];
      return { messages: log.filter((m) => BigInt(m.seq) > BigInt(after)), ...(log.length ? { highestSeq: log.at(-1).seq } : {}) };
    },
    postMessage: async (input) => {
      const log = messages.get(input.sessionId);
      log.push({ seq: String(log.length + 1), body: input.body, kind: input.kind, role: input.role, senderKey: input.senderKey, sessionId: input.sessionId });
      return { ok: true, seq: String(log.length) };
    },
    getResult: async () => { throw new Error("pending"); },
  };
  if (listSessions) {
    relay.listSessions = async () => {
      if (listThrows) throw new Error("RELAY_NETWORK");
      return [...sessions]
        .sort((a, b) => Number(b.createdAtMs) - Number(a.createdAtMs))
        .map((item) => ({ sessionId: item.sessionId, startedAtMs: Number(item.createdAtMs), stage: item.stage ?? null }));
    };
  }
  const coordinator = createV2Coordinator({
    accessKeys: [key],
    activeAccessKey: key,
    invitationService: createV2InvitationService({ activeKey: key, verificationKeys: [key], store: createV2InvitationStore(), nowMs: () => state.clock }),
    relay,
    stateStore: createHandshakeStateStore({}),
    now: () => state.clock,
    recoverEip191Address: async () => "0x7564105e977516c53be337314c7e53838967bdac",
    registrationFundingReady: async () => true,
    resolveRegistration: async () => null,
    advanceTransitions: async () => [],
    nextWaitDefaultMs: 0,
    verifiedHelperPrefix: "node --verified-helper",
  });
  const invitationsOn = (sessionId) => (messages.get(sessionId) ?? []).filter((m) => m.kind === "agent_v2_invitation_created" && m.role === "initiator").length;
  return { coordinator, messages, fetched, state, invitationsOn };
}

const isTransient = (expectedRetryMs) => (error) =>
  error?.name === "V2TransientCoordinatorError" && (expectedRetryMs === undefined || error.retryAfterMs === expectedRetryMs);

test("two concurrent invites land in two different free sessions", async () => {
  // Three staggered hosts: opened 80 s, 40 s and 0 s ago at the invite moment.
  const now = T0 + 80_000;
  const sessions = [session(T0), session(T0 + 40_000), session(T0 + 80_000)];
  const h = harness({ sessions, clock: now, delayMessagesMs: 5 });
  const [a, b] = await Promise.all([h.coordinator.invite(terms), h.coordinator.invite(terms)]);
  assert.notEqual(a.sessionId, b.sessionId);
  for (const id of [a.sessionId, b.sessionId]) assert.equal(h.invitationsOn(id), 1);
  // Oldest free window first (keeps the freshest session for the next caller).
  assert.deepEqual(new Set([a.sessionId, b.sessionId]), new Set([sessions[0].sessionId, sessions[1].sessionId]));
});

test("a third concurrent invite takes the third session; a fourth is transient with a bounded hint", async () => {
  const now = T0 + 80_000;
  const sessions = [session(T0), session(T0 + 40_000), session(T0 + 80_000)];
  const h = harness({ sessions, clock: now, delayMessagesMs: 5 });
  const results = await Promise.allSettled([1, 2, 3, 4].map(() => h.coordinator.invite(terms)));
  const ok = results.filter((r) => r.status === "fulfilled").map((r) => r.value.sessionId);
  const failed = results.filter((r) => r.status === "rejected");
  assert.equal(new Set(ok).size, 3);
  assert.equal(failed.length, 1);
  assert.ok(isTransient()(failed[0].reason));
  assert.ok(failed[0].reason.retryAfterMs >= 5_000 && failed[0].reason.retryAfterMs <= 120_000);
  for (const s of sessions) assert.equal(h.invitationsOn(s.sessionId), 1);
});

test("sequential invites skip a session that already holds an invitation", async () => {
  const now = T0 + 50_000;
  const sessions = [session(T0), session(T0 + 50_000)];
  const h = harness({ sessions, clock: now });
  const first = await h.coordinator.invite(terms);
  assert.equal(first.sessionId, sessions[0].sessionId);
  const second = await h.coordinator.invite(terms);
  assert.equal(second.sessionId, sessions[1].sessionId);
  await assert.rejects(() => h.coordinator.invite(terms), isTransient());
});

test("a session with under 30 s of invitation runway is skipped in favour of a younger one", async () => {
  // Older session opened 95 s ago: 25 s left (< 30 s runway). Younger: 115 s left.
  const now = T0 + 95_000;
  const sessions = [session(T0), session(T0 + 90_000)];
  const h = harness({ sessions, clock: now });
  const invited = await h.coordinator.invite(terms);
  assert.equal(invited.sessionId, sessions[1].sessionId);
  assert.equal(h.invitationsOn(sessions[0].sessionId), 0);
});

test("foreign sessions on the open relay are never selected", async () => {
  const now = T0 + 60_000;
  const current = session(T0 + 60_000);
  // Occupy current so only the foreign candidates could be "free".
  const foreign = [
    session(T0 + 10_000, { repositorySha: "e".repeat(40) }),             // other host build
    session(T0 + 20_000, { invitationWindowMs: 500_000 }),              // wider window than ours
    session(T0 + 30_000, { rootKid: "root-evil" }),                     // other host root
    session(T0 + 40_000, { terms: { ...terms, validForSeconds: "60" } }), // other published terms
  ];
  const h = harness({ sessions: [current, ...foreign], clock: now });
  const first = await h.coordinator.invite(terms);
  assert.equal(first.sessionId, current.sessionId);
  await assert.rejects(() => h.coordinator.invite(terms), isTransient());
  for (const f of foreign) assert.equal(h.invitationsOn(f.sessionId), 0);
});

test("sessions that finished (stage set) or are too old are not even fetched", async () => {
  const now = T0 + 700_000;
  const old = session(T0);
  const finished = { ...session(T0 + 650_000), stage: "CERTIFIED" };
  const current = session(T0 + 690_000);
  const h = harness({ sessions: [old, finished, current], clock: now });
  const invited = await h.coordinator.invite(terms);
  assert.equal(invited.sessionId, current.sessionId);
  assert.ok(!h.fetched.includes(old.sessionId));
  assert.ok(!h.fetched.includes(finished.sessionId));
});

test("without listSessions (or if listing fails) invite() keeps the single-session behaviour", async () => {
  for (const variant of [{ listSessions: false }, { listThrows: true }]) {
    const now = T0 + 50_000;
    const sessions = [session(T0), session(T0 + 50_000)];
    const h = harness({ sessions, clock: now, ...variant });
    const first = await h.coordinator.invite(terms);
    // Only "current" (the newest) is used.
    assert.equal(first.sessionId, sessions[1].sessionId);
    await assert.rejects(() => h.coordinator.invite(terms), isTransient());
    assert.equal(h.invitationsOn(sessions[0].sessionId), 0);
  }
});

test("a failed mint releases the reservation so the session can be retried", async () => {
  const now = T0 + 10_000;
  const sessions = [session(T0)];
  const h = harness({ sessions, clock: now });
  // First attempt fails at create time (commit guard): clock jumps into the dead tail during create.
  // Simulate by inviting with a mismatched terms object -> terms mismatch is thrown BEFORE selection,
  // so instead break post(): make the relay refuse the first postMessage.
  const relayPost = h.messages.get(sessions[0].sessionId);
  let refuse = true;
  const originalPush = relayPost.push.bind(relayPost);
  relayPost.push = (...items) => { if (refuse) { refuse = false; throw new Error("RELAY_REFUSED"); } return originalPush(...items); };
  await assert.rejects(() => h.coordinator.invite(terms));
  // Not stuck "reserved": the next invite can use the same session.
  const retry = await h.coordinator.invite(terms);
  assert.equal(retry.sessionId, sessions[0].sessionId);
});

test("the published-terms mismatch is still reported from the current session", async () => {
  const now = T0 + 10_000;
  const h = harness({ sessions: [session(T0)], clock: now });
  await assert.rejects(
    () => h.coordinator.invite({ ...terms, validForSeconds: "60" }),
    (error) => error?.name === "V2TermsMismatchError",
  );
});
