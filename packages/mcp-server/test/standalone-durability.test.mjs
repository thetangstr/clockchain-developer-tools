// Spec B2 for Standalone: sessions and csha_ handles survive a restart. Each "restart"
// throws the coordinator and public server away and builds new ones from the same state
// directory, sharing only the ledger (which is external) and the clock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getAddress } from "viem";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { BODY_RETENTION_MS } from "../dist/standalone-handshake/session-store.js";
import { validTerms } from "./helpers/standalone-fixtures.mjs";
import { fakeLedger, newSessionKey, recoverLocally, verifyAndSign } from "./helpers/standalone-signer.mjs";

const T = Date.parse("2026-09-14T00:00:00.000Z");
const MIN = 60_000;
const ACCEPT = "application/json, text/event-stream";

const worlds = [];
test.afterEach(async () => {
  while (worlds.length > 0) await worlds.pop().stop();
});

function world() {
  const dir = mkdtempSync(join(tmpdir(), "standalone-durable-"));
  const ledger = fakeLedger();
  const keys = { initiator: newSessionKey(), responder: newSessionKey() };
  const clock = { now: T };
  let live;

  async function boot(overrides = {}) {
    if (live) await live.stop();
    live = undefined;
    const coordinator = createStandaloneCoordinator({
      client: overrides.client ?? ledger,
      now: () => clock.now,
      recoverEip191Address: overrides.recover ?? recoverLocally,
      nextPollMs: 5,
      stateDir: dir,
      coalesceMs: 20,
    });
    const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args), stateDir: dir, env: {} });
    const server = createServer((req, res) => { void handler(req, res); });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
    const call = async (name, args) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return JSON.parse(JSON.parse(data ? data.slice(5) : text).result.content[0].text);
    };
    live = {
      coordinator,
      call,
      // A deploy: in-flight requests die with the process; nothing is flushed on purpose
      // beyond what the store already wrote synchronously.
      async stop() {
        const closed = new Promise((resolve) => server.close(resolve));
        server.closeAllConnections();
        await closed;
        coordinator.close();
      },
    };
    return live;
  }

  async function readiness(call, role, overrides = {}) {
    const account = keys[role];
    const prepared = await call("readiness_prepare", { sessionKeyAddress: getAddress(account.address), accountableParty: "Acme", statement: "Authorized for Acme." });
    return {
      sessionKeyAddress: getAddress(account.address),
      identity: null,
      authorityStatement: { accountableParty: "Acme", statement: "Authorized for Acme." },
      authoritySignatureHex: await verifyAndSign(account, prepared),
      capabilityManifest: { dataHandlingClass: "confidential", purpose: validTerms().purpose },
      ...overrides,
    };
  }

  async function consent(call, role, access) {
    const step = await call("handshake_next", { access, waitMs: 0, playbookVersion: 99 });
    assert.equal(step.action, "sign", JSON.stringify(step));
    const signed = await call("consent_sign", { access, signatureHex: await verifyAndSign(keys[role], step.sign) });
    assert.equal(signed.error, undefined, JSON.stringify(signed));
  }

  const handle = { dir, ledger, clock, keys, boot, readiness, consent, stop: async () => { if (live) await live.stop(); live = undefined; } };
  worlds.push(handle);
  return handle;
}

const entries = (ledger, suffix) => [...ledger.entries.values()].filter((entry) => entry.assetReferenceId.endsWith(suffix));

test("restart before acceptance: the invitation and the initiator's handle survive; a mid-accept restart is simply retryable", async () => {
  const w = world();
  let { call, coordinator } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const a = invite.roleAccess;

  // Restart with a Responder whose accept dies mid-evaluation (the checklist never completes).
  ({ call, coordinator } = await w.boot({ recover: () => new Promise(() => {}) }));
  const responderReadiness = await w.readiness(call, "responder");
  void coordinator.invoke("handshake_accept_invitation", { invitation: invite.invitation, readiness: responderReadiness });
  await new Promise((resolve) => setTimeout(resolve, 20));

  ({ call } = await w.boot());
  // The interrupted attempt was rolled back: the invitation is claimable and the retry works.
  assert.equal((await call("handshake_preview_invitation", { invitation: invite.invitation })).sessionId, invite.sessionId);
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: responderReadiness });
  assert.equal(accept.stage, "ready");
  assert.equal((await call("handshake_next", { access: a, waitMs: 0 })).action, "sign", "the pre-restart csha_ handle still works");
  const timeline = await call("handshake_timeline", { access: a });
  assert.ok(timeline.events.some((event) => event.type === "attempt_interrupted"));
});

test("restart mid-signing: both sides resume with their existing csha_ handles and complete", async () => {
  const w = world();
  let { call } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const [a, b] = [invite.roleAccess, accept.roleAccess];
  await w.consent(call, "initiator", a);

  ({ call } = await w.boot());
  const waiting = await call("handshake_next", { access: a, waitMs: 0 });
  assert.equal(waiting.action, "wait");
  assert.equal(waiting.roleAccess, a);
  await w.consent(call, "responder", b);
  const opened = await call("channel_open", { access: b });
  assert.deepEqual(opened.anchors.map((anchor) => anchor.kind), ["terms-readiness", "consent", "open"]);
  assert.equal((await call("handshake_next", { access: a, waitMs: 0 })).action, "respond");
});

test("restart with an open channel: messages, cursors and anchors carry over, and nothing is anchored twice", async () => {
  const w = world();
  let { call } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const [a, b] = [invite.roleAccess, accept.roleAccess];
  await w.consent(call, "initiator", a);
  await w.consent(call, "responder", b);
  await call("channel_open", { access: a });
  await call("channel_send", { access: a, kind: "question", body: "Tuesday?" });
  const first = await call("handshake_next", { access: b, waitMs: 0 });
  assert.equal(first.cursor, 1);
  await call("channel_send", { access: b, kind: "proposal", body: "Tuesday 10:00." });
  await call("channel_send", { access: a, kind: "question", body: "Confirmed?" });

  ({ call } = await w.boot());
  const resumed = await call("handshake_next", { access: b, waitMs: 0, cursor: first.cursor });
  assert.deepEqual(resumed.messages.map((message) => [message.seq, message.body]), [[3, "Confirmed?"]]);
  assert.equal(resumed.cursor, 3);
  assert.equal((await call("handshake_next", { access: b, waitMs: 0, cursor: resumed.cursor })).action, "wait");
  // A second open is refused as already open; the opening anchors exist once.
  assert.equal((await call("channel_open", { access: b })).error, "ALREADY_OPEN");
  assert.equal(w.ledger.entries.size, 3);
  await call("channel_close", { access: b });
  assert.equal(entries(w.ledger, ":closure").length, 1);
});

test("a closure pinned before a restart is re-anchored byte-identically after it: one closure anchor", async () => {
  const w = world();
  let failClosure = true;
  const flaky = {
    ...w.ledger,
    async log(input) {
      if (failClosure && input.assetReferenceId.endsWith(":closure")) {
        const error = new Error("ledger unavailable");
        error.name = "TimeoutError";
        throw error;
      }
      return w.ledger.log(input);
    },
  };
  let { call } = await w.boot({ client: flaky });
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const [a, b] = [invite.roleAccess, accept.roleAccess];
  await w.consent(call, "initiator", a);
  await w.consent(call, "responder", b);
  await call("channel_open", { access: a });
  assert.equal((await call("channel_close", { access: a })).retryable, true);

  w.clock.now += 2 * MIN;
  failClosure = false;
  ({ call } = await w.boot({ client: flaky }));
  const closed = await call("channel_close", { access: a });
  assert.equal(closed.outcome, "closed");
  assert.equal(entries(w.ledger, ":closure").length, 1);
  const pinnedFile = readFileSync(join(w.dir, "sessions", `${invite.sessionId}.json`), "utf8");
  assert.equal(JSON.parse(pinnedFile).value.pendingClosure, undefined, "the pin is cleared once the close completes");
  assert.equal((await call("handshake_next", { access: b, waitMs: 0 })).action, "closed");
});

test("a reply deadline that passed while the server was down ends the session as stalled once, with one anchor", async () => {
  const w = world();
  let { call } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const [a, b] = [invite.roleAccess, accept.roleAccess];
  await w.consent(call, "initiator", a);
  await w.consent(call, "responder", b);
  await call("channel_open", { access: a });
  await call("channel_send", { access: a, kind: "question", body: "Tuesday?" });

  w.clock.now = T + 30 * MIN; // down for half an hour
  ({ call } = await w.boot());
  for (const access of [a, b]) {
    const ended = await call("handshake_next", { access, waitMs: 0, cursor: access === a ? 0 : 1 });
    assert.equal(ended.action, "stalled");
    assert.equal(ended.reason, "STALLED_REPLY_BY_RESPONDER");
  }
  ({ call } = await w.boot());
  assert.equal((await call("handshake_next", { access: a, waitMs: 0 })).action, "stalled");
  assert.equal(entries(w.ledger, ":closure-stalled").length, 1);
  const timeline = await call("handshake_timeline", { access: a });
  assert.equal(timeline.events.filter((event) => event.type === "turn_timeout").length, 1);
});

test("at rest: no access tokens, invitation secrets, handles or webhook secrets are stored in the clear", async () => {
  const w = world();
  const { call } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const secret = JSON.parse(Buffer.from(invite.invitation.slice(5), "base64url").toString("utf8")).secret;
  const sessionFile = readFileSync(join(w.dir, "sessions", `${invite.sessionId}.json`), "utf8");
  const everything = [sessionFile, readFileSync(join(w.dir, "role-handles.json"), "utf8")].join("\n");
  assert.equal(everything.includes(secret), false, "invitation secret");
  assert.equal(everything.includes(invite.roleAccess), false, "initiator handle");
  assert.equal(everything.includes(accept.roleAccess), false, "responder handle");
  assert.equal(/sat_[A-Za-z0-9_-]{20,}/.test(sessionFile), false, "raw access tokens");
});

test("message bodies are deleted 24 hours after the session ends; digests and seqs stay", async () => {
  const w = world();
  let { call } = await w.boot();
  const invite = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await w.readiness(call, "responder") });
  const [a, b] = [invite.roleAccess, accept.roleAccess];
  await w.consent(call, "initiator", a);
  await w.consent(call, "responder", b);
  await call("channel_open", { access: a });
  await call("channel_send", { access: a, kind: "question", body: "The PELICAN plan?" });
  await call("channel_close", { access: a });
  const file = join(w.dir, "sessions", `${invite.sessionId}.json`);
  assert.ok(readFileSync(file, "utf8").includes("PELICAN"), "kept while the session is fresh");

  w.clock.now += BODY_RETENTION_MS - 1;
  ({ call } = await w.boot());
  assert.ok(readFileSync(file, "utf8").includes("PELICAN"), "kept until 24h after it ended");
  w.clock.now += 1;
  ({ call } = await w.boot());
  const stored = readFileSync(file, "utf8");
  assert.equal(stored.includes("PELICAN"), false);
  const message = JSON.parse(stored).value.messages[0];
  assert.equal(message.body, null);
  assert.match(message.bodyDigest, /^[0-9a-f]{64}$/);
  assert.equal(message.seq, 1);
});

test("one unreadable session file is logged and skipped; the others still load", async (t) => {
  const errors = t.mock.method(console, "error", () => {});
  const w = world();
  let { call } = await w.boot();
  const good = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  const bad = await call("handshake_invite", { ...validTerms(), readiness: await w.readiness(call, "initiator") });
  // Both the file and its last-good backup are garbage (with a valid .bak it would recover).
  writeFileSync(join(w.dir, "sessions", `${bad.sessionId}.json`), "garbage", { mode: 0o600 });
  writeFileSync(join(w.dir, "sessions", `${bad.sessionId}.json.bak`), "garbage", { mode: 0o600 });
  ({ call } = await w.boot());
  assert.equal((await call("handshake_next", { access: good.roleAccess, waitMs: 0 })).action, "wait");
  const events = errors.mock.calls.map((c) => { try { return JSON.parse(c.arguments[0]).event; } catch { return ""; } });
  assert.ok(events.includes("handshake_state_session_unreadable"));
  assert.ok(readdirSync(join(w.dir, "sessions")).includes(`${bad.sessionId}.json`), "left in place for an operator");
});
