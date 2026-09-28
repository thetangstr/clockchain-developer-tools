// Active facilitation (F1-F4) on a fake clock: stall reports, resume, turn deadlines, webhooks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import { verifyWebhook } from "@clockchain/keeper";

import { listStandaloneSessions } from "../dist/standalone-handshake/coordinator.js";
import { createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { standaloneCanonicalRecord } from "../dist/standalone-handshake/protocol.js";
import { validTerms } from "./helpers/standalone-fixtures.mjs";
import { harness } from "./helpers/standalone-harness.mjs";

// The fake ledger's block time: channel clocks start here, so the test clock starts here too.
const T = Date.parse("2026-09-14T00:00:00.000Z");
const MIN = 60_000;
const SERVER_SECRET = "whsec_" + Buffer.from("standalone-test-server-secret").toString("base64");
const HOOK = "https://hooks.example.com/clockchain/turn";
const limits = (extra) => ({ channelLimits: { ...validTerms().channelLimits, ...extra } });

function webhookHarness(options = {}) {
  const posts = [];
  const fetchFn = async (url, init) => {
    posts.push({ url, headers: init.headers, body: init.body });
    return { status: options.status ?? 204 };
  };
  const h = harness({ nowMs: T, coordinator: { webhooks: { serverSecret: SERVER_SECRET, ssrf: {}, fetchFn, ...(options.webhooks ?? {}) }, ...(options.coordinator ?? {}) } });
  return { h, posts };
}

async function withHook(h, role, overrides = {}) {
  return { ...(await h.readiness(role, overrides)), notify: { webhookUrl: HOOK } };
}

async function toConsentPending(h) {
  const invite = await h.invite();
  const accept = await h.accept(invite.invitation);
  await h.consent("initiator", invite.initiatorAccess);
  return { invite, accept, a: invite.initiatorAccess, b: accept.responderAccess };
}

async function toOpen(h) {
  const { invite, accept, a, b } = await toConsentPending(h);
  await h.consent("responder", b);
  await h.instance.invoke("channel_open", { access: a });
  return { invite, accept, a, b };
}

const types = async (h, access) => (await h.instance.invoke("handshake_timeline", { access })).events.map((event) => event.type);

// ---------------------------------------------------------------------------
// F1 stall detection
// ---------------------------------------------------------------------------

test("F1: a silent counterparty is reported to the waiting party after stallAfterMs, and the report clears when it returns", async () => {
  const h = harness({ nowMs: T });
  const { a, b } = await toConsentPending(h);
  h.setNow(T + 3 * MIN - 1);
  assert.equal((await h.next(a)).counterpartyStalled, undefined);

  h.setNow(T + 3 * MIN);
  const waiting = await h.next(a);
  assert.equal(waiting.action, "wait");
  assert.deepEqual({ ...waiting.counterpartyStalled, options: undefined }, {
    sinceMs: 3 * MIN,
    lastSeenAt: new Date(T).toISOString(),
    pendingAction: "CONSENT",
    turnDeadlineAt: new Date(T + 10 * MIN).toISOString(),
    options: undefined,
  });
  assert.deepEqual(waiting.counterpartyStalled.options.map((option) => option.option), ["wait", "nudge"]);
  assert.match(waiting.tellYourUser, /silent for 3 minute\(s\) on its turn to sign consent/);
  await h.next(a);
  assert.equal((await types(h, a)).filter((type) => type === "stalled").length, 1, "one stalled event per turn");

  // The silent party checks in: resumed, and the waiting party no longer sees a stall.
  assert.equal((await h.next(b)).action, "sign");
  assert.equal((await types(h, a)).at(-1), "resumed");
  assert.equal((await h.next(a)).counterpartyStalled, undefined);
});

test("F1: on an open channel the options include close and revoke; the pending party itself is never told it stalled", async () => {
  const h = harness({ nowMs: T });
  const { a, b } = await toOpen(h);
  await h.instance.invoke("channel_send", { access: a, kind: "question", body: "hello?" });
  h.setNow(T + 4 * MIN);
  const waiting = await h.next(a, { cursor: 0 });
  assert.deepEqual(waiting.counterpartyStalled.options.map((option) => option.option), ["wait", "nudge", "close", "revoke"]);
  assert.equal(waiting.counterpartyStalled.pendingAction, "REPLY");
  const pending = await h.next(b);
  assert.equal(pending.action, "respond");
  assert.equal(pending.counterpartyStalled, undefined);
});

// ---------------------------------------------------------------------------
// F2 resume
// ---------------------------------------------------------------------------

test("F2: after a gap, or with resume: true, handshake_next carries a catchUp of what changed (never bodies)", async () => {
  const h = harness({ nowMs: T });
  const { a, b } = await toOpen(h);
  assert.equal((await h.next(b)).catchUp, undefined, "no catchUp on a prompt call");
  await h.instance.invoke("channel_send", { access: a, kind: "question", body: "Secret PELICAN plan?" });
  h.setNow(T + 3 * MIN);
  const resumed = await h.next(b);
  assert.equal(resumed.action, "respond");
  assert.deepEqual(resumed.catchUp.changes, { message: 1 });
  assert.equal(resumed.catchUp.since, new Date(T).toISOString());
  assert.equal(resumed.catchUp.stage, "open");
  assert.equal(resumed.catchUp.nextAction, "respond");
  assert.match(resumed.catchUp.nextStep, /channel_send/);
  assert.equal(JSON.stringify(resumed.catchUp).includes("PELICAN"), false);

  const asked = await h.next(b, { cursor: 1, resume: true });
  assert.deepEqual(asked.catchUp.changes, {});
  assert.equal(asked.catchUp.nextAction, "wait");
});

// ---------------------------------------------------------------------------
// F3 turn deadlines
// ---------------------------------------------------------------------------

async function assertStalledForBoth(h, accesses, reason, { anchored }) {
  const results = [];
  for (const access of accesses) {
    const result = await h.next(access);
    assert.equal(result.action, "stalled");
    assert.equal(result.stage, "stalled");
    assert.equal(result.reason, reason);
    assert.equal(result.terminal.outcome, "stalled");
    assert.equal(typeof result.tellYourUser, "string");
    assert.match(result.nextStep, /handshake_invite/);
    assert.equal(result.terminal.anchors.some((anchor) => anchor.kind === "stall-closure"), anchored);
    results.push(result);
  }
  return results;
}

test("F3: consent that is never signed ends as stalled for both, naming who did not act", async () => {
  const h = harness({ nowMs: T });
  const { a, b } = await toConsentPending(h);
  h.setNow(T + 10 * MIN);
  const [initiator, responder] = await assertStalledForBoth(h, [a, b], "STALLED_CONSENT_BY_RESPONDER", { anchored: false });
  assert.equal(initiator.tellYourUser, "The handshake ended because the other agent did not sign consent in time.");
  assert.equal(responder.tellYourUser, "The handshake ended because I did not sign consent in time.");
  assert.equal(h.ledger.entries.size, 0, "nothing was ever anchored before open");
});

test("F3: shared turns (neither consent, open) stall as BY_BOTH", async () => {
  const neither = harness({ nowMs: T });
  const invite = await neither.invite();
  const accept = await neither.accept(invite.invitation);
  neither.setNow(T + 10 * MIN);
  await assertStalledForBoth(neither, [invite.initiatorAccess, accept.responderAccess], "STALLED_CONSENT_BY_BOTH", { anchored: false });

  const unopened = harness({ nowMs: T });
  const { a, b } = await toConsentPending(unopened);
  await unopened.consent("responder", b);
  unopened.setNow(T + 10 * MIN);
  const [result] = await assertStalledForBoth(unopened, [a, b], "STALLED_OPEN_BY_BOTH", { anchored: false });
  assert.equal(result.tellYourUser, "The handshake ended because neither agent managed to open the channel in time.");
});

test("F3: a missed first message or reply stalls an open channel and anchors a stalled closure once", async () => {
  const h = harness({ nowMs: T });
  const { a, b, invite } = await toOpen(h);
  h.setNow(T + 10 * MIN);
  const [first] = await assertStalledForBoth(h, [a, b], "STALLED_SEND_BY_INITIATOR", { anchored: true });
  const closures = [...h.ledger.entries.values()].filter((entry) => entry.assetReferenceId.endsWith(":closure-stalled"));
  assert.equal(closures.length, 1, "both callers share one anchor");
  const expected = standaloneCanonicalRecord({
    schema: "clockchain.standalone-handshake-closure/v1",
    protocol: "clockchain.standalone-handshake/v1",
    sessionId: invite.sessionId,
    outcome: "stalled",
    byRole: "initiator",
    closedAtMs: String(T + 10 * MIN),
    externalBusinessActionPerformed: false,
  }).digest;
  assert.equal(closures[0].assetHash, expected);
  assert.equal(first.terminal.anchors.find((anchor) => anchor.kind === "stall-closure").digest, expected);
  assert.deepEqual((await types(h, a)).slice(-2), ["turn_timeout", "close"]);
  await assert.rejects(() => h.instance.invoke("channel_close", { access: a }), (error) => error.reason === "STALLED");

  const replying = harness({ nowMs: T });
  const open = await toOpen(replying);
  replying.setNow(T + 2 * MIN);
  await replying.instance.invoke("channel_send", { access: open.a, kind: "question", body: "Tuesday?" });
  replying.setNow(T + 12 * MIN - 1);
  assert.equal((await replying.next(open.a, { cursor: 0 })).action, "wait");
  replying.setNow(T + 12 * MIN);
  await assertStalledForBoth(replying, [open.a, open.b], "STALLED_REPLY_BY_RESPONDER", { anchored: true });
});

test("F3: per-session windows are bounded, apply, and never outlast the channel", async () => {
  const bounded = harness({ nowMs: T });
  const readiness = await bounded.readiness("initiator");
  for (const bad of [{ replyDeadlineSeconds: "59" }, { turnDeadlineSeconds: "3601" }]) {
    await assert.rejects(() => bounded.instance.invoke("handshake_invite", { ...validTerms(limits(bad)), readiness }));
  }

  const quick = harness({ nowMs: T, terms: limits({ replyDeadlineSeconds: "120" }) });
  const q = await toOpen(quick);
  quick.setNow(T + 2 * MIN);
  assert.equal((await quick.next(q.a)).reason, "STALLED_SEND_BY_INITIATOR");

  // A reply window equal to the channel duration: expiry, not a stall, ends it.
  const short = harness({ nowMs: T, terms: limits({ durationSeconds: "600" }) });
  const s = await toOpen(short);
  short.setNow(T + 10 * MIN);
  const ended = await short.next(s.a);
  assert.equal(ended.action, "expired");
  assert.equal(ended.reason, "DURATION_ELAPSED");
});

test("F3 vs abandoned: one deadline rule, the earlier wins, and a session ends only once", async () => {
  // Pre-open deadline earlier than the turn deadline: abandoned.
  const early = harness({ nowMs: T, coordinator: { preOpenTtlMs: 5 * MIN } });
  const e = await toConsentPending(early);
  early.setNow(T + 5 * MIN);
  assert.equal((await early.next(e.a)).reason, "NOT_OPENED_BEFORE_DEADLINE");

  // Turn deadline earlier: stalled.
  const late = harness({ nowMs: T, coordinator: { preOpenTtlMs: 60 * MIN } });
  const l = await toConsentPending(late);
  late.setNow(T + 10 * MIN);
  assert.equal((await late.next(l.a)).reason, "STALLED_CONSENT_BY_RESPONDER");
  // Much later the outcome is unchanged and there is exactly one terminal event.
  late.setNow(T + 120 * MIN);
  assert.equal((await late.next(l.b)).reason, "STALLED_CONSENT_BY_RESPONDER");
  const terminal = (await types(late, l.a)).filter((type) => ["turn_timeout", "abandon", "expire"].includes(type));
  assert.deepEqual(terminal, ["turn_timeout"]);

  // An exact tie keeps the whole-session rule: abandoned.
  const tie = harness({ nowMs: T, coordinator: { preOpenTtlMs: 10 * MIN } });
  const invite = await tie.invite();
  const accept = await tie.accept(invite.invitation);
  tie.setNow(T + 10 * MIN);
  assert.equal((await tie.next(accept.responderAccess)).action, "abandoned");

  // Before acceptance only the invitation TTL applies: abandoned, never stalled.
  const unaccepted = harness({ nowMs: T });
  const u = await unaccepted.invite();
  unaccepted.setNow(T + 60 * MIN);
  assert.equal((await unaccepted.next(u.initiatorAccess)).reason, "INVITATION_NOT_ACCEPTED");
});

// ---------------------------------------------------------------------------
// F4 webhooks and handshake_nudge
// ---------------------------------------------------------------------------

test("F4: a quiet role's turn is pushed once, signed, with no bodies, secrets or URLs", async () => {
  const { h, posts } = webhookHarness();
  const invite = await h.instance.invoke("handshake_invite", { ...validTerms(), readiness: await withHook(h, "initiator") });
  assert.equal(invite.notify.registered, true);
  const secret = invite.notify.webhookSecret;
  assert.match(secret, /^whsec_/);
  const accept = await h.accept(invite.invitation);
  await h.instance.drainNotices();
  assert.equal(posts.length, 0, "the initiator was seen moments ago: not quiet, no push");

  h.setNow(T + MIN);
  await h.consent("responder", accept.responderAccess);
  await h.instance.drainNotices();
  assert.equal(posts.length, 1);
  const [post] = posts;
  assert.equal(post.url, HOOK);
  assert.deepEqual(JSON.parse(post.body), {
    type: "clockchain.standalone-handshake.turn",
    sessionId: invite.sessionId,
    role: "initiator",
    pendingAction: "CONSENT",
    trigger: "turn",
    callTool: "handshake_next",
  });
  assert.ok(verifyWebhook({ id: post.headers["webhook-id"], timestampSec: Number(post.headers["webhook-timestamp"]), body: post.body, secret, signatureHeader: post.headers["webhook-signature"] }));

  // Same turn, another trigger: nothing more is pushed for the turn.
  await h.instance.invoke("handshake_status", { access: accept.responderAccess });
  await h.instance.drainNotices();
  assert.equal(posts.length, 1);
  const notifyEvents = (await h.instance.invoke("handshake_timeline", { access: invite.initiatorAccess })).events.filter((event) => event.type === "notify");
  assert.deepEqual(notifyEvents.map((event) => [event.role, event.trigger, event.ok, event.status]), [["initiator", "turn", true, 204]]);

  // The webhook and its secret are shown to nobody else.
  const seen = JSON.stringify([
    await h.next(accept.responderAccess),
    await h.instance.invoke("handshake_status", { access: accept.responderAccess }),
    await h.instance.invoke("handshake_timeline", { access: accept.responderAccess }),
    await h.instance.invoke("handshake_timeline", { access: invite.initiatorAccess }),
    listStandaloneSessions(h.instance),
  ]);
  for (const leak of ["hooks.example.com", secret, SERVER_SECRET]) assert.equal(seen.includes(leak), false, `leaked ${leak}`);
});

test("F4: https-only, no private or loopback targets, and a refused webhook never burns the invitation", async () => {
  const { h } = webhookHarness();
  const readiness = await h.readiness("initiator");
  for (const url of ["http://hooks.example.com/x", "https://127.0.0.1/x", "https://10.1.2.3/x", "https://169.254.169.254/latest", "https://[::1]/x", "https://localhost/x", "https://user:pw@hooks.example.com/x", "not a url"]) {
    await assert.rejects(() => h.instance.invoke("handshake_invite", { ...validTerms(), readiness: { ...readiness, notify: { webhookUrl: url } } }), (error) => error.reason === "WEBHOOK_REFUSED", url);
  }
  const invite = await h.invite();
  const privateHook = { ...(await h.readiness("responder")), notify: { webhookUrl: "https://192.168.1.10/hook" } };
  await assert.rejects(() => h.instance.invoke("handshake_accept_invitation", { invitation: invite.invitation, readiness: privateHook }), (error) => error.reason === "WEBHOOK_REFUSED");
  assert.equal((await h.accept(invite.invitation)).stage, "ready", "the invitation survived the refused webhook");

  // Without a signing secret the server has no push channel to offer.
  const plain = harness({ nowMs: T });
  const hooked = await withHook(plain, "initiator");
  await assert.rejects(() => plain.instance.invoke("handshake_invite", { ...validTerms(), readiness: hooked }), (error) => error.reason === "WEBHOOKS_UNAVAILABLE");
});

test("F4: a hostname that resolves to a private address is refused at delivery (DNS-pinned) and the failure is recorded", async () => {
  const { h } = webhookHarness({ webhooks: { fetchFn: undefined, resolver: async () => [{ address: "10.0.0.7", family: 4 }] } });
  // The hostname passes the registration check; at delivery it resolves to a private address.
  const invite = await h.instance.invoke("handshake_invite", { ...validTerms(), readiness: await h.readiness("initiator") });
  const accept = await h.instance.invoke("handshake_accept_invitation", { invitation: invite.invitation, readiness: await withHook(h, "responder") });
  await h.consent("initiator", invite.initiatorAccess);
  h.setNow(T + 4 * MIN);
  const nudge = await h.instance.invoke("handshake_nudge", { access: invite.initiatorAccess });
  assert.equal(nudge.pushed, true);
  assert.equal(nudge.delivery.ok, false);
  const events = (await h.instance.invoke("handshake_timeline", { access: invite.initiatorAccess })).events;
  assert.deepEqual(events.filter((event) => event.type === "notify").map((event) => [event.role, event.trigger, event.ok]), [["responder", "nudge", false]]);
  assert.ok(accept.notify.registered);
});

test("handshake_nudge: once per turn, only on the counterparty's turn, recorded, and shown to the nudged party", async () => {
  const h = harness({ nowMs: T });
  const { a, b } = await toConsentPending(h);
  await assert.rejects(() => h.instance.invoke("handshake_nudge", { access: b }), (error) => error.reason === "NOT_THEIR_TURN");
  const nudge = await h.instance.invoke("handshake_nudge", { access: a });
  assert.deepEqual([nudge.nudged, nudge.toRole, nudge.pendingAction, nudge.pushed], [true, "responder", "CONSENT", false]);
  assert.match(nudge.note, /No push channel exists/);
  await assert.rejects(() => h.instance.invoke("handshake_nudge", { access: a }), (error) => error.reason === "NUDGE_RATE_LIMITED");
  const told = await h.next(b);
  assert.deepEqual(told.nudged.byRole, "initiator");
  assert.equal((await h.next(b)).nudged, undefined, "shown once");
  assert.ok((await types(h, a)).includes("nudged"));

  // A new turn allows a new nudge.
  await h.consent("responder", b);
  await h.instance.invoke("channel_open", { access: a });
  await h.instance.invoke("channel_send", { access: a, kind: "question", body: "hi" });
  assert.equal((await h.instance.invoke("handshake_nudge", { access: a })).nudged, true);
});

// ---------------------------------------------------------------------------
// End to end over HTTP
// ---------------------------------------------------------------------------

async function overHttp(h, fn) {
  const handler = createStandaloneHttpHandler({ invoke: (name, args) => h.instance.invoke(name, args), env: {} });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const call = async (name, args) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/connect/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await response.text();
    const data = text.split("\n").find((line) => line.startsWith("data:"));
    return JSON.parse(JSON.parse(data ? data.slice(5) : text).result.content[0].text);
  };
  try {
    await fn(call);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("e2e: an agent goes silent, is reported and nudged, then resumes from catchUp and the session closes", async () => {
  const h = harness({ nowMs: T });
  await overHttp(h, async (call) => {
    const invite = await call("handshake_invite", { ...validTerms(), readiness: await h.readiness("initiator") });
    const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await h.readiness("responder") });
    const a = invite.roleAccess;
    const b = accept.roleAccess;
    for (const [role, access] of [["initiator", a], ["responder", b]]) {
      const step = await call("handshake_next", { access, waitMs: 0 });
      await call("consent_sign", { access, signatureHex: await h.keys[role].signMessage({ message: step.sign.bytes }) });
    }
    await call("channel_open", { access: a });
    await call("channel_send", { access: a, kind: "question", body: "Can we talk Tuesday?" });

    // The responder goes silent for four minutes.
    h.setNow(T + 4 * MIN);
    const waiting = await call("handshake_next", { access: a, waitMs: 0, cursor: 0 });
    assert.equal(waiting.counterpartyStalled.pendingAction, "REPLY");
    assert.equal((await call("handshake_nudge", { access: a })).nudged, true);

    // It comes back with no memory of where it was.
    h.setNow(T + 6 * MIN);
    const back = await call("handshake_next", { access: b, waitMs: 0, resume: true });
    assert.equal(back.action, "respond");
    assert.deepEqual(back.catchUp.changes, { open: 1, message: 1, stalled: 1, nudged: 1 });
    assert.equal(back.nudged.byRole, "initiator");
    await call("channel_send", { access: b, kind: "proposal", body: "Tuesday works." });
    const reply = await call("handshake_next", { access: a, waitMs: 0, cursor: 0 });
    assert.equal(reply.action, "respond");
    assert.equal(reply.counterpartyStalled, undefined);
    await call("channel_close", { access: a });
    const done = await call("handshake_next", { access: b, waitMs: 0, cursor: 1 });
    assert.equal(done.action, "closed");
    const timeline = await call("handshake_timeline", { access: a });
    const kinds = timeline.events.map((event) => event.type);
    for (const kind of ["stalled", "nudged", "resumed"]) assert.ok(kinds.includes(kind), kind);
  });
});

test("e2e: an agent that never returns ends the session as stalled for the other, with an anchored closure", async () => {
  const h = harness({ nowMs: T });
  await overHttp(h, async (call) => {
    const invite = await call("handshake_invite", { ...validTerms(), readiness: await h.readiness("initiator") });
    const accept = await call("handshake_accept_invitation", { invitation: invite.invitation, readiness: await h.readiness("responder") });
    const a = invite.roleAccess;
    for (const [role, access] of [["initiator", a], ["responder", accept.roleAccess]]) {
      const step = await call("handshake_next", { access, waitMs: 0 });
      await call("consent_sign", { access, signatureHex: await h.keys[role].signMessage({ message: step.sign.bytes }) });
    }
    await call("channel_open", { access: a });
    await call("channel_send", { access: a, kind: "question", body: "Are you there?" });
    h.setNow(T + 10 * MIN);
    const ended = await call("handshake_next", { access: a, waitMs: 0, cursor: 0 });
    assert.equal(ended.action, "stalled");
    assert.equal(ended.reason, "STALLED_REPLY_BY_RESPONDER");
    assert.equal(ended.tellYourUser, "The handshake ended because the other agent did not reply in time.");
    assert.deepEqual(ended.terminal.anchors.map((anchor) => anchor.kind), ["terms-readiness", "consent", "open", "stall-closure"]);
  });
});
