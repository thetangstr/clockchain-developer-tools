// The public book of agent keys (src/agent-keys/routes.ts): anyone can look a key up by fingerprint, and an agent replaces
// its key (signed by the old key) or cancels it (signed by the key itself). Both changes take effect at once and are filed
// on Clockchain under the key's reference. Off unless MCP_AGENT_KEYS=1.
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ApiError } from "@clockchain/core";

import { readJsonBody, runHttp } from "../dist/http.js";
import { createAgentKeyRoutes } from "../dist/agent-keys/routes.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { jwtBearerProof } from "../dist/agent-keys/proof.js";
import { memoryExpiringSet } from "../dist/oauth-replay.js";
import { ShadowService } from "../dist/shadow/service.js";
import { createLogBudget } from "../dist/budget.js";
import { hash } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const PUBLIC = "https://mcp.example.test";
const SECRET = "agent-keys-routes-test-secret";
const STATIC_TOKEN = "static-test-token";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const tempDir = (label) => mkdtempSync(path.join(tmpdir(), `ak-routes-${label}-`));
const keyRef = (fp) => `agent-key:v1:${fp}`;
const actionUrl = (fp, action) => `${PUBLIC}/agent-keys/${fp}/${action}`;
/** The new key's own assertion for a replace: signed by it, naming the key it replaces. */
const proving = (key, oldFp, more = {}) => key.assertion(actionUrl(oldFp, "replace"), { ...more, claims: { replaces: oldFp, ...more.claims } });
/** The claim a replace assertion names its new key with. */
const naming = (key, more = {}) => ({ ...more, claims: { new_key: key.fingerprint, ...more.claims } });

/** The routes alone over a real HTTP server, with a fake ledger behind a real ShadowService, and a controllable clock. */
async function harness(o = {}) {
  const clock = { t: Date.now() };
  const fake = new FakeLedger();
  const book = new AgentKeyBook({ dir: tempDir("keys"), now: () => new Date(clock.t) });
  const svc = new ShadowService({
    stateDir: tempDir("shadow"), ledger: () => fake, budget: () => createLogBudget({}), now: () => new Date(clock.t),
    sleep: async () => {}, log: () => {}, agentKeys: book,
  });
  svc.sweep();
  const logs = [];
  const routes = createAgentKeyRoutes({
    book, proof: jwtBearerProof(), usedAssertions: o.usedAssertions ?? memoryExpiringSet(1000, () => Math.floor(clock.t / 1000)),
    publicUrl: PUBLIC, ipOf: () => "203.0.113.9", readJsonBody,
    ...(o.noFiling ? {} : { file: (fp, event, extra) => svc.fileAgentKeyEvent(fp, event, extra) }),
    lookupsPerMinute: o.lookups ?? 600, changesPerHour: o.changes ?? 20, now: () => clock.t, log: (e) => logs.push(e),
    ...(o.allowNewKey ? { allowNewKey: o.allowNewKey } : {}),
  });
  const server = createServer(async (req, res) => {
    if (!(await routes(req, res))) {
      res.writeHead(418);
      res.end();
    }
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url, fake, book, svc, clock, logs,
    /** An agent whose key is in the book (and so has a root). */
    agent() {
      const key = makeAgentKey();
      book.admit(key.publicKeyPem);
      return key;
    },
    lookup: (fp) => fetch(`${url}/agent-keys/${fp}.json`),
    post: (fp, action, body) => fetch(`${url}/agent-keys/${fp}/${action}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body),
    }),
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    },
  };
}

/** Every value in a JSON tree, for "never includes" checks. */
function walk(value, visit) {
  visit(value);
  if (value && typeof value === "object") for (const v of Object.values(value)) walk(v, visit);
}

/** Waits for a background filing (a lookup's retry) to land in the book. */
async function until(check) {
  for (let i = 0; i < 200; i++) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.fail("timed out waiting");
}

test("lookup shows a filed key with its ledger id and block", async () => {
  const h = await harness();
  try {
    const agent = h.agent();
    // The key is filed before its first record anchors (Task 8).
    await h.svc.startSession(`ak:${agent.fingerprint}`, { title: "an agent's", agents: [{ id: "planner" }] }, PUBLIC);
    const filed = h.fake.records.find((r) => r.assetReferenceId === keyRef(agent.fingerprint));
    assert.ok(filed);
    const res = await h.lookup(agent.fingerprint);
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(res.headers.get("cache-control"), "public, max-age=60");
    assert.match(res.headers.get("content-type"), /^application\/json/);
    assert.equal(body.fingerprint, agent.fingerprint);
    assert.equal(body.agentId, agent.fingerprint.slice(0, 16));
    assert.equal(body.publicKey, agent.publicKeyPem);
    assert.equal(body.status, "active");
    assert.equal(body.root, agent.fingerprint);
    assert.equal(typeof body.firstSeenAt, "string");
    assert.equal(body.filing.state, "filed");
    assert.equal(body.filing.ledgerId, filed.ledgerId);
    assert.equal(body.filing.block, Number(filed.blockHeight));
    assert.equal(typeof body.filing.filedAt, "string");
    assert.equal(body.replacedBy, undefined);
    assert.equal(body.revokedAt, undefined);
    assert.deepEqual(body.events, [{ action: "filed", at: body.filing.filedAt, state: "filed", ledgerId: filed.ledgerId, block: Number(filed.blockHeight) }]);
    // No sign-in, and nothing about the key or the caller is needed beyond the fingerprint.
    assert.equal(res.headers.get("set-cookie"), null);
  } finally {
    await h.close();
  }
});

test("lookup of an unknown key is 404", async () => {
  const h = await harness();
  try {
    for (const fp of ["0".repeat(64), "not-a-fingerprint", "A".repeat(64), `${"0".repeat(64)}/extra`]) {
      const res = await h.lookup(fp);
      assert.equal(res.status, 404, fp);
      const body = await res.json();
      assert.equal(body.error, "not_found");
      assert.equal(typeof body.error_description, "string");
      assert.equal(res.headers.get("cache-control"), "no-store");
    }
    // A path that isn't one of ours under /agent-keys/ is a 404 too; other paths are left alone.
    assert.equal((await fetch(`${h.url}/agent-keys/`)).status, 404);
    assert.equal((await fetch(`${h.url}/agent-keys/${"0".repeat(64)}/rename`, { method: "POST" })).status, 404);
    assert.equal((await fetch(`${h.url}/elsewhere`)).status, 418);
    // A known path with the wrong method.
    const agent = h.agent();
    const wrong = await fetch(`${h.url}/agent-keys/${agent.fingerprint}.json`, { method: "POST" });
    assert.equal(wrong.status, 405);
    assert.equal(wrong.headers.get("allow"), "GET, HEAD");
    assert.equal((await fetch(`${h.url}/agent-keys/${agent.fingerprint}/revoke`)).status, 405);
  } finally {
    await h.close();
  }
});

test("replace needs the old key's signature", async () => {
  const h = await harness();
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const stranger = h.agent();
    const url = actionUrl(old.fingerprint, "replace");
    const refusals = [
      // Signed by someone else (an active key in the book), by the new key, for another action, for another key's URL.
      [stranger.assertion(url, naming(next)), 401, "invalid_client"],
      [next.assertion(url, naming(next)), 401, "invalid_client"],
      [old.assertion(actionUrl(old.fingerprint, "revoke"), naming(next)), 401, "invalid_client"],
      [old.assertion(`${PUBLIC}/oauth/token`, naming(next)), 401, "invalid_client"],
      [old.assertion(actionUrl(stranger.fingerprint, "replace"), naming(next)), 401, "invalid_client"],
      // Expired, and not an assertion at all.
      [old.assertion(url, naming(next, { iat: Math.floor(h.clock.t / 1000) - 400, exp: Math.floor(h.clock.t / 1000) - 100 })), 401, "invalid_client"],
      ["not.an.assertion", 401, "invalid_client"],
    ];
    for (const [assertion, status, error] of refusals) {
      const res = await h.post(old.fingerprint, "replace", { assertion, new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
      const body = await res.json();
      assert.equal(res.status, status, JSON.stringify(body));
      assert.equal(body.error, error);
      assert.equal(typeof body.error_description, "string");
      assert.ok(!JSON.stringify(body).includes(assertion), "the assertion is never echoed");
      assert.equal(res.headers.get("cache-control"), "no-store");
    }
    // A stranger's key can't take over the old key's root by naming itself, either.
    const takeover = await h.post(old.fingerprint, "replace", { assertion: stranger.assertion(url, naming(stranger)), new_public_key: stranger.publicKeyPem, new_key_assertion: proving(stranger, old.fingerprint) });
    assert.equal(takeover.status, 401);
    // Malformed bodies.
    assert.equal((await h.post(old.fingerprint, "replace", { new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) })).status, 400);
    assert.equal((await h.post(old.fingerprint, "replace", { assertion: old.assertion(url) })).status, 400);
    assert.equal((await h.post(old.fingerprint, "replace", "{not json")).status, 400);
    assert.equal((await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint), extra: 1 })).status, 400);
    const crlf = await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem.replace(/\n/g, "\r\n"), new_key_assertion: proving(next, old.fingerprint) });
    assert.equal(crlf.status, 400, "the new key must be a canonical Ed25519 SPKI PEM");
    assert.equal((await crlf.json()).error, "invalid_request");
    // The new key may not be one that already belongs to an agent.
    const taken = await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(stranger)), new_public_key: stranger.publicKeyPem, new_key_assertion: proving(stranger, old.fingerprint) });
    assert.equal(taken.status, 409);
    assert.equal((await taken.json()).error, "key_exists");
    assert.equal(h.book.get(old.fingerprint).status, "active", "nothing changed yet");
    assert.equal(h.fake.writes.length, 0);

    // Signed by the old key, naming the new one.
    const assertion = old.assertion(url, naming(next));
    const res = await h.post(old.fingerprint, "replace", { assertion, new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(body.fingerprint, next.fingerprint);
    assert.equal(body.publicKey, next.publicKeyPem);
    assert.equal(body.root, old.fingerprint, "the new key keeps the agent's root");
    assert.equal(body.agentId, old.fingerprint.slice(0, 16));
    assert.equal(body.status, "active");
    assert.equal(body.replaces, old.fingerprint);
    assert.equal(body.event.action, "replaced");
    assert.equal(body.event.state, "filed");
    // Filed under the old key's reference.
    const write = h.fake.records.find((r) => r.additionalInfo === "agent key replaced");
    assert.equal(write.assetReferenceId, keyRef(old.fingerprint));
    const was = await (await h.lookup(old.fingerprint)).json();
    assert.equal(was.status, "replaced");
    assert.equal(was.replacedBy, next.fingerprint);
    const event = was.events.find((e) => e.action === "replaced");
    assert.equal(write.assetHash, hash("agent-key-event:v1", { fp: old.fingerprint, event: "replaced", newFp: next.fingerprint, at: event.at }));
    assert.deepEqual(event, { action: "replaced", at: event.at, state: "filed", ledgerId: write.ledgerId, block: Number(write.blockHeight), filedAt: event.filedAt });
    assert.equal(typeof event.filedAt, "string");

    // The same assertion again is refused: each jti is single use.
    const replay = await h.post(old.fingerprint, "replace", { assertion, new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    assert.equal(replay.status, 401);
    // The old key can't replace itself again with another key, and a stranger can't replace the new one.
    const other = makeAgentKey();
    const again = await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(other)), new_public_key: other.publicKeyPem, new_key_assertion: proving(other, old.fingerprint) });
    assert.equal(again.status, 409);
    assert.equal((await again.json()).error, "key_not_active");
    const thief = makeAgentKey();
    const hijack = await h.post(next.fingerprint, "replace", { assertion: old.assertion(actionUrl(next.fingerprint, "replace"), naming(thief)), new_public_key: thief.publicKeyPem, new_key_assertion: proving(thief, next.fingerprint) });
    assert.equal(hijack.status, 401);
    // Asked again by the old key for the same new key (a lost response), it finishes without a second write.
    const retry = await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    assert.equal(retry.status, 200);
    assert.equal(h.fake.writes.filter((w) => w.additionalInfo === "agent key replaced").length, 1);
    // No log line carries the assertion.
    assert.ok(!JSON.stringify(h.logs).includes(assertion));
  } finally {
    await h.close();
  }
});

test("a replace assertion binds the new key, so a captured one can't be redirected", async () => {
  const h = await harness();
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const attacker = makeAgentKey();
    const url = actionUrl(old.fingerprint, "replace");
    const refusedWith = async (assertion, newKey) => {
      const res = await h.post(old.fingerprint, "replace", { assertion, new_public_key: newKey.publicKeyPem, new_key_assertion: proving(newKey, old.fingerprint) });
      const body = await res.json();
      assert.equal(res.status, 401, JSON.stringify(body));
      assert.equal(body.error, "invalid_client");
      assert.match(body.error_description, /new_key/);
      assert.ok(!body.error_description.includes(assertion));
    };
    // No new_key claim, a malformed one, and one naming a different key than the body.
    await refusedWith(old.assertion(url), next);
    for (const bad of [42, "", next.fingerprint.toUpperCase(), next.fingerprint.slice(1), next.publicKeyPem]) {
      await refusedWith(old.assertion(url, { claims: { new_key: bad } }), next);
    }
    await refusedWith(old.assertion(url, naming(attacker)), next);
    // A captured valid assertion sent with the attacker's key instead: refused, nothing changes, nothing is written.
    const captured = old.assertion(url, naming(next));
    await refusedWith(captured, attacker);
    assert.equal(h.book.get(old.fingerprint).status, "active");
    assert.equal(h.book.get(attacker.fingerprint), null);
    assert.equal(h.fake.writes.length, 0);
    // The redirect didn't spend it: the agent's own request with that assertion goes through.
    const res = await h.post(old.fingerprint, "replace", { assertion: captured, new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.fingerprint, next.fingerprint);
    assert.equal(h.book.get(old.fingerprint).replacedBy, next.fingerprint);
    // Finishing the same replacement again needs new_key too.
    await refusedWith(old.assertion(url), next);
    assert.equal((await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) })).status, 200);
  } finally {
    await h.close();
  }
});

test("the new key must prove itself when replacing", async () => {
  const h = await harness();
  try {
    const attacker = h.agent();
    const victim = makeAgentKey();
    const stranger = makeAgentKey();
    const aUrl = actionUrl(attacker.fingerprint, "replace");
    const refused = async (fp, body, status = 401) => {
      const res = await h.post(fp, "replace", body);
      const out = await res.json();
      assert.equal(res.status, status, JSON.stringify(out));
      assert.equal(typeof out.error_description, "string");
      for (const v of Object.values(body)) assert.ok(!JSON.stringify(out).includes(v), "no assertion is echoed");
      return out;
    };
    // The squat: the attacker names the victim's public key without the victim's signature. Refused; the victim's key
    // never enters the book, so its first sign-in starts its own root.
    const squat = { assertion: attacker.assertion(aUrl, naming(victim)), new_public_key: victim.publicKeyPem };
    assert.equal((await refused(attacker.fingerprint, squat, 400)).error, "invalid_request");
    for (const forged of [attacker, stranger]) {
      const out = await refused(attacker.fingerprint, { ...squat, assertion: attacker.assertion(aUrl, naming(victim)), new_key_assertion: proving(forged, attacker.fingerprint) });
      assert.equal(out.error, "invalid_client");
    }
    assert.equal(h.book.get(victim.fingerprint), null);
    assert.equal(h.book.get(attacker.fingerprint).status, "active");

    const old = h.agent();
    const next = makeAgentKey();
    const url = actionUrl(old.fingerprint, "replace");
    const body = (newKeyAssertion, assertion = old.assertion(url, naming(next))) => ({ assertion, new_public_key: next.publicKeyPem, new_key_assertion: newKeyAssertion });
    // Wrong `replaces` (another key, missing, malformed), wrong audience, and signed by a key other than new_public_key.
    for (const bad of [
      proving(next, attacker.fingerprint),
      next.assertion(url, { claims: { replaces: attacker.fingerprint } }),
      next.assertion(url),
      next.assertion(url, { claims: { replaces: old.fingerprint.toUpperCase() } }),
      next.assertion(url, { claims: { replaces: 7 } }),
      next.assertion(actionUrl(old.fingerprint, "revoke"), { claims: { replaces: old.fingerprint } }),
      next.assertion(`${PUBLIC}/oauth/token`, { claims: { replaces: old.fingerprint } }),
      stranger.assertion(url, { claims: { replaces: old.fingerprint } }),
      old.assertion(url, { claims: { replaces: old.fingerprint } }),
    ]) {
      assert.equal((await refused(old.fingerprint, body(bad))).error, "invalid_client");
    }
    assert.equal(h.book.get(old.fingerprint).status, "active");
    assert.equal(h.book.get(next.fingerprint), null);
    assert.equal(h.fake.writes.length, 0);

    // Neither assertion is burned by a refusal: each is refused alongside a bad partner, then both go through together.
    const oldOk = old.assertion(url, naming(next));
    const newOk = proving(next, old.fingerprint);
    await refused(old.fingerprint, body(next.assertion(url), oldOk));
    await refused(old.fingerprint, body(newOk, stranger.assertion(url, naming(next))));
    const res = await h.post(old.fingerprint, "replace", body(newOk, oldOk));
    const done = await res.json();
    assert.equal(res.status, 200, JSON.stringify(done));
    assert.equal(done.fingerprint, next.fingerprint);
    assert.equal(done.root, old.fingerprint);

    // Both are spent: the new key's assertion can't be used again, even with a fresh old-key assertion (a resume).
    await refused(old.fingerprint, body(newOk));
    await refused(old.fingerprint, body(proving(next, old.fingerprint), oldOk));
    // A resume needs both assertions, fresh.
    await refused(old.fingerprint, { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem }, 400);
    assert.equal((await h.post(old.fingerprint, "replace", body(proving(next, old.fingerprint)))).status, 200);
    assert.ok(!JSON.stringify(h.logs).includes(newOk));
  } finally {
    await h.close();
  }
});

test("revoke shows status revoked with revokedAt", async () => {
  const h = await harness();
  try {
    const agent = h.agent();
    const stranger = h.agent();
    const url = actionUrl(agent.fingerprint, "revoke");
    // Only the key itself may cancel it.
    const forged = await h.post(agent.fingerprint, "revoke", { assertion: stranger.assertion(url) });
    assert.equal(forged.status, 401);
    assert.equal((await forged.json()).error, "invalid_client");
    assert.equal((await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(actionUrl(agent.fingerprint, "replace")) })).status, 401);
    assert.equal((await h.post(agent.fingerprint, "revoke", {})).status, 400);
    assert.equal(h.book.get(agent.fingerprint).status, "active");

    const res = await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(url) });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.fingerprint, agent.fingerprint);
    assert.equal(body.status, "revoked");
    assert.equal(typeof body.revokedAt, "string");
    assert.equal(body.event.action, "revoked");
    assert.equal(body.event.state, "filed");

    const looked = await (await h.lookup(agent.fingerprint)).json();
    assert.equal(looked.status, "revoked");
    assert.equal(looked.revokedAt, body.revokedAt);
    const event = looked.events.find((e) => e.action === "revoked");
    assert.equal(event.at, looked.revokedAt);
    assert.equal(event.state, "filed");
    const write = h.fake.records.find((r) => r.additionalInfo === "agent key revoked");
    assert.equal(write.assetReferenceId, keyRef(agent.fingerprint));
    assert.equal(event.ledgerId, write.ledgerId);
    assert.equal(event.block, Number(write.blockHeight));

    // Final: a cancelled key can't cancel or replace again.
    const again = await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(url) });
    assert.equal(again.status, 409);
    assert.equal((await again.json()).error, "key_not_active");
    const after = makeAgentKey();
    const replace = await h.post(agent.fingerprint, "replace", { assertion: agent.assertion(actionUrl(agent.fingerprint, "replace"), naming(after)), new_public_key: after.publicKeyPem, new_key_assertion: proving(after, agent.fingerprint) });
    assert.equal(replace.status, 409);
  } finally {
    await h.close();
  }
});

test("a revoke when the spent-assertion list is full gets 503 and changes nothing", async () => {
  const nowSec = () => Math.floor(Date.now() / 1000);
  const usedAssertions = memoryExpiringSet(1, nowSec, "refuse");
  usedAssertions.add("held", nowSec() + 3600);
  const h = await harness({ usedAssertions });
  try {
    const agent = h.agent();
    const before = h.book.get(agent.fingerprint);
    const res = await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(actionUrl(agent.fingerprint, "revoke")) });
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "60");
    const body = await res.json();
    assert.equal(body.error, "temporarily_unavailable");
    assert.equal(body.error_description, "Clockchain is taking too many key changes right now. Try again in a minute.");
    assert.ok(h.logs.some((e) => e.event === "agent_keys_replay_state_full"), JSON.stringify(h.logs));
    assert.deepEqual(h.book.get(agent.fingerprint), before);
  } finally {
    await h.close();
  }
});

test("a key route takes only an assertion whose aud is its URL as one string, never an array", async () => {
  const h = await harness();
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const url = actionUrl(old.fingerprint, "replace");
    const tries = [
      [old.assertion(url, naming(next, { claims: { aud: [url] } })), proving(next, old.fingerprint)],
      [old.assertion(url, naming(next)), proving(next, old.fingerprint, { claims: { aud: [url] } })],
    ];
    for (const [assertion, newKeyAssertion] of tries) {
      const res = await h.post(old.fingerprint, "replace", { assertion, new_public_key: next.publicKeyPem, new_key_assertion: newKeyAssertion });
      const body = await res.json();
      assert.equal(res.status, 401, JSON.stringify(body));
      assert.equal(body.error, "invalid_client");
      assert.match(body.error_description, /aud must be this URL as a single string/);
    }
    const revoke = actionUrl(old.fingerprint, "revoke");
    const res = await h.post(old.fingerprint, "revoke", { assertion: old.assertion(revoke, { claims: { aud: [revoke] } }) });
    assert.equal(res.status, 401);
    assert.equal(h.book.get(old.fingerprint).status, "active", "nothing changed");
    // A refusal spends nothing: the same assertions with aud as a string go through.
    const ok = await h.post(old.fingerprint, "replace", { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    assert.equal(ok.status, 200);
  } finally {
    await h.close();
  }
});

test("a replace spends both assertions in one write: one that fails spends neither, and the same request then goes through", async () => {
  const nowSec = () => Math.floor(Date.now() / 1000);
  const inner = memoryExpiringSet(1000, nowSec);
  let failing = true;
  const writes = [];
  const usedAssertions = {
    has: (k) => inner.has(k),
    add: () => { throw new Error("a replace must spend its two assertions in one write"); },
    addAll: (entries) => {
      writes.push(entries.length);
      if (failing) throw new Error("disk full");
      inner.addAll(entries);
    },
    full: () => inner.full(),
    size: () => inner.size(),
  };
  const h = await harness({ usedAssertions });
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const url = actionUrl(old.fingerprint, "replace");
    const body = { assertion: old.assertion(url, naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) };
    const failed = await h.post(old.fingerprint, "replace", body);
    assert.equal(failed.status, 503);
    assert.equal(inner.size(), 0, "neither assertion was spent");
    assert.equal(h.book.get(old.fingerprint).status, "active");
    assert.equal(h.book.get(next.fingerprint), null);
    failing = false;
    assert.equal((await h.post(old.fingerprint, "replace", body)).status, 200);
    assert.deepEqual(writes, [2, 2], "one write of both, each time");
    assert.equal(inner.size(), 2);
    assert.equal((await h.post(old.fingerprint, "replace", body)).status, 401, "then both are spent");
  } finally {
    await h.close();
  }
});

test("lookup never includes private material", async () => {
  const h = await harness();
  try {
    const old = h.agent();
    const next = makeAgentKey();
    await h.post(old.fingerprint, "replace", { assertion: old.assertion(actionUrl(old.fingerprint, "replace"), naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    await h.post(next.fingerprint, "revoke", { assertion: next.assertion(actionUrl(next.fingerprint, "revoke")) });
    for (const fp of [old.fingerprint, next.fingerprint]) {
      const text = await (await h.lookup(fp)).text();
      assert.ok(!text.includes("PRIVATE KEY"));
      walk(JSON.parse(text), (v) => {
        if (v && typeof v === "object" && !Array.isArray(v) && "kty" in v) assert.ok(!("d" in v), "no private JWK member");
      });
      assert.deepEqual(Object.keys(JSON.parse(text)).filter((k) => !["fingerprint", "agentId", "publicKey", "status", "root", "firstSeenAt", "filing", "replacedBy", "revokedAt", "events"].includes(k)), []);
    }
  } finally {
    await h.close();
  }
});

test("a change stands while its filing waits, and a later lookup files it", async () => {
  const h = await harness();
  try {
    const agent = h.agent();
    let down = true;
    const log = h.fake.log.bind(h.fake);
    h.fake.log = async (e) => {
      if (down) throw new ApiError("Clockchain API error (503)", 503);
      return log(e);
    };
    const res = await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(actionUrl(agent.fingerprint, "revoke")) });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.status, "revoked", "cancelled at once, whatever the ledger says");
    assert.equal(body.event.state, "pending");
    assert.equal(h.fake.writes.length, 0);

    down = false;
    h.clock.t += 61_000; // a minute after the change's own try
    const first = await (await h.lookup(agent.fingerprint)).json();
    assert.equal(first.events.find((e) => e.action === "revoked").state, "pending", "the lookup answers at once; the retry runs behind it");
    await until(() => h.book.get(agent.fingerprint).events.some((e) => e.action === "revoked" && e.filedAt));
    const later = await (await h.lookup(agent.fingerprint)).json();
    const event = later.events.find((e) => e.action === "revoked");
    assert.equal(event.state, "filed");
    assert.equal(event.ledgerId, h.fake.records[0].ledgerId);
    assert.equal(h.fake.writes.length, 1);
    // Filed: further lookups don't touch the ledger.
    await h.lookup(agent.fingerprint);
    assert.equal(h.fake.writes.length, 1);
  } finally {
    await h.close();
  }
});

test("lookups retry a waiting filing at most once a minute", async () => {
  const h = await harness();
  try {
    const agent = h.agent();
    let tries = 0;
    h.fake.log = async () => {
      tries++;
      throw new ApiError("Clockchain API error (503)", 503);
    };
    await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(actionUrl(agent.fingerprint, "revoke")) });
    const afterChange = tries;
    assert.ok(afterChange >= 1);
    for (let i = 0; i < 5; i++) await h.lookup(agent.fingerprint);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(tries, afterChange, "within the minute after the change's own try, lookups only read");
    h.clock.t += 61_000;
    for (let i = 0; i < 5; i++) await h.lookup(agent.fingerprint);
    await until(() => tries > afterChange);
    await new Promise((r) => setTimeout(r, 50));
    assert.ok(tries <= afterChange + 3, "one retry (with its own in-call tries), not one per lookup");
  } finally {
    await h.close();
  }
});

test("without a ledger the change still stands and shows as pending", async () => {
  const h = await harness({ noFiling: true });
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const res = await h.post(old.fingerprint, "replace", { assertion: old.assertion(actionUrl(old.fingerprint, "replace"), naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.event.state, "pending");
    assert.equal(h.book.get(old.fingerprint).status, "replaced");
    const looked = await (await h.lookup(old.fingerprint)).json();
    assert.equal(looked.events.find((e) => e.action === "replaced").state, "pending");
  } finally {
    await h.close();
  }
});

test("lookups and changes are limited per address", async () => {
  const h = await harness({ lookups: 2, changes: 1 });
  try {
    const agent = h.agent();
    assert.equal((await h.lookup(agent.fingerprint)).status, 200);
    assert.equal((await h.lookup(agent.fingerprint)).status, 200);
    const limited = await h.lookup(agent.fingerprint);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "60");
    assert.equal((await limited.json()).error, "temporarily_unavailable");
    h.clock.t += 61_000;
    assert.equal((await h.lookup(agent.fingerprint)).status, 200, "a new minute");

    const other = h.agent();
    assert.equal((await h.post(other.fingerprint, "revoke", { assertion: other.assertion(actionUrl(other.fingerprint, "revoke")) })).status, 200);
    const second = await h.post(agent.fingerprint, "revoke", { assertion: agent.assertion(actionUrl(agent.fingerprint, "revoke")) });
    assert.equal(second.status, 429);
    assert.equal(h.book.get(agent.fingerprint).status, "active");
  } finally {
    await h.close();
  }
});

test("a replace past the hourly ceiling on new keys is refused, and spends nothing", async () => {
  let open = false;
  let asked = 0;
  const h = await harness({ allowNewKey: () => { asked++; return open; } });
  try {
    const old = h.agent();
    const next = makeAgentKey();
    const body = { assertion: old.assertion(actionUrl(old.fingerprint, "replace"), naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) };
    const refused = await h.post(old.fingerprint, "replace", body);
    assert.equal(refused.status, 429);
    assert.equal(refused.headers.get("retry-after"), "3600");
    assert.deepEqual(await refused.json(), { error: "temporarily_unavailable", error_description: "Clockchain isn't taking new agent keys right now. Try again later." });
    assert.equal(h.book.get(old.fingerprint).status, "active", "nothing changed");
    assert.equal(h.book.get(next.fingerprint), null);
    assert.ok(h.logs.some((e) => e.event === "agent_keys_rate_limited" && e.surface === "agent_key_new_global"));
    // A refused request burns neither assertion: the same one goes through once there is room.
    open = true;
    const res = await h.post(old.fingerprint, "replace", body);
    assert.equal(res.status, 200, JSON.stringify(await res.clone().json()));
    assert.equal(h.book.get(next.fingerprint).status, "active");
    // A revoke makes no new key, so it never asks.
    const before = asked;
    open = false;
    const other = h.agent();
    assert.equal((await h.post(other.fingerprint, "revoke", { assertion: other.assertion(actionUrl(other.fingerprint, "revoke")) })).status, 200);
    assert.equal(asked, before);
  } finally {
    await h.close();
  }
});

// ---- through the real server ------------------------------------------------------------

const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS",
  "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "MCP_AGENT_KEYS", "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR", "MCP_AGENT_KEYS_NEW_PER_HOUR", "SHADOW_ENABLED", "SHADOW_STATE_DIR",
  "SHADOW_ANON_PER_MINUTE",
];

async function freeLoopbackPort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

/** The real runHttp wiring with the given env (as test/oauth-agent-keys.test.mjs boots it, with its port retry). */
async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  let server;
  const stateDir = tempDir("state");
  for (let attempt = 1; ; attempt++) {
    Object.assign(process.env, { MCP_PORT: String(await freeLoopbackPort()), MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: stateDir }, env);
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    try {
      server = await runHttp();
      if (!server.listening) await once(server, "listening");
    } catch (e) {
      if (e?.code !== "EADDRINUSE" || attempt >= 5) throw e;
      continue;
    }
    let reached = false;
    const mark = () => { reached = true; };
    server.prependListener("request", mark);
    await fetch(`http://127.0.0.1:${server.address().port}/health`).then((r) => r.arrayBuffer()).catch(() => {});
    server.removeListener("request", mark);
    if (reached) break;
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    assert.ok(attempt < 5, "no 127.0.0.1 port reached this server in 5 tries");
  }
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/** The client_credentials grant for `agent`: a fresh client assertion and a DPoP proof from the same key. */
const grant = (base, agent) =>
  fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: agent.dpop("POST", `${PUBLIC}/oauth/token`) },
    body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: agent.assertion(`${PUBLIC}/oauth/token`) }),
  });

test("routes 404 when MCP_AGENT_KEYS is off", async () => {
  const agent = makeAgentKey();
  const off = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    assert.equal((await fetch(`${off.url}/agent-keys/${agent.fingerprint}.json`)).status, 404);
    for (const action of ["replace", "revoke"]) {
      const res = await fetch(`${off.url}/agent-keys/${agent.fingerprint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ assertion: agent.assertion(actionUrl(agent.fingerprint, action)), new_public_key: makeAgentKey().publicKeyPem }),
      });
      assert.equal(res.status, 404, action);
    }
  } finally {
    await off.close();
  }
});

test("on the real server, keys made by replace count toward the hourly ceiling on new keys", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_HOUR: "2" });
  try {
    const old = makeAgentKey();
    assert.equal((await grant(s.url, old)).status, 200, "one new key");
    const next = makeAgentKey();
    const replaced = await fetch(`${s.url}/agent-keys/${old.fingerprint}/replace`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion: old.assertion(actionUrl(old.fingerprint, "replace"), naming(next)), new_public_key: next.publicKeyPem, new_key_assertion: proving(next, old.fingerprint) }),
    });
    assert.equal(replaced.status, 200, "two");
    const third = await grant(s.url, makeAgentKey());
    assert.equal(third.status, 429, "the ceiling is shared with replace");
    assert.equal((await third.json()).error, "temporarily_unavailable");
    // The key the replace made is known now, so it still mints.
    assert.equal((await grant(s.url, next)).status, 200);
    const later = makeAgentKey();
    const again = await fetch(`${s.url}/agent-keys/${next.fingerprint}/replace`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion: next.assertion(actionUrl(next.fingerprint, "replace"), naming(later)), new_public_key: later.publicKeyPem, new_key_assertion: proving(later, next.fingerprint) }),
    });
    assert.equal(again.status, 429);
  } finally {
    await s.close();
  }
});

test("on the real server, a key's token stops after replace and the new key's works", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1" });
  try {
    const old = makeAgentKey();
    const minted = await grant(s.url, old);
    assert.equal(minted.status, 200);
    const { access_token: oldToken } = await minted.json();
    const looked = await fetch(`${s.url}/agent-keys/${old.fingerprint}.json`);
    assert.equal(looked.status, 200);
    assert.equal((await looked.json()).status, "active");

    const next = makeAgentKey();
    const assertion = old.assertion(actionUrl(old.fingerprint, "replace"), naming(next));
    const newKeyAssertion = proving(next, old.fingerprint);
    const send = () => fetch(`${s.url}/agent-keys/${old.fingerprint}/replace`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion, new_public_key: next.publicKeyPem, new_key_assertion: newKeyAssertion }),
    });
    const res = await send();
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.root, old.fingerprint);
    // Shadow is off on this server, so there is no ledger to file on yet: the event waits, the change stands.
    assert.equal(body.event.state, "pending");
    assert.equal((await send()).status, 401, "single use through the server's own spent-assertion set");

    // The old key's token is refused on the next call; the new key mints, and owns the same root.
    const call = (token, agent) => fetch(`${s.url}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json", accept: "application/json, text/event-stream",
        authorization: `DPoP ${token}`, dpop: agent.dpop("POST", `${PUBLIC}/mcp`, { accessToken: token }),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal((await call(oldToken, old)).status, 401);
    const fresh = await grant(s.url, next);
    const freshBody = await fresh.json();
    assert.equal(fresh.status, 200, JSON.stringify(freshBody));
    assert.equal(freshBody.agent_id, old.fingerprint.slice(0, 16));
    assert.equal((await call(freshBody.access_token, next)).status, 200);
  } finally {
    await s.close();
  }
});
