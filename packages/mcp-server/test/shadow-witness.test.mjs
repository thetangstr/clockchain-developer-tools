// Hosted Shadow signing modes. Clockchain holds no key per account: with SHADOW_WITNESS_KEY_FILE set, a signed-in
// account's checkpoints are witnessed under Clockchain's single published service key; an agent-key owner (ak:) is the
// agent's to sign, so the server never signs for it; with no witness key, everything is as before.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ShadowService } from "../dist/shadow/service.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { DOMAIN, hash, parseStrict } from "../dist/shadow/lib/profile.js";
import { fingerprint } from "../dist/shadow/lib/keys.js";
import { createLogBudget, __resetSharedLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { HOSTED_LIMITS, checkpointBody, limitsFor } from "../dist/shadow/recorder.js";
import { loadWitnessKey } from "../dist/shadow/witness.js";
import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const A = "jti:11111111-1111-4111-8111-111111111111";
const ROOT = "ab".repeat(32);
const AGENT = `ak:${ROOT}`;
const BASE = "https://mcp.example.test";
const strict = (v) => parseStrict(JSON.stringify(v));
const DAY = 24 * 60 * 60_000;
const WITNESSED = "Witnessed: Clockchain received each step from the signed-in account and signed with its single published service key. The agent did not sign.";
const AGENT_SIGNED = "Signed by the agent's own key. Clockchain received the steps and holds no key for this agent.";

function witnessFile(keyType = "ed25519") {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-key-"));
  const file = path.join(dir, "witness.pem");
  const { privateKey } = keyType === "ec" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync(keyType);
  writeFileSync(file, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return file;
}

function setup(o = {}) {
  const dir = o.dir ?? mkdtempSync(path.join(tmpdir(), "shadow-witness-"));
  const fake = o.fake ?? new FakeLedger();
  // Start the fake clock at the real time: the retention sweep compares it with real file mtimes (operator.json).
  const clock = o.clock ?? { t: Math.floor(Date.now() / 1000) * 1000 };
  const logs = o.logs ?? [];
  const budget = o.budget ?? createLogBudget({});
  const svc = new ShadowService({
    stateDir: dir, ledger: () => fake, budget: () => budget, limits: o.limits, now: () => new Date(clock.t),
    sleep: async () => {}, log: (event, fields) => logs.push({ event, ...fields }),
    ...(o.witness ? { witness: o.witness } : {}),
  });
  svc.sweep();
  return { svc, fake, clock, dir, logs, budget };
}

const capOf = (links) => new URL(links.packet).pathname.split("/").pop().replace(/\.json$/, "");

async function packetOf(svc, links) {
  const doc = JSON.parse(await svc.packetForCap(capOf(links)));
  return { packet: strict(doc.packet), pin: strict(doc.pin), doc };
}

async function shortSession(svc, owner = A) {
  const s = await svc.startSession(owner, { title: "Plan a trip", agents: [{ id: "planner" }] }, BASE);
  await svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  await svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  const closed = await svc.close(owner, { session_id: s.session_id, status: "succeeded" }, BASE);
  return { s, closed };
}

const ownerDir = (dir, owner) => path.join(dir, "owners", ownerKeyOf(owner));

test("with a witness key, account checkpoints are signed by it and no key.json is created", async () => {
  const witness = loadWitnessKey(witnessFile());
  const { svc, dir } = setup({ witness });
  const one = await shortSession(svc);
  const two = await shortSession(svc);
  const { packet } = await packetOf(svc, one.closed.links);
  assert.equal(packet.checkpoint.publicKey, witness.publicKey());
  assert.equal(existsSync(path.join(ownerDir(dir, A), "key.json")), false, "no per-account key");
  assert.ok(existsSync(path.join(ownerDir(dir, A), "operator.json")), "the operator id is kept on its own");
  assert.doesNotMatch(readFileSync(path.join(ownerDir(dir, A), "operator.json"), "utf8"), /PRIVATE KEY/);
  // One operator id per account, across sessions and restarts.
  assert.equal(one.closed.pin.operatorId, two.closed.pin.operatorId);
  assert.match(one.closed.pin.operatorId, /^[0-9a-f-]{36}$/);
  svc.stop();
  const again = setup({ dir, witness });
  const three = await shortSession(again.svc);
  assert.equal(three.closed.pin.operatorId, one.closed.pin.operatorId);
});

test("an existing key.json keeps its operatorId but its key is not used for new checkpoints", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-legacy-"));
  const fake = new FakeLedger();
  const legacy = setup({ dir, fake });
  const old = await legacy.svc.startSession(A, { title: "before the witness key", agents: [{ id: "planner" }] }, BASE);
  await legacy.svc.record(A, { session_id: old.session_id, agent: "planner", kind: "task", content: "Find flights" });
  const cp = await legacy.svc.checkpoint(A, { session_id: old.session_id });
  assert.equal(cp.checkpoint.status, "anchored");
  const done = await shortSession(legacy.svc);
  const legacyKey = (await packetOf(legacy.svc, done.closed.links)).packet.checkpoint.publicKey;
  legacy.svc.stop();
  const keyFile = path.join(ownerDir(dir, A), "key.json");
  // The durable writer keeps a .bak beside a rewritten file, which holds the private key too.
  copyFileSync(keyFile, `${keyFile}.bak`);
  const keyCreatedAt = JSON.parse(readFileSync(keyFile, "utf8")).value.createdAt;
  const old_ = Date.now() - 3 * DAY;
  utimesSync(keyFile, old_ / 1000, old_ / 1000);
  const keyMtime = statSync(keyFile).mtimeMs;

  const witness = loadWitnessKey(witnessFile());
  const { svc } = setup({ dir, fake, witness });
  // A new session keeps the account's operator id.
  const fresh = await shortSession(svc);
  assert.equal(fresh.closed.pin.operatorId, done.closed.pin.operatorId);
  assert.equal((await packetOf(svc, fresh.closed.links)).packet.checkpoint.publicKey, witness.publicKey());
  // The open session continues, and its new checkpoint is witnessed, not signed with the old key.
  await svc.record(A, { session_id: old.session_id, agent: "planner", kind: "message", content: "after the switch" });
  const closed = await svc.close(A, { session_id: old.session_id, status: "succeeded" }, BASE);
  const { packet, pin } = await packetOf(svc, closed.links);
  assert.equal(packet.checkpoint.publicKey, witness.publicKey());
  assert.notEqual(packet.checkpoint.publicKey, legacyKey);
  assert.equal(packet.checkpoint.body.operatorId, done.closed.pin.operatorId);
  assert.equal((await verifyPacket(packet, { pin })).result, "pass");
  // The held key is gone, .bak included; operator.json keeps the operator id, and the retention clock where it was.
  assert.equal(existsSync(keyFile), false);
  assert.equal(existsSync(`${keyFile}.bak`), false);
  const opFile = path.join(ownerDir(dir, A), "operator.json");
  const op = JSON.parse(readFileSync(opFile, "utf8")).value;
  assert.equal(op.operatorId, done.closed.pin.operatorId);
  assert.equal(op.createdAt, keyCreatedAt);
  assert.doesNotMatch(readFileSync(opFile, "utf8"), /PRIVATE KEY/);
  assert.equal(statSync(opFile).mtimeMs, keyMtime);
  // A packet signed with the old key still verifies: it carries its own public key.
  const earlier = await packetOf(svc, done.closed.links);
  assert.equal(earlier.packet.checkpoint.publicKey, legacyKey);
  assert.equal((await verifyPacket(earlier.packet, { pin: earlier.pin })).result, "pass");
});

test("at start with the witness key, owners that never come back lose their key.json too, keeping their operator ids", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-dormant-"));
  const fake = new FakeLedger();
  const B = "jti:22222222-2222-4222-8222-222222222222";
  const legacy = setup({ dir, fake });
  const ids = {};
  for (const owner of [A, B]) ids[owner] = (await shortSession(legacy.svc, owner)).closed.pin.operatorId;
  legacy.svc.stop();
  const keyFile = (owner) => path.join(ownerDir(dir, owner), "key.json");
  copyFileSync(keyFile(A), `${keyFile(A)}.bak`);
  const held = () => [A, B].flatMap((o) => readdirSync(ownerDir(dir, o)).filter((n) => n === "key.json" || n.startsWith("key.json.")));
  assert.deepEqual(held().sort(), ["key.json", "key.json", "key.json.bak"]);

  // Legacy mode leaves them alone.
  const plain = setup({ dir, fake });
  plain.svc.start();
  plain.svc.stop();
  assert.equal(held().length, 3);

  const witness = loadWitnessKey(witnessFile());
  const logs = [];
  const { svc } = setup({ dir, fake, witness, logs });
  svc.start();
  svc.stop();
  assert.deepEqual(held(), [], "no key.json, .bak or other copy is left");
  for (const owner of [A, B]) {
    const opFile = path.join(ownerDir(dir, owner), "operator.json");
    assert.equal(JSON.parse(readFileSync(opFile, "utf8")).value.operatorId, ids[owner]);
    assert.doesNotMatch(readFileSync(opFile, "utf8"), /PRIVATE KEY/);
  }
  const moved = logs.filter((l) => l.event === "shadow_held_keys_migrated");
  assert.deepEqual(moved, [{ event: "shadow_held_keys_migrated", owners: 2, failed: 0 }], "counts only");

  // Once is enough: a second start finds nothing, changes nothing, and says nothing.
  const again = setup({ dir, fake, witness, logs });
  again.svc.start();
  again.svc.stop();
  assert.equal(logs.filter((l) => l.event === "shadow_held_keys_migrated").length, 1);
  for (const owner of [A, B]) assert.equal(JSON.parse(readFileSync(path.join(ownerDir(dir, owner), "operator.json"), "utf8")).value.operatorId, ids[owner]);
  // And the next session is still the same operator.
  assert.equal((await shortSession(again.svc, B)).closed.pin.operatorId, ids[B]);
});

test("switched back to no witness key, an owner keeps the operator id from operator.json", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-back-"));
  const fake = new FakeLedger();
  const witnessed = setup({ dir, fake, witness: loadWitnessKey(witnessFile()) });
  const first = await shortSession(witnessed.svc);
  witnessed.svc.stop();
  const { svc } = setup({ dir, fake });
  const next = await shortSession(svc);
  assert.equal(next.closed.pin.operatorId, first.closed.pin.operatorId);
  assert.ok(existsSync(path.join(ownerDir(dir, A), "key.json")), "a legacy key, under the same operator id");
  const { packet, pin } = await packetOf(svc, next.closed.links);
  assert.equal(packet.checkpoint.body.operatorId, first.closed.pin.operatorId);
  assert.equal((await verifyPacket(packet, { pin })).result, "pass");
});

test("records made before the witness key still verify after the switch and after the rollback", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-roundtrip-"));
  const fake = new FakeLedger();
  const keyFile = path.join(ownerDir(dir, A), "key.json");
  const opFile = path.join(ownerDir(dir, A), "operator.json");
  const verifies = async (svc, links, pin) => {
    const { packet } = await packetOf(svc, links);
    const v = await verifyPacket(packet, { pin });
    assert.equal(v.result, "pass", JSON.stringify(v.checks, null, 1));
    return packet;
  };

  // 1. No witness key: session A under the account's own key.
  const before = setup({ dir, fake });
  const a = await shortSession(before.svc);
  const first = await packetOf(before.svc, a.closed.links);
  assert.equal((await verifyPacket(first.packet, { pin: first.pin })).result, "pass");
  assert.deepEqual(first.packet.checkpoint.body.knownLimits, HOSTED_LIMITS);
  const operatorId = a.closed.pin.operatorId;
  const legacyKey = first.packet.checkpoint.publicKey;
  before.svc.stop();

  // 2. Restart with the witness key.
  const witness = loadWitnessKey(witnessFile());
  const switched = setup({ dir, fake, witness });
  switched.svc.start(); // the start-time migration of every owner's held key
  assert.equal(existsSync(keyFile), false, "the held key is gone");
  assert.equal(JSON.parse(readFileSync(opFile, "utf8")).value.operatorId, operatorId);
  const aSwitched = await verifies(switched.svc, a.closed.links, first.pin);
  assert.equal(aSwitched.checkpoint.publicKey, legacyKey);
  assert.deepEqual(aSwitched.checkpoint.body.knownLimits, HOSTED_LIMITS);
  const html = await switched.svc.summaryForCap(capOf(a.closed.links));
  // The viewer shows no key line for a legacy record (the limits line it carries is the packet's, checked above).
  assert.match(html, /Matches what the server signed/);
  assert.doesNotMatch(html, /Witnessed by Clockchain/);
  assert.doesNotMatch(html, /Signed by agent/);
  assert.match(html, /Result: pass/);
  const b = await shortSession(switched.svc);
  assert.equal(b.closed.pin.operatorId, operatorId);
  const bPacket = await verifies(switched.svc, b.closed.links, b.closed.pin);
  assert.equal(bPacket.checkpoint.publicKey, witness.publicKey());
  assert.equal(bPacket.checkpoint.body.knownLimits.at(-1), WITNESSED);
  switched.svc.stop();

  // 3. Restart without it: the rollback.
  const back = setup({ dir, fake });
  await verifies(back.svc, a.closed.links, first.pin);
  await verifies(back.svc, b.closed.links, b.closed.pin);
  const c = await shortSession(back.svc);
  assert.equal(c.closed.pin.operatorId, operatorId);
  assert.ok(existsSync(keyFile), "a fresh per-account key");
  const cPacket = await verifies(back.svc, c.closed.links, c.closed.pin);
  assert.equal(cPacket.checkpoint.body.operatorId, operatorId);
  assert.notEqual(cPacket.checkpoint.publicKey, legacyKey, "a new key, not the deleted one");
  assert.notEqual(cPacket.checkpoint.publicKey, witness.publicKey());
  assert.deepEqual(cPacket.checkpoint.body.knownLimits, HOSTED_LIMITS);
  assert.equal(JSON.parse(readFileSync(opFile, "utf8")).value.operatorId, operatorId);
});

test("verifyPacket passes and the pin fingerprint is the witness fingerprint", async () => {
  const witness = loadWitnessKey(witnessFile());
  const { svc } = setup({ witness });
  const { closed } = await shortSession(svc);
  const { packet, pin } = await packetOf(svc, closed.links);
  assert.equal(pin.publicKeyFingerprint, fingerprint(witness.publicKey()));
  assert.equal(closed.pin.publicKeyFingerprint, fingerprint(witness.publicKey()));
  const v = await verifyPacket(packet, { pin });
  assert.equal(v.result, "pass", JSON.stringify(v.checks, null, 1));
});

test("knownLimits says witnessed", async () => {
  const witness = loadWitnessKey(witnessFile());
  const { svc } = setup({ witness });
  const { closed } = await shortSession(svc);
  const { packet } = await packetOf(svc, closed.links);
  assert.deepEqual(packet.checkpoint.body.knownLimits, limitsFor("witness"));
  assert.equal(packet.checkpoint.body.knownLimits.at(-1), WITNESSED);
  // Only the last line depends on the mode.
  assert.deepEqual(limitsFor("legacy"), HOSTED_LIMITS);
  assert.deepEqual(limitsFor("witness").slice(0, -1), HOSTED_LIMITS.slice(0, -1));
  assert.deepEqual(limitsFor("agent").slice(0, -1), HOSTED_LIMITS.slice(0, -1));
  assert.equal(limitsFor("agent").at(-1), AGENT_SIGNED);
});

test("without a witness key, behaviour is byte-identical", async () => {
  const { svc, dir } = setup();
  const { closed } = await shortSession(svc);
  const { packet, pin } = await packetOf(svc, closed.links);
  assert.deepEqual(packet.checkpoint.body.knownLimits, HOSTED_LIMITS);
  assert.ok(existsSync(path.join(ownerDir(dir, A), "key.json")));
  assert.equal(existsSync(path.join(ownerDir(dir, A), "operator.json")), false);
  assert.equal((await verifyPacket(packet, { pin })).result, "pass");
});

for (const withWitness of [false, true]) {
  test(`agent owners get agent-<root> and no keys, and the server never signs for them (${withWitness ? "witness" : "no witness"})`, async () => {
    const witness = withWitness ? loadWitnessKey(witnessFile()) : undefined;
    const { svc, dir } = setup({ witness });
    const s1 = await svc.startSession(AGENT, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
    const s2 = await svc.startSession(AGENT, { title: "another" }, BASE);
    const meta1 = svc.store.readMeta(ownerKeyOf(AGENT), s1.session_id);
    const meta2 = svc.store.readMeta(ownerKeyOf(AGENT), s2.session_id);
    assert.equal(meta1.operatorId, `agent-${ROOT.slice(0, 32)}`);
    assert.equal(meta2.operatorId, meta1.operatorId);
    assert.equal(existsSync(path.join(ownerDir(dir, AGENT), "key.json")), false);
    assert.equal(existsSync(path.join(ownerDir(dir, AGENT), "operator.json")), false);
    await svc.record(AGENT, { session_id: s1.session_id, agent: "planner", kind: "task", content: "Find flights" });
    // Signing is the agent's (test/shadow-agent-sign.test.mjs): a hash to sign, never a witness or legacy signature.
    const r = await svc.checkpoint(AGENT, { session_id: s1.session_id });
    assert.match(r.sign.hash, /^[0-9a-f]{64}$/);
    assert.equal(svc.store.readMeta(ownerKeyOf(AGENT), s1.session_id).checkpoint, null);
    assert.equal(existsSync(path.join(ownerDir(dir, AGENT), "key.json")), false);
  });
}

test("checkpointBody builds the unsigned agent-mode body for the agent to sign", async () => {
  const { svc } = setup();
  const s = await svc.startSession(AGENT, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  await svc.record(AGENT, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  const meta = svc.store.readMeta(ownerKeyOf(AGENT), s.session_id);
  const events = svc.store.readEvents(meta);
  const r = checkpointBody(meta, events, new Date(), "agent");
  assert.ok(!("unchanged" in r));
  assert.equal(r.hash, hash(DOMAIN.checkpoint, r.body));
  assert.equal(r.body.operatorId, `agent-${ROOT.slice(0, 32)}`);
  assert.equal(r.body.count, events.length);
  assert.deepEqual(r.body.knownLimits, limitsFor("agent"));
  assert.equal("signature" in r, false);
});

test("retention and account deletion remove operator.json as they removed key.json", async () => {
  const witness = loadWitnessKey(witnessFile());
  const { svc, clock, dir } = setup({ witness });
  const s = await svc.startSession(A, { title: "old" }, BASE);
  const opFile = path.join(ownerDir(dir, A), "operator.json");
  assert.ok(existsSync(opFile));
  clock.t += 31 * DAY;
  assert.equal(svc.sweep().removed, 1);
  assert.equal(existsSync(path.join(ownerDir(dir, A), "sessions", s.session_id)), false);
  assert.equal(existsSync(ownerDir(dir, A)), false, "the owner goes once nothing is left and its operator id is old");

  // A young operator.json keeps an owner with no sessions for now.
  const young = setup({ witness });
  await young.svc.startSession(A, { title: "kept" }, BASE);
  const youngFile = path.join(ownerDir(young.dir, A), "operator.json");
  const sid = young.svc.store.sessionIds(ownerKeyOf(A))[0];
  young.svc.store.deleteSession(ownerKeyOf(A), sid, null);
  young.svc.sweep();
  assert.ok(existsSync(youngFile));
  // Old enough: removed.
  const past = (Date.now() - 40 * DAY) / 1000;
  utimesSync(youngFile, past, past);
  young.svc.sweep();
  assert.equal(existsSync(ownerDir(young.dir, A)), false);

  const del = setup({ witness });
  await del.svc.startSession(A, { title: "to delete" }, BASE);
  assert.ok(existsSync(path.join(ownerDir(del.dir, A), "operator.json")));
  await del.svc.deleteOwner(A, () => {});
  assert.equal(existsSync(ownerDir(del.dir, A)), false);
});

test("loadWitnessKey refuses a missing file, a non-Ed25519 key and a public key, without echoing the file", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-bad-"));
  assert.throws(() => loadWitnessKey(path.join(dir, "missing.pem")), /SHADOW_WITNESS_KEY_FILE/);
  assert.throws(() => loadWitnessKey(witnessFile("ec")), /Ed25519/);
  const pub = path.join(dir, "public.pem");
  writeFileSync(pub, generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  assert.throws(() => loadWitnessKey(pub), /SHADOW_WITNESS_KEY_FILE/);
  const junk = path.join(dir, "junk.pem");
  const secret = randomBytes(24).toString("hex");
  writeFileSync(junk, `-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----\n`, { mode: 0o600 });
  assert.throws(() => loadWitnessKey(junk), (e) => {
    assert.match(e.message, /SHADOW_WITNESS_KEY_FILE/);
    assert.doesNotMatch(e.message, new RegExp(secret));
    return true;
  });
  // A good key signs, and its public key is the canonical SPKI PEM.
  const good = loadWitnessKey(witnessFile());
  assert.match(good.publicKey(), /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/]{59}=\n-----END PUBLIC KEY-----\n$/);
  assert.match(good.sign("00".repeat(32)), /^[A-Za-z0-9+/]{86}==$/);
});

// ---- the published key, over HTTP ---------------------------------------------------------------------------------

const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "MCP_LOG_BUDGET", "SHADOW_WITNESS_KEY_FILE"];
const WELL_KNOWN = "/.well-known/clockchain-witness-key.json";

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  __setShadowLedgerForTests(new FakeLedger());
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  const stateDir = mkdtempSync(path.join(tmpdir(), "shadow-witness-http-"));
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "witness-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"), MCP_PUBLIC_URL: BASE, SHADOW_ENABLED: "1", ...env });
  const errors = [];
  const original = console.error;
  console.error = (...args) => { errors.push(args.join(" ")); };
  let server;
  try {
    server = await runHttp();
    if (!server.listening) await once(server, "listening");
  } finally {
    console.error = original;
  }
  return {
    url: `http://127.0.0.1:${server.address().port}`, errors,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

test("GET /.well-known/clockchain-witness-key.json publishes the witness key, with no auth", async () => {
  const file = witnessFile();
  const app = await boot({ SHADOW_WITNESS_KEY_FILE: file });
  try {
    const res = await fetch(`${app.url}${WELL_KNOWN}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /application\/json/);
    const body = await res.json();
    const expected = loadWitnessKey(file).publicKey();
    assert.deepEqual(body, { publicKey: expected, fingerprint: fingerprint(expected) });
    assert.doesNotMatch(JSON.stringify(body), /PRIVATE/);
  } finally {
    await app.close();
  }
});

test("without a witness key the route is 404; a bad key file keeps Shadow from starting, and says why without the key", async () => {
  const off = await boot({});
  try {
    assert.equal((await fetch(`${off.url}${WELL_KNOWN}`)).status, 404);
  } finally {
    await off.close();
  }
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-witness-badboot-"));
  const junk = path.join(dir, "junk.pem");
  const secret = randomBytes(24).toString("hex");
  writeFileSync(junk, `-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----\n`, { mode: 0o600 });
  for (const file of [path.join(dir, "missing.pem"), witnessFile("ec"), junk]) {
    const bad = await boot({ SHADOW_WITNESS_KEY_FILE: file });
    try {
      const line = bad.errors.find((l) => l.includes("shadow_unavailable"));
      assert.ok(line, bad.errors.join("\n"));
      const logged = JSON.parse(line);
      assert.equal(logged.error, "ShadowConfigError");
      assert.match(logged.reason, /SHADOW_WITNESS_KEY_FILE/);
      assert.doesNotMatch(bad.errors.join("\n"), new RegExp(secret));
      assert.equal((await fetch(`${bad.url}/shadow/mcp`, { method: "POST" })).status, 503);
      assert.equal((await fetch(`${bad.url}${WELL_KNOWN}`)).status, 404);
    } finally {
      await bad.close();
    }
  }
});
