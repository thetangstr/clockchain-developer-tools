// CDT-SEC (state/ledger/notes/cdt-integration-security-review.md): sink-side
// fixes for L4 (lane store pruning), L5 (audience, lane release) and L7
// (no plaintext anchor token in production), L8 (forwarder control secret).
// Loopback only, OS-assigned ports; every key is generated.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createEnrollmentRegistry,
  createLaneService,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  enrollParty,
  resolveAnchorToken,
  laneOpenMessage,
  runLinkMessage,
} from "../dist/index.js";
import * as sinkLib from "../dist/index.js";

const contract = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contract.publicKey };
const buyerX = (() => {
  const jwk = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  return `0x${Buffer.from(jwk.x, "base64url").toString("hex")}`;
})();

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const HOUR = 3600_000;
const iso = (ms) => new Date(ms).toISOString();

const SINK_AUD = "ac-telemetry-test";

function laneOpen({ keyId = "buyer-key", role = "buyer", mcpSessionId, ts, aud = SINK_AUD }) {
  const fields = { aud, keyId, role, mcpSessionId, ts: iso(ts) };
  const sig = sign(null, Buffer.from(laneOpenMessage(fields, { alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { schema: "ac-lane-open/v1", ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

function runLink(runId, lanes, ts, aud = SINK_AUD) {
  const sig = sign(null, Buffer.from(runLinkMessage({ aud, runId, lanes, ts: iso(ts) }, { alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { schema: "ac-run-link/v1", aud, runId, lanes, ts: iso(ts), signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

async function laneStore() {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-sec-lanes-"));
  let now = T0;
  const clock = () => now;
  const tokens = createTokenStore({ now: clock, recordsFile: path.join(dir, "tokens.json") });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "buyer-key", role: "buyer", x25519: buyerX });
  const enrollments = createEnrollmentRegistry({ file: path.join(dir, "enrollments.json") });
  const file = path.join(dir, "lanes.json");
  const make = () => createLaneService({ audience: SINK_AUD, tokens, enrollments, contractKeys: contractPublicKeys, file, now: clock });
  return { dir, file, make, tokens, setNow: (ms) => { now = ms; }, now: () => now };
}

test("L4 sink: an unlinked lane past window + grace is pruned; a linked lane and its link are kept", async () => {
  const s = await laneStore();
  let lanes = s.make();
  const stale = await lanes.open(laneOpen({ mcpSessionId: "sess-stale", ts: T0 }));
  const linked = await lanes.open(laneOpen({ mcpSessionId: "sess-linked", ts: T0 }));
  assert.equal(stale.ok, true);
  assert.equal(linked.ok, true);
  const link = await lanes.link("run-1", runLink("run-1", { buyer: [linked.laneId], provider: [] }, T0));
  assert.equal(link.ok, true);
  assert.equal(statSync(s.file).mode & 0o777, 0o600, "lanes.json is owner-only");

  // Still inside window + grace: nothing is dropped.
  s.setNow(T0 + 7 * HOUR - 1);
  const mid = await lanes.open(laneOpen({ mcpSessionId: "sess-mid", ts: s.now() }));
  assert.equal(mid.ok, true);
  assert.ok(lanes.lane(stale.laneId), "kept until window + grace");

  // Past window (6 h) + grace (1 h): the next write prunes the stale lane.
  s.setNow(T0 + 7 * HOUR + 1);
  const fresh = await lanes.open(laneOpen({ mcpSessionId: "sess-fresh", ts: s.now() }));
  assert.equal(fresh.ok, true);
  assert.equal(lanes.lane(stale.laneId), undefined, "the expired unlinked lane is forgotten");
  assert.equal(lanes.lane(linked.laneId)?.runId, "run-1", "a linked lane is run evidence and is kept");
  assert.equal(lanes.linkFor("run-1")?.lanes.buyer[0], linked.laneId);
  const onDisk = JSON.parse(readFileSync(s.file, "utf8"));
  assert.equal(Object.hasOwn(onDisk.lanes, stale.laneId), false, "pruned from lanes.json too");
  assert.equal(Object.hasOwn(onDisk.lanes, linked.laneId), true);

  // A reload keeps the pruned view, and boot itself prunes what expired while down.
  s.setNow(T0 + 8 * HOUR); // sess-mid (opened at ~7 h) is still inside its window + grace
  lanes = s.make();
  assert.equal(lanes.lane(stale.laneId), undefined);
  assert.ok(lanes.lane(mid.laneId));
  s.setNow(T0 + 14 * HOUR);
  lanes = s.make();
  assert.equal(lanes.lane(mid.laneId), undefined, "boot prunes a lane that expired while the sink was down");
  assert.equal(Object.hasOwn(JSON.parse(readFileSync(s.file, "utf8")).lanes, mid.laneId), false);
  assert.equal(lanes.lane(linked.laneId)?.runId, "run-1");
});

test("L4 sink: a pruned lane's stale signed open cannot be replayed", async () => {
  const s = await laneStore();
  const lanes = s.make();
  const body = laneOpen({ mcpSessionId: "sess-replay", ts: T0 });
  assert.equal((await lanes.open(body)).ok, true);
  s.setNow(T0 + 8 * HOUR);
  await lanes.open(laneOpen({ mcpSessionId: "sess-other", ts: s.now() })); // triggers the prune
  const replay = await lanes.open(body);
  assert.deepEqual(replay, { ok: false, code: "RECEIPT_STALE" }, "the skew check refuses the old signed open");
});

function laneRelease({ laneId, keyId = "buyer-key", role = "buyer", mcpSessionId, ts, aud = SINK_AUD }) {
  const fields = { aud, laneId, keyId, role, mcpSessionId, ts: iso(ts) };
  // Looked up at call time so the file still loads on a build without it.
  const sig = sign(null, Buffer.from(sinkLib.laneReleaseMessage(fields, { alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { schema: "ac-lane-release/v1", ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

test("L5 sink: lane-open and run-link signed for another sink are refused", async () => {
  const s = await laneStore();
  const lanes = s.make();
  const ours = await lanes.open(laneOpen({ mcpSessionId: "sess-ours", ts: T0 }));
  assert.equal(ours.ok, true, JSON.stringify(ours));
  assert.deepEqual(await lanes.open(laneOpen({ mcpSessionId: "sess-other", ts: T0, aud: "another-sink" })),
    { ok: false, code: "RECEIPT_INVALID" });
  const noAud = laneOpen({ mcpSessionId: "sess-noaud", ts: T0 });
  delete noAud.aud;
  assert.deepEqual(await lanes.open(noAud), { ok: false, code: "REQUEST_INVALID" });
  assert.deepEqual(await lanes.link("run-x", runLink("run-x", { buyer: [ours.laneId], provider: [] }, T0, "another-sink")),
    { ok: false, code: "RECEIPT_INVALID" });
  assert.equal((await lanes.link("run-x", runLink("run-x", { buyer: [ours.laneId], provider: [] }, T0))).ok, true);
});

test("L5 sink: a released lane stops counting toward LANE_LIMIT and can never be linked", async () => {
  const s = await laneStore();
  const lanes = s.make();
  const opened = [];
  for (let i = 0; i < 8; i += 1) {
    const r = await lanes.open(laneOpen({ mcpSessionId: `sess-${i}`, ts: T0 }));
    assert.equal(r.ok, true);
    opened.push(r);
  }
  assert.deepEqual(await lanes.open(laneOpen({ mcpSessionId: "sess-8", ts: T0 })), { ok: false, code: "LANE_LIMIT" });

  // Wrong audience, wrong session, or a lane already linked: refused.
  assert.deepEqual(await lanes.release(laneRelease({ laneId: opened[0].laneId, mcpSessionId: "sess-0", ts: T0, aud: "another-sink" })),
    { ok: false, code: "RECEIPT_INVALID" });
  assert.deepEqual(await lanes.release(laneRelease({ laneId: opened[0].laneId, mcpSessionId: "sess-1", ts: T0 })),
    { ok: false, code: "LINK_INVALID" });
  assert.equal((await lanes.link("run-1", runLink("run-1", { buyer: [opened[7].laneId], provider: [] }, T0))).ok, true);
  assert.deepEqual(await lanes.release(laneRelease({ laneId: opened[7].laneId, mcpSessionId: "sess-7", ts: T0 })),
    { ok: false, code: "LANE_REUSED" });

  // The link freed one slot; release frees another.
  assert.equal((await lanes.open(laneOpen({ mcpSessionId: "sess-8", ts: T0 }))).ok, true);
  assert.deepEqual(await lanes.open(laneOpen({ mcpSessionId: "sess-9", ts: T0 })), { ok: false, code: "LANE_LIMIT" });
  assert.deepEqual(await lanes.release(laneRelease({ laneId: opened[0].laneId, mcpSessionId: "sess-0", ts: T0 })),
    { ok: true, laneId: opened[0].laneId });
  assert.deepEqual(await lanes.release(laneRelease({ laneId: opened[0].laneId, mcpSessionId: "sess-0", ts: T0 })),
    { ok: true, laneId: opened[0].laneId }, "idempotent");
  assert.equal((await lanes.open(laneOpen({ mcpSessionId: "sess-9", ts: T0 }))).ok, true);
  assert.equal(typeof lanes.lane(opened[0].laneId).releasedAtMs, "number");

  // Released: never linked, and the session stays used.
  assert.deepEqual(await lanes.link("run-2", runLink("run-2", { buyer: [opened[0].laneId], provider: [] }, T0)),
    { ok: false, code: "LINK_INVALID" });
  assert.deepEqual(await lanes.open(laneOpen({ mcpSessionId: "sess-0", ts: T0 })), { ok: false, code: "LANE_REUSED" });
  // Durable across a restart.
  const again = s.make();
  assert.equal(typeof again.lane(opened[0].laneId).releasedAtMs, "number");
});

async function listenClose(server) {
  // An OS-assigned loopback port: a fixed range collides with other local stacks.
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  return `http://127.0.0.1:${server.address().port}`;
}

test("L5 sink: the close listener serves POST /v1/lanes/release", async (t) => {
  const s = await laneStore();
  const lanes = s.make();
  const tokens = s.tokens;
  const sinkKeys = generateKeyPairSync("ed25519");
  const sink = createTelemetrySink({
    signer: { keyId: SINK_AUD, privateKey: sinkKeys.privateKey }, tokens, now: s.now, lanes,
    contractKeys: contractPublicKeys, flushGraceMs: 0,
  });
  const servers = createTelemetrySinkServer({ sink, tokens, lanes });
  const url = await listenClose(servers.close);
  t.after(() => servers.close.close());
  const opened = await lanes.open(laneOpen({ mcpSessionId: "sess-http", ts: T0 }));
  const post = (body) => fetch(`${url}/v1/lanes/release`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const bad = await post(laneRelease({ laneId: opened.laneId, mcpSessionId: "sess-http", ts: T0, aud: "another-sink" }));
  assert.equal(bad.status, 403);
  assert.deepEqual(await bad.json(), { error: "receipt_invalid" });
  const good = await post(laneRelease({ laneId: opened.laneId, mcpSessionId: "sess-http", ts: T0 }));
  assert.equal(good.status, 200);
  assert.deepEqual(await good.json(), { released: true, laneId: opened.laneId });
});

test("L7: production refuses the plaintext TELEMETRY_ANCHOR_TOKEN env; only _FILE is accepted", () => {
  for (const env of [{ TELEMETRY_ANCHOR_TOKEN: "plain" }, { TELEMETRY_ENV: "production", TELEMETRY_ANCHOR_TOKEN: "plain" },
    { TELEMETRY_ANCHOR_TOKEN: "" }]) {
    assert.throws(() => resolveAnchorToken(env), /refused in production; use TELEMETRY_ANCHOR_TOKEN_FILE/, JSON.stringify(env));
  }
  // The error never echoes the value.
  try { resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN: "anchor-secret-test-value" }); } catch (err) {
    assert.doesNotMatch(String(err), /anchor-secret-test-value/);
  }
  assert.equal(resolveAnchorToken({ TELEMETRY_ENV: "staging", TELEMETRY_ANCHOR_TOKEN: "plain" }), "plain");
  assert.equal(resolveAnchorToken({}), undefined);
});

test("L8: the lane-token control port requires this start's secret; the secret file is 0600 and replaced", async (t) => {
  const services = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  const make = () => sinkLib.createLaneForwarder({
    listen: { host: "127.0.0.1", port: 0 }, control: { host: "127.0.0.1", port: 0 },
    targetBaseUrl: "http://127.0.0.1:19469", servicesPrivateKeyJwk: services, role: "buyer",
  });
  const fwd = make();
  assert.match(fwd.controlSecret, /^[0-9a-f]{64}$/);
  assert.notEqual(make().controlSecret, fwd.controlSecret, "per start");
  const url = await listenClose(fwd.control);
  t.after(() => fwd.control.close());
  const post = (auth) => fetch(`${url}/v1/lane-token`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth === undefined ? {} : { authorization: auth }) },
    body: JSON.stringify({ laneId: `lane:${"0".repeat(32)}`, sealedBox: {} }),
  });
  for (const auth of [undefined, "Bearer ", `Bearer ${"f".repeat(64)}`, fwd.controlSecret]) {
    const res = await post(auth);
    assert.equal(res.status, 401, String(auth));
    assert.deepEqual(await res.json(), { error: "unauthorized" });
  }
  // With the secret the request reaches the box check (a bogus box: 400, still undelivered).
  assert.equal((await post(`Bearer ${fwd.controlSecret}`)).status, 400);
  assert.equal(fwd.status().tokenDelivered, false);

  const dir = mkdtempSync(path.join(tmpdir(), "cdt-sec-l8-"));
  const file = path.join(dir, "control.secret");
  writeFileSync(file, "stale\n", { mode: 0o644 });
  sinkLib.writeControlSecretFile(file, fwd.controlSecret);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(readFileSync(file, "utf8"), `${fwd.controlSecret}\n`);
});
