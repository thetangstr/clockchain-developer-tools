// O-1 sealed-log lanes: enrollment, contract-signed lane-open, run link,
// ac-terminal-receipt/v2, the /receipt read route, the lane-mode forwarder,
// and TELEMETRY_ANCHOR_TOKEN_FILE. Loopback ports 19400-19439 only.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createEnrollmentRegistry,
  createLaneForwarder,
  createLaneService,
  createRunLedger,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  enrollParty,
  laneOpenMessage,
  linkDigestOf,
  openSealJwk,
  resolveAnchorToken,
  runEnrollCli,
  runLinkMessage,
  startFromEnv,
  verifyRecords,
} from "../dist/index.js";

let nextPort = 19400;
const port = () => {
  const p = nextPort;
  nextPort = nextPort >= 19439 ? 19400 : nextPort + 1;
  return p;
};

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };
const contract = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contract.publicKey };
const peer = generateKeyPairSync("ed25519"); // a key the sink never pinned (peer env / attacker)

const x25519 = () => {
  const kp = generateKeyPairSync("x25519");
  const jwk = kp.privateKey.export({ format: "jwk" });
  return { jwk, pub: `0x${Buffer.from(jwk.x, "base64url").toString("hex")}` };
};
const buyerKey = x25519();
const providerKey = x25519();

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();
const SPAN = (name) => JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ name }] }] }] });

function laneOpen({ keyId = "buyer-key", role = "buyer", mcpSessionId = "sess-1", ts = T0, signer = contract.privateKey, signerKeyId = "contract-server", extra = {} } = {}) {
  const fields = { keyId, role, mcpSessionId, ts: iso(ts) };
  const sig = sign(null, Buffer.from(laneOpenMessage(fields, { alg: "ed25519", keyId: signerKeyId }), "utf8"), signer);
  return { schema: "ac-lane-open/v1", ...fields, ...extra, signature: { alg: "ed25519", keyId: signerKeyId, sig: `0x${sig.toString("hex")}` } };
}

function runLink(runId, lanes, ts = T0, signer = contract.privateKey) {
  const sig = sign(null, Buffer.from(runLinkMessage({ runId, lanes, ts: iso(ts) }, { alg: "ed25519", keyId: "contract-server" }), "utf8"), signer);
  return { schema: "ac-run-link/v1", runId, lanes, ts: iso(ts), signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

function receiptV2(runId, lanes, ts = T0, linkDigest = linkDigestOf(runId, lanes)) {
  const fields = { schema: "ac-terminal-receipt/v2", runId, terminalState: "settled", ts: iso(ts), lanes, linkDigest };
  const sig = sign(null, Buffer.from(canonicalJson({ ...fields, alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

function receiptV1(runId, ts = T0) {
  const fields = { schema: "ac-terminal-receipt/v1", runId, terminalState: "settled", ts: iso(ts), alg: "ed25519", keyId: "contract-server" };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), contract.privateKey);
  const { alg, keyId, ...rest } = fields;
  return { ...rest, signature: { alg, keyId, sig: `0x${sig.toString("hex")}` } };
}

const stateDir = () => mkdtempSync(path.join(tmpdir(), "o1-lanes-"));

// Other local agents share the 194xx range — skip a port that is taken.
async function listen(server) {
  for (let tries = 0; ; tries += 1) {
    const p = port();
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(p, "127.0.0.1", () => { server.off("error", reject); resolve(); });
      });
      return `http://127.0.0.1:${p}`;
    } catch (err) {
      if (err.code !== "EADDRINUSE" || tries >= 40) throw err;
    }
  }
}

async function boot(t, { dir = stateDir(), t0 = T0, sinkOpts = {}, laneOpts = {}, enroll = true } = {}) {
  let now = t0;
  const clock = () => now;
  const ledger = createRunLedger({ file: path.join(dir, "runs.json"), now: clock });
  const tokens = createTokenStore({ now: clock, recordsFile: path.join(dir, "tokens.json") });
  if (enroll) {
    await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "buyer-key", role: "buyer", x25519: buyerKey.pub });
    await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "provider-key", role: "provider", x25519: providerKey.pub });
  }
  const enrollments = createEnrollmentRegistry({ file: path.join(dir, "enrollments.json") });
  const lanes = createLaneService({
    tokens, enrollments, contractKeys: contractPublicKeys, file: path.join(dir, "lanes.json"), now: clock, ...laneOpts,
  });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: clock, runLedger: ledger, lanes,
    contractKeys: contractPublicKeys, flushGraceMs: 0, ...sinkOpts,
  });
  const servers = createTelemetrySinkServer({ sink, tokens, lanes });
  const writeUrl = await listen(servers.write);
  const readUrl = await listen(servers.read);
  const closeUrl = await listen(servers.close);
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  return { dir, sink, tokens, lanes, writeUrl, readUrl, closeUrl, setNow: (ms) => { now = ms; } };
}

const postJson = (url, p, body, token) => fetch(url + p, {
  method: "POST",
  headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const get = (url, p, token) => fetch(url + p, { headers: token ? { authorization: `Bearer ${token}` } : {} });

async function openLane(env, opts) {
  const res = await postJson(env.closeUrl, "/v1/lanes/open", laneOpen(opts));
  const text = await res.text();
  return { status: res.status, text, body: JSON.parse(text) };
}

// ---------------------------------------------------------------- enrollment

test("enrollment: admin CLI writes public material only; write-once per keyId; server reads by mtime", async () => {
  const dir = stateDir();
  const file = path.join(dir, "enrollments.json");
  const registry = createEnrollmentRegistry({ file });
  assert.equal(registry.get("buyer-key"), undefined);

  const out = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk) => { out.push(String(chunk)); return true; };
  let code;
  try {
    code = await runEnrollCli(["--keyId", "buyer-key", "--role", "buyer", "--x25519", buyerKey.pub, "--state-dir", dir]);
  } finally {
    process.stdout.write = origWrite;
  }
  assert.equal(code, 0);
  assert.equal(JSON.parse(out.find((l) => l.startsWith('{"enrollment"'))).enrollment.x25519, buyerKey.pub);
  assert.equal(registry.get("buyer-key").x25519, buyerKey.pub, "picked up by mtime, no restart");
  assert.equal(registry.get("buyer-key").role, "buyer");

  // Identical re-enroll is a no-op; a different key or role is refused.
  assert.equal((await enrollParty({ file, keyId: "buyer-key", role: "buyer", x25519: buyerKey.pub })).created, false);
  await assert.rejects(() => enrollParty({ file, keyId: "buyer-key", role: "buyer", x25519: providerKey.pub }), /different key or role/);
  await assert.rejects(() => enrollParty({ file, keyId: "buyer-key", role: "provider", x25519: buyerKey.pub }), /different key or role/);
  await assert.rejects(() => enrollParty({ file, keyId: "k", role: "buyer", x25519: `0x${"0".repeat(64)}` }), /all-zero/);

  // Stored entries carry exactly {role, x25519, enrolledAtMs} — no secret fields.
  const doc = JSON.parse(readFileSync(file, "utf8"));
  assert.deepEqual(Object.keys(doc.entries["buyer-key"]).sort(), ["enrolledAtMs", "role", "x25519"]);

  // A file that smuggles a private field fails closed.
  const bad = path.join(stateDir(), "enrollments.json");
  writeFileSync(bad, JSON.stringify({ schema: "ac-telemetry.enrollments/v1", entries: { k: { role: "buyer", x25519: buyerKey.pub, enrolledAtMs: 1, d: buyerKey.jwk.d } } }));
  assert.throws(() => createEnrollmentRegistry({ file: bad }), /bad entry shape/);
});

test("enrollment: no HTTP route on any listener writes or reads an enrollment", async (t) => {
  const env = await boot(t);
  for (const url of [env.writeUrl, env.readUrl, env.closeUrl]) {
    for (const p of ["/v1/enroll", "/v1/enrollments", "/v1/enrollments/buyer-key"]) {
      assert.equal((await postJson(url, p, { keyId: "x", role: "buyer", x25519: buyerKey.pub })).status, 404, `${url}${p}`);
      assert.equal((await get(url, p)).status, 404, `${url}${p}`);
    }
  }
  assert.equal(env.lanes.lane("x"), undefined);
});

// ---------------------------------------------------------------- lane open

test("lane-open: mints, seals ONLY to the enrolled key bound to (laneId, role), returns ciphertext only", async (t) => {
  const env = await boot(t);
  const before = env.tokens.listRecords().length;
  const r = await openLane(env, { keyId: "buyer-key", role: "buyer", mcpSessionId: "sess-a" });
  assert.equal(r.status, 200);
  assert.match(r.body.laneId, /^lane:[0-9a-f]{32}$/);
  assert.deepEqual(Object.keys(r.body).sort(), ["keyId", "laneId", "mcpSessionId", "role", "sealedBox"]);
  assert.doesNotMatch(r.text, /otlp-ing-/, "no plaintext token in the response");
  assert.equal(env.tokens.listRecords().length, before + 1);

  const token = openSealJwk(buyerKey.jwk, r.body.sealedBox, { runId: r.body.laneId, role: "buyer" });
  assert.match(token, /^otlp-ing-/);
  // The box does not open under another key, role, or lane.
  assert.throws(() => openSealJwk(providerKey.jwk, r.body.sealedBox, { runId: r.body.laneId, role: "buyer" }));
  assert.throws(() => openSealJwk(buyerKey.jwk, r.body.sealedBox, { runId: r.body.laneId, role: "provider" }));
  assert.throws(() => openSealJwk(buyerKey.jwk, r.body.sealedBox, { runId: `lane:${"0".repeat(32)}`, role: "buyer" }));

  // The token ingests into the lane's own chain, and is write-only.
  const ing = await postJson(env.writeUrl, "/v1/traces", SPAN("first"), token);
  assert.equal(ing.status, 200);
  assert.equal((await ing.json()).runId, r.body.laneId);
  assert.equal((await get(env.readUrl, `/v1/runs/${r.body.laneId}/head`, token)).status, 403);
  const lane = env.lanes.lane(r.body.laneId);
  assert.equal(lane.mcpSessionId, "sess-a");
  assert.equal(lane.runId, null);
});

test("lane-open: unknown keyId refused NOT_ENROLLED; role mismatch reads the same; nothing minted", async (t) => {
  const env = await boot(t);
  const before = env.tokens.listRecords().length;
  const unknown = await openLane(env, { keyId: "nobody", role: "buyer" });
  assert.equal(unknown.status, 404);
  assert.deepEqual(unknown.body, { error: "not_enrolled" });
  const wrongRole = await openLane(env, { keyId: "buyer-key", role: "provider" });
  assert.equal(wrongRole.status, 404);
  assert.deepEqual(wrongRole.body, { error: "not_enrolled" });
  assert.equal(env.tokens.listRecords().length, before, "no token minted for a refused open");
});

test("lane-open: a public key in the request is refused, even under a valid signature; nothing minted", async (t) => {
  const env = await boot(t);
  const attacker = x25519();
  const before = env.tokens.listRecords().length;
  for (const extra of [{ publicKey: attacker.pub }, { x25519: attacker.pub }, { sealTo: attacker.pub }, { recipient: attacker.pub }]) {
    // The signature covers the base fields; the extra field rides alongside.
    const res = await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: `pk-${Object.keys(extra)[0]}`, extra }));
    assert.equal(res.status, 400, JSON.stringify(extra));
    assert.deepEqual(await res.json(), { error: "request_invalid" });
  }
  assert.equal(env.tokens.listRecords().length, before);
  // And the sealed box of a normal open never opens under the attacker key.
  const ok = await openLane(env, { mcpSessionId: "pk-clean" });
  assert.throws(() => openSealJwk(attacker.jwk, ok.body.sealedBox, { runId: ok.body.laneId, role: "buyer" }));
});

test("lane-open: unsigned, wrong-key, peer-key, and stale requests are refused", async (t) => {
  const env = await boot(t);
  const body = laneOpen({ mcpSessionId: "sig-1" });
  const { signature, ...unsigned } = body;
  assert.equal((await postJson(env.closeUrl, "/v1/lanes/open", unsigned)).status, 400);
  assert.equal((await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-2", signer: peer.privateKey }))).status, 403);
  assert.equal((await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-3", signer: peer.privateKey, signerKeyId: "peer-contract" }))).status, 403);
  // A tampered field breaks the signature.
  assert.equal((await postJson(env.closeUrl, "/v1/lanes/open", { ...laneOpen({ mcpSessionId: "sig-4" }), mcpSessionId: "sig-5" })).status, 403);
  const stale = await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-6", ts: T0 - 10 * 60_000 }));
  assert.equal(stale.status, 403);
  assert.deepEqual(await stale.json(), { error: "receipt_stale" });
  // Lane routes do not exist on the write or read listener.
  assert.equal((await postJson(env.writeUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-7" }))).status, 404);
  assert.equal((await postJson(env.readUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-8" }))).status, 404);
  // Without a lane service the close listener has no lane routes at all.
  const tokens = createTokenStore();
  const bare = createTelemetrySinkServer({ sink: createTelemetrySink({ signer: sinkSigner, tokens }), tokens });
  const bareUrl = await listen(bare.close);
  t.after(() => bare.close.close());
  assert.equal((await postJson(bareUrl, "/v1/lanes/open", laneOpen({ mcpSessionId: "sig-9" }))).status, 404);
});

test("lane reuse refused: one lane per (keyId, role, session), across a restart; a lane links to one run; per-key cap", async (t) => {
  const env = await boot(t);
  const first = await openLane(env, { mcpSessionId: "reuse-1" });
  assert.equal(first.status, 200);
  const again = await openLane(env, { mcpSessionId: "reuse-1", ts: T0 + 1000 });
  assert.equal(again.status, 409);
  assert.deepEqual(again.body, { error: "lane_reused" });

  // A restarted lane service (same lanes.json) still refuses the session.
  const restarted = createLaneService({
    tokens: env.tokens, enrollments: createEnrollmentRegistry({ file: path.join(env.dir, "enrollments.json") }),
    contractKeys: contractPublicKeys, file: path.join(env.dir, "lanes.json"), now: () => T0,
  });
  assert.deepEqual(await restarted.open(laneOpen({ mcpSessionId: "reuse-1" })), { ok: false, code: "LANE_REUSED" });

  // A linked lane cannot join a second run.
  const lanesA = { buyer: [first.body.laneId], provider: [] };
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-A/link", runLink("run-A", lanesA))).status, 200);
  const toB = await postJson(env.closeUrl, "/v1/runs/run-B/link", runLink("run-B", lanesA));
  assert.equal(toB.status, 409);
  assert.deepEqual(await toB.json(), { error: "lane_reused" });

  // Cap: 8 unlinked lanes per keyId inside the window.
  for (let i = 0; i < 8; i += 1) assert.equal((await openLane(env, { mcpSessionId: `cap-${i}` })).status, 200);
  const capped = await openLane(env, { mcpSessionId: "cap-8" });
  assert.equal(capped.status, 429);
  assert.deepEqual(capped.body, { error: "lane_limit" });
  // Past the lane window the old unlinked lanes stop counting.
  env.setNow(T0 + 7 * 60 * 60 * 1000);
  assert.equal((await openLane(env, { mcpSessionId: "cap-9", ts: T0 + 7 * 60 * 60 * 1000 })).status, 200);
});

// ---------------------------------------------------------------- link

test("link: contract-signed, write-once, idempotent on identical re-delivery; refuses unknown / mis-roled lanes", async (t) => {
  const env = await boot(t);
  const b = (await openLane(env, { mcpSessionId: "l-b" })).body.laneId;
  const p = (await openLane(env, { keyId: "provider-key", role: "provider", mcpSessionId: "l-p" })).body.laneId;
  const lanes = { buyer: [b], provider: [p] };

  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", lanes, T0, peer.privateKey))).status, 403);
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-X/link", runLink("run-L", lanes))).status, 400, "path/body runId mismatch");
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", { buyer: [p], provider: [b] }))).status, 409, "role slot mismatch");
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", { buyer: [`lane:${"a".repeat(32)}`], provider: [] }))).status, 409, "unknown lane");

  const ok = await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", lanes));
  assert.equal(ok.status, 200);
  const okBody = await ok.json();
  assert.equal(okBody.linkDigest, linkDigestOf("run-L", lanes));
  assert.equal(okBody.created, true);
  const again = await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", lanes, T0 + 5000));
  assert.equal(again.status, 200);
  assert.equal((await again.json()).created, false);
  const conflict = await postJson(env.closeUrl, "/v1/runs/run-L/link", runLink("run-L", { buyer: [b], provider: [] }));
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: "link_conflict" });
  assert.equal(env.lanes.lane(b).runId, "run-L");
  // The contract runId is now a real run: a query token is mintable for it.
  assert.ok(env.tokens.mintQuery({ runId: "run-L" }).token);
});

// ---------------------------------------------------------------- close v2

async function linkedRun(env, runId, { buyerSpans = 1, providerSpans = 1 } = {}) {
  const b = await openLane(env, { mcpSessionId: `${runId}-b` });
  const p = await openLane(env, { keyId: "provider-key", role: "provider", mcpSessionId: `${runId}-p` });
  const bTok = openSealJwk(buyerKey.jwk, b.body.sealedBox, { runId: b.body.laneId, role: "buyer" });
  const pTok = openSealJwk(providerKey.jwk, p.body.sealedBox, { runId: p.body.laneId, role: "provider" });
  for (let i = 0; i < buyerSpans; i += 1) assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN(`b${i}`), bTok)).status, 200);
  for (let i = 0; i < providerSpans; i += 1) assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN(`p${i}`), pTok)).status, 200);
  const lanes = { buyer: [b.body.laneId], provider: [p.body.laneId] };
  assert.equal((await postJson(env.closeUrl, `/v1/runs/${runId}/link`, runLink(runId, lanes))).status, 200);
  return { lanes, bTok, pTok };
}

test("close: an unlinked lane (or any lane id) is RECEIPT_INVALID under v1 or v2; v2 without a link is RECEIPT_INVALID", async (t) => {
  const env = await boot(t);
  const lane = (await openLane(env, { mcpSessionId: "unlinked" })).body;
  const tok = openSealJwk(buyerKey.jwk, lane.sealedBox, { runId: lane.laneId, role: "buyer" });
  assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN("x"), tok)).status, 200);

  for (const receipt of [receiptV1(lane.laneId), receiptV2(lane.laneId, { buyer: [lane.laneId], provider: [] })]) {
    const res = await postJson(env.closeUrl, `/v1/runs/${lane.laneId}/close`, receipt);
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "receipt_invalid" });
  }
  // A v2 for a contract runId that was never linked.
  const res = await postJson(env.closeUrl, "/v1/runs/run-nolink/close", receiptV2("run-nolink", { buyer: [lane.laneId], provider: [] }));
  assert.equal(res.status, 403);
  assert.equal(env.sink.isClosed(lane.laneId), false, "the lane is still open — only its link or window seals it");
});

test("close v2: lane mismatch, wrong linkDigest, and v1 on a linked run are RECEIPT_INVALID; a match freezes every lane", async (t) => {
  const env = await boot(t);
  const { lanes, bTok } = await linkedRun(env, "run-v2", { buyerSpans: 2, providerSpans: 1 });
  const other = (await openLane(env, { mcpSessionId: "stranger" })).body.laneId;

  const bad = [
    receiptV2("run-v2", { buyer: [other], provider: lanes.provider }),
    receiptV2("run-v2", { buyer: lanes.buyer, provider: [] }),
    receiptV2("run-v2", lanes, T0, `0x${"1".repeat(64)}`),
    receiptV1("run-v2"),
    { ...receiptV2("run-v2", lanes), extra: true },
  ];
  for (const receipt of bad) {
    const res = await postJson(env.closeUrl, "/v1/runs/run-v2/close", receipt);
    assert.equal(res.status, 403, JSON.stringify(receipt).slice(0, 80));
  }
  assert.equal(env.sink.isClosed(lanes.buyer[0]), false);

  const ok = await postJson(env.closeUrl, "/v1/runs/run-v2/close", receiptV2("run-v2", lanes));
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.closed, true);
  assert.equal(body.head.schema, "ac-telemetry.run-set/v1");
  assert.equal(body.head.final, true);
  assert.equal(body.head.receiptDigest, canonicalDigest(receiptV2("run-v2", lanes)));
  for (const role of ["buyer", "provider"]) {
    for (const lane of body.head.lanes[role]) {
      assert.equal(lane.state, "final");
      assert.equal(lane.head.final, true);
      assert.equal(lane.head.closeCause, "terminal_receipt");
      assert.equal(lane.head.receiptDigest, body.head.receiptDigest);
      assert.equal(lane.refusedAfterClose, 0);
    }
  }
  assert.equal(body.head.lanes.buyer[0].head.recordCount, 2);
  // Lane ingest authority ended at the seal.
  assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN("late"), bTok)).status, 409);
  // A retried close returns the same run set.
  const retry = await (await postJson(env.closeUrl, "/v1/runs/run-v2/close", receiptV2("run-v2", lanes))).json();
  assert.equal(retry.head.receiptDigest, body.head.receiptDigest);
  assert.equal(retry.head.lanes.buyer[0].refusedAfterClose, 1, "the post-close refusal is disclosed per lane");
});

test("v1 still works for an unlinked run with lanes wired", async (t) => {
  const env = await boot(t);
  const ing = env.tokens.mintIngest({ runId: "run-v1", role: "buyer" });
  assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN("v1"), ing.token)).status, 200);
  const res = await postJson(env.closeUrl, "/v1/runs/run-v1/close", receiptV1("run-v1", T0));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.closed, true);
  assert.equal(body.head.schema, "ac-telemetry.chain-head/v1");
  assert.equal(body.head.final, true);
  // A v1-era run can never be re-purposed as a linked run.
  const lane = (await openLane(env, { mcpSessionId: "v1-lane" })).body.laneId;
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-v1/link", runLink("run-v1", { buyer: [lane], provider: [] }))).status, 409);
  // And the accepted v1 receipt is served to the verifier.
  const q = env.tokens.mintQuery({ runId: "run-v1" });
  const rr = await get(env.readUrl, "/v1/runs/run-v1/receipt", q.token);
  assert.equal(rr.status, 200);
  assert.deepEqual((await rr.json()).receipt, receiptV1("run-v1", T0));
});

test("GET /receipt: query-gated; serves the accepted v2 body the verifier checks itself; lanes readable by the run's query token", async (t) => {
  const env = await boot(t);
  const { lanes } = await linkedRun(env, "run-r");
  const q = env.tokens.mintQuery({ runId: "run-r" });
  assert.equal((await get(env.readUrl, "/v1/runs/run-r/receipt", q.token)).status, 404, "nothing accepted yet");
  const receipt = receiptV2("run-r", lanes);
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-r/close", receipt)).status, 200);

  assert.equal((await get(env.readUrl, "/v1/runs/run-r/receipt")).status, 401);
  const otherRun = env.tokens.mintIngest({ runId: "run-other", role: "buyer" });
  await postJson(env.writeUrl, "/v1/traces", SPAN("o"), otherRun.token);
  assert.equal((await get(env.readUrl, "/v1/runs/run-r/receipt", env.tokens.mintQuery({ runId: "run-other" }).token)).status, 403);
  assert.equal((await get(env.readUrl, "/v1/runs/run-r/receipt", otherRun.token)).status, 403, "ingest tokens never read");
  const got = await get(env.readUrl, "/v1/runs/run-r/receipt", q.token);
  assert.equal(got.status, 200);
  const served = (await got.json()).receipt;
  assert.deepEqual(served, receipt);
  // The verifier re-checks the contract signature over every field.
  const { signature, ...fields } = served;
  const { verify } = await import("node:crypto");
  assert.ok(verify(null, Buffer.from(canonicalJson({ ...fields, alg: signature.alg, keyId: signature.keyId }), "utf8"), contract.publicKey, Buffer.from(signature.sig.slice(2), "hex")));
  // The run head is the run set; each lane's records verify under the sink key.
  const head = await (await get(env.readUrl, "/v1/runs/run-r/head", q.token)).json();
  assert.equal(head.runSet.final, true);
  for (const laneId of [...lanes.buyer, ...lanes.provider]) {
    const rec = await (await get(env.readUrl, `/v1/runs/${laneId}/records`, q.token)).json();
    assert.equal(verifyRecords(rec.records, rec.head, sinkPublicKeys).ok, true);
  }
  // Another run's query token cannot read these lanes.
  assert.equal((await get(env.readUrl, `/v1/runs/${lanes.buyer[0]}/records`, env.tokens.mintQuery({ runId: "run-other" }).token)).status, 403);
});

test("lanes: a never-ingested linked lane seals empty; an unlinked lane expires on its window", async (t) => {
  const env = await boot(t, { sinkOpts: { runWindowMs: 60_000 } });
  const { lanes } = await linkedRun(env, "run-e", { buyerSpans: 1, providerSpans: 0 });
  const stray = (await openLane(env, { mcpSessionId: "stray" })).body;
  const strayTok = openSealJwk(buyerKey.jwk, stray.sealedBox, { runId: stray.laneId, role: "buyer" });
  assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN("s"), strayTok)).status, 200);

  const res = await (await postJson(env.closeUrl, "/v1/runs/run-e/close", receiptV2("run-e", lanes))).json();
  assert.equal(res.closed, true);
  assert.equal(res.head.lanes.provider[0].state, "empty");
  assert.equal(res.head.lanes.provider[0].head, null);
  assert.equal(env.tokens.isRunUsed(lanes.provider[0]), true, "an empty lane can never be re-minted");

  env.setNow(T0 + 61_000);
  assert.equal(env.sink.isClosed(stray.laneId), true);
  assert.equal(env.sink.head(stray.laneId).closeCause, "window_expired");
});

test("restart: an ingested lane is RUN_LOST, never reset; its v2 close signs lost:true", async (t) => {
  const dir = stateDir();
  const env1 = await boot(t, { dir });
  const { lanes, bTok } = await linkedRun(env1, "run-rs");
  // Same state volume, fresh process memory.
  const env2 = await boot(t, { dir, enroll: false });
  const lost = await postJson(env2.writeUrl, "/v1/traces", SPAN("after-restart"), bTok);
  assert.equal(lost.status, 410);
  assert.equal(env2.lanes.linkFor("run-rs").linkDigest, linkDigestOf("run-rs", lanes), "the link survived");
  const res = await (await postJson(env2.closeUrl, "/v1/runs/run-rs/close", receiptV2("run-rs", lanes))).json();
  assert.equal(res.closed, true);
  for (const l of [...res.head.lanes.buyer, ...res.head.lanes.provider]) {
    assert.equal(l.state, "lost");
    assert.equal(l.head.lost, true);
    assert.equal(verifyRecords([], l.head, sinkPublicKeys).code, "RUN_LOST");
  }
});

// ---------------------------------------------------------------- forwarder

test("lane forwarder: fails closed and buffers until the token arrives; pre-handshake spans are sealed and covered by the final head", async (t) => {
  const env = await boot(t);
  const fwd = createLaneForwarder({
    listen: { host: "127.0.0.1", port: 0 },
    control: { host: "127.0.0.1", port: 0 },
    targetBaseUrl: env.writeUrl,
    servicesPrivateKeyJwk: buyerKey.jwk,
    role: "buyer",
    maxQueuedRequests: 3,
  });
  const fwdUrl = await listen(fwd.server);
  const ctlUrl = await listen(fwd.control);
  t.after(() => { fwd.server.close(); fwd.control.close(); });

  // Before the handshake: buffered, nothing reaches the sink.
  const pre = [];
  for (let i = 0; i < 3; i += 1) {
    const res = await postJson(fwdUrl, "/v1/traces", SPAN(`pre-${i}`));
    assert.equal(res.status, 202);
    pre.push(SPAN(`pre-${i}`));
  }
  assert.equal((await postJson(fwdUrl, "/v1/traces", SPAN("overflow"))).status, 503, "bounded queue");
  assert.equal(fwd.status().tokenDelivered, false);
  assert.equal(fwd.status().forwarded, 0);

  const lane = (await openLane(env, { mcpSessionId: "fwd-1" })).body;
  // A box for another lane / role / recipient is refused and changes nothing.
  const other = (await openLane(env, { keyId: "provider-key", role: "provider", mcpSessionId: "fwd-p" })).body;
  assert.equal((await postJson(ctlUrl, "/v1/lane-token", { laneId: other.laneId, sealedBox: other.sealedBox })).status, 400);
  assert.equal((await postJson(ctlUrl, "/v1/lane-token", { laneId: other.laneId, sealedBox: lane.sealedBox })).status, 400);
  assert.equal(fwd.status().tokenDelivered, false);
  // The control route is not on the OTLP port: posting the box there delivers nothing.
  assert.notEqual((await postJson(fwdUrl, "/v1/lane-token", { laneId: lane.laneId, sealedBox: lane.sealedBox })).status, 200);
  assert.equal(fwd.status().tokenDelivered, false);
  const delivered = await postJson(ctlUrl, "/v1/lane-token", { laneId: lane.laneId, sealedBox: lane.sealedBox });
  assert.equal(delivered.status, 200);
  assert.equal((await postJson(ctlUrl, "/v1/lane-token", { laneId: lane.laneId, sealedBox: lane.sealedBox })).status, 409, "write-once");
  await fwd.idle();

  const live = await postJson(fwdUrl, "/v1/traces", SPAN("live"));
  assert.equal(live.status, 200);
  assert.equal((await live.json()).runId, lane.laneId);

  const lanes = { buyer: [lane.laneId], provider: [] };
  assert.equal((await postJson(env.closeUrl, "/v1/runs/run-fwd/link", runLink("run-fwd", lanes))).status, 200);
  const closed = await (await postJson(env.closeUrl, "/v1/runs/run-fwd/close", receiptV2("run-fwd", lanes))).json();
  const laneHead = closed.head.lanes.buyer[0].head;
  assert.equal(laneHead.final, true);
  const records = env.sink.exportRecords(lane.laneId);
  // The three pre-handshake spans land first, in order, byte-for-byte.
  assert.deepEqual(records.slice(0, 3).map((r) => r.body), pre);
  assert.equal(records.at(-1).body, SPAN("live"));
  assert.equal(laneHead.recordCount, records.length);
  assert.equal(verifyRecords(records, laneHead, sinkPublicKeys).ok, true);
});

test("lane forwarder: refuses non-loopback binds and a control listener on the OTLP port", () => {
  const base = { targetBaseUrl: "http://127.0.0.1:19439", servicesPrivateKeyJwk: buyerKey.jwk, role: "buyer" };
  assert.throws(() => createLaneForwarder({ ...base, listen: { host: "0.0.0.0", port: 19438 } }), /non-loopback/);
  assert.throws(() => createLaneForwarder({ ...base, listen: { host: "127.0.0.1", port: 19438 }, control: { host: "localhost", port: 19437 } }), /non-loopback/);
  assert.throws(() => createLaneForwarder({ ...base, listen: { host: "127.0.0.1", port: 19438 }, control: { host: "127.0.0.1", port: 19438 } }), /must not share/);
});

// ---------------------------------------------------------------- anchor token file

test("TELEMETRY_ANCHOR_TOKEN_FILE: read and trimmed; both-set, empty, missing, and multi-token files refuse", () => {
  const dir = stateDir();
  const file = path.join(dir, "anchor_token");
  writeFileSync(file, "anchor-test-value\n");
  chmodSync(file, 0o600);
  assert.equal(resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: file }), "anchor-test-value");
  assert.equal(resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN: "plain" }), "plain", "legacy env still accepted");
  assert.equal(resolveAnchorToken({}), undefined);
  assert.throws(() => resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: file, TELEMETRY_ANCHOR_TOKEN: "plain" }), /not both/);
  assert.throws(() => resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: path.join(dir, "missing") }), /not readable/);
  assert.throws(() => resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: dir }), /not a regular file/);
  const empty = path.join(dir, "empty");
  writeFileSync(empty, "  \n");
  assert.throws(() => resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: empty }), /exactly one non-empty token/);
  const two = path.join(dir, "two");
  writeFileSync(two, "a b\n");
  assert.throws(() => resolveAnchorToken({ TELEMETRY_ANCHOR_TOKEN_FILE: two }), /exactly one non-empty token/);
});

test("startFromEnv: URL + TOKEN_FILE boots with the anchor on; FILE without URL refuses; the token never reaches stdout", () => {
  const dir = stateDir();
  const file = path.join(dir, "anchor_token");
  writeFileSync(file, "anchor-test-value\n");
  const lines = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk) => { lines.push(String(chunk)); return true; };
  let servers;
  try {
    servers = startFromEnv({
      TELEMETRY_STATE_DIR: dir, TELEMETRY_ENV: "staging", TELEMETRY_BIND_HOST: "127.0.0.1",
      TELEMETRY_WRITE_PORT: "19430", TELEMETRY_READ_PORT: "19431", TELEMETRY_CLOSE_PORT: "19432",
      TELEMETRY_ANCHOR_MCP_URL: "http://127.0.0.1:19433/mcp",
      TELEMETRY_ANCHOR_TOKEN_FILE: file,
    });
  } finally {
    process.stdout.write = origWrite;
  }
  servers.write.close(); servers.read.close(); servers.close.close();
  const ready = JSON.parse(lines.find((l) => l.includes("telemetry-sink-ready")));
  assert.equal(ready.anchor, true);
  assert.doesNotMatch(lines.join(""), /anchor-test-value/);
  assert.throws(() => startFromEnv({ TELEMETRY_STATE_DIR: stateDir(), TELEMETRY_ENV: "staging", TELEMETRY_ANCHOR_TOKEN_FILE: file }), /both be set or both unset/);
});
