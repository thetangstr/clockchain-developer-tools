// CDT-GAPS gap 3: a linked (lane-mode) run gets ONE signed combined head —
// the same sink key and the same anchor-then-sign scheme as a single-lane
// head — opt-in via `signRunSet` / TELEMETRY_RUN_SET_HEAD=1. Loopback port 0.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createEnrollmentRegistry,
  createLaneService,
  createRunLedger,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  enrollParty,
  laneOpenMessage,
  linkDigestOf,
  openSealJwk,
  runLinkMessage,
  startFromEnv,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-gaps", privateKey: sinkKeys.privateKey };
const contract = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contract.publicKey };
const SINK_AUD = sinkSigner.keyId;

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
const contractSig = (message) => `0x${sign(null, Buffer.from(message, "utf8"), contract.privateKey).toString("hex")}`;

function laneOpen({ keyId, role, mcpSessionId, ts = T0 }) {
  const fields = { aud: SINK_AUD, keyId, role, mcpSessionId, ts: iso(ts) };
  const sig = contractSig(laneOpenMessage(fields, { alg: "ed25519", keyId: "contract-server" }));
  return { schema: "ac-lane-open/v1", ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig } };
}

function runLink(runId, lanes, ts = T0) {
  const sig = contractSig(runLinkMessage({ aud: SINK_AUD, runId, lanes, ts: iso(ts) }, { alg: "ed25519", keyId: "contract-server" }));
  return { schema: "ac-run-link/v1", aud: SINK_AUD, runId, lanes, ts: iso(ts), signature: { alg: "ed25519", keyId: "contract-server", sig } };
}

function receiptV2(runId, lanes, ts = T0) {
  const fields = { schema: "ac-terminal-receipt/v2", runId, terminalState: "settled", ts: iso(ts), lanes, linkDigest: linkDigestOf(runId, lanes) };
  const sig = contractSig(canonicalJson({ ...fields, alg: "ed25519", keyId: "contract-server" }));
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig } };
}

/** A TsaAnchor fake that records every subject it was asked to anchor. */
function recordingAnchor() {
  const subjects = [];
  return {
    subjects,
    async issue(digest) {
      subjects.push(digest);
      return { anchorId: `tsa:c-${subjects.length}`, eventHash: `0x${"ab".repeat(32)}`, ledger: { ledgerId: "clock-testnet", blockHeight: "9", time: "2030-01-01", status: "anchored" } };
    },
  };
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function boot(t, sinkOpts = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-gaps-runset-"));
  let now = T0;
  const clock = () => now;
  const ledger = createRunLedger({ file: path.join(dir, "runs.json"), now: clock });
  const tokens = createTokenStore({ now: clock, recordsFile: path.join(dir, "tokens.json") });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "buyer-key", role: "buyer", x25519: buyerKey.pub });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "provider-key", role: "provider", x25519: providerKey.pub });
  const enrollments = createEnrollmentRegistry({ file: path.join(dir, "enrollments.json") });
  const lanes = createLaneService({ audience: SINK_AUD, tokens, enrollments, contractKeys: contractPublicKeys, file: path.join(dir, "lanes.json"), now: clock });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: clock, runLedger: ledger, lanes,
    contractKeys: contractPublicKeys, flushGraceMs: 0, ...sinkOpts,
  });
  const servers = createTelemetrySinkServer({ sink, tokens, lanes });
  const writeUrl = await listen(servers.write);
  const readUrl = await listen(servers.read);
  const closeUrl = await listen(servers.close);
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  return { sink, tokens, writeUrl, readUrl, closeUrl, setNow: (ms) => { now = ms; } };
}

const postJson = (url, p, body, token) => fetch(url + p, {
  method: "POST",
  headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const getJson = async (url, p, token) => (await fetch(url + p, { headers: { authorization: `Bearer ${token}` } })).json();

async function linkedRun(env, runId, { buyerSpans = 2, providerSpans = 1 } = {}) {
  const b = await (await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ keyId: "buyer-key", role: "buyer", mcpSessionId: `${runId}-b` }))).json();
  const p = await (await postJson(env.closeUrl, "/v1/lanes/open", laneOpen({ keyId: "provider-key", role: "provider", mcpSessionId: `${runId}-p` }))).json();
  const bTok = openSealJwk(buyerKey.jwk, b.sealedBox, { runId: b.laneId, role: "buyer" });
  const pTok = openSealJwk(providerKey.jwk, p.sealedBox, { runId: p.laneId, role: "provider" });
  for (let i = 0; i < buyerSpans; i += 1) assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN(`b${i}`), bTok)).status, 200);
  for (let i = 0; i < providerSpans; i += 1) assert.equal((await postJson(env.writeUrl, "/v1/traces", SPAN(`p${i}`), pTok)).status, 200);
  const lanes = { buyer: [b.laneId], provider: [p.laneId] };
  assert.equal((await postJson(env.closeUrl, `/v1/runs/${runId}/link`, runLink(runId, lanes))).status, 200);
  return { lanes };
}

/** The verifier's check: the sink key signed canonicalJson({...fields, alg, keyId}). */
function verifySinkSignature(head) {
  const { signature, ...fields } = head;
  assert.equal(signature.alg, "ed25519");
  assert.equal(signature.keyId, sinkSigner.keyId);
  return verify(null, Buffer.from(canonicalJson({ ...fields, alg: signature.alg, keyId: signature.keyId }), "utf8"), sinkKeys.publicKey, Buffer.from(signature.sig.slice(2), "hex"));
}

test("gap 3: a linked run closes under ONE signed, anchored combined head — same key and scheme as a lane head; served on /head", async (t) => {
  const anchor = recordingAnchor();
  const env = await boot(t, { signRunSet: true, anchor });
  const { lanes } = await linkedRun(env, "run-g3");
  const receipt = receiptV2("run-g3", lanes);

  const res = await postJson(env.closeUrl, "/v1/runs/run-g3/close", receipt);
  assert.equal(res.status, 200);
  const set = (await res.json()).head;
  assert.equal(set.final, true);
  const combined = set.signedHead;
  assert.ok(combined, "the close answer carries the signed combined head");

  // Same key, same scheme as the single-lane SignedHead.
  assert.equal(combined.schema, "ac-telemetry.run-set-head/v1");
  assert.equal(verifySinkSignature(combined), true);
  const laneHead = set.lanes.buyer[0].head;
  assert.equal(verifySinkSignature(laneHead), true, "the lane head verifies by the very same routine");
  assert.equal(combined.signature.keyId, laneHead.signature.keyId);

  // Anchor-then-sign: the anchor covers the head minus `anchor` and `signature`, and rides inside the signature.
  const { signature: _s, anchor: headAnchor, ...unsigned } = combined;
  assert.equal(headAnchor.status, "anchored");
  assert.ok(anchor.subjects.includes(canonicalDigest(unsigned)), "the combined head's subject was anchored");
  assert.equal(anchor.subjects.length, 3, "two lane heads + one combined head, each anchored once");

  // It binds the run: link, receipt, every lane's WHOLE signed final head, the record total and the seal boundary.
  assert.equal(combined.runId, "run-g3");
  assert.equal(combined.linkDigest, linkDigestOf("run-g3", lanes));
  assert.equal(combined.receiptDigest, canonicalDigest(receipt));
  assert.equal(combined.final, true);
  assert.equal(combined.closeCause, "terminal_receipt");
  assert.equal(combined.closedAt, receipt.ts, "flushGrace 0: the seal boundary is the receipt ts");
  assert.equal(combined.lost, undefined);
  let total = 0;
  for (const role of ["buyer", "provider"]) {
    assert.equal(combined.lanes[role].length, set.lanes[role].length);
    combined.lanes[role].forEach((entry, i) => {
      const lane = set.lanes[role][i];
      assert.deepEqual(entry, {
        laneId: lane.laneId, state: "final", headDigest: canonicalDigest(lane.head), recordCount: lane.head.recordCount,
        keyId: lane.keyId, mcpSessionId: lane.mcpSessionId, openDigest: lane.openDigest,
      });
      total += lane.head.recordCount;
    });
  }
  assert.equal(combined.recordCount, total);
  assert.equal(total, 3);

  // Served as `head` on the read route (null before the change), byte-identical to the close answer.
  const q = env.tokens.mintQuery({ runId: "run-g3" });
  const read = await getJson(env.readUrl, "/v1/runs/run-g3/head", q.token);
  assert.deepEqual(read.head, combined);
  assert.deepEqual(read.runSet.signedHead, combined);

  // Signed once: a close retry and a later read return the same bytes; no second anchor.
  env.setNow(T0 + 60_000);
  const retry = (await (await postJson(env.closeUrl, "/v1/runs/run-g3/close", receipt)).json()).head;
  assert.deepEqual(retry.signedHead, combined);
  assert.deepEqual(await env.sink.runSetHead("run-g3"), combined);
  assert.equal(anchor.subjects.length, 3);

  // Tamper evidence: any field change breaks the signature.
  assert.equal(verifySinkSignature({ ...combined, recordCount: combined.recordCount + 1 }), false);
});

test("gap 3: null until the set is final; an empty lane is disclosed with headDigest null; no anchor configured signs without one", async (t) => {
  const env = await boot(t, { signRunSet: true, flushGraceMs: 30_000 });
  const { lanes } = await linkedRun(env, "run-g3b", { buyerSpans: 1, providerSpans: 0 });
  const q = env.tokens.mintQuery({ runId: "run-g3b" });

  const before = await getJson(env.readUrl, "/v1/runs/run-g3b/head", q.token);
  assert.equal(before.head, null);
  assert.equal(before.runSet.signedHead, null);

  const receipt = receiptV2("run-g3b", lanes);
  const pending = await (await postJson(env.closeUrl, "/v1/runs/run-g3b/close", receipt)).json();
  assert.deepEqual(pending, { closed: false, pending: true, closedAt: iso(T0 + 30_000) }, "lanes still in their flush grace");
  assert.equal((await getJson(env.readUrl, "/v1/runs/run-g3b/head", q.token)).head, null);
  assert.equal(await env.sink.runSetHead("run-g3b"), null);

  env.setNow(T0 + 30_000);
  const read = await getJson(env.readUrl, "/v1/runs/run-g3b/head", q.token);
  const combined = read.head;
  assert.ok(combined, "the seal boundary passed: the combined head is signed on read");
  assert.equal(verifySinkSignature(combined), true);
  assert.equal(combined.anchor, undefined, "no anchor configured — as a lane head");
  assert.equal(combined.closedAt, iso(T0 + 30_000));
  assert.deepEqual(combined.lanes.provider.map((l) => [l.state, l.headDigest, l.recordCount]), [["empty", null, 0]]);
  assert.equal(combined.lanes.buyer[0].state, "final");
  assert.equal(combined.recordCount, 1);
  assert.deepEqual(await env.sink.runSetHead("run-g3b"), combined);
});

test("gap 3: off by default — a linked run's head stays null and the run set carries no signedHead", async (t) => {
  const env = await boot(t);
  const { lanes } = await linkedRun(env, "run-g3c");
  const res = await (await postJson(env.closeUrl, "/v1/runs/run-g3c/close", receiptV2("run-g3c", lanes))).json();
  assert.equal(res.head.final, true);
  assert.equal("signedHead" in res.head, false);
  const read = await getJson(env.readUrl, "/v1/runs/run-g3c/head", env.tokens.mintQuery({ runId: "run-g3c" }).token);
  assert.equal(read.head, null);
  assert.equal("signedHead" in read.runSet, false);
  assert.equal(await env.sink.runSetHead("run-g3c"), null);
});

test("gap 3: TELEMETRY_RUN_SET_HEAD accepts only unset, 0 or 1; the ready line reports it", () => {
  const dir = () => mkdtempSync(path.join(tmpdir(), "cdt-gaps-env-"));
  const LOOPBACK = { TELEMETRY_BIND_HOST: "127.0.0.1", TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0" };
  assert.throws(
    () => {
      // If a build ever accepts the value, close what it bound so the run never hangs.
      const s = startFromEnv({ TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "staging", ...LOOPBACK, TELEMETRY_RUN_SET_HEAD: "yes" });
      s.write.close(); s.read.close(); s.close.close();
    },
    /TELEMETRY_RUN_SET_HEAD must be unset, "0" or "1"/,
  );
  for (const [value, expected] of [[undefined, false], ["1", true]]) {
    const lines = [];
    const origWrite = process.stdout.write;
    process.stdout.write = (chunk) => { lines.push(String(chunk)); return true; };
    let servers;
    try {
      servers = startFromEnv({
        TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "staging", TELEMETRY_BIND_HOST: "127.0.0.1",
        TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0",
        ...(value === undefined ? {} : { TELEMETRY_RUN_SET_HEAD: value }),
      });
    } finally {
      process.stdout.write = origWrite;
    }
    servers.write.close(); servers.read.close(); servers.close.close();
    const ready = JSON.parse(lines.find((l) => l.includes("telemetry-sink-ready")));
    assert.equal(ready.runSetHead, expected);
  }
});
