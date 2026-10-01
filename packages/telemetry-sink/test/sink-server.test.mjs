import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  verifyRecords,
  HEAD_SCHEMA,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };

const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const T0 = Date.parse("2030-01-01T00:00:00.000Z");

function receiptFor(runId, ts = T0) {
  const fields = {
    schema: "ac-terminal-receipt/v1",
    runId,
    terminalState: "settled",
    ts: new Date(ts).toISOString(),
    alg: "ed25519",
    keyId: "contract-server",
  };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), contractKeys.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

const OTLP_TRACES = JSON.stringify({
  resourceSpans: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: "claude-code" } }] }, scopeSpans: [] }],
});
const OTLP_LOGS = JSON.stringify({ resourceLogs: [{ scopeLogs: [] }] });

async function boot(t, t0 = T0, sinkOpts = {}) {
  let now = t0;
  const tokens = createTokenStore({ now: () => now });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: () => now,
    contractKeys: contractPublicKeys, flushGraceMs: 0,
    ...sinkOpts,
  });
  const { write, read, close } = createTelemetrySinkServer({ sink, tokens });
  await new Promise((resolve) => write.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => read.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => close.listen(0, "127.0.0.1", resolve));
  t.after(() => { write.close(); read.close(); close.close(); });
  return {
    sink, tokens,
    writeUrl: `http://127.0.0.1:${write.address().port}`,
    readUrl: `http://127.0.0.1:${read.address().port}`,
    closeUrl: `http://127.0.0.1:${close.address().port}`,
    setNow: (ms) => { now = ms; },
  };
}

const post = (url, path, body, token, contentType = "application/json") =>
  fetch(url + path, {
    method: "POST",
    headers: {
      "content-type": contentType,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body,
  });

const get = (url, path, token) =>
  fetch(url + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });

test("ingest accepts OTLP/JSON and appends hash-chained records", async (t) => {
  const { tokens, writeUrl, readUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-t1", role: "buyer" });

  const r1 = await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token);
  assert.equal(r1.status, 200);
  const r2 = await post(writeUrl, "/v1/logs", OTLP_LOGS, ing.token);
  assert.equal(r2.status, 200);
  const qry = tokens.mintQuery({ runId: "run-t1" }); // mintable once the run exists

  const res = await get(readUrl, "/v1/runs/run-t1/records", qry.token);
  assert.equal(res.status, 200);
  const payload = await res.json();
  assert.equal(payload.records.length, 2);
  const [a, b] = payload.records;
  assert.equal(a.seq, 0);
  assert.equal(a.kind, "traces");
  assert.equal(a.role, "buyer");
  assert.equal(a.tokenId, ing.record.tokenId);
  assert.equal(a.bodyDigest.startsWith("0x"), true);
  assert.equal(b.prevHash, a.recordDigest);
  assert.equal(b.kind, "logs");
  assert.equal(payload.head.runId, "run-t1");
  assert.equal(payload.head.headDigest, b.recordDigest);
  assert.equal(payload.head.final, false);
  // The advisory check result is informative only — never evidentiary.
  assert.equal(payload.advisory.evidentiary, false);
  assert.equal(payload.advisory.result.ok, "incomplete");
});

test("ingest and query tokens are strictly separated", async (t) => {
  const { tokens, writeUrl, readUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-a1", role: "provider" });

  // Ingest token can write but can never read.
  assert.equal((await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token)).status, 200);
  const qry = tokens.mintQuery({ runId: "run-a1" }); // mintable once the run exists
  assert.equal((await get(readUrl, "/v1/runs/run-a1/records", ing.token)).status, 403);
  assert.equal((await get(readUrl, "/v1/runs/run-a1/head", ing.token)).status, 403);

  // Query token can read but can never write.
  assert.equal((await get(readUrl, "/v1/runs/run-a1/records", qry.token)).status, 200);
  assert.equal((await post(writeUrl, "/v1/traces", OTLP_TRACES, qry.token)).status, 403);

  // Unknown / missing / revoked tokens: 401, nothing written.
  assert.equal((await post(writeUrl, "/v1/traces", OTLP_TRACES, "otlp-ing-" + "f".repeat(32))).status, 401);
  assert.equal((await post(writeUrl, "/v1/traces", OTLP_TRACES)).status, 401);
  assert.equal((await get(readUrl, "/v1/runs/run-a1/records", "otlp-qry-" + "f".repeat(32))).status, 401);
  tokens.revoke(ing.record.tokenId);
  assert.equal((await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token)).status, 401);

  const res = await get(readUrl, "/v1/runs/run-a1/records", qry.token);
  assert.equal((await res.json()).records.length, 1); // only the first write landed
});

test("records are per-run: another run's token writes only to its own chain", async (t) => {
  const { tokens, writeUrl, readUrl } = await boot(t);
  const ingA = tokens.mintIngest({ runId: "run-ra", role: "buyer" });
  const ingB = tokens.mintIngest({ runId: "run-rb", role: "provider" });

  await post(writeUrl, "/v1/traces", OTLP_TRACES, ingA.token);
  await post(writeUrl, "/v1/traces", OTLP_TRACES, ingB.token);
  const qryA = tokens.mintQuery({ runId: "run-ra" });
  const qryB = tokens.mintQuery({ runId: "run-rb" });

  const a = await (await get(readUrl, "/v1/runs/run-ra/records", qryA.token)).json();
  const b = await (await get(readUrl, "/v1/runs/run-rb/records", qryB.token)).json();
  assert.equal(a.records.length, 1);
  assert.equal(b.records.length, 1);
  assert.equal(a.records[0].role, "buyer");
  assert.equal(b.records[0].role, "provider");
  // Disjoint chains: same seq, different digests (tokenId binds role+run).
  assert.equal(a.records[0].seq, 0);
  assert.equal(b.records[0].seq, 0);
  assert.notEqual(a.records[0].recordDigest, b.records[0].recordDigest);

  // A query token scoped to run A cannot read run B.
  assert.equal((await get(readUrl, "/v1/runs/run-rb/records", qryA.token)).status, 403);
});

test("verifyRecords catches a tampered byte, a deleted record, and a reorder", async (t) => {
  const { tokens, sink, writeUrl, readUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-v1", role: "buyer" });
  await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token);
  await post(writeUrl, "/v1/logs", OTLP_LOGS, ing.token);
  await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token);
  const qry = tokens.mintQuery({ runId: "run-v1" }); // mintable once the run exists

  const { records, head } = await (await get(readUrl, "/v1/runs/run-v1/records", qry.token)).json();
  // Query payload carries `{...record, body}` rows; open head → incomplete.
  assert.equal(verifyRecords(records, head, sinkPublicKeys).ok, "incomplete");

  // Single-byte tamper in a stored body digest.
  const tampered = records.map((r) => ({ ...r }));
  tampered[1].bodyDigest = "0x" + "0".repeat(64);
  assert.equal(verifyRecords(tampered, head, sinkPublicKeys).ok, false);

  // A swapped body (metadata kept) fails the recomputed body digest.
  const swapped = records.map((r) => ({ ...r }));
  swapped[1].body = records[0].body;
  assert.equal(verifyRecords(swapped, head, sinkPublicKeys).ok, false);

  // Deleted middle record breaks the link.
  const deleted = [records[0], records[2]];
  assert.equal(verifyRecords(deleted, head, sinkPublicKeys).ok, false);

  // Reordered tail breaks the link.
  const reordered = [records[0], records[2], records[1]];
  assert.equal(verifyRecords(reordered, head, sinkPublicKeys).ok, false);

  // Tampered receivedAt breaks the record digest.
  const restamped = records.map((r) => ({ ...r }));
  restamped[0].receivedAt = "2031-01-01T00:00:00.000Z";
  assert.equal(verifyRecords(restamped, head, sinkPublicKeys).ok, false);

});

test("the signed head fails under the wrong key or a forged headDigest", async (t) => {
  const { tokens, sink, writeUrl, readUrl } = await boot(t);
  const wrongKeys = generateKeyPairSync("ed25519");
  const ing = tokens.mintIngest({ runId: "run-h1", role: "buyer" });
  await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token);
  const qry = tokens.mintQuery({ runId: "run-h1" }); // mintable once the run exists

  const res = await get(readUrl, "/v1/runs/run-h1/head", qry.token);
  const { head } = await res.json();
  assert.equal(head.schema, HEAD_SCHEMA);
  assert.equal(head.signature.keyId, "ac-telemetry-test");

  const entries = sink.exportRecords("run-h1");
  // Head forged under a different sig fails.
  const forged = { ...head, signature: { ...head.signature, sig: "0x" + "0".repeat(128) } };
  assert.equal(verifyRecords(entries, forged, sinkPublicKeys).ok, false);
  // Verified against an unrelated keyring fails too.
  assert.equal(
    verifyRecords(entries, head, { "ac-telemetry-test": wrongKeys.publicKey }).ok,
    false,
  );
  assert.equal(
    verifyRecords(entries, head, { stranger: wrongKeys.publicKey }).ok,
    false,
  );
});

test("protobuf content-type is refused (415) — exporters must use http/json", async (t) => {
  const { tokens, writeUrl, readUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-pb", role: "buyer" });
  const res = await post(writeUrl, "/v1/traces", Buffer.from([0x0a, 0x00]), ing.token, "application/x-protobuf");
  assert.equal(res.status, 415);
});

test("no response or record ever carries the plaintext token", async (t) => {
  const { tokens, writeUrl, readUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-s1", role: "buyer" });
  const postRes = await post(writeUrl, "/v1/traces", OTLP_TRACES, ing.token);
  const body = await postRes.text();
  const qry = tokens.mintQuery({ runId: "run-s1" }); // mintable once the run exists
  assert.ok(!body.includes(ing.token));

  const recordsBody = await (await get(readUrl, "/v1/runs/run-s1/records", qry.token)).text();
  assert.ok(!recordsBody.includes(ing.token));
  assert.ok(!recordsBody.includes(qry.token));
});

test("tsa anchor seam: injected fake receives the unsigned-head digest; the id rides the signed head", async (t) => {
  let anchored = null;
  let now = Date.parse("2030-01-01T00:00:00.000Z");
  const tokens = createTokenStore({ now: () => now });
  const sink = createTelemetrySink({
    signer: sinkSigner,
    tokens,
    now: () => now,
    anchor: { issue: async (digest) => { anchored = digest; return { anchorId: "tsa:test" }; } },
    contractKeys: contractPublicKeys,
    flushGraceMs: 0,
  });
  const ing = tokens.mintIngest({ runId: "run-a", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "traces", body: Buffer.from(OTLP_TRACES), contentType: "application/json" });
  const out = await sink.closeRun({ runId: "run-a", receipt: receiptFor("run-a") });
  assert.equal(out.ok, true);
  // The anchor covers the unsigned head fields (signature + anchor land
  // AFTER the anchor resolves); the anchor id is inside the signed head.
  const { signature, anchor, ...anchoredFields } = out.head;
  assert.equal(anchored, canonicalDigest(anchoredFields));
  assert.equal(anchor.anchorId, "tsa:test");
  assert.equal(out.head.final, true);
});
