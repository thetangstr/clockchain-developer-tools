import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  verifyAndExtract,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };

const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const LOGS = (logRecords) => JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords }] }] });
const EMPTY = LOGS([]);
const NONCE = (c) => "0x" + c.repeat(32);

const geminiCall = (nonce) => ({
  timeUnixNano: "1",
  attributes: [
    { key: "event.name", value: { stringValue: "gemini_cli.tool_call" } },
    { key: "function_name", value: { stringValue: "mcp__contract__booking_execute" } },
    { key: "function_response", value: { stringValue: JSON.stringify({ serverNonce: nonce }) } },
  ],
});

const T0 = Date.parse("2030-01-01T00:00:00.000Z");

function terminalReceipt({ runId, ts = T0, state = "settled" }) {
  const fields = {
    schema: "ac-terminal-receipt/v1",
    runId,
    terminalState: state,
    ts: new Date(ts).toISOString(),
    alg: "ed25519",
    keyId: "contract-server",
  };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), contractKeys.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

async function boot(t, { t0 = T0, flushGraceMs = 0, clockSkewMs = 60_000, ...sinkOpts } = {}) {
  let now = t0;
  const tokens = createTokenStore({ now: () => now });
  const sink = createTelemetrySink({
    signer: sinkSigner,
    tokens,
    now: () => now,
    contractKeys: contractPublicKeys,
    flushGraceMs,
    clockSkewMs,
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

const post = (url, path, body, token) =>
  fetch(url + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body,
  });
const get = (url, path, token) =>
  fetch(url + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });

// ------------------------------------------------- 1: receipt freshness + no reuse

test("receipt freshness: a receipt older than the run or beyond the skew is refused", async (t) => {
  const { tokens, sink, writeUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-f", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(EMPTY), contentType: "application/json" });

  // 2020 receipt against a 2030 run.
  assert.equal(
    (await post(closeUrl, "/v1/runs/run-f/close", JSON.stringify(terminalReceipt({ runId: "run-f", ts: Date.parse("2020-01-01T00:00:00Z") })))).status,
    403,
  );
  // Receipt far in the future (beyond the 60s skew).
  assert.equal(
    (await post(closeUrl, "/v1/runs/run-f/close", JSON.stringify(terminalReceipt({ runId: "run-f", ts: T0 + 3600_000 })))).status,
    403,
  );
  // Receipt at the run's opening instant is fine.
  const res = await post(closeUrl, "/v1/runs/run-f/close", JSON.stringify(terminalReceipt({ runId: "run-f", ts: T0 })));
  assert.equal(res.status, 200);
});

test("no runId reuse: ingest authority is never re-minted; query tokens need an existing run", async (t) => {
  const { tokens, sink } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-u", role: "buyer" });
  // Before the first ingest the run does not exist — no query token yet.
  assert.throws(() => tokens.mintQuery({ runId: "run-u" }), /exist/i);
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(EMPTY), contentType: "application/json" });
  // The run exists now — no new ingest authority for the same id, but a
  // reader (the verifier) can still be minted.
  assert.throws(() => tokens.mintIngest({ runId: "run-u", role: "provider" }), /used|reuse/i);
  assert.ok(tokens.mintQuery({ runId: "run-u" }).token);
  // An untouched runId still mints ingest.
  assert.ok(tokens.mintIngest({ runId: "run-unused", role: "buyer" }).token);
});

// ------------------------------------------------- pending seal: closedAt = ts + grace

test("close: closedAt = receipt ts + flush grace; ingest lands until the seal", async (t) => {
  const { tokens, sink, writeUrl, closeUrl, setNow } = await boot(t, { flushGraceMs: 30_000 });
  const ing = tokens.mintIngest({ runId: "run-p", role: "buyer" });
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([geminiCall(NONCE("a"))]), ing.token)).status, 200);

  // Receipt ts = t0 → seals at t0 + 30s.
  const res = await post(closeUrl, "/v1/runs/run-p/close", JSON.stringify(terminalReceipt({ runId: "run-p", ts: T0 })));
  assert.equal(res.status, 200);
  const payload = await res.json();
  assert.equal(payload.pending, true);
  assert.equal(payload.closedAt, new Date(T0 + 30_000).toISOString());

  // Inside the grace window ingest is still accepted (flush).
  setNow(T0 + 10_000);
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([geminiCall(NONCE("b"))]), ing.token)).status, 200);

  // Past the seal point the run freezes — and the final head covers BOTH records.
  setNow(T0 + 31_000);
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 409);
  const head = sink.head("run-p");
  assert.equal(head.final, true);
  assert.equal(head.recordCount, 2);
  assert.equal(head.closedAt, new Date(T0 + 30_000).toISOString());
});

// ------------------------------------------------- 2: one final head + signed refusal annex

test("annex: post-close refusals go into a separately signed annex; the head never changes", async (t) => {
  const { tokens, sink, writeUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-an", role: "buyer" });
  await post(writeUrl, "/v1/logs", EMPTY, ing.token);
  const close = await post(closeUrl, "/v1/runs/run-an/close", JSON.stringify(terminalReceipt({ runId: "run-an", ts: T0 })));
  const { head } = await close.json();

  // Two refused writes → the head object is byte-identical, the annex moves.
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 409);
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 409);
  assert.deepEqual(sink.head("run-an"), head);

  const annex = sink.annex("run-an");
  assert.equal(annex.schema, "ac-telemetry.refusal-annex/v1");
  assert.equal(annex.runId, "run-an");
  assert.equal(annex.refusedAfterClose, 2);
  assert.equal(annex.finalHeadDigest, canonicalDigest(head));
  assert.equal(annex.signature.keyId, "ac-telemetry-test");
});

test("verifyAndExtract requires the latest annex and checks its binding to the head", async (t) => {
  const { tokens, sink, writeUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-va", role: "buyer" });
  await post(writeUrl, "/v1/logs", LOGS([geminiCall(NONCE("a"))]), ing.token);
  const { head } = await (await post(closeUrl, "/v1/runs/run-va/close", JSON.stringify(terminalReceipt({ runId: "run-va", ts: T0 })))).json();
  const entries = sink.exportRecords("run-va");
  const runtime = { buyer: "gemini-cli", provider: "gemini-cli" };

  // Happy path.
  const good = verifyAndExtract(entries, head, sink.annex("run-va"), sinkPublicKeys, { roleRuntime: runtime });
  assert.equal(good.ok, true);
  assert.equal(good.refusedAfterClose, 0);

  // Missing annex → refused.
  assert.equal(verifyAndExtract(entries, head, null, sinkPublicKeys, { roleRuntime: runtime }).ok, false);
  // Annex bound to a different head → refused.
  const alienAnnex = { ...sink.annex("run-va"), finalHeadDigest: "0x" + "0".repeat(64) };
  assert.equal(verifyAndExtract(entries, head, alienAnnex, sinkPublicKeys, { roleRuntime: runtime }).ok, false);

  // A post-close refusal re-signs the annex; an early (count-0) annex cannot
  // hide the later refusals — the verifier reads the sink's latest itself.
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 409);
  const latest = sink.annex("run-va");
  assert.equal(latest.refusedAfterClose, 1);
  const out = verifyAndExtract(entries, head, latest, sinkPublicKeys, { roleRuntime: runtime });
  assert.equal(out.ok, true);
  assert.equal(out.refusedAfterClose, 1);
});

// ------------------------------------------------- 3: auto-close at window end

test("auto-close stamps closedAt = the window end, not the access time", async (t) => {
  const { tokens, sink, writeUrl, closeUrl, setNow } = await boot(t, { runWindowMs: 60_000 });
  const ing = tokens.mintIngest({ runId: "run-w2", role: "buyer" });
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 200);

  setNow(T0 + 90_000); // window ended at t0+60s; we only notice at t0+90s
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 409);
  const head = sink.head("run-w2");
  assert.equal(head.closeCause, "window_expired");
  assert.equal(head.closedAt, new Date(T0 + 60_000).toISOString()); // window end
});

// ------------------------------------------------- 4: anchor covers the whole signed head

test("the anchor receives the digest of the unsigned final-head fields", async (t) => {
  let anchored = null;
  const { tokens, sink } = await boot(t, {
    anchor: { issue: async (d) => { anchored = d; return { anchorId: "tsa:x" }; } },
  });
  const ing = tokens.mintIngest({ runId: "run-ak", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(EMPTY), contentType: "application/json" });
  const { head } = await sink.closeRun({ runId: "run-ak", receipt: terminalReceipt({ runId: "run-ak", ts: T0 }) });
  const { signature, anchor, ...anchoredFields } = head;
  assert.equal(anchored, canonicalDigest(anchoredFields));
  assert.equal(anchor.status, "anchored");
  assert.equal(anchor.anchorId, "tsa:x");
});

// ------------------------------------------------- separate write/read ports

test("the sink serves writes and queries on separate listeners", async (t) => {
  const { tokens, writeUrl, readUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-sp", role: "buyer" });

  // Write port: ingest works; queries and close do not exist there.
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 200);
  const qry = tokens.mintQuery({ runId: "run-sp" }); // mintable once the run exists
  assert.equal((await get(writeUrl, "/v1/runs/run-sp/records", qry.token)).status, 404);
  assert.equal(
    (await post(writeUrl, "/v1/runs/run-sp/close", JSON.stringify(terminalReceipt({ runId: "run-sp", ts: T0 })))).status,
    404,
  );
  // Read port: queries work; ingest does not exist there.
  assert.equal((await get(readUrl, "/v1/runs/run-sp/records", qry.token)).status, 200);
  assert.equal((await post(readUrl, "/v1/logs", EMPTY, ing.token)).status, 404);
  // The head endpoint exposes the annex alongside the head.
  const { head, annex } = await (await get(readUrl, "/v1/runs/run-sp/head", qry.token)).json();
  assert.equal(head.runId, "run-sp");
  assert.equal(annex, null); // open run — no annex yet
});
