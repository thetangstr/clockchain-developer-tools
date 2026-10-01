import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  verifyAndExtract,
  verifyRecords,
  readServicesKeyFile,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };

// The contract server's signing key — pinned on the sink, not the harness.
const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const LOGS = (logRecords) => JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords }] }] });
const NONCE = (c) => "0x" + c.repeat(32);
const T0 = Date.parse("2030-01-01T00:00:00.000Z");

const geminiCall = (nonce, extra = {}) => ({
  timeUnixNano: "1",
  attributes: [
    { key: "event.name", value: { stringValue: "gemini_cli.tool_call" } },
    { key: "function_name", value: { stringValue: "mcp__contract__booking_execute" } },
    {
      key: "function_response",
      value: { stringValue: JSON.stringify({ serverNonce: nonce, ...extra }) },
    },
  ],
});

function terminalReceipt({ runId, state = "settled", ts = T0, key = contractKeys }) {
  const fields = {
    schema: "ac-terminal-receipt/v1",
    runId,
    terminalState: state,
    ts: new Date(ts).toISOString(),
    alg: "ed25519",
    keyId: "contract-server",
  };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), key.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

async function boot(t, { t0 = T0, ...sinkOpts } = {}) {
  let now = t0;
  const tokens = createTokenStore({ now: () => now });
  const sink = createTelemetrySink({
    signer: sinkSigner,
    tokens,
    now: () => now,
    contractKeys: contractPublicKeys,
    flushGraceMs: 0,
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
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body,
  });
const get = (url, path, token) =>
  fetch(url + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });

// ------------------------------------------------- 1: no chain, no rows

test("verifyAndExtract: rows only under a fully verified final head", async (t) => {
  const { tokens, sink } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-v1", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS([geminiCall(NONCE("a"))])), contentType: "application/json" });
  const receipt = terminalReceipt({ runId: "run-v1" });
  const close = await sink.closeRun({ runId: "run-v1", receipt });
  assert.equal(close.ok, true);

  const entries = sink.exportRecords("run-v1");
  const out = verifyAndExtract(entries, close.head, sink.annex("run-v1"), sinkPublicKeys, {
    roleRuntime: { buyer: "gemini-cli", provider: "gemini-cli" },
  });
  assert.equal(out.ok, true);
  assert.equal(out.spans.length, 1);
  assert.equal(out.spans[0].serverNonce, NONCE("a"));

  // A made-up record with a correct bodyDigest but a fake recordDigest → no rows.
  const fake = {
    record: { ...entries[0].record, recordDigest: "0x" + "f".repeat(64), prevHash: "0x" + "0".repeat(64) },
    body: entries[0].body,
  };
  const bad = verifyAndExtract([fake], close.head, sink.annex("run-v1"), sinkPublicKeys, {
    roleRuntime: { buyer: "gemini-cli", provider: "gemini-cli" },
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.spans, undefined);

  // A valid prefix under a non-final head → no rows either.
  const openHead = null;
  assert.equal(verifyAndExtract(entries, openHead, sink.annex("run-v1"), sinkPublicKeys, { roleRuntime: { buyer: "gemini-cli", provider: "gemini-cli" } }).ok, false);
});

// ------------------------------------------------- 2: close authority is the sink

test("close: a missing, wrong-run, or badly-signed terminal receipt is refused", async (t) => {
  const { tokens, sink, writeUrl, readUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-cx", role: "buyer" });
  await post(writeUrl, "/v1/logs", LOGS([]), ing.token);

  // No receipt at all.
  assert.equal((await post(closeUrl, "/v1/runs/run-cx/close", "{}")).status, 403);
  // Receipt for another run.
  const other = terminalReceipt({ runId: "run-other" });
  assert.equal((await post(closeUrl, "/v1/runs/run-cx/close", JSON.stringify(other))).status, 403);
  // Receipt signed by an unknown key.
  const stranger = generateKeyPairSync("ed25519");
  const forged = terminalReceipt({ runId: "run-cx", key: stranger });
  assert.equal((await post(closeUrl, "/v1/runs/run-cx/close", JSON.stringify(forged))).status, 403);
  // Tampered state.
  const tampered = { ...terminalReceipt({ runId: "run-cx" }), terminalState: "closed_early" };
  assert.equal((await post(closeUrl, "/v1/runs/run-cx/close", JSON.stringify(tampered))).status, 403);

  // Valid receipt closes.
  const res = await post(closeUrl, "/v1/runs/run-cx/close", JSON.stringify(terminalReceipt({ runId: "run-cx" })));
  assert.equal(res.status, 200);
  const { head } = await res.json();
  assert.equal(head.final, true);
  assert.equal(head.closeCause, "terminal_receipt");
  assert.match(head.receiptDigest, /^0x[0-9a-f]{64}$/);
  assert.equal(sink.annex("run-cx").refusedAfterClose, 0);
});

test("close: the run auto-closes at its maximum window", async (t) => {
  const t0 = Date.parse("2030-01-01T00:00:00.000Z");
  const { tokens, sink, writeUrl, readUrl, closeUrl, setNow } = await boot(t, { t0, runWindowMs: 60_000 });
  const ing = tokens.mintIngest({ runId: "run-w", role: "buyer" });
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), ing.token)).status, 200);

  setNow(t0 + 61_000); // past the window
  const res = await post(writeUrl, "/v1/logs", LOGS([]), ing.token);
  assert.equal(res.status, 409);

  const head = sink.head("run-w");
  assert.equal(head.final, true);
  assert.equal(head.closeCause, "window_expired");
  assert.equal(head.receiptDigest, null);
  assert.equal(sink.annex("run-w").refusedAfterClose, 1); // this very attempt counted
});

test("close: refused-after-close count lives in the signed annex, not the head", async (t) => {
  const { tokens, sink, writeUrl, readUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-rc", role: "buyer" });
  await post(writeUrl, "/v1/logs", LOGS([]), ing.token);
  await post(closeUrl, "/v1/runs/run-rc/close", JSON.stringify(terminalReceipt({ runId: "run-rc" })));

  // Two post-close ingest attempts bump the signed annex — the head stays put.
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), ing.token)).status, 409);
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), ing.token)).status, 409);
  const head = sink.head("run-rc");
  const annex = sink.annex("run-rc");
  assert.equal(annex.refusedAfterClose, 2);
  assert.equal(annex.finalHeadDigest, canonicalDigest(head));
  // …and it still verifies — the count is signed.
  const entries = sink.exportRecords("run-rc");
  const v = verifyAndExtract(entries, head, sink.annex("run-rc"), sinkPublicKeys, { roleRuntime: { buyer: "gemini-cli", provider: "gemini-cli" } });
  assert.equal(v.ok, true);
});

test("close: an anchor failure signs anchor:'failed' into the head — the verifier rejects it", async (t) => {
  // N4b-8: retries live inside the anchor client; when it throws the head
  // still signs — once — with the failure folded in, and the verifier
  // decides. No silent un-anchored head, no closeRun refusal loop.
  const anchor = { issue: async () => { throw new Error("tsa down"); } };
  const { tokens, sink } = await boot(t, { anchor });
  const ing = tokens.mintIngest({ runId: "run-ra", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS([])), contentType: "application/json" });

  const receipt = terminalReceipt({ runId: "run-ra" });
  const first = await sink.closeRun({ runId: "run-ra", receipt });
  assert.equal(first.ok, true);
  assert.equal(first.head.anchor.status, "failed");
  assert.match(first.head.anchor.error, /tsa down/);
  assert.equal(sink.isClosed("run-ra"), true);

  // Signed and final — the failure is part of the signed evidence.
  assert.equal(first.head.final, true);
  assert.equal(typeof first.head.signature.sig, "string");

  // The verifier decides: an anchor:failed head is rejected, never accepted.
  const v = verifyRecords(sink.exportRecords("run-ra"), first.head, sinkPublicKeys);
  assert.equal(v.ok, false);
  assert.equal(v.code, "ANCHOR_FAILED");

  // A retry returns the same signed head — the anchor is never re-run.
  const second = await sink.closeRun({ runId: "run-ra", receipt });
  assert.equal(second.ok, true);
  assert.deepEqual(second.head, first.head);
});

test("close: a post-close 409 fires only after the token kind is checked", async (t) => {
  const { tokens, writeUrl, readUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-no", role: "buyer" });
  await post(writeUrl, "/v1/logs", LOGS([]), ing.token);
  const qry = tokens.mintQuery({ runId: "run-no" }); // mintable once the run exists
  await post(closeUrl, "/v1/runs/run-no/close", JSON.stringify(terminalReceipt({ runId: "run-no" })));

  // A query token must not learn the run is closed via a 409 — it gets 403.
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), qry.token)).status, 403);
  // An unknown token gets 401, not 409.
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), "otlp-ing-" + "f".repeat(32))).status, 401);
  // The (now-revoked) ingest token gets the real 409.
  assert.equal((await post(writeUrl, "/v1/logs", LOGS([]), ing.token)).status, 409);
});

// ------------------------------------------------- LOWs

test("an isError:true tool result yields no nonce and is flagged error_result", async (t) => {
  const { tokens, sink } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-e", role: "buyer" });
  sink.ingest({
    token: ing.token,
    kind: "logs",
    body: Buffer.from(LOGS([geminiCall(NONCE("e"), { isError: true })])),
    contentType: "application/json",
  });
  const close = await sink.closeRun({ runId: "run-e", receipt: terminalReceipt({ runId: "run-e" }) });
  const out = verifyAndExtract(sink.exportRecords("run-e"), close.head, sink.annex("run-e"), sinkPublicKeys, {
    roleRuntime: { buyer: "gemini-cli", provider: "gemini-cli" },
  });
  assert.equal(out.ok, true);
  assert.equal(out.spans[0].serverNonce, undefined);
  assert.deepEqual(out.spans[0].flags, ["error_result"]);
});

test("the services key file must be owned by the services uid, not just 0600", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "ac-key-"));
  const keyPath = path.join(dir, "services.jwk");
  const jwk = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  writeFileSync(keyPath, JSON.stringify(jwk));
  chmodSync(keyPath, 0o600);
  // Owner check honours an injected expectation.
  assert.throws(() => readServicesKeyFile(keyPath, { ownerUid: 99999 }), /owner|uid/i);
  assert.deepEqual(readServicesKeyFile(keyPath), jwk);
});
