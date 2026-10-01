import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createMcpTsaAnchor,
  createTelemetrySink,
  createTokenStore,
  verifyRecords,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };
const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const LOGS = JSON.stringify({ resourceLogs: [{ scopeLogs: [] }] });

function receiptFor(runId, terminalState = "settled", ts = T0) {
  const fields = {
    schema: "ac-terminal-receipt/v1",
    runId,
    terminalState,
    ts: new Date(ts).toISOString(),
    alg: "ed25519",
    keyId: "contract-server",
  };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), contractKeys.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

const OK_RECEIPT = {
  commitmentId: "c-deadbeef",
  eventHash: "0x" + "ab".repeat(32),
  anchor: { ledgerId: "clock-testnet", blockHeight: "777", time: "01-01-2030", status: "anchored" },
  status: "anchored",
};

/**
 * A fake /mcp endpoint. `respond(rpc, callIndex)` returns:
 *   {status, json}        — plain JSON-RPC response at any status
 *   {status, sse: result} — 200 text/event-stream carrying the result
 * default: a tsa_issue-shaped receipt.
 */
async function fakeMcp(t, respond) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const rpc = JSON.parse(body);
      seen.push({ authorization: req.headers.authorization, accept: req.headers.accept, rpc });
      const out = respond === undefined
        ? { status: 200, json: { jsonrpc: "2.0", id: rpc.id, result: { structuredContent: OK_RECEIPT } } }
        : respond(rpc, seen.length);
      if (out.sse !== undefined) {
        res.writeHead(out.status ?? 200, { "content-type": "text/event-stream" });
        res.end(`data: ${JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: out.sse })}\n\n`);
        return;
      }
      res.writeHead(out.status ?? 200, { "content-type": "application/json" });
      res.end(JSON.stringify(out.json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, seen };
}

function makeSink(opts = {}) {
  const tokens = createTokenStore({ now: () => T0 });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: () => T0,
    contractKeys: contractPublicKeys, flushGraceMs: 0,
    ...opts,
  });
  return { tokens, sink };
}

test("mcp anchor client calls tsa_issue on /mcp with the sink bearer token", async (t) => {
  const { url, seen } = await fakeMcp(t);
  const anchor = createMcpTsaAnchor({ url, token: "sink-clock-key", agentId: "telemetry-sink" });
  const digest = "0x" + "cd".repeat(32);
  const write = await anchor.issue(digest);

  assert.equal(seen.length, 1);
  assert.equal(seen[0].authorization, "Bearer sink-clock-key");
  assert.match(seen[0].accept, /text\/event-stream/);
  const rpc = seen[0].rpc;
  assert.equal(rpc.method, "tools/call");
  assert.equal(rpc.params.name, "tsa_issue");
  assert.equal(rpc.params.arguments.agent_id, "telemetry-sink");
  assert.match(rpc.params.arguments.commitment, /0xcdcd/);
  assert.equal(typeof rpc.params.arguments.deadline, "string");
  // Idempotent by construction: the key is bound to the anchored digest.
  assert.equal(rpc.params.arguments.idempotency_key, `anchor-${digest.slice(2, 34)}`);

  assert.equal(write.anchorId, "tsa:c-deadbeef");
  assert.equal(write.eventHash, "0x" + "ab".repeat(32));
  assert.equal(write.ledger.ledgerId, "clock-testnet");
});

test("mcp anchor client parses an SSE-framed response", async (t) => {
  const { url } = await fakeMcp(t, () => ({
    sse: { structuredContent: { commitmentId: "c-sse", anchor: { ledgerId: "l", blockHeight: null, time: null, status: "pending" } } },
  }));
  const anchor = createMcpTsaAnchor({ url, token: "t", backoffMs: [] });
  const write = await anchor.issue("0x" + "11".repeat(32));
  assert.equal(write.anchorId, "tsa:c-sse");
  assert.equal(write.ledger.status, "pending");
});

test("mcp anchor retries 5xx within its backoff budget, then lands", async (t) => {
  let n = 0;
  const { url, seen } = await fakeMcp(t, (rpc) => {
    n += 1;
    return n === 1
      ? { status: 503, json: { error: "down" } }
      : { status: 200, json: { jsonrpc: "2.0", id: rpc.id, result: { structuredContent: { commitmentId: "c-r" } } } };
  });
  const anchor = createMcpTsaAnchor({ url, token: "t", backoffMs: [1] });
  const write = await anchor.issue("0x" + "22".repeat(32));
  assert.equal(write.anchorId, "tsa:c-r");
  assert.equal(seen.length, 2);
});

test("mcp anchor throws after the retry budget is exhausted", async (t) => {
  const { url, seen } = await fakeMcp(t, (rpc) => ({ status: 503, json: { jsonrpc: "2.0", id: rpc.id, error: "down" } }));
  const anchor = createMcpTsaAnchor({ url, token: "t", backoffMs: [1, 1] });
  await assert.rejects(() => anchor.issue("0x" + "33".repeat(32)), /HTTP 503/);
  assert.equal(seen.length, 3); // initial + 2 retries
});

test("mcp anchor does NOT retry a deterministic refusal (4xx / isError)", async (t) => {
  const { url, seen } = await fakeMcp(t, (rpc) => ({
    status: 200,
    json: { jsonrpc: "2.0", id: rpc.id, result: { isError: true, content: [{ type: "text", text: "insufficient credits" }] } },
  }));
  const anchor = createMcpTsaAnchor({ url, token: "t", backoffMs: [1, 1, 1] });
  await assert.rejects(() => anchor.issue("0x" + "44".repeat(32)), /insufficient credits/);
  assert.equal(seen.length, 1);
});

test("end to end: the anchor id lands INSIDE the signed final head", async (t) => {
  const { url, seen } = await fakeMcp(t);
  const anchor = createMcpTsaAnchor({ url, token: "sink-clock-key" });
  const { tokens, sink } = makeSink({ anchor });
  const ing = tokens.mintIngest({ runId: "run-ah", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS), contentType: "application/json" });

  const out = await sink.closeRun({ runId: "run-ah", receipt: receiptFor("run-ah") });
  assert.equal(out.ok, true);
  assert.equal(seen.length, 1);
  // The anchored subject is the canonical digest of the unsigned head fields.
  const { signature, anchor: headAnchor, ...fields } = out.head;
  assert.equal(canonicalDigest(fields), /ac-telemetry-head (0x[0-9a-f]{64})/.exec(seen[0].rpc.params.arguments.commitment)[1]);
  // …and the write rides inside the signed head — verifyable by anyone.
  assert.deepEqual(headAnchor, {
    status: "anchored",
    anchorId: "tsa:c-deadbeef",
    eventHash: "0x" + "ab".repeat(32),
    ledger: { ledgerId: "clock-testnet", blockHeight: "777", time: "01-01-2030", status: "anchored" },
  });
  const v = verifyRecords(sink.exportRecords("run-ah"), out.head, sinkPublicKeys);
  assert.equal(v.ok, true);
});

test("end to end: a failing anchor still signs the head — marked anchor:failed", async (t) => {
  const { url } = await fakeMcp(t, (rpc) => ({ status: 503, json: { jsonrpc: "2.0", id: rpc.id, error: "down" } }));
  const anchor = createMcpTsaAnchor({ url, token: "t", backoffMs: [1] });
  const { tokens, sink } = makeSink({ anchor });
  const ing = tokens.mintIngest({ runId: "run-af", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS), contentType: "application/json" });

  const out = await sink.closeRun({ runId: "run-af", receipt: receiptFor("run-af") });
  assert.equal(out.ok, true);
  assert.equal(out.head.anchor.status, "failed");
  assert.match(out.head.anchor.error, /HTTP 503/);
  assert.equal(typeof out.head.signature.sig, "string");
  const v = verifyRecords(sink.exportRecords("run-af"), out.head, sinkPublicKeys);
  assert.equal(v.ok, false);
  assert.equal(v.code, "ANCHOR_FAILED");
});

test("the contract server's 'cancelled' terminal state is an accepted close cause", async (t) => {
  const { tokens, sink } = makeSink();
  const ing = tokens.mintIngest({ runId: "run-cancel", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS), contentType: "application/json" });
  const out = await sink.closeRun({ runId: "run-cancel", receipt: receiptFor("run-cancel", "cancelled") });
  assert.equal(out.ok, true);
  assert.equal(out.head.final, true);
  assert.equal(out.head.closeCause, "terminal_receipt");
});
