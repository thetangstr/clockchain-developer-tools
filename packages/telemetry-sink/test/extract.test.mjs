import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  canonicalJson,
  createTelemetrySink,
  createTokenStore,
  verifyAndExtract,
} from "../dist/index.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const load = (name) => readFileSync(path.join(FIXTURES, name), "utf8");

const sinkKeys = generateKeyPairSync("ed25519");
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };
const contractKeys = generateKeyPairSync("ed25519");

const RUNTIMES = { buyer: "claude-code", provider: "claude-code" };
const CODEX = { buyer: "codex", provider: "codex" };
const GEMINI = { buyer: "gemini-cli", provider: "gemini-cli" };

function receiptFor(runId, ts = "2030-01-01T00:00:00.000Z") {
  const fields = {
    schema: "ac-terminal-receipt/v1",
    runId,
    terminalState: "settled",
    ts,
    alg: "ed25519",
    keyId: "contract-server",
  };
  const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), contractKeys.privateKey);
  return { ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

async function sinkWithFixture(runId, role, fixtureName) {
  const tokens = createTokenStore({ now: () => Date.parse("2030-01-01T00:00:00.000Z") });
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey },
    tokens,
    now: () => Date.parse("2030-01-01T00:00:00.000Z"),
    contractKeys: { "contract-server": contractKeys.publicKey },
    flushGraceMs: 0,
  });
  const ing = tokens.mintIngest({ runId, role });
  const kind = fixtureName.includes("claude") ? "traces" : "logs";
  const out = sink.ingest({ token: ing.token, kind, body: Buffer.from(load(fixtureName)), contentType: "application/json" });
  assert.equal(out.ok, true, JSON.stringify(out));
  return sink;
}

async function extractVerified(sink, runId, roleRuntime) {
  const { head } = await sink.closeRun({ runId, receipt: receiptFor(runId) });
  const out = verifyAndExtract(sink.exportRecords(runId), head, sink.annex(runId), sinkPublicKeys, { roleRuntime });
  assert.equal(out.ok, true);
  return out;
}

test("claude fixture: claude_code.mcp.rpc spans extract with serverNonce from tool.output", async () => {
  const sink = await sinkWithFixture("run-x1", "provider", "otlp-claude-SYNTHETIC.json");
  const { spans, refused } = await extractVerified(sink, "run-x1", RUNTIMES);
  assert.deepEqual(refused, []);
  assert.equal(spans.length, 2);
  const [first, second] = spans;
  assert.equal(first.role, "provider"); // stamped from the record, never the caller
  assert.equal(first.runtime, "claude-code");
  assert.equal(first.tool, "catalog_quote");
  assert.equal(first.serverNonce, "0xaaaabbbbccccdddd1111222233334444");
  assert.equal(first.ts, 1798761600000);
  assert.equal(first.receivedAt, "2030-01-01T00:00:00.000Z");
  assert.equal(first.sinkRef, sink.recordsFor("run-x1")[0].recordDigest);
  // Second span has no tool.output event → no nonce, still extracted.
  assert.equal(second.tool, "rendezvous_inbox");
  assert.equal(second.serverNonce, undefined);
});

test("codex fixture: codex.tool_result log events extract tool + nonce", async () => {
  const sink = await sinkWithFixture("run-x2", "buyer", "otlp-codex-SYNTHETIC.json");
  const { spans } = await extractVerified(sink, "run-x2", CODEX);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].runtime, "codex");
  assert.equal(spans[0].tool, "booking_lookup");
  assert.equal(spans[0].serverNonce, "0xbbbbccccddddeeee2222333344445555");
  assert.equal(spans[0].ts, 1798761600200);
  assert.equal(spans[0].sinkRef, sink.recordsFor("run-x2")[0].recordDigest);
  assert.equal(spans[1].tool, "contract_status");
  assert.equal(spans[1].serverNonce, undefined);
});

test("gemini fixture: gemini_cli.tool_call extracts function + nonce", async () => {
  const sink = await sinkWithFixture("run-x3", "buyer", "otlp-gemini-SYNTHETIC.json");
  const { spans } = await extractVerified(sink, "run-x3", GEMINI);
  assert.equal(spans.length, 1);
  assert.equal(spans[0].runtime, "gemini-cli");
  assert.equal(spans[0].tool, "settlement_status");
  assert.equal(spans[0].serverNonce, "0xccccddddeeeeffff3333444455556666");
  assert.equal(spans[0].sinkRef, sink.recordsFor("run-x3")[0].recordDigest);
});

test("claude 2.1.202/GLM shape: claude_code.tool spans with empty events yield nonceless rows", async () => {
  // N4e-2 mini capture: under the Z.AI/GLM backend the tool span carries
  // tool_name + a call_* tool_use_id but NO tool.output event — the span
  // row still extracts, just with no serverNonce.
  const sink = await sinkWithFixture("run-x5", "provider", "otlp-claude-glm-SYNTHETIC.json");
  const { spans, refused } = await extractVerified(sink, "run-x5", RUNTIMES);
  assert.deepEqual(refused, []);
  assert.equal(spans.length, 2); // llm_request span ignored
  assert.equal(spans[0].tool, "echo");
  assert.equal(spans[0].runtime, "claude-code");
  assert.equal(spans[0].serverNonce, undefined);
  assert.equal(spans[1].tool, "echo");
  assert.equal(spans[1].serverNonce, undefined);
});

test("codex api_request/startup log records are not tool results — no rows, no refusals", async () => {
  // N4e-2 mini capture (codex 0.148, dead-auth run): api_request and
  // lifecycle records carry no tool result and must not produce rows.
  const sink = await sinkWithFixture("run-x6", "buyer", "otlp-codex-apireq-SYNTHETIC.json");
  const { spans, refused } = await extractVerified(sink, "run-x6", CODEX);
  assert.deepEqual(refused, []);
  assert.equal(spans.length, 0);
});

test("extractor yields argsDigest when args are present and ignores unrelated events", async () => {
  const sink = await sinkWithFixture("run-x4", "buyer", "otlp-codex-SYNTHETIC.json");
  const { spans } = await extractVerified(sink, "run-x4", CODEX);
  assert.match(spans[0].argsDigest ?? "", /^0x[0-9a-f]{64}$/);
});
