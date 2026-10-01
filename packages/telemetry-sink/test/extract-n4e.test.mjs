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

const CLAUDE = { buyer: "claude-code", provider: "claude-code" };
const CODEX = { buyer: "codex", provider: "codex" };

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

async function sinkWith(runId, role, fixtureName, body) {
  const tokens = createTokenStore({ now: () => Date.parse("2030-01-01T00:00:00.000Z") });
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey },
    tokens,
    now: () => Date.parse("2030-01-01T00:00:00.000Z"),
    contractKeys: { "contract-server": contractKeys.publicKey },
    flushGraceMs: 0,
  });
  const bytes = body ?? load(fixtureName);
  const ing = tokens.mintIngest({ runId, role });
  const out = sink.ingest({
    token: ing.token,
    kind: bytes.includes("resourceSpans") ? "traces" : "logs",
    body: Buffer.from(bytes),
    contentType: "application/json",
  });
  assert.equal(out.ok, true, JSON.stringify(out));
  return sink;
}

async function extractVerified(sink, runId, roleRuntime) {
  const { head } = await sink.closeRun({ runId, receipt: receiptFor(runId) });
  return verifyAndExtract(sink.exportRecords(runId), head, sink.annex(runId), sinkPublicKeys, { roleRuntime });
}

/** Minimal OTLP logs doc with one codex.tool_result record. */
function codexDoc(output, extra = []) {
  return JSON.stringify({
    resourceLogs: [{
      resource: { attributes: [{ key: "service.name", value: { stringValue: "codex_cli" } }] },
      scopeLogs: [{
        scope: { name: "codex_core::otel" },
        logRecords: [{
          timeUnixNano: "1798761600200000000",
          severityNumber: 9,
          body: { stringValue: "codex.tool_result" },
          attributes: [
            { key: "event.name", value: { stringValue: "codex.tool_result" } },
            { key: "tool_name", value: { stringValue: "echo" } },
            { key: "output", value: { stringValue: output } },
            ...extra,
          ],
        }],
      }],
    }],
  });
}

/** Minimal OTLP traces doc with one claude_code.tool span. */
function claudeToolDoc(events) {
  return JSON.stringify({
    resourceSpans: [{
      resource: { attributes: [{ key: "service.name", value: { stringValue: "claude-code" } }] },
      scopeSpans: [{
        scope: { name: "claude-code" },
        spans: [{
          name: "claude_code.tool",
          startTimeUnixNano: "1798761600200000000",
          endTimeUnixNano: "1798761600300000000",
          attributes: [
            { key: "tool_name", value: { stringValue: "mcp__pairingstub__echo" } },
          ],
          events,
        }],
      }],
    }],
  });
}

const NONCE1 = "0xaaaa1111bbbb2222cccc3333dddd4444";
const NONCE2 = "0x555566667777888899990000eeeeffff";

// ---------- codex preamble unwrap ----------

test("codex N4e excerpt: wrapped tool_result outputs yield the real nonces", async () => {
  const sink = await sinkWith("run-e1", "buyer", "otlp-codex-N4E-EXCERPT.json");
  const { ok, spans, refused } = await extractVerified(sink, "run-e1", CODEX);
  assert.equal(ok, true);
  assert.equal(refused.length, 0);
  // Two direct echo calls + one functions.exec record (its output is a
  // JSONL pair of CallToolResults — ambiguous, no nonce).
  assert.equal(spans.length, 3);
  assert.equal(spans[0].tool, "echo");
  assert.equal(spans[0].serverNonce, "0xb229000214d72cb222b9ec44da163db0");
  assert.equal(spans[1].serverNonce, "0x9773be66bdfa14746da551d48d0d359d");
  const exec = spans[2];
  assert.equal(exec.tool, "exec");
  assert.equal(exec.serverNonce, undefined);
  assert.ok(exec.flags?.includes("nonce_ambiguous"));
});

test("codex: a preamble wrapping two JSON bodies is ambiguous, never nonce-matched", async () => {
  const two = `{"echoed":"a","serverNonce":"${NONCE1}"}\n{"echoed":"b","serverNonce":"${NONCE2}"}`;
  const output = `Wall time: 0.01 seconds\nOutput:\n${two}`;
  const sink = await sinkWith("run-e2", "buyer", "x", codexDoc(output));
  const { spans } = await extractVerified(sink, "run-e2", CODEX);
  assert.equal(spans.length, 1);
  assert.equal(spans[0].serverNonce, undefined);
  assert.ok(spans[0].flags?.includes("nonce_ambiguous"));
});

test("codex: a non-matching wrapper is flagged codex_output_unrecognized, no nonce", async () => {
  const output = `SomeOtherWrapper 1.2s\nResult:\n{"echoed":"a","serverNonce":"${NONCE1}"}`;
  const sink = await sinkWith("run-e3", "buyer", "x", codexDoc(output));
  const { spans } = await extractVerified(sink, "run-e3", CODEX);
  assert.equal(spans.length, 1);
  assert.equal(spans[0].serverNonce, undefined);
  assert.ok(spans[0].flags?.includes("codex_output_unrecognized"));
});

test("codex: clean JSON output still extracts without the preamble", async () => {
  const sink = await sinkWith("run-e4", "buyer", "x",
    codexDoc(`{"echoed":"a","serverNonce":"${NONCE1}"}`));
  const { spans } = await extractVerified(sink, "run-e4", CODEX);
  assert.equal(spans[0].serverNonce, NONCE1);
  assert.equal(spans[0].flags, undefined);
});

// ---------- claude_code.tool (2.1.284) ----------

test("claude N4e excerpt: claude_code.tool spans yield nonces from tool.output events", async () => {
  const sink = await sinkWith("run-e5", "provider", "otlp-claude-N4E-EXCERPT.json");
  const { ok, spans, refused } = await extractVerified(sink, "run-e5", CLAUDE);
  assert.equal(ok, true);
  assert.equal(refused.length, 0);
  assert.equal(spans.length, 3);
  // Builtin ToolSearch span: no tool.output event → no nonce, no flag.
  assert.equal(spans[0].tool, "ToolSearch");
  assert.equal(spans[0].serverNonce, undefined);
  // MCP echo spans: mcp__pairingstub__ stripped, nonce from the event output.
  assert.equal(spans[1].tool, "echo");
  assert.equal(spans[1].serverNonce, "0xdede34efb163409308fae015ce07eab2");
  assert.equal(spans[2].tool, "echo");
  assert.equal(spans[2].serverNonce, "0x572c0cdf43b2cf25534de6e9cec9982d");
});

test("claude_code.tool: an event without output carries no nonce", async () => {
  const sink = await sinkWith("run-e6", "provider", "x", claudeToolDoc([
    { name: "tool.output", timeUnixNano: "1798761600250000000", attributes: [] },
  ]));
  const { spans } = await extractVerified(sink, "run-e6", CLAUDE);
  assert.equal(spans.length, 1);
  assert.equal(spans[0].tool, "echo");
  assert.equal(spans[0].serverNonce, undefined);
  assert.equal(spans[0].flags, undefined);
});
