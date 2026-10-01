import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  canonicalDigest,
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

// Hermes is pinned per role — as claude-code/codex/gemini-cli are.
const HERMES = { buyer: "hermes", provider: "hermes" };

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

async function sinkWithHermesFixture(runId, role = "provider") {
  const tokens = createTokenStore({ now: () => Date.parse("2030-01-01T00:00:00.000Z") });
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey },
    tokens,
    now: () => Date.parse("2030-01-01T00:00:00.000Z"),
    contractKeys: { "contract-server": contractKeys.publicKey },
    flushGraceMs: 0,
  });
  const ing = tokens.mintIngest({ runId, role });
  const out = sink.ingest({
    token: ing.token, kind: "logs",
    body: Buffer.from(load("otlp-hermes-SYNTHETIC.json")), contentType: "application/json",
  });
  assert.equal(out.ok, true, JSON.stringify(out));
  return sink;
}

async function extractVerified(sink, runId, roleRuntime) {
  const { head } = await sink.closeRun({ runId, receipt: receiptFor(runId) });
  return verifyAndExtract(sink.exportRecords(runId), head, sink.annex(runId), sinkPublicKeys, { roleRuntime });
}

test("hermes fixture: hermes.tool_call extracts tool, structural nonce, recomputed argsDigest", async () => {
  const sink = await sinkWithHermesFixture("run-h1", "provider");
  const { ok, spans, refused } = await extractVerified(sink, "run-h1", HERMES);
  assert.equal(ok, true);
  // Three tool calls extracted; the unrelated hermes.session log is ignored.
  assert.equal(spans.length, 3);
  const first = spans[0];
  assert.equal(first.role, "provider");
  assert.equal(first.runtime, "hermes");
  assert.equal(first.tool, "submit_offer"); // mcp__contract__ prefix stripped
  // The nonce is found structurally inside the double-encoded content[].text.
  assert.equal(first.serverNonce, "0xddddccccbbbbaaaa4444555566667777");
  assert.equal(first.ts, 1798761600300);
  assert.equal(first.receivedAt, "2030-01-01T00:00:00.000Z");
  assert.equal(first.sinkRef, sink.recordsFor("run-h1")[0].recordDigest);
  // argsDigest is RECOMPUTED from function_args — the fixture's args_digest
  // attr is all-zeros and must not be trusted.
  assert.equal(first.argsDigest, canonicalDigest({ name: "arg-trap", price: 42 }));
  assert.notEqual(first.argsDigest, "0x" + "0".repeat(64));
  assert.equal(refused.length, 0);
});

test("hermes: a tool arg called name does not rename the tool", async () => {
  const sink = await sinkWithHermesFixture("run-h2", "provider");
  const { spans } = await extractVerified(sink, "run-h2", HERMES);
  // rec1's function_args contain {"name":"arg-trap"} — tool stays submit_offer.
  assert.equal(spans[0].tool, "submit_offer");
});

test("hermes: error_type attr and isError output both yield no nonce + error_result", async () => {
  const sink = await sinkWithHermesFixture("run-h3", "provider");
  const { spans } = await extractVerified(sink, "run-h3", HERMES);
  const errored = spans[1];
  assert.equal(errored.tool, "bad_call");
  assert.equal(errored.serverNonce, undefined); // decoy nonce in output not surfaced
  assert.ok(errored.flags?.includes("error_result"));
  const isErr = spans[2];
  assert.equal(isErr.tool, "local_shell");
  assert.equal(isErr.serverNonce, undefined);
  assert.ok(isErr.flags?.includes("error_result"));
});

test("hermes: runtime mismatch is refused, not relabelled", async () => {
  const sink = await sinkWithHermesFixture("run-h4", "provider");
  const out = await extractVerified(sink, "run-h4", { buyer: "codex", provider: "codex" });
  assert.equal(out.ok, true);
  assert.equal(out.spans.length, 0);
  assert.equal(out.refused.length, 3);
  assert.ok(out.refused.every((r) => r.code === "RUNTIME_MISMATCH"));
});
