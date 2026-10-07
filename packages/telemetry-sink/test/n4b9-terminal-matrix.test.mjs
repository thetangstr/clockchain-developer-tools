import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  canonicalDigest,
  canonicalJson,
  createTelemetrySink,
  createTokenStore,
  TERMINAL_STATES,
} from "../dist/index.js";

// N4b-9 (F10): the producer and the sink share ONE terminal-state vocabulary.
// The producer's set (contract-mcp schemas.ts CONTRACT_TERMINAL_STATES) is
// duplicated here verbatim — drift on either side fails this side's suite.

const PRODUCER_TERMINAL_STATES = [
  "settled",
  "no_agreement",
  "verification_failed",
  "blocked_by_policy",
  "budget_exhausted",
  "harness_error",
  "cancelled",
  "expired_unbound",
  // CDT-GAPS gap 2: a fully bound run reaching its TTL (CONTRACT_EXPIRE_AT_TTL=1).
  "expired",
];

const sinkKeys = generateKeyPairSync("ed25519");
const contractKeys = generateKeyPairSync("ed25519");
const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const LOGS = JSON.stringify({ resourceLogs: [{ scopeLogs: [] }] });

/** The producer's mintTerminalReceipt byte convention (close-emitter.ts). */
function receiptFor(runId, terminalState, ts = T0) {
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

function freshSink() {
  const tokens = createTokenStore({ now: () => T0 });
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey },
    tokens,
    now: () => T0,
    contractKeys: { "contract-server": contractKeys.publicKey },
    flushGraceMs: 0,
  });
  return { tokens, sink };
}

test("F10: the sink terminal-state set is identical to the producer's", () => {
  assert.deepEqual([...TERMINAL_STATES].sort(), [...PRODUCER_TERMINAL_STATES].sort());
});

test("F10: every producer terminal state closes a real run through checkReceipt + closeRun", async () => {
  for (const terminalState of PRODUCER_TERMINAL_STATES) {
    const runId = `run-${terminalState}`;
    const { tokens, sink } = freshSink();
    const ing = tokens.mintIngest({ runId, role: "buyer" });
    const out = sink.ingest({
      token: ing.token, kind: "logs",
      body: Buffer.from(LOGS), contentType: "application/json",
    });
    assert.equal(out.ok, true, `${terminalState}: ingest refused`);
    const receipt = receiptFor(runId, terminalState);
    const close = await sink.closeRun({ runId, receipt });
    assert.equal(close.ok, true, `${terminalState}: closeRun refused ${JSON.stringify(close)}`);
    assert.equal(close.head.final, true);
    // The receipt that closed the run is the one digested into the head
    // (checkReceipt digests schema/runId/terminalState/ts/signature).
    assert.equal(
      close.head.receiptDigest,
      canonicalDigest({
        schema: receipt.schema, runId: receipt.runId,
        terminalState: receipt.terminalState, ts: receipt.ts,
        signature: receipt.signature,
      }),
      `${terminalState}: head binds a different receipt`,
    );
  }
});

test("F10: a state outside the shared vocabulary is refused, not silently mapped", async () => {
  const runId = "run-bogus";
  const { tokens, sink } = freshSink();
  const ing = tokens.mintIngest({ runId, role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(LOGS), contentType: "application/json" });
  const close = await sink.closeRun({ runId, receipt: receiptFor(runId, "completed") });
  assert.equal(close.ok, false);
  assert.equal(close.code, "RECEIPT_INVALID");
});
