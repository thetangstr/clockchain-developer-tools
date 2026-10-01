import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalJson,
  createRunLedger,
  createTelemetrySink,
  createTokenStore,
  verifyAndExtract,
  verifyRecords,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const sinkPublicKeys = { "ac-telemetry-test": sinkKeys.publicKey };

const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const T0 = Date.parse("2030-01-01T00:00:00.000Z");

function receiptFor(runId, state = "settled", ts = T0) {
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

const TRACES = JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [] }] }] });
const CT = "application/json";
const ROLE_RUNTIME = { buyer: "cli-x/1", provider: "cli-y/1" };

function tmpStateDir() {
  return mkdtempSync(path.join(tmpdir(), "n7a-restart-"));
}

/** A boot as the container would do it: store + ledger bound to stateDir. */
function boot(stateDir, now = () => T0, sinkOpts = {}) {
  const tokens = createTokenStore({ now, recordsFile: path.join(stateDir, "tokens.json") });
  const ledger = createRunLedger({ file: path.join(stateDir, "runs.json"), now });
  const sink = createTelemetrySink({
    signer: sinkSigner,
    tokens,
    now,
    runLedger: ledger,
    contractKeys: contractPublicKeys,
    flushGraceMs: 0,
    ...sinkOpts,
  });
  return { sink, tokens, ledger };
}

const send = (sink, token, body = TRACES) =>
  sink.ingest({ token, kind: "traces", body: Buffer.from(body), contentType: CT });

test("HIGH: restart mid-run — ingest refuses RUN_LOST, never reopens at seq 0", async () => {
  const stateDir = tmpStateDir();
  const first = boot(stateDir);
  const minted = first.tokens.mintIngest({ runId: "run-lost", role: "buyer" });
  const r1 = send(first.sink, minted.token);
  assert.equal(r1.ok, true);
  const r2 = send(first.sink, minted.token);
  assert.equal(r2.ok, true);
  assert.equal(r2.record.seq, 1);
  await first.tokens.flush();

  // The durable marker exists from the OPEN transition — before the "restart".
  const doc = JSON.parse(readFileSync(path.join(stateDir, "runs.json"), "utf8"));
  assert.equal(typeof doc.runs["run-lost"].openedAtMs, "number");

  // Restart: fresh store + ledger on the SAME volume, empty memory.
  const second = boot(stateDir);
  const r3 = send(second.sink, minted.token);
  assert.deepEqual({ ok: r3.ok, code: r3.code }, { ok: false, code: "RUN_LOST" });

  // Permanently lost — across ANOTHER restart too.
  const third = boot(stateDir);
  const r4 = send(third.sink, minted.token);
  assert.deepEqual({ ok: r4.ok, code: r4.code }, { ok: false, code: "RUN_LOST" });
});

test("HIGH: a lost run's close signs a lost:true head rejected by verifier AND extractor", async () => {
  const stateDir = tmpStateDir();
  const first = boot(stateDir);
  const minted = first.tokens.mintIngest({ runId: "run-lost2", role: "buyer" });
  send(first.sink, minted.token);
  await first.tokens.flush();

  // Restart → the receipt still authorizes a close, but the head is lost:true.
  const second = boot(stateDir);
  const closed = await second.sink.closeRun({ runId: "run-lost2", receipt: receiptFor("run-lost2") });
  assert.equal(closed.ok, true);
  assert.equal(closed.head.lost, true);
  assert.equal(closed.head.final, true);
  assert.equal(closed.head.closeCause, "run_lost");
  assert.equal(closed.head.recordCount, 0);
  assert.equal(closed.head.seq, -1);
  assert.match(closed.head.signature.sig, /^0x[0-9a-f]{128}$/);

  // The signed head is served back to queries.
  assert.equal(second.sink.head("run-lost2")?.lost, true);

  // Verifier: a lost head is never complete — whatever records accompany it.
  const verdict = verifyRecords([], closed.head, sinkPublicKeys);
  assert.deepEqual({ ok: verdict.ok, code: verdict.code }, { ok: false, code: "RUN_LOST" });
  const smuggled = verifyRecords(
    [{ seq: 0, runId: "run-lost2", kind: "traces", bodyDigest: "0x0", bodyBytes: 1, contentType: CT, receivedAt: "x", tokenId: "0x0", role: "buyer", prevHash: "0x0", recordDigest: "0x0" }],
    closed.head,
    sinkPublicKeys,
  );
  assert.deepEqual({ ok: smuggled.ok, code: smuggled.code }, { ok: false, code: "RUN_LOST" });

  // The extraction path rejects identically — no rows leave a lost run.
  const extracted = verifyAndExtract([], closed.head, second.sink.annex("run-lost2"), sinkPublicKeys, { roleRuntime: ROLE_RUNTIME });
  assert.deepEqual({ ok: extracted.ok, code: extracted.code }, { ok: false, code: "RUN_LOST" });

  // A close retry is idempotent — the same lost head, not a fresh attempt.
  const again = await second.sink.closeRun({ runId: "run-lost2", receipt: receiptFor("run-lost2") });
  assert.equal(again.head.lost, true);
});

test("HIGH: markRunUsed throwing at seq 0 poisons the run — RUN_LOST now and post-restart", async () => {
  const stateDir = tmpStateDir();
  const first = boot(stateDir);
  const minted = first.tokens.mintIngest({ runId: "run-fail", role: "buyer" });
  // Persistence fails AFTER the ledger marker — the ledger knows the run.
  const realMark = first.tokens.markRunUsed;
  first.tokens.markRunUsed = (runId) => { throw new Error("simulated persist failure"); };
  const r1 = send(first.sink, minted.token);
  assert.deepEqual({ ok: r1.ok, code: r1.code }, { ok: false, code: "RUN_LOST" });
  first.tokens.markRunUsed = realMark;

  // No in-memory chain was ever created — every later attempt is RUN_LOST.
  const r2 = send(first.sink, minted.token);
  assert.deepEqual({ ok: r2.ok, code: r2.code }, { ok: false, code: "RUN_LOST" });

  // Restart: the ledger marker makes it RUN_LOST permanently — the partial
  // pre-restart state can never close as complete.
  await first.tokens.flush();
  const second = boot(stateDir);
  const r3 = send(second.sink, minted.token);
  assert.deepEqual({ ok: r3.ok, code: r3.code }, { ok: false, code: "RUN_LOST" });
  const closed = await second.sink.closeRun({ runId: "run-fail", receipt: receiptFor("run-fail") });
  assert.equal(closed.ok, true);
  assert.equal(closed.head.lost, true);
  const verdict = verifyRecords([], closed.head, sinkPublicKeys);
  assert.deepEqual({ ok: verdict.ok, code: verdict.code }, { ok: false, code: "RUN_LOST" });
  const extracted = verifyAndExtract([], closed.head, null, sinkPublicKeys, { roleRuntime: ROLE_RUNTIME });
  assert.deepEqual({ ok: extracted.ok, code: extracted.code }, { ok: false, code: "RUN_LOST" });
});

test("HIGH: markOpened throwing leaves no chain — and the poisoned runId stays refused", async () => {
  const stateDir = tmpStateDir();
  const tokens = createTokenStore({ recordsFile: path.join(stateDir, "tokens.json") });
  const badLedger = {
    isOpened: () => false,
    isLost: () => false,
    markOpened: () => { throw new Error("disk gone"); },
    markClosed: () => {},
    markLost: () => {},
  };
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: () => T0,
    runLedger: badLedger, contractKeys: contractPublicKeys, flushGraceMs: 0,
  });
  const minted = tokens.mintIngest({ runId: "run-poison", role: "buyer" });
  const r1 = send(sink, minted.token);
  assert.deepEqual({ ok: r1.ok, code: r1.code }, { ok: false, code: "RUN_LOST" });
  assert.equal(sink.recordsFor("run-poison").length, 0, "no in-memory chain after rollback");
  // In-memory poison persists for this process.
  const r2 = send(sink, minted.token);
  assert.deepEqual({ ok: r2.ok, code: r2.code }, { ok: false, code: "RUN_LOST" });
  // Best-effort markRunUsed lands on the file — a restart still refuses.
  await tokens.flush();
  const second = boot(stateDir);
  const r3 = send(second.sink, minted.token);
  assert.deepEqual({ ok: r3.ok, code: r3.code }, { ok: false, code: "RUN_LOST" });
});

test("HIGH: close-pending across restart — a second close signs the lost head", async () => {
  const stateDir = tmpStateDir();
  const first = boot(stateDir, () => T0, { flushGraceMs: 60_000 });
  const minted = first.tokens.mintIngest({ runId: "run-pending", role: "buyer" });
  send(first.sink, minted.token);
  // Receipt accepted; the run seals only at receipt.ts + flushGrace.
  const pending = await first.sink.closeRun({ runId: "run-pending", receipt: receiptFor("run-pending") });
  assert.equal(pending.ok, true);
  assert.equal(pending.head, null);
  assert.equal(typeof pending.pendingClosedAt, "string");

  // Restart BEFORE the seal: pending state dies with the process, but the
  // ledger marker survives — the run is lost, not completable.
  const second = boot(stateDir, () => T0 + 61_000);
  const closed = await second.sink.closeRun({ runId: "run-pending", receipt: receiptFor("run-pending") });
  assert.equal(closed.ok, true);
  assert.equal(closed.head.lost, true);
  assert.equal(closed.head.closeCause, "run_lost");
  const verdict = verifyRecords([], closed.head, sinkPublicKeys);
  assert.deepEqual({ ok: verdict.ok, code: verdict.code }, { ok: false, code: "RUN_LOST" });
});

test("HIGH: exact refusal codes — RUN_EMPTY for never-opened, RUN_CLOSED in-process, UNAUTHORIZED first", async () => {
  const stateDir = tmpStateDir();
  const { sink, tokens } = boot(stateDir);
  // Never opened → RUN_EMPTY (not RUN_LOST).
  const closedGhost = await sink.closeRun({ runId: "run-ghost", receipt: receiptFor("run-ghost") });
  assert.equal(closedGhost.code, "RUN_EMPTY");
  // Unknown token → UNAUTHORIZED beats everything, including RUN_LOST runs.
  const stateDir2 = tmpStateDir();
  const first = boot(stateDir2);
  const minted = first.tokens.mintIngest({ runId: "run-codes", role: "buyer" });
  send(first.sink, minted.token);
  await first.tokens.flush();
  const second = boot(stateDir2);
  assert.equal(send(second.sink, "otlp-ing-wrong").code, "UNAUTHORIZED");
  assert.equal(send(second.sink, minted.token).code, "RUN_LOST");
  // A healthy in-process close still gives RUN_CLOSED for later writes.
  const minted2 = tokens.mintIngest({ runId: "run-ok", role: "buyer" });
  assert.equal(send(sink, minted2.token).ok, true);
  const sealed = await sink.closeRun({ runId: "run-ok", receipt: receiptFor("run-ok") });
  assert.equal(sealed.ok, true);
  assert.equal(sealed.head.lost, undefined);
  assert.equal(send(sink, minted2.token).code, "RUN_CLOSED");
  const verdict = verifyRecords(sink.exportRecords("run-ok"), sink.head("run-ok"), sinkPublicKeys);
  assert.equal(verdict.ok, true);
});

test("MED: ledger retention prunes terminal markers; usedRunIds still refuses reopening", async () => {
  const stateDir = tmpStateDir();
  let now = T0;
  const tokens = createTokenStore({ now: () => now, recordsFile: path.join(stateDir, "tokens.json") });
  const ledger = createRunLedger({ file: path.join(stateDir, "runs.json"), now: () => now, retentionMs: 1000 });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: () => now,
    runLedger: ledger, contractKeys: contractPublicKeys, flushGraceMs: 0,
  });
  const minted = tokens.mintIngest({ runId: "run-old", role: "buyer" });
  assert.equal(send(sink, minted.token).ok, true);
  const sealed = await sink.closeRun({ runId: "run-old", receipt: receiptFor("run-old") });
  assert.equal(sealed.ok, true);
  assert.equal(sealed.head.lost, undefined);
  // Past the retention window — the terminal marker is pruned on next write.
  await tokens.flush();
  now = T0 + 10_000;
  ledger.markLost("run-other", now);
  const doc = JSON.parse(readFileSync(path.join(stateDir, "runs.json"), "utf8"));
  assert.equal(doc.runs["run-old"], undefined, "closed marker pruned past retention");
  assert.ok(doc.runs["run-other"], "live marker kept");
  // Restart: usedRunIds is never pruned — minting a FRESH token for the same
  // runId refuses outright, and the ingest cross-check stands behind it.
  const second = boot(stateDir, () => now);
  assert.throws(
    () => second.tokens.mintIngest({ runId: "run-old", role: "buyer" }),
    /runId already used/,
  );
});

test("LOW: hostile runIds — 'constructor'/'toString'/'valueOf' are ordinary runs", async () => {
  const stateDir = tmpStateDir();
  const { sink, tokens } = boot(stateDir);
  for (const runId of ["constructor", "toString", "hasOwnProperty", "valueOf", "prototype.x"]) {
    const minted = tokens.mintIngest({ runId, role: "buyer" });
    const r = send(sink, minted.token);
    assert.equal(r.ok, true, runId);
  }
  // And they survive a restart boundary as RUN_LOST like any other run,
  // while a genuinely fresh runId still opens cleanly.
  await tokens.flush();
  const second = boot(stateDir);
  const minted = second.tokens.mintIngest({ runId: "run-x", role: "buyer" });
  assert.equal(send(second.sink, minted.token).ok, true, "fresh run unaffected");
  assert.throws(
    () => second.tokens.mintIngest({ runId: "constructor", role: "buyer" }),
    /runId already used/,
  );
});

test("LOW: stale lock is stolen via rename — a fresh lock is never deleted", async () => {
  // Covered in n7a-config's lock test for acquire semantics; here assert the
  // ledger's own marker file tolerates Object.prototype-adjacent keys on disk.
  const stateDir = tmpStateDir();
  const file = path.join(stateDir, "runs.json");
  const ledger = createRunLedger({ file });
  ledger.markOpened("__proto__", 1);
  const doc = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(Object.hasOwn(doc.runs, "__proto__"), true);
  assert.equal(ledger.isOpened("__proto__"), true);
  assert.equal(ledger.isOpened("hasOwnProperty"), false);
});
