// N4C-CHANGES-4: query tokens mintable for an existing (even sealed) run —
// never before the run exists; a dedicated close-only listener for the
// contract server; /close removed from the write port.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  canonicalJson,
  createForwarder,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  sealToken,
} from "../dist/index.js";

const sinkKeys = generateKeyPairSync("ed25519");
const sinkSigner = { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey };
const contractKeys = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contractKeys.publicKey };

const LOGS = (logRecords) => JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords }] }] });
const EMPTY = LOGS([]);
const T0 = Date.parse("2030-01-01T00:00:00.000Z");

function terminalReceipt({ runId, ts = T0, key = contractKeys, state = "settled" }) {
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

async function boot(t, sinkOpts = {}) {
  let now = T0;
  const tokens = createTokenStore({ now: () => now });
  const sink = createTelemetrySink({
    signer: sinkSigner, tokens, now: () => now,
    contractKeys: contractPublicKeys, flushGraceMs: 0,
    ...sinkOpts,
  });
  const { write, read, close } = createTelemetrySinkServer({ sink, tokens });
  await new Promise((r) => write.listen(0, "127.0.0.1", r));
  await new Promise((r) => read.listen(0, "127.0.0.1", r));
  await new Promise((r) => close.listen(0, "127.0.0.1", r));
  t.after(() => { write.close(); read.close(); close.close(); });
  return {
    sink, tokens,
    writeUrl: `http://127.0.0.1:${write.address().port}`,
    readUrl: `http://127.0.0.1:${read.address().port}`,
    closeUrl: `http://127.0.0.1:${close.address().port}`,
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

// ------------------------------------------- 1: used-runId check is ingest-only

test("query tokens mint for an existing run — never before it exists; ingest re-mint still refused", async (t) => {
  const { tokens, sink, readUrl } = await boot(t);

  // Never-before-seen runId: no query token.
  assert.throws(() => tokens.mintQuery({ runId: "run-q0" }), /exist|used|unknown/i);
  // Wildcard stays refused too.
  assert.throws(() => tokens.mintQuery({ runId: "*" }), /runId/i);

  const ing = tokens.mintIngest({ runId: "run-q1", role: "buyer" });
  // Minted-but-never-used is still "does not exist" — the run has no records.
  assert.throws(() => tokens.mintQuery({ runId: "run-q1" }), /exist|used|unknown/i);

  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(EMPTY), contentType: "application/json" });
  // Now the run exists — a query token mints fine.
  const qry = tokens.mintQuery({ runId: "run-q1" });
  assert.equal((await get(readUrl, "/v1/runs/run-q1/records", qry.token)).status, 200);

  // Ingest authority can never be re-minted for a used runId.
  assert.throws(() => tokens.mintIngest({ runId: "run-q1", role: "provider" }), /used|reuse/i);
  assert.throws(() => tokens.mintIngest({ runId: "run-q1", role: "buyer" }), /used|reuse/i);
});

test("the verifier mints a query token after sealing and reads the evidence", async (t) => {
  const { tokens, sink, readUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-q2", role: "buyer" });
  sink.ingest({ token: ing.token, kind: "logs", body: Buffer.from(EMPTY), contentType: "application/json" });

  const res = await post(closeUrl, "/v1/runs/run-q2/close", JSON.stringify(terminalReceipt({ runId: "run-q2" })));
  assert.equal(res.status, 200);

  // Post-seal mint (the verifier flow) works.
  const qry = tokens.mintQuery({ runId: "run-q2" });
  const out = await get(readUrl, "/v1/runs/run-q2/head", qry.token);
  assert.equal(out.status, 200);
  const { head, annex } = await out.json();
  assert.equal(head.final, true);
  assert.equal(annex.refusedAfterClose, 0);
});

// ------------------------------------------- 2: close-only listener

test("/close is gone from the write port; the close port seals on a genuine receipt", async (t) => {
  const { tokens, sink, writeUrl, closeUrl } = await boot(t);
  const ing = tokens.mintIngest({ runId: "run-cl", role: "buyer" });
  assert.equal((await post(writeUrl, "/v1/logs", EMPTY, ing.token)).status, 200);

  // Write port no longer knows the route — even with a valid receipt.
  assert.equal(
    (await post(writeUrl, "/v1/runs/run-cl/close", JSON.stringify(terminalReceipt({ runId: "run-cl" })))).status,
    404,
  );
  assert.equal(sink.isClosed("run-cl"), false);

  // Close port: forged receipt refused, genuine receipt seals.
  const forged = { ...terminalReceipt({ runId: "run-cl" }), signature: { alg: "ed25519", keyId: "contract-server", sig: "0x" + "0".repeat(128) } };
  assert.equal((await post(closeUrl, "/v1/runs/run-cl/close", JSON.stringify(forged))).status, 403);
  const res = await post(closeUrl, "/v1/runs/run-cl/close", JSON.stringify(terminalReceipt({ runId: "run-cl" })));
  assert.equal(res.status, 200);
  const { head } = await res.json();
  assert.equal(head.final, true);
  assert.equal(sink.isClosed("run-cl"), true);

  // The close port serves ONLY close — no traces/logs/records/health.
  assert.equal((await post(closeUrl, "/v1/logs", EMPTY, ing.token)).status, 404);
  assert.equal((await get(closeUrl, "/v1/runs/run-cl/head", ing.token)).status, 404);
  assert.equal((await get(closeUrl, "/v1/health")).status, 404);
});

test("the forwarder cannot deliver a close: it only sees the write port", async (t) => {
  const { tokens, writeUrl } = await boot(t);
  const services = generateKeyPairSync("x25519");
  const servicesPubHex = "0x" + Buffer.from(services.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex");
  const minted = tokens.mintIngest({ runId: "run-fw", role: "buyer" });
  const sealed = sealToken(servicesPubHex, minted.token, { runId: "run-fw", role: "buyer" });

  const forwarder = createForwarder({
    listen: { host: "127.0.0.1", port: 0 },
    targetBaseUrl: writeUrl,
    sealedToken: sealed,
    servicesPrivateKeyJwk: services.privateKey.export({ format: "jwk" }),
    runId: "run-fw",
    role: "buyer",
  });
  await new Promise((r) => forwarder.listen(0, "127.0.0.1", r));
  t.after(() => forwarder.close());
  const fwdUrl = `http://127.0.0.1:${forwarder.address().port}`;

  // A close relayed through the forwarder lands on the write port → 404.
  const res = await post(fwdUrl, "/v1/runs/run-fw/close", JSON.stringify(terminalReceipt({ runId: "run-fw" })));
  assert.equal(res.status, 404);
  // While a normal log write through the same forwarder still works.
  assert.equal((await post(fwdUrl, "/v1/logs", EMPTY)).status, 200);
});
