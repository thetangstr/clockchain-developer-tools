import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import { createV2PublicHttpHandler } from "../dist/agent-handshake/v2/public-server.js";
import { AGENT_HANDSHAKE_ROLE_TOOLS, authorizeV2RoleAccess, mintV2RoleAccess } from "../dist/agent-handshake/v2/access.js";
import { createHandshakeReceiptRecorder, loadHandshakeReceiptsConfig } from "../dist/agent-handshake/v2/receipts.js";
import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain, serverReceiptSchema } from "../dist/agent-contract/receipts.js";

const pin = {
  version: "2.1.8",
  sourceCommit: "d".repeat(40),
  manifestDigest: "a".repeat(64),
  allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/",
  hostRoots: [{ kid: "root-2026-08", fingerprint: "b".repeat(64) }],
};
const ACCEPT = "application/json, text/event-stream";
const roleKey = { kid: "role-test", secret: Buffer.alloc(32, "r") };
const SESSION = "11111111-2222-4333-8444-555555555555";
const SEED = Buffer.alloc(32, 7).toString("base64");
const OPT = { "x-forwarded-prefix": "/next", "x-clockchain-receipt": "1" };

const access = (role) =>
  mintV2RoleAccess({
    key: roleKey, jti: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sessionId: SESSION, role,
    statementDigest: "f".repeat(64), allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS, nbfMs: 0, expMs: 60_000,
  });

const config = () => loadHandshakeReceiptsConfig({
  HANDSHAKE_V2_RECEIPTS: "1",
  HANDSHAKE_V2_RECEIPT_ED25519_SEED: SEED,
  HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM: "2026-10-01T00:00:00Z",
  HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: "observer-token-for-tests",
});

async function pubKeys(url) {
  const keys = await (await fetch(url.replace("/handshake/mcp", "/handshake/receipt-keys"))).json();
  const k = keys.keys[0];
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(k.publicKeyHex.slice(2), "hex")]), format: "der", type: "spki" });
  return { [k.keyId]: pub };
}

async function serve({ withReceipts = true } = {}) {
  const recorder = withReceipts
    ? createHandshakeReceiptRecorder({ config: config(), accessKeys: [roleKey], now: () => 1_000 })
    : undefined;
  const handler = createV2PublicHttpHandler({
    pin, now: () => 1_000, stateDir: undefined,
    invoke: async (name, args) => {
      if (typeof args.access === "string") authorizeV2RoleAccess(args.access, { keys: [roleKey], nowMs: 1_000, requiredTool: name });
      return { role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart" };
    },
    ...(recorder ? { receipts: recorder } : {}),
  });
  const server = createServer((req, res) => { if (recorder && recorder.routes(req, res)) return; handler(req, res); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/handshake/mcp`, recorder, close: () => new Promise((r) => server.close(r)) };
}

const post = (url, body, headers = {}) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT, ...headers }, body: JSON.stringify(body) });

async function initialize(url, headers = OPT) {
  const r = await post(url, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }, headers);
  const sid = r.headers.get("mcp-session-id");
  await r.text();
  if (sid) await post(url, { jsonrpc: "2.0", method: "notifications/initialized" }, { ...headers, "mcp-session-id": sid }).then((x) => x.text());
  return sid;
}

const call = (url, sid, role, id = 1, headers = OPT) =>
  post(url, { jsonrpc: "2.0", id, method: "tools/call", params: { name: "agent_handshake_status", arguments: { access: access(role) } } }, { ...headers, ...(sid ? { "mcp-session-id": sid } : {}) }).then((r) => r.text());

test("receipt carries the mcp-session-id of the transport that handled the call, inside the signed body", async () => {
  const s = await serve();
  try {
    const sid = await initialize(s.url);
    assert.match(sid, /^[0-9a-f-]{36}$/);
    await call(s.url, sid, "initiator");
    await call(s.url, sid, "initiator", 2);
    const chain = s.recorder.store.receipts(SESSION);
    assert.equal(chain.length, 2);
    for (const r of chain) assert.equal(r.mcpSessionId, sid);
    assert.equal(verifyChain(chain, await pubKeys(s.url)).ok, true);
    chain.forEach((r) => assert.ok(serverReceiptSchema.safeParse(r).success));
    // Tampering with the session id breaks the receipt's content address (it is hashed/signed).
    const forged = { ...chain[0], mcpSessionId: "00000000-0000-4000-8000-000000000000" };
    assert.notEqual(canonicalDigest(forged), canonicalDigest(chain[0]));
  } finally { await s.close(); }
});

test("two transports (two MCP sessions) yield two distinct mcpSessionIds; chain links and signatures still verify", async () => {
  const s = await serve();
  try {
    const a = await initialize(s.url);
    const b = await initialize(s.url);
    assert.notEqual(a, b);
    await call(s.url, a, "initiator", 1);
    await call(s.url, b, "responder", 2);
    await call(s.url, a, "initiator", 3);
    const chain = s.recorder.store.receipts(SESSION);
    assert.deepEqual(chain.map((r) => r.mcpSessionId), [a, b, a]);
    assert.equal(chain[1].prevHash, canonicalDigest(chain[0]));
    assert.equal(chain[2].prevHash, canonicalDigest(chain[1]));
    assert.equal(verifyChain(chain, await pubKeys(s.url)).ok, true);
    // The session id is inside the signature's coverage: editing it fails verification.
    const forged = chain.map((r, i) => (i === 1 ? { ...r, mcpSessionId: a } : r));
    assert.equal(verifyChain(forged, await pubKeys(s.url)).ok, false);
  } finally { await s.close(); }
});

test("stateless callers (no session / no opt-in) are unchanged: no mcp-session-id header, receipts omit mcpSessionId", async () => {
  const s = await serve();
  const off = await serve({ withReceipts: false });
  try {
    const r = await post(s.url, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }, { "x-forwarded-prefix": "/next" });
    assert.equal(r.headers.get("mcp-session-id"), null);
    await r.text();
    await call(s.url, undefined, "initiator", 1, { "x-forwarded-prefix": "/next" });
    await call(s.url, undefined, "initiator", 2, {}); // legacy path (no prefix, no opt-in): unrecorded
    assert.equal(s.recorder.store.receipts(SESSION).length, 1);
    for (const r of s.recorder.store.receipts(SESSION)) assert.equal(r.mcpSessionId, undefined);
    // Flag off: the opt-in header is ignored entirely, no session minted.
    const o = await post(off.url, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }, OPT);
    assert.equal(o.headers.get("mcp-session-id"), null);
    await o.text();
    // A stale/unknown session id still works statelessly, as before.
    assert.ok((await call(s.url, "00000000-0000-4000-8000-000000000000", "initiator", 3)).includes("awaiting_counterpart"));
  } finally { await s.close(); await off.close(); }
});

test("stateful call responses and echo meta match the stateless shape; echo hash equals the session-bearing receipt", async () => {
  const s = await serve();
  try {
    const sid = await initialize(s.url);
    const stateful = await call(s.url, sid, "initiator");
    const stateless = await call(s.url, undefined, "responder", 9);
    const body = (t) => JSON.parse(t.split("\n").find((l) => l.startsWith("data: ")).slice(6)).result;
    const e = body(stateful)._meta["clockchain/receipt"];
    const chain = s.recorder.store.receipts(SESSION);
    assert.equal(e.receiptHash, canonicalDigest(chain[0]));
    assert.deepEqual(Object.keys(body(stateless)._meta["clockchain/receipt"]).sort(), Object.keys(e).sort());
    assert.equal(chain[1].mcpSessionId, undefined);
  } finally { await s.close(); }
});

test("session objects are not leaked by failed initializes; per-IP session cap falls back to stateless", async () => {
  const s = await serve();
  try {
    // bad Accept: SDK refuses with 406, no session minted
    const bad = await post(s.url, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }, { ...OPT, accept: "application/json" });
    assert.equal(bad.status, 406);
    await bad.text();
    const ids = new Set();
    for (let i = 0; i < 8; i += 1) ids.add(await initialize(s.url));
    assert.equal(ids.size, 8);
    assert.equal(await initialize(s.url), null); // 9th from the same IP: stateless fallback
  } finally { await s.close(); }
});
