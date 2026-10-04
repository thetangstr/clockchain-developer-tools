import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createV2PublicHttpHandler } from "../dist/agent-handshake/v2/public-server.js";
import { AGENT_HANDSHAKE_ROLE_TOOLS, authorizeV2RoleAccess, mintV2RoleAccess } from "../dist/agent-handshake/v2/access.js";
import {
  HANDSHAKE_RECEIPT_FEED_SCHEMA,
  MAX_RECEIPTS_PER_SESSION,
  createHandshakeReceiptRecorder,
  loadHandshakeReceiptsConfig,
} from "../dist/agent-handshake/v2/receipts.js";
import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";

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
const OTHER_SESSION = "22222222-3333-4444-8555-666666666666";
const SEED = Buffer.alloc(32, 7).toString("base64");
const TOKEN = "observer-token-for-tests";

const access = (role, overrides = {}) =>
  mintV2RoleAccess({
    key: roleKey,
    jti: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    sessionId: SESSION,
    role,
    statementDigest: "f".repeat(64),
    allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
    nbfMs: 0,
    expMs: 60_000,
    ...overrides,
  });

const env = (extra = {}) => ({
  HANDSHAKE_V2_RECEIPTS: "1",
  HANDSHAKE_V2_RECEIPT_ED25519_SEED: SEED,
  HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM: "2026-10-01T00:00:00Z",
  HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: TOKEN,
  ...extra,
});

async function rpc(url, name, args, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT, ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  return { status: response.status, text: await response.text() };
}

const normalize = (text) => text.replace(/ccra_[A-Za-z0-9_-]{22}/g, "ccra_X");
const CERT = { hostSessionKeyCertificate: { x: 1 }, result: { sessionId: SESSION, outcome: "VERIFIED" }, signer: { y: 2 } };

function fakeInvoke(calls) {
  return async (name, args) => {
    calls.push({ name, args });
    // Mirror the coordinator: a role-scoped call needs a verifying bearer.
    if (typeof args.access === "string") {
      try { authorizeV2RoleAccess(args.access, { keys: [roleKey], nowMs: 1_000, requiredTool: name }); }
      catch (error) { throw error; }
    }
    if (name === "agent_handshake_invite") return { sessionId: SESSION, initiatorAccess: access("initiator"), responderInvitation: "secret-invitation-xyz" };
    if (name === "agent_handshake_accept_invitation") return { sessionId: SESSION, responderAccess: access("responder") };
    if (name === "agent_handshake_submit") throw Object.assign(new Error("nope"), { name: "V2CoordinatorError" });
    return { role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart" };
  };
}

async function serve({ withReceipts, config = loadHandshakeReceiptsConfig(env()), extra = {} }) {
  const calls = [];
  const recorder = withReceipts
    ? createHandshakeReceiptRecorder({
        config,
        accessKeys: [roleKey],
        getCertificate: async (id) => (id === SESSION ? CERT : (() => { throw new Error("no"); })()),
        now: () => 1_000,
        ...extra,
      })
    : undefined;
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => 1_000,
    invoke: fakeInvoke(calls),
    stateDir: undefined,
    ...(recorder ? { receipts: recorder } : {}),
  });
  const server = createServer((req, res) => {
    if (recorder && recorder.routes(req, res)) return;
    handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, calls, recorder, close: () => new Promise((r) => server.close(r)) };
}

async function scriptedRun(base, headers) {
  const out = [];
  const inviteArgs = { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } };
  out.push(await rpc(`${base}/handshake/mcp`, "agent_handshake_invite", inviteArgs, headers));
  out.push(await rpc(`${base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, headers));
  out.push(await rpc(`${base}/handshake/mcp`, "agent_handshake_next", { access: access("responder"), waitMs: 0 }, headers));
  out.push(await rpc(`${base}/handshake/mcp`, "agent_handshake_submit", { access: access("initiator"), policyDigest: "a".repeat(64), signatureHex: `0x${"b".repeat(130)}` }, headers));
  out.push(await rpc(`${base}/handshake/mcp`, "agent_handshake_get_certificate", { access: access("initiator") }, headers));
  return out;
}

const feed = (base, query = `sessionId=${SESSION}`, headers = { authorization: `Bearer ${TOKEN}` }) =>
  fetch(`${base}/handshake/receipts?${query}`, { headers });


const result = (text) => JSON.parse(text.split("\n").find((l) => l.startsWith("data: ")).slice(6)).result;
const ECHO = { "x-forwarded-prefix": "/next", "x-clockchain-receipt": "1" };

test("nonce echo: opt-in header returns the receipt's serverNonce + hash in result._meta, matching the signed feed", async () => {
  const on = await serve({ withReceipts: true });
  try {
    const metas = [];
    const base = `${on.base}/handshake/mcp`;
    metas.push(result((await rpc(base, "agent_handshake_status", { access: access("initiator") }, ECHO)).text));
    metas.push(result((await rpc(base, "agent_handshake_next", { access: access("responder"), waitMs: 0 }, ECHO)).text));
    // a refused call is echoed too (error path)
    metas.push(result((await rpc(base, "agent_handshake_submit", { access: access("initiator"), policyDigest: "a".repeat(64), signatureHex: `0x${"b".repeat(130)}` }, ECHO)).text));
    const chain = on.recorder.store.receipts(SESSION);
    assert.equal(chain.length, 3);
    metas.forEach((r, i) => {
      const e = r._meta["clockchain/receipt"];
      assert.equal(e.serverNonce, chain[i].serverNonce);
      assert.equal(e.receiptId, chain[i].receiptId);
      assert.equal(e.receiptHash, canonicalDigest(chain[i]));
      assert.match(e.serverNonce, /^0x[0-9a-f]{32}$/);
    });
    assert.equal(new Set(metas.map((r) => r._meta["clockchain/receipt"].serverNonce)).size, 3);
    // The echoed hash is the next receipt's prevHash link.
    assert.equal(chain[1].prevHash, metas[0]._meta["clockchain/receipt"].receiptHash);
    // Nonce only ever appears in _meta, never in the tool body.
    assert.ok(!JSON.stringify(metas[0].structuredContent).includes(chain[0].serverNonce));
  } finally { await on.close(); }
});

test("nonce echo: without the header (or when the path is not receipted, or the value is not exactly 1) responses stay byte-identical and carry no _meta", async () => {
  const off = await serve({ withReceipts: false });
  const on = await serve({ withReceipts: true });
  try {
    const a = await scriptedRun(off.base, { "x-forwarded-prefix": "/next" });
    const b = await scriptedRun(on.base, { "x-forwarded-prefix": "/next" });
    const c = await scriptedRun(on.base, { "x-clockchain-receipt": "1" }); // header but legacy path: no recorder hook
    const d = await scriptedRun(on.base, { "x-forwarded-prefix": "/next", "x-clockchain-receipt": "true" });
    const flat = (rs) => rs.map((r) => [r.status, normalize(r.text)]);
    assert.deepEqual(flat(b), flat(a));
    assert.deepEqual(flat(c), flat(a));
    assert.deepEqual(flat(d), flat(a));
    for (const r of [...a, ...b, ...c, ...d]) assert.ok(!r.text.includes("_meta") && !r.text.includes("clockchain/receipt"));
  } finally { await off.close(); await on.close(); }
});

test("nonce echo: flag off (no recorder) ignores the request header entirely", async () => {
  const off = await serve({ withReceipts: false });
  try {
    const plain = await scriptedRun(off.base, { "x-forwarded-prefix": "/next" });
    const hdr = await scriptedRun(off.base, ECHO);
    assert.deepEqual(hdr.map((r) => [r.status, normalize(r.text)]), plain.map((r) => [r.status, normalize(r.text)]));
  } finally { await off.close(); }
});

test("nonce echo: a call that is not attributable (forged access) is not echoed", async () => {
  const on = await serve({ withReceipts: true });
  try {
    const r = await rpc(`${on.base}/handshake/mcp`, "agent_handshake_status", { access: "forged" }, ECHO);
    assert.ok(!r.text.includes("clockchain/receipt"));
  } finally { await on.close(); }
});

test("nonce echo: concurrent calls in one JSON-RPC batch each get their own receipt's nonce", async () => {
  const on = await serve({ withReceipts: true });
  try {
    const call = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
    const response = await fetch(`${on.base}/handshake/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, ...ECHO },
      body: JSON.stringify([
        call(1, "agent_handshake_status", { access: access("initiator") }),
        call(2, "agent_handshake_next", { access: access("responder"), waitMs: 0 }),
        call(3, "agent_handshake_get_certificate", { access: access("initiator") }),
      ]),
    });
    const text = await response.text();
    const messages = text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)));
    const chain = on.recorder.store.receipts(SESSION);
    const toolOf = { 1: "agent_handshake_status", 2: "agent_handshake_next", 3: "agent_handshake_get_certificate" };
    assert.equal(messages.length, 3, text);
    for (const m of messages) {
      const e = m.result._meta["clockchain/receipt"];
      const receipt = chain.find((r) => r.serverNonce === e.serverNonce);
      assert.ok(receipt, "echoed nonce names a real receipt");
      assert.equal(receipt.tool, toolOf[m.id]);
    }
    assert.equal(new Set(messages.map((m) => m.result._meta["clockchain/receipt"].serverNonce)).size, 3);
  } finally { await on.close(); }
});
