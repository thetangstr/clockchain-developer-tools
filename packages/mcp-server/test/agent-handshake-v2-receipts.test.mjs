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

test("config: off unless HANDSHAKE_V2_RECEIPTS=1; closed on misconfiguration", () => {
  assert.equal(loadHandshakeReceiptsConfig({}).kind, "disabled");
  assert.equal(loadHandshakeReceiptsConfig({ ...env(), HANDSHAKE_V2_RECEIPTS: "0" }).kind, "disabled");
  assert.equal(loadHandshakeReceiptsConfig({ HANDSHAKE_V2_RECEIPTS: "1" }).kind, "misconfigured");
  assert.equal(loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_ED25519_SEED: "not-base64!" })).kind, "misconfigured");
  assert.equal(loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM: "" })).kind, "misconfigured");
  assert.equal(loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_KEY_ID: "ephemeral-dev-abc" })).kind, "misconfigured");
  const ready = loadHandshakeReceiptsConfig(env());
  assert.equal(ready.kind, "ready");
  assert.equal(ready.signer.keyId, "handshake-v2-receipts");
  assert.equal(ready.prefix, "/next");
  const eph = loadHandshakeReceiptsConfig({ HANDSHAKE_V2_RECEIPTS: "1", HANDSHAKE_V2_RECEIPTS_ALLOW_EPHEMERAL_KEY: "1", HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM: "2026-10-01T00:00:00Z" });
  assert.match(eph.signer.keyId, /^ephemeral-dev-/);
  // The feed token falls back to the contract observer token; neither set -> closed feed.
  assert.equal(loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: "", CONTRACT_OBSERVER_TOKEN: "c-tok" })).observerToken, "c-tok");
  assert.equal(loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: "" })).observerToken, undefined);
});

test("flag off and flag on answer byte-identically (receipts are a pure side effect), on /handshake/mcp", async () => {
  const off = await serve({ withReceipts: false });
  const on = await serve({ withReceipts: true });
  try {
    const next = { "x-forwarded-prefix": "/next" };
    const a = await scriptedRun(off.base, next);
    const b = await scriptedRun(on.base, next);
    const c = await scriptedRun(on.base, {}); // legacy /handshake/mcp path: not opted in
    assert.deepEqual(b.map((r) => [r.status, normalize(r.text)]), a.map((r) => [r.status, normalize(r.text)]));
    assert.deepEqual(c.map((r) => [r.status, normalize(r.text)]), a.map((r) => [r.status, normalize(r.text)]));
    assert.deepEqual(on.calls.map((x) => x.name), [...off.calls.map((x) => x.name), ...off.calls.map((x) => x.name)]);
    // Without the opt-in prefix the second pass recorded nothing: only /next calls are receipted.
    assert.equal(on.recorder.store.receipts(SESSION).length, 5);
    // Flag-off server serves no receipt routes and no recorder exists.
    const noRoute = await fetch(`${off.base}/handshake/receipts?sessionId=${SESSION}`, { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(noRoute.status, 404);
    const noKeys = await fetch(`${off.base}/handshake/receipt-keys`);
    assert.equal(noKeys.status, 404);
  } finally {
    await off.close();
    await on.close();
  }
});

test("chain integrity, signatures, nonce uniqueness, roles, refusals, and no secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-receipts-"));
  const file = join(dir, "r.jsonl");
  const config = loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPTS_FILE: file }));
  const on = await serve({ withReceipts: true, config });
  try {
    await scriptedRun(on.base, { "x-forwarded-prefix": "/next" });
    const res = await feed(on.base);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    const doc = await res.json();
    assert.equal(doc.schema, HANDSHAKE_RECEIPT_FEED_SCHEMA);
    assert.equal(doc.sessionId, SESSION);
    assert.deepEqual(doc.principalRoleMap, { initiator: "buyer", responder: "provider" });
    assert.deepEqual(doc.certificate, CERT);
    assert.equal(doc.receipts.length, 5);
    assert.deepEqual(doc.receipts.map((r) => r.tool), ["agent_handshake_invite", "agent_handshake_status", "agent_handshake_next", "agent_handshake_submit", "agent_handshake_get_certificate"]);
    assert.deepEqual(doc.receipts.map((r) => r.principal.role), ["buyer", "buyer", "provider", "buyer", "buyer"]);
    assert.deepEqual(doc.receipts.map((r) => r.outcome), ["ok", "ok", "ok", "refused:V2CoordinatorError", "ok"]);
    assert.ok(doc.receipts.every((r) => r.surface === "handshake" && r.runId === SESSION));
    assert.equal(new Set(doc.receipts.map((r) => r.serverNonce)).size, doc.receipts.length);
    assert.equal(doc.head, canonicalDigest(doc.receipts.at(-1)));

    // Published key verifies the chain through the same verifier the contract server uses.
    const keys = await (await fetch(`${on.base}/handshake/receipt-keys`)).json();
    const k = keys.keys[0];
    assert.equal(k.keyId, "handshake-v2-receipts");
    const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(k.publicKeyHex.slice(2), "hex")]), format: "der", type: "spki" });
    assert.deepEqual(verifyChain(doc.receipts, { [k.keyId]: pub }), { ok: true, head: doc.head });

    // Tamper / drop / reorder / re-sign under another key all break the chain.
    const tampered = structuredClone(doc.receipts); tampered[2].outcome = "ok2";
    assert.equal(verifyChain(tampered, { [k.keyId]: pub }).ok, false);
    assert.equal(verifyChain([doc.receipts[0], doc.receipts[2]], { [k.keyId]: pub }).code, "CHAIN_LINK");
    assert.equal(verifyChain([doc.receipts[1], doc.receipts[0]], { [k.keyId]: pub }).ok, false);
    const wrong = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.alloc(32, 9)]), format: "der", type: "spki" });
    assert.equal(verifyChain(doc.receipts, { [k.keyId]: wrong }).code, "RECEIPT_SIGNATURE");

    // No bearer capability or private payload is stored: digests only.
    const stored = readFileSync(file, "utf8");
    const wire = JSON.stringify(doc);
    for (const secret of ["secret-invitation-xyz", access("initiator"), access("responder"), "b".repeat(130)]) {
      assert.equal(stored.includes(secret), false);
      assert.equal(wire.includes(secret), false);
    }
    assert.equal(stored.trim().split("\n").length, 5);
    assert.equal(doc.receipts[0].argsDigestScheme, "canonical");
  } finally {
    await on.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the chain survives a restart (file-backed) and continues", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-receipts-"));
  const file = join(dir, "r.jsonl");
  const config = loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPTS_FILE: file }));
  const first = await serve({ withReceipts: true, config });
  await rpc(`${first.base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, { "x-forwarded-prefix": "/next" });
  await first.close();
  const second = await serve({ withReceipts: true, config });
  try {
    await rpc(`${second.base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, { "x-forwarded-prefix": "/next" });
    const doc = await (await feed(second.base)).json();
    assert.equal(doc.receipts.length, 2);
    const keys = await (await fetch(`${second.base}/handshake/receipt-keys`)).json();
    const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(keys.keys[0].publicKeyHex.slice(2), "hex")]), format: "der", type: "spki" });
    assert.equal(verifyChain(doc.receipts, { [keys.keys[0].keyId]: pub }).ok, true);
  } finally {
    await second.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("forged or expired role access never creates or grows a chain; unknown sessions 404", async () => {
  const on = await serve({ withReceipts: true });
  try {
    const next = { "x-forwarded-prefix": "/next" };
    const forged = mintV2RoleAccess({ key: { kid: "role-test", secret: Buffer.alloc(32, "x") }, jti: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", sessionId: OTHER_SESSION, role: "initiator", statementDigest: "f".repeat(64), allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS, nbfMs: 0, expMs: 60_000 });
    const r = await rpc(`${on.base}/handshake/mcp`, "agent_handshake_status", { access: forged }, next);
    assert.equal(r.status, 200); // tool-level error, same as without receipts
    assert.equal(on.recorder.store.receipts(OTHER_SESSION), undefined);
    const missing = await feed(on.base, `sessionId=${OTHER_SESSION}`);
    assert.equal(missing.status, 404);
    assert.equal((await feed(on.base, "sessionId=not-a-uuid")).status, 404);
    assert.equal((await feed(on.base, "")).status, 404);
  } finally {
    await on.close();
  }
});

test("feed auth: closed without a token, 401 on bad/missing bearer, 403 on non-GET, 429 when limited", async () => {
  const closedCfg = loadHandshakeReceiptsConfig(env({ HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: "" }));
  const closed = await serve({ withReceipts: true, config: closedCfg });
  const limited = await serve({ withReceipts: true, extra: { allowFeed: (() => { let n = 0; return () => ++n <= 1; })() } });
  try {
    await rpc(`${limited.base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, { "x-forwarded-prefix": "/next" });
    await rpc(`${closed.base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, { "x-forwarded-prefix": "/next" });
    assert.equal((await feed(closed.base)).status, 404);
    assert.equal((await feed(limited.base, `sessionId=${SESSION}`, {})).status, 401);
    // allowFeed counts only authenticated requests (auth is checked first): first ok, second 429.
    assert.equal((await feed(limited.base, `sessionId=${SESSION}`, { authorization: "Bearer wrong" })).status, 401);
    assert.equal((await feed(limited.base)).status, 200);
    assert.equal((await feed(limited.base)).status, 429);
    assert.equal((await fetch(`${limited.base}/handshake/receipts?sessionId=${SESSION}`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } })).status, 403);
    // The key document is public, no credentials.
    assert.equal((await fetch(`${limited.base}/handshake/receipt-keys`)).status, 200);
  } finally {
    await closed.close();
    await limited.close();
  }
});

test("a certificate whose result names another session is never served; relay failure omits it", async () => {
  const bad = await serve({ withReceipts: true, extra: { getCertificate: async () => ({ result: { sessionId: OTHER_SESSION } }) } });
  const down = await serve({ withReceipts: true, extra: { getCertificate: async () => { throw new Error("relay down"); } } });
  try {
    for (const s of [bad, down]) {
      await rpc(`${s.base}/handshake/mcp`, "agent_handshake_status", { access: access("initiator") }, { "x-forwarded-prefix": "/next" });
      const doc = await (await feed(s.base)).json();
      assert.equal(doc.certificate, undefined);
      assert.equal(doc.receipts.length, 1);
    }
  } finally {
    await bad.close();
    await down.close();
  }
});

test("per-session cap is explicit (truncated), never a silent wrap", () => {
  const recorder = createHandshakeReceiptRecorder({ config: loadHandshakeReceiptsConfig(env()), accessKeys: [roleKey], now: () => 1_000 });
  for (let i = 0; i < MAX_RECEIPTS_PER_SESSION + 3; i += 1) {
    recorder.store.append(SESSION, { role: "initiator", tool: "agent_handshake_status", argsDigest: `0x${"0".repeat(64)}`, outcome: "ok", responseDigest: `0x${"1".repeat(64)}` });
  }
  assert.equal(recorder.store.receipts(SESSION).length, MAX_RECEIPTS_PER_SESSION);
  assert.equal(recorder.store.truncated(SESSION), true);
});
