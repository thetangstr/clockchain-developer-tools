// log_action step labels (action_type, intent_type): bound into the anchored hash through the v1 envelope, never sent
// to the gateway as text, and refused before any write or budget use when invalid. Drives the real handler from
// registerTools() with a stubbed fetch (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { registerTools } from "../dist/tools.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { __resetIdempotency } from "../dist/idempotency.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };
const HEX = "ab".repeat(32);
const sha = (s) => createHash("sha256").update(s).digest("hex");
const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");
const HEALTHY = { success: true, data: { "nodeParticipation%": 100, totalNodes: 1, blockHeight: "1", madMarzulloTime: "t" } };

function collectTools() {
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg);
  return tools;
}

/** Stub fetch; returns every request made, with /log bodies parsed. */
function stub() {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    calls.push({ url: u, body: opts.body ? JSON.parse(opts.body) : undefined });
    const body = u.includes("/getTime") ? HEALTHY : u.includes("/log") ? { ledgerId: "L1", blockHeight: null } : null;
    if (!body) throw new Error("no stubbed route for " + u);
    return { status: 200, ok: true, statusText: "stub", text: async () => JSON.stringify(body) };
  };
  return calls;
}
const logBodies = (calls) => calls.filter((c) => c.url.includes("/log")).map((c) => c.body);

test("no labels: the content's own SHA-256 is anchored and /log gets exactly what it got before", async () => {
  const calls = stub();
  const res = await collectTools().log_action({ content: "hello", asset_reference_id: "r", additional_info: "note" });
  assert.ok(!res.isError, textOf(res));
  assert.deepEqual(logBodies(calls), [{
    clientId: "c", walletId: "w", assetReferenceId: "r", assetHash: sha("hello"), hashType: "SHA-256", versionNumber: 1, additionalInfo: "note",
  }]);
  assert.equal("label_envelope" in JSON.parse(textOf(res)), false);

  const calls2 = stub();
  const res2 = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", action_type: "", intent_type: undefined });
  assert.ok(!res2.isError);
  assert.equal(logBodies(calls2)[0].assetHash, HEX, "empty labels count as no labels");
  assert.equal("label_envelope" in JSON.parse(textOf(res2)), false);
});

test("labels with content: the anchored hash is SHA-256 of the documented envelope; any label change changes it", async () => {
  const calls = stub();
  const res = await collectTools().log_action({ content: "hello", asset_reference_id: "r", action_type: "send", intent_type: "communicate" });
  assert.ok(!res.isError, textOf(res));
  const canonical = `{"v":1,"content_sha256":"${sha("hello")}","action_type":"send","intent_type":"communicate"}`;
  const [body] = logBodies(calls);
  assert.equal(body.assetHash, sha(canonical));
  assert.equal(body.hashType, "SHA-256");
  const out = JSON.parse(textOf(res)).label_envelope;
  assert.equal(out.canonical_json, canonical);
  assert.equal(out.anchored_hash, sha(canonical));
  assert.deepEqual(out.envelope, JSON.parse(canonical));

  const hashFor = async (args) => { const c = stub(); await collectTools().log_action({ content: "hello", asset_reference_id: "r", ...args }); return logBodies(c)[0].assetHash; };
  const seen = new Set([body.assetHash, sha("hello")]);
  for (const args of [{ action_type: "read", intent_type: "communicate" }, { action_type: "send", intent_type: "verify" }, { action_type: "send" }, { intent_type: "communicate" }]) {
    const h = await hashFor(args);
    assert.ok(!seen.has(h), JSON.stringify(args));
    seen.add(h);
  }
  assert.equal(await hashFor({ action_type: "send" }), sha(`{"v":1,"content_sha256":"${sha("hello")}","action_type":"send"}`), "absent label key is omitted");
});

test("labels with asset_hash: the envelope carries the lowercase inner hash and its hash_type", async () => {
  const upper = HEX.toUpperCase();
  const calls = stub();
  const res = await collectTools().log_action({ asset_hash: upper, hash_type: "SHA-256", asset_reference_id: "r", intent_type: "verify" });
  assert.ok(!res.isError, textOf(res));
  const canonical = `{"v":1,"asset_hash":"${HEX}","hash_type":"SHA-256","intent_type":"verify"}`;
  const [body] = logBodies(calls);
  assert.equal(body.assetHash, sha(canonical));
  assert.equal(body.hashType, "SHA-256");
  assert.equal(JSON.parse(textOf(res)).label_envelope.canonical_json, canonical);

  const c2 = stub();
  await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", intent_type: "recover" });
  assert.notEqual(logBodies(c2)[0].assetHash, body.assetHash);

  const c3 = stub();
  const sha512 = "cd".repeat(64);
  await collectTools().log_action({ asset_hash: sha512, hash_type: "SHA-512", asset_reference_id: "r", action_type: "read" });
  assert.equal(logBodies(c3)[0].assetHash, sha(`{"v":1,"asset_hash":"${sha512}","hash_type":"SHA-512","action_type":"read"}`));
  assert.equal(logBodies(c3)[0].hashType, "SHA-256", "the anchored hash is the envelope's SHA-256");
});

test("labels never reach the gateway as text: reference id and additional_info stay as passed", async () => {
  const calls = stub();
  await collectTools().log_action({
    content: "c", asset_reference_id: "ref-1", did: "did:x:1", additional_info: "plain note",
    action_type: "x-acme.refund", intent_type: "x-acme.chargeback", wait: false,
  });
  const [body] = logBodies(calls);
  assert.equal(body.assetReferenceId, "did:x:1:ref-1");
  assert.equal(body.additionalInfo, "plain note");
  const sent = calls.map((c) => c.url + JSON.stringify(c.body ?? "")).join("\n");
  for (const word of ["x-acme", "refund", "chargeback", "action_type", "intent_type", "content_sha256"]) assert.doesNotMatch(sent, new RegExp(word), word);
});

test("an invalid label is refused before any request and before the budget is spent", async () => {
  const prev = process.env.MCP_LOG_BUDGET;
  process.env.MCP_LOG_BUDGET = "1";
  __resetSharedLogBudget();
  __resetIdempotency();
  try {
    const tools = collectTools();
    for (const bad of [{ action_type: "purchase" }, { intent_type: "SEND" }, { action_type: "because I wanted to" }, { intent_type: "x-acme" }]) {
      const calls = stub();
      const res = await tools.log_action({ content: "c", asset_reference_id: "r", idempotency_key: "k-bad", ...bad });
      assert.equal(res.isError, true, JSON.stringify(bad));
      assert.match(textOf(res), /action_type|intent_type/);
      assert.equal(calls.length, 0, `no request for ${JSON.stringify(bad)}`);
    }
    // The single budgeted write is still available, and the refused key was not cached.
    const calls = stub();
    const good = await tools.log_action({ content: "c", asset_reference_id: "r", idempotency_key: "k-bad", action_type: "read" });
    assert.ok(!good.isError, textOf(good));
    assert.equal(logBodies(calls).length, 1);
    const replay = await tools.log_action({ content: "c", asset_reference_id: "r", idempotency_key: "k-bad", action_type: "read" });
    assert.equal(textOf(replay), textOf(good), "idempotent replay returns the original result");
    assert.equal(logBodies(calls).length, 1);
    const over = await tools.log_action({ content: "d", asset_reference_id: "r" });
    assert.match(textOf(over), /budget/i);
  } finally {
    if (prev === undefined) delete process.env.MCP_LOG_BUDGET;
    else process.env.MCP_LOG_BUDGET = prev;
    __resetSharedLogBudget();
    __resetIdempotency();
  }
});

test("custom x-<org>.<name> labels are accepted; secret-looking custom labels are refused", async () => {
  const calls = stub();
  const res = await collectTools().log_action({ content: "c", asset_reference_id: "r", action_type: "x-acme.refund", intent_type: "x-bigco.close_books" });
  assert.ok(!res.isError, textOf(res));
  assert.deepEqual(JSON.parse(textOf(res)).label_envelope.envelope, { v: 1, content_sha256: sha("c"), action_type: "x-acme.refund", intent_type: "x-bigco.close_books" });
  assert.equal(logBodies(calls).length, 1);

  for (const secret of [`x-acme.sk-${"a".repeat(30)}`, "x-acme.a1b2c3d4e5f6g7h8", "x-acme.k1234567"]) {
    const c = stub();
    const r = await collectTools().log_action({ content: "c", asset_reference_id: "r", action_type: secret });
    assert.equal(r.isError, true, secret);
    assert.equal(c.length, 0, secret);
    assert.doesNotMatch(textOf(r), new RegExp(secret.slice(7)), "the refusal does not echo the value");
  }
});

test("tool description and field help say labels are hashed, not written in plain text", () => {
  let config;
  registerTools({ registerTool: (name, c) => { if (name === "log_action") config = c; } }, cfg);
  const note = /Labels are hashed with the content and not written to Clockchain in plain text\./;
  assert.match(config.description, note);
  assert.match(config.inputSchema.action_type.description, note);
  assert.match(config.inputSchema.intent_type.description, note);
  assert.doesNotMatch(config.description, /\bmust\b.*(action_type|intent_type)|always (set|fill)/i);
});
