import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { canonicalJson, canonicalDigest, saltedCanonicalDigest } from "../dist/agent-contract/canonical.js";

// Local copy of the amount-field scan so the suite fails per-assertion, not at import.
const AMOUNT_KEY = /^(?:.*_)?(?:cap|price|fare|amount|fee|total|cost)(?:minor|usd|cents|decimal)?$/i;
function containsAmountField(v) {
  if (v === null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some(containsAmountField);
  return Object.keys(v).some((k) => AMOUNT_KEY.test(k) || containsAmountField(v[k]));
}
import { verifyChain, RECEIPT_CHAIN_GENESIS, makeReceipt } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { buildContractServer } from "../dist/agent-contract/server.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { eip191SignDigest32, eip191RecoverPublicKey } from "../dist/agent-contract/eip191.js";

const ACCEPT = "application/json, text/event-stream";

// N4b-3 changes-1 (docs/agent-contract/N4B3-CHANGES-1.md): receipts must be
// built+validated BEFORE dispatch; the pre-bind chain is SEGMENTED so polling
// can't lock a principal out; sessions are capped and swept; amount-bearing
// responses get a salted responseDigest; the LOWs (verifier≠observer token,
// pinned key-validity windows enforced by verifyChain, per-segment salts).

// --- test-only certificate minter (same wire format as the bind suite) -------

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

const rootKey = generateKeyPairSync("ed25519");
const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);

function mintCertificate({ root, session, sessionId }) {
  const t = Date.now();
  const sessionKeyAddress = `0x${createHash("sha256").update(session.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 40)}`;
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test",
    sessionId,
    repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs: String(t - 60_000),
    validUntilMs: String(t + 10 * 60_000),
  };
  const hostSessionKeyCertificate = {
    certificate,
    rootSignature: {
      algorithm: "ed25519",
      keyId: "root-test",
      publicKey: rawPublicKeyBase64(root.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(certificate), "utf8"), root.privateKey).toString("base64"),
    },
  };
  const party = (addr, agentId, n) => ({
    sessionKeyAddress: addr,
    policyDigest: `${n === 0 ? "a" : "b"}${"0".repeat(63)}`,
    erc8004: {
      agentId,
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`,
      registrationBlock: `700${n}`,
    },
  });
  const initiator = party(sessionKeyAddress, "9452", 0);
  const responder = party(`0x${"9".repeat(40)}`, "9453", 1);
  const anchor = (kind, n) => ({ blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`, digest: `${n}${"0".repeat(63)}`, kind, ledgerId: `33333333-4444-4555-8666-77777777777${n}` });
  const result = {
    anchors: [anchor("proposal", 0), anchor("acceptance", 1), anchor("acknowledgment", 2)],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: canonicalDigest(hostSessionKeyCertificate).slice(2),
    identityPolicy: {
      chainId: "eip155:11155111", erc8004: "required_fresh",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    },
    issuedAtMs: String(t), outcome: "VERIFIED",
    parties: { initiator, responder },
    policyDigests: { initiator: initiator.policyDigest, responder: responder.policyDigest },
    reference: "NS-1847", schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "e".repeat(64), sessionId,
    statementDigest: "f".repeat(64), subjectRun: "stakeholder",
  };
  return {
    hostSessionKeyCertificate, result,
    signer: {
      algorithm: "ed25519", keyId: "session-host",
      publicKey: rawPublicKeyBase64(session.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(result), "utf8"), session.privateKey).toString("base64"),
    },
  };
}

const secpPriv = (n) => `0x${n.toString(16).padStart(64, "0")}`;
function pubFromPriv(privHex) {
  const dummy = Buffer.alloc(32, 1);
  const sig = eip191SignDigest32(dummy, privHex);
  return `0x${Buffer.from(eip191RecoverPublicKey(dummy, sig)).toString("hex")}`;
}
const keys = {
  buyerSigner: { keyId: "signer-buyer", priv: secpPriv(0xb1) },
  buyerApproval: { keyId: "approval-buyer", priv: secpPriv(0xb2) },
  providerSigner: { keyId: "signer-provider", priv: secpPriv(0xc1) },
  providerApproval: { keyId: "approval-provider", priv: secpPriv(0xc2) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);

const POLICY_DIGESTS = Object.freeze({ buyer: `0x${"7".repeat(64)}`, provider: `0x${"8".repeat(64)}` });
const PRINCIPALS = Object.freeze(new Map(
  Array.from({ length: 12 }, (_, i) => [`kb${i + 1}`, "0x" + "a".repeat(40)]),
));

const TOKENS_RAW = [
  ...Array.from({ length: 12 }, (_, i) => `tb${i + 1}:buyer:kb${i + 1}:9452:initiator`),
  ...Array.from({ length: 12 }, (_, i) => `tp${i + 1}:provider:kp${i + 1}:9453:responder`),
].join(",");
const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };
const SERVER_PUBKEYS = { [SIGNER.keyId]: serverKeys.publicKey };

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

function bindArgs(certificate, role, extra = {}) {
  const signerKey = role === "buyer" ? keys.buyerSigner : keys.providerSigner;
  const approvalKey = role === "buyer" ? keys.buyerApproval : keys.providerApproval;
  return {
    certificate,
    signerKey: { keyId: signerKey.keyId, publicKeyHex: signerKey.publicKeyHex },
    approvalKey: { keyId: approvalKey.keyId, publicKeyHex: approvalKey.publicKeyHex },
    ...extra,
  };
}

// --- HTTP harness --------------------------------------------------------------

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b3c1-"));
let http;
let baseUrl;
let service;

test.before(async () => {
  service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    stateDir,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  http = createServer(handler);
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${http.address().port}`;
});

test.after(() => new Promise((resolve) => http.close(resolve)));

const sessions = new Map();
const CLIENT_INFO = { name: "n4b3c1-test-client", version: "1.0.0" };

async function ensureSession(token) {
  if (sessions.has(token)) return sessions.get(token);
  const headers = { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` };
  const response = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST", headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id: 0, method: "initialize",
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO },
    }),
  });
  assert.ok(response.status < 300, `initialize: ${response.status}`);
  const sid = response.headers.get("mcp-session-id");
  sessions.set(token, sid);
  if (sid !== null) {
    await fetch(`${baseUrl}/contract/mcp`, {
      method: "POST",
      headers: { ...headers, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
  }
  return sid;
}

async function rpc(method, params = {}, token = "tb1", { session = true } = {}) {
  if (session) await ensureSession(token);
  const headers = { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` };
  const sid = sessions.get(token);
  if (sid) headers["mcp-session-id"] = sid;
  const response = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST", headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(data ? data.slice(5) : text);
  return { status: response.status, body };
}

async function callTool(token, name, args = {}) {
  const r = await rpc("tools/call", { name, arguments: args }, token);
  if (r.body.error !== undefined) return { rpcError: r.body.error };
  return r.body.result?.structuredContent ?? {};
}

// === HIGH-1: receipts first, for every cause ===================================

test("CH1: an empty or oversized clientInfo is refused at initialize", async () => {
  const bad = [
    { name: "", version: "" },            // the probe's repro
    { name: "", version: "1.0.0" },
    { name: "ok", version: "" },
    { name: "x".repeat(200), version: "1" },   // oversized
    { name: "ok", version: "v".repeat(100) },  // oversized
  ];
  for (const clientInfo of bad) {
    const response = await fetch(`${baseUrl}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb1" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo },
      }),
    });
    assert.equal(response.status, 400, `clientInfo ${JSON.stringify(clientInfo)} must be refused`);
    assert.equal(response.headers.get("mcp-session-id"), null, "no session is issued");
    const body = await response.json();
    assert.equal(body.error.code, -32602);
    // Nothing session-bound can now run: a follow-up call has no session.
    const call = await rpc("tools/call", { name: "contract_status", arguments: {} }, "tb9", { session: false });
    assert.equal(call.status, 400);
  }
});

test("CH1: a receipt that cannot be built refuses the call BEFORE dispatch — no state change", async () => {
  // A poisoned session ctx can no longer arrive over HTTP (initialize
  // refuses), but the structural guarantee is that the RECEIPT is built and
  // schema-validated before any business dispatch. Prove it directly on the
  // MCP server path with a poisoned ctx via the in-memory transport.
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const principal = { keyId: "kp-poison", role: "provider", agentId: "9453", side: "responder" };
  const server = buildContractServer({
    principal,
    service: localService,
    session: { id: "sess-poisoned", clientInfo: { name: "", version: "" }, sourceIp: "10.0.0.9" },
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "probe", version: "0" });
  await server.connect(serverSide);
  await client.connect(clientSide);
  try {
    const res = await client.callTool({ name: "rendezvous_publish_listing", arguments: {
      title: "poison", summary: "x", sealedBoxPublicKeyHex: `0x${"aa".repeat(32)}`,
    } });
    const sc = res.structuredContent;
    // The consequential action NEVER ran — refused with a generic code +
    // serverNonce, no zod detail, and nothing was published.
    assert.equal(res.isError, true);
    assert.equal(sc.error, "CONTRACT_UNAVAILABLE");
    assert.match(sc.serverNonce, /^0x[0-9a-f]{32}$/);
    assert.ok(!("zod" in sc) && !("issues" in sc), "no zod text leaks to the agent");
  } finally {
    await client.close();
    await server.close();
  }
  // Nothing stateful happened: a clean buyer's search still shows no listing.
  const clean = buildContractServer({
    principal: { keyId: "kb-clean", role: "buyer", agentId: "9452", side: "initiator" },
    service: localService,
  });
  const [cs, ss] = InMemoryTransport.createLinkedPair();
  const c2 = new Client({ name: "probe", version: "0" });
  await clean.connect(ss);
  await c2.connect(cs);
  try {
    const res = await c2.callTool({ name: "rendezvous_search", arguments: { origin: "LON", destination: "PAR" } });
    assert.equal(res.structuredContent.listings.length, 0);
  } finally {
    await c2.close();
    await clean.close();
  }
  localService.close();
});

test("CH1: the service-level receipt preflight refuses bad evidence before any mutation", () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const principal = { keyId: "kb-check", role: "buyer", agentId: "9452", side: "initiator" };
  const fields = {
    tool: "rendezvous_search",
    argsDigest: canonicalDigest({}),
    argsDigestScheme: "canonical",
    serverNonce: `0x${"ab".repeat(16)}`,
  };
  const good = localService.checkReceiptEvidence(undefined, principal, fields);
  assert.equal(good.ok, true);
  const bad = localService.checkReceiptEvidence(undefined, principal, {
    ...fields, clientInfo: { name: "", version: "" },
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "CONTRACT_UNAVAILABLE");
  localService.close();
});

// === HIGH-2: pre-bind chain segments + independent poll limiter ================

test("CH2: pre-bind receipts roll into segments — the cap never locks out and every segment verifies", () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const principal = { keyId: "kb-segments", role: "buyer", agentId: "9452", side: "initiator" };
  const fields = (i) => ({
    tool: "contract_status",
    argsDigest: canonicalDigest({ i }),
    argsDigestScheme: "canonical",
    outcome: "ok",
    responseDigest: canonicalDigest({ stage: "rendezvous", i }),
    serverNonce: `0x${String(i).padStart(32, "0")}`,
  });
  // 600 receipts cross the 256 segment boundary twice — the OLD code refused
  // at 256; segments must keep appending.
  for (let i = 0; i < 600; i++) {
    const r = localService.recordPreBind(principal, fields(i));
    assert.equal(r.ok, true, `recordPreBind ${i}: ${JSON.stringify(r)}`);
  }
  const feed = localService.preBindFeed("kb-segments");
  assert.ok(feed !== undefined);
  assert.ok(feed.segments.length >= 3, `expected ≥3 segments, got ${feed.segments.length}`);
  // Every segment is an internally-chained signed chain anchored at the
  // carried-forward head of the previous segment.
  for (const [i, seg] of feed.segments.entries()) {
    assert.ok(seg.receipts.length > 0);
    assert.equal(seg.receipts[0].prevHash, seg.anchor, `segment ${i} anchor`);
    const verdict = verifyChain(seg.receipts, SERVER_PUBKEYS, { firstPrevHash: seg.anchor });
    assert.equal(verdict.ok, true, `segment ${i} verify: ${JSON.stringify(verdict)}`);
    if (i > 0) {
      assert.equal(seg.anchor, canonicalDigest(feed.segments[i - 1].receipts.at(-1)),
        `segment ${i} must anchor on segment ${i - 1}'s head`);
    }
  }
  // The flattened feed is the concatenation of segments and the reported head
  // is the last receipt's digest.
  assert.equal(feed.receipts.length, feed.segments.reduce((n, s) => n + s.receipts.length, 0));
  assert.equal(feed.head, canonicalDigest(feed.receipts.at(-1)));
  localService.close();
});

test("CH2: each bind seals the current pre-bind segment — new calls start a fresh, salt-rotated segment", async () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const principal = { keyId: "kb-seal", role: "buyer", agentId: "9452", side: "initiator" };
  const rec = (i) => localService.recordPreBind(principal, {
    tool: "contract_status",
    argsDigest: canonicalDigest({ i }),
    argsDigestScheme: "canonical",
    outcome: "ok",
    responseDigest: canonicalDigest({ i }),
    serverNonce: `0x${String(i).padStart(32, "0")}`,
  });
  rec(1);
  const saltA = localService.saltFor({ keyId: "kb-seal" });
  // A bind seals the active segment — simulate via the service hook.
  localService.sealPreBindSegment("kb-seal");
  rec(2);
  rec(3);
  const saltB = localService.saltFor({ keyId: "kb-seal" });
  const feed = localService.preBindFeed("kb-seal");
  assert.equal(feed.segments.length, 2);
  // LOW: the salt rotates with each segment; older segment salts stay
  // disclosed for verification of their own receipts only.
  assert.notEqual(saltA.salt, saltB.salt);
  assert.ok(Array.isArray(saltB.salts) && saltB.salts.length === 2);
  assert.equal(saltB.salts[0], saltA.salt);
  assert.equal(saltB.salts[1], saltB.salt);
  // Segment 2's first receipt links to segment 1's head.
  assert.equal(feed.segments[1].anchor, canonicalDigest(feed.segments[0].receipts.at(-1)));
  localService.close();
});

test("CH2: old segments roll off by count — the retained feed stays internally verifiable", () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    preBindSegmentMax: 4,
    preBindMaxSegments: 3,
  });
  const principal = { keyId: "kb-rolled", role: "buyer", agentId: "9452", side: "initiator" };
  for (let i = 0; i < 30; i++) {
    const r = localService.recordPreBind(principal, {
      tool: "contract_status",
      argsDigest: canonicalDigest({ i }),
      argsDigestScheme: "canonical",
      outcome: "ok",
      responseDigest: canonicalDigest({ i }),
      serverNonce: `0x${String(i).padStart(32, "0")}`,
    });
    assert.equal(r.ok, true);
  }
  const feed = localService.preBindFeed("kb-rolled");
  assert.equal(feed.segments.length, 3, "only the newest 3 segments are retained");
  assert.ok(feed.truncated === true || feed.segments[0].anchor !== RECEIPT_CHAIN_GENESIS,
    "the oldest retained segment must advertise that it anchors on dropped evidence");
  for (const seg of feed.segments) {
    const verdict = verifyChain(seg.receipts, SERVER_PUBKEYS, { firstPrevHash: seg.anchor });
    assert.equal(verdict.ok, true, JSON.stringify(verdict));
  }
  localService.close();
});

test("CH2: polling is rate-limited by its own limiter — never the evidence cap", async () => {
  // A provider polls the inbox for deliveries; at the OLD cap of 256 those
  // polls permanently locked the principal out. Now a poll limiter applies
  // (configurable; here 5/min) and exhausted polls refuse politely — while
  // genuine calls keep working and the chains still verify.
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: localService,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    pollsPerMinute: 5,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  try {
    const headers = { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tp9" };
    const init = await fetch(`${url}/contract/mcp`, {
      method: "POST", headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
    });
    const sid = init.headers.get("mcp-session-id");
    const call = async (name, args = {}) => {
      const res = await fetch(`${url}/contract/mcp`, {
        method: "POST", headers: { ...headers, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
          params: { name, arguments: args } }),
      });
      const text = await res.text();
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text).result?.structuredContent ?? {};
    };
    // 5 inbox polls allowed; the 6th is the limiter — RATE_LIMITED.
    for (let i = 0; i < 5; i++) {
      const out = await call("rendezvous_inbox");
      assert.equal(out.error, undefined, `poll ${i}: ${JSON.stringify(out)}`);
    }
    const limited = await call("rendezvous_inbox");
    assert.equal(limited.error, "RATE_LIMITED");
    assert.match(limited.serverNonce, /^0x[0-9a-f]{32}$/);
    // And a NON-poll call still proceeds — the limiter never blocks work.
    const pub = await call("rendezvous_publish_listing", {
      title: "post-poll listing", summary: "proves non-poll calls still run",
      sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
    });
    assert.ok(pub.listingId !== undefined, JSON.stringify(pub));
  } finally {
    await new Promise((r) => srv.close(r));
    localService.close();
  }
});

// === MED: session caps + sweep ================================================

test("CH3: the 5th session for one principal is refused; a closed session frees the slot", async () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: localService,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const init = async (token) => {
    const res = await fetch(`${url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
    });
    return { status: res.status, sid: res.headers.get("mcp-session-id") };
  };
  try {
    const ids = [];
    for (let i = 0; i < 4; i++) {
      const r = await init("tb10");
      assert.equal(r.status, 200, `session ${i}: ${r.status}`);
      assert.ok(r.sid);
      ids.push(r.sid);
    }
    const fifth = await init("tb10");
    assert.equal(fifth.status, 429, "the per-principal cap refuses the 5th session");
    // A different principal is unaffected.
    const other = await init("tp10");
    assert.equal(other.status, 200);
    // Closing one (DELETE) frees the slot.
    const del = await fetch(`${url}/contract/mcp`, {
      method: "DELETE",
      headers: { authorization: "Bearer tb10", "mcp-session-id": ids[0], accept: ACCEPT },
    });
    assert.ok(del.status < 300, `DELETE: ${del.status}`);
    const after = await init("tb10");
    assert.equal(after.status, 200, "a freed slot is reusable");
  } finally {
    await new Promise((r) => srv.close(r));
    localService.close();
  }
});

test("CH3: idle sessions are swept and free their slots; a global cap bounds the total", async () => {
  let t = 1_000_000;
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    now: () => t,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: localService,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    now: () => t,
    sessionTtlMs: 5 * 60_000,
    maxSessionsPerPrincipal: 4,
    maxSessions: 6,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const init = async (token) => {
    const res = await fetch(`${url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
    });
    return res.status;
  };
  try {
    // Global cap 6: fill it with 4 of one principal + 2 of another.
    for (let i = 0; i < 4; i++) assert.equal(await init("tb11"), 200);
    assert.equal(await init("tp11"), 200);
    assert.equal(await init("tp11"), 200);
    assert.equal(await init("tp12"), 429, "the global cap refuses the 7th");
    // Time advances past the TTL: the next request sweeps the idle sessions
    // and the slot is free again.
    t += 10 * 60_000;
    assert.equal(await init("tp12"), 200, "swept sessions free capacity");
  } finally {
    await new Promise((r) => srv.close(r));
    localService.close();
  }
});

// === MED: salted amount-bearing response digests ==============================

test("CH4: amount-bearing responses carry a salted responseDigest the observer can't brute-force", async () => {
  const localService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: localService,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const localSessions = new Map();
  const localRpc = async (token, name, args = {}) => {
    let sid = localSessions.get(token);
    if (!sid) {
      const init = await fetch(`${url}/contract/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
      });
      sid = init.headers.get("mcp-session-id");
      localSessions.set(token, sid);
      await fetch(`${url}/contract/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(`${url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    return body.result?.structuredContent ?? {};
  };
  try {
    // Bind a buyer+provider pair so a run exists, then drive an amount-bearing call.
    const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(500) });
    const b = await localRpc("tb2", "contract_bind", bindArgs(cert, "buyer"));
    assert.equal(b.bound, true, JSON.stringify(b));
    const p = await localRpc("tp2", "contract_bind", bindArgs(cert, "provider"));
    assert.equal(p.bound, true, JSON.stringify(p));
    const runId = b.runId;
    // A provider offer needs no mandate and its response carries fare/fee/totalMinor.
    const offer = await localRpc("tp2", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
    assert.equal(offer.error, undefined, JSON.stringify(offer));
    assert.ok(containsAmountField(offer), "the response carries an amount (totalMinor)");

    const feed = localService.receiptFeed(runId);
    const receipt = feed.receipts.find((r) => r.tool === "offer_prepare" && r.principal.keyId === "kp2");
    assert.ok(receipt, "the offer_prepare receipt exists");
    assert.equal(receipt.responseDigestScheme, "hmac-sha256");
    // The disclosed salt reconstructs it; the plain canonical digest can't.
    const salt = localService.saltFor({ runId });
    assert.equal(salt.salt !== undefined, true);
    assert.equal(receipt.responseDigest, saltedCanonicalDigest(salt.salt, offer));
    assert.notEqual(receipt.responseDigest, canonicalDigest(offer),
      "without the salt the agreed amount can't be brute-forced off the feed");
    // The observer feed must not carry the salt.
    assert.equal(JSON.stringify(feed).includes(salt.salt), false);
  } finally {
    await new Promise((r) => srv.close(r));
    localService.close();
  }
});

// === LOWs =====================================================================

test("LOW: CONTRACT_VERIFIER_TOKEN equal to CONTRACT_OBSERVER_TOKEN is misconfigured", () => {
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tok:buyer:k1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"),
    CONTRACT_POLICY_DIGESTS: `buyer:0x${"1".repeat(64)},provider:0x${"2".repeat(64)}`,
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_OBSERVER_TOKEN: "same-token",
    CONTRACT_VERIFIER_TOKEN: "same-token",
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-same-")),
  };
  const cfg = loadContractConfig(env);
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /verifier|observer/i);
});

test("LOW: a seeded server key REQUIRES a pinned validity window — never boot time", () => {
  const base = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tok:buyer:k1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"),
    CONTRACT_POLICY_DIGESTS: `buyer:0x${"1".repeat(64)},provider:0x${"2".repeat(64)}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-keywin-")),
  };
  const missing = loadContractConfig(base);
  assert.equal(missing.kind, "misconfigured");
  assert.match(missing.reason, /VALID_FROM/i);
  const pinned = loadContractConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-keywin2-")),
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_SERVER_KEY_VALID_UNTIL: "2027-03-01T00:00:00.000Z",
  });
  assert.equal(pinned.kind, "ready");
  assert.equal(pinned.serverKeys[0].validFrom, "2026-09-01T00:00:00.000Z");
  assert.equal(pinned.serverKeys[0].validUntil, "2027-03-01T00:00:00.000Z");
});

test("LOW: verifyChain enforces the published key's validity window", () => {
  const receipt = makeReceipt(null, {
    runId: "r1", tool: "contract_status", argsDigest: canonicalDigest({}),
    principal: { role: "buyer", keyId: "k1" }, outcome: "ok",
    responseDigest: canonicalDigest({ ok: true }), ts: 1_700_000_000_000,
  }, SIGNER);
  const inWindow = {
    [SIGNER.keyId]: { validFromMs: 1_699_000_000_000, validUntilMs: 1_800_000_000_000 },
  };
  assert.equal(verifyChain([receipt], SERVER_PUBKEYS, { keyWindows: inWindow }).ok, true);
  const tooEarly = {
    [SIGNER.keyId]: { validFromMs: 1_800_000_000_000, validUntilMs: null },
  };
  const v1 = verifyChain([receipt], SERVER_PUBKEYS, { keyWindows: tooEarly });
  assert.equal(v1.ok, false);
  assert.equal(v1.code, "KEY_WINDOW");
  const expired = {
    [SIGNER.keyId]: { validFromMs: null, validUntilMs: 1_600_000_000_000 },
  };
  const v2 = verifyChain([receipt], SERVER_PUBKEYS, { keyWindows: expired });
  assert.equal(v2.ok, false);
  assert.equal(v2.code, "KEY_WINDOW");
});
