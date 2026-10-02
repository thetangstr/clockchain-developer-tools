import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain, RECEIPT_CHAIN_GENESIS } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { eip191SignDigest32, eip191RecoverPublicKey } from "../dist/agent-contract/eip191.js";

const ACCEPT = "application/json, text/event-stream";

// N4b-3 (N4B3-BRIEF): P-hardening — M1 pre-bind receipt chains linked at bind,
// M2 stateful MCP sessions on receipts, M3 published signing keys, salted
// argsDigest for cap-bearing calls, and the LOW rendezvous items.

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

const V2_SEAL = {
  v: 2,
  epk: `0x${"ab".repeat(32)}`,
  iv: `0x${"cd".repeat(12)}`,
  ct: `0x${"ef".repeat(48)}`,
  tag: `0x${"01".repeat(16)}`,
};

const TOKENS_RAW = [
  ...Array.from({ length: 12 }, (_, i) => `tb${i + 1}:buyer:kb${i + 1}:9452:initiator`),
  ...Array.from({ length: 12 }, (_, i) => `tp${i + 1}:provider:kp${i + 1}:9453:responder`),
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b3-"));
let http;
let baseUrl;
let service;

const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

test.before(async () => {
  service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    stateDir,
    allowLegacySealV2: true, // test posture = CONTRACT_LEVEL=L
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

// One MCP session per token: initialize once, then carry `mcp-session-id`
// when the transport is stateful. Under the stateless transport the header
// is simply absent and everything still works.
const sessions = new Map();
const CLIENT_INFO = { name: "n4b3-test-client", version: "1.2.3" };

async function ensureSession(token) {
  if (sessions.has(token)) return;
  const headers = { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` };
  const response = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST", headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id: 0, method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: CLIENT_INFO,
      },
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

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

const SERVER_PUBKEYS = { [SIGNER.keyId]: serverKeys.publicKey };

// === M1: pre-bind receipt chains ==============================================

test("M1: unbound rendezvous/status calls land on a signed, hash-chained pre-bind chain", async () => {
  const s = await callTool("tb1", "rendezvous_search", { origin: "ZRH", destination: "JFK" });
  assert.match(s.serverNonce, /^0x[0-9a-f]{32}$/, JSON.stringify(s));
  const st = await callTool("tb1", "contract_status", {});
  assert.equal(st.stage, "rendezvous");

  const feed = service.preBindFeed("kb1");
  assert.ok(feed !== undefined && feed.receipts.length >= 2, "pre-bind chain exists");
  const tools = feed.receipts.map((r) => r.tool);
  assert.deepEqual(tools.slice(0, 2), ["rendezvous_search", "contract_status"]);
  assert.equal(feed.receipts[0].serverNonce, s.serverNonce, "receipt carries the call's nonce");
  assert.equal(feed.receipts[0].prevHash, RECEIPT_CHAIN_GENESIS);
  assert.equal(feed.head, canonicalDigest(feed.receipts.at(-1)));

  const verdict = verifyChain(feed.receipts, SERVER_PUBKEYS);
  assert.equal(verdict.ok, true, JSON.stringify(verdict));

  // Tamper with a link and the chain breaks.
  const tampered = feed.receipts.map((r) => ({ ...r }));
  tampered[1].argsDigest = `0x${"f".repeat(64)}`;
  const bad = verifyChain(tampered, SERVER_PUBKEYS);
  assert.equal(bad.ok, false);
});

test("M1: each side's bind receipt carries that principal's preBindHead; the observer feed serves both chains", async () => {
  // Both parties rendezvous first so each has a distinct pre-bind head.
  const pub = await callTool("tp2", "rendezvous_publish_listing", {
    title: "bind-link listing", summary: "x", sealedBoxPublicKeyHex: `0x${"33".repeat(32)}`,
  });
  await callTool("tb2", "rendezvous_send_invitation", { listingId: pub.listingId, sealedInvitation: V2_SEAL });
  const buyerHead = service.preBindFeed("kb2").head;
  const providerHead = service.preBindFeed("kp2").head;
  assert.notEqual(buyerHead, providerHead);

  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(301) });
  const b = await callTool("tb2", "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, JSON.stringify(b));
  const p = await callTool("tp2", "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, JSON.stringify(p));

  const feed = service.receiptFeed(b.runId);
  const byTool = feed.receipts.filter((r) => r.tool === "contract_bind");
  assert.equal(byTool.length, 2);
  const buyerBind = byTool.find((r) => r.principal.keyId === "kb2");
  const providerBind = byTool.find((r) => r.principal.keyId === "kp2");
  assert.equal(buyerBind.preBindHead, buyerHead, "run genesis links the buyer's pre-bind head");
  assert.equal(providerBind.preBindHead, providerHead, "provider bind links its pre-bind head");

  // The feed serves both chains.
  assert.ok(Array.isArray(feed.preBind), "feed carries preBind chains");
  const feeds = Object.fromEntries(feed.preBind.map((c) => [c.principalKeyId, c]));
  assert.equal(feeds.kb2.head, buyerHead);
  assert.equal(feeds.kp2.head, providerHead);
  assert.equal(verifyChain(feed.receipts, SERVER_PUBKEYS).ok, true);
  assert.equal(verifyChain(feeds.kb2.receipts, SERVER_PUBKEYS).ok, true);
});

test("M1: a refused bind is receipted on the principal's pre-bind chain", async () => {
  const before = service.preBindFeed("kb3")?.receipts.length ?? 0;
  const r = await callTool("tb3", "contract_bind", bindArgs({ garbage: true }, "buyer"));
  assert.ok(r.error !== undefined || r.rpcError !== undefined, JSON.stringify(r));
  const feed = service.preBindFeed("kb3");
  assert.ok(feed.receipts.length > before, "refusal appended to the pre-bind chain");
  const last = feed.receipts.at(-1);
  assert.equal(last.tool, "contract_bind");
  assert.notEqual(last.outcome, "ok");
  assert.equal(verifyChain(feed.receipts, SERVER_PUBKEYS).ok, true);
});

// === M2: stateful MCP sessions =================================================

test("M2: receipts carry the MCP session id and the initialize clientInfo", async () => {
  const s = await callTool("tb4", "contract_status", {});
  assert.equal(s.stage, "rendezvous");
  const sessionId = sessions.get("tb4");
  assert.ok(typeof sessionId === "string" && sessionId.length > 0, "stateful session negotiated");
  const receipt = service.preBindFeed("kb4")?.receipts.at(-1);
  assert.equal(receipt.tool, "contract_status");
  assert.equal(receipt.mcpSessionId, sessionId, "receipt carries mcpSessionId");
  assert.deepEqual(receipt.clientInfo, CLIENT_INFO, "receipt carries clientInfo");
});

test("M2: a non-initialize request without a session is refused per the MCP spec", async () => {
  // tools/call with NO mcp-session-id → 400
  const noSession = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb4" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "contract_status", arguments: {} } }),
  });
  assert.equal(noSession.status, 400, await noSession.text());

  // …and a BOGUS session id → 404
  const bogus = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json", accept: ACCEPT,
      authorization: "Bearer tb4", "mcp-session-id": "deadbeef-dead-beef-dead-beefdeadbeef",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "contract_status", arguments: {} } }),
  });
  assert.equal(bogus.status, 404, await bogus.text());
});

test("M2: a session is bound to its principal — a different token on it is refused", async () => {
  await ensureSession("tb5");
  const sid = sessions.get("tb5");
  const r = await fetch(`${baseUrl}/contract/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json", accept: ACCEPT,
      authorization: "Bearer tp5", "mcp-session-id": sid,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "contract_status", arguments: {} } }),
  });
  assert.ok(r.status === 401 || r.status === 403, `expected 401/403, got ${r.status}`);
});

test("M2: session TTL — an idle session expires; DELETE terminates it", async () => {
  // Dedicated handler with a tiny TTL and an injectable clock.
  let nowMs = Date.now();
  const ttlService = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const h2 = createServer(createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: ttlService,
    sessionTtlMs: 500, now: () => nowMs,
  }));
  await new Promise((r) => h2.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${h2.address().port}/contract/mcp`;
  try {
    const init = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb6" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO },
      }),
    });
    assert.ok(init.status < 300, `initialize: ${init.status}`);
    const sid = init.headers.get("mcp-session-id");
    assert.ok(sid, "session id issued");

    const call = (headers = {}) => fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json", accept: ACCEPT,
        authorization: "Bearer tb6", "mcp-session-id": sid, ...headers,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "contract_status", arguments: {} } }),
    });
    assert.equal((await call()).status, 200, "live session serves");

    // Idle past the TTL → the session is gone.
    nowMs += 5_000;
    assert.equal((await call()).status, 404, "expired session is refused");

    // Fresh session → DELETE terminates it → subsequent calls 404.
    const init2 = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb6" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO },
      }),
    });
    const sid2 = init2.headers.get("mcp-session-id");
    const del = await fetch(url, {
      method: "DELETE",
      headers: { authorization: "Bearer tb6", "mcp-session-id": sid2, accept: ACCEPT },
    });
    assert.ok(del.status < 300, `DELETE: ${del.status}`);
    assert.equal((await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json", accept: ACCEPT,
        authorization: "Bearer tb6", "mcp-session-id": sid2,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "contract_status", arguments: {} } }),
    })).status, 404);
  } finally {
    await new Promise((r) => h2.close(r));
    ttlService.close();
  }
});

// === LOWs ===================================================================

import { publicKeyToAddress } from "../dist/agent-contract/eip191.js";
import { writeFileSync } from "node:fs";

const PRINCIPAL_PRIV = secpPriv(0xd5);
const PRINCIPAL_ADDRESS = publicKeyToAddress(
  Buffer.from(pubFromPriv(PRINCIPAL_PRIV).slice(2), "hex"),
);

function signMandate(privHex, mandate) {
  const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...mandate });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

test("LOW: inbox deliveries carry the sender's agentId; a bind consumes ONLY that listing", async () => {
  // kp6 and kp7 each publish a listing (a provider holds ONE live listing —
  // a newer publish supersedes the old one); two buyers each deliver to one.
  const l1 = await callTool("tp6", "rendezvous_publish_listing", {
    title: "Listing One", summary: "s", sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`,
  });
  const l2 = await callTool("tp7", "rendezvous_publish_listing", {
    title: "Listing Two", summary: "s", sealedBoxPublicKeyHex: `0x${"22".repeat(32)}`,
  });
  const d1 = await callTool("tb8", "rendezvous_send_invitation", { listingId: l1.listingId, sealedInvitation: V2_SEAL });
  assert.equal(d1.delivered, true, JSON.stringify(d1));
  const d2 = await callTool("tb9", "rendezvous_send_invitation", { listingId: l2.listingId, sealedInvitation: V2_SEAL });
  assert.equal(d2.delivered, true, JSON.stringify(d2));

  // Inbox messages name the sender's keyId AND its token-pinned agentId.
  const inbox = await callTool("tp6", "rendezvous_inbox", {});
  const m1 = inbox.messages.find((m) => m.listingId === l1.listingId);
  assert.equal(m1.senderKeyId, "kb8");
  assert.equal(m1.senderAgentId, "9452", "inbox message carries the sender's agentId");

  // The provider binds the handshake that came through l1 — ONLY l1 is
  // consumed; l2 still accepts deliveries.
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(601) });
  const bind = await callTool("tp6", "contract_bind", bindArgs(cert, "provider", { listingId: l1.listingId }));
  assert.equal(bind.bound, true, JSON.stringify(bind));

  const late1 = await callTool("tb10", "rendezvous_send_invitation", { listingId: l1.listingId, sealedInvitation: V2_SEAL });
  assert.equal(late1.error, "LISTING_UNAVAILABLE");
  const ok2 = await callTool("tb10", "rendezvous_send_invitation", { listingId: l2.listingId, sealedInvitation: V2_SEAL });
  assert.equal(ok2.delivered, true, "unconsumed listing still accepts deliveries");
});

test("LOW: a provider bind naming a listing it does not own is refused", async () => {
  const l = await callTool("tp8", "rendezvous_publish_listing", {
    title: "Mine Only", summary: "s", sealedBoxPublicKeyHex: `0x${"33".repeat(32)}`,
  });
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(602) });
  // tp9 does NOT own l.listingId — the bind must refuse, not consume.
  const bind = await callTool("tp9", "contract_bind", bindArgs(cert, "provider", { listingId: l.listingId }));
  assert.equal(bind.error, "LISTING_UNAVAILABLE", JSON.stringify(bind));
  // …and the foreign listing was NOT consumed by the refused bind.
  const still = await callTool("tb11", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: V2_SEAL });
  assert.equal(still.delivered, true);
});

test("LOW: used-mandates prunes entries past expiresAt + grace; live and legacy entries survive", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-mandate-prune-"));
  const principals = new Map([["kb1", PRINCIPAL_ADDRESS], ["kb2", PRINCIPAL_ADDRESS]]);
  const key = (mid) => `${PRINCIPAL_ADDRESS.toLowerCase()}:${mid}`;
  // Seed the ledger directly: one expired (expired > grace ago), one live,
  // one LEGACY string entry (no expiry — kept forever, fail closed).
  writeFileSync(path.join(dir, "used-mandates.json"), JSON.stringify({
    mandates: {
      [key("mdt-expired")]: { runId: "r-old", expiresAt: new Date(Date.now() - 48 * 3600_000).toISOString() },
      [key("mdt-live")]: { runId: "r-new", expiresAt: new Date(Date.now() + 3600_000).toISOString() },
      [key("mdt-legacy")]: "r-legacy",
    },
  }));
  const svc = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals, stateDir: dir,
    graceMs: 600_000,
  });
  const h = createServer(createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc }));
  await new Promise((r) => h.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${h.address().port}`;
  try {
    // Per-token sessions — M2 binds a session to the principal that
    // initialized it, so tp1's calls can't ride tb1's session.
    const localSessions = new Map();
    const localRpc = async (method, params = {}, token = "tb1") => {
      if (!localSessions.has(token)) {
        const init = await fetch(`${url}/contract/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
          body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
        });
        localSessions.set(token, init.headers.get("mcp-session-id"));
      }
      const r = await fetch(`${url}/contract/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": localSessions.get(token) },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await r.text();
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text);
    };
    const call = async (token, name, args) => (await localRpc("tools/call", { name, arguments: args }, token)).result?.structuredContent ?? {};
    const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(603) });
    const bb = await call("tb1", "contract_bind", bindArgs(cert, "buyer"));
    assert.equal(bb.bound, true, JSON.stringify(bb));
    const pb = await call("tp1", "contract_bind", bindArgs(cert, "provider"));
    assert.equal(pb.bound, true, JSON.stringify(pb));

    const submitMandate = async (token, mandateId) => {
      const mandate = { kind: "mandate", mandateId, capMinor: 1_000, currency: "USD", partySize: 2, allowedItineraryIds: ["IT-QW-ONESTOP"], expiresAt: "2030-01-01T00:00:00.000Z" };
      const prep = await call(token, "mandate_prepare", {
        mandate, mandateSignature: signMandate(PRINCIPAL_PRIV, mandate),
      });
      assert.ok(prep.envelope, `prepare ${mandateId}: ${JSON.stringify(prep)}`);
      const roleSig = eip191SignDigest32(Buffer.from(canonicalDigest({
        domain: "agent-contract.role-sig/v1", runId: prep.envelope.runId, role: "buyer",
        tool: prep.envelope.tool, nonce: prep.envelope.nonce, payloadDigest: prep.envelope.payloadDigest,
      }).slice(2), "hex"), keys.buyerSigner.priv);
      return call(token, "mandate_submit", { envelope: prep.envelope, signatureHex: roleSig });
    };

    // mdt-expired was PRUNED at load — the id is free again, so a correctly
    // signed submit SUCCEEDS (it claims the id under the new run).
    const expiredReuse = await submitMandate("tb1", "mdt-expired");
    assert.match(expiredReuse.mandateDigest ?? "", /^0x[0-9a-f]{64}$/, `pruned id reusable: ${JSON.stringify(expiredReuse)}`);

    // A second run (kb2 is pinned to the SAME principal address): the live
    // entry still refuses its mandateId, and the legacy string entry (no
    // expiry — never pruned, fail closed) refuses too.
    const cert2 = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(604) });
    const bb2 = await call("tb2", "contract_bind", bindArgs(cert2, "buyer"));
    assert.equal(bb2.bound, true, JSON.stringify(bb2));
    const pb2 = await call("tp2", "contract_bind", bindArgs(cert2, "provider"));
    assert.equal(pb2.bound, true, JSON.stringify(pb2));

    const live = await submitMandate("tb2", "mdt-live");
    assert.equal(live.error, "MANDATE_INVALID", JSON.stringify(live));
    const legacySubmit = await submitMandate("tb2", "mdt-legacy");
    assert.equal(legacySubmit.error, "MANDATE_INVALID", JSON.stringify(legacySubmit));
  } finally {
    await new Promise((r) => h.close(r));
    svc.close();
  }
});
// -- Live run p6-l-2026-10-01-8: stale listings across runs --------------------
// The server keeps listings in memory across runs; each run's provider signer
// has a FRESH seal key, so the deterministic listing id (keyId + title + seal
// key) changes per run. Search used to return every earlier run's listing too,
// and the buyer sealed to an OLD key the provider could no longer open.

test("rendezvous: a new publish from the same provider keyId SUPERSEDES its previous listing(s)", async () => {
  const oldL = await callTool("tp10", "rendezvous_publish_listing", {
    title: "Stale Run Listing", summary: "run 7", sealedBoxPublicKeyHex: `0x${"a1".repeat(32)}`,
    terms: { origin: "OPO", destination: "MAD" },
  });
  // A buyer delivered to the old listing before the provider republished.
  const pre = await callTool("tb12", "rendezvous_send_invitation", { listingId: oldL.listingId, sealedInvitation: V2_SEAL });
  assert.equal(pre.delivered, true, JSON.stringify(pre));
  // Next run: same provider keyId, same title, FRESH seal key → new listing id.
  const newL = await callTool("tp10", "rendezvous_publish_listing", {
    title: "Stale Run Listing", summary: "run 8", sealedBoxPublicKeyHex: `0x${"b2".repeat(32)}`,
    terms: { origin: "OPO", destination: "MAD" },
  });
  assert.notEqual(newL.listingId, oldL.listingId);

  // Search returns ONLY the latest listing for this provider, with publishedAt.
  // (Earlier tests' term-less listings match any route — look at ours only.)
  const s = await callTool("tb12", "rendezvous_search", { origin: "OPO", destination: "MAD" });
  const mine = s.listings.filter((l) => l.title === "Stale Run Listing");
  assert.deepEqual(mine.map((l) => l.listingId), [newL.listingId], JSON.stringify(s));
  assert.equal(mine[0].sealedBoxPublicKeyHex, `0x${"b2".repeat(32)}`);
  assert.equal(mine[0].publishedAt, newL.publishedAt, "search exposes publishedAt");
  assert.ok(s.listings.every((l) => typeof l.publishedAt === "string"));

  // A late invitation to the superseded listing is refused clearly — never
  // silently delivered to a seal key the provider no longer holds.
  const late = await callTool("tb12", "rendezvous_send_invitation", { listingId: oldL.listingId, sealedInvitation: V2_SEAL });
  assert.equal(late.error, "LISTING_UNAVAILABLE", JSON.stringify(late));
  // The pending delivery sealed to the old key is dropped from the inbox.
  const inbox = await callTool("tp10", "rendezvous_inbox", {});
  assert.equal(inbox.messages.filter((m) => m.listingId === oldL.listingId).length, 0, JSON.stringify(inbox));
  // The provider can no longer bind through the superseded listing.
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(611) });
  const bind = await callTool("tp10", "contract_bind", bindArgs(cert, "provider", { listingId: oldL.listingId }));
  assert.equal(bind.error, "LISTING_UNAVAILABLE", JSON.stringify(bind));
  // The new listing accepts deliveries.
  const fresh = await callTool("tb12", "rendezvous_send_invitation", { listingId: newL.listingId, sealedInvitation: V2_SEAL });
  assert.equal(fresh.delivered, true, JSON.stringify(fresh));
});

test("rendezvous: supersession is per provider — another provider's listing is untouched", async () => {
  const a = await callTool("tp11", "rendezvous_publish_listing", {
    title: "Provider Eleven", summary: "s", sealedBoxPublicKeyHex: `0x${"c3".repeat(32)}`,
    terms: { origin: "BCN", destination: "LIS" },
  });
  const b1 = await callTool("tp12", "rendezvous_publish_listing", {
    title: "Provider Twelve", summary: "s", sealedBoxPublicKeyHex: `0x${"d4".repeat(32)}`,
    terms: { origin: "BCN", destination: "LIS" },
  });
  const b2 = await callTool("tp12", "rendezvous_publish_listing", {
    title: "Provider Twelve", summary: "s", sealedBoxPublicKeyHex: `0x${"e5".repeat(32)}`,
    terms: { origin: "BCN", destination: "LIS" },
  });
  const s = await callTool("tb12", "rendezvous_search", { origin: "BCN", destination: "LIS" });
  const ids = s.listings.filter((l) => l.title.startsWith("Provider ")).map((l) => l.listingId).sort();
  assert.deepEqual(ids, [a.listingId, b2.listingId].sort(), JSON.stringify(s));
  assert.ok(!ids.includes(b1.listingId));
  // Republishing the SAME listing (same id) is a refresh, not a supersession.
  const again = await callTool("tp11", "rendezvous_publish_listing", {
    title: "Provider Eleven", summary: "s", sealedBoxPublicKeyHex: `0x${"c3".repeat(32)}`,
  });
  assert.equal(again.listingId, a.listingId);
  assert.equal(again.publishedAt, a.publishedAt);
  const s2 = await callTool("tb12", "rendezvous_search", { origin: "BCN", destination: "LIS" });
  assert.ok(s2.listings.some((l) => l.listingId === a.listingId));
});
