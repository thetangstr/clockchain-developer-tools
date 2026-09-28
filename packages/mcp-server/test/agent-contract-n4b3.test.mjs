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
