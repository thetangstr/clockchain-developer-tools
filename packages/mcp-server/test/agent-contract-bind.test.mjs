import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { toolsListForRole, CONTRACT_SERVER_INSTRUCTIONS, guidanceDigests } from "../dist/agent-contract/tools-list.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { verifyCertificateEnvelope } from "../dist/agent-contract/certificate.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const ACCEPT = "application/json, text/event-stream";

// --- test-only certificate minter ------------------------------------------
// Reproduces the agent-handshake-v2 certificate envelope wire format
// (clockchain.host-session-key/v1 + agent-handshake-result/v2 + session-key
// signature) with freshly generated ed25519 keys — no real keys anywhere.

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64"); // strip 12-byte SPKI prefix
}

function mintCertificate({ root, session, sessionId, outcome = "VERIFIED", issuedAtMs = "1786337200000", validFromMs = "1786337000000", validUntilMs = "1786337600000" }) {
  const sessionKeyAddress = `0x${createHash("sha256").update(session.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 40)}`;
  const counterKeyAddress = `0x${"9".repeat(40)}`;
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test",
    sessionId,
    repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs,
    validUntilMs,
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
  const party = (sessionAddress, agentId, policyDigest, regBlock) => ({
    sessionKeyAddress: sessionAddress,
    policyDigest,
    erc8004: {
      agentId,
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`,
      registrationBlock: regBlock,
    },
  });
  const initiator = party(sessionKeyAddress, "9452", "a".repeat(64), "7000");
  const responder = party(counterKeyAddress, "9453", "b".repeat(64), "7001");
  const identityPolicy = {
    chainId: "eip155:11155111",
    erc8004: "required_fresh",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  };
  const anchor = (kind, n) => ({ blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`, digest: `${n}${"0".repeat(63)}`, kind, ledgerId: `33333333-4444-4555-8666-77777777777${n}` });
  const result = {
    anchors: [anchor("proposal", 0), anchor("acceptance", 1), anchor("acknowledgment", 2)],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: canonicalDigest(hostSessionKeyCertificate).slice(2),
    identityPolicy,
    issuedAtMs,
    outcome,
    parties: { initiator, responder },
    policyDigests: { initiator: initiator.policyDigest, responder: responder.policyDigest },
    reference: "NS-1847",
    schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "e".repeat(64),
    sessionId,
    statementDigest: "f".repeat(64),
    subjectRun: "stakeholder",
  };
  return {
    hostSessionKeyCertificate,
    result,
    signer: {
      algorithm: "ed25519",
      keyId: "session-host",
      publicKey: rawPublicKeyBase64(session.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(result), "utf8"), session.privateKey).toString("base64"),
    },
  };
}

const rootA = generateKeyPairSync("ed25519");
const rootB = generateKeyPairSync("ed25519");
const sessionA = generateKeyPairSync("ed25519");
const sessionB = generateKeyPairSync("ed25519");
const SESSION_A = "aaaaaaaa-1111-4444-8888-aaaaaaaaaaaa";
const SESSION_B = "bbbbbbbb-2222-4444-8888-bbbbbbbbbbbb";

const certA = mintCertificate({ root: rootA, session: sessionA, sessionId: SESSION_A });
const certB = mintCertificate({ root: rootA, session: sessionB, sessionId: SESSION_B });

const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootA.publicKey), "base64")).digest("hex") },
]);

// --- HTTP harness ------------------------------------------------------------

const TOKENS = {
  "tok-buyer-1": { keyId: "buyer-key-1", role: "buyer" },
  "tok-buyer-2": { keyId: "buyer-key-2", role: "buyer" },
  "tok-buyer-3": { keyId: "buyer-key-3", role: "buyer" },
  "tok-provider-1": { keyId: "provider-key-1", role: "provider" },
  "tok-provider-2": { keyId: "provider-key-2", role: "provider" },
};

const serverKeys = generateKeyPairSync("ed25519");
const serverPublicB64 = rawPublicKeyBase64(serverKeys.publicKey);

let http;
let baseUrl;
let service;

function authenticate(headers) {
  const raw = /^Bearer\s+(.+)$/i.exec(
    (Array.isArray(headers.authorization) ? headers.authorization[0] : headers.authorization) ?? "",
  );
  const token = raw?.[1]?.trim() ?? "";
  return TOKENS[token] ?? null;
}

test.before(async () => {
  service = createContractService({
    hostRoots: HOST_ROOTS,
    signer: { keyId: "contract-server-test", privateKey: serverKeys.privateKey },
  });
  const handler = createContractHttpHandler({
    authenticate,
    hostRoots: HOST_ROOTS,
    signer: { keyId: "contract-server-test", privateKey: serverKeys.privateKey },
    service,
  });
  http = createServer(handler);
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${http.address().port}/contract/mcp`;
});

test.after(() => new Promise((resolve) => http.close(resolve)));

async function rpc(method, params = {}, token = "tok-buyer-1", url = baseUrl) {
  const headers = { "content-type": "application/json", accept: ACCEPT };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((line) => line.startsWith("data:"));
  return { status: response.status, body: JSON.parse(data ? data.slice(5) : text) };
}

async function call(tool, args = {}, token = "tok-buyer-1") {
  const { body } = await rpc("tools/call", { name: tool, arguments: args }, token);
  const result = body.result;
  if (result === undefined) return { error: body.error, json: undefined };
  return { isError: result.isError === true, json: JSON.parse(result.content[0].text) };
}

const bindArgs = (cert, suffix = "") => ({
  certificate: cert,
  signerKey: { keyId: `signer${suffix}`, publicKeyHex: `0x${"11".repeat(32)}` },
  approvalKey: { keyId: `approval${suffix}`, publicKeyHex: `0x${"22".repeat(32)}` },
});

// --- auth --------------------------------------------------------------------

test("parseContractTokens maps bearer tokens to role-scoped principals", () => {
  const parsed = parseContractTokens(" tok-a : buyer : k-buyer , tok-b:provider:k-prov ");
  assert.deepEqual(parsed, {
    "tok-a": { role: "buyer", keyId: "k-buyer" },
    "tok-b": { role: "provider", keyId: "k-prov" },
  });
  assert.deepEqual(parseContractTokens(""), {});
  assert.deepEqual(parseContractTokens(undefined), {});
  assert.throws(() => parseContractTokens("tok-x:viewer:k"), /role/);
  assert.throws(() => parseContractTokens("bad-entry"), /token/);
});

test("the route requires a role-scoped bearer token", async () => {
  assert.equal((await rpc("tools/list", {}, null)).status, 401);
  assert.equal((await rpc("tools/list", {}, "tok-nobody")).status, 401);
  assert.equal((await rpc("tools/list")).status, 200);
});

// --- tools/list --------------------------------------------------------------

test("tools/list serves the verbatim N4a role payload, matching guidanceDigests", async () => {
  const buyer = await rpc("tools/list", {}, "tok-buyer-1");
  const provider = await rpc("tools/list", {}, "tok-provider-1");
  assert.deepEqual(buyer.body.result, toolsListForRole("buyer"));
  assert.deepEqual(provider.body.result, toolsListForRole("provider"));
  const names = (r) => r.body.result.tools.map((t) => t.name);
  assert.ok(names(buyer).includes("rendezvous_search"));
  assert.ok(!names(buyer).includes("rendezvous_publish_listing"));
  assert.ok(names(provider).includes("rendezvous_publish_listing"));
  assert.ok(!names(provider).includes("rendezvous_search"));
  assert.ok(names(buyer).includes("contract_bind") && names(provider).includes("contract_bind"));
  assert.equal(
    canonicalDigest(buyer.body.result),
    guidanceDigests("buyer").toolsListDigest,
  );
});

test("initialize returns the published server instructions", async () => {
  const { body } = await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "test-client", version: "0.0.0" },
  });
  assert.equal(body.result.instructions, CONTRACT_SERVER_INSTRUCTIONS);
});

// --- contract_bind -----------------------------------------------------------

test("both roles bind the same verified certificate; status advances to bound", async () => {
  const buyer = await call("contract_bind", bindArgs(certA), "tok-buyer-1");
  assert.equal(buyer.json.bound, true);
  assert.equal(buyer.json.role, "buyer");
  assert.equal(buyer.json.runId, SESSION_A);
  assert.match(buyer.json.serverNonce, /^0x[0-9a-f]{32}$/);

  const mid = await call("contract_status", {}, "tok-buyer-1");
  assert.equal(mid.json.stage, "handshake");

  const provider = await call("contract_bind", bindArgs(certA, "-p"), "tok-provider-1");
  assert.equal(provider.json.bound, true);
  assert.equal(provider.json.role, "provider");
  assert.equal(provider.json.runId, SESSION_A);

  for (const token of ["tok-buyer-1", "tok-provider-1"]) {
    const status = await call("contract_status", {}, token);
    assert.equal(status.json.stage, "bound");
    assert.equal(status.json.terminalState, null);
  }
});

test("contract_bind refuses certificates that fail verification", async () => {
  // Untrusted root
  const certOtherRoot = mintCertificate({ root: rootB, session: generateKeyPairSync("ed25519"), sessionId: "cccccccc-3333-4444-8888-cccccccccccc" });
  const a = await call("contract_bind", bindArgs(certOtherRoot), "tok-buyer-2");
  assert.equal(a.isError, true);
  assert.equal(a.json.error, "CERTIFICATE_INVALID");

  // Tampered result (signature no longer covers it)
  const tampered = JSON.parse(JSON.stringify(certA));
  tampered.result.outcome = "FAILED";
  const b = await call("contract_bind", bindArgs(tampered), "tok-buyer-2");
  assert.equal(b.json.error, "CERTIFICATE_INVALID");

  // Signer key not the certified session key
  const wrongSigner = JSON.parse(JSON.stringify(certA));
  wrongSigner.signer.publicKey = rawPublicKeyBase64(generateKeyPairSync("ed25519").publicKey);
  const c = await call("contract_bind", bindArgs(wrongSigner), "tok-buyer-2");
  assert.equal(c.json.error, "CERTIFICATE_INVALID");

  // Garbage
  const d = await call("contract_bind", bindArgs({ not: "a certificate" }), "tok-buyer-2");
  assert.equal(d.json.error, "CERTIFICATE_INVALID");
});

test("a second role must bind the SAME certificate digest", async () => {
  const ok = await call("contract_bind", bindArgs(certB, "-b2"), "tok-buyer-2");
  assert.equal(ok.json.bound, true);
  // Same sessionId but a different envelope digest is a substitution attempt.
  const forgedB = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: SESSION_B });
  assert.notEqual(canonicalDigest(forgedB), canonicalDigest(certB));
  const foreign = await call("contract_bind", bindArgs(forgedB, "-p2"), "tok-provider-2");
  assert.equal(foreign.json.error, "CERTIFICATE_INVALID");
  // A cert for a genuinely different session starts a different run — legal.
  const certC = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "cccccccc-5555-4444-8888-cccccccccccc" });
  const otherRun = await call("contract_bind", bindArgs(certC, "-p2"), "tok-provider-2");
  assert.equal(otherRun.json.bound, true);
});

test("rebinding rules: idempotent for the same principal, refused otherwise", async () => {
  const again = await call("contract_bind", bindArgs(certA), "tok-buyer-1");
  assert.equal(again.json.bound, true);
  // Same certificate, different keys → refused.
  const drifted = await call("contract_bind", bindArgs(certA, "-drift"), "tok-buyer-1");
  assert.equal(drifted.json.error, "STATE_REFUSED");
  // A different certificate for the same principal → refused.
  const foreign = await call("contract_bind", bindArgs(certB), "tok-buyer-1");
  assert.equal(foreign.json.error, "STATE_REFUSED");
  // The buyer role on run A is already claimed by buyer-key-1.
  const steal = await call("contract_bind", bindArgs(certA, "-steal"), "tok-buyer-3");
  assert.equal(steal.json.error, "ROLE_REFUSED");
});

test("role scoping on tools/call; unimplemented tools refuse cleanly", async () => {
  const wrongRole = await call("rendezvous_publish_listing", {
    title: "x", summary: "y", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
  }, "tok-buyer-1");
  assert.equal(wrongRole.isError, true);
  assert.equal(wrongRole.json.error, "ROLE_REFUSED");

  const unimplemented = await call("mandate_prepare", { mandate: {} }, "tok-buyer-1");
  assert.equal(unimplemented.json.error, "CONTRACT_UNAVAILABLE");

  const unknown = await call("nonsense_tool", {}, "tok-buyer-1");
  assert.equal(unknown.json.error, "NOT_FOUND");
});

test("malformed call arguments fail as JSON-RPC invalid params, not a refusal", async () => {
  const { body } = await rpc("tools/call", { name: "contract_bind", arguments: { certificate: {} } });
  assert.ok(body.error, "expected a JSON-RPC error");
  assert.equal(body.error.code, -32602);
});

test("an unbound caller reports the rendezvous stage", async () => {
  // tok-buyer-3 never bound (its certA attempt was ROLE_REFUSED).
  const status = await call("contract_status", {}, "tok-buyer-3");
  assert.equal(status.json.stage, "rendezvous");
  assert.equal(status.json.terminalState, null);
  assert.match(status.json.serverNonce, /^0x[0-9a-f]{32}$/);
});

test("every bound call appends a verifiable receipt to the run chain", async () => {
  const run = service.runFor("aaaaaaaa-1111-4444-8888-aaaaaaaaaaaa");
  assert.ok(run);
  assert.ok(run.receipts.length >= 3, `expected >=3 receipts, got ${run.receipts.length}`);
  const verdict = verifyChain(run.receipts, { "contract-server-test": serverKeys.publicKey });
  assert.equal(verdict.ok, true, `chain verdict: ${JSON.stringify(verdict)}`);
  // Every receipt names its tool + principal and carries the echoed serverNonce.
  const bind = run.receipts.find((r) => r.tool === "contract_bind" && r.principal.keyId === "buyer-key-1");
  assert.ok(bind);
  assert.equal(bind.outcome, "ok");
});

// --- pure certificate verifier ----------------------------------------------

test("verifyCertificateEnvelope accepts the canonical fixture with its root pinned", () => {
  const fixture = JSON.parse(readFileSync(path.join(FIXTURES, "agent-handshake-v2-canonical.json"), "utf8"));
  const envelope = fixture.objects.certificateEnvelope;
  const rootPub = envelope.hostSessionKeyCertificate.rootSignature.publicKey;
  const fp = createHash("sha256").update(Buffer.from(rootPub, "base64")).digest("hex");
  const verdict = verifyCertificateEnvelope(envelope, {
    hostRoots: [{ kid: "root-2026-08", fingerprint: fp }],
  });
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
  assert.equal(verdict.sessionId, "22222222-3333-4444-8555-666666666666");
  assert.equal(verdict.certificateDigest, canonicalDigest(envelope));
});
