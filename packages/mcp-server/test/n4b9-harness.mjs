import { createServer } from "node:http";
import {
  generateKeyPairSync, createHash, sign as edSign, verify as edVerify,
} from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { CONTRACT_TOOL_DEFS } from "../dist/agent-contract/schemas.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

// N4b-9 (Increment 4) shared harness: test-only certificate minter, key set,
// service+HTTP boot, signed-submit helpers, fake anchor, and a faithful port
// of the sink's checkReceipt (the sink package lives on the n4c branch — not
// importable from this worktree). No network, test keys only.

export { canonicalJson, canonicalDigest };
export const ACCEPT = "application/json, text/event-stream";

// --- test-only certificate minter (same wire format as the business suite) --

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

export function mintCertificate({ root, session, sessionId }) {
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
    issuedAtMs: String(t),
    outcome: "VERIFIED",
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

export const rootKey = generateKeyPairSync("ed25519");
export const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);

const secpPriv = (n) => `0x${n.toString(16).padStart(64, "0")}`;
function pubFromPriv(privHex) {
  const dummy = Buffer.alloc(32, 1);
  const sig = eip191SignDigest32(dummy, privHex);
  return `0x${Buffer.from(eip191RecoverPublicKey(dummy, sig)).toString("hex")}`;
}
export const keys = {
  buyerSigner: { keyId: "signer-buyer", priv: secpPriv(0xb1) },
  buyerApproval: { keyId: "approval-buyer", priv: secpPriv(0xb2) },
  providerSigner: { keyId: "signer-provider", priv: secpPriv(0xc1) },
  providerApproval: { keyId: "approval-provider", priv: secpPriv(0xc2) },
  principal: { keyId: "principal", priv: secpPriv(0xd1) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);
export const PRINCIPAL_ADDRESS = publicKeyToAddress(Buffer.from(keys.principal.publicKeyHex.slice(2), "hex"));

export const POLICY_DIGEST = `0x${"7".repeat(64)}`;
export const POLICY = { buyer: POLICY_DIGEST, provider: POLICY_DIGEST };
export const PRINCIPALS = new Map(
  ["kb1", "kb2"].map((k) => [k, PRINCIPAL_ADDRESS]),
);

export const serverKeys = generateKeyPairSync("ed25519");
export const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };
export const serverPubKey = serverKeys.publicKey;

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
].join(",");
const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

export function signRoleSig(privHex, { runId, role, tool, nonce, payloadDigest }) {
  const digest = canonicalDigest({
    domain: "agent-contract.role-sig/v1", runId, role, tool, nonce, payloadDigest,
  });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

export function signMandateFields(mandate) {
  const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...mandate });
  return {
    mandate,
    mandateSignature: eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), keys.principal.priv),
  };
}

export function signMandate(overrides = {}) {
  return signMandateFields({
    kind: "mandate",
    mandateId: `mnd-${Math.floor(Math.random() * 1e9)}`,
    capMinor: 700_000,
    currency: "USD",
    allowedItineraryIds: ["IT-QW-ONESTOP", "IT-ROME-ZX118-ECON"],
    partySize: 2,
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    ...overrides,
  });
}

export function makeApproval({ envelope, role, action, tool, key, policyDigest = POLICY_DIGEST, decision = "allow" }) {
  const digest = computeApprovalDigest({
    runId: envelope.runId,
    tool,
    nonce: envelope.nonce,
    envelopeDigest: canonicalDigest(envelope),
    expiresAt: envelope.expiresAt,
  });
  const record = {
    role, action, digest, policyDigest,
    decision, ts: Date.now(), approverKeyId: key.keyId,
  };
  const sigDigest = computeApprovalSigDigest({ runId: envelope.runId, role, record });
  return { ...record, signature: eip191SignDigest32(Buffer.from(sigDigest.slice(2), "hex"), key.priv) };
}

// --- service + HTTP harness -------------------------------------------------

export async function boot(serviceOptions = {}) {
  const stateDir = serviceOptions.stateDir ?? mkdtempSync(path.join(tmpdir(), "n4b9-"));
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    stateDir,
    ...serviceOptions,
  });
  const handler = createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
  const sessions = new Map();
  // `sessionKey` (default: the token) selects the MCP session — O-3 tests
  // open several sessions under one bearer token.
  const callTool = async (token, name, args = {}, sessionKey = token) => {
    let sid = sessions.get(sessionKey);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(sessionKey, sid);
      await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  return {
    service, callTool, stateDir,
    sessionIdOf: (sessionKey) => sessions.get(sessionKey),
    close: () => { srv.close(); service.close(); },
  };
}

function bindArgs(certificate, role) {
  const signerKey = role === "buyer" ? keys.buyerSigner : keys.providerSigner;
  const approvalKey = role === "buyer" ? keys.buyerApproval : keys.providerApproval;
  return {
    certificate,
    signerKey: { keyId: signerKey.keyId, publicKeyHex: signerKey.publicKeyHex },
    approvalKey: { keyId: approvalKey.keyId, publicKeyHex: approvalKey.publicKeyHex },
  };
}

export async function bindPair(env, sessionId, buyerToken, providerToken) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  if (b.bound !== true) throw new Error(`buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool(providerToken, "contract_bind", bindArgs(cert, "provider"));
  if (p.bound !== true) throw new Error(`provider bind: ${JSON.stringify(p)}`);
  return b.runId;
}

export async function signedSubmit(env, { token, role, prepared, submitTool, extraArgs = {} }) {
  const e = prepared.envelope;
  const signatureHex = signRoleSig(keys[`${role}Signer`].priv, {
    runId: e.runId, role, tool: e.tool, nonce: e.nonce, payloadDigest: e.payloadDigest,
  });
  return env.callTool(token, submitTool, { envelope: e, signatureHex, ...extraArgs });
}

export function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

export async function agreePair(env, sessionId, buyerToken, providerToken, { itineraryId = "IT-QW-ONESTOP", feeMinor = 10_000, mandateOverrides = {} } = {}) {
  const runId = await bindPair(env, sessionId, buyerToken, providerToken);
  const prepM = await env.callTool(buyerToken, "mandate_prepare", signMandate(mandateOverrides));
  const m = await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  if (!/^0x[0-9a-f]{64}$/.test(m.mandateDigest ?? "")) throw new Error(JSON.stringify(m));
  const prepO = await env.callTool(buyerToken, "offer_prepare", { itineraryId, feeMinor });
  const offered = await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  if (offered.state !== "offered") throw new Error(JSON.stringify(offered));
  const prepA = await env.callTool(providerToken, "offer_accept_prepare", { offerId: offered.offerId });
  const accepted = await signedSubmit(env, { token: providerToken, role: "provider", prepared: prepA, submitTool: "offer_accept_submit" });
  if (accepted.agreementFormed !== true) throw new Error(JSON.stringify(accepted));
  return { runId, agreementId: accepted.agreementId };
}

export async function bookPair(env, sessionId, buyerToken, providerToken, opts = {}) {
  const { runId, agreementId } = await agreePair(env, sessionId, buyerToken, providerToken, opts);
  const prep = await env.callTool(providerToken, "booking_prepare", { agreementId });
  const approval = makeApproval({
    envelope: prep.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit(env, {
    token: providerToken, role: "provider", prepared: prep,
    submitTool: "booking_execute", extraArgs: { approval },
  });
  return { runId, agreementId, booked };
}

export async function waitFor(fn, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await new Promise((r) => setTimeout(r, 10));
  }
}

// --- fake anchor ------------------------------------------------------------

export function fakeAnchor({ pending = false, fail = false, confirmLedger = null } = {}) {
  const calls = [];
  const confirms = [];
  return {
    calls, confirms,
    async anchor({ kind, runId, digestHex }) {
      calls.push({ kind, runId, digestHex });
      if (fail) throw new Error("anchor substrate unreachable (fake)");
      const ledger = pending
        ? { ledgerId: "ledger-fake", blockHeight: null, time: null, status: "pending_confirmation" }
        : { ledgerId: "ledger-fake", blockHeight: "42", time: "2026-09-01T00:00:00Z", status: "anchored" };
      return {
        anchorId: `tsa:fake-${kind}-${digestHex.slice(2, 10)}`,
        eventHash: `0x${createHash("sha256").update(`${kind}|${digestHex}`).digest("hex")}`,
        anchor: ledger,
      };
    },
    async confirm(anchorId) {
      confirms.push(anchorId);
      return confirmLedger ?? { ledgerId: "ledger-fake", blockHeight: "43", time: "2026-09-01T00:00:30Z", status: "anchored" };
    },
  };
}

// --- faithful sink checkReceipt port ----------------------------------------
// Independent sorted-keys canonical JSON (not the emitter's module).

function sinkCanonicalJson(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "number": return JSON.stringify(v);
    case "boolean":
    case "string": return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return `[${v.map(sinkCanonicalJson).join(",")}]`;
      return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${sinkCanonicalJson(v[k])}`).join(",")}}`;
    }
    default: throw new Error("unrepresentable");
  }
}

export function sinkCheckReceipt(receipt, runId, publicKey) {
  const r = receipt;
  const s = r?.signature;
  return (
    r?.schema === "ac-terminal-receipt/v1" && r.runId === runId &&
    typeof r.terminalState === "string" && typeof r.ts === "string" &&
    s?.alg === "ed25519" && typeof s.keyId === "string" && /^0x[0-9a-f]{128}$/.test(s.sig ?? "") &&
    edVerify(null, Buffer.from(sinkCanonicalJson({
      schema: r.schema, runId: r.runId, terminalState: r.terminalState, ts: r.ts,
      alg: s.alg, keyId: s.keyId,
    }), "utf8"), publicKey, Buffer.from(s.sig.slice(2), "hex"))
  );
}

export const statusSchema = CONTRACT_TOOL_DEFS.find((d) => d.name === "contract_status").outputSchema;
