// CDT-SEC: fixes for the cdt-integration security review
// (state/ledger/notes/cdt-integration-security-review.md, M1-M5 and L1-L9).
// Each test fails on track-b/cdt-integration (4d8f3e1) and passes after its
// fix. Offline: loopback ports 19440-19459 only; every key is generated.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { buildServerCard } from "../dist/agent-contract/server-card.js";
import { toolsListForRole, guidanceDigests } from "../dist/agent-contract/tools-list.js";
import { eip191SignDigest32 } from "../dist/agent-contract/eip191.js";
import { policyRegistrationDigest } from "../dist/agent-contract/policy-registry.js";
import {
  ACCEPT, HOST_ROOTS, POLICY, boot, agreePair, bookPair, signedSubmit, makeApproval, fakeAnchor, waitFor, uuid, keys,
} from "./n4b9-harness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const B04059E = JSON.parse(readFileSync(path.join(here, "fixtures", "b04059e-tools-list.json"), "utf8"));

// --- loopback ports 19440-19459, rotating ---------------------------------------

let nextPort = 0;
async function listen(server) {
  for (let tries = 0; tries < 20; tries += 1) {
    const p = 19440 + (nextPort++ % 20);
    const ok = await new Promise((resolve) => {
      const onError = () => resolve(false);
      server.once("error", onError);
      server.listen(p, "127.0.0.1", () => { server.off("error", onError); resolve(true); });
    });
    if (ok) return `http://127.0.0.1:${p}`;
  }
  throw new Error("no free loopback port in 19440-19459");
}
const closeServer = (srv) => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tp1:provider:kp1:9453:responder",
].join(",");
const SERVER_SEED = Buffer.alloc(32, 7);

const POLICY_D = `0x${"5a".repeat(32)}`;
const inHours = (h) => new Date(Date.now() + h * 3600_000).toISOString();

/** A family-principal-signed buyer policy registration (harness principal key). */
function signPolicy({ tokenKeyId = "kb1", digest = POLICY_D, expiresAt = inHours(1), priv = keys.principal.priv } = {}) {
  const d = policyRegistrationDigest({ tokenKeyId, digest, expiresAt });
  return {
    role: "buyer", digest, expiresAt,
    principalSig: eip191SignDigest32(Buffer.from(d.slice(2), "hex"), priv),
  };
}

/** Books, verifies and tries to settle under an approval citing `policyDigest`. */
async function settleUnder(env, n, policyDigest) {
  const { booked } = await bookPair(env, uuid(n), "tb1", "tp1");
  const prepV = await env.callTool("tb1", "verification_prepare", {
    orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
  });
  await signedSubmit(env, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
  const prepS = await env.callTool("tb1", "settlement_prepare", {});
  const approval = makeApproval({
    envelope: prepS.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval, policyDigest,
  });
  return signedSubmit(env, {
    token: "tb1", role: "buyer", prepared: prepS, submitTool: "settlement_authorize", extraArgs: { approval },
  });
}

/** Production wiring: loadContractConfig (env) → the HTTP handler, over loopback. */
async function bootConfig(t, env = {}) {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS_RAW,
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED.toString("base64"),
    CONTRACT_SERVER_KEY_ID: "contract-server-sec",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-sec-")),
    ...env,
  });
  if (cfg.kind !== "ready") return { cfg };
  t.after(() => cfg.service.close());
  const srv = createServer(createContractHttpHandler({
    authenticate: cfg.authenticate, hostRoots: cfg.hostRoots, signer: cfg.signer, service: cfg.service,
    ...(cfg.telemetryLanes !== undefined ? { telemetryLanes: cfg.telemetryLanes } : {}),
  }));
  const baseUrl = `${await listen(srv)}/contract/mcp`;
  t.after(() => closeServer(srv));
  const sessions = new Map();
  let id = 1;
  const rpc = async (token, method, params) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "sec", version: "1" } } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(token, sid);
      await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: id++, method, params }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    return JSON.parse(data ? data.slice(5) : text);
  };
  const callTool = async (token, name, args = {}) => {
    const body = await rpc(token, "tools/call", { name, arguments: args });
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  const listTools = async (token) => (await rpc(token, "tools/list", {})).result;
  return { cfg, service: cfg.service, callTool, listTools };
}

// =============================================================================
// M5 — true default-off: with every new env unset the served surface and the
// behaviour are b04059e's.
// =============================================================================

test("M5: with every new env unset, tools/list and guidance digests equal b04059e's", async (t) => {
  assert.equal(B04059E.commit, "b04059e");
  assert.equal(B04059E.buyer.toolsList.tools.length, 21);
  assert.equal(B04059E.provider.toolsList.tools.length, 18);

  // Library level: the default role payloads are b04059e's, byte for byte.
  for (const role of ["buyer", "provider"]) {
    assert.deepEqual(toolsListForRole(role), B04059E[role].toolsList, `${role} tools/list`);
    assert.deepEqual(guidanceDigests(role), B04059E[role].guidance, `${role} guidance digests`);
  }

  // Wire level: production config with no new env serves exactly that.
  const env = await bootConfig(t);
  assert.equal(env.cfg.kind, "ready", JSON.stringify(env.cfg));
  assert.deepEqual(env.service.features, {});
  assert.equal(env.service.serverAnchors, false);
  const buyerList = await env.listTools("tb1");
  const providerList = await env.listTools("tp1");
  assert.deepEqual(buyerList, B04059E.buyer.toolsList);
  assert.deepEqual(providerList, B04059E.provider.toolsList);
  assert.equal(canonicalDigest(buyerList), B04059E.buyer.guidance.toolsListDigest);
  assert.equal(canonicalDigest(providerList), B04059E.provider.guidance.toolsListDigest);
  const card = buildServerCard([], { features: env.service.features });
  assert.deepEqual(card.guidance.buyer, B04059E.buyer.guidance);
  assert.deepEqual(card.guidance.provider, B04059E.provider.guidance);

  // The gated tools answer NOT_FOUND like any unknown name; their new fields
  // are unknown keys (invalid params) exactly as at b04059e.
  const reg = await env.callTool("tb1", "contract_register_policy", {
    role: "buyer", digest: `0x${"5a".repeat(32)}`, expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    principalSig: `0x${"11".repeat(65)}`,
  });
  assert.equal(reg.error, "NOT_FOUND", JSON.stringify(reg));
  assert.equal((await env.callTool("tb1", "contract_get_brief", { name: "family-travel" })).error, "NOT_FOUND");
  assert.equal((await env.callTool("tp1", "rendezvous_ack", { messageIds: ["msg-0001"] })).error, "NOT_FOUND");
  assert.equal((await env.callTool("tp1", "telemetry_open", {})).error, "NOT_FOUND");
  const waited = await env.callTool("tp1", "rendezvous_inbox", { waitMs: 10 });
  assert.equal(waited.rpcError?.code, -32602, JSON.stringify(waited));
  const named = await env.callTool("tb1", "rendezvous_search", { origin: "SFO", destination: "FCO", name: "roma-travel" });
  assert.equal(named.rpcError?.code, -32602, JSON.stringify(named));
  const listing = await env.callTool("tp1", "rendezvous_publish_listing", {
    title: "Roma", summary: "Rome trips", sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`, directoryName: "roma-travel",
  });
  assert.equal(listing.rpcError?.code, -32602, JSON.stringify(listing));
});

test("M5: each feature appears only with its own env; a malformed switch is a startup error", async (t) => {
  const reg = await bootConfig(t, { CONTRACT_POLICY_REGISTRATION: "1" });
  assert.deepEqual(reg.service.features, { policyRegistration: true });
  const buyerList = await reg.listTools("tb1");
  assert.deepEqual(buyerList, toolsListForRole("buyer", { policyRegistration: true }));
  assert.ok(buyerList.tools.some((x) => x.name === "contract_register_policy"));
  assert.ok(!buyerList.tools.some((x) => x.name === "contract_get_brief"));
  // The provider surface is untouched by a buyer-only feature.
  assert.deepEqual(await reg.listTools("tp1"), B04059E.provider.toolsList);
  assert.equal(canonicalDigest(buyerList), guidanceDigests("buyer", reg.service.features).toolsListDigest);
  assert.notEqual(canonicalDigest(buyerList), B04059E.buyer.guidance.toolsListDigest);

  const bad = await bootConfig(t, { CONTRACT_POLICY_REGISTRATION: "yes" });
  assert.equal(bad.cfg.kind, "misconfigured");
  const badAnchors = await bootConfig(t, { CONTRACT_SERVER_ANCHORS: "true" });
  assert.equal(badAnchors.cfg.kind, "misconfigured");
});

test("M5: without CONTRACT_SERVER_ANCHORS an anchoring server fires only the b04059e anchors", async () => {
  const anchor = fakeAnchor();
  const env = await boot({ anchor });
  try {
    const { runId } = await agreePair(env, uuid(1501), "tb1", "tp1");
    await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "anchored");
    const st = await env.callTool("tb1", "contract_status", {});
    assert.deepEqual(Object.keys(st.anchors).sort(), ["agreement", "terminal"], JSON.stringify(st.anchors));
    assert.deepEqual([...new Set(anchor.calls.map((c) => c.kind))], ["agreement"]);
  } finally { env.close(); }

  const on = await boot({ anchor: fakeAnchor(), serverAnchors: true });
  try {
    const { runId } = await agreePair(on, uuid(1502), "tb1", "tp1");
    await waitFor(() => on.service.runFor(runId)?.anchors?.terms?.status === "anchored");
    const st = await on.callTool("tb1", "contract_status", {});
    assert.equal(st.anchors.terms.status, "anchored");
  } finally { on.close(); }
});

test("M5: with CONTRACT_POLICY_REGISTRATION off, persisted registrations authorize nothing", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-sec-m5-reg-"));
  const on = await boot({ stateDir, policyRegistration: true });
  try {
    assert.equal(on.service.registerPolicy({ keyId: "kb1" }, signPolicy()).ok, true);
  } finally { on.close(); }

  const off = await boot({ stateDir });
  try {
    assert.equal(off.service.registerPolicy({ keyId: "kb1" }, signPolicy({ digest: `0x${"5b".repeat(32)}` })).ok, false);
    const refused = await settleUnder(off, 1503, POLICY_D);
    assert.notEqual(refused.status, "released", JSON.stringify(refused));
    assert.ok(refused.error, JSON.stringify(refused));
  } finally { off.close(); }

  const again = await boot({ stateDir, policyRegistration: true });
  try {
    const settled = await settleUnder(again, 1504, POLICY_D);
    assert.equal(settled.status, "released", JSON.stringify(settled));
  } finally { again.close(); }
});
