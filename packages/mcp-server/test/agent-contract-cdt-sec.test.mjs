// CDT-SEC: fixes for the cdt-integration security review
// (state/ledger/notes/cdt-integration-security-review.md, M1-M5 and L1-L9).
// Each test fails on track-b/cdt-integration (4d8f3e1) and passes after its
// fix. Offline: loopback ports 19440-19459 only; every key is generated.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { buildServerCard } from "../dist/agent-contract/server-card.js";
import { toolsListForRole, guidanceDigests } from "../dist/agent-contract/tools-list.js";
import { eip191RecoverPublicKey, eip191SignDigest32, publicKeyToAddress } from "../dist/agent-contract/eip191.js";
import { createPolicyRegistry, policyRegistrationDigest } from "../dist/agent-contract/policy-registry.js";
import { parseContractBriefs } from "../dist/agent-contract/server-anchors.js";
import {
  ACCEPT, HOST_ROOTS, POLICY, SIGNER, PRINCIPAL_ADDRESS, boot, agreePair, bookPair, signedSubmit, makeApproval,
  fakeAnchor, waitFor, uuid, keys,
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
function signPolicy({
  tokenKeyId = "kb1", digest = POLICY_D, expiresAt = inHours(1), priv = keys.principal.priv,
  audience = SIGNER.keyId, chainId = null,
} = {}) {
  const d = policyRegistrationDigest({ audience, chainId, tokenKeyId, digest, expiresAt });
  return {
    role: "buyer", digest, expiresAt,
    principalSig: eip191SignDigest32(Buffer.from(d.slice(2), "hex"), priv),
  };
}

/** Books, verifies and tries to settle under an approval citing `policyDigest`. */
async function settleUnder(env, n, policyDigest, buyerToken = "tb1") {
  const { booked } = await bookPair(env, uuid(n), buyerToken, "tp1");
  const prepV = await env.callTool(buyerToken, "verification_prepare", {
    orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"dd".repeat(32)}`,
  });
  await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepV, submitTool: "verification_submit" });
  const prepS = await env.callTool(buyerToken, "settlement_prepare", {});
  const approval = makeApproval({
    envelope: prepS.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval, policyDigest,
  });
  return signedSubmit(env, {
    token: buyerToken, role: "buyer", prepared: prepS, submitTool: "settlement_authorize", extraArgs: { approval },
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

// =============================================================================
// M1 — registrations approve on (keyId, digest) only; per-keyId cap; reloaded
// entries are re-checked against the CURRENT principal pins.
// =============================================================================

const digestN = (i) => `0x${i.toString(16).padStart(64, "0")}`;

test("M1: a registration for kb1 does not authorize kb2's settlement, even under the same principal", async () => {
  const env = await boot({ policyRegistration: true });
  try {
    const reg = await env.callTool("tb1", "contract_register_policy", signPolicy({ tokenKeyId: "kb1" }));
    assert.equal(reg.registered, true, JSON.stringify(reg));
    // kb1's own run settles (and frees the provider for the next run)…
    const own = await settleUnder(env, 1601, POLICY_D, "tb1");
    assert.equal(own.status, "released", JSON.stringify(own));
    // …but kb2, pinned to the SAME principal, gets nothing from it.
    const other = await settleUnder(env, 1602, POLICY_D, "tb2");
    assert.notEqual(other.status, "released", JSON.stringify(other));
    assert.ok(other.error, JSON.stringify(other));
  } finally { env.close(); }
});

test("M1: the cap is per keyId — kb1 cannot exhaust the allowed set of kb2", async () => {
  const env = await boot({ policyRegistration: true });
  try {
    for (let i = 1; i <= 8; i += 1) {
      assert.equal(env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ digest: digestN(i) })).ok, true, `kb1 #${i}`);
    }
    const ninth = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ digest: digestN(9) }));
    assert.deepEqual(ninth, { ok: false, code: "RATE_LIMITED" });
    const kb2 = env.service.registerPolicy({ keyId: "kb2" }, signPolicy({ tokenKeyId: "kb2", digest: digestN(9) }));
    assert.equal(kb2.ok, true, JSON.stringify(kb2));
  } finally { env.close(); }
});

test("M1: a removed or changed principal pin revokes that key's persisted registrations on reload", () => {
  // The registry directly: a changed pin also breaks the mandate path, so a
  // full settlement cannot isolate the registration check.
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-sec-m1-pin-"));
  const base = { stateDir, envBuyer: new Set([POLICY.buyer]), maxPerRole: 64, now: Date.now, audience: SIGNER.keyId, chainId: null };
  const pinned = new Map([["kb1", PRINCIPAL_ADDRESS], ["kb2", PRINCIPAL_ADDRESS]]);
  // Before CDT-SEC the registry exposed one union set as `buyer`.
  const allows = (r, keyId) => (typeof r.buyerFor === "function" ? r.buyerFor(keyId) : r.buyer).has(POLICY_D);
  const first = createPolicyRegistry({ ...base, principals: pinned });
  assert.equal(first.register({ keyId: "kb1" }, signPolicy()).ok, true);
  assert.equal(allows(first, "kb1"), true);

  const otherAddress = publicKeyToAddress(Buffer.from(keys.buyerSigner.publicKeyHex.slice(2), "hex"));
  const changed = createPolicyRegistry({ ...base, principals: new Map([["kb1", otherAddress], ["kb2", PRINCIPAL_ADDRESS]]) });
  assert.equal(allows(changed, "kb1"), false, "a changed pin revokes");
  const removed = createPolicyRegistry({ ...base, principals: new Map([["kb2", PRINCIPAL_ADDRESS]]) });
  assert.equal(allows(removed, "kb1"), false, "a removed pin revokes");
  assert.equal(removed.buyerFor?.("kb1").has(POLICY.buyer) ?? true, true, "env pins are unaffected");

  // Only re-check, never delete-on-read: with the pin restored the
  // still-unexpired registration authorizes again.
  const restored = createPolicyRegistry({ ...base, principals: pinned });
  assert.equal(allows(restored, "kb1"), true);
});

// =============================================================================
// M2 — per-keyId rate limit before recovery; recovery cached by signature
// bytes; every call receipted, refusals included.
// =============================================================================

test("M2: contract_register_policy is rate limited per keyId, and every call is receipted", async () => {
  let recoveries = 0;
  const env = await boot({
    policyRegistration: true,
    recoverPolicySigner: (d, sig) => { recoveries += 1; return eip191RecoverPublicKey(d, sig); },
  });
  try {
    const out = [];
    for (let i = 1; i <= 7; i += 1) {
      out.push(await env.callTool("tb1", "contract_register_policy", signPolicy({ digest: digestN(i) })));
    }
    assert.equal(out.slice(0, 6).every((r) => r.registered === true), true, JSON.stringify(out));
    assert.equal(out[6].error, "RATE_LIMITED", JSON.stringify(out[6]));
    assert.equal(out[6].retryable, true);
    assert.equal(recoveries, 6, "the limited call never reaches signature recovery");
    // Another keyId has its own budget.
    const kb2 = await env.callTool("tb2", "contract_register_policy", signPolicy({ tokenKeyId: "kb2", digest: digestN(1) }));
    assert.equal(kb2.registered, true, JSON.stringify(kb2));
    const regs = env.service.preBindFeed("kb1").receipts.filter((r) => r.tool === "contract_register_policy");
    assert.equal(regs.length, 7, "the refusal is receipted too");
    assert.equal(regs.filter((r) => r.outcome === "ok").length, 6);
  } finally { env.close(); }
});

test("M2: the same signature bytes are recovered once (valid and invalid alike)", async () => {
  let recoveries = 0;
  const env = await boot({
    policyRegistration: true,
    recoverPolicySigner: (d, sig) => { recoveries += 1; return eip191RecoverPublicKey(d, sig); },
  });
  try {
    const good = signPolicy();
    assert.equal(env.service.registerPolicy({ keyId: "kb1" }, good).ok, true);
    assert.deepEqual(env.service.registerPolicy({ keyId: "kb1" }, good), { ok: false, code: "NONCE_REUSED" });
    assert.equal(recoveries, 1);
    const bad = signPolicy({ digest: digestN(2), priv: keys.buyerSigner.priv });
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(env.service.registerPolicy({ keyId: "kb1" }, bad), { ok: false, code: "SIGNATURE_INVALID" });
    }
    assert.equal(recoveries, 2);
  } finally { env.close(); }
});

// =============================================================================
// L1 — the signed registration names this server (signer keyId) and chain.
// =============================================================================

test("L1: a registration signed for another server or chain is refused", async () => {
  const chainId = "eip155:11155111";
  const env = await boot({
    policyRegistration: true,
    expectedErc8004: { chainId, registryAddress: `0x${"8004".repeat(10)}` },
  });
  try {
    const otherServer = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ audience: "contract-server-other", chainId }));
    assert.deepEqual(otherServer, { ok: false, code: "SIGNATURE_INVALID" });
    const otherChain = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ chainId: "eip155:1" }));
    assert.deepEqual(otherChain, { ok: false, code: "SIGNATURE_INVALID" });
    const noChain = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ chainId: null }));
    assert.deepEqual(noChain, { ok: false, code: "SIGNATURE_INVALID" });
    const ours = env.service.registerPolicy({ keyId: "kb1" }, signPolicy({ chainId }));
    assert.equal(ours.ok, true, JSON.stringify(ours));
  } finally { env.close(); }
});

// =============================================================================
// M3 — above cap 1, a dropped MCP session's pre-bind chain is evicted unless
// a bind captured it; chains per keyId are capped; saltFor reads an index.
// =============================================================================

/** The env bound to one named MCP session per token (`<token>#<suffix>`). */
const viaSession = (env, suffix) => ({
  ...env,
  callTool: (token, name, args = {}) => env.callTool(token, name, args, `${token}#${suffix}`),
});

/** Client-side DELETE of an MCP session (the spec's session termination). */
async function deleteSession(env, token, sid) {
  const res = await fetch(env.baseUrl, {
    method: "DELETE",
    headers: { accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
  });
  await res.text();
  return res.status;
}

test("M3: a dropped session's pre-bind chain is evicted; a chain a bind captured stays with its run", async () => {
  const env = await boot({ maxRunsPerKey: 2 });
  try {
    const st = await viaSession(env, "A").callTool("tb1", "contract_status", {});
    assert.ok(st.serverNonce, JSON.stringify(st));
    const sidA = env.sessionIdOf("tb1#A");
    assert.ok(env.service.preBindFeed("kb1", sidA), "the session has a pre-bind chain");
    assert.equal(await deleteSession(env, "tb1", sidA), 200);
    assert.equal(await waitFor(() => env.service.preBindFeed("kb1", sidA) === undefined, 2_000), true,
      "the dropped session's chain is evicted");

    // Captured by a bind: the run's feed keeps the seat's pre-bind evidence.
    const sB = viaSession(env, "B");
    await sB.callTool("tb1", "contract_status", {});
    const { runId } = await agreePair(sB, uuid(1701), "tb1", "tp1");
    const sidB = env.sessionIdOf("tb1#B");
    assert.equal(await deleteSession(env, "tb1", sidB), 200);
    const feed = env.service.receiptFeed(runId);
    const buyerPre = feed.preBind.find((p) => p.role === "buyer");
    assert.ok(buyerPre && buyerPre.receipts.some((r) => r.tool === "contract_status"), JSON.stringify(feed.preBind));
  } finally { env.close(); }
});

test("M3: pre-bind chains per keyId are capped (oldest uncaptured evicted)", async () => {
  const env = await boot({ maxRunsPerKey: 2 });
  try {
    const principal = { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" };
    for (let i = 0; i < 24; i += 1) {
      const r = env.service.recordPreBind(principal, {
        tool: "contract_status", argsDigest: canonicalDigest({ i }), argsDigestScheme: "canonical",
        outcome: "ok", responseDigest: canonicalDigest({ i }), serverNonce: `0x${String(i).padStart(32, "0")}`,
        mcpSessionId: `sess-${i}`,
      });
      assert.equal(r.ok, true, JSON.stringify(r));
    }
    const salts = env.service.saltFor({ keyId: "kb1" });
    assert.equal(salts.salts.length, 16, "at most 16 chains per keyId");
    assert.equal(env.service.preBindFeed("kb1", "sess-0"), undefined, "the oldest went first");
    assert.ok(env.service.preBindFeed("kb1", "sess-23"));
  } finally { env.close(); }
});

// =============================================================================
// M4 — one brief anchor per digest shared by every scope; ≥ 60 s backoff after
// a failure. L6 — no keyId / session id / run id in the brief anchor subject.
// =============================================================================

function briefsFixture() {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-sec-briefs-"));
  const text = "# Family travel brief\n\nBook within the signed mandate only.\n";
  writeFileSync(path.join(dir, "family-travel.md"), text);
  const digest = `0x${createHash("sha256").update(text).digest("hex")}`;
  return parseContractBriefs(`family-travel:${digest}`, dir);
}

/** A fake anchor whose brief writes fail while `failing.on` is true. */
function switchableAnchor() {
  const base = fakeAnchor();
  const failing = { on: false };
  return {
    calls: base.calls, failing, confirm: base.confirm,
    async anchor(input) {
      if (failing.on && input.kind === "brief") {
        base.calls.push({ ...input });
        throw new Error("anchor substrate unreachable (fake)");
      }
      return base.anchor(input);
    },
  };
}

test("M4/L6: every scope shares one brief anchor, and its ledger subject names no tenant, session or run", async () => {
  const anchor = fakeAnchor();
  const env = await boot({ anchor, briefs: briefsFixture(), serverAnchors: true, maxRunsPerKey: 2 });
  try {
    const got = [];
    for (const [token, suffix] of [["tb1", "A"], ["tb1", "B"], ["tb1", "C"], ["tb2", "A"]]) {
      got.push(await viaSession(env, suffix).callTool(token, "contract_get_brief", { name: "family-travel" }));
    }
    const sA = viaSession(env, "A");
    const { runId } = await agreePair(sA, uuid(1801), "tb1", "tp1");
    got.push(await sA.callTool("tb1", "contract_get_brief", { name: "family-travel" }));
    for (const g of got) assert.equal(g.anchor?.status, "anchored", JSON.stringify(g));
    assert.equal(new Set(got.map((g) => g.anchor.anchorId)).size, 1, "one anchor id across scopes");
    const briefCalls = anchor.calls.filter((c) => c.kind === "brief");
    assert.equal(briefCalls.length, 1, JSON.stringify(briefCalls));
    // L6: the subject is scope-free.
    assert.equal(briefCalls[0].runId, "brief");
    for (const c of briefCalls) assert.doesNotMatch(c.runId, /kb1|kb2|pre-bind|[0-9a-f]{8}-/);
    // The run still reports the brief anchor it was served (R10(b) evidence).
    assert.equal(env.service.runFor(runId).anchors.brief.anchorId, got[0].anchor.anchorId);
  } finally { env.close(); }
});

test("M4: a failed brief anchor is not re-issued on every serve (backoff)", async () => {
  const anchor = switchableAnchor();
  anchor.failing.on = true;
  const env = await boot({ anchor, briefs: briefsFixture(), serverAnchors: true, maxRunsPerKey: 2 });
  try {
    const first = await viaSession(env, "A").callTool("tb1", "contract_get_brief", { name: "family-travel" });
    assert.equal(first.anchor?.status, "failed", JSON.stringify(first));
    for (const suffix of ["A", "B", "C"]) {
      const again = await viaSession(env, suffix).callTool("tb1", "contract_get_brief", { name: "family-travel" });
      assert.equal(again.anchor?.status, "failed");
    }
    assert.equal(anchor.calls.filter((c) => c.kind === "brief").length, 1, "no retry inside the backoff window");
  } finally { env.close(); }

  // Past the backoff (shortened here) the next serve retries once.
  const anchor2 = switchableAnchor();
  anchor2.failing.on = true;
  const env2 = await boot({ anchor: anchor2, briefs: briefsFixture(), serverAnchors: true, briefRetryMs: 50 });
  try {
    await env2.callTool("tb1", "contract_get_brief", { name: "family-travel" });
    anchor2.failing.on = false;
    await new Promise((r) => setTimeout(r, 80));
    const retried = await env2.callTool("tb1", "contract_get_brief", { name: "family-travel" });
    assert.equal(retried.anchor?.status, "anchored", JSON.stringify(retried));
    assert.equal(anchor2.calls.filter((c) => c.kind === "brief").length, 2);
  } finally { env2.close(); }
});
