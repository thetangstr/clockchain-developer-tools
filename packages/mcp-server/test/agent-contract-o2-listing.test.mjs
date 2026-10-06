import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createContractService } from "../dist/agent-contract/service.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createBusinessOps, MAX_INBOX_WAIT_MS } from "../dist/agent-contract/business.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { parseContractDirectory, STANDING_LISTINGS_FILE } from "../dist/agent-contract/directory.js";
import {
  ACCEPT, HOST_ROOTS, POLICY, PRINCIPALS, SIGNER, keys, mintCertificate, rootKey, uuid,
} from "./n4b9-harness.mjs";

// O-2 (mcp-coordination-design.md): a standing provider (Roma Travel)
// receives traveler invitations through /contract/mcp with no human copy
// step — a durable, directory-pinned listing; a bounded inbox long-poll;
// per-delivery consumption (ack / TTL); standing listings survive restart.
// Offline: loopback only, port in the Track B 19400-19499 range; test keys.

// Other Track B agents share the range — take the first free port in it.
// Each boot starts past the previous boot's port, so a pooled keep-alive
// socket to a closed earlier server is never reused against a new one.
let nextPort = 61;
const portsFrom = (start) => Array.from({ length: 100 }, (_, i) => 19400 + ((start + i) % 100));
const DIRECTORY = new Map([["roma-travel", "kp1"]]);
const SEAL_KEY = `0x${"11".repeat(32)}`;

const seal = (n) => ({
  v: 2,
  epk: `0x${n.toString(16).padStart(2, "0").repeat(32)}`,
  iv: `0x${"cd".repeat(12)}`,
  ct: `0x${n.toString(16).padStart(2, "0").repeat(48)}`,
  tag: `0x${"01".repeat(16)}`,
});
const nonce = () => `0x${"0".repeat(32)}`;
const provider = (keyId) => ({ keyId, role: "provider", agentId: "9453", side: "responder" });
const buyer = (keyId) => ({ keyId, role: "buyer", agentId: "9452", side: "initiator" });

function directOps({ now = Date.now, directory = DIRECTORY, stateDir } = {}) {
  return createBusinessOps({
    signer: SIGNER, sim: createSimWorld({ now }), now,
    policyDigests: POLICY, endRun() {}, allowLegacySealV2: true,
    directory, ...(stateDir !== undefined ? { stateDir } : {}),
  });
}

// --- HTTP harness on a fixed loopback port ------------------------------------

const authenticate = tokenAuthenticator(parseContractTokens([
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
].join(",")));

async function bootHttp(stateDir) {
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    directory: DIRECTORY, stateDir, allowLegacySealV2: true,
  });
  const srv = createServer(createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service }));
  let port;
  for (const candidate of portsFrom(nextPort)) {
    const bound = await new Promise((resolve) => {
      const onError = () => resolve(false);
      srv.once("error", onError);
      srv.listen(candidate, "127.0.0.1", () => { srv.off("error", onError); resolve(true); });
    });
    if (bound) { port = candidate; nextPort = candidate - 19400 + 1; break; }
  }
  assert.ok(port !== undefined, "no free loopback port in 19400-19499");
  const baseUrl = `http://127.0.0.1:${port}/contract/mcp`;
  const sessions = new Map();
  const callTool = async (token, name, args = {}) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
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
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  const close = async () => {
    await new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); });
    service.close();
  };
  return { service, callTool, close };
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

async function bindPair(env, sessionId, buyerToken, providerToken, listingId) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool(providerToken, "contract_bind", bindArgs(cert, "provider", { listingId }));
  return { runId: b.runId, provider: p };
}

// =============================================================================
// 1. A standing listing serves two sequential travelers (end to end, HTTP).
// =============================================================================

test("O-2: a standing directory listing serves two sequential travelers; each delivery is consumed on its own", async () => {
  const env = await bootHttp(mkdtempSync(path.join(tmpdir(), "o2-two-")));
  try {
    const pub = await env.callTool("tp1", "rendezvous_publish_listing", {
      title: "Roma Travel", summary: "Standing agency listing",
      sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel", standing: true,
    });
    assert.equal(pub.standing, true, JSON.stringify(pub));
    assert.equal(pub.directoryName, "roma-travel");
    assert.ok(Date.parse(pub.expiresAt) > Date.now());
    const listingId = pub.listingId;

    // Travelers find Roma by NAME, not by copying a listingId around.
    // (origin/destination stay required on the wire; an undeclared term never contradicts)
    const ROUTE = { origin: "SFO", destination: "FCO" };
    const found = await env.callTool("tb1", "rendezvous_search", { ...ROUTE, name: "roma-travel" });
    assert.deepEqual(found.listings.map((l) => l.listingId), [listingId]);
    assert.equal(found.listings[0].standing, true);

    for (const [i, buyerToken] of [[1, "tb1"], [2, "tb2"]]) {
      // The provider is already waiting (long-poll) when the traveler sends.
      const poll = env.callTool("tp1", "rendezvous_inbox", { waitMs: 10_000 });
      await new Promise((r) => setTimeout(r, 100));
      const t0 = Date.now();
      const sent = await env.callTool(buyerToken, "rendezvous_send_invitation", { listingId, sealedInvitation: seal(i) });
      assert.equal(sent.delivered, true, `traveler ${i}: ${JSON.stringify(sent)}`);
      const box = await poll;
      assert.ok(Date.now() - t0 < 2_000, "the long-poll answered on delivery, not at waitMs");
      const mine = box.messages.filter((m) => m.listingId === listingId);
      assert.equal(mine.length, 1, `traveler ${i} inbox: ${JSON.stringify(box)}`);
      assert.equal(mine[0].sealedPayload.ct, seal(i).ct);

      // The provider consumes THIS delivery; the listing stays live.
      const ack = await env.callTool("tp1", "rendezvous_ack", { messageIds: [mine[0].messageId] });
      assert.equal(ack.acked, 1, JSON.stringify(ack));
      const after = await env.callTool("tp1", "rendezvous_inbox", {});
      assert.equal(after.messages.filter((m) => m.listingId === listingId).length, 0);

      // Binding the handshake through the listing does NOT consume it.
      const { provider: p } = await bindPair(env, uuid(700 + i), buyerToken, "tp1", listingId);
      assert.equal(p.bound, true, `traveler ${i} provider bind: ${JSON.stringify(p)}`);
      const still = await env.callTool(buyerToken, "rendezvous_search", { ...ROUTE, name: "roma-travel" });
      assert.deepEqual(still.listings.map((l) => l.listingId), [listingId], "listing survives the bind");

      // Run i ends (the traveler withdraws) — Roma is free for the next one.
      const w = await env.callTool(buyerToken, "contract_withdraw", { reason: "test run done" });
      assert.equal(w.state, "withdrawn", JSON.stringify(w));
    }
  } finally {
    await env.close();
  }
});

// =============================================================================
// 2. Directory pin — squatting refused.
// =============================================================================

test("O-2: only the pinned provider keyId may publish under a directory name (squatting refused)", () => {
  const ops = directOps();
  const pub = (p, extra) => ops.dispatch(p, undefined, "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, ...extra,
  }, nonce());

  // kp2 is not pinned to roma-travel — refused, standing or not.
  const squat = pub(provider("kp2"), { directoryName: "roma-travel", standing: true });
  assert.equal(squat.ok, false);
  assert.equal(squat.code, "LISTING_UNAVAILABLE");
  assert.equal(pub(provider("kp2"), { directoryName: "roma-travel" }).code, "LISTING_UNAVAILABLE");
  // A name nobody is pinned to is unclaimable.
  assert.equal(pub(provider("kp1"), { directoryName: "unpinned-agency" }).code, "LISTING_UNAVAILABLE");
  // Standing requires a directory name.
  assert.equal(pub(provider("kp1"), { standing: true }).code, "PAYLOAD_INVALID");

  // The squatter may still publish an ordinary listing with the SAME title —
  // but a by-name search never returns it.
  const decoy = pub(provider("kp2"), {});
  assert.equal(decoy.ok, true);
  const real = pub(provider("kp1"), { directoryName: "roma-travel", standing: true });
  assert.equal(real.ok, true);
  const byName = ops.dispatch(buyer("kb1"), undefined, "rendezvous_search", { name: "roma-travel" }, nonce());
  assert.deepEqual(byName.result.listings.map((l) => l.listingId), [real.result.listingId]);
});

test("O-2: CONTRACT_DIRECTORY parsing fails closed (malformed, duplicate, non-provider pin)", () => {
  assert.deepEqual([...parseContractDirectory("roma-travel:kp1, other-co:kp2")], [["roma-travel", "kp1"], ["other-co", "kp2"]]);
  assert.equal(parseContractDirectory(undefined).size, 0);
  assert.throws(() => parseContractDirectory("roma-travel"), /malformed/);
  assert.throws(() => parseContractDirectory("Roma Travel:kp1"), /malformed/);
  assert.throws(() => parseContractDirectory("roma-travel:kp1:extra"), /malformed/);
  assert.throws(() => parseContractDirectory("roma-travel:kp1,roma-travel:kp2"), /more than once/);
  assert.throws(() => parseContractDirectory("roma-travel:kb1", new Set(["kp1"])), /no provider token/);

  const READY_ENV = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"),
    CONTRACT_POLICY_DIGESTS: `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`,
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_OBSERVER_TOKEN: "obs-token",
    CONTRACT_VERIFIER_TOKEN: "ver-token",
  };
  const cfg = (dir) => loadContractConfig({
    ...READY_ENV,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "o2-cfg-")),
    ...(dir !== undefined ? { CONTRACT_DIRECTORY: dir } : {}),
  });
  for (const bad of ["roma-travel", "roma-travel:kp1,roma-travel:kp1", "roma-travel:kb1"]) {
    const c = cfg(bad);
    assert.equal(c.kind, "misconfigured", bad);
    assert.match(c.reason, /CONTRACT_DIRECTORY/);
  }
  for (const good of [undefined, "roma-travel:kp1"]) {
    const c = cfg(good);
    assert.equal(c.kind, "ready", `${good}: ${c.reason}`);
    c.service.close();
  }
});

// =============================================================================
// 3. Inbox long-poll — returns on delivery, times out cleanly, bounded.
// =============================================================================

test("O-2: inbox long-poll returns on delivery, times out with an empty list, and is bounded", async () => {
  const ops = directOps();
  const pub = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
    directoryName: "roma-travel", standing: true,
  }, nonce());
  const listingId = pub.result.listingId;
  const inbox = (args) => ops.dispatch(provider("kp1"), undefined, "rendezvous_inbox", args, nonce());

  // Timeout: nothing arrives — the hold answers the same shape, empty.
  let t0 = Date.now();
  const empty = await inbox({ waitMs: 150 });
  const waited = Date.now() - t0;
  assert.equal(empty.ok, true);
  assert.deepEqual(empty.result.messages, []);
  assert.ok(waited >= 140 && waited < 2_000, `timed out after ${waited} ms`);

  // Delivery: the hold wakes as soon as a traveler's invitation lands.
  t0 = Date.now();
  const held = inbox({ waitMs: 20_000 });
  assert.ok(held instanceof Promise, "an empty inbox with waitMs holds");
  setTimeout(() => {
    const s = ops.dispatch(buyer("kb1"), undefined, "rendezvous_send_invitation", { listingId, sealedInvitation: seal(1) }, nonce());
    assert.equal(s.ok, true, JSON.stringify(s));
  }, 50);
  const woke = await held;
  assert.ok(Date.now() - t0 < 2_000, "woke on delivery, not at waitMs");
  assert.equal(woke.result.messages.length, 1);

  // A non-empty inbox answers at once even with waitMs.
  const immediate = inbox({ waitMs: 20_000 });
  assert.ok(!(immediate instanceof Promise));
  assert.equal(immediate.result.messages.length, 1);

  // `since` past the newest message: the hold still applies, then times out.
  const since = woke.result.messages[0].receivedAt;
  const afterSince = await inbox({ waitMs: 100, since });
  assert.deepEqual(afterSince.result.messages, []);

  // One hold per provider keyId: a newer poll releases the older one.
  ops.dispatch(provider("kp1"), undefined, "rendezvous_ack", { messageIds: [woke.result.messages[0].messageId] }, nonce());
  t0 = Date.now();
  const first = inbox({ waitMs: 20_000 });
  const second = inbox({ waitMs: 100 });
  assert.deepEqual((await first).result.messages, [], "superseded hold answers empty");
  assert.ok(Date.now() - t0 < 2_000, "superseded hold answered early");
  await second;

  // Bounded: the published cap is 25 s.
  assert.equal(MAX_INBOX_WAIT_MS, 25_000);
});

test("O-2: the wire schema refuses waitMs above 25 s", async () => {
  const env = await bootHttp(mkdtempSync(path.join(tmpdir(), "o2-wait-")));
  try {
    const r = await env.callTool("tp1", "rendezvous_inbox", { waitMs: 25_001 });
    assert.ok(r.rpcError !== undefined || r.error !== undefined, JSON.stringify(r));
    const ok = await env.callTool("tp1", "rendezvous_inbox", { waitMs: 0 });
    assert.deepEqual(ok.messages, []);
  } finally {
    await env.close();
  }
});

// =============================================================================
// 4. Per-delivery consumption on a standing listing: ack and TTL.
// =============================================================================

test("O-2: ack frees the sender's pending slot; unacked standing deliveries expire after 5 min", () => {
  let clock = Date.parse("2026-10-06T10:00:00.000Z");
  const ops = directOps({ now: () => clock });
  const listingId = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
    directoryName: "roma-travel", standing: true,
  }, nonce()).result.listingId;
  const send = (k, n) => ops.dispatch(buyer(k), undefined, "rendezvous_send_invitation", { listingId, sealedInvitation: seal(n) }, nonce());
  const box = () => ops.dispatch(provider("kp1"), undefined, "rendezvous_inbox", {}, nonce()).result.messages;

  // Fill all 16 pending slots; the 17th sender is refused.
  for (let i = 0; i < 16; i++) assert.equal(send(`kx${i}`, i + 1).ok, true);
  assert.equal(send("kx16", 0xee).code, "LISTING_UNAVAILABLE");

  // Acking one delivery frees exactly one slot. Another provider cannot ack it.
  const [first] = box();
  const foreign = ops.dispatch(provider("kp2"), undefined, "rendezvous_ack", { messageIds: [first.messageId] }, nonce());
  assert.equal(foreign.result.acked, 0);
  assert.equal(box().length, 16);
  const ack = ops.dispatch(provider("kp1"), undefined, "rendezvous_ack", { messageIds: [first.messageId, "msg-unknown"] }, nonce());
  assert.equal(ack.result.acked, 1);
  assert.equal(box().length, 15);
  assert.equal(send("kx16", 0xee).ok, true, "the freed slot takes a new traveler");

  // Five minutes on, every unacked delivery has expired; the listing has not.
  clock += 5 * 60_000;
  assert.equal(box().length, 0);
  assert.equal(send("kx20", 0x20).ok, true, "a standing listing outlives its deliveries");
  assert.equal(box().length, 1);
});

test("O-2: a standing listing renews by republishing; it is never resurrected from consumed", () => {
  let clock = Date.parse("2026-10-06T10:00:00.000Z");
  const ops = directOps({ now: () => clock });
  const pub = (extra = {}) => ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel", ...extra,
  }, nonce());
  const a = pub({ standing: true });
  clock += 50 * 60_000;
  const b = pub(); // a renewal need not repeat `standing`
  assert.equal(b.result.listingId, a.result.listingId);
  assert.equal(b.result.standing, true);
  assert.equal(Date.parse(b.result.expiresAt), clock + 60 * 60_000);
  clock += 30 * 60_000; // past the ORIGINAL expiry — still live after renewal
  const found = ops.dispatch(buyer("kb1"), undefined, "rendezvous_search", { name: "roma-travel" }, nonce());
  assert.equal(found.result.listings.length, 1);

  // A default listing consumed by a bind cannot be turned standing.
  const plain = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Roma plain", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel",
  }, nonce());
  assert.equal(ops.consumeListing("kp1", plain.result.listingId), true);
  const revived = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Roma plain", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, standing: true,
  }, nonce());
  assert.equal(revived.code, "LISTING_UNAVAILABLE");
});

// =============================================================================
// 5. Default mode unchanged.
// =============================================================================

test("O-2: default listings are unchanged — same output shape, consumed by the bind, sync inbox", async () => {
  const ops = directOps();
  const pub = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
    title: "Ordinary listing", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
  }, nonce());
  assert.deepEqual(Object.keys(pub.result).sort(), ["listingId", "publishedAt", "serverNonce"]);
  const search = ops.dispatch(buyer("kb1"), undefined, "rendezvous_search", {}, nonce());
  assert.deepEqual(Object.keys(search.result.listings[0]).sort(),
    ["listingId", "publishedAt", "sealedBoxPublicKeyHex", "summary", "title"]);
  const inbox = ops.dispatch(provider("kp1"), undefined, "rendezvous_inbox", {}, nonce());
  assert.ok(!(inbox instanceof Promise), "no waitMs → the inbox answers synchronously");

  // HTTP: the provider's bind consumes the default listing exactly as before.
  const env = await bootHttp(mkdtempSync(path.join(tmpdir(), "o2-default-")));
  try {
    const l = await env.callTool("tp1", "rendezvous_publish_listing", {
      title: "Ordinary listing", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
    });
    assert.equal(l.standing, undefined);
    assert.equal((await env.callTool("tb1", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(1) })).delivered, true);
    const { provider: p } = await bindPair(env, uuid(710), "tb1", "tp1", l.listingId);
    assert.equal(p.bound, true, JSON.stringify(p));
    const late = await env.callTool("tb2", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(2) });
    assert.equal(late.error, "LISTING_UNAVAILABLE", JSON.stringify(late));
    const box = await env.callTool("tp1", "rendezvous_inbox", {});
    assert.equal(box.messages.filter((m) => m.listingId === l.listingId).length, 0);
  } finally {
    await env.close();
  }
});

// =============================================================================
// 6. Restart evidence.
// =============================================================================

test("O-2 restart: standing listings survive a restart; default listings and the inbox do not", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "o2-restart-"));
  const boot = () => createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    directory: DIRECTORY, stateDir, allowLegacySealV2: true,
  });
  const call = (svc, p, name, args) => svc.business.dispatch(p, undefined, name, args, nonce());

  const a = boot();
  const standing = call(a, provider("kp1"), "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel", standing: true,
  }).result.listingId;
  const plain = call(a, provider("kp2"), "rendezvous_publish_listing", {
    title: "Ordinary listing", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
  }).result.listingId;
  assert.equal(call(a, buyer("kb1"), "rendezvous_send_invitation", { listingId: standing, sealedInvitation: seal(1) }).ok, true);
  assert.equal(call(a, provider("kp1"), "rendezvous_inbox", {}).result.messages.length, 1);
  const file = path.join(stateDir, STANDING_LISTINGS_FILE);
  assert.ok(existsSync(file));
  const persisted = JSON.parse(readFileSync(file, "utf8"));
  assert.deepEqual(persisted.listings.map((l) => l.listingId), [standing], "only standing metadata is written");
  assert.equal(JSON.stringify(persisted).includes(seal(1).ct.slice(2)), false, "no delivery ciphertext on disk");
  a.close();

  const b = boot();
  try {
    const listed = call(b, buyer("kb1"), "rendezvous_search", {}).result.listings.map((l) => l.listingId);
    assert.deepEqual(listed, [standing], "the standing listing is back; the default one is gone");
    assert.deepEqual(call(b, provider("kp1"), "rendezvous_inbox", {}).result.messages, [], "the inbox is not persisted");
    assert.equal(call(b, buyer("kb2"), "rendezvous_send_invitation", { listingId: standing, sealedInvitation: seal(2) }).ok, true);
    assert.equal(call(b, buyer("kb2"), "rendezvous_send_invitation", { listingId: plain, sealedInvitation: seal(3) }).code, "NOT_FOUND");
  } finally {
    b.close();
  }

  // A restart whose directory no longer pins the name does not restore it.
  const c = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    directory: new Map([["roma-travel", "kp2"]]), stateDir, allowLegacySealV2: true,
  });
  try {
    assert.deepEqual(c.business.dispatch(buyer("kb1"), undefined, "rendezvous_search", {}, nonce()).result.listings, []);
  } finally {
    c.close();
  }
});

test("O-2 restart: a corrupt standing-listings file is a hard startup error; a failed write refuses the publish", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "o2-corrupt-"));
  writeFileSync(path.join(stateDir, STANDING_LISTINGS_FILE), JSON.stringify({ schema: "nope", listings: [] }));
  assert.throws(() => directOps({ stateDir }), /corrupt standing-listings\.json/);

  const roDir = mkdtempSync(path.join(tmpdir(), "o2-ro-"));
  const ops = directOps({ stateDir: roDir });
  chmodSync(roDir, 0o555);
  try {
    const r = ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
      title: "Roma Travel", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel", standing: true,
    }, nonce());
    assert.equal(r.code, "CONTRACT_UNAVAILABLE");
    const found = ops.dispatch(buyer("kb1"), undefined, "rendezvous_search", {}, nonce());
    assert.deepEqual(found.result.listings, [], "nothing half-published");
    // A default listing never touches the disk, so it still publishes.
    assert.equal(ops.dispatch(provider("kp1"), undefined, "rendezvous_publish_listing", {
      title: "Ordinary", summary: "x", sealedBoxPublicKeyHex: SEAL_KEY,
    }, nonce()).ok, true);
  } finally {
    chmodSync(roDir, 0o700);
  }
});
