// Local self-test: drives the gateway exactly as the MCP coordinator's anchorV2 + ClockchainClient do —
// including the payload-bound request signature (x-cc-*), idempotency (duplicate submissions), restart recovery,
// and the auth failure modes (tamper, replay, stale, missing, wrong-key, fail-closed). No network beyond
// localhost. Exit 0 = pass. The sign() helper here is the canonical reference for packages/core/src/client.ts.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash, createHmac, randomBytes } from "node:crypto";

const PORT = 8097;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA = mkdtempSync(path.join(tmpdir(), "gw-selftest-"));
const GATEWAY = new URL("./gateway.mjs", import.meta.url).pathname;
let failures = 0;
const ok = (c, m) => { if (!c) { failures += 1; console.error("FAIL:", m); } else console.log("ok:", m); };

// ---- signer (must match gateway.mjs verifySignature byte-for-byte) ----
const KEY_ID = "selftest-key";
const SECRET = "selftest-secret-" + randomBytes(12).toString("hex");
const SIGNING_KEYS_ENV = `${KEY_ID}:${SECRET}`;
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
function sign(method, pathWithQuery, body, opts = {}) {
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const nonce = opts.nonce ?? randomBytes(16).toString("hex");
  const secret = opts.secret ?? SECRET;
  const keyId = opts.keyId ?? KEY_ID;
  const canonical = `${method.toUpperCase()}\n${pathWithQuery}\n${ts}\n${nonce}\n${sha256hex(body ?? "")}`;
  const sig = createHmac("sha256", secret).update(canonical, "utf8").digest("base64");
  return { "x-cc-key-id": keyId, "x-cc-timestamp": ts, "x-cc-nonce": nonce, "x-cc-signature": sig };
}
async function signedFetch(pathWithQuery, { method = "GET", body = null, headers: extra } = {}) {
  const headers = extra ?? sign(method, pathWithQuery, body ?? "");
  if (body != null) headers["content-type"] = "application/json";
  return fetch(`${BASE}${pathWithQuery}`, { method, headers, body });
}

const SYNC = process.env.SELFTEST_SYNC ?? "1"; // 1 = sync-seal (deploy mode), 0 = async pending
function start(extraEnv = {}) {
  const p = spawn(process.execPath, [GATEWAY], {
    env: {
      ...process.env, GATEWAY_PORT: String(PORT), GATEWAY_HOST: "127.0.0.1", GATEWAY_DATA_DIR: DATA,
      GATEWAY_SEAL_INTERVAL_MS: "300", GATEWAY_SYNC_SEAL: SYNC, GATEWAY_SIGNING_KEYS: SIGNING_KEYS_ENV,
      GATEWAY_HEARTBEAT_MS: "300", ...extraEnv,
    },
    stdio: ["ignore", "inherit", "inherit"],
  });
  return p;
}
async function waitUp(port = PORT) {
  for (let i = 0; i < 50; i += 1) { try { const r = await fetch(`http://127.0.0.1:${port}/healthz`); if (r.ok) return; } catch {} await new Promise((r) => setTimeout(r, 100)); }
  throw new Error("gateway did not come up");
}
const j = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });

async function main() {
  let proc = start();
  await waitUp();

  const digest = "0x" + "a".repeat(64);
  const reference = "agent-handshake-v2:0xdeadbeef:proposed";
  const logBody = { clientId: "test@d4d.group", walletId: "test@d4d.group", assetReferenceId: reference, assetHash: digest, hashType: "SHA-256", versionNumber: 1, additionalInfo: "selftest" };
  const logJson = JSON.stringify(logBody);

  // 0) /healthz is open (no signature); a protected route with NO signature is rejected 401.
  ok((await fetch(`${BASE}/healthz`)).ok, "healthz is open (unauthenticated)");
  const rUnsigned = await j(await fetch(`${BASE}/log`, { method: "POST", headers: { "content-type": "application/json" }, body: logJson }));
  ok(rUnsigned.status === 401, "unsigned POST /log is rejected 401");

  // 1) POST /log (signed) -> pending or anchored, returns ledgerId
  const r1 = await j(await signedFetch(`/log`, { method: "POST", body: logJson }));
  ok(r1.status === 200 && typeof r1.body.ledgerId === "string", "signed log returns ledgerId");
  if (SYNC === "1") ok(/^[0-9]+$/.test(String(r1.body.blockHeight)), "sync-seal: log returns anchored (durable blockHeight)");
  else ok(r1.body.blockHeight === null, "async: log is pending (blockHeight null) until sealed");
  const ledgerId = r1.body.ledgerId;

  // 2) idempotency: same (clientId,reference,hash), fresh signature -> same ledgerId
  const r2 = await j(await signedFetch(`/log`, { method: "POST", body: logJson }));
  ok(r2.body.ledgerId === ledgerId, "duplicate submission is idempotent (same ledgerId)");

  // 3) GET /ledger/{id} polled until sealed
  let entry = null;
  for (let i = 0; i < 40; i += 1) { const r = await j(await signedFetch(`/ledger/${encodeURIComponent(ledgerId)}`)); if (r.body && r.body.blockHeight != null) { entry = r.body; break; } await new Promise((rr) => setTimeout(rr, 100)); }
  ok(entry && /^[0-9]+$/.test(String(entry.blockHeight)), "ledger entry becomes anchored (decimal blockHeight)");
  ok(entry && entry.assetHash === digest && entry.assetReferenceId === reference, "anchored entry preserves hash+reference");
  const blockHeight = entry.blockHeight;

  // 4) getChainRecord: GET /searchAssetFromChain?blockHeight=H
  const r4 = await j(await signedFetch(`/searchAssetFromChain?blockHeight=${encodeURIComponent(blockHeight)}`));
  const txn = (r4.body.transactions || []).find((t) => t.includes(`ledgerId=${ledgerId}`));
  ok(!!txn, "searchAssetFromChain lists the ledgerId transaction");
  ok(txn && txn.includes(`assetHash=${digest}`) && txn.includes(`assetReferenceId=${reference}`), "chain transaction carries assetHash + reference");
  ok(typeof r4.body.proposerAddress === "string" && r4.body.proposerAddress.length > 0, "chain block has proposerAddress");
  ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(r4.body.blockTime || ""), "chain block has RFC3339 blockTime");

  // 5) getBlock: GET /api/time/block?height=H
  const r5 = await j(await signedFetch(`/api/time/block?height=${encodeURIComponent(blockHeight)}`));
  ok(r5.body.success === true && Number(r5.body.data.blockHeight) === Number(blockHeight), "api/time/block returns the block");
  ok(typeof r5.body.data.blockTime === "string" && r5.body.data.blockTime.length > 0, "api/time/block has blockTime");

  // 6) searchAsset exact-match
  const r6 = await j(await signedFetch(`/searchAsset?clientId=${encodeURIComponent(logBody.clientId)}&assetReferenceId=${encodeURIComponent(reference)}`));
  ok(Array.isArray(r6.body) && r6.body.some((e) => e.ledgerId === ledgerId), "searchAsset returns the entry (bare array)");

  // 7) getTime shape
  const r7 = await j(await signedFetch(`/getTime`));
  ok(r7.body.success === true && typeof r7.body.data.blockHeight === "string" && typeof r7.body.data.madMarzulloTime === "string", "getTime has {success,data:{blockHeight,madMarzulloTime}}");

  // 7c) fresh time: an idle ledger must not serve a stale "now". After > HEARTBEAT_MS with no writes, a
  // /getTime read seals an empty heartbeat block: height advances by exactly one, madMarzulloTime moves forward
  // and equals that block's blockTime, and the block is real (searchAssetFromChain finds it, empty). A second
  // read inside the heartbeat window seals nothing.
  const t0 = r7.body.data;
  await new Promise((r) => setTimeout(r, 450));
  const r7c = await j(await signedFetch(`/getTime`));
  const t1 = r7c.body.data;
  ok(Number(t1.blockHeight) === Number(t0.blockHeight) + 1, "idle /getTime seals one heartbeat block (height +1)");
  ok(Date.parse(t1.madMarzulloTime) - Date.parse(t0.madMarzulloTime) >= 400, "heartbeat: madMarzulloTime moved forward with the wait");
  const r7cb = await j(await signedFetch(`/searchAssetFromChain?blockHeight=${encodeURIComponent(t1.blockHeight)}`));
  ok(r7cb.status === 200 && r7cb.body.blockTime === t1.madMarzulloTime && Array.isArray(r7cb.body.transactions) && r7cb.body.transactions.length === 0, "heartbeat block is a real, empty, durable block whose blockTime is the served time");
  const r7cc = await j(await signedFetch(`/getTime`));
  ok(Number(r7cc.body.data.blockHeight) === Number(t1.blockHeight), "a read inside the heartbeat window seals nothing");
  const hz = await j(await fetch(`${BASE}/healthz`));
  ok(hz.body.heartbeatMs === 300, "healthz reports heartbeatMs");

  // 7b) interop lock: this signer, the core signer (packages/core gateway-signing.test.mjs), and the gateway
  // verifier (which accepts this signer's output above) are pinned to ONE shared vector — any drift fails a test.
  const vectorSig = sign("POST", "/log", '{"a":1}', { ts: "1700000000", nonce: "00112233445566778899aabbccddeeff", secret: "test-secret", keyId: "x" })["x-cc-signature"];
  ok(vectorSig === "7Ev9pILEBFhcI99k88ET9pgqj5um5KBhi+ARuSAgvnc=", "signer matches the shared interop vector (== core signer, == gateway verifier)");

  // ---- 8) AUTH failure modes ----
  // tamper: signature computed over one body, a different body is sent -> 401
  const tamperHeaders = sign("POST", "/log", logJson);
  tamperHeaders["content-type"] = "application/json";
  const rTamper = await j(await fetch(`${BASE}/log`, { method: "POST", headers: tamperHeaders, body: JSON.stringify({ ...logBody, assetHash: "0x" + "b".repeat(64) }) }));
  ok(rTamper.status === 401, "tampered body is rejected 401 (payload-bound)");

  // stale: timestamp well outside the skew window -> 401
  const rStale = await j(await signedFetch(`/getTime`, { headers: (() => { const h = sign("GET", "/getTime", "", { ts: Math.floor(Date.now() / 1000) - 100000 }); return h; })() }));
  ok(rStale.status === 401, "stale timestamp is rejected 401 (replay window)");

  // replay: a valid signed request reused with the SAME nonce -> first ok, second 401 replay
  const replayHeaders = sign("GET", "/getTime", "");
  const rReplay1 = await fetch(`${BASE}/getTime`, { headers: replayHeaders });
  const rReplay2 = await fetch(`${BASE}/getTime`, { headers: replayHeaders });
  ok(rReplay1.status === 200 && rReplay2.status === 401, "replayed nonce is rejected 401 (single-use)");

  // wrong key material -> 401
  const rWrong = await j(await signedFetch(`/getTime`, { headers: sign("GET", "/getTime", "", { secret: "not-the-secret" }) }));
  ok(rWrong.status === 401, "wrong signing secret is rejected 401");

  // unknown key id -> 401
  const rUnknown = await j(await signedFetch(`/getTime`, { headers: sign("GET", "/getTime", "", { keyId: "no-such-key" }) }));
  ok(rUnknown.status === 401, "unknown key id is rejected 401");

  // 9) restart recovery (signed reads)
  proc.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 800));
  proc = start();
  await waitUp();
  const r9 = await j(await signedFetch(`/ledger/${encodeURIComponent(ledgerId)}`));
  ok(r9.body && String(r9.body.blockHeight) === String(blockHeight), "restart recovery: entry + blockHeight survive a restart");
  const r9t = await j(await signedFetch(`/getTime`));
  ok(Number(r9t.body.data.blockHeight) >= Number(t1.blockHeight), "restart recovery: heartbeat blocks survive (height never goes backwards)");
  const r9b = await j(await signedFetch(`/searchAssetFromChain?blockHeight=${encodeURIComponent(blockHeight)}`));
  ok((r9b.body.transactions || []).some((t) => t.includes(`ledgerId=${ledgerId}`)), "restart recovery: sealed block + transactions survive");
  proc.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 300));

  // 10) fail-closed: a gateway with NO signing key configured refuses protected routes (503), healthz still open
  const noKey = start({ GATEWAY_SIGNING_KEYS: "" });
  await waitUp();
  ok((await fetch(`${BASE}/healthz`)).ok, "no-key gateway: healthz still open");
  const rNoKey = await j(await signedFetch(`/log`, { method: "POST", body: logJson }));
  ok(rNoKey.status === 503, "no-key gateway: protected route fails closed 503 (no unauthenticated mode)");
  noKey.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 300));

  rmSync(DATA, { recursive: true, force: true });
  console.log(failures === 0 ? "\nSELFTEST PASS" : `\nSELFTEST FAIL (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
