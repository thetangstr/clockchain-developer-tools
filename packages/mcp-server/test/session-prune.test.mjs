// Route-level proof that an expired observed handshake session is pruned by
// /metrics collection itself — with NO intervening handshake tool call.
// Spawns the real server with the full v2 runtime env against a stubbed
// relay/gateway/EVM upstream, runs agent_handshake_invite over the public
// /handshake/mcp route to create a real inflight session, waits out its
// sessionDeadlineMs, then scrapes authenticated /metrics twice.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const PORT = 39541;
const BASE = `http://127.0.0.1:${PORT}`;
const METRICS_TOKEN = "metrics-prune-test";
const SESSION_ID = "9d1a2b3c-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

const INVITE_RUNWAY_MS = 39_000; // invite requires >30s of invitation runway
const SESSION_TTL_MS = 40_000; // sessionDeadlineMs — the expiry under test

let upstream;
let upstreamPort;
let proc;
let stateDir;
let discoveryDoc;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Frozen doc: storeInitial re-fetches /v1/discovery/{sessionId} and requires
// byte-identical timing fields vs. the /current fetch, so timestamps are
// computed once at fixture setup — never per-request.
function buildDiscovery() {
  const now = Date.now();
  return {
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    repositorySha: "deadbeefcafe1234deadbeefcafe1234deadbeef",
    kitRepoUrl: "https://example.invalid/kit",
    relayUrl: `http://127.0.0.1:${upstreamPort}`,
    createdAtMs: String(now),
    invitationExpiresAtMs: String(now + INVITE_RUNWAY_MS),
    sessionDeadlineMs: String(now + SESSION_TTL_MS),
    sessionOpenedBlock: "17100",
    hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
    externalBusinessActionPerformed: false,
    // No `terms`: invite then binds the caller's terms (warnCompatibility path),
    // which keeps this fixture free of canonical-terms duplication.
  };
}

before(async () => {
  stateDir = mkdtempSync(path.join(tmpdir(), "cc-prune-"));
  upstream = createServer((req, res) => {
    const url = (req.url ?? "").split("?")[0];
    const json = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method === "POST" && /^\/v1\/sessions\/[^/]+\/messages$/.test(url)) {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => json(200, { ok: true, seq: "1" }));
      return;
    }
    if (req.method === "POST") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => json(200, { jsonrpc: "2.0", id: 1, result: "0xaa36a7" }));
      return;
    }
    if (url === "/v1/discovery/current" || url === `/v1/discovery/${SESSION_ID}`) {
      json(200, discoveryDoc);
      return;
    }
    if (/^\/v1\/sessions\/[^/]+\/messages$/.test(url)) {
      json(200, { ok: true, messages: [] });
      return;
    }
    if (/^\/v1\/sessions\/[^/]+\/result$/.test(url)) {
      json(404, { error: "RESULT_PENDING" });
      return;
    }
    if (url === "/getTime") {
      json(200, { success: true, data: { nodeParticipation: 100, totalNodes: 12, blockHeight: "1" } });
      return;
    }
    json(404, { error: "not_found" });
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = upstream.address().port;
  discoveryDoc = buildDiscovery();

  const key = (kid, fill) => JSON.stringify({ kid, secretBase64: Buffer.alloc(32, fill).toString("base64") });
  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      HANDSHAKE_RELAY: `http://127.0.0.1:${upstreamPort}`,
      CLOCKCHAIN_ENDPOINT: `http://127.0.0.1:${upstreamPort}`,
      EVM_RPC_URL: `http://127.0.0.1:${upstreamPort}`,
      MCP_METRICS_TOKEN: METRICS_TOKEN,
      AGENT_HANDSHAKE_RELEASE_PIN: JSON.stringify({
        version: "2.1.7",
        sourceCommit: "a".repeat(40),
        manifestDigest: "b".repeat(64),
        allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.7/",
        hostRoots: [{ kid: "root-test", fingerprint: "c".repeat(64) }],
      }),
      AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: key("access-active", 1),
      AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: key("hmac-active", 2),
      AGENT_HANDSHAKE_V2_STATE_FILE: path.join(stateDir, "state.json"),
      AGENT_HANDSHAKE_V2_INVITATION_FILE: path.join(stateDir, "invitations.json"),
      STATUS_CACHE_MS: "25",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start in time")), 15_000);
    proc.stderr.on("data", (d) => {
      if (String(d).includes("listening on")) { clearTimeout(t); resolve(); }
    });
    proc.on("exit", (code) => reject(new Error(`server exited early (${code})`)));
  });
});

after(() => {
  if (proc && !proc.killed) proc.kill();
  if (upstream) upstream.close();
});

async function mcpCall(name, args) {
  const res = await fetch(`${BASE}/handshake/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  assert.equal(res.status, 200, `${name} HTTP ${res.status}`);
  const text = await res.text();
  const data = text.split("\n").find((line) => line.startsWith("data:"));
  return JSON.parse(data ? data.slice(5) : text);
}

async function metricsText() {
  const res = await fetch(`${BASE}/metrics`, { headers: { authorization: `Bearer ${METRICS_TOKEN}` } });
  assert.equal(res.status, 200);
  return res.text();
}

function inflightValue(text) {
  const m = text.match(/^clockchain_handshake_inflight (\d+)$/m);
  assert.ok(m, "clockchain_handshake_inflight series missing");
  return Number(m[1]);
}

test("expired observed session is pruned by the next /metrics scrape — no handshake call between", async () => {
  const invited = await mcpCall("agent_handshake_invite", {
    reference: "NS-1847",
    statement: "prune test",
    validForSeconds: "30",
    identityPolicy: {
      erc8004: "required_fresh",
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    },
  });
  const inviteBody = JSON.parse(invited.result.content[0].text);
  assert.equal(inviteBody.sessionId, SESSION_ID);
  assert.equal(typeof inviteBody.roleAccess, "string");

  // The invite created a real tracked session: inflight is 1 on this scrape.
  assert.equal(inflightValue(await metricsText()), 1);

  // Wait out sessionDeadlineMs (+ margin) with NO further handshake call.
  await sleep(SESSION_TTL_MS + 1_500);

  // The next authenticated /metrics collection must prune on its own.
  const text = await metricsText();
  assert.equal(inflightValue(text), 0);
});
