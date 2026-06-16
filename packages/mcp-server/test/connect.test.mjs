// End-to-end "fresh install" connect-path test. Boots the real HTTP server and
// does what a brand-new MCP client does — POST initialize over HTTP — for each
// credential case. The MCP initialize handshake is local (no gateway call), so
// this is deterministic and offline. Guards the connect/auth path against
// regressions: the failures that bit real users were all in exactly this path.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PORT = 39517;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = "test-mcp-token";
const here = path.dirname(fileURLToPath(import.meta.url));
const entry = path.join(here, "..", "dist", "index.js");

let proc;

before(async () => {
  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      MCP_AUTH_TOKENS: TOKEN,
      MCP_REQUIRE_AUTH: "1",
      MCP_TOKEN_SIGNING_SECRET: "connect-test-secret",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  // Wait for the listen line on stderr (with a hard timeout).
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start in time")), 10_000);
    proc.stderr.on("data", (d) => {
      if (String(d).includes("listening on")) {
        clearTimeout(t);
        resolve();
      }
    });
    proc.on("exit", (code) => reject(new Error(`server exited early (${code})`)));
  });
});

after(() => {
  if (proc && !proc.killed) proc.kill();
});

const initialize = (headers) =>
  fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "connect-test", version: "1" },
      },
    }),
  });

test("a valid MCP token connects (delegated key)", async () => {
  const res = await initialize({ "x-api-key": TOKEN });
  assert.equal(res.status, 200);
});

test("forgiving fallback: a non-token key in x-api-key still connects (treated as BYO)", async () => {
  // The #1 real-world mistake — a Clockchain key pasted into x-api-key. initialize
  // succeeds; a bad key would only fail later at the gateway, with its own error.
  const res = await initialize({ "x-api-key": "not-an-mcp-token-looks-like-a-key" });
  assert.equal(res.status, 200);
});

test("self-serve: POST /token mints a token that then authorizes initialize", async () => {
  const mint = await fetch(`${BASE}/token`, { method: "POST" });
  assert.equal(mint.status, 200);
  const { token, expires_at } = await mint.json();
  assert.ok(token.startsWith("cc_"));
  assert.ok(Date.parse(expires_at) > 0);
  // The freshly minted token connects (grants the delegated key).
  const res = await initialize({ "x-api-key": token });
  assert.equal(res.status, 200);
});

test("no credential → self-documenting 401 naming BOTH credential types", async () => {
  const res = await initialize({});
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.equal(body.error, "unauthorized");
  assert.equal(body.auth.mcpToken.header, "x-api-key");
  assert.ok(body.auth.bringYourOwnKey.headers.includes("x-clockchain-api-key"));
  assert.equal(body.endpoint, "https://mcp.clockchain.network/mcp");
});
