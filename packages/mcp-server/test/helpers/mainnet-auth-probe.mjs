// Runs the real HTTP server with this process's SHADOW_NETWORK settings, signs an account in, and reports what each
// credential can reach. Each case needs its own process, because the network is read when the process starts.
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { runHttp } from "../../dist/http.js";
import { __setShadowLedgerForTests } from "../../dist/shadow/ledger.js";
import { mintToken } from "../../dist/token.js";
import { FakeLedger } from "./shadow-fake-ledger.mjs";

const PUBLIC = "https://mcp.example.test", CB = "https://claude.ai/api/mcp/auth_callback", SECRET = "x-secret";
__setShadowLedgerForTests(new FakeLedger());
const probe = createServer().listen(0, "127.0.0.1");
await once(probe, "listening");
const { port } = probe.address();
await new Promise((r) => probe.close(r));
const stateDir = mkdtempSync(path.join(tmpdir(), "net-auth-"));
Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_REQUIRE_AUTH: "1", MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"), MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR: "1000", MCP_OAUTH_APPROVALS_PER_HOUR: "1000" });
console.error = () => {};
console.warn = () => {};
const server = await runHttp();
if (!server.listening) await once(server, "listening");
const base = `http://127.0.0.1:${server.address().port}`;
const decide = (fields) => fetch(`${base}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: PUBLIC }, body: new URLSearchParams(fields) });
const resource = `${PUBLIC}/shadow/mcp`;
const client = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json();
const verifier = randomBytes(32).toString("base64url");
const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: "s", resource });
const html = await (await fetch(`${base}/oauth/authorize?${q}`, { headers: { accept: "text/html" } })).text();
const request = /name="request" value="([^"]+)"/.exec(html)[1];
const created = await decide({ request, decision: "create", ...(/name="name"/.test(html) ? { name: "Acme" } : {}) });
const keyHtml = await created.text();
const cont = await decide({ request, decision: "continue", grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
const code = new URL(cont.headers.get("location")).searchParams.get("code");
const t = await (await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: client.client_id, code_verifier: verifier, resource }) })).json();
const rpc = async (p, token) => (await fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) })).status;
const now = Math.floor(Date.now() / 1000);
const anon = mintToken(SECRET, 3600, now).token;
const out = {
  account: { shadow: await rpc("/shadow/mcp", t.access_token), chat: await rpc("/shadow/chat/mcp", t.access_token), mcp: await rpc("/mcp", t.access_token) },
  anonymous: { mcp: await rpc("/mcp", anon) },
  static: { mcp: await rpc("/mcp", "static-test-token") },
  token_route: (await fetch(`${base}/token`, { method: "POST" })).status,
};
process.stdout.write(JSON.stringify(out));
process.exit(0);
