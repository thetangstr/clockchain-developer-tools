// How an agent finds hosted Shadow: /llms.txt, /install.txt and /.well-known/mcp.json name it only when a person can
// use it, and are byte-identical to the plain files otherwise. Also runs scripts/e2e-shadow-public.mjs against a local
// server on a fake ledger: read-only mode writes nothing, and --write refuses production.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runHttp } from "../dist/http.js";
import { INSTALL_TXT, MCP_MANIFEST } from "../dist/landing.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { connectInstructions, installTxtWithShadow, manifestWithShadow, shadowInstallSection } from "../dist/shadow/discovery.js";
import { baseKind, parseArgs } from "../../../scripts/e2e-shadow-public.mjs";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const SCRIPT = fileURLToPath(new URL("../../../scripts/e2e-shadow-public.mjs", import.meta.url));
const CHAT = "/shadow/chat/mcp";
const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH",
  "MCP_RATE_PER_MIN", "MCP_TOKEN_MINT_PER_HOUR", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_MAX_BYTES",
  "CLOCKCHAIN_ENDPOINT", "CLOCKCHAIN_API_KEY", "CLOCKCHAIN_CLIENT_ID", "CLOCKCHAIN_WALLET_ID",
];
const tempDir = (label) => mkdtempSync(path.join(tmpdir(), `shadow-discovery-${label}-`));
const SHADOW_ON = () => ({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: tempDir("shadow") });

async function freeLoopbackPort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

/** A stand-in for the Clockchain gateway, so get_time works here and nothing reaches the real network. */
let gatewayUrl;
test.before(async () => {
  const gateway = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ success: true, data: { blockHeight: "136", madMarzulloTime: "2026-09-10T22:59:34.197Z", totalNodes: 1, nodeParticipationPct: 100 } }));
  }).listen(0, "127.0.0.1");
  await once(gateway, "listening");
  gateway.unref();
  gatewayUrl = `http://127.0.0.1:${gateway.address().port}`;
});

/** The real runHttp wiring. MCP_PUBLIC_URL is this server's own URL, as it is in production. */
async function boot(env = {}) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const stateDir = tempDir("state");
  let server;
  let url;
  for (let attempt = 1; ; attempt++) {
    const port = await freeLoopbackPort();
    url = `http://127.0.0.1:${port}`;
    Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-token", MCP_TOKEN_SIGNING_SECRET: "discovery-test-secret", MCP_STATE_DIR: stateDir, MCP_PUBLIC_URL: url, CLOCKCHAIN_ENDPOINT: gatewayUrl, CLOCKCHAIN_API_KEY: "test-key", CLOCKCHAIN_CLIENT_ID: "test@example.com", CLOCKCHAIN_WALLET_ID: "test@example.com" }, env);
    server = await runHttp();
    if (!server.listening) await once(server, "listening");
    let reached = false;
    const mark = () => { reached = true; };
    server.prependListener("request", mark);
    await fetch(`${url}/health`).then((r) => r.arrayBuffer()).catch(() => {});
    server.removeListener("request", mark);
    if (reached) break;
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    assert.ok(attempt < 5, "no 127.0.0.1 port reached this server in 5 tries");
  }
  return {
    url,
    stateDir,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/** The raw bytes and the headers that matter, so "byte-identical" means exactly that. */
async function fetchRaw(url) {
  const res = await fetch(url);
  return { status: res.status, type: res.headers.get("content-type"), cache: res.headers.get("cache-control"), body: Buffer.from(await res.arrayBuffer()) };
}

async function assertPlainFiles(url) {
  for (const p of ["/llms.txt", "/install.txt"]) {
    const r = await fetchRaw(`${url}${p}`);
    assert.equal(r.status, 200, p);
    assert.equal(r.type, "text/plain; charset=utf-8", p);
    assert.equal(r.cache, "public, max-age=300", p);
    assert.ok(r.body.equals(Buffer.from(INSTALL_TXT, "utf8")), `${p} is INSTALL_TXT, byte for byte`);
    assert.doesNotMatch(r.body.toString(), /shadow/i, p);
  }
  const m = await fetchRaw(`${url}/.well-known/mcp.json`);
  assert.equal(m.status, 200);
  assert.equal(m.type, "application/json; charset=utf-8");
  assert.equal(m.cache, "public, max-age=300");
  assert.ok(m.body.equals(Buffer.from(JSON.stringify(MCP_MANIFEST, null, 2), "utf8")), "the manifest is MCP_MANIFEST, byte for byte");
  assert.doesNotMatch(m.body.toString(), /shadow/i);
}

test("flag off: the discovery files are byte-identical to the plain files", async () => {
  const app = await boot();
  try {
    await assertPlainFiles(app.url);
  } finally {
    await app.close();
  }
});

test("flag off with sign-in on: still byte-identical, and the unrelated chat flag adds nothing", async () => {
  const app = await boot({ MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    await assertPlainFiles(app.url);
  } finally {
    await app.close();
  }
});

test("SHADOW_ENABLED=1 without sign-in: not advertised, because nobody could use it", async () => {
  const app = await boot(SHADOW_ON());
  try {
    await assertPlainFiles(app.url);
  } finally {
    await app.close();
  }
});

test("SHADOW_ENABLED=1 that failed to start: not advertised, because every /shadow path answers 503", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_MAX_BYTES: "not-a-number" });
  try {
    assert.equal((await fetch(`${app.url}/shadow/connect`)).status, 503);
    await assertPlainFiles(app.url);
  } finally {
    await app.close();
  }
});

test("flag on: /llms.txt and /install.txt add one Shadow section and change nothing else", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const llms = await fetchRaw(`${app.url}/llms.txt`);
    const install = await fetchRaw(`${app.url}/install.txt`);
    assert.equal(llms.status, 200);
    assert.equal(llms.type, "text/plain; charset=utf-8");
    assert.equal(llms.cache, "public, max-age=300");
    assert.ok(install.body.equals(llms.body), "the same bytes on both paths");
    const text = llms.body.toString();

    const section = shadowInstallSection(app.url, CHAT);
    assert.equal(text.replace(section, ""), INSTALL_TXT, "taking the section out gives back the plain file");
    assert.ok(text.indexOf("SHADOW —") < text.indexOf("TWO-PERSON STAKEHOLDER HANDSHAKE"), "it comes before the handshake section");

    // What it is, and the two endpoints.
    assert.match(text, /flight recorder for AI agents/);
    assert.ok(text.includes(`${app.url}/shadow/mcp\n      for ChatGPT and Claude Code`));
    assert.ok(text.includes(`${app.url}${CHAT}\n      for claude.ai`));
    // claude.ai, with the two settings to pick by hand.
    assert.match(text, /"Sign in when needed" \(it\s+guesses "No sign-in"\)/);
    assert.match(text, /"Register automatically" \(it defaults to "Use\s+Claude's published identity"\)/);
    assert.match(text, /The key never enters the chat/);
    // Claude Code and ChatGPT, with what is not confirmed marked as such.
    assert.ok(text.includes(`claude mcp add --transport http shadow ${app.url}/shadow/mcp`));
    assert.match(text, /Developer Mode/);
    assert.match(text, /Not yet confirmed in a real ChatGPT account/);
    assert.match(text, /Not yet confirmed with a real Claude Code sign-up/);
    // The free key, and that an account is required.
    assert.ok(text.includes(`curl -X POST ${app.url}/token`));
    assert.match(text, /An account is required/);
    assert.match(text, /403\s+account_required/);
    // What is kept where.
    assert.match(text, /deleted 30 days after the session starts/);
    assert.match(text, /links\s+cannot\s+be\s+revoked/);
    assert.match(text, /Hashes only/);
    assert.match(text, /not that what it says is true or compliant/);
    assert.doesNotMatch(text, /audited|@(?!example)[a-z]+\.[a-z]+/i);
  } finally {
    await app.close();
  }
});

test("flag on: /.well-known/mcp.json adds one shadow block and changes nothing else", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const raw = await fetchRaw(`${app.url}/.well-known/mcp.json`);
    assert.equal(raw.type, "application/json; charset=utf-8");
    assert.equal(raw.cache, "public, max-age=300");
    const { shadow, ...rest } = JSON.parse(raw.body.toString());
    assert.equal(JSON.stringify(rest, null, 2), JSON.stringify(MCP_MANIFEST, null, 2), "the rest is the plain manifest, in the same order");
    assert.deepEqual(shadow.endpoints, { signIn: `${app.url}/shadow/mcp`, chat: `${app.url}${CHAT}` });
    assert.equal(shadow.instructions, `${app.url}/shadow/connect`);
    assert.equal(shadow.authentication.type, "oauth");
    assert.equal(shadow.authentication.accountRequired, true);
    assert.equal(shadow.authentication.freeKey.obtain, `POST ${app.url}/token`);
    assert.equal(shadow.clients.claudeAi.endpoint, `${app.url}${CHAT}`);
    assert.deepEqual(shadow.clients.claudeAi.settings, ["Sign in when needed", "Register automatically"]);
    assert.equal(shadow.clients.claudeCode.endpoint, `${app.url}/shadow/mcp`);
    assert.equal(shadow.clients.chatgpt.endpoint, `${app.url}/shadow/mcp`);
    assert.match(shadow.clients.chatgpt.note, /Not yet confirmed/);
    assert.match(shadow.keptWhere.record, /30 days/);
    assert.match(shadow.keptWhere.ledger, /Hashes only/);
  } finally {
    await app.close();
  }
});

test("flag on, no chat endpoint: only /shadow/mcp is named, in all three places", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1" });
  try {
    assert.equal((await fetch(`${app.url}${CHAT}`, { method: "POST" })).status, 404, "the chat endpoint really is off");
    const llms = await (await fetch(`${app.url}/llms.txt`)).text();
    const connect = await (await fetch(`${app.url}/shadow/connect`)).text();
    const manifest = await (await fetch(`${app.url}/.well-known/mcp.json`)).json();
    for (const text of [llms, connect, JSON.stringify(manifest)]) {
      assert.ok(text.includes(`${app.url}/shadow/mcp`));
      assert.ok(!text.includes(CHAT), "no chat endpoint");
      assert.ok(!text.includes("Sign in when needed"), "no setting that needs the chat endpoint");
    }
    assert.deepEqual(manifest.shadow.endpoints, { signIn: `${app.url}/shadow/mcp` });
    assert.equal(manifest.shadow.clients.claudeAi.endpoint, `${app.url}/shadow/mcp`);
  } finally {
    await app.close();
  }
});

test("flag on: the discovery files' URLs follow MCP_PUBLIC_URL, not a forged Host header", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const res = await fetch(`${app.url}/llms.txt`, { headers: { "x-forwarded-host": "evil.example", "x-forwarded-prefix": "/evil" } });
    const text = await res.text();
    assert.ok(!text.includes("evil"));
    assert.ok(text.includes(`${app.url}/shadow/mcp`));
  } finally {
    await app.close();
  }
});

test("a prefixed public URL (staging) carries its prefix on every Shadow URL", () => {
  const base = "https://mcp.clockchain.network/staging";
  for (const text of [shadowInstallSection(base, CHAT), connectInstructions(base, CHAT), JSON.stringify(manifestWithShadow(base, CHAT).shadow)]) {
    const urls = text.match(/https:\/\/[^\s"]+/g);
    assert.ok(urls.length >= 4);
    for (const u of urls) assert.ok(u.startsWith(`${base}/`), u);
  }
  assert.ok(installTxtWithShadow(base, CHAT).includes(`${base}/shadow/connect`));
});

test("/shadow/connect names the chat endpoint, the settings, the account and what is kept where", async () => {
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const res = await fetch(`${app.url}/shadow/connect`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/plain; charset=utf-8");
    const text = await res.text();
    assert.equal(text, connectInstructions(app.url, CHAT));
    assert.match(text, /^Hosted Shadow: connect with sign-in\n/);
    for (const fact of [`${app.url}/shadow/mcp`, `${app.url}${CHAT}`, "Sign in when needed", "Register automatically", `curl -X POST ${app.url}/token`, "An account is required", "30 days"]) {
      assert.ok(text.includes(fact), fact);
    }
  } finally {
    await app.close();
  }
});

// ---- scripts/e2e-shadow-public.mjs ------------------------------------------------

/** Runs the script without blocking this process, which is the server it talks to. */
function runScript(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [SCRIPT, ...args], { env: { ...process.env, ...env }, timeout: 120_000 }, (error, stdout, stderr) => {
      resolve({ code: error ? error.code : 0, stdout, stderr });
    });
  });
}

const NO_SECRETS = /cck_[A-Za-z0-9_-]{8}|cc_[A-Za-z0-9_-]{8}|\/shadow\/[sp]\/[A-Za-z0-9_-]{22}/;

test("script: --write decides what counts as production without trusting the spelling", () => {
  for (const base of [
    "https://mcp.clockchain.network",
    "https://mcp.clockchain.network/",
    "https://MCP.clockchain.network",
    "https://mcp.clockchain.network/staging/..",
    "https://mcp.clockchain.network/stagingish",
    "https://mcp-aws.clockchain.network",
    "https://localhost.evil.example",
    "http://127.0.0.1@evil.example",
    "https://example.com",
  ]) assert.equal(baseKind(base), "production", base);
  for (const base of ["http://127.0.0.1:3000", "http://localhost:3000", "http://[::1]:3000"]) assert.equal(baseKind(base), "local", base);
  assert.equal(baseKind("https://mcp.clockchain.network/staging"), "staging");
  assert.equal(baseKind("https://mcp.clockchain.network/staging/"), "staging");
});

test("script: argument parsing", () => {
  assert.equal(parseArgs([]).base, "https://mcp.clockchain.network");
  assert.equal(parseArgs(["--base", "http://127.0.0.1:1/"]).base, "http://127.0.0.1:1");
  assert.equal(parseArgs(["--base=https://mcp.clockchain.network/staging/"]).base, "https://mcp.clockchain.network/staging");
  assert.equal(parseArgs(["--write"]).write, true);
  for (const bad of [["--base"], ["--base", "nope"], ["--base", "ftp://x"], ["--base", "http://a/?x=1"], ["--nope"]]) assert.ok(parseArgs(bad).error, bad.join(" "));
});

test("script: --write refuses a production base before sending anything, unless told otherwise", async () => {
  // The base would hang or fail if it were ever contacted; a refusal is immediate, with exit code 2.
  for (const args of [["--write"], ["--write", "--base", "https://mcp.clockchain.network"], ["--write", "--base", "https://mcp.clockchain.network/staging/.."], ["--base", "https://example.invalid", "--write"]]) {
    const r = await runScript(args);
    assert.equal(r.code, 2, args.join(" "));
    assert.match(r.stderr, /Refusing --write/);
    assert.equal(r.stdout, "", "no check ran");
  }
});

test("script: read-only against a local server passes, creates no account and writes nothing to the ledger", async () => {
  const ledger = new FakeLedger();
  __setShadowLedgerForTests(ledger);
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const r = await runScript(["--base", app.url]);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /read-only/);
    assert.match(r.stdout, /0 failed, 0 skipped/);
    assert.doesNotMatch(r.stdout, /FAIL|SKIP/);
    assert.doesNotMatch(r.stdout + r.stderr, NO_SECRETS);
    assert.equal(ledger.writes.length, 0, "no ledger write");
    const accounts = path.join(app.stateDir, "accounts");
    assert.deepEqual(existsSync(accounts) ? readdirSync(accounts).filter((f) => f.startsWith("acct_")) : [], [], "no account");
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("script: read-only fails, with exit code 1, against a server that does not advertise Shadow", async () => {
  const app = await boot();
  try {
    const r = await runScript(["--base", app.url]);
    assert.equal(r.code, 1, r.stdout);
    assert.match(r.stdout, /FAIL {2}\/llms\.txt names Shadow/);
    assert.match(r.stdout, /FAIL {2}\/\.well-known\/mcp\.json has a shadow block/);
  } finally {
    await app.close();
  }
});

test("script: --write against a local server signs up and takes one record through to a pass", async () => {
  const ledger = new FakeLedger();
  __setShadowLedgerForTests(ledger);
  const app = await boot({ ...SHADOW_ON(), MCP_OAUTH: "1", SHADOW_LAZY_AUTH: "1" });
  try {
    const r = await runScript(["--write", "--base", app.url]);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /WRITE/);
    for (const step of ["Create an account", "shadow_record message", "shadow_checkpoint anchors", "shadow_verify passes", "The viewer link opens", "The packet link opens", "The same account works on /shadow/mcp"]) {
      assert.ok(r.stdout.includes(`PASS  ${step}`), step);
    }
    assert.doesNotMatch(r.stdout + r.stderr, NO_SECRETS);
    assert.ok(ledger.writes.length > 0, "the ledger was written");
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});
