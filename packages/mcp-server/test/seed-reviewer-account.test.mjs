// scripts/seed-reviewer-account.mjs against a local server on a fake ledger: it creates the account, writes the key only to
// its file, seeds samples, can run again with no change, replaces samples close to expiry, and refuses production.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { parseArgs, SAMPLES, signIn, toolCaller, topUpSamples } from "../../../scripts/seed-reviewer-account.mjs";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const SCRIPT = fileURLToPath(new URL("../../../scripts/seed-reviewer-account.mjs", import.meta.url));
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "MCP_LOG_BUDGET", "MCP_OAUTH_APPROVALS_PER_HOUR"];
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `seed-reviewer-${label}-`));

async function boot() {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const fake = new FakeLedger();
  __setShadowLedgerForTests(fake);
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  const stateDir = tmp("state");
  const url = `http://127.0.0.1:${port}`;
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "seed-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"), MCP_OAUTH: "1", MCP_PUBLIC_URL: url, SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", MCP_OAUTH_APPROVALS_PER_HOUR: "1000" });
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url, fake,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [SCRIPT, ...args], { timeout: 60_000, env: { PATH: process.env.PATH } }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }));
});

test("arguments: --base and --key-file are required; a bad URL or refresh window is refused", () => {
  assert.match(parseArgs([]).error, /--base/);
  assert.match(parseArgs(["--base", "http://localhost:1"]).error, /--key-file/);
  assert.match(parseArgs(["--base", "nope", "--key-file", "k"]).error, /not a URL/);
  assert.match(parseArgs(["--base", "http://localhost:1", "--key-file", "k", "--refresh-days", "30"]).error, /refresh-days/);
  assert.equal(parseArgs(["--base", "http://localhost:1/", "--key-file", "k"]).base, "http://localhost:1");
});

test("production is refused before anything is sent or written, and an unknown host counts as production", async () => {
  const dir = tmp("refused");
  for (const base of ["https://mcp.clockchain.network", "https://mcp-aws.clockchain.network", "https://example.com"]) {
    const keyFile = path.join(dir, "key.txt");
    const r = await run(["--base", base, "--key-file", keyFile]);
    assert.equal(r.code, 2, base);
    assert.match(r.stderr, /Refusing/, base);
    assert.match(r.stderr, /--allow-production/, base);
    assert.equal(existsSync(keyFile), false, base);
  }
});

test("first run creates the account and samples, with the key only in its file; a second run signs in and changes nothing", async () => {
  const s = await boot();
  try {
    const keyFile = path.join(tmp("key"), "reviewer.txt");
    const first = await run(["--base", s.url, "--key-file", keyFile]);
    assert.equal(first.code, 0, first.stderr + first.stdout);
    const file = readFileSync(keyFile, "utf8");
    const key = /Key: (cck_[A-Za-z0-9_-]{32})/.exec(file)[1];
    assert.equal(statSync(keyFile).mode & 0o777, 0o600);
    assert.equal((first.stdout + first.stderr).includes(key), false, "the key is printed nowhere");
    assert.doesNotMatch(first.stdout + first.stderr, /cck_|cc_[A-Za-z0-9]{10}/);
    assert.match(first.stdout, /samples: 3 added, 0 still fresh, 0 old ones deleted/);
    for (const line of first.stdout.split("\n").filter((l) => l.startsWith("- "))) assert.match(line, /^- Sample \(fictional\): .*: started .*verify pass$/);
    assert.equal(first.stdout.split("\n").filter((l) => l.startsWith("- ")).length, SAMPLES.length);
    assert.match(file, /I have an account key/);
    assert.match(file, /fictional/);
    const writes = s.fake.writes.length;
    assert.equal(writes, 3 * SAMPLES.length, "3 ledger writes per sample, as the script says");

    const second = await run(["--base", s.url, "--key-file", keyFile]);
    assert.equal(second.code, 0, second.stderr + second.stdout);
    assert.match(second.stdout, /signing in with the key file/);
    assert.match(second.stdout, /samples: 0 added, 3 still fresh, 0 old ones deleted/);
    assert.equal(s.fake.writes.length, writes, "no new ledger writes");
    assert.equal(readFileSync(keyFile, "utf8"), file, "the file isn't touched");

    // The key works as a reviewer would use it, and the samples are all there.
    const { token } = await signIn(s.url, { key });
    const call = toolCaller(s.url, token);
    assert.deepEqual((await call("shadow_list_sessions")).sessions.map((x) => x.title).sort(), SAMPLES.map((x) => x.title).sort());

    // Near expiry: replaced, one for one, with no duplicates left.
    const later = Date.now() + 25 * 86_400_000;
    assert.deepEqual(await topUpSamples(call, { refreshDays: 10, nowMs: later }), { added: 3, kept: 0, removed: 3 });
    assert.equal((await call("shadow_list_sessions")).sessions.length, 3);
    assert.deepEqual(await topUpSamples(call, { refreshDays: 10 }), { added: 0, kept: 3, removed: 0 });
  } finally {
    await s.close();
  }
});

test("a key file with no key, or a key that doesn't work, stops with nothing changed", async () => {
  const s = await boot();
  try {
    const dir = tmp("badkey");
    const empty = path.join(dir, "empty.txt");
    writeFileSync(empty, "nothing here\n");
    const r = await run(["--base", s.url, "--key-file", empty]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /holds no account key/);

    const wrong = path.join(dir, "wrong.txt");
    writeFileSync(wrong, `Key: cck_${"A".repeat(32)}\n`);
    const w = await run(["--base", s.url, "--key-file", wrong]);
    assert.equal(w.code, 1);
    assert.match(w.stderr, /signing in with the key in the key file: HTTP 400/);
    assert.equal(s.fake.writes.length, 0);
  } finally {
    await s.close();
  }
});
