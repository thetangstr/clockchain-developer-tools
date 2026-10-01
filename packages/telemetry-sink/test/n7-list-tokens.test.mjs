import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTokenStore } from "../dist/index.js";

// M2 reconciliation: a READ-ONLY listing of minted-token records (runId, role,
// kind, tokenId digest, times) the founder diffs against the mint log. Never
// prints plaintext, never writes or creates state files, never takes the lock.
const cli = path.resolve(new URL("../dist/list-tokens-cli.js", import.meta.url).pathname);
const run = (args) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });

async function stateWithTokens() {
  const dir = mkdtempSync(path.join(tmpdir(), "n7-list-"));
  const store = createTokenStore({ recordsFile: path.join(dir, "tokens.json") });
  const buyer = store.mintIngest({ runId: "run-a", role: "buyer" });
  const provider = store.mintIngest({ runId: "run-a", role: "provider" });
  store.mintIngest({ runId: "run-b", role: "buyer" });
  store.markRunUsed("run-a");
  const q = store.mintQuery({ runId: "run-a" });
  const g = store.mintGlobalQuery();
  store.revokeRunIngests("run-a");
  await store.flush();
  return { dir, plaintexts: [buyer.token, provider.token, q.token, g.token], ids: [buyer.record.tokenId, q.record.tokenId] };
}

test("lists every record as one JSON line: runId, role, kind, tokenId, times — no plaintext", async () => {
  const { dir, plaintexts, ids } = await stateWithTokens();
  const r = run(["--state-dir", dir]);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 5);
  for (const l of lines) {
    assert.deepEqual(Object.keys(l).sort(), ["createdAt", "kind", "revokedAt", "role", "runId", "tokenId"]);
    assert.match(l.createdAt, /^\d{4}-\d\d-\d\dT/);
  }
  for (const p of plaintexts) assert.ok(!r.stdout.includes(p), "plaintext never printed");
  assert.ok(lines.some((l) => l.tokenId === ids[0] && l.kind === "ingest" && l.role === "buyer" && l.revokedAt !== null));
  assert.ok(lines.some((l) => l.tokenId === ids[1] && l.kind === "query" && l.role === null));
  assert.ok(lines.some((l) => l.kind === "global-query"));
});

test("--runId filters to that run", async () => {
  const { dir } = await stateWithTokens();
  const r = run(["--state-dir", dir, "--runId", "run-b"]);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => [l.runId, l.role, l.kind]), [["run-b", "buyer", "ingest"]]);
});

test("read-only: never writes, creates, or locks state", async () => {
  const { dir } = await stateWithTokens();
  const before = Object.fromEntries(readdirSync(dir).map((f) => [f, [statSync(path.join(dir, f)).mtimeMs, readFileSync(path.join(dir, f), "utf8")]]));
  assert.equal(run(["--state-dir", dir]).status, 0);
  const after = Object.fromEntries(readdirSync(dir).map((f) => [f, [statSync(path.join(dir, f)).mtimeMs, readFileSync(path.join(dir, f), "utf8")]]));
  assert.deepEqual(after, before);
  // A fresh volume: empty output, exit 0, and no runs.json/tokens.json created.
  const fresh = mkdtempSync(path.join(tmpdir(), "n7-list-fresh-"));
  const r = run(["--state-dir", fresh]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, "");
  assert.deepEqual(readdirSync(fresh), []);
});

test("bad args and a corrupt file fail closed", () => {
  assert.equal(run(["--runId", "bad id!"]).status, 64);
  assert.equal(run(["--bogus"]).status, 64);
  const dir = mkdtempSync(path.join(tmpdir(), "n7-list-bad-"));
  writeFileSync(path.join(dir, "tokens.json"), "{}");
  const r = run(["--state-dir", dir]);
  assert.equal(r.status, 65);
  assert.match(r.stderr, /corrupt/);
  assert.ok(existsSync(path.join(dir, "tokens.json")));
});
