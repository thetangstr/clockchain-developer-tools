import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createRunLedger,
  createTokenStore,
  startFromEnv,
} from "../dist/index.js";
import { runMintCli } from "../dist/mint-cli.js";

function tmpStateDir() {
  return mkdtempSync(path.join(tmpdir(), "n4b8-review-"));
}

function bootStaging(stateDir) {
  return startFromEnv({
    TELEMETRY_STATE_DIR: stateDir,
    TELEMETRY_ENV: "staging",
    TELEMETRY_BIND_HOST: "127.0.0.1",
    TELEMETRY_WRITE_PORT: "0",
    TELEMETRY_READ_PORT: "0",
    TELEMETRY_CLOSE_PORT: "0",
  });
}

function closeServers(s) {
  s.write.close(); s.read.close(); s.close.close();
}

// ---------------------------------------------------------------------------
// F8 — durable empty-ledger initialization before token provisioning
// ---------------------------------------------------------------------------

test("F8: empty volume → mint → restart lifecycle", async () => {
  const stateDir = tmpStateDir();
  const runsPath = path.join(stateDir, "runs.json");
  const tokensPath = path.join(stateDir, "tokens.json");

  // Boot 1 on a virgin volume: the versioned empty ledger must be durable
  // BEFORE anything can provision tokens.
  const s1 = bootStaging(stateDir);
  closeServers(s1);
  const initDoc = JSON.parse(readFileSync(runsPath, "utf8"));
  assert.equal(initDoc.schema, "ac-telemetry.runs/v1");
  assert.equal(typeof initDoc.initializedAtMs, "number");
  assert.deepEqual(initDoc.runs, {});
  assert.ok(!existsSync(tokensPath), "no tokens yet");

  // Provisioning: the mint path (as `docker compose exec` would run it).
  const code = await runMintCli(["global-query"], { TELEMETRY_STATE_DIR: stateDir });
  assert.equal(code, 0);
  assert.ok(existsSync(tokensPath));

  // Boot 2 — restart before any ingest. The F8 false-positive refused here.
  const s2 = bootStaging(stateDir);
  closeServers(s2);
});

test("F8: mint-cli on a virgin volume initializes the ledger first", async () => {
  const stateDir = tmpStateDir();
  const code = await runMintCli(["global-query"], { TELEMETRY_STATE_DIR: stateDir });
  assert.equal(code, 0);
  const runsPath = path.join(stateDir, "runs.json");
  assert.ok(existsSync(runsPath), "ledger initialized before tokens.json was written");
  const initDoc = JSON.parse(readFileSync(runsPath, "utf8"));
  assert.equal(initDoc.schema, "ac-telemetry.runs/v1");
  assert.deepEqual(initDoc.runs, {});
  // Provisioning-then-restart stays bootable.
  const s = bootStaging(stateDir);
  closeServers(s);
});

test("F8: a genuinely lost initialized ledger still fails closed", async () => {
  const stateDir = tmpStateDir();
  const runsPath = path.join(stateDir, "runs.json");
  const s = bootStaging(stateDir);
  closeServers(s);
  assert.ok(existsSync(runsPath));
  // Provision tokens, then lose the ledger — the marker proves init happened.
  const tokens = createTokenStore({ recordsFile: path.join(stateDir, "tokens.json") });
  tokens.mintGlobalQuery();
  await tokens.flush();
  rmSync(runsPath);
  assert.throws(() => bootStaging(stateDir), /no runs\.json/);
});

test("F8: createRunLedger persists the empty doc only when absent", () => {
  const stateDir = tmpStateDir();
  const runsPath = path.join(stateDir, "runs.json");
  const ledger1 = createRunLedger({ file: runsPath });
  const ino1 = statSync(runsPath).ino;
  const doc1 = JSON.parse(readFileSync(runsPath, "utf8"));
  // Re-construction does NOT rewrite an existing ledger.
  createRunLedger({ file: runsPath });
  assert.equal(statSync(runsPath).ino, ino1);
  // Transition markers merge into the same initialized document.
  ledger1.markOpened("run-1", 1_000);
  const doc2 = JSON.parse(readFileSync(runsPath, "utf8"));
  assert.equal(doc2.initializedAtMs, doc1.initializedAtMs);
  assert.equal(doc2.runs["run-1"].openedAtMs, 1_000);
});
