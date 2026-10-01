import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTokenStore, parseContractKeys, startFromEnv } from "../dist/index.js";

function tmpStateDir() {
  return mkdtempSync(path.join(tmpdir(), "n7a-config-"));
}

test("LOW-8: tokens.json lock — async waits, no lost updates, fail-closed flush", async () => {
  const stateDir = tmpStateDir();
  const file = path.join(stateDir, "tokens.json");
  const server = createTokenStore({ recordsFile: file });
  const cli = createTokenStore({ recordsFile: file });

  server.mintIngest({ runId: "run-a", role: "buyer" });
  cli.mintIngest({ runId: "run-b", role: "provider" });
  server.markRunUsed("run-a");
  // Writes are serialized through the async lock queue — flush both writers.
  await server.flush();
  await cli.flush();

  const doc = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(doc.records.length, 2);
  assert.deepEqual([...doc.usedRunIds].sort(), ["run-a"]);
  assert.ok(!existsSync(`${file}.lock`), "lock file is released after the write");

  // A held lock fails CLOSED via flush — the mutation never reaches disk.
  writeFileSync(`${file}.lock`, "999999 held");
  const slowStore = createTokenStore({ recordsFile: file, lockTimeoutMs: 100 });
  slowStore.markRunUsed("run-c");
  await assert.rejects(() => slowStore.flush(), /lock timeout/);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).usedRunIds.includes("run-c"), false);

  // A STALE lock is stolen by rename — a crashed holder cannot wedge writers.
  const old = new Date(Date.now() - 20_000);
  utimesSync(`${file}.lock`, old, old);
  slowStore.markRunUsed("run-c");
  await slowStore.flush();
  assert.equal(JSON.parse(readFileSync(file, "utf8")).usedRunIds.includes("run-c"), true);
});

test("MED: tokens.json present but runs.json missing — boot refuses", () => {
  const stateDir = tmpStateDir();
  writeFileSync(path.join(stateDir, "tokens.json"), JSON.stringify({
    schema: "ac-telemetry.tokens/v1", records: [], revokedTokenIds: [], usedRunIds: [],
  }));
  assert.throws(
    () => startFromEnv({ TELEMETRY_STATE_DIR: stateDir, TELEMETRY_ENV: "staging" }),
    /no runs\.json/,
  );
  // Fresh volume (neither file) boots fine.
  const fresh = tmpStateDir();
  const servers = startFromEnv({
    TELEMETRY_STATE_DIR: fresh, TELEMETRY_ENV: "staging", TELEMETRY_BIND_HOST: "127.0.0.1",
    TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0",
  });
  servers.write.close(); servers.read.close(); servers.close.close();
});

test("LOW: production requires TELEMETRY_PEER_CONTRACT_KEYS too", () => {
  const a = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  assert.throws(
    () => startFromEnv({
      TELEMETRY_STATE_DIR: tmpStateDir(), TELEMETRY_ENV: "production",
      TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server": a }),
    }),
    /TELEMETRY_PEER_CONTRACT_KEYS is required in production/,
  );
});

test("LOW-10: production refuses to boot without TELEMETRY_CONTRACT_KEYS", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n7a-prod-"));
  assert.throws(
    () => startFromEnv({ TELEMETRY_STATE_DIR: stateDir }),
    /TELEMETRY_CONTRACT_KEYS is required in production/,
  );
});

test("LOW-10: staging may boot without contract keys; prod boots with them", async (t) => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n7a-stg-"));
  const servers = startFromEnv({
    TELEMETRY_STATE_DIR: stateDir,
    TELEMETRY_ENV: "staging",
    TELEMETRY_BIND_HOST: "127.0.0.1",
    TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0",
  });
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  assert.ok(servers.write);

  const stg2 = mkdtempSync(path.join(tmpdir(), "n7a-badenv-"));
  assert.throws(
    () => startFromEnv({ TELEMETRY_STATE_DIR: stg2, TELEMETRY_ENV: "qa" }),
    /TELEMETRY_ENV must be "production" or "staging"/,
  );
});

test("MED-6: overlapping prod/staging contract-key sets refuse the boot", () => {
  const pair = generateKeyPairSync("ed25519");
  const pair2 = generateKeyPairSync("ed25519");
  const pubJwk = pair.publicKey.export({ format: "jwk" });
  const pubJwk2 = pair2.publicKey.export({ format: "jwk" });
  const mine = JSON.stringify({ "contract-server": pubJwk });
  const overlappingPeer = JSON.stringify({ "contract-staging": pubJwk }); // same key, different keyId
  const disjointPeer = JSON.stringify({ "contract-staging": pubJwk2 });
  const dir = () => mkdtempSync(path.join(tmpdir(), "n7a-keys-"));

  // Same KEY MATERIAL under a different keyId still counts as overlap.
  assert.throws(
    () => startFromEnv({
      TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "staging",
      TELEMETRY_CONTRACT_KEYS: mine, TELEMETRY_PEER_CONTRACT_KEYS: overlappingPeer,
      TELEMETRY_BIND_HOST: "127.0.0.1",
    }),
    /contract-key overlap/,
  );
});

test("MED-6: disjoint peer keys boot fine", async (t) => {
  const a = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  const b = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  const servers = startFromEnv({
    TELEMETRY_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n7a-keys-")),
    TELEMETRY_ENV: "staging",
    TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server": a }),
    TELEMETRY_PEER_CONTRACT_KEYS: JSON.stringify({ "contract-staging": b }),
    TELEMETRY_BIND_HOST: "127.0.0.1",
    TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0",
  });
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  assert.ok(servers.write);
});

test("MED-6: parseContractKeys still refuses private key material", () => {
  const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  assert.throws(() => parseContractKeys(JSON.stringify({ k: jwk })), /private key material/);
});
