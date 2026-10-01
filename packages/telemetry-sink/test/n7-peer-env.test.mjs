import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { startFromEnv } from "../dist/index.js";

// D22 deploy: production ships WITHOUT a staging sink. The peer-key
// requirement exists so an EMPTY compose default cannot silently disable the
// disjoint-key check. TELEMETRY_PEER_ENV="none" is the explicit, literal
// statement that no peer environment exists — the only way prod may boot
// with an empty peer set. Anything else keeps the original refusal.

const dir = () => mkdtempSync(path.join(tmpdir(), "n7-peer-"));
const pub = () => generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
const ports = {
  TELEMETRY_BIND_HOST: "127.0.0.1",
  TELEMETRY_WRITE_PORT: "0", TELEMETRY_READ_PORT: "0", TELEMETRY_CLOSE_PORT: "0",
};

test("prod boots with contract keys and TELEMETRY_PEER_ENV=none (no staging key needed)", async (t) => {
  const servers = startFromEnv({
    TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "production",
    TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server-v1": pub() }),
    TELEMETRY_PEER_ENV: "none",
    TELEMETRY_PEER_CONTRACT_KEYS: "",
    ...ports,
  });
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  assert.ok(servers.close);
});

test("prod without peer keys and without TELEMETRY_PEER_ENV=none still refuses", () => {
  for (const peerEnv of [undefined, "", "None", "staging", "0"]) {
    const env = {
      TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "production",
      TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server-v1": pub() }),
      ...ports,
    };
    if (peerEnv !== undefined) env.TELEMETRY_PEER_ENV = peerEnv;
    assert.throws(() => startFromEnv(env), /TELEMETRY_PEER_CONTRACT_KEYS is required in production|TELEMETRY_PEER_ENV/,
      `peerEnv=${JSON.stringify(peerEnv)}`);
  }
});

test("TELEMETRY_PEER_ENV=none with a non-empty peer set is a contradiction — refused", () => {
  assert.throws(() => startFromEnv({
    TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "production",
    TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server-v1": pub() }),
    TELEMETRY_PEER_CONTRACT_KEYS: JSON.stringify({ "contract-staging": pub() }),
    TELEMETRY_PEER_ENV: "none",
    ...ports,
  }), /TELEMETRY_PEER_ENV=none.*TELEMETRY_PEER_CONTRACT_KEYS/);
});

test("TELEMETRY_PEER_ENV=none never relaxes the contract-key requirement itself", () => {
  assert.throws(() => startFromEnv({
    TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "production",
    TELEMETRY_PEER_ENV: "none",
    ...ports,
  }), /TELEMETRY_CONTRACT_KEYS is required in production/);
});

test("TELEMETRY_PEER_ENV only accepts the literal \"none\" when set", () => {
  assert.throws(() => startFromEnv({
    TELEMETRY_STATE_DIR: dir(), TELEMETRY_ENV: "production",
    TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server-v1": pub() }),
    TELEMETRY_PEER_CONTRACT_KEYS: JSON.stringify({ "contract-staging": pub() }),
    TELEMETRY_PEER_ENV: "yes",
    ...ports,
  }), /TELEMETRY_PEER_ENV must be unset or "none"/);
});
