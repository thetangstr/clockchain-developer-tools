import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  loadOrCreateSinkKey,
  sinkKeysDoc,
  SINK_KEY_FILE_NAME,
  SINK_KEY_SCHEMA,
} from "../dist/index.js";
import { startFromEnv, parseContractKeys } from "../dist/main.js";

function tmpState() {
  return mkdtempSync(path.join(tmpdir(), "ac-telemetry-n7a-"));
}

function request(port, { method = "GET", path = "/", headers = {}, body } = {}) {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method, headers, body: body === undefined ? undefined : Buffer.from(body),
  }).then(async (res) => ({ status: res.status, body: await res.json() }));
}

describe("N7a sink signing key (volume-backed)", () => {
  it("generates the ed25519 key inside the container on first boot", () => {
    const dir = tmpState();
    try {
      const key = loadOrCreateSinkKey(dir, { env: {} });
      assert.equal(key.created, true);
      assert.match(key.keyId, /^sink-ed25519-[0-9a-f]{32}$/);
      assert.equal(key.privateKey.asymmetricKeyType, "ed25519");
      const file = path.join(dir, SINK_KEY_FILE_NAME);
      const doc = JSON.parse(readFileSync(file, "utf8"));
      assert.equal(doc.schema, SINK_KEY_SCHEMA);
      assert.equal(typeof doc.jwk.d, "string"); // private stays on the volume
      assert.equal(doc.keyId, key.keyId);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("persists across restart when the volume remains (fs-level persistence)", () => {
    const dir = tmpState();
    try {
      const first = loadOrCreateSinkKey(dir, { env: {} });
      const second = loadOrCreateSinkKey(dir, { env: {} }); // "restart"
      assert.equal(second.created, false);
      assert.equal(second.keyId, first.keyId);
      // Same signing identity: a head signed by the first key verifies under the second.
      assert.equal(
        createPublicKey(second.privateKey).export({ format: "jwk" }).x,
        first.publicKeyJwk.x,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("generates a NEW key with a new volume", () => {
    const a = tmpState();
    const b = tmpState();
    try {
      const ka = loadOrCreateSinkKey(a, { env: {} });
      const kb = loadOrCreateSinkKey(b, { env: {} });
      assert.notEqual(ka.keyId, kb.keyId);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  it("refuses boot when a private key is injected via env", () => {
    const dir = tmpState();
    try {
      for (const name of [
        "TELEMETRY_PRIVATE_KEY", "TELEMETRY_SIGNING_KEY", "TELEMETRY_SINK_PRIVATE_KEY",
        "SINK_PRIVATE_KEY", "AC_SINK_PRIVATE_KEY", "TELEMETRY_KEY_JWK",
        "TELEMETRY_PRIVATE_KEY_FILE", "TELEMETRY_SEED",
      ]) {
        assert.throws(
          () => loadOrCreateSinkKey(dir, { env: { [name]: "0xdeadbeef" } }),
          /refusing to boot/,
          name,
        );
      }
      // Public/config vars are NOT key material and must not trip the guard.
      const key = loadOrCreateSinkKey(dir, {
        env: { TELEMETRY_CONTRACT_KEYS: "{}", TELEMETRY_WRITE_PORT: "8081" },
      });
      assert.equal(key.created, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a pre-made private key file (no schema marker)", () => {
    const dir = tmpState();
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      writeFileSync(
        path.join(dir, SINK_KEY_FILE_NAME),
        JSON.stringify(privateKey.export({ format: "jwk" })),
        { mode: 0o600 },
      );
      assert.throws(() => loadOrCreateSinkKey(dir, { env: {} }), /refusing .*sink-key\.json/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a key file with permissive mode", () => {
    const dir = tmpState();
    try {
      loadOrCreateSinkKey(dir, { env: {} });
      chmodSync(path.join(dir, SINK_KEY_FILE_NAME), 0o644);
      assert.throws(() => loadOrCreateSinkKey(dir, { env: {} }), /mode 644/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("N7a /v1/keys publication", () => {
  it("publishes ONLY the public key on the read listener", async () => {
    const dir = tmpState();
    let servers;
    try {
      const key = loadOrCreateSinkKey(dir, { env: {} });
      const tokens = createTokenStore();
      const sink = createTelemetrySink({ signer: key, tokens });
      servers = createTelemetrySinkServer({ sink, tokens, keys: () => sinkKeysDoc(key) });
      await new Promise((r) => servers.read.listen(0, "127.0.0.1", r));
      const port = servers.read.address().port;
      const res = await request(port, { path: "/v1/keys" });
      assert.equal(res.status, 200);
      assert.equal(res.body.schema, "ac-telemetry.sink-keys/v1");
      assert.equal(res.body.keys.length, 1);
      assert.equal(res.body.keys[0].keyId, key.keyId);
      assert.equal(res.body.keys[0].alg, "ed25519");
      assert.equal(typeof res.body.keys[0].publicKeyJwk.x, "string");
      assert.equal(res.body.keys[0].publicKeyJwk.d, undefined);
      assert.equal(JSON.stringify(res.body).includes('"d"'), false);
    } finally {
      servers?.read.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not serve keys on the write listener", async () => {
    const dir = tmpState();
    let servers;
    try {
      const key = loadOrCreateSinkKey(dir, { env: {} });
      const tokens = createTokenStore();
      const sink = createTelemetrySink({ signer: key, tokens });
      servers = createTelemetrySinkServer({ sink, tokens, keys: () => sinkKeysDoc(key) });
      await new Promise((r) => servers.write.listen(0, "127.0.0.1", r));
      const res = await request(servers.write.address().port, { path: "/v1/keys" });
      assert.equal(res.status, 404);
    } finally {
      servers?.write.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("N7a durable token records", () => {
  it("a mint CLI write is visible to a separate store on the same volume", async () => {
    const dir = tmpState();
    const file = path.join(dir, "tokens.json");
    try {
      const cli = createTokenStore({ recordsFile: file });
      const minted = cli.mintIngest({ runId: "run-x", role: "buyer" });
      await cli.flush();
      const server = createTokenStore({ recordsFile: file });
      assert.deepEqual(server.resolve(minted.token)?.tokenId, minted.record.tokenId);
      // The file carries no plaintext credential.
      assert.equal(readFileSync(file, "utf8").includes(minted.token), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("server-side markRunUsed persists — a fresh CLI process sees the used run", async () => {
    const dir = tmpState();
    const file = path.join(dir, "tokens.json");
    try {
      const server = createTokenStore({ recordsFile: file });
      const minted = server.mintIngest({ runId: "run-y", role: "provider" });
      server.markRunUsed("run-y");
      await server.flush();
      const cli = createTokenStore({ recordsFile: file });
      assert.throws(() => cli.mintIngest({ runId: "run-y", role: "buyer" }), /already used/);
      assert.equal(cli.resolve(minted.token)?.runId, "run-y");
      const q = cli.mintQuery({ runId: "run-y" }); // post-seal verifier token still mintable
      assert.equal(q.record.kind, "query");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a corrupt token file is refused at construction", () => {
    const dir = tmpState();
    const file = path.join(dir, "tokens.json");
    try {
      writeFileSync(file, JSON.stringify({ records: [{ tokenId: "plaintext-token" }] }));
      assert.throws(() => createTokenStore({ recordsFile: file }), /corrupt/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("N7a bootstrap env", () => {
  it("startFromEnv refuses to boot with injected key material", () => {
    const dir = tmpState();
    try {
      assert.throws(
        () => startFromEnv({ TELEMETRY_STATE_DIR: dir, TELEMETRY_PRIVATE_KEY: "0xabc" }),
        /refusing to boot/,
      );
      assert.equal(existsSync(path.join(dir, SINK_KEY_FILE_NAME)), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("boots all three listeners with distinct ports", async () => {
    const dir = tmpState();
    let servers;
    try {
      const base = 39000 + Math.floor(Math.random() * 1000);
      const contractPub = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
      const stagingPub = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
      servers = startFromEnv({
        TELEMETRY_STATE_DIR: dir,
        TELEMETRY_ENV: "production",
        TELEMETRY_CONTRACT_KEYS: JSON.stringify({ "contract-server": contractPub }),
        TELEMETRY_PEER_CONTRACT_KEYS: JSON.stringify({ "contract-staging": stagingPub }),
        TELEMETRY_BIND_HOST: "127.0.0.1",
        TELEMETRY_WRITE_PORT: String(base),
        TELEMETRY_READ_PORT: String(base + 1),
        TELEMETRY_CLOSE_PORT: String(base + 2),
      });
      await new Promise((r) => setImmediate(r));
      const w = await request(base, { path: "/v1/health" });
      const rd = await request(base + 1, { path: "/v1/health" });
      const k = await request(base + 1, { path: "/v1/keys" });
      const c = await request(base + 2, { path: "/v1/health" });
      assert.equal(w.status, 200);
      assert.equal(rd.status, 200);
      assert.equal(k.status, 200);
      assert.equal(c.status, 404); // close listener serves nothing but /close
    } finally {
      servers?.write.close(); servers?.read.close(); servers?.close.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parses contract public keys and rejects private material", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
    const keys = parseContractKeys(JSON.stringify({ "contract-v1": pem }));
    assert.equal(keys["contract-v1"].asymmetricKeyType, "ed25519");
    const privJwk = privateKey.export({ format: "jwk" });
    assert.throws(
      () => parseContractKeys(JSON.stringify({ bad: privJwk })),
      /private key material is not allowed/,
    );
  });
});
