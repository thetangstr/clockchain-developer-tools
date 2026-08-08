import { chmodSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  __resetHandshakeStateStore,
  createHandshakeStateStore,
} from "../dist/handshake/state.js";

test("handshake state stores records under hashed principal/session/role keys and deep-copies reads", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "did:example:alice", session: "session-1", role: "requester" };
  await store.put(key, {
    principal: key.principal,
    session: key.session,
    role: key.role,
    status: "active",
    relayEd25519Pem: "-----BEGIN PUBLIC KEY-----\nrelay\n-----END PUBLIC KEY-----",
    data: { nested: { count: 1 } },
    updatedAt: 1000,
  });

  const first = await store.get(key);
  assert.match(first.keyHash, /^[0-9a-f]{64}$/);
  assert.notEqual(first.keyHash, "did:example:alice");
  first.data.nested.count = 99;

  const second = await store.get(key);
  assert.equal(second.data.nested.count, 1);
  assert.deepEqual((await store.list()).map((r) => r.keyHash), [first.keyHash]);
});

test("handshake state update callback is serialized", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "p", session: "s", role: "relay" };

  await Promise.all(
    Array.from({ length: 8 }, () =>
      store.update(key, (record) => ({
        principal: "p",
        session: "s",
        role: "relay",
        status: "active",
        data: { count: Number(record?.data?.count ?? 0) + 1 },
      })),
    ),
  );

  assert.equal((await store.get(key)).data.count, 8);
});

test("MCP_HANDSHAKE_FILE selects durable atomic 0600 file persistence", async () => {
  const dir = mkdtempSync(join(tmpdir(), "clockchain-handshake-"));
  const file = join(dir, "state.json");
  const env = { MCP_HANDSHAKE_FILE: file };
  __resetHandshakeStateStore();
  let store = createHandshakeStateStore(env);
  const key = { principal: "p-file", session: "s-file", role: "owner" };
  await store.put(key, {
    principal: "p-file",
    session: "s-file",
    role: "owner",
    status: "complete",
    data: { ok: true },
  });

  assert.equal((statSync(file).mode & 0o777), 0o600);
  const raw = readFileSync(file, "utf8");
  assert.doesNotMatch(raw, /p-file|s-file|owner/);

  __resetHandshakeStateStore();
  store = createHandshakeStateStore(env);
  assert.equal((await store.get(key)).data.ok, true);
});

test("handshake state rejects private key, mnemonic, and seed fields but allows relayEd25519Pem", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "p", session: "s", role: "relay" };

  await store.put(key, {
    principal: "p",
    session: "s",
    role: "relay",
    status: "active",
    relayEd25519Pem: "-----BEGIN PUBLIC KEY-----\nrelay\n-----END PUBLIC KEY-----",
  });

  await assert.rejects(
    store.put(key, {
      principal: "p",
      session: "s",
      role: "relay",
      status: "active",
      data: { privateKey: "nope" },
    }),
    /private key, mnemonic, seed, or plaintext credential/i,
  );
});

test("handshake state rejects nested plaintext API and auth credential fields", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "p", session: "s", role: "relay" };
  const forbiddenRecords = [
    { data: { apiKey: "secret" } },
    { data: { auth: { accessToken: "secret" } } },
    { data: { headers: [{ bearerToken: "secret" }] } },
    { data: { oauth: { auth_token: "secret" } } },
    { data: { clientSecret: "secret" } },
    { data: { password: "secret" } },
    { data: { passphrase: "secret" } },
    { data: { credential: "secret" } },
    { data: { nested: { credentials: { value: "secret" } } } },
  ];

  for (const partial of forbiddenRecords) {
    await assert.rejects(
      store.put(key, {
        principal: "p",
        session: "s",
        role: "relay",
        status: "active",
        ...partial,
      }),
      /private key, mnemonic, seed, or plaintext credential/i,
    );
  }
});

test("handshake state rejects party, EVM, and wallet signing secret fields", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "p-signing", session: "s-signing", role: "relay" };
  const forbiddenRecords = [
    { data: { signingSecret: "secret" } },
    { data: { partySigningSecret: "secret" } },
    { data: { evmSigningSecret: "secret" } },
    { data: { walletSigningSecret: "secret" } },
    { data: { nested: { party_signing_secret: "secret" } } },
  ];

  for (const partial of forbiddenRecords) {
    await assert.rejects(
      store.put(key, {
        principal: "p-signing",
        session: "s-signing",
        role: "relay",
        status: "active",
        ...partial,
      }),
      /private key, mnemonic, seed, or plaintext credential/i,
    );
  }
});

test("handshake state allows public key-like fields and the relay Ed25519 PEM exception", async () => {
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({});
  const key = { principal: "p-public", session: "s-public", role: "relay" };

  await store.put(key, {
    principal: "p-public",
    session: "s-public",
    role: "relay",
    status: "active",
    relayEd25519Pem: "-----BEGIN PUBLIC KEY-----\nrelay\n-----END PUBLIC KEY-----",
    data: {
      senderKey: "public-sender-key",
      publicKey: "public-key",
      keyId: "kid-1",
    },
  });

  const record = await store.get(key);
  assert.equal(record.data.senderKey, "public-sender-key");
  assert.equal(record.data.publicKey, "public-key");
  assert.equal(record.data.keyId, "kid-1");
});

test("file-backed handshake state uses fsync-backed crash-durable temp rename writes", async () => {
  const source = readFileSync(new URL("../src/handshake/state.ts", import.meta.url), "utf8");
  assert.match(source, /openSync\([^)]*0o600/s);
  assert.match(source, /fsyncSync\(fd\)/);
  assert.match(source, /closeSync\(fd\)/);
  assert.match(source, /renameSync\(tmp,\s*this\.path\)/);
  assert.match(source, /fsyncDirectory\(dirname\(this\.path\)\)/);
  assert.match(source, /openSync\(path,\s*"r"\)/);
  assert.match(source, /fsyncSync\(dirFd\)/);
  assert.match(source, /unlinkSync\(tmp\)/);
});

test("file-backed handshake state does not leave temp files after successful writes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "clockchain-handshake-clean-"));
  const file = join(dir, "state.json");
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({ MCP_HANDSHAKE_FILE: file });

  await store.put(
    { principal: "p-clean", session: "s-clean", role: "owner" },
    {
      principal: "p-clean",
      session: "s-clean",
      role: "owner",
      status: "complete",
      data: { ok: true },
    },
  );

  assert.deepEqual(readdirSync(dir).sort(), ["state.json"]);
});

test("file-backed handshake state rolls back failed put visibility when flush fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "clockchain-handshake-fail-put-"));
  const parent = join(dir, "not-a-directory");
  const file = join(parent, "state.json");
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({ MCP_HANDSHAKE_FILE: file });
  const key = { principal: "p-fail-put", session: "s-fail-put", role: "owner" };
  writeFileSync(parent, "not a directory");

  await assert.rejects(
    store.put(key, {
      principal: "p-fail-put",
      session: "s-fail-put",
      role: "owner",
      status: "complete",
      data: { shouldNotAppear: true },
    }),
  );
  assert.equal(await store.get(key), null);
});

test("file-backed handshake state rolls back failed delete visibility when flush fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "clockchain-handshake-fail-delete-"));
  const file = join(dir, "state.json");
  __resetHandshakeStateStore();
  const store = createHandshakeStateStore({ MCP_HANDSHAKE_FILE: file });
  const key = { principal: "p-fail-delete", session: "s-fail-delete", role: "owner" };
  await store.put(key, {
    principal: "p-fail-delete",
    session: "s-fail-delete",
    role: "owner",
    status: "complete",
    data: { keep: true },
  });

  chmodSync(dir, 0o500);
  try {
    await assert.rejects(store.update(key, () => null));
    assert.equal((await store.get(key)).data.keep, true);
  } finally {
    chmodSync(dir, 0o700);
  }
});
