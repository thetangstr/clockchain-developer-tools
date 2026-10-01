import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  createTokenStore,
  sealToken,
  openSealedToken,
  SealError,
} from "../dist/index.js";

/** x25519 keypair; returns {publicKeyHex, privateKeyJwk} for the seal helpers. */
function x25519Keypair() {
  const kp = generateKeyPairSync("x25519");
  return {
    publicKeyHex: "0x" + Buffer.from(kp.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex"),
    privateKeyJwk: kp.privateKey.export({ format: "jwk" }),
  };
}

const BIND = { runId: "run-1", role: "buyer" };

test("a sealed ingest token round-trips through the services key", () => {
  const store = createTokenStore();
  const services = x25519Keypair();
  const minted = store.mintIngest({ runId: "run-1", role: "buyer" });
  assert.match(minted.token, /^otlp-ing-[0-9a-f]{32}$/);
  assert.equal(minted.record.kind, "ingest");
  assert.equal(minted.record.runId, "run-1");
  assert.equal(minted.record.role, "buyer");

  const sealed = sealToken(services.publicKeyHex, minted.token, BIND);
  assert.equal(sealed.v, 3);
  for (const field of ["epk", "iv", "ct", "tag"]) assert.match(sealed[field], /^0x[0-9a-f]+$/);
  assert.equal(sealed.epk.length, 66); // 0x + 64 hex
  assert.equal(sealed.iv.length, 26); // 0x + 24 hex
  assert.equal(sealed.tag.length, 34); // 0x + 32 hex

  const opened = openSealedToken(services.privateKeyJwk, sealed, BIND);
  assert.equal(opened, minted.token);
});

test("seal fails closed: wrong key, tampered tag/ct, wrong version, wrong runId/role", () => {
  const services = x25519Keypair();
  const other = x25519Keypair();
  const sealed = sealToken(services.publicKeyHex, "otlp-ing-0123456789abcdef0123456789abcdef", BIND);

  assert.throws(() => openSealedToken(other.privateKeyJwk, sealed, BIND), SealError);
  const badTag = { ...sealed, tag: "0x" + "0".repeat(32) };
  assert.throws(() => openSealedToken(services.privateKeyJwk, badTag, BIND), SealError);
  const badCt = { ...sealed, ct: sealed.ct.slice(0, -2) + (sealed.ct.endsWith("00") ? "01" : "00") };
  assert.throws(() => openSealedToken(services.privateKeyJwk, badCt, BIND), SealError);
  const oldVersion = { ...sealed, v: 2 };
  assert.throws(() => openSealedToken(services.privateKeyJwk, oldVersion, BIND), SealError);
  // A box sealed under a different run/role binding cannot be opened under this one.
  const otherRun = sealToken(services.publicKeyHex, "otlp-ing-0123456789abcdef0123456789abcdef", { runId: "run-2", role: "buyer" });
  assert.throws(() => openSealedToken(services.privateKeyJwk, otherRun, BIND), SealError);
  // Re-binding the box to a different recipient ephemeral fails too (AAD context).
  const rebound = { ...sealed, epk: sealToken(other.publicKeyHex, "x", BIND).epk };
  assert.throws(() => openSealedToken(services.privateKeyJwk, rebound, BIND), SealError);
});

test("token kinds are distinct and resolvable only by digest", () => {
  const store = createTokenStore();
  const ing = store.mintIngest({ runId: "run-1", role: "provider" });
  store.markRunUsed("run-1"); // query tokens mint only for existing runs
  const qry = store.mintQuery({ runId: "run-1" });
  assert.match(qry.token, /^otlp-qry-[0-9a-f]{32}$/);
  assert.equal(qry.record.role, null);

  assert.equal(store.resolve(ing.token)?.tokenId, ing.record.tokenId);
  assert.equal(store.resolve(qry.token)?.tokenId, qry.record.tokenId);
  assert.equal(store.resolve("otlp-ing-" + "0".repeat(32)), undefined);
  assert.equal(store.resolve("not-a-token"), undefined);

  // The store never retains plaintext: tokenId is a digest.
  assert.notEqual(ing.record.tokenId, ing.token);
  assert.ok(!JSON.stringify(store.listRecords()).includes(ing.token));
});

test("revoked tokens stop resolving", () => {
  const store = createTokenStore();
  const ing = store.mintIngest({ runId: "run-1", role: "buyer" });
  store.revoke(ing.record.tokenId);
  assert.equal(store.resolve(ing.token), undefined);
});

test("plaintext tokens appear in no minted record, sealed box, or serialized store", () => {
  const store = createTokenStore();
  const services = x25519Keypair();
  const ing = store.mintIngest({ runId: "run-9", role: "buyer" });
  store.markRunUsed("run-9"); // query tokens mint only for existing runs
  const qry = store.mintQuery({ runId: "run-9" });
  const sealed = sealToken(services.publicKeyHex, ing.token, { runId: "run-9", role: "buyer" });
  for (const secret of [ing.token, qry.token]) {
    assert.ok(!JSON.stringify(sealed).includes(secret), "sealed box leaks token");
    assert.ok(!JSON.stringify(ing.record).includes(secret), "record leaks token");
    assert.ok(!JSON.stringify(store.listRecords()).includes(secret), "store leaks token");
  }
});
