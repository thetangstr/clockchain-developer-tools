import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fingerprint } from "../dist/shadow/lib/keys.js";
import { AgentKeyBook, AgentKeyError } from "../dist/agent-keys/book.js";

const pem = () => generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
const fresh = () => {
  const dir = join(mkdtempSync(join(tmpdir(), "agent-keys-")), "agent-keys");
  return { dir, book: new AgentKeyBook({ dir, now: () => new Date("2026-11-13T00:00:00Z") }) };
};
const code = (c) => (e) => e instanceof AgentKeyError && e.code === c;

test("admit returns created:true once, then the same entry", () => {
  const { book } = fresh();
  const p = pem();
  const a = book.admit(p);
  assert.equal(a.created, true);
  assert.equal(a.entry.root, a.entry.fingerprint);
  assert.equal(a.entry.status, "active");
  const b = book.admit(p);
  assert.equal(b.created, false);
  assert.deepEqual(b.entry, a.entry);
  assert.equal(book.rootOf(a.entry.fingerprint), a.entry.fingerprint);
  assert.equal(book.get("0".repeat(64)), null);
});

test("admit rejects a non-canonical PEM", () => {
  const { book } = fresh();
  assert.throws(() => book.admit("not a pem"), code("invalid_key"));
  assert.throws(() => book.admit(pem().replace("\n", "\r\n")), code("invalid_key"));
});

test("replace keeps the root and marks the old key replaced", () => {
  const { book } = fresh();
  const a = book.admit(pem()).entry;
  const b = book.replace(a.fingerprint, pem());
  assert.equal(b.root, a.fingerprint);
  assert.equal(b.status, "active");
  const old = book.get(a.fingerprint);
  assert.equal(old.status, "replaced");
  assert.equal(old.replacedBy, b.fingerprint);
  assert.equal(book.rootOf(b.fingerprint), a.fingerprint);
  const c = book.replace(b.fingerprint, pem());
  assert.equal(c.root, a.fingerprint);
  assert.throws(() => book.replace(a.fingerprint, pem()), code("already_replaced"));
});

test("revoke is final", () => {
  const { book } = fresh();
  const a = book.admit(pem()).entry;
  const r = book.revoke(a.fingerprint);
  assert.equal(r.status, "revoked");
  assert.equal(r.revokedAt, "2026-11-13T00:00:00.000Z");
  assert.throws(() => book.revoke(a.fingerprint), code("already_revoked"));
  assert.throws(() => book.replace(a.fingerprint, pem()), code("already_revoked"));
});

test("setFiling records the filing", () => {
  const { book } = fresh();
  const a = book.admit(pem()).entry;
  book.setFiling(a.fingerprint, { state: "filed", ledgerId: "L1", block: 7, filedAt: "2026-11-13T00:00:01Z" });
  const e = book.get(a.fingerprint);
  assert.equal(e.filing.state, "filed");
  assert.deepEqual(e.events, [{ action: "filed", at: "2026-11-13T00:00:01Z", ledgerId: "L1", block: 7 }]);
});

test("a fresh book over the same dir reads the same entries", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  const b = book.replace(a.fingerprint, pem());
  const again = new AgentKeyBook({ dir, now: () => new Date() });
  assert.deepEqual(again.get(a.fingerprint), book.get(a.fingerprint));
  assert.deepEqual(again.get(b.fingerprint), b);
});

test("files are 0600", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, `${a.fingerprint}.json`)).mode & 0o777, 0o600);
  for (const f of readdirSync(dir)) assert.equal(statSync(join(dir, f)).mode & 0o077, 0);
});

test("replace is safe to retry after an interruption", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  const newPem = pem();
  const newFp = fingerprint(newPem);
  // The interruption: only the old key's "replaced" mark reached the disk.
  const path = join(dir, `${a.fingerprint}.json`);
  const stored = JSON.parse(readFileSync(path, "utf8"));
  stored.value.status = "replaced";
  stored.value.replacedBy = newFp;
  writeFileSync(path, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
  assert.equal(book.get(a.fingerprint).status, "replaced");
  assert.equal(book.get(newFp), null);
  const b = book.replace(a.fingerprint, newPem);
  assert.equal(b.fingerprint, newFp);
  assert.equal(b.root, a.fingerprint);
  assert.equal(b.status, "active");
  assert.equal(book.get(a.fingerprint).replacedBy, newFp);
  // A retry once complete returns the same entry; a different key is still refused.
  assert.deepEqual(book.replace(a.fingerprint, newPem), b);
  assert.throws(() => book.replace(a.fingerprint, pem()), code("already_replaced"));
});

test("setEventFiling records where a replace or revoke landed, and never sets a filed event back", () => {
  const { book } = fresh();
  const a = book.admit(pem()).entry;
  assert.throws(() => book.setEventFiling(a.fingerprint, "revoked", { state: "filed", ledgerId: "L0" }), code("no_event"));
  book.replace(a.fingerprint, pem());
  const at = book.get(a.fingerprint).events[0].at;
  // Written, not yet in a block: the ledger id is kept, and the event is still waiting.
  book.setEventFiling(a.fingerprint, "replaced", { state: "pending", ledgerId: "L1" });
  assert.deepEqual(book.get(a.fingerprint).events, [{ action: "replaced", at, ledgerId: "L1" }]);
  book.setEventFiling(a.fingerprint, "replaced", { state: "filed", ledgerId: "L1", block: 9, filedAt: "2026-11-13T00:00:05Z" });
  const filed = { action: "replaced", at, ledgerId: "L1", block: 9, filedAt: "2026-11-13T00:00:05Z" };
  assert.deepEqual(book.get(a.fingerprint).events, [filed]);
  // A late, slower retry can't undo it.
  book.setEventFiling(a.fingerprint, "replaced", { state: "pending" });
  book.setEventFiling(a.fingerprint, "replaced", { state: "unfiled" });
  assert.deepEqual(book.get(a.fingerprint).events, [filed]);
  // The event's own `at` is what its ledger hash was built from, so it never changes.
  assert.equal(book.get(a.fingerprint).events[0].at, at);
});
