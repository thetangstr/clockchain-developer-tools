import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
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
  let { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  const newPem = pem();
  const newFp = fingerprint(newPem);
  // The interruption: only the old key's "replaced" mark reached the disk.
  const path = join(dir, `${a.fingerprint}.json`);
  const stored = JSON.parse(readFileSync(path, "utf8"));
  stored.value.status = "replaced";
  stored.value.replacedBy = newFp;
  writeFileSync(path, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
  // The book caches what it wrote, so the restart after the interruption is a new book.
  book = new AgentKeyBook({ dir, now: () => new Date("2026-11-13T00:00:00Z") });
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

test("admit stores a new key's source, and a known key keeps its first one", () => {
  const { book } = fresh();
  const p = pem();
  const first = "a".repeat(32);
  const a = book.admit(p, first);
  assert.equal(a.entry.source, first);
  assert.equal(book.get(a.entry.fingerprint).source, first);
  const b = book.admit(p, "b".repeat(32));
  assert.equal(b.created, false);
  assert.equal(b.entry.source, first);
  assert.equal(book.get(a.entry.fingerprint).source, first);
  // Without one, the entry has no source field at all; a replacement key never gets one of its own.
  const plain = book.admit(pem()).entry;
  assert.equal("source" in plain, false);
  const next = book.replace(a.entry.fingerprint, pem());
  assert.equal("source" in next, false);
  assert.equal(book.get(next.root).source, first, "the root's source is the agent's");
});

test("an entry whose stored source isn't 32 lowercase hex characters is invalid; one without a source loads", () => {
  const { dir, book } = fresh();
  const withSource = book.admit(pem(), "c".repeat(32)).entry;
  const without = book.admit(pem()).entry;
  // As an entry written before sources existed: no field at all.
  const again = new AgentKeyBook({ dir, now: () => new Date() });
  assert.deepEqual(again.get(without.fingerprint), without);
  for (const bad of ["C".repeat(32), "c".repeat(31), "c".repeat(64), 7, null, "203.0.113.7"]) {
    const path = join(dir, `${withSource.fingerprint}.json`);
    const stored = JSON.parse(readFileSync(path, "utf8"));
    stored.value.source = bad;
    writeFileSync(path, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
    // Its backup still holds the good entry, so set that aside too: the bad file alone must not load.
    writeFileSync(`${path}.bak`, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
    assert.throws(() => new AgentKeyBook({ dir, now: () => new Date() }).get(withSource.fingerprint), undefined, `source ${JSON.stringify(bad)}`);
  }
});

// ---- The cache (D2): one durable file object per key, so the corrupt-file guard is kept between reading and writing ----

const NOW = () => new Date("2026-11-13T00:00:00Z");

test("a corrupt key file with a good backup is never rotated over the backup", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  book.setFiling(a.fingerprint, { state: "pending", ledgerId: "L1" });
  const main = join(dir, `${a.fingerprint}.json`);
  const goodBak = readFileSync(`${main}.bak`);
  writeFileSync(main, `${JSON.stringify({ schema: "agent-key-v1", value: {} })}\n`, { mode: 0o600 });
  const again = new AgentKeyBook({ dir, now: NOW });
  assert.deepEqual(again.get(a.fingerprint), a, "the backup's entry");
  again.setFiling(a.fingerprint, { state: "filed", ledgerId: "L2", block: 3, filedAt: "2026-11-13T00:00:02Z" });
  assert.deepEqual(readFileSync(`${main}.bak`), goodBak, "the good backup is kept");
  assert.equal(JSON.parse(readFileSync(main, "utf8")).value.filing.ledgerId, "L2");
  assert.equal(new AgentKeyBook({ dir, now: NOW }).get(a.fingerprint).filing.state, "filed");
});

test("a second get() of a key reads the cache", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  assert.deepEqual(book.get(a.fingerprint), a);
  unlinkSync(join(dir, `${a.fingerprint}.json`));
  assert.deepEqual(book.get(a.fingerprint), a);
  // A key the book has never seen is not cached: a flood of unknown fingerprints costs no memory, and a later file is read.
  const later = pem();
  const fp = fingerprint(later);
  assert.equal(book.get(fp), null);
  new AgentKeyBook({ dir, now: NOW }).admit(later);
  assert.equal(book.get(fp).fingerprint, fp);
});

test("changing what get() or a change returned changes nothing stored", () => {
  const { book } = fresh();
  const admitted = book.admit(pem()).entry;
  const fp = admitted.fingerprint;
  const copy = structuredClone(admitted);
  admitted.status = "revoked";
  const got = book.get(fp);
  got.status = "revoked";
  got.events.push({ action: "revoked", at: "x" });
  got.filing.state = "filed";
  assert.deepEqual(book.get(fp), copy);
  const revoked = book.revoke(fp);
  revoked.events.length = 0;
  assert.equal(book.get(fp).events.length, 1);
});

test("a failed save leaves the book as the disk says", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  // Too big to write: the save throws before anything reaches the disk.
  assert.throws(() => book.setFiling(a.fingerprint, { state: "pending", ledgerId: "x".repeat(70_000) }));
  assert.deepEqual(book.get(a.fingerprint).filing, { state: "unfiled" });
  // The failed key's file object was dropped, so what is on disk now is what the book reads.
  new AgentKeyBook({ dir, now: NOW }).setFiling(a.fingerprint, { state: "pending", ledgerId: "L9" });
  assert.throws(() => book.setFiling(a.fingerprint, { state: "pending", ledgerId: "x".repeat(70_000) }));
  assert.equal(book.get(a.fingerprint).filing.ledgerId, "L9");
});

test("opening the book removes temp files and quarantined copies older than 7 days, and keeps newer ones", () => {
  const { dir, book } = fresh();
  const a = book.admit(pem()).entry;
  const main = join(dir, `${a.fingerprint}.json`);
  const day = 86_400_000;
  const tmp = `${main}.123.abc.tmp`;
  const old = `${main}.corrupt-${Date.now() - 8 * day}`;
  const recent = `${main}.corrupt-${Date.now() - 6 * day}`;
  for (const f of [tmp, old, recent]) writeFileSync(f, "x", { mode: 0o600 });
  new AgentKeyBook({ dir, now: NOW });
  assert.equal(existsSync(tmp), false);
  assert.equal(existsSync(old), false);
  assert.equal(existsSync(recent), true);
  assert.equal(existsSync(main), true);
  // A book over a directory that doesn't exist yet opens.
  new AgentKeyBook({ dir: join(dir, "not-yet"), now: NOW });
});

test("past the cache's cap the oldest key is dropped and still loads from disk", () => {
  const { dir } = fresh();
  const book = new AgentKeyBook({ dir, now: NOW, maxCached: 2 });
  const [k1, k2, k3] = [pem(), pem(), pem()].map((p) => book.admit(p).entry.fingerprint);
  const other = new AgentKeyBook({ dir, now: NOW });
  for (const fp of [k1, k2, k3]) other.setFiling(fp, { state: "pending", ledgerId: "L5" });
  assert.equal(book.get(k1).filing.ledgerId, "L5", "dropped, so read from disk");
  assert.equal(book.get(k3).filing.state, "unfiled", "still cached");
  // Reading k1 again made it the newest, so k2 was dropped next.
  assert.equal(book.get(k2).filing.ledgerId, "L5");
});

// ---- Forgetting keys nobody used (D5, FC4): only an active, unfiled root with no history, first seen long ago ----

test("forgetUnused removes only a key nobody used, and keeps every key with history, a filing, an owner or a bad file", () => {
  const DAY = 86_400_000;
  const T0 = Date.parse("2026-11-13T00:00:00Z");
  const clock = { t: T0 - 31 * DAY };
  const dir = join(mkdtempSync(join(tmpdir(), "agent-keys-")), "agent-keys");
  const book = new AgentKeyBook({ dir, now: () => new Date(clock.t) });
  const admitted = () => book.admit(pem()).entry.fingerprint;
  const kept = {};
  kept.revoked = admitted();
  book.revoke(kept.revoked);
  kept.replaced = admitted();
  kept.replacement = book.replace(kept.replaced, pem()).fingerprint;
  kept.filedEvent = admitted();
  book.setFiling(kept.filedEvent, { state: "filed", ledgerId: "L1", block: 1, filedAt: "2026-10-13T00:00:00Z" });
  book.setFiling(kept.filedEvent, { state: "unfiled" }); // a filed event, though the filing reads unfiled
  kept.pending = admitted();
  book.setFiling(kept.pending, { state: "pending", ledgerId: "L2" });
  kept.filed = admitted();
  book.setFiling(kept.filed, { state: "filed", ledgerId: "L3", block: 2 });
  kept.inUse = admitted();
  kept.unreadable = admitted();
  const unused = admitted();
  book.setFiling(unused, { state: "unfiled" }); // so it has a .bak as well
  clock.t = T0 - 29 * DAY;
  kept.young = admitted();
  clock.t = T0;
  writeFileSync(join(dir, `${kept.unreadable}.json`), "not json", { mode: 0o600 });
  // Every file looks old to the mtime prefilter, so each key is kept by its own rule, not by the prefilter.
  const old = (T0 - 31 * DAY) / 1000;
  for (const name of readdirSync(dir)) utimesSync(join(dir, name), old, old);
  const reader = new AgentKeyBook({ dir, now: () => new Date(clock.t) });
  const asked = [];
  const removed = reader.forgetUnused({
    firstSeenBefore: new Date(T0 - 30 * DAY),
    inUse: (fp) => { asked.push(fp); return fp === kept.inUse; },
  });
  assert.equal(removed, 1);
  assert.equal(reader.get(unused), null);
  assert.equal(existsSync(join(dir, `${unused}.json`)), false);
  assert.equal(existsSync(join(dir, `${unused}.json.bak`)), false);
  assert.deepEqual(asked.sort(), [kept.inUse, unused].sort(), "only a key that passes every other rule is asked about");
  for (const [label, fp] of Object.entries(kept)) {
    assert.ok(existsSync(join(dir, `${fp}.json`)), label);
    if (label !== "unreadable") assert.equal(reader.get(fp).fingerprint, fp, label);
  }
  // A file written since the cutoff isn't even opened, whatever it says inside.
  clock.t = T0 - 31 * DAY;
  const written = book.admit(pem()).entry.fingerprint;
  clock.t = T0;
  assert.ok(statSync(join(dir, `${written}.json`)).mtimeMs > T0 - 30 * DAY);
  const newer = new AgentKeyBook({ dir, now: () => new Date(clock.t) });
  assert.equal(newer.forgetUnused({ firstSeenBefore: new Date(T0 - 30 * DAY), inUse: (fp) => fp === kept.inUse }), 0);
  assert.equal(newer.get(written).fingerprint, written);
  // An empty or missing directory is nothing to do.
  assert.equal(new AgentKeyBook({ dir: join(dir, "none"), now: () => new Date() }).forgetUnused({ firstSeenBefore: new Date(), inUse: () => false }), 0);
});
