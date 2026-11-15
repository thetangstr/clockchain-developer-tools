// The agent key book: a local, public-only record of the Ed25519 public keys agents sign in with. Clockchain holds no
// private keys. One JSON file per key at <dir>/<fingerprint>.json, written with the handshake surfaces' durable writer
// (0700 dirs, 0600 files, fsync, rename, .bak). `root` follows a replaced key back to the agent's first key.
//
// Each key's file object is kept in memory (at most MAX_CACHED, oldest dropped first), so a request reads no disk and the
// object that saw a corrupt main file is the one that writes it. That makes this instance the only writer (one server
// process per state directory): an operator who edits a key file by hand restarts the server.
import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { cleanStaleFiles, createDurableJsonFile, type DurableJsonFile } from "../handshake-core/durable-store.js";
import { ed25519PublicKeyDer, fingerprint } from "../shadow/lib/keys.js";

export type KeyStatus = "active" | "replaced" | "revoked";
export type KeyFiling = { state: "unfiled" | "pending" | "filed"; ledgerId?: string; block?: number; filedAt?: string };
export type KeyEntry = {
  fingerprint: string;
  publicKeyPem: string;
  root: string;
  status: KeyStatus;
  firstSeenAt: string;
  filing: KeyFiling;
  replacedBy?: string;
  revokedAt?: string;
  /**
   * A keyed hash of the address the agent first signed in from (oauth.ts), so the Starter allowance can give each address a
   * share. Only a root key has one; never shown publicly or sent to Clockchain.
   */
  source?: string;
  /** A replaced or revoked event is filed once it has `filedAt`; until then it is waiting for Clockchain. */
  events: { action: "filed" | "replaced" | "revoked"; at: string; ledgerId?: string; block?: number; filedAt?: string }[];
};

export class AgentKeyError extends Error {
  constructor(readonly code: string, message?: string) {
    super(message ?? code);
    this.name = "AgentKeyError";
  }
}

const FINGERPRINT = /^[0-9a-f]{64}$/;
const SOURCE = /^[0-9a-f]{32}$/;
const SCHEMA = "agent-key-v1";
const MAX_BYTES = 64 * 1024;
const MAX_CACHED = 10_000;

type Slot = { file: DurableJsonFile<KeyEntry>; entry: KeyEntry };

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** A key file's entry, which must be the key its file is named for: its public key hashes to `fp`. */
function validEntry(fp: string, v: unknown): KeyEntry {
  if (
    !isObj(v) ||
    v.fingerprint !== fp ||
    typeof v.publicKeyPem !== "string" || !ed25519PublicKeyDer(v.publicKeyPem) || fingerprint(v.publicKeyPem) !== fp ||
    typeof v.root !== "string" || !FINGERPRINT.test(v.root) ||
    (v.status !== "active" && v.status !== "replaced" && v.status !== "revoked") ||
    typeof v.firstSeenAt !== "string" ||
    (v.source !== undefined && (typeof v.source !== "string" || !SOURCE.test(v.source))) ||
    !isObj(v.filing) || !Array.isArray(v.events)
  ) throw new Error("bad agent key file");
  return v as unknown as KeyEntry;
}

export class AgentKeyBook {
  private readonly dir: string;
  private readonly now: () => Date;
  private readonly maxCached: number;
  /** fingerprint -> its one file object and entry, oldest first. */
  private readonly slots = new Map<string, Slot>();

  /** `maxCached` is for tests only. */
  constructor(opts: { dir: string; now: () => Date; maxCached?: number }) {
    this.dir = opts.dir;
    this.now = opts.now;
    this.maxCached = opts.maxCached ?? MAX_CACHED;
    cleanStaleFiles(this.dir);
  }

  get(fp: string): KeyEntry | null {
    if (!FINGERPRINT.test(fp)) return null;
    const cached = this.slots.get(fp);
    if (cached) {
      this.slots.delete(fp);
      this.slots.set(fp, cached);
      return structuredClone(cached.entry);
    }
    const slot = this.open(fp);
    const entry = slot.file.load();
    // An unknown key is not cached, so a flood of them costs no memory.
    if (entry === undefined) return null;
    slot.entry = entry;
    this.keep(fp, slot);
    return structuredClone(entry);
  }

  /** A new key is stored with `source`; a known key keeps what it has. */
  admit(publicKeyPem: string, source?: string): { entry: KeyEntry; created: boolean } {
    const fp = this.fingerprintOf(publicKeyPem);
    const existing = this.get(fp);
    if (existing) return { entry: existing, created: false };
    if (source !== undefined && !SOURCE.test(source)) throw new AgentKeyError("invalid_source");
    const entry: KeyEntry = {
      fingerprint: fp,
      publicKeyPem,
      root: fp,
      status: "active",
      firstSeenAt: this.now().toISOString(),
      filing: { state: "unfiled" },
      events: [],
      ...(source !== undefined ? { source } : {}),
    };
    this.save(entry);
    return { entry, created: true };
  }

  rootOf(fp: string): string | null {
    return this.get(fp)?.root ?? null;
  }

  setFiling(fp: string, filing: KeyFiling): void {
    const entry = this.must(fp);
    entry.filing = filing;
    if (filing.state === "filed") {
      entry.events.push({ action: "filed", at: filing.filedAt ?? this.now().toISOString(), ...(filing.ledgerId !== undefined && { ledgerId: filing.ledgerId }), ...(filing.block !== undefined && { block: filing.block }) });
    }
    this.save(entry);
  }

  /**
   * Records where the latest `action` event landed on Clockchain (fileKey's result for "replaced" or "revoked"). The event's
   * `at` never changes, since its ledger hash is built from it, and a filed event is never set back by a later, slower try.
   */
  setEventFiling(fp: string, action: "replaced" | "revoked", filing: KeyFiling): void {
    const entry = this.must(fp);
    const event = [...entry.events].reverse().find((e) => e.action === action);
    if (!event) throw new AgentKeyError("no_event");
    if (event.filedAt !== undefined) return;
    if (filing.ledgerId !== undefined) event.ledgerId = filing.ledgerId;
    if (filing.state === "filed") {
      if (filing.block !== undefined) event.block = filing.block;
      event.filedAt = filing.filedAt ?? this.now().toISOString();
    } else if (filing.ledgerId === undefined) {
      return;
    }
    this.save(entry);
  }

  /**
   * The old key is marked replaced (with replacedBy) before the new entry is written, so an interruption never leaves
   * the old key valid. Calling replace again with the same new key finishes the job.
   */
  replace(oldFp: string, newPem: string): KeyEntry {
    const old = this.must(oldFp);
    if (old.status === "revoked") throw new AgentKeyError("already_revoked");
    const newFp = this.fingerprintOf(newPem);
    if (old.status === "replaced" && old.replacedBy !== newFp) throw new AgentKeyError("already_replaced");
    const existing = this.get(newFp);
    if (existing) {
      if (old.replacedBy === newFp && existing.root === old.root) return existing;
      throw new AgentKeyError("key_exists");
    }
    if (newFp === oldFp) throw new AgentKeyError("key_exists");
    const at = this.now().toISOString();
    if (old.status === "active") {
      old.status = "replaced";
      old.replacedBy = newFp;
      old.events.push({ action: "replaced", at });
      this.save(old);
    }
    const fresh: KeyEntry = { fingerprint: newFp, publicKeyPem: newPem, root: old.root, status: "active", firstSeenAt: at, filing: { state: "unfiled" }, events: [] };
    this.save(fresh);
    return fresh;
  }

  revoke(fp: string): KeyEntry {
    const entry = this.must(fp);
    if (entry.status === "revoked") throw new AgentKeyError("already_revoked");
    const at = this.now().toISOString();
    entry.status = "revoked";
    entry.revokedAt = at;
    entry.events.push({ action: "revoked", at });
    this.save(entry);
    return entry;
  }

  /**
   * Removes keys nobody used: an active root key, with no replacement, no events and no filing (not even a pending one),
   * first seen before `firstSeenBefore`, for which `inUse` (Shadow has an owner for it) is false. A file that can't be read
   * is kept. Synchronous from the check to the unlink, so no grant or route can come in between. Returns how many it removed.
   */
  forgetUnused(opts: { firstSeenBefore: Date; inUse: (fp: string) => boolean }): number {
    if (!existsSync(this.dir)) return 0;
    const before = opts.firstSeenBefore.getTime();
    let removed = 0;
    for (const name of readdirSync(this.dir)) {
      const fp = /^([0-9a-f]{64})\.json$/.exec(name)?.[1];
      if (!fp) continue;
      const path = join(this.dir, name);
      let entry: KeyEntry | null;
      try {
        // An unused key is written once, at admit, so a file written since the cutoff isn't opened.
        if (statSync(path).mtimeMs >= before) continue;
        entry = this.get(fp);
      } catch {
        continue;
      }
      if (
        !entry || entry.status !== "active" || entry.root !== fp || entry.replacedBy !== undefined || entry.events.length > 0 ||
        entry.filing.state !== "unfiled" || !(Date.parse(entry.firstSeenAt) < before) || opts.inUse(fp)
      ) continue;
      // The backup first: an interruption between the two leaves the main file, never a backup to restore it from.
      rmSync(`${path}.bak`, { force: true });
      rmSync(path, { force: true });
      this.slots.delete(fp);
      removed++;
    }
    return removed;
  }

  private fingerprintOf(pem: string): string {
    if (!ed25519PublicKeyDer(pem)) throw new AgentKeyError("invalid_key");
    return fingerprint(pem);
  }

  private must(fp: string): KeyEntry {
    const entry = this.get(fp);
    if (!entry) throw new AgentKeyError("unknown_key");
    return entry;
  }

  /** Writes through the key's own file object; on failure the slot is dropped, so the next get() reads the disk. */
  private save(entry: KeyEntry): void {
    const fp = entry.fingerprint;
    let slot = this.slots.get(fp);
    if (!slot) {
      slot = this.open(fp);
      slot.file.load();
    }
    slot.entry = structuredClone(entry);
    try {
      slot.file.save("now");
    } catch (error) {
      this.slots.delete(fp);
      throw error;
    }
    this.keep(fp, slot);
  }

  private open(fp: string): Slot {
    const slot = { entry: undefined } as unknown as Slot;
    slot.file = createDurableJsonFile<KeyEntry>({ path: join(this.dir, `${fp}.json`), schema: SCHEMA, snapshot: () => slot.entry, validate: (v) => validEntry(fp, v), maxBytes: MAX_BYTES });
    return slot;
  }

  private keep(fp: string, slot: Slot): void {
    this.slots.delete(fp);
    this.slots.set(fp, slot);
    while (this.slots.size > this.maxCached) this.slots.delete(this.slots.keys().next().value as string);
  }
}
