// The agent key book: a local, public-only record of the Ed25519 public keys agents sign in with. Clockchain holds no
// private keys. One JSON file per key at <dir>/<fingerprint>.json, written with the handshake surfaces' durable writer
// (0700 dirs, 0600 files, fsync, rename, .bak). `root` follows a replaced key back to the agent's first key.
import { join } from "node:path";
import { createDurableJsonFile } from "../handshake-core/durable-store.js";
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
  events: { action: "filed" | "replaced" | "revoked"; at: string; ledgerId?: string; block?: number }[];
};

export class AgentKeyError extends Error {
  constructor(readonly code: string, message?: string) {
    super(message ?? code);
    this.name = "AgentKeyError";
  }
}

const FINGERPRINT = /^[0-9a-f]{64}$/;
const SCHEMA = "agent-key-v1";
const MAX_BYTES = 64 * 1024;

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function validEntry(v: unknown): KeyEntry {
  if (
    !isObj(v) ||
    typeof v.fingerprint !== "string" || !FINGERPRINT.test(v.fingerprint) ||
    typeof v.publicKeyPem !== "string" ||
    typeof v.root !== "string" || !FINGERPRINT.test(v.root) ||
    (v.status !== "active" && v.status !== "replaced" && v.status !== "revoked") ||
    typeof v.firstSeenAt !== "string" ||
    !isObj(v.filing) || !Array.isArray(v.events)
  ) throw new Error("bad agent key file");
  return v as unknown as KeyEntry;
}

export class AgentKeyBook {
  private readonly dir: string;
  private readonly now: () => Date;

  constructor(opts: { dir: string; now: () => Date }) {
    this.dir = opts.dir;
    this.now = opts.now;
  }

  get(fp: string): KeyEntry | null {
    if (!FINGERPRINT.test(fp)) return null;
    return this.file(fp, () => { throw new Error("not loaded"); }).load() ?? null;
  }

  admit(publicKeyPem: string): { entry: KeyEntry; created: boolean } {
    const fp = this.fingerprintOf(publicKeyPem);
    const existing = this.get(fp);
    if (existing) return { entry: existing, created: false };
    const entry: KeyEntry = {
      fingerprint: fp,
      publicKeyPem,
      root: fp,
      status: "active",
      firstSeenAt: this.now().toISOString(),
      filing: { state: "unfiled" },
      events: [],
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

  private fingerprintOf(pem: string): string {
    if (!ed25519PublicKeyDer(pem)) throw new AgentKeyError("invalid_key");
    return fingerprint(pem);
  }

  private must(fp: string): KeyEntry {
    const entry = this.get(fp);
    if (!entry) throw new AgentKeyError("unknown_key");
    return entry;
  }

  private save(entry: KeyEntry): void {
    this.file(entry.fingerprint, () => entry).save("now");
  }

  private file(fp: string, snapshot: () => KeyEntry) {
    return createDurableJsonFile<KeyEntry>({ path: join(this.dir, `${fp}.json`), schema: SCHEMA, snapshot, validate: validEntry, maxBytes: MAX_BYTES });
  }
}
