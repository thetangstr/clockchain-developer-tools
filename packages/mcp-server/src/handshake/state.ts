import { createHash, randomBytes } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type HandshakeRole = "requester" | "relay" | "owner" | "agent" | string;
export type HandshakeStatus = "pending" | "active" | "complete" | "failed" | string;

export interface HandshakeKey {
  principal: string;
  session: string;
  role: HandshakeRole;
}

export interface HandshakeRecord extends HandshakeKey {
  keyHash?: string;
  status: HandshakeStatus;
  data?: JsonObject;
  /** Relay Ed25519 PEM material; intentionally named so it is not confused with EVM private keys. */
  relayEd25519Pem?: string;
  createdAt?: number;
  updatedAt?: number;
}

export interface HandshakeStateStore {
  get(key: HandshakeKey): Promise<HandshakeRecord | null>;
  put(key: HandshakeKey, record: HandshakeRecord): Promise<HandshakeRecord>;
  list(): Promise<HandshakeRecord[]>;
  update(key: HandshakeKey, mutate: (current: HandshakeRecord | null) => HandshakeRecord | null): Promise<HandshakeRecord | null>;
}

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
type JsonObject = { [key: string]: JsonValue };
type PersistedHandshakeRecord = Omit<HandshakeRecord, "principal" | "session" | "role">;
type FileShape = { records: Record<string, PersistedHandshakeRecord> };

export interface HandshakeStateStoreOptions {
  /**
   * Drop records whose last update (updatedAt, else createdAt) is older than
   * this many milliseconds, on load and on every persisted write. Unset or
   * non-positive = keep forever (the historical behaviour).
   */
  retentionMs?: number;
  /** Clock for retention (tests). */
  now?: () => number;
}

class InMemoryHandshakeStateStore implements HandshakeStateStore {
  protected records = new Map<string, HandshakeRecord>();
  private mutationQueue: Promise<unknown> = Promise.resolve();

  constructor(protected readonly storeOptions: HandshakeStateStoreOptions = {}) {}

  /** Number of records held in memory (observability/tests). */
  size(): number {
    return this.records.size;
  }

  /** Remove records past the retention window from `records` (never `keep`). */
  protected pruneExpired(records: Map<string, HandshakeRecord>, keep?: string): void {
    const retentionMs = this.storeOptions.retentionMs;
    if (retentionMs === undefined || !Number.isFinite(retentionMs) || retentionMs <= 0) return;
    const cutoff = (this.storeOptions.now ?? Date.now)() - retentionMs;
    for (const [keyHash, record] of records) {
      if (keyHash === keep) continue;
      const last = record.updatedAt ?? record.createdAt;
      if (typeof last === "number" && last < cutoff) records.delete(keyHash);
    }
  }

  async get(key: HandshakeKey): Promise<HandshakeRecord | null> {
    const record = this.records.get(handshakeKeyHash(key));
    return record ? clone(record) : null;
  }

  async put(key: HandshakeKey, record: HandshakeRecord): Promise<HandshakeRecord> {
    return this.update(key, () => record) as Promise<HandshakeRecord>;
  }

  async list(): Promise<HandshakeRecord[]> {
    return Array.from(this.records.values(), clone);
  }

  async update(
    key: HandshakeKey,
    mutate: (current: HandshakeRecord | null) => HandshakeRecord | null,
  ): Promise<HandshakeRecord | null> {
    return this.enqueue(async () => {
      const keyHash = handshakeKeyHash(key);
      const current = this.records.get(keyHash);
      const next = mutate(current ? clone(current) : null);
      // Stored records are private, immutable clones (every read returns a
      // fresh clone and every write stores a fresh one), so the draft only
      // needs a SHALLOW copy of the map. Deep-cloning every record on every
      // mutation made each write O(total state): with the production v2 file
      // (1,607 records, 19 MB) every agent_handshake_next poll cloned the whole
      // store and rewrote 19 MB, which ballooned the V8 heap until the kernel
      // OOM-killed the container (2026-10-08 14:42Z).
      if (next === null) {
        if (current === undefined) return null;
        const draft = new Map(this.records);
        draft.delete(keyHash);
        await this.flush(draft);
        this.records = draft;
        return null;
      }
      const stored = prepareRecord(key, keyHash, next, current);
      if (current !== undefined && samePersistedRecord(current, stored)) {
        // No-op write (e.g. a refresh() poll that observed nothing new): the
        // persisted bytes would be identical, so skip the full-file rewrite.
        this.records.set(keyHash, stored);
        return clone(stored);
      }
      const draft = new Map(this.records);
      draft.set(keyHash, stored);
      this.pruneExpired(draft, keyHash);
      await this.flush(draft);
      this.records = draft;
      return clone(stored);
    });
  }

  protected async flush(_records: Map<string, HandshakeRecord>): Promise<void> {
    // In-memory store has nothing to persist.
  }

  private async enqueue<T>(work: () => Promise<T>): Promise<T> {
    const run = this.mutationQueue.then(work, work);
    this.mutationQueue = run.catch(() => undefined);
    return run;
  }
}

class FileHandshakeStateStore extends InMemoryHandshakeStateStore {
  constructor(private readonly path: string, options: HandshakeStateStoreOptions = {}) {
    super(options);
    this.load();
    // Expired records drop out of memory at boot; the file catches up on the next write.
    this.pruneExpired(this.records);
  }

  private load(): void {
    try {
      const data = JSON.parse(readFileSync(this.path, "utf8")) as Partial<FileShape>;
      for (const [keyHash, record] of Object.entries(data.records ?? {})) {
        this.records.set(keyHash, {
          ...record,
          principal: "",
          session: "",
          role: "",
          keyHash,
          status: record.status ?? "pending",
        });
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new Error(`Failed to load handshake state file ${this.path}: ${(err as Error).message}`);
      }
    }
  }

  protected override async flush(recordsToPersist: Map<string, HandshakeRecord>): Promise<void> {
    const records = Array.from(recordsToPersist.entries(), ([keyHash, record]) => {
      const { principal: _principal, session: _session, role: _role, ...rest } = record;
      return [keyHash, rest] as const;
    });
    const data: FileShape = { records: Object.fromEntries(records) };
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    let fd: number | null = null;
    let renamed = false;
    try {
      fd = openSync(tmp, "wx", 0o600);
      // Compact JSON: the pretty-printed form was ~40% larger (19 MB vs 14 MB in production) for no reader's benefit.
      writeFileSync(fd, JSON.stringify(data), { encoding: "utf8" });
      fsyncSync(fd);
      closeSync(fd);
      fd = null;
      renameSync(tmp, this.path);
      renamed = true;
      fsyncDirectory(dirname(this.path));
    } catch (err) {
      if (fd !== null) {
        try {
          closeSync(fd);
        } catch {
          // Preserve the original write/rename/fsync failure.
        }
      }
      if (!renamed) {
        try {
          unlinkSync(tmp);
        } catch (cleanupErr) {
          if ((cleanupErr as NodeJS.ErrnoException).code !== "ENOENT") {
            // Preserve the original write/rename/fsync failure.
          }
        }
      }
      throw err;
    }
  }

  override async get(key: HandshakeKey): Promise<HandshakeRecord | null> {
    const record = await super.get(key);
    return record ? { ...record, principal: key.principal, session: key.session, role: key.role } : null;
  }
}

let shared: HandshakeStateStore | null = null;

export function createHandshakeStateStore(env: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): HandshakeStateStore {
  if (shared) return shared;
  shared = env.MCP_HANDSHAKE_FILE
    ? new FileHandshakeStateStore(env.MCP_HANDSHAKE_FILE)
    : new InMemoryHandshakeStateStore();
  return shared;
}

export function createIsolatedHandshakeStateStore(
  path?: string,
  options: HandshakeStateStoreOptions = stateStoreOptionsFromEnv(process.env),
): HandshakeStateStore {
  return path ? new FileHandshakeStateStore(path, options) : new InMemoryHandshakeStateStore(options);
}

/**
 * AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS (opt-in, positive number): records not
 * updated for that many days are dropped from the isolated (v2) state store.
 * Unset/invalid = keep forever.
 */
export function stateStoreOptionsFromEnv(env: NodeJS.ProcessEnv | Record<string, string | undefined>): HandshakeStateStoreOptions {
  const days = Number(env.AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS ?? "");
  return Number.isFinite(days) && days > 0 ? { retentionMs: days * 24 * 60 * 60 * 1000 } : {};
}

export function __resetHandshakeStateStore(): void {
  shared = null;
}

export function handshakeKeyHash(key: HandshakeKey): string {
  return createHash("sha256")
    .update(JSON.stringify([key.principal, key.session, key.role]))
    .digest("hex");
}

function prepareRecord(
  key: HandshakeKey,
  keyHash: string,
  record: HandshakeRecord,
  current?: HandshakeRecord,
): HandshakeRecord {
  assertNoPrivateMaterial(record);
  const now = Date.now();
  return clone({
    ...record,
    principal: key.principal,
    session: key.session,
    role: key.role,
    keyHash,
    createdAt: record.createdAt ?? current?.createdAt ?? now,
    updatedAt: record.updatedAt ?? now,
  });
}

function assertNoPrivateMaterial(value: unknown, path = ""): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoPrivateMaterial(item, `${path}[${index}]`));
    return;
  }
  if (typeof value !== "object" || value === null) return;

  for (const [key, child] of Object.entries(value)) {
    if (key !== "relayEd25519Pem" && forbiddenSecretField(key)) {
      throw new Error(`Handshake state must not store private key, mnemonic, seed, or plaintext credential fields (${path ? `${path}.` : ""}${key})`);
    }
    assertNoPrivateMaterial(child, path ? `${path}.${key}` : key);
  }
}

function forbiddenSecretField(key: string): boolean {
  const normalized = key.replace(/[_-]/g, "").toLowerCase();
  return normalized.includes("privatekey")
    || normalized === "mnemonic"
    || normalized.endsWith("mnemonic")
    || normalized === "seed"
    || normalized.endsWith("seed")
    || normalized === "apikey"
    || normalized.endsWith("apikey")
    || normalized === "accesstoken"
    || normalized.endsWith("accesstoken")
    || normalized === "authtoken"
    || normalized.endsWith("authtoken")
    || normalized === "bearertoken"
    || normalized.endsWith("bearertoken")
    || normalized === "clientsecret"
    || normalized.endsWith("clientsecret")
    || normalized === "apisecret"
    || normalized.endsWith("apisecret")
    || normalized === "password"
    || normalized.endsWith("password")
    || normalized === "passphrase"
    || normalized.endsWith("passphrase")
    || normalized.includes("credential")
    || normalized === "signingsecret"
    || normalized.endsWith("signingsecret");
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Whether two records serialize to the same persisted form (key fields are not persisted). */
function samePersistedRecord(a: HandshakeRecord, b: HandshakeRecord): boolean {
  const strip = ({ principal: _p, session: _s, role: _r, ...rest }: HandshakeRecord) => rest;
  return JSON.stringify(strip(a)) === JSON.stringify(strip(b));
}

function fsyncDirectory(path: string): void {
  const dirFd = openSync(path, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}
