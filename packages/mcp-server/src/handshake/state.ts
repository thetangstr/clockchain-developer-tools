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

class InMemoryHandshakeStateStore implements HandshakeStateStore {
  protected records = new Map<string, HandshakeRecord>();
  private mutationQueue: Promise<unknown> = Promise.resolve();

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
      const draft = cloneRecords(this.records);
      if (next === null) {
        draft.delete(keyHash);
        await this.flush(draft);
        this.records = draft;
        return null;
      }
      const stored = prepareRecord(key, keyHash, next, current);
      draft.set(keyHash, stored);
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
  constructor(private readonly path: string) {
    super();
    this.load();
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
      writeFileSync(fd, JSON.stringify(data, null, 2), { encoding: "utf8" });
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

export function createIsolatedHandshakeStateStore(path?: string): HandshakeStateStore {
  return path ? new FileHandshakeStateStore(path) : new InMemoryHandshakeStateStore();
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

function cloneRecords(records: Map<string, HandshakeRecord>): Map<string, HandshakeRecord> {
  return new Map(Array.from(records.entries(), ([key, record]) => [key, clone(record)]));
}

function fsyncDirectory(path: string): void {
  const dirFd = openSync(path, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}
