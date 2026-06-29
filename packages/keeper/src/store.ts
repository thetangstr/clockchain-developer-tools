/**
 * Durable, pluggable store for {@link Trigger}s.
 *
 * The keeper depends only on the {@link KeeperStore} interface, so the backing
 * store is swappable. Two implementations ship:
 *   - {@link FileStore}   — a single JSON file, written atomically (tmp + rename).
 *                           Dependency-free default; survives restart and re-arms
 *                           on boot because every trigger that is not terminal is
 *                           reloaded into the dispatch loop.
 *   - {@link MemoryStore} — in-process only, for tests.
 *
 * TODO (deferred): a SQLite-backed store for higher write throughput and
 * concurrent workers. The interface is intentionally tiny so adding one is a
 * drop-in. Multi-worker coordination (leasing a trigger so two workers don't fire
 * it twice) is also deferred — today assume a single keeper process per store.
 */
import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname } from "node:path";
import type { Trigger } from "./types.js";

export interface KeeperStore {
  /** Load all persisted triggers (called once on boot to re-arm). */
  all(): Promise<Trigger[]>;
  /** Read one trigger by id, or null. */
  get(id: string): Promise<Trigger | null>;
  /** Insert or replace a trigger, durably. */
  put(trigger: Trigger): Promise<void>;
  /** Remove a trigger by id. */
  delete(id: string): Promise<void>;
}

/** In-memory store. Not durable; for tests and ephemeral runs. */
export class MemoryStore implements KeeperStore {
  private readonly map = new Map<string, Trigger>();

  constructor(seed: Trigger[] = []) {
    for (const t of seed) this.map.set(t.id, t);
  }

  async all(): Promise<Trigger[]> {
    return [...this.map.values()].map(clone);
  }
  async get(id: string): Promise<Trigger | null> {
    const t = this.map.get(id);
    return t ? clone(t) : null;
  }
  async put(trigger: Trigger): Promise<void> {
    this.map.set(trigger.id, clone(trigger));
  }
  async delete(id: string): Promise<void> {
    this.map.delete(id);
  }
}

interface FileShape {
  schema: "clockchain.keeper.store/v1";
  triggers: Trigger[];
}

/**
 * JSON-file store. The whole set is held in memory and rewritten on every
 * mutation. Each write goes to a UNIQUE temp file (`${path}.${uuid}.tmp`), is
 * fsync'd, then atomically `rename`d over `path`; the containing dir is fsync'd so
 * the rename survives a crash. Writes are SERIALIZED through an async queue so the
 * tick loop and the HTTP control plane (same process) can't interleave flushes and
 * corrupt the file. Adequate for the first increment (hundreds–thousands of
 * triggers, single instance); swap to SQLite past that.
 */
export class FileStore implements KeeperStore {
  private readonly path: string;
  private map: Map<string, Trigger> | null = null;
  /** Serializes mutations: each write runs after the previous one settles. */
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.path = path;
  }

  /** Run `fn` after all previously-enqueued writes complete (mutual exclusion). */
  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.writeQueue.then(fn);
    // Keep the chain alive even if a write rejects, so later writes still run.
    this.writeQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async load(): Promise<Map<string, Trigger>> {
    if (this.map) return this.map;
    const map = new Map<string, Trigger>();
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed = JSON.parse(raw) as FileShape;
      for (const t of parsed.triggers ?? []) map.set(t.id, t);
    } catch (err) {
      // ENOENT = first run; anything else (corrupt JSON) we surface loudly rather
      // than silently dropping schedules.
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    this.map = map;
    return map;
  }

  /** Durably write the current map to disk: unique tmp -> fsync -> rename -> dir fsync. */
  private async flush(): Promise<void> {
    const map = await this.load();
    const body: FileShape = {
      schema: "clockchain.keeper.store/v1",
      triggers: [...map.values()],
    };
    const dir = dirname(this.path);
    await mkdir(dir, { recursive: true });
    const tmp = `${this.path}.${randomUUID()}.tmp`;
    const fh = await open(tmp, "w");
    try {
      await fh.writeFile(JSON.stringify(body, null, 2), "utf8");
      await fh.sync(); // flush file contents to disk before the rename
    } finally {
      await fh.close();
    }
    await rename(tmp, this.path);
    // fsync the directory so the rename (a dir-entry change) is durable too.
    try {
      const dh = await open(dir, "r");
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch {
      // Directory fsync is unsupported on some platforms/filesystems; the rename
      // is still atomic, so this is a durability nicety, not a correctness gate.
    }
  }

  async all(): Promise<Trigger[]> {
    const map = await this.load();
    return [...map.values()].map(clone);
  }
  async get(id: string): Promise<Trigger | null> {
    const map = await this.load();
    const t = map.get(id);
    return t ? clone(t) : null;
  }
  async put(trigger: Trigger): Promise<void> {
    await this.enqueue(async () => {
      const map = await this.load();
      map.set(trigger.id, clone(trigger));
      await this.flush();
    });
  }
  async delete(id: string): Promise<void> {
    await this.enqueue(async () => {
      const map = await this.load();
      map.delete(id);
      await this.flush();
    });
  }
}

/** Deep clone so callers can't mutate stored state by reference. */
function clone<T>(value: T): T {
  return structuredClone(value);
}
