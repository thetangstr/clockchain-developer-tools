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
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
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
 * mutation. Writes go to `${path}.tmp` then `rename` over `path`, which is atomic
 * on POSIX — a crash mid-write never corrupts the live file. Adequate for the
 * first increment (hundreds–thousands of triggers); swap to SQLite past that.
 */
export class FileStore implements KeeperStore {
  private readonly path: string;
  private map: Map<string, Trigger> | null = null;

  constructor(path: string) {
    this.path = path;
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

  private async flush(): Promise<void> {
    const map = await this.load();
    const body: FileShape = {
      schema: "clockchain.keeper.store/v1",
      triggers: [...map.values()],
    };
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(body, null, 2), "utf8");
    await rename(tmp, this.path);
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
    const map = await this.load();
    map.set(trigger.id, clone(trigger));
    await this.flush();
  }
  async delete(id: string): Promise<void> {
    const map = await this.load();
    map.delete(id);
    await this.flush();
  }
}

/** Deep clone so callers can't mutate stored state by reference. */
function clone<T>(value: T): T {
  return structuredClone(value);
}
