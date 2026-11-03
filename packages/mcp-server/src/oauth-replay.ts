import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { appendDurableLine, cleanStaleFiles, createDurableJsonFile, DurableStateError } from "./handshake-core/durable-store.js";

/**
 * The OAuth server's replay state (src/oauth.ts): spent authorization codes, spent refresh tokens and revoked
 * refresh-token families, each an id with an expiry (unix seconds). Entries are kept only until the artifact they
 * guard expires; after that the artifact is refused on its own.
 *
 * `durableExpiringSet` keeps a set across restarts under `<MCP_STATE_DIR>/oauth/` with the handshake surfaces'
 * durable helpers: a snapshot `<name>.json` (fsync, rename, .bak) plus an append-only journal `<name>.jsonl`
 * (one fsync'd line per entry, written before the token response leaves). Opening merges both, drops expired
 * entries, writes a fresh snapshot and removes the journal; a journal past its bound is compacted the same way.
 * A torn last journal line (a crash mid-append) is skipped. A corrupt snapshot with no valid backup throws, and the
 * token endpoint then refuses closed. Ids are artifact jtis and family ids, never tokens.
 */

export interface ExpiringSet {
  has(key: string): boolean;
  /** Records `key` until `exp`. The durable set writes it to disk first and throws if it cannot. */
  add(key: string, exp: number): void;
  size(): number;
}

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const SNAPSHOT_MAX_BYTES = 48 * 1024 * 1024;
const JOURNAL_MAX_BYTES = 4 * 1024 * 1024;

function sweep(entries: Map<string, number>, now: number): void {
  for (const [k, e] of entries) if (now >= e) entries.delete(k);
}

/** Entries live until their expiry; past `cap`, the oldest entry is evicted first (best effort under a flood). */
export function memoryExpiringSet(cap: number, nowSec: () => number): ExpiringSet {
  const entries = new Map<string, number>();
  let nextSweep = 0;
  return {
    has: (key) => {
      const exp = entries.get(key);
      return exp !== undefined && nowSec() < exp;
    },
    add: (key, exp) => {
      const t = nowSec();
      if (t >= nextSweep || entries.size >= cap) {
        sweep(entries, t);
        nextSweep = t + 60;
      }
      while (entries.size >= cap) entries.delete(entries.keys().next().value as string);
      entries.set(key, exp);
    },
    size: () => entries.size,
  };
}

function validEntry(value: unknown): value is [string, number] {
  return Array.isArray(value) && value.length === 2 && typeof value[0] === "string" && ID.test(value[0]) &&
    typeof value[1] === "number" && Number.isSafeInteger(value[1]);
}

/** A set that survives restarts (see the module comment). Throws when its files cannot be opened or are corrupt. */
export function durableExpiringSet(dir: string, name: string, cap: number, nowSec: () => number): ExpiringSet {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  cleanStaleFiles(dir);
  const memory = memoryExpiringSet(cap, nowSec);
  const live = new Map<string, number>(); // mirrors `memory`, for snapshots
  const journal = join(dir, `${name}.jsonl`);
  const snapshot = createDurableJsonFile<[string, number][]>({
    path: join(dir, `${name}.json`),
    schema: `oauth-${name}-v1`,
    snapshot: () => {
      sweep(live, nowSec());
      return [...live];
    },
    validate: (value) => {
      if (!Array.isArray(value) || !value.every(validEntry)) throw new Error("bad entry list");
      return value as [string, number][];
    },
    maxBytes: SNAPSHOT_MAX_BYTES,
  });

  const remember = (key: string, exp: number) => {
    memory.add(key, exp);
    live.set(key, exp);
    while (live.size > cap) live.delete(live.keys().next().value as string);
  };
  const compact = () => {
    snapshot.save("now"); // the merged state is durable before the journal goes
    if (existsSync(journal)) unlinkSync(journal);
  };

  const now = nowSec();
  for (const [key, exp] of snapshot.load() ?? []) if (now < exp) remember(key, exp);
  if (existsSync(journal)) {
    for (const line of readFileSync(journal, "utf8").split("\n")) {
      if (!line) continue;
      try {
        const entry = JSON.parse(line) as unknown;
        if (validEntry(entry) && now < entry[1]) remember(entry[0], entry[1]);
      } catch {
        // A torn final line from a crash mid-append: that entry's response never left.
      }
    }
  }
  compact();

  return {
    has: (key) => memory.has(key),
    add: (key, exp) => {
      if (!ID.test(key) || !Number.isSafeInteger(exp)) throw new DurableStateError("bad replay-state entry");
      const line = JSON.stringify([key, exp]);
      try {
        appendDurableLine(journal, line, JOURNAL_MAX_BYTES);
      } catch (error) {
        if (!(error instanceof DurableStateError)) throw error;
        compact(); // past its bound: fold the journal into a snapshot, then append to a fresh one
        appendDurableLine(journal, line, JOURNAL_MAX_BYTES);
      }
      remember(key, exp);
    },
    size: () => memory.size(),
  };
}
