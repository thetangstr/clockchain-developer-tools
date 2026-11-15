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
 *
 * A set made with whenFull "refuse" (spent agent assertions) throws ReplayStateFullError from add() while it holds `cap`
 * unexpired entries, instead of evicting one, so a flood can't push out a spent entry that is still valid. Opening such a
 * set with more than `cap` live entries on disk, in its snapshot or its journal (only possible if the cap constant was
 * lowered), throws the same error, so the set fails to open and its endpoint refuses closed (503), as for a corrupt snapshot.
 */

/** Thrown by add() on a set made with whenFull "refuse" that holds `cap` unexpired entries. Nothing was written. */
export class ReplayStateFullError extends Error {
  constructor() {
    super("replay state is full");
    this.name = "ReplayStateFullError";
  }
}

export interface ExpiringSet {
  has(key: string): boolean;
  /** Records `key` until `exp`. The durable set writes it to disk first and throws if it cannot. */
  add(key: string, exp: number): void;
  /** Records every entry or none: the durable set writes them in one journal append. */
  addAll(entries: readonly (readonly [string, number])[]): void;
  /** True when a set made with whenFull "refuse" would refuse a new entry now; always false for "evict". */
  full(): boolean;
  size(): number;
}

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const SNAPSHOT_MAX_BYTES = 48 * 1024 * 1024;
const JOURNAL_MAX_BYTES = 4 * 1024 * 1024;

function sweep(entries: Map<string, number>, now: number): void {
  for (const [k, e] of entries) if (now >= e) entries.delete(k);
}

/**
 * Entries live until their expiry. Past `cap`, "evict" (the default) drops the oldest entry first (best effort under a
 * flood); "refuse" throws ReplayStateFullError instead.
 */
export function memoryExpiringSet(cap: number, nowSec: () => number, whenFull: "evict" | "refuse" = "evict"): ExpiringSet & { roomFor(n: number): boolean } {
  const entries = new Map<string, number>();
  let nextSweep = 0;
  /** Whether `n` more entries fit under `cap`, after sweeping the expired ones when that is due or they wouldn't fit. */
  const roomFor = (n: number) => {
    const t = nowSec();
    if (t >= nextSweep || entries.size + n > cap) {
      sweep(entries, t);
      nextSweep = t + 60;
    }
    return entries.size + n <= cap;
  };
  const add = (key: string, exp: number) => {
    if (!roomFor(1)) {
      // Setting a key it already holds doesn't grow the set (a journal line repeating the snapshot, at boot).
      if (whenFull === "refuse" && !entries.has(key)) throw new ReplayStateFullError();
      while (whenFull === "evict" && entries.size >= cap) entries.delete(entries.keys().next().value as string);
    }
    entries.set(key, exp);
  };
  return {
    has: (key) => {
      const exp = entries.get(key);
      return exp !== undefined && nowSec() < exp;
    },
    add,
    addAll: (items) => {
      if (whenFull === "refuse" && !roomFor(items.filter(([key]) => !entries.has(key)).length)) throw new ReplayStateFullError();
      for (const [key, exp] of items) add(key, exp);
    },
    size: () => entries.size,
    full: () => whenFull === "refuse" && !roomFor(1),
    roomFor,
  };
}

function validEntry(value: unknown): value is [string, number] {
  return Array.isArray(value) && value.length === 2 && typeof value[0] === "string" && ID.test(value[0]) &&
    typeof value[1] === "number" && Number.isSafeInteger(value[1]);
}

/** A set that survives restarts (see the module comment). Throws when its files cannot be opened or are corrupt. */
export function durableExpiringSet(dir: string, name: string, cap: number, nowSec: () => number, whenFull: "evict" | "refuse" = "evict"): ExpiringSet {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  cleanStaleFiles(dir);
  const memory = memoryExpiringSet(cap, nowSec, whenFull);
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
    while (whenFull === "evict" && live.size > cap) live.delete(live.keys().next().value as string);
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
      let entry: unknown;
      try {
        entry = JSON.parse(line);
      } catch {
        // A torn final line from a crash mid-append: that entry's response never left.
        continue;
      }
      // Outside the try: a refusing set past its cap throws ReplayStateFullError and fails to open, as for a snapshot.
      if (validEntry(entry) && now < entry[1]) remember(entry[0], entry[1]);
    }
  }
  compact();

  /** Every entry in one fsync'd append (lines, so a torn last one is skipped at boot), remembered only once it is written. */
  const addAll = (items: readonly (readonly [string, number])[]) => {
    for (const [key, exp] of items) if (!ID.test(key) || !Number.isSafeInteger(exp)) throw new DurableStateError("bad replay-state entry");
    // Not a DurableStateError, so the compact-and-retry below never catches it; and checked first, so it journals nothing.
    if (whenFull === "refuse" && !memory.roomFor(items.length)) throw new ReplayStateFullError();
    const lines = items.map((item) => JSON.stringify(item)).join("\n");
    try {
      appendDurableLine(journal, lines, JOURNAL_MAX_BYTES);
    } catch (error) {
      if (!(error instanceof DurableStateError)) throw error;
      compact(); // past its bound: fold the journal into a snapshot, then append to a fresh one
      appendDurableLine(journal, lines, JOURNAL_MAX_BYTES);
    }
    for (const [key, exp] of items) remember(key, exp);
  };

  return {
    has: (key) => memory.has(key),
    add: (key, exp) => addAll([[key, exp]]),
    addAll,
    size: () => memory.size(),
    full: () => memory.full(),
  };
}
