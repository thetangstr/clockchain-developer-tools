// Durable JSON state for the handshake surfaces (spec B2).
//
// One file per concern, written with the fsync'd atomic-rename pattern already used by
// agent-handshake/invitation-store.ts: 0700 directory, 0600 file, write tmp -> fsync ->
// keep the previous file as `.bak` -> rename tmp into place -> fsync the directory.
// A crash at any point leaves either the new file or the last good one.
//
// Writes are made only when state changes. `save("now")` writes synchronously: the
// process has no SIGTERM hook, so anything a client was told must already be on disk.
// `save("soon")` coalesces bookkeeping (last-seen times, timeline notes) into at most
// one write per `coalesceMs`, and any "now" write carries it along.
//
// Corruption is loud, never silent: a file that does not parse or validate is copied to
// `<file>.corrupt-<ms>` and logged. The `.bak` (last good) is used if it validates;
// otherwise loading throws DurableStateError, so the surface refuses to start (http.ts
// answers 503 for it) until an operator restores or wipes it (see the RUNBOOK). A garbage
// file is never overwritten with an empty state by accident.
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";

export class DurableStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DurableStateError";
  }
}

export const DEFAULT_COALESCE_MS = 1_000;

/** Where a surface keeps its files: `<root>/<surface>/`, or undefined for memory-only. */
export function handshakeStateDir(surface: "standalone-handshake" | "agent-handshake-v2", env: Record<string, string | undefined> = process.env): string | undefined {
  const root = (env.HANDSHAKE_STATE_DIR ?? "").trim();
  return root ? join(root, surface) : undefined;
}

function log(event: string, fields: Record<string, unknown>): void {
  console.error(JSON.stringify({ event, ...fields }));
}

function fsyncPath(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { mode: 0o700, recursive: true });
  chmodSync(path, 0o700);
  const stat = statSync(path);
  if (!stat.isDirectory()) throw new DurableStateError(`${path} is not a directory`);
}

export interface DurableJsonFile<T> {
  /** The stored value, or undefined when no file exists yet. Throws DurableStateError on unrecoverable corruption. */
  load(): T | undefined;
  /** Persist `snapshot()` now (synchronously) or coalesced. */
  save(kind: "now" | "soon"): void;
  /** Write any coalesced change immediately. */
  flush(): void;
  /** Stop the coalescing timer (tests). */
  close(): void;
}

export function createDurableJsonFile<T>(options: {
  path: string;
  /** Identifies the format; a file with another schema is treated as corrupt. */
  schema: string;
  /** Returns the value to write. */
  snapshot: () => T;
  /** Throws (anything) when a parsed value is not acceptable. */
  validate: (value: unknown) => T;
  maxBytes: number;
  coalesceMs?: number;
}): DurableJsonFile<T> {
  const { path, schema, maxBytes } = options;
  const backup = `${path}.bak`;
  const coalesceMs = options.coalesceMs ?? DEFAULT_COALESCE_MS;
  let timer: NodeJS.Timeout | undefined;
  // Set when the main file failed validation: it must never be rotated over the good `.bak`.
  let mainCorrupt = false;

  function readValid(file: string): T {
    const link = lstatSync(file);
    if (!link.isFile() || link.isSymbolicLink()) throw new Error("not a regular file");
    if (link.size > maxBytes) throw new Error("file exceeds the size bound");
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { schema?: unknown; value?: unknown };
    if (parsed === null || typeof parsed !== "object" || parsed.schema !== schema) throw new Error("unknown schema");
    return options.validate(parsed.value);
  }

  function write(): void {
    if (timer) {
      clearTimeout(timer);
      timer = undefined;
    }
    const body = `${JSON.stringify({ schema, value: options.snapshot() })}\n`;
    if (Buffer.byteLength(body) > maxBytes) {
      // Keep serving from memory; the previous file stays the durable copy.
      log("handshake_state_oversize", { path, bytes: Buffer.byteLength(body), maxBytes });
      return;
    }
    const parent = dirname(path);
    ensurePrivateDirectory(parent);
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporary, body, { encoding: "utf8", flag: "wx", mode: 0o600 });
      fsyncPath(temporary);
      if (mainCorrupt) unlinkSync(path);
      else if (existsSync(path)) renameSync(path, backup);
      mainCorrupt = false;
      renameSync(temporary, path);
      fsyncPath(parent);
    } catch (error) {
      try { unlinkSync(temporary); } catch { /* keep the original failure */ }
      log("handshake_state_write_failed", { path, error: (error as Error).name });
      throw new DurableStateError(`could not persist ${path}`);
    }
  }

  return {
    load(): T | undefined {
      if (!existsSync(path) && !existsSync(backup)) return undefined;
      if (existsSync(path)) {
        try {
          const stat = statSync(path);
          if ((stat.mode & 0o077) !== 0) throw new Error("file is readable by others");
          return readValid(path);
        } catch (error) {
          const quarantine = `${path}.corrupt-${Date.now()}`;
          try { copyFileSync(path, quarantine); } catch { /* best effort */ }
          log("handshake_state_corrupt", { path, quarantine, reason: (error as Error).message });
          mainCorrupt = true;
        }
      }
      if (existsSync(backup)) {
        try {
          const value = readValid(backup);
          log("handshake_state_restored_from_backup", { path, backup });
          return value;
        } catch (error) {
          log("handshake_state_corrupt", { path: backup, reason: (error as Error).message });
        }
      }
      throw new DurableStateError(`${path} is unreadable and has no valid backup; see RUNBOOK "Handshake state"`);
    },

    save(kind: "now" | "soon"): void {
      if (kind === "now") {
        write();
        return;
      }
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        try {
          write();
        } catch {
          // Logged in write(); the next change retries.
        }
      }, coalesceMs);
      timer.unref();
    },

    flush(): void {
      if (timer) write();
    },

    close(): void {
      if (timer) clearTimeout(timer);
      timer = undefined;
    },
  };
}
