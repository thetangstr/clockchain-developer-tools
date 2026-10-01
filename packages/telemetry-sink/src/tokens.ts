import { createHash, randomBytes, type JsonWebKey } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { open as openAsync } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import path from "node:path";

import { openSealJwk, sealTo, type SealedBox, type SealBind } from "./seal.js";

/**
 * Token minting for the telemetry sink (N4c, LLD §9). Capability-separated
 * kinds:
 *
 *   - "ingest"       per-(runId, role), WRITE-ONLY: append records, never read.
 *   - "query"        per-runId, READ-ONLY: records + signed head, never write.
 *   - "global-query" explicit verifier-scope reader across runs — minted only
 *                    via mintGlobalQuery; the wildcard `runId: "*"` is refused
 *                    on every scoped mint so no accidental global exists.
 *
 * Plaintext tokens exist only in the minting return value — the store indexes
 * them by sha256 (`tokenId`), so records, dumps, and logs never carry usable
 * credentials. Revocation flips `revokedAtMs` and the token immediately stops
 * resolving (`peek` still sees it, for closed-run precedence).
 *
 * Tokens are delivered to roles sealed (`sealToken`) to that role's
 * local-services X25519 public key, bound to the (runId, role) pair (M4).
 */

export type TokenKind = "ingest" | "query" | "global-query";
export type ContractRole = "buyer" | "provider";

export interface TokenRecord {
  /** sha256(token), `0x`-hex — the public identifier; never the token itself. */
  tokenId: string;
  kind: TokenKind;
  runId: string;
  /** `null` on query/global-query tokens — those are role-agnostic. */
  role: ContractRole | null;
  createdAtMs: number;
  revokedAtMs: number | null;
}

export interface MintedToken {
  /** The plaintext token — returned ONCE to the minter for immediate sealing. */
  token: string;
  record: TokenRecord;
}

export interface TokenStore {
  mintIngest(input: { runId: string; role: ContractRole }): MintedToken;
  mintQuery(input: { runId: string }): MintedToken;
  mintGlobalQuery(): MintedToken;
  /**
   * Mark a runId as used (first ingest / close). A used runId can never
   * regain INGEST authority, but it becomes a real run — query tokens are
   * mintable only for used runIds (the verifier mints after sealing).
   */
  markRunUsed(runId: string): void;
  /** Durable cross-check for the run ledger — true once any ingest or close touched this runId. */
  isRunUsed(runId: string): boolean;
  /** Resolve a plaintext token to its record; revoked/unknown → undefined. */
  resolve(token: string): TokenRecord | undefined;
  /** Like resolve but includes revoked records (closed-run precedence checks). */
  peek(token: string): TokenRecord | undefined;
  revoke(tokenId: string): void;
  /** Revoke every ingest token for a run (used by run close). */
  revokeRunIngests(runId: string): void;
  /** Public records only — contains no plaintext tokens. */
  listRecords(): TokenRecord[];
  /**
   * Await the pending file writes and surface their outcome. Mutations update
   * memory synchronously and persist through the serialized async queue;
   * flush() resolves once the queue drains and REJECTS with the last write
   * error (a caller that needs durability — e.g. the mint CLI — must flush).
   */
  flush(): Promise<void>;
}

const PREFIX: Record<TokenKind, string> = {
  ingest: "otlp-ing-",
  query: "otlp-qry-",
  "global-query": "otlp-gqr-",
};

/** runId charset: no wildcard, no whitespace, no control chars. */
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const digestOf = (token: string): string =>
  `0x${createHash("sha256").update(token, "utf8").digest("hex")}`;

/**
 * N7a: durable token records for the deployed sink. The admin mint CLI and
 * the running server share ONE file on the `telemetry_state` volume:
 *
 *   tokens.json = { schema, records, revokedTokenIds, usedRunIds }
 *
 * Merge discipline: the server re-reads on mtime change (union of records,
 * revoked ids and used runIds — file entries win because the CLI writes
 * them), and persists its own mutations (markRunUsed on first ingest,
 * revokeRunIngests on close) back through the same atomic write. A raw JWK
 * or plaintext token in this file is REFUSED at load — only tokenIds
 * (sha256) are stored, never usable credentials.
 */
export const TOKEN_FILE_SCHEMA = "ac-telemetry.tokens/v1" as const;

interface TokenFileDoc {
  schema: typeof TOKEN_FILE_SCHEMA;
  records: TokenRecord[];
  revokedTokenIds: string[];
  usedRunIds: string[];
}

function isTokenRecord(v: unknown): v is TokenRecord {
  if (typeof v !== "object" || v === null) return false;
  const r = v as TokenRecord;
  return typeof r.tokenId === "string" && /^0x[0-9a-f]{64}$/.test(r.tokenId)
    && (r.kind === "ingest" || r.kind === "query" || r.kind === "global-query")
    && typeof r.runId === "string"
    && (r.role === null || r.role === "buyer" || r.role === "provider")
    && typeof r.createdAtMs === "number"
    && (r.revokedAtMs === null || typeof r.revokedAtMs === "number");
}

function readTokenFile(file: string): TokenFileDoc {
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (typeof raw !== "object" || raw === null || (raw as TokenFileDoc).schema !== TOKEN_FILE_SCHEMA) {
    throw new Error(`corrupt ${file}: not a ${TOKEN_FILE_SCHEMA} document`);
  }
  const doc = raw as TokenFileDoc;
  if (!Array.isArray(doc.records) || !doc.records.every(isTokenRecord)) {
    throw new Error(`corrupt ${file}: bad record shape`);
  }
  for (const list of [doc.revokedTokenIds, doc.usedRunIds]) {
    if (!Array.isArray(list) || !list.every((v) => typeof v === "string")) {
      throw new Error(`corrupt ${file}: bad id list`);
    }
  }
  return doc;
}

function writeTokenFileAtomic(file: string, doc: TokenFileDoc): void {
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify(doc));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
}

/**
 * LOW-8 + N4b-8 (F9): ownership-aware advisory lockfile around the
 * tokens.json read-modify-write. Both the mint CLI and the server write the
 * same file — without the lock a revoke and a markRunUsed can interleave
 * into a lost update.
 *
 * The lock body is `<pid> <nonce> <ms>` — the nonce pins the holder
 * GENERATION, so owner checks never confuse a recreated lock for a stale
 * one:
 *
 *   - A parseable owner whose pid is DEAD is stealable immediately — the
 *     steal is gated on an identical-content re-read, so a fresh lock that
 *     won the race between our read and the rename is never taken.
 *   - A parseable owner whose pid is ALIVE is never stolen regardless of
 *     age — a slow-but-live holder (big fsync, scheduler stall) keeps its
 *     lock; the waiter fails closed at the timeout instead of corrupting
 *     the write.
 *   - An unparseable body is ambiguous: only a stat-identical file past
 *     STALE_MS is stealable (ino+mtime+size must match across two reads).
 *   - Release deletes only OUR nonce — a former holder resuming after its
 *     lock was stolen can never unlink the thief's live lock.
 *
 * `wx` create is atomic on local filesystems; the WAIT is async (the event
 * loop never blocks). Acquire fails closed: timeout rejects, the queued
 * write is dropped.
 */
const LOCK_STALE_MS = 8_000;
const LOCK_TIMEOUT_MS = 10_000;
const LOCK_POLL_MS = 20;

interface LockOwner { pid: number; nonce: string; ts: number }

function parseLockOwner(raw: string): LockOwner | null {
  const m = /^(\d+) ([0-9a-f]{16}) (\d+)\s*$/.exec(raw.trim());
  if (m === null) return null;
  return { pid: Number(m[1]), nonce: m[2], ts: Number(m[3]) };
}

/** EPERM means the pid exists but isn't signalable by us — still alive. */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Identity tuple for a lock pathname — ino pins the inode, not the name. */
function lockStatSig(st: { ino: number; mtimeMs: number; size: number }): string {
  return `${st.ino}:${st.mtimeMs}:${st.size}`;
}

/**
 * Acquire the lock; resolves with OUR nonce (the release token). Exported
 * for the F9 race tests; the store's write queue is the in-process user.
 */
export async function acquireTokenFileLock(file: string, timeoutMs: number): Promise<string> {
  const lockFile = `${file}.lock`;
  const nonce = randomBytes(8).toString("hex");
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const handle = await openAsync(lockFile, "wx", 0o600);
      await handle.writeFile(`${process.pid} ${nonce} ${Date.now()}`);
      await handle.close();
      return nonce;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let raw: string | undefined;
      let sig: string | undefined;
      let mtimeMs = Number.NaN;
      try {
        raw = readFileSync(lockFile, "utf8");
        const st = statSync(lockFile);
        sig = lockStatSig(st);
        mtimeMs = st.mtimeMs;
      } catch { /* lock moved between our create-attempt and read */ }
      if (raw !== undefined && sig !== undefined) {
        const owner = parseLockOwner(raw);
        // A live owner is never stolen on age alone. Same-pid content is
        // ambiguous (could be our own orphaned write) — also never stolen.
        const deadOwner = owner !== null && owner.pid !== process.pid && !pidAlive(owner.pid);
        const staleAmbiguous = owner === null && Date.now() - mtimeMs > LOCK_STALE_MS;
        if (deadOwner || staleAmbiguous) {
          // Re-read AND re-stat: the file at the path must still be the
          // exact same bytes/inode we decided on — a fresh replacement
          // (won its own wx race during our check) is left alone.
          try {
            const raw2 = readFileSync(lockFile, "utf8");
            const sig2 = lockStatSig(statSync(lockFile));
            if (raw2 === raw && sig2 === sig) {
              const stale = `${lockFile}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
              renameSync(lockFile, stale);
              rmSync(stale, { force: true });
            }
          } catch { /* moved or recreated — keep waiting */ }
        }
      }
      if (Date.now() > deadline) {
        throw new Error(`tokens file lock timeout: ${lockFile}`);
      }
      await sleep(LOCK_POLL_MS);
    }
  }
}

/**
 * Owner-checked release: the lock file is deleted only when its body still
 * carries OUR nonce. A resumed former holder — whose lock was stolen while
 * it was stalled — finds a different nonce and unlinks nothing.
 */
export function releaseTokenFileLock(file: string, nonce: string): void {
  const lockFile = `${file}.lock`;
  try {
    const owner = parseLockOwner(readFileSync(lockFile, "utf8"));
    if (owner === null || owner.nonce !== nonce) return;
    rmSync(lockFile, { force: true });
  } catch { /* already gone — nothing to release */ }
}

export function createTokenStore(options: {
  now?: () => number;
  recordsFile?: string;
  /** LOW-8: tokens.json lock acquire timeout — mutations fail closed past it. */
  lockTimeoutMs?: number;
} = {}): TokenStore {
  const now = options.now ?? Date.now;
  const recordsFile = options.recordsFile;
  const lockTimeoutMs = options.lockTimeoutMs ?? LOCK_TIMEOUT_MS;
  const byId = new Map<string, TokenRecord>();
  const revoked = new Set<string>();
  const usedRunIds = new Set<string>();
  let lastMtimeMs = 0;

  /** Merge the file on mtime change — the mint CLI's writes become visible. */
  function refresh(force = false): void {
    if (recordsFile === undefined) return;
    if (!existsSync(recordsFile)) return;
    const mtimeMs = statSync(recordsFile).mtimeMs;
    if (!force && mtimeMs <= lastMtimeMs) return;
    const doc = readTokenFile(recordsFile);
    for (const record of doc.records) {
      const existing = byId.get(record.tokenId);
      if (existing === undefined) byId.set(record.tokenId, { ...record });
      // File rows win on revocation state (the CLI may revoke).
      else if (record.revokedAtMs !== null && existing.revokedAtMs === null) {
        existing.revokedAtMs = record.revokedAtMs;
      }
    }
    for (const tokenId of doc.revokedTokenIds) {
      const record = byId.get(tokenId);
      if (record !== undefined && record.revokedAtMs === null) record.revokedAtMs = now();
      revoked.add(tokenId);
    }
    for (const runId of doc.usedRunIds) usedRunIds.add(runId);
    lastMtimeMs = mtimeMs;
  }

  /**
   * Persist after a local mutation — merge-first under the file lock so a
   * concurrent CLI write isn't clobbered. The write runs on a serialized
   * async queue: the lock wait is async (never blocks the event loop) and a
   * failed write is captured for flush() rather than thrown mid-ingest.
   */
  let writeQueue: Promise<void> = Promise.resolve();
  let lastPersistError: Error | undefined;

  async function persistLocked(): Promise<void> {
    if (recordsFile === undefined) return;
    try {
      const nonce = await acquireTokenFileLock(recordsFile, lockTimeoutMs);
      try {
        refresh(true);
        writeTokenFileAtomic(recordsFile, {
          schema: TOKEN_FILE_SCHEMA,
          records: [...byId.values()].map((r) => ({ ...r })),
          revokedTokenIds: [...revoked],
          usedRunIds: [...usedRunIds],
        });
        lastMtimeMs = statSync(recordsFile).mtimeMs;
      } finally {
        releaseTokenFileLock(recordsFile, nonce);
      }
    } catch (error) {
      lastPersistError = error instanceof Error ? error : new Error(String(error));
    }
  }

  function persist(): void {
    if (recordsFile === undefined) return;
    writeQueue = writeQueue.then(persistLocked, persistLocked);
  }

  refresh(true);

  function mint(kind: TokenKind, input: { runId: string; role: ContractRole | null }): MintedToken {
    if (!RUN_ID_RE.test(input.runId)) {
      throw new Error("token mint: runId must match [A-Za-z0-9._:-]{1,128} (no wildcards)");
    }
    // A runId that has ever carried records (or been closed) can never regain
    // ingest authority — no reopening a consumed run under fresh authority.
    if (kind === "ingest" && usedRunIds.has(input.runId)) {
      throw new Error(`token mint: runId already used: ${input.runId}`);
    }
    // ...but a query token must point at a real run: it exists only after its
    // first ingest (or close). The verifier mints after sealing.
    if (kind === "query" && !usedRunIds.has(input.runId)) {
      throw new Error(`token mint: run does not exist: ${input.runId}`);
    }
    const token = `${PREFIX[kind]}${randomBytes(16).toString("hex")}`;
    const record: TokenRecord = {
      tokenId: digestOf(token),
      kind,
      runId: input.runId,
      role: input.role,
      createdAtMs: now(),
      revokedAtMs: null,
    };
    byId.set(record.tokenId, record);
    persist();
    return { token, record };
  }

  function peek(token: string): TokenRecord | undefined {
    refresh();
    if (typeof token !== "string") return undefined;
    const known = Object.values(PREFIX).some((p) => token.startsWith(p));
    if (!known) return undefined;
    return byId.get(digestOf(token));
  }

  function revoke(tokenId: string): void {
    refresh();
    revoked.add(tokenId);
    const record = byId.get(tokenId);
    if (record !== undefined && record.revokedAtMs === null) {
      record.revokedAtMs = now();
    }
    persist();
  }

  return {
    mintIngest: (input) => { refresh(); return mint("ingest", input); },
    mintQuery: (input) => { refresh(); return mint("query", { ...input, role: null }); },
    markRunUsed: (runId) => { refresh(); usedRunIds.add(runId); persist(); },
    isRunUsed: (runId) => { refresh(); return usedRunIds.has(runId); },
    mintGlobalQuery() {
      refresh();
      // The one place a "*" runId exists: an explicit, separately-kinded token.
      const token = `${PREFIX["global-query"]}${randomBytes(16).toString("hex")}`;
      const record: TokenRecord = {
        tokenId: digestOf(token),
        kind: "global-query",
        runId: "*",
        role: null,
        createdAtMs: now(),
        revokedAtMs: null,
      };
      byId.set(record.tokenId, record);
      persist();
      return { token, record };
    },
    peek,
    resolve(token) {
      const record = peek(token);
      if (record === undefined || revoked.has(record.tokenId)) return undefined;
      return record;
    },
    revoke,
    revokeRunIngests(runId) {
      for (const record of byId.values()) {
        if (record.kind === "ingest" && record.runId === runId) revoke(record.tokenId);
      }
    },
    listRecords() {
      refresh();
      return [...byId.values()].map((r) => ({ ...r }));
    },
    async flush() {
      await writeQueue;
      if (lastPersistError !== undefined) {
        const error = lastPersistError;
        lastPersistError = undefined;
        throw error;
      }
    },
  };
}

/** Mint an ingest token and return it SEALED to the role's services key, bound to (runId, role). */
export function mintIngestTokenSealed(
  store: TokenStore,
  input: { runId: string; role: ContractRole; recipientX25519Pub: `0x${string}` },
): { sealed: SealedBox; record: TokenRecord } {
  const minted = store.mintIngest(input);
  const sealed = sealToken(input.recipientX25519Pub, minted.token, {
    runId: input.runId,
    role: input.role,
  });
  return { sealed, record: minted.record };
}

/** Seal a plaintext token to a recipient's raw x25519 public key (0x-hex), bound to (runId, role). */
export function sealToken(
  recipientX25519Pub: `0x${string}`,
  token: string,
  bind: SealBind,
): SealedBox {
  return sealTo(recipientX25519Pub, token, bind);
}

/** Unseal a token box with the services uid's x25519 private key (JWK) under the expected binding. */
export function openSealedToken(privateKeyJwk: JsonWebKey, box: unknown, bind: SealBind): string {
  return openSealJwk(privateKeyJwk, box, bind);
}
