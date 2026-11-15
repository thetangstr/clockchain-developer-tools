// Hosted Shadow storage (under SHADOW_STATE_DIR). Everything is plain files, so it survives a container restart on
// the /app/state volume and needs no native module:
//
//   owners/<ownerKey>/key.json                      operator id + Ed25519 private key (0600, written once), with no witness key
//   owners/<ownerKey>/operator.json                 operator id only, with the witness key (SHADOW_WITNESS_KEY_FILE), which
//                                                   replaces and removes key.json
//   owners/<ownerKey>/usage.json                    anchors and session starts today (the per-owner daily limits)
//   owners/<ownerKey>/settings.json                 written once the owner turns automatic logging off (SHADOW_AUTO_LOG)
//   owners/<ownerKey>/sessions/<sessionId>/meta.json      small durable JSON: state, head, checkpoint, outbox, anchors
//   owners/<ownerKey>/sessions/<sessionId>/events.jsonl   append-only, fsync'd, one event per line
//   caps/<sha256(cap)>.json                         link capability -> (ownerKey, sessionId)
//
// The ownerKey is a hash of the authenticated owner id, so no token, jti or account id appears in a path. JSON files
// use the handshake surfaces' durable writer (0700 dirs, 0600 files, fsync, rename, .bak). Events are appended with
// appendDurableLine. A crash between an event append and the meta write is repaired on the next load (reconcile).
import { createHash, createPrivateKey, generateKeyPairSync, randomUUID, timingSafeEqual } from "node:crypto";
import { closeSync, existsSync, ftruncateSync, lstatSync, openSync, readFileSync, readdirSync, rmSync, statSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { appendDurableLine, cleanStaleFiles, createDurableJsonFile, DurableStateError } from "../handshake-core/durable-store.js";
import { isLogLevel, levelSetBy, type LevelSetBy, type LogLevel } from "./log-level.js";
import type { KeyProvider } from "./lib/keys.js";
import { keyProvider } from "./witness.js";
import type { Checkpoint, CheckpointBody, Network, ShadowEvent } from "./lib/types.js";

/** Big enough for a session with an anchor per step: about 260 bytes per anchor in meta.anchors. */
export const META_MAX_BYTES = 512 * 1024;
const KEY_MAX_BYTES = 8 * 1024;
const SMALL_MAX_BYTES = 4 * 1024;

/** The owner's settings file holds what can't be read back: its value is unknown, so nothing may fall back to an older one. */
class CorruptSettings extends Error {}

const OWNER_KEY = /^[0-9a-f]{32}$/;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const CAP = /^[A-Za-z0-9_-]{22}$/;

export const isSessionId = (v: unknown): v is string => typeof v === "string" && SESSION_ID.test(v);

/** The storage key for an authenticated owner id (acct_..., jti:..., tok:...). */
export function ownerKeyOf(ownerId: string): string {
  return createHash("sha256").update(`shadow-owner:v1\0${ownerId}`).digest("hex").slice(0, 32);
}

export type RunState = { id: string; agent: string; open: boolean };

/** A Clockchain write the recorder still owes (spec §10 outbox). Checkpoint rows carry the body they commit to. */
export type OutboxRow = {
  id: string;
  kind: "start" | "checkpoint";
  hash: string;
  body: CheckpointBody | null;
  state: "queued" | "pending" | "failed";
  attempts: number;
  ledgerId: string | null;
  submittedAt: string | null;
  lastErrorKind: string | null;
  lastErrorCode: string | null;
  createdAt: string;
  /**
   * Whether a send may have reached the ledger: saved before each network call, and cleared only when a failure shows no write
   * was tried. Rows from before this field don't have it, and count as true. A row marked true is searched for before it is
   * paid for, and is never dropped from the queue, because the packet has to account for it.
   */
  sendStarted?: boolean;
  /** Not before this, unless a person's retry asks: how a row that keeps failing backs off. */
  nextTryAt?: string;
  /** An agent-signed checkpoint's signing key (fingerprint), filed on Clockchain before the row is. Other rows don't have it. */
  signer?: string;
};

/** A receipt that landed in the record (a session.opened receipt or a clockchain.anchored step). */
export type AnchorInfo = {
  marker: "start" | "checkpoint";
  seq: number;
  hash: string;
  count: number | null;
  ledgerId: string;
  blockHeight: string;
  blockTime: string | null;
  submittedAt: string | null;
};

/** Who acts in a session. purpose and accountableOwner are what the agent reported; older sessions don't have them. */
export type AgentEntry = { id: string; role: string | null; purpose?: string; accountableOwner?: string };

export type SessionMeta = {
  v: 1;
  sessionId: string;
  ownerKey: string;
  operatorId: string;
  title: string;
  agents: AgentEntry[];
  network: Network;
  state: "open" | "closed";
  createdAt: string;
  closedAt: string | null;
  expiresAt: string;
  cap: string;
  nonce: string;
  startHash: string;
  seq: number;
  head: string | null;
  eventsBytes: number;
  agentSteps: number;
  runs: RunState[];
  checkpoint: Checkpoint | null;
  /**
   * An agent-key session's checkpoint body waiting for the agent's own signature, kept here so a restart doesn't change
   * the hash it was given. `final` is the close's. Cleared when the agent signs it. Other sessions never have it.
   */
  awaitingSignature?: { hash: string; body: CheckpointBody; final: boolean };
  /** An agent-key owner's root key (ak:<root>), filed on Clockchain before any of the session's anchors. Other sessions don't have it. */
  agentRoot?: string;
  outbox: OutboxRow[];
  anchors: AnchorInfo[];
  /** The person revoked this session's links: its capability file is gone, and no tool hands the links out. */
  linksRevoked?: true;
  /** Set at close when the assistant gave a count of the person's messages. Older sessions don't have it. */
  capture?: { person_messages_reported: number; person_messages_logged: number; missing: number };
  /** When the last step landed. Older sessions don't have it, and count from createdAt. */
  lastStepAt?: string;
  /** Closed by the server after no new steps, not by the person or the agent. */
  closedIdle?: true;
  /** How much detail this session anchors. Sessions at the default don't have it. What a reader sees comes from the hashed notes, not from here. */
  logLevel?: LogLevel;
  logLevelBy?: LevelSetBy;
  /** The account's level when this session last looked, null for none. Sessions from before hashed notes don't have it: they read and run as "step". */
  accountLevelSeen?: LogLevel | null;
};

export type Operator = { operatorId: string; keys: KeyProvider };

/** levelUnreadable: logging was switched while the file couldn't be read, so its level is unknown, not gone. */
type OwnerSettings = { loggingOff: boolean; logLevel?: LogLevel; levelUnreadable?: true };
type KeyFile = { operatorId: string; privateKeyPem: string; createdAt: string };
type OperatorFile = { operatorId: string; createdAt: string };
type UsageFile = { day: string; anchors: number; starts?: number };
export type DailyCounter = "anchors" | "starts";
type CapFile = { ownerKey: string; sessionId: string };

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

const SETTINGS_SCHEMA = "shadow-settings-v1";

function validSettings(v: unknown): OwnerSettings {
  if (!isObj(v) || typeof v.loggingOff !== "boolean" || (v.logLevel !== undefined && !isLogLevel(v.logLevel))) throw new Error("bad settings file");
  return { loggingOff: v.loggingOff, ...(v.logLevel ? { logLevel: v.logLevel as LogLevel } : {}), ...(v.levelUnreadable === true ? { levelUnreadable: true as const } : {}) };
}

function validateMeta(v: unknown): SessionMeta {
  if (!isObj(v) || v.v !== 1 || !isSessionId(v.sessionId) || typeof v.ownerKey !== "string" || !OWNER_KEY.test(v.ownerKey) ||
    typeof v.operatorId !== "string" || !Array.isArray(v.agents) || (v.state !== "open" && v.state !== "closed") ||
    !Number.isSafeInteger(v.seq) || !Number.isSafeInteger(v.eventsBytes) || typeof v.cap !== "string" || !CAP.test(v.cap) ||
    !Array.isArray(v.runs) || !Array.isArray(v.outbox) || !Array.isArray(v.anchors) || typeof v.expiresAt !== "string")
    throw new Error("not a shadow session");
  // Stored before the level became the account's: it meant the same thing.
  if (v.logLevelBy !== undefined) v.logLevelBy = levelSetBy(v.logLevelBy) ?? undefined;
  return v as unknown as SessionMeta;
}

function mtimeOf(path: string): Date | undefined {
  try {
    return statSync(path).mtime;
  } catch {
    return undefined;
  }
}

function dirBytes(dir: string): number {
  let total = 0;
  if (!existsSync(dir)) return 0;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    try {
      const st = lstatSync(p);
      total += st.isDirectory() ? dirBytes(p) : st.size;
    } catch {
      // Removed while walking.
    }
  }
  return total;
}

/** Anchors a session still owes Clockchain, by state. Totals only: nothing here names an owner or a session. */
export type AnchorBacklog = { queued: number; pending: number; failed: number };

function backlogOf(meta: SessionMeta): AnchorBacklog | undefined {
  if (meta.outbox.length === 0) return undefined;
  const b: AnchorBacklog = { queued: 0, pending: 0, failed: 0 };
  for (const r of meta.outbox) b[r.state]++;
  return b;
}

export class ShadowStore {
  readonly root: string;
  private readonly operators = new Map<string, Operator>();
  /** Sessions with anchors still owed, kept current by writeMeta and rebuilt by every sweep, so /metrics never walks the disk. */
  private readonly backlog = new Map<string, AnchorBacklog>();
  /** How many idle passes have asked what is owed, so each starts where the last left off. */
  private owedTurn = 0;
  /** Where each owing account's next turn starts in its sessions. */
  private owedNext = new Map<string, number>();

  /** Clockchain's single witness key: when set, no owner key is created or used. */
  private readonly witness: KeyProvider | undefined;

  constructor(root: string, witness?: KeyProvider) {
    this.root = root;
    this.witness = witness;
  }

  private ownerDir(ownerKey: string): string {
    if (!OWNER_KEY.test(ownerKey)) throw new Error("bad owner key");
    return join(this.root, "owners", ownerKey);
  }

  /** Whether Shadow keeps anything for this owner: sessions, settings or an operator file, alive or in retention. */
  hasOwner(ownerKey: string): boolean {
    return existsSync(this.ownerDir(ownerKey));
  }

  sessionDir(ownerKey: string, sessionId: string): string {
    if (!isSessionId(sessionId)) throw new Error("bad session id");
    return join(this.ownerDir(ownerKey), "sessions", sessionId);
  }

  eventsPath(ownerKey: string, sessionId: string): string {
    return join(this.sessionDir(ownerKey, sessionId), "events.jsonl");
  }

  // ---- operator key -------------------------------------------------------------------------------------------

  /**
   * The owner's operator id and signing key. With the witness key, the key is the witness and the operator id comes from
   * operator.json. An owner from before it has its operator id moved there from key.json, whose private key is then
   * removed with every copy of it: Clockchain holds no key per account. Without the witness key, both come from key.json,
   * created on first use (under operator.json's id, if the witness key was on before); the private key never leaves it.
   */
  operator(ownerKey: string, now: Date): Operator {
    const cached = this.operators.get(ownerKey);
    if (cached) return cached;
    const op: Operator = this.witness ? { operatorId: this.witnessedOperatorId(ownerKey, now).operatorId, keys: this.witness } : this.ownerKeyOperator(ownerKey, now);
    if (this.operators.size >= 512) this.operators.delete(this.operators.keys().next().value as string);
    this.operators.set(ownerKey, op);
    return op;
  }

  private operatorFile(ownerKey: string, current: () => OperatorFile) {
    return createDurableJsonFile<OperatorFile>({
      path: join(this.ownerDir(ownerKey), "operator.json"),
      schema: "shadow-operator-v1",
      snapshot: current,
      validate: (v) => {
        if (!isObj(v) || typeof v.operatorId !== "string" || typeof v.createdAt !== "string") throw new Error("bad operator file");
        return v as unknown as OperatorFile;
      },
      maxBytes: SMALL_MAX_BYTES,
    });
  }

  /**
   * `damaged`: key.json and its backup were both unreadable. Its private key would never be used again and its operator id
   * can't be read, so the owner gets a new operator id and every copy of the file is removed (FC5).
   */
  private witnessedOperatorId(ownerKey: string, now: Date): { operatorId: string; damaged: boolean } {
    let current: OperatorFile | undefined;
    let damaged = false;
    const file = this.operatorFile(ownerKey, () => current!);
    current = file.load();
    if (!current) {
      const keyPath = join(this.ownerDir(ownerKey), "key.json");
      const heldKey = createDurableJsonFile<OperatorFile>({
        path: keyPath,
        schema: "shadow-operator-key-v1",
        snapshot: () => { throw new Error("key.json is never written with the witness key"); },
        validate: (v) => {
          if (!isObj(v) || typeof v.operatorId !== "string") throw new Error("bad key file");
          return { operatorId: v.operatorId, createdAt: typeof v.createdAt === "string" ? v.createdAt : now.toISOString() };
        },
        maxBytes: KEY_MAX_BYTES,
        redactReasons: true,
      });
      let old: OperatorFile | undefined;
      try {
        old = heldKey.load();
      } catch (e) {
        if (!(e instanceof DurableStateError)) throw e;
        // Damaged means bytes that were read and are bad. A file that couldn't be read at all (EACCES, EMFILE, EIO) may be
        // fine a moment later: that error goes up, the owner counts as failed, and nothing is removed.
        for (const file of [keyPath, `${keyPath}.bak`]) {
          try {
            readFileSync(file);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
        }
        damaged = true;
        console.error(JSON.stringify({
          event: "shadow_damaged_key_removed",
          owner: ownerKey.slice(0, 16),
          note: "key.json and its backup were unreadable; a new operator id was issued and every copy removed",
        }));
      }
      // The retention clock (the file's age, in the sweep) carries over with the id.
      const since = old ? (mtimeOf(keyPath) ?? mtimeOf(`${keyPath}.bak`)) : undefined;
      current = old ?? { operatorId: randomUUID(), createdAt: now.toISOString() };
      file.save("now");
      if (since) utimesSync(join(this.ownerDir(ownerKey), "operator.json"), since, since);
    }
    // Only once the id is durable elsewhere: key.json, its .bak, any quarantined or half-written copy.
    this.removeHeldKeys(ownerKey);
    return { operatorId: current.operatorId, damaged };
  }

  /**
   * With the witness key, once at start: every owner that still holds a key.json (or a copy of one) has it moved to
   * operator.json as its next use would, so an owner that never comes back doesn't keep a private key on disk. Idempotent;
   * without the witness key, nothing. Returns counts only.
   */
  migrateHeldKeys(now: Date): { migrated: number; failed: number; damaged: number } {
    const counts = { migrated: 0, failed: 0, damaged: 0 };
    const ownersDir = join(this.root, "owners");
    if (!this.witness || !existsSync(ownersDir)) return counts;
    for (const ownerKey of readdirSync(ownersDir)) {
      if (!OWNER_KEY.test(ownerKey)) continue;
      try {
        if (!readdirSync(join(ownersDir, ownerKey)).some((name) => name === "key.json" || name.startsWith("key.json."))) continue;
        if (this.witnessedOperatorId(ownerKey, now).damaged) counts.damaged++;
        else counts.migrated++;
      } catch {
        counts.failed++; // Left as it is: its next use, or the next start, tries again.
      }
    }
    return counts;
  }

  private removeHeldKeys(ownerKey: string): void {
    const dir = this.ownerDir(ownerKey);
    if (!existsSync(dir)) return;
    for (const name of readdirSync(dir)) if (name === "key.json" || name.startsWith("key.json.")) rmSync(join(dir, name), { force: true });
  }

  private ownerKeyOperator(ownerKey: string, now: Date): Operator {
    let current: KeyFile | undefined;
    const file = createDurableJsonFile<KeyFile>({
      path: join(this.ownerDir(ownerKey), "key.json"),
      schema: "shadow-operator-key-v1",
      snapshot: () => current!,
      validate: (v) => {
        if (!isObj(v) || typeof v.operatorId !== "string" || typeof v.privateKeyPem !== "string") throw new Error("bad key file");
        return v as unknown as KeyFile;
      },
      maxBytes: KEY_MAX_BYTES,
      redactReasons: true,
    });
    current = file.load();
    if (!current) {
      const privateKeyPem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      // An owner made while the witness key was on keeps its operator id.
      const operatorId = this.operatorFile(ownerKey, () => { throw new Error("operator.json is only read here"); }).load()?.operatorId ?? randomUUID();
      current = { operatorId, privateKeyPem, createdAt: now.toISOString() };
      file.save("now");
    }
    return { operatorId: current.operatorId, keys: keyProvider(createPrivateKey(current.privateKeyPem)) };
  }

  // ---- the owner's logging setting (SHADOW_AUTO_LOG) ------------------------------------------------------------

  private settingsFile(ownerKey: string, current: () => OwnerSettings) {
    return createDurableJsonFile<OwnerSettings>({
      path: this.settingsPath(ownerKey),
      schema: SETTINGS_SCHEMA,
      snapshot: current,
      validate: validSettings,
      maxBytes: SMALL_MAX_BYTES,
    });
  }

  private settingsPath(ownerKey: string): string {
    return join(this.ownerDir(ownerKey), "settings.json");
  }

  /**
   * The owner's settings. The durable file falls back to its .bak when the main file is corrupt, which is right for state that
   * only grows, and wrong here: the .bak can hold an "on" from before the person said stop. So a corrupt main file is looked
   * for first, by the same tests, and throws CorruptSettings. A .bak with no main file is a crash in the middle of a save,
   * and reads as before. A read that fails for any other reason throws as it is: the file may be fine.
   */
  private settings(ownerKey: string): OwnerSettings {
    const path = this.settingsPath(ownerKey);
    let raw: string | undefined;
    try {
      const link = lstatSync(path);
      if (!link.isFile() || link.isSymbolicLink() || (link.mode & 0o077) !== 0 || link.size > SMALL_MAX_BYTES) throw new CorruptSettings();
      raw = readFileSync(path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    if (raw !== undefined) {
      try {
        const parsed = JSON.parse(raw) as { schema?: unknown; value?: unknown } | null;
        if (parsed?.schema !== SETTINGS_SCHEMA) throw new Error("unknown schema");
        return validSettings(parsed.value);
      } catch {
        throw new CorruptSettings();
      }
    }
    return this.settingsFile(ownerKey, () => ({ loggingOff: false })).load() ?? { loggingOff: false };
  }

  /** True once the owner turned logging off. Default false. Throws if the file cannot be read (callers fail closed). */
  loggingOff(ownerKey: string): boolean {
    return this.settings(ownerKey).loggingOff === true;
  }

  setLoggingOff(ownerKey: string, loggingOff: boolean): void {
    // Turning logging off must work even with an unreadable file. A level that can't be read stays unknown rather than
    // becoming "none": readers keep failing closed until a level is set again.
    let kept: Pick<OwnerSettings, "logLevel" | "levelUnreadable">;
    try {
      const { logLevel, levelUnreadable } = this.settings(ownerKey);
      kept = { ...(logLevel ? { logLevel } : {}), ...(levelUnreadable ? { levelUnreadable } : {}) };
    } catch (e) {
      // A read that merely failed may be of a healthy file: it isn't overwritten for that, unless logging is being turned off.
      if (!(e instanceof CorruptSettings) && !loggingOff) throw e;
      kept = { levelUnreadable: true };
    }
    this.settingsFile(ownerKey, () => ({ loggingOff, ...kept })).save("now");
  }

  /** This account's level, or null. Throws if it cannot be read (callers fail closed). */
  logLevel(ownerKey: string): LogLevel | null {
    const { logLevel, levelUnreadable } = this.settings(ownerKey);
    if (levelUnreadable) throw new Error("the account's level could not be read");
    return logLevel ?? null;
  }

  /**
   * Sets the level, which is also the way back from a settings file that can't be read: then whether logging was off is
   * unknown too, and it reads as off, as "off" must never silently turn back on. Returns whether that happened.
   */
  setLogLevel(ownerKey: string, logLevel: LogLevel): { reset: boolean } {
    let loggingOff = true, reset = true;
    try {
      ({ loggingOff } = this.settings(ownerKey));
      reset = false;
    } catch (e) {
      if (!(e instanceof CorruptSettings)) throw e; // The file may be fine: it stays as it is.
    }
    this.settingsFile(ownerKey, () => ({ loggingOff, logLevel })).save("now");
    return { reset };
  }

  // ---- per-owner daily anchor count ---------------------------------------------------------------------------

  private usageFile(ownerKey: string, current: () => UsageFile) {
    return createDurableJsonFile<UsageFile>({
      path: join(this.ownerDir(ownerKey), "usage.json"),
      schema: "shadow-usage-v1",
      snapshot: current,
      validate: (v) => {
        if (!isObj(v) || typeof v.day !== "string" || !Number.isSafeInteger(v.anchors) || (v.starts !== undefined && !Number.isSafeInteger(v.starts)))
          throw new Error("bad usage file");
        return v as unknown as UsageFile;
      },
      maxBytes: SMALL_MAX_BYTES,
    });
  }

  /** Adds `delta` to today's count and returns the new count; refuses (returns null) past `max` when delta > 0. */
  bump(ownerKey: string, counter: DailyCounter, day: string, delta: number, max: number): number | null {
    let value: UsageFile = { day, anchors: 0, starts: 0 };
    const file = this.usageFile(ownerKey, () => value);
    const stored = file.load();
    if (stored && stored.day === day) value = { day, anchors: stored.anchors, starts: stored.starts ?? 0 };
    const current = value[counter] ?? 0;
    if (delta > 0 && current + delta > max) return null;
    value = { ...value, [counter]: Math.max(0, current + delta) };
    file.save("now");
    return value[counter] ?? 0;
  }

  bumpAnchors(ownerKey: string, day: string, delta: number, max: number): number | null {
    return this.bump(ownerKey, "anchors", day, delta, max);
  }

  today(ownerKey: string, counter: DailyCounter, day: string): number {
    const stored = this.usageFile(ownerKey, () => ({ day, anchors: 0 })).load();
    return stored && stored.day === day ? stored[counter] ?? 0 : 0;
  }

  anchorsToday(ownerKey: string, day: string): number {
    return this.today(ownerKey, "anchors", day);
  }

  /** Bytes an owner's sessions hold on disk (event logs plus a metadata estimate per session). */
  ownerBytes(ownerKey: string): number {
    let total = 0;
    for (const id of this.sessionIds(ownerKey)) {
      try {
        const m = this.readMeta(ownerKey, id);
        total += (m?.eventsBytes ?? 0) + 4096;
      } catch {
        total += 4096;
      }
    }
    return total;
  }

  // ---- sessions -----------------------------------------------------------------------------------------------

  private metaFile(ownerKey: string, sessionId: string, current: () => SessionMeta) {
    return createDurableJsonFile<SessionMeta>({
      path: join(this.sessionDir(ownerKey, sessionId), "meta.json"),
      schema: "shadow-session-v1",
      snapshot: current,
      validate: validateMeta,
      maxBytes: META_MAX_BYTES,
    });
  }

  readMeta(ownerKey: string, sessionId: string): SessionMeta | undefined {
    if (!OWNER_KEY.test(ownerKey) || !isSessionId(sessionId)) return undefined;
    if (!existsSync(this.sessionDir(ownerKey, sessionId))) return undefined;
    const meta = this.metaFile(ownerKey, sessionId, () => { throw new Error("read only"); }).load();
    return meta && meta.ownerKey === ownerKey && meta.sessionId === sessionId ? meta : undefined;
  }

  writeMeta(meta: SessionMeta): void {
    // Never resurrect a session the retention sweep removed while an operation was in flight.
    if (!existsSync(this.sessionDir(meta.ownerKey, meta.sessionId))) throw new Error("session removed");
    this.metaFile(meta.ownerKey, meta.sessionId, () => meta).save("now");
    this.noteBacklog(meta);
  }

  private noteBacklog(meta: SessionMeta): void {
    const key = `${meta.ownerKey}/${meta.sessionId}`;
    const b = backlogOf(meta);
    if (b) this.backlog.set(key, b);
    else this.backlog.delete(key);
  }

  sessionExists(ownerKey: string, sessionId: string): boolean {
    return OWNER_KEY.test(ownerKey) && isSessionId(sessionId) && existsSync(this.sessionDir(ownerKey, sessionId));
  }

  /** Stops a session's links at once: its capability file goes. The record stays. */
  revokeCap(meta: SessionMeta): void {
    this.removeCap(meta.cap);
  }

  /** Removes everything kept for an owner besides its sessions (signing key, daily counts, logging setting). */
  deleteOwner(ownerKey: string): void {
    rmSync(this.ownerDir(ownerKey), { recursive: true, force: true });
    this.operators.delete(ownerKey);
  }

  /** Anchors still owed across every session, as of the last write or sweep. */
  anchorBacklog(): AnchorBacklog {
    const total: AnchorBacklog = { queued: 0, pending: 0, failed: 0 };
    for (const b of this.backlog.values()) {
      total.queued += b.queued;
      total.pending += b.pending;
      total.failed += b.failed;
    }
    return total;
  }

  sessionIds(ownerKey: string): string[] {
    const dir = join(this.ownerDir(ownerKey), "sessions");
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((n) => SESSION_ID.test(n));
  }

  createSession(meta: SessionMeta): void {
    const dir = this.sessionDir(meta.ownerKey, meta.sessionId);
    if (existsSync(dir)) throw new Error("session exists");
    this.metaFile(meta.ownerKey, meta.sessionId, () => meta).save("now");
    let cap: CapFile = { ownerKey: meta.ownerKey, sessionId: meta.sessionId };
    this.capFile(meta.cap, () => cap).save("now");
  }

  /** Appends one serialised event as a line (fsync'd); refuses past `maxBytes` for the whole file. */
  appendLine(meta: SessionMeta, line: string, maxBytes: number): void {
    if (!existsSync(this.sessionDir(meta.ownerKey, meta.sessionId))) throw new Error("session removed");
    appendDurableLine(this.eventsPath(meta.ownerKey, meta.sessionId), line, maxBytes);
  }

  eventsFileBytes(meta: SessionMeta): number {
    const p = this.eventsPath(meta.ownerKey, meta.sessionId);
    return existsSync(p) ? statSync(p).size : 0;
  }

  /** The first `count` events of a session. */
  readEvents(meta: SessionMeta, count = meta.seq): ShadowEvent[] {
    if (count === 0) return [];
    const text = readFileSync(this.eventsPath(meta.ownerKey, meta.sessionId), "utf8");
    const out: ShadowEvent[] = [];
    let start = 0;
    while (out.length < count) {
      const end = text.indexOf("\n", start);
      if (end < 0) break;
      out.push(JSON.parse(text.slice(start, end)) as ShadowEvent);
      start = end + 1;
    }
    if (out.length < count) throw new Error("event log is shorter than its metadata");
    return out;
  }

  /**
   * Reads every complete, well-chained event line, truncating a torn or unchained tail (a write the client was never
   * told succeeded). Returns the events and the byte length kept.
   */
  readAndRepairEvents(meta: SessionMeta): { events: ShadowEvent[]; bytes: number } {
    const p = this.eventsPath(meta.ownerKey, meta.sessionId);
    if (!existsSync(p)) return { events: [], bytes: 0 };
    const buf = readFileSync(p);
    const events: ShadowEvent[] = [];
    let start = 0, kept = 0;
    let prev: string | null = null;
    while (start < buf.length) {
      const end = buf.indexOf(0x0a, start);
      if (end < 0) break;
      let e: ShadowEvent;
      try {
        e = JSON.parse(buf.subarray(start, end).toString("utf8")) as ShadowEvent;
      } catch {
        break;
      }
      if (!e || !e.body || e.body.seq !== events.length + 1 || e.body.previousHash !== prev || typeof e.hash !== "string") break;
      events.push(e);
      prev = e.hash;
      start = end + 1;
      kept = start;
    }
    if (kept < buf.length) {
      const fd = openSync(p, "r+");
      try {
        ftruncateSync(fd, kept);
      } finally {
        closeSync(fd);
      }
    }
    return { events, bytes: kept };
  }

  deleteSession(ownerKey: string, sessionId: string, cap: string | null): void {
    rmSync(this.sessionDir(ownerKey, sessionId), { recursive: true, force: true });
    if (cap && CAP.test(cap)) this.removeCap(cap);
    this.backlog.delete(`${ownerKey}/${sessionId}`);
  }

  // ---- link capabilities --------------------------------------------------------------------------------------

  private capPath(cap: string): string {
    return join(this.root, "caps", `${createHash("sha256").update(cap).digest("hex")}.json`);
  }

  private capFile(cap: string, current: () => CapFile) {
    return createDurableJsonFile<CapFile>({
      path: this.capPath(cap),
      schema: "shadow-cap-v1",
      snapshot: current,
      validate: (v) => {
        if (!isObj(v) || typeof v.ownerKey !== "string" || !OWNER_KEY.test(v.ownerKey) || !isSessionId(v.sessionId)) throw new Error("bad cap");
        return v as unknown as CapFile;
      },
      maxBytes: SMALL_MAX_BYTES,
    });
  }

  private removeCap(cap: string): void {
    const p = this.capPath(cap);
    rmSync(p, { force: true });
    rmSync(`${p}.bak`, { force: true });
  }

  /** The session a link capability names, or undefined. The stored cap is compared in constant time as well. */
  resolveCap(cap: string): { ownerKey: string; sessionId: string } | undefined {
    if (!CAP.test(cap) || !existsSync(this.capPath(cap))) return undefined;
    let target: CapFile | undefined;
    try {
      target = this.capFile(cap, () => { throw new Error("read only"); }).load();
    } catch {
      return undefined;
    }
    if (!target) return undefined;
    const meta = this.readMeta(target.ownerKey, target.sessionId);
    if (!meta) return undefined;
    const a = Buffer.from(meta.cap), b = Buffer.from(cap);
    return a.length === b.length && timingSafeEqual(a, b) ? target : undefined;
  }

  /** When a step last landed. Sessions from before lastStepAt: the metadata file's own time, as every step writes it. */
  private lastActivity(m: SessionMeta): number {
    if (m.lastStepAt) return Date.parse(m.lastStepAt);
    try {
      return statSync(join(this.sessionDir(m.ownerKey, m.sessionId), "meta.json")).mtimeMs;
    } catch {
      return Date.parse(m.createdAt);
    }
  }

  /** One owner's open sessions, unexpired, with no step since the cutoff, idle longest first. */
  idleOpenSessionsOf(ownerKey: string, cutoffMs: number, nowMs: number): { ownerKey: string; sessionId: string }[] {
    const found: { sessionId: string; at: number }[] = [];
    for (const sessionId of this.sessionIds(ownerKey)) {
      try {
        const m = this.readMeta(ownerKey, sessionId);
        if (!m || m.state !== "open" || Date.parse(m.expiresAt) <= nowMs) continue;
        const at = this.lastActivity(m);
        if (at <= cutoffMs) found.push({ sessionId, at });
      } catch {
        // Unreadable: left for the retention sweep.
      }
    }
    return found.sort((a, b) => a.at - b.at).map(({ sessionId }) => ({ ownerKey, sessionId }));
  }

  /**
   * The whole store, for the idle pass: sessions to close, closed ones with an anchor due, and open ones `waits` picks (an
   * agent's anchors held by our own limit, now with room), oldest first and capped on their own. Gives way to the event loop as
   * it goes, because every route shares this process. `owed` takes turns: one session per account per round, and each pass
   * starts further along, in accounts and in each account's sessions, so stuck sessions can't keep others off the list.
   */
  async idleScan(cutoffMs: number, nowMs: number, limit: number, waits?: (m: SessionMeta) => boolean): Promise<{ idle: { ownerKey: string; sessionId: string }[]; owed: { ownerKey: string; sessionId: string }[]; held: { ownerKey: string; sessionId: string }[] }> {
    const ownersDir = join(this.root, "owners");
    if (!existsSync(ownersDir)) return { idle: [], owed: [], held: [] };
    const idle: { ownerKey: string; sessionId: string; at: number }[] = [];
    const held: { ownerKey: string; sessionId: string; at: number }[] = [];
    const owing = new Map<string, string[]>();
    let read = 0;
    for (const ownerKey of readdirSync(ownersDir)) {
      if (!OWNER_KEY.test(ownerKey)) continue;
      for (const sessionId of this.sessionIds(ownerKey)) {
        if (++read % 50 === 0) await new Promise((r) => setImmediate(r));
        try {
          const m = this.readMeta(ownerKey, sessionId);
          if (!m || Date.parse(m.expiresAt) <= nowMs) continue;
          if (m.state === "closed") {
            if (m.outbox.some((r) => r.state !== "failed" && (!r.nextTryAt || Date.parse(r.nextTryAt) <= nowMs))) owing.set(ownerKey, [...(owing.get(ownerKey) ?? []), sessionId]);
            continue;
          }
          const at = this.lastActivity(m);
          if (at <= cutoffMs) idle.push({ ownerKey, sessionId, at });
          else if (waits?.(m)) held.push({ ownerKey, sessionId, at });
        } catch {
          // Unreadable: left for the retention sweep.
        }
      }
    }
    const oldest = (list: { ownerKey: string; sessionId: string; at: number }[]) => list.sort((a, b) => a.at - b.at).slice(0, limit).map(({ ownerKey, sessionId }) => ({ ownerKey, sessionId }));
    return { idle: oldest(idle), owed: this.takeTurns(owing, limit), held: oldest(held) };
  }

  private takeTurns(owing: Map<string, string[]>, limit: number): { ownerKey: string; sessionId: string }[] {
    const owners = [...owing.keys()].sort();
    const first = this.owedTurn++ * limit;
    const order = owners.map((_, i) => owners[(first + i) % owners.length]);
    const taken = new Map(order.map((o) => [o, 0]));
    const owed: { ownerKey: string; sessionId: string }[] = [];
    for (let round = 0; owed.length < limit; round++) {
      const before = owed.length;
      for (const ownerKey of order) {
        const list = owing.get(ownerKey)!.sort();
        if (round >= list.length || owed.length >= limit) continue;
        owed.push({ ownerKey, sessionId: list[((this.owedNext.get(ownerKey) ?? 0) + round) % list.length] });
        taken.set(ownerKey, round + 1);
      }
      if (owed.length === before) break;
    }
    const next = new Map(order.map((o) => [o, (this.owedNext.get(o) ?? 0) + taken.get(o)!]));
    this.owedNext = next; // Only accounts owing now, so this stays as small as the list.
    return owed;
  }

  // ---- retention ----------------------------------------------------------------------------------------------

  /**
   * Removes sessions past their expiry (and owners left with no sessions and an old key), drops dangling link
   * capabilities and temp files, and returns the bytes the state directory holds afterwards. `busy` sessions (an
   * operation holds their lock) are left for the next sweep.
   */
  sweep(nowMs: number, retentionMs: number, busy: (ownerKey: string, sessionId: string) => boolean): { removed: number; bytes: number } {
    let removed = 0;
    this.backlog.clear();
    const ownersDir = join(this.root, "owners");
    const live = new Set<string>();
    if (existsSync(ownersDir)) {
      for (const ownerKey of readdirSync(ownersDir)) {
        if (!OWNER_KEY.test(ownerKey)) continue;
        const odir = join(ownersDir, ownerKey);
        cleanStaleFiles(odir, nowMs);
        let remaining = 0;
        for (const sessionId of this.sessionIds(ownerKey)) {
          const sdir = this.sessionDir(ownerKey, sessionId);
          const isBusy = busy(ownerKey, sessionId);
          if (!isBusy) cleanStaleFiles(sdir, nowMs);
          let meta: SessionMeta | undefined;
          try {
            meta = this.readMeta(ownerKey, sessionId);
          } catch {
            meta = undefined;
          }
          // An unreadable session is removed once its directory is older than the retention period.
          const expired = !isBusy && (meta ? Date.parse(meta.expiresAt) <= nowMs : nowMs - statSync(sdir).mtimeMs > retentionMs);
          if (expired) {
            this.deleteSession(ownerKey, sessionId, meta?.cap ?? null);
            removed++;
          } else {
            remaining++;
            if (meta) {
              live.add(createHash("sha256").update(meta.cap).digest("hex"));
              this.noteBacklog(meta);
            }
          }
        }
        if (remaining === 0) {
          // The younger of the operator files: an owner made with the witness key on, then used with it off, has both.
          let keyAge = Infinity;
          for (const name of ["key.json", "operator.json"]) {
            const p = join(odir, name);
            if (existsSync(p)) keyAge = Math.min(keyAge, nowMs - statSync(p).mtimeMs);
          }
          // A logging setting outlives the records: "off" must never silently turn back on.
          if (keyAge > retentionMs && !existsSync(join(odir, "settings.json"))) {
            rmSync(odir, { recursive: true, force: true });
            this.operators.delete(ownerKey);
          }
        }
      }
    }
    const capsDir = join(this.root, "caps");
    if (existsSync(capsDir)) {
      cleanStaleFiles(capsDir, nowMs);
      for (const name of readdirSync(capsDir)) {
        const m = /^([0-9a-f]{64})\.json(\.bak)?$/.exec(name);
        if (m && !live.has(m[1])) {
          // A link whose session is gone, or one being created right now (its session is busy): keep a young file.
          const p = join(capsDir, name);
          try {
            if (nowMs - statSync(p).mtimeMs > 60_000) rmSync(p, { force: true });
          } catch {
            // Gone already.
          }
        }
      }
    }
    return { removed, bytes: dirBytes(this.root) };
  }
}
