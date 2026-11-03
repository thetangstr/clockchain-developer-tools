import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { cleanStaleFiles, createDurableJsonFile } from "./handshake-core/durable-store.js";
import { isAcctId, newAcctId } from "./token.js";

/**
 * Clockchain accounts for the OAuth approval page (src/oauth.ts): a person names an account once, with no email,
 * and every app they approve afterwards gets the same `acct`. Plain files under `<MCP_STATE_DIR>/accounts/`, written
 * with the handshake surfaces' durable writer (0700 dirs, 0600 files, fsync, rename, .bak), like the hosted Shadow
 * store, so accounts survive restarts and code-only deploys on the /app/state volume:
 *
 *   a/<acct>.json        { acct, name, createdAt, keyHash }
 *   k/<keyHash>.json     { acct }        lookup index for account-key sign-in
 *
 * The account key (`cck_` + 32 base64url characters, 192 random bits) is shown once at creation. Only its SHA-256 is
 * stored, compared in constant time; the key itself is never written or logged.
 */

export const ACCOUNT_KEY_PATTERN = /^cck_[A-Za-z0-9_-]{32}$/;
export const ACCOUNT_NAME_MAX = 40;
export const DEFAULT_MAX_ACCOUNTS = 50_000;
const KEY_HASH = /^[0-9a-f]{64}$/;
const ACCOUNT_FILE = /^acct_[A-Za-z0-9_-]{22}\.json$/;
const RECORD_MAX_BYTES = 4 * 1024;

export interface Account {
  acct: string;
  name: string;
  createdAt: string;
  keyHash: string;
}

/** True for text holding (part of) an account key: cck_ and 16 or more key characters (follow-up finding 7). */
export const looksLikeAccountKey = (raw: unknown): boolean => typeof raw === "string" && /cck_[A-Za-z0-9_-]{16,}/.test(raw);

/**
 * A display name: control and format characters dropped, whitespace collapsed and trimmed, 1 to 40 characters.
 * Never something that looks like an account key, so a key pasted into the name box is never stored as a name.
 */
export function cleanAccountName(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length > 1000 || looksLikeAccountKey(raw)) return undefined;
  const text = raw.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/g, " ").trim();
  const length = Array.from(text).length;
  return length >= 1 && length <= ACCOUNT_NAME_MAX ? text : undefined;
}

const hashKey = (key: string): string => createHash("sha256").update(key, "utf8").digest("hex");
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function validateAccount(value: unknown): Account {
  if (
    !isObject(value) || !isAcctId(value.acct) || typeof value.name !== "string" || cleanAccountName(value.name) !== value.name ||
    typeof value.createdAt !== "string" || typeof value.keyHash !== "string" || !KEY_HASH.test(value.keyHash)
  ) throw new Error("bad account record");
  return { acct: value.acct, name: value.name, createdAt: value.createdAt, keyHash: value.keyHash };
}

function validateKeyEntry(value: unknown): { acct: string } {
  if (!isObject(value) || !isAcctId(value.acct)) throw new Error("bad key index entry");
  return { acct: value.acct };
}

export type CreateResult = { ok: true; account: Account; key: string } | { ok: false; reason: "full" };

/**
 * A record exists but cannot be read (corrupt, with no valid backup). Distinct from "not found": the person's cookie
 * must survive it, and the page answers 503 until an operator restores the file.
 */
export class AccountUnavailableError extends Error {
  constructor() {
    super("account record unreadable");
    this.name = "AccountUnavailableError";
  }
}

export class AccountStore {
  private readonly accountsDir: string;
  private readonly keysDir: string;
  private readonly cache = new Map<string, Account>();
  /** Unreadable record files -> their mtime when they failed: re-read (and re-quarantined) only once they change. */
  private readonly unreadable = new Map<string, number>();
  private total: number;

  /** Opens (creating if needed) the store at `root`; throws when the directory cannot be made private. */
  constructor(root: string, private readonly maxAccounts = DEFAULT_MAX_ACCOUNTS, private readonly now: () => number = Date.now) {
    this.accountsDir = join(root, "a");
    this.keysDir = join(root, "k");
    for (const dir of [root, this.accountsDir, this.keysDir]) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
    }
    cleanStaleFiles(this.accountsDir);
    cleanStaleFiles(this.keysDir);
    this.total = readdirSync(this.accountsDir).filter((name) => ACCOUNT_FILE.test(name)).length;
  }

  /** Accounts on disk (the global cap counts these). */
  count(): number {
    return this.total;
  }

  private accountFile(acct: string, current?: Account) {
    return createDurableJsonFile<Account>({
      path: join(this.accountsDir, `${acct}.json`),
      schema: "clockchain-account-v1",
      snapshot: () => current!,
      validate: validateAccount,
      maxBytes: RECORD_MAX_BYTES,
    });
  }

  private keyFile(keyHash: string, current?: { acct: string }) {
    return createDurableJsonFile<{ acct: string }>({
      path: join(this.keysDir, `${keyHash}.json`),
      schema: "clockchain-account-key-v1",
      snapshot: () => current!,
      validate: validateKeyEntry,
      maxBytes: RECORD_MAX_BYTES,
    });
  }

  /**
   * Loads a record file. A missing file is undefined; an unreadable one throws AccountUnavailableError, and is not
   * read again (so its quarantine copy is written once) until its mtime changes, as when an operator restores it.
   */
  private loadRecord<T>(path: string, load: () => T | undefined): T | undefined {
    const failedAt = this.unreadable.get(path);
    if (failedAt !== undefined) {
      if (!existsSync(path)) {
        this.unreadable.delete(path);
        return undefined;
      }
      if (statSync(path).mtimeMs === failedAt) throw new AccountUnavailableError();
      this.unreadable.delete(path);
    }
    try {
      return load();
    } catch {
      // The durable writer has logged it and copied the bad file aside (handshake_state_corrupt).
      this.unreadable.set(path, existsSync(path) ? statSync(path).mtimeMs : -1);
      throw new AccountUnavailableError();
    }
  }

  /** The account for a well-formed acct id, or undefined when there is none. Throws AccountUnavailableError when its record cannot be read. */
  get(acct: string): Account | undefined {
    if (!isAcctId(acct)) return undefined;
    const cached = this.cache.get(acct);
    if (cached) return cached;
    const account = this.loadRecord(join(this.accountsDir, `${acct}.json`), () => this.accountFile(acct).load());
    if (!account || account.acct !== acct) return undefined;
    this.cache.set(acct, account);
    return account;
  }

  /** Creates an account with an already-cleaned name. Refuses past the global cap. Throws if it cannot be persisted. */
  create(name: string): CreateResult {
    if (this.total >= this.maxAccounts) return { ok: false, reason: "full" };
    const clean = cleanAccountName(name);
    if (clean === undefined || clean !== name) throw new Error("account name must be cleaned first");
    let acct = newAcctId();
    while (this.get(acct)) acct = newAcctId();
    const key = `cck_${randomBytes(24).toString("base64url")}`;
    const account: Account = { acct, name, createdAt: new Date(this.now()).toISOString(), keyHash: hashKey(key) };
    // The account first, then its key index: a crash in between leaves an account the cookie still reaches.
    this.accountFile(acct, account).save("now");
    this.keyFile(account.keyHash, { acct }).save("now");
    this.cache.set(acct, account);
    this.total += 1;
    return { ok: true, account, key };
  }

  /** The account an account key belongs to, or undefined. Throws AccountUnavailableError when a record cannot be read. */
  findByKey(key: unknown): Account | undefined {
    if (typeof key !== "string" || !ACCOUNT_KEY_PATTERN.test(key)) return undefined;
    const keyHash = hashKey(key);
    const entry = this.loadRecord(join(this.keysDir, `${keyHash}.json`), () => this.keyFile(keyHash).load());
    const account = entry ? this.get(entry.acct) : undefined;
    if (!account) return undefined;
    const stored = Buffer.from(account.keyHash, "hex");
    const given = Buffer.from(keyHash, "hex");
    return stored.length === given.length && timingSafeEqual(stored, given) ? account : undefined;
  }
}
