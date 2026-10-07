/**
 * O-2 (mcp-coordination-design.md): the provider directory and the durable
 * ("standing") listing store.
 *
 * Directory pin — `CONTRACT_DIRECTORY=<name>:<providerKeyId>[,…]`, the same
 * append-only env discipline as `CONTRACT_PRINCIPALS`. A listing may claim a
 * directory name only when the publishing provider keyId is the one pinned
 * to that name, so a name such as `roma-travel` cannot be squatted. Only a
 * directory-pinned listing may be standing.
 *
 * Standing listings are persisted to `<stateDir>/standing-listings.json`
 * (metadata only — never pending deliveries) with the same tmp + fsync +
 * rename + dirsync discipline as terminal-jobs/used-mandates, so a restart
 * keeps Roma findable. A corrupt file is a hard startup error, never
 * silently "empty".
 */
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync,
  renameSync, writeFileSync,
} from "node:fs";
import path from "node:path";

/** Directory names: lowercase slug, 2-64 chars. */
export const DIRECTORY_NAME = /^[a-z0-9][a-z0-9-]{1,63}$/;

/**
 * Parse `CONTRACT_DIRECTORY`. Fails closed on a malformed entry, a name
 * listed twice (a re-pin must replace the entry, never shadow it), and —
 * when `providerKeyIds` is given — a keyId that is not a provider token.
 */
export function parseContractDirectory(
  raw: string | undefined,
  providerKeyIds?: ReadonlySet<string>,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const entry of (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const [name, keyId, ...extra] = entry.split(":").map((s) => s.trim());
    if (!name || !DIRECTORY_NAME.test(name) || !keyId || keyId.length > 64 || extra.length > 0) {
      throw new Error("malformed CONTRACT_DIRECTORY entry (want name:providerKeyId)");
    }
    if (out.has(name)) throw new Error(`CONTRACT_DIRECTORY lists ${name} more than once`);
    if (providerKeyIds !== undefined && !providerKeyIds.has(keyId)) {
      throw new Error(`CONTRACT_DIRECTORY: ${name} is pinned to a keyId with no provider token`);
    }
    out.set(name, keyId);
  }
  return out;
}

export const STANDING_LISTINGS_FILE = "standing-listings.json";
const STANDING_LISTINGS_SCHEMA = "agent-contract.standing-listings/v1";

export interface StandingListingRecord {
  listingId: string;
  providerKeyId: string;
  directoryName: string;
  title: string;
  summary: string;
  sealedBoxPublicKeyHex: string;
  terms?: Record<string, unknown>;
  publishedAtMs: number;
  expiresAtMs: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function validRecord(r: unknown): r is StandingListingRecord {
  return isRecord(r)
    && typeof r.listingId === "string" && typeof r.providerKeyId === "string"
    && typeof r.directoryName === "string" && typeof r.title === "string"
    && typeof r.summary === "string" && typeof r.sealedBoxPublicKeyHex === "string"
    && (r.terms === undefined || isRecord(r.terms))
    && Number.isSafeInteger(r.publishedAtMs) && Number.isSafeInteger(r.expiresAtMs);
}

/** Load persisted standing listings (expiry and pin re-checks are the caller's). */
export function loadStandingListings(stateDir: string): StandingListingRecord[] {
  const file = path.join(stateDir, STANDING_LISTINGS_FILE);
  if (!existsSync(file)) return [];
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isRecord(raw) || raw.schema !== STANDING_LISTINGS_SCHEMA || !Array.isArray(raw.listings)) {
    throw new Error(`corrupt ${STANDING_LISTINGS_FILE}`);
  }
  for (const r of raw.listings) {
    if (!validRecord(r)) throw new Error(`corrupt ${STANDING_LISTINGS_FILE}`);
  }
  return raw.listings as StandingListingRecord[];
}

/** Durable write: tmp file → fsync → rename → fsync the directory. */
export function persistStandingListings(stateDir: string, listings: readonly StandingListingRecord[]): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, STANDING_LISTINGS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ schema: STANDING_LISTINGS_SCHEMA, listings }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dirFd = openSync(stateDir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}
