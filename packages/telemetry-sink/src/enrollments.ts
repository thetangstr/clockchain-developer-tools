import { createPublicKey } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { acquireTokenFileLock, releaseTokenFileLock, type ContractRole } from "./tokens.js";

/**
 * O-1 enrollment registry: the ONLY place a seal-to key enters the sink.
 *
 *   enrollments.json = {
 *     schema: "ac-telemetry.enrollments/v1",
 *     entries: { "<principal keyId>": { role, x25519: "0x<64 hex>", enrolledAtMs } },
 *   }
 *
 * Written only by the sink admin (`enroll-cli`, inside the sink container,
 * against the state volume — same position as the mint CLI). The running
 * server reads it on mtime change and NEVER writes it: no HTTP route adds,
 * changes, or reveals an entry. `/v1/lanes/open` names a keyId; the sink seals
 * the lane's ingest token to the key it enrolled here, never to a key from
 * the request.
 */

export const ENROLLMENTS_SCHEMA = "ac-telemetry.enrollments/v1" as const;

export interface Enrollment {
  keyId: string;
  role: ContractRole;
  /** raw x25519 public key, 0x + 64 lower-case hex. */
  x25519: `0x${string}`;
  enrolledAtMs: number;
}

interface EnrollmentsDoc {
  schema: typeof ENROLLMENTS_SCHEMA;
  entries: Record<string, Omit<Enrollment, "keyId">>;
}

/** Principal keyIds as the contract service's CONTRACT_AUTH_TOKENS carries them (no `:` / `,`). */
export const ENROLL_KEY_ID_RE = /^[A-Za-z0-9._*@+-]{1,128}$/;
const X25519_RE = /^0x[0-9a-f]{64}$/;

/** Throws unless `hex` is a usable raw x25519 public key (not all-zero). */
export function assertX25519Public(hex: string): asserts hex is `0x${string}` {
  if (!X25519_RE.test(hex)) throw new Error("x25519 public key must be 0x + 64 lower-case hex");
  if (/^0x0{64}$/.test(hex)) throw new Error("x25519 public key must not be all-zero");
  createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: Buffer.from(hex.slice(2), "hex").toString("base64url") },
    format: "jwk",
  });
}

function readEnrollmentsFile(file: string): EnrollmentsDoc {
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (typeof raw !== "object" || raw === null || (raw as EnrollmentsDoc).schema !== ENROLLMENTS_SCHEMA) {
    throw new Error(`corrupt ${file}: not a ${ENROLLMENTS_SCHEMA} document`);
  }
  const entries = (raw as EnrollmentsDoc).entries;
  if (typeof entries !== "object" || entries === null || Array.isArray(entries)) {
    throw new Error(`corrupt ${file}: bad entries`);
  }
  // Null-prototype map: a keyId like "__proto__" must never smuggle state.
  const out: Record<string, Omit<Enrollment, "keyId">> = Object.create(null);
  for (const [keyId, e] of Object.entries(entries)) {
    if (!ENROLL_KEY_ID_RE.test(keyId)) throw new Error(`corrupt ${file}: bad keyId`);
    const v = e as Record<string, unknown>;
    if (typeof v !== "object" || v === null
      || (v.role !== "buyer" && v.role !== "provider")
      || typeof v.x25519 !== "string" || !X25519_RE.test(v.x25519)
      || typeof v.enrolledAtMs !== "number"
      || Object.keys(v).some((k) => k !== "role" && k !== "x25519" && k !== "enrolledAtMs")) {
      // Only the three public fields are ever stored — anything else (a
      // private JWK, a token) refuses the whole file.
      throw new Error(`corrupt ${file}: bad entry shape`);
    }
    out[keyId] = { role: v.role, x25519: v.x25519 as `0x${string}`, enrolledAtMs: v.enrolledAtMs };
  }
  return { schema: ENROLLMENTS_SCHEMA, entries: out };
}

function writeEnrollmentsAtomic(file: string, doc: EnrollmentsDoc): void {
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

/** Read-only view the server holds. */
export interface EnrollmentRegistry {
  get(keyId: string): Enrollment | undefined;
  list(): Enrollment[];
}

/**
 * The server's read-only registry. `file` absent → no enrollments (every
 * lane-open refuses NOT_ENROLLED). A corrupt file fails closed: the read
 * throws, and the lane-open route answers 500 without minting.
 */
export function createEnrollmentRegistry(options: { file?: string; entries?: Enrollment[] } = {}): EnrollmentRegistry {
  let entries: Record<string, Omit<Enrollment, "keyId">> = Object.create(null);
  for (const e of options.entries ?? []) {
    assertX25519Public(e.x25519);
    entries[e.keyId] = { role: e.role, x25519: e.x25519, enrolledAtMs: e.enrolledAtMs };
  }
  let lastMtimeMs = -1;
  const refresh = (): void => {
    const file = options.file;
    if (file === undefined || !existsSync(file)) return;
    const mtimeMs = statSync(file).mtimeMs;
    if (mtimeMs === lastMtimeMs) return;
    entries = readEnrollmentsFile(file).entries;
    lastMtimeMs = mtimeMs;
  };
  refresh();
  return {
    get(keyId) {
      refresh();
      if (!Object.hasOwn(entries, keyId)) return undefined;
      return { keyId, ...entries[keyId] };
    },
    list() {
      refresh();
      return Object.entries(entries).map(([keyId, e]) => ({ keyId, ...e }));
    },
  };
}

/**
 * Admin write (enroll-cli only). Write-once per keyId: an identical
 * re-enrollment is a no-op; a different key or role for an enrolled keyId
 * is refused (rotation is a separate, reviewed step — not an overwrite).
 * Serialized with the same ownership-aware lock discipline as tokens.json.
 */
export async function enrollParty(input: {
  file: string;
  keyId: string;
  role: ContractRole;
  x25519: string;
  now?: () => number;
}): Promise<{ enrollment: Enrollment; created: boolean }> {
  if (!ENROLL_KEY_ID_RE.test(input.keyId)) throw new Error("keyId must match [A-Za-z0-9._*@+-]{1,128}");
  if (input.role !== "buyer" && input.role !== "provider") throw new Error("role must be buyer|provider");
  assertX25519Public(input.x25519);
  const nonce = await acquireTokenFileLock(input.file, 10_000);
  try {
    const doc: EnrollmentsDoc = existsSync(input.file)
      ? readEnrollmentsFile(input.file)
      : { schema: ENROLLMENTS_SCHEMA, entries: Object.create(null) };
    const existing = Object.hasOwn(doc.entries, input.keyId) ? doc.entries[input.keyId] : undefined;
    if (existing !== undefined) {
      if (existing.role !== input.role || existing.x25519 !== input.x25519) {
        throw new Error(`keyId already enrolled with a different key or role: ${input.keyId}`);
      }
      return { enrollment: { keyId: input.keyId, ...existing }, created: false };
    }
    const entry = { role: input.role, x25519: input.x25519, enrolledAtMs: (input.now ?? Date.now)() };
    doc.entries[input.keyId] = entry;
    writeEnrollmentsAtomic(input.file, doc);
    return { enrollment: { keyId: input.keyId, ...entry }, created: true };
  } finally {
    releaseTokenFileLock(input.file, nonce);
  }
}
