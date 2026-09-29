// A durable map from short public role-access handles (Standalone `csha_`, v2 `ccra_`) to
// the role tokens behind them, so a client keeps its handle across a restart (spec B2).
//
// Token at rest: the file never holds a raw handle or a raw token. Each record is keyed by
// sha256(handle) and holds the token sealed with a key derived from the HANDLE, and the
// handle sealed with a key derived from the TOKEN (AES-256-GCM, HKDF-SHA256, per-surface
// domain label, the handle digest as AAD):
//   - resolve(handle): only a caller holding the handle can derive the key that opens the
//     token, exactly the capability it already has;
//   - issue(token) (idempotent per token): only a caller holding the token can recover its
//     existing handle, and a token holder can already act as that role.
// A stolen state file, even together with every server secret, yields no usable handle or
// token: there is no server-side key to steal and nothing to rotate. Both credentials are
// high-entropy (128-bit random handles; 256-bit random or HMAC-signed tokens), so the
// sealed values cannot be brute-forced. Tokens are still verified on every use as before.
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";

import { createDurableJsonFile, type DurableJsonFile } from "./durable-store.js";

interface SealedRecord {
  /** sha256(token), hex: the per-token index for idempotent issue. */
  t: string;
  /** Token sealed under a key derived from the handle. */
  tokenSealed: string;
  /** Handle sealed under a key derived from the token. */
  handleSealed: string;
  expiresAt: number;
}

const SCHEMA = "clockchain.handshake-handle-map/v1";
const SEAL_SALT = Buffer.from("clockchain.handle-seal/v1", "utf8");
const MAX_FILE_BYTES = 16 * 1024 * 1024;

function digest(label: string, value: string): string {
  return createHash("sha256").update(`${label}\u0000${value}`, "utf8").digest("hex");
}

function keyFrom(label: string, purpose: "token" | "handle", credential: string): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(credential, "utf8"), SEAL_SALT, `${label}:${purpose}`, 32));
}

function seal(key: Buffer, plaintext: string, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, body, cipher.getAuthTag()]).toString("base64url");
}

function open(key: Buffer, sealed: string, aad: string): string | undefined {
  try {
    const raw = Buffer.from(sealed, "base64url");
    const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString("utf8");
  } catch {
    return undefined;
  }
}

export interface HandleMap {
  /** The live handle for `token`, reused if one exists (TTL refreshed), else a new one. Undefined when full. */
  issue(token: string, expiresAt: number): string | undefined;
  /** The token behind `handle`, or undefined. With `slideTo`, the handle's expiry moves forward. */
  resolve(handle: string, slideTo?: number): string | undefined;
  size(): number;
  close(): void;
}

export function createHandleMap(options: {
  /** Domain label, e.g. "standalone/csha" or "v2/ccra". */
  label: string;
  prefix: string;
  limit: number;
  now: () => number;
  /** Durable file; memory-only when omitted. */
  path?: string;
  coalesceMs?: number;
}): HandleMap {
  const { label, prefix, limit, now } = options;
  const records = new Map<string, SealedRecord>(); // sha256(handle) -> record
  const byToken = new Map<string, string>(); // sha256(token) -> sha256(handle)

  const file: DurableJsonFile<Record<string, SealedRecord>> | undefined = options.path === undefined ? undefined : createDurableJsonFile({
    path: options.path,
    schema: SCHEMA,
    maxBytes: MAX_FILE_BYTES,
    coalesceMs: options.coalesceMs,
    snapshot: () => Object.fromEntries(records),
    validate: (value) => {
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("records must be an object");
      for (const [key, record] of Object.entries(value as Record<string, any>)) {
        if (!/^[0-9a-f]{64}$/.test(key) || typeof record?.t !== "string" || !/^[0-9a-f]{64}$/.test(record.t)) throw new Error("bad key");
        if (typeof record.tokenSealed !== "string" || typeof record.handleSealed !== "string" || !Number.isSafeInteger(record.expiresAt)) throw new Error("bad record");
      }
      return value as Record<string, SealedRecord>;
    },
  });

  const loaded = file?.load();
  if (loaded) {
    const current = now();
    for (const [key, record] of Object.entries(loaded)) {
      if (current >= record.expiresAt) continue;
      records.set(key, record);
      byToken.set(record.t, key);
    }
  }

  function prune(current: number): boolean {
    let changed = false;
    for (const [key, record] of records) {
      if (current < record.expiresAt) continue;
      records.delete(key);
      if (byToken.get(record.t) === key) byToken.delete(record.t);
      changed = true;
    }
    return changed;
  }

  return {
    issue(token: string, expiresAt: number): string | undefined {
      const current = now();
      const pruned = prune(current);
      const tokenDigest = digest(label, token);
      const existingKey = byToken.get(tokenDigest);
      const existing = existingKey === undefined ? undefined : records.get(existingKey);
      if (existingKey !== undefined && existing !== undefined) {
        const handle = open(keyFrom(label, "handle", token), existing.handleSealed, existingKey);
        if (handle !== undefined && digest(label, handle) === existingKey) {
          if (expiresAt > existing.expiresAt) {
            existing.expiresAt = expiresAt;
            file?.save("soon");
          }
          return handle;
        }
      }
      if (records.size >= limit) {
        if (pruned) file?.save("soon");
        return undefined;
      }
      let handle: string;
      let key: string;
      do {
        handle = `${prefix}${randomBytes(16).toString("base64url")}`;
        key = digest(label, handle);
      } while (records.has(key));
      records.set(key, {
        t: tokenDigest,
        tokenSealed: seal(keyFrom(label, "token", handle), token, key),
        handleSealed: seal(keyFrom(label, "handle", token), handle, key),
        expiresAt,
      });
      byToken.set(tokenDigest, key);
      // A client may use the handle the moment it has it, so it is durable before it is returned.
      file?.save("now");
      return handle;
    },

    resolve(handle: string, slideTo?: number): string | undefined {
      const current = now();
      if (prune(current)) file?.save("soon");
      const key = digest(label, handle);
      const record = records.get(key);
      if (record === undefined) return undefined;
      const token = open(keyFrom(label, "token", handle), record.tokenSealed, key);
      if (token === undefined || digest(label, token) !== record.t) return undefined;
      if (slideTo !== undefined && slideTo > record.expiresAt) {
        record.expiresAt = slideTo;
        file?.save("soon");
      }
      return token;
    },

    size(): number {
      return records.size;
    },

    close(): void {
      file?.flush();
      file?.close();
    },
  };
}
