import { readFileSync, statSync } from "node:fs";
import type { JsonWebKey } from "node:crypto";

/**
 * Load the role local-services x25519 private key (JWK) from disk.
 * The file MUST be mode 0600 AND owned by the services uid — anything looser
 * means the services uid is not the only reader/writer and the key cannot be
 * trusted to seal/unseal tokens.
 */
export function readServicesKeyFile(path: string, opts: { ownerUid?: number } = {}): JsonWebKey {
  const stat = statSync(path);
  const ownerUid = opts.ownerUid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  if (ownerUid !== undefined && stat.uid !== ownerUid) {
    throw new Error(
      `services key file must be owned by uid ${ownerUid} (got uid ${stat.uid}): ${path}`,
    );
  }
  const mode = stat.mode & 0o777;
  if (mode !== 0o600) {
    throw new Error(
      `services key file must be mode 0600 (got ${mode.toString(8)}): ${path}`,
    );
  }
  const jwk = JSON.parse(readFileSync(path, "utf8")) as JsonWebKey;
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || typeof jwk.d !== "string") {
    throw new Error("services key file is not an x25519 private JWK");
  }
  return jwk;
}
