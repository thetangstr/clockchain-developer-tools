import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

/** Compute a lowercase hex SHA-256 digest of a string or Buffer. */
export function computeHash(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Compute the SHA-256 hex digest of a file's contents. */
export async function hashFile(path: string): Promise<string> {
  const buf = await readFile(path);
  return computeHash(buf);
}
