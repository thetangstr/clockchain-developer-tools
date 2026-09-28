import { createHash } from "node:crypto";

/**
 * Deterministic PRNG primitives ported verbatim from the travel repo's
 * `src/lib/travel/simulator/prng.ts` (N4b-2 sim slice). `mulberry32` gives a
 * stable stream per 32-bit seed; `seedFromName` derives that seed from a name
 * via sha256 so a runId alone fully determines every simulated identifier.
 */
export function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

export function seedFromName(name: string): number {
  const digest = createHash("sha256").update(name, "utf8").digest();
  return digest.readUInt32BE(0);
}
