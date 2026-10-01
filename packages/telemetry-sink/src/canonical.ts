import { createHash } from "node:crypto";

/**
 * Canonical JSON per the pairing LLD §9: object keys sorted recursively, no
 * insignificant whitespace, UTF-8. Undefined object properties are dropped
 * (JSON semantics); `undefined`/`function`/`symbol` array members or
 * top-level values throw — digests must never silently collide.
 *
 * Byte-compatible copy of `packages/mcp-server/src/agent-contract/canonical.ts`
 * (itself a port of the travel repo's T0 contracts). The telemetry-sink
 * package is standalone, so this is vendored rather than imported.
 */
export function canonicalJson(value: unknown): string {
  const canon = (v: unknown): string => {
    if (v === null) return "null";
    switch (typeof v) {
      case "number":
        if (!Number.isFinite(v)) throw new Error("canonicalJson: non-finite number");
        return JSON.stringify(v);
      case "boolean":
      case "string":
        return JSON.stringify(v);
      case "object": {
        if (Array.isArray(v)) {
          return `[${v.map((item) => {
            if (item === undefined || typeof item === "function" || typeof item === "symbol") {
              throw new Error("canonicalJson: unrepresentable array member");
            }
            return canon(item);
          }).join(",")}]`;
        }
        const obj = v as Record<string, unknown>;
        return `{${Object.keys(obj)
          .filter((k) => obj[k] !== undefined && typeof obj[k] !== "function" && typeof obj[k] !== "symbol")
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canon(obj[k])}`)
          .join(",")}}`;
      }
      default:
        throw new Error(`canonicalJson: unrepresentable type ${typeof v}`);
    }
  };
  return canon(value);
}

/** sha256 of canonical JSON, `0x`-prefixed hex. */
export function canonicalDigest(value: unknown): string {
  return `0x${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

/** sha256 of raw bytes, `0x`-prefixed hex (for stored request bodies). */
export function bodyDigest(data: Uint8Array): string {
  return `0x${createHash("sha256").update(data).digest("hex")}`;
}
