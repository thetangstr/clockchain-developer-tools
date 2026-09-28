import { createHash, createHmac } from "node:crypto";

/**
 * Canonical JSON per the pairing LLD §9: object keys sorted recursively, no
 * insignificant whitespace, UTF-8. Undefined object properties are dropped
 * (JSON semantics); `undefined`/`function`/`symbol` array members or
 * top-level values throw — digests must never silently collide.
 *
 * This is a deliberate port of the travel repo's T0
 * `src/lib/agent-pairing/contracts.ts` canonicalJson/canonicalDigest.
 * The two repos carry different zod majors, so parity is proven by the
 * committed vectors in `test/fixtures/agent-contract-canonical-digest-vectors.json`,
 * not by shared code — keep this implementation byte-compatible.
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

/** HMAC-SHA256 over canonical JSON, `0x`-prefixed hex (M4 salted argsDigests). */
export function saltedCanonicalDigest(saltHex: string, value: unknown): string {
  return `0x${createHmac("sha256", Buffer.from(saltHex, "hex"))
    .update(canonicalJson(value), "utf8")
    .digest("hex")}`;
}

/**
 * M4 (N4b-3): a call is CAP-BEARING — its arguments could leak a money value
 * through a brute-forced argsDigest — when the tool is in the `mandate_*`
 * family or any argument key carries an amount (`*Minor`, `price`, `cap`,
 * `amount`, `fare`, `fee`, `total`, `cost` — matched case-insensitively at
 * any depth). Cap-bearing receipts carry HMAC-SHA256(runSalt, args) instead
 * of the plain canonicalDigest; the per-scope salt is disclosed only to the
 * verifier endpoint, never to the observer feed.
 */
const AMOUNT_KEY = /^(?:.*_)?(?:cap|price|fare|amount|fee|total|cost)(?:minor|usd|cents|decimal)?$/i;
export function isCapBearingCall(toolName: string, args: unknown): boolean {
  if (toolName.startsWith("mandate_")) return true;
  const scan = (v: unknown): boolean => {
    if (v === null || typeof v !== "object") return false;
    if (Array.isArray(v)) return v.some(scan);
    return Object.keys(v as Record<string, unknown>).some(
      (k) => AMOUNT_KEY.test(k) || scan((v as Record<string, unknown>)[k]),
    );
  };
  return scan(args);
}
