// A safety net for the automatic logging tools: credentials the agent should already have replaced with [redacted]
// (the instructions say so) are replaced here too before a step is recorded, because a record can be read by anyone
// holding its link. Only well-known shapes are matched, so this is a backstop, not a guarantee.
const PATTERNS: [RegExp, string][] = [
  [/cck_[A-Za-z0-9_-]{16,}/g, "[redacted]"], // Clockchain account key
  [/\bcc_(?:rt_|code_|grant_|req_|ac_|client_)[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g, "[redacted]"], // our OAuth artifacts
  [/\bcc_[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, "[redacted]"], // our signed tokens
  [/\b(Bearer)\s+[A-Za-z0-9._~+/=-]{16,}/gi, "$1 [redacted]"],
  [/\bsk-[A-Za-z0-9_-]{20,}/g, "[redacted]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[redacted]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[redacted]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[redacted]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted]"],
];

export function redactText(text: string): string {
  let out = text;
  for (const [re, by] of PATTERNS) out = out.replace(re, by);
  return out;
}

/** The same value with every string (object keys included) passed through {@link redactText}. Depth is checked first. */
export function redactSecrets<T>(value: T): T {
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      // defineProperty: a key called __proto__ stays plain data.
      Object.defineProperty(out, redactText(k), { value: redactSecrets(v), enumerable: true, writable: true, configurable: true });
    }
    return out as T;
  }
  return value;
}
