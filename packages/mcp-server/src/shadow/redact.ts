// A safety net for the automatic logging tools: credentials the agent should already have replaced with [redacted]
// (the instructions say so) are replaced here too before a step is recorded, because a record can be read by anyone
// holding its link. Only well-known shapes are matched, so this is a backstop, not a guarantee.
//
// Every step here runs in time linear in the text, on purpose: this runs on the event loop, on text an authenticated
// caller chose. A regex that can rescan from each of many start positions (a `\b` prefix inside a run that also matches
// its own character class, or a lazy scan to a closing marker that never comes) stalled the whole server in review.
// Those shapes are matched in two steps below: find the whole run once, then look inside it. Callers also cap the text
// before it gets here.
const PATTERNS: [RegExp, string][] = [
  [/cck_[A-Za-z0-9_-]{16,}/g, "[redacted]"], // Clockchain account key
  [/\bcc_(?:rt_|code_|grant_|req_|ac_|client_)[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g, "[redacted]"], // our OAuth artifacts
  [/\b(Bearer)\s+[A-Za-z0-9._~+/=-]{16,}/gi, "$1 [redacted]"],
  [/\bsk-[A-Za-z0-9_-]{20,}/g, "[redacted]"],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, "[redacted]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[redacted]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[redacted]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[redacted]"],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, "[redacted]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[redacted]"],
  [/\b(password|passwd|pwd|api[_-]?key)(["']?\s{0,8}[=:]\s{0,8})("[^"\n]{1,200}"|'[^'\n]{1,200}'|[^\s"'&,;]{1,200})/gi, "$1$2[redacted]"],
];

/** Our signed tokens, cc_<payload>.<signature>, found by looking inside each run once. */
const signedTokens = (text: string): string =>
  text.replace(/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]{20,})?/g, (run: string, tail: string | undefined) => {
    if (!tail) return run;
    const at = run.search(/\bcc_/);
    return at >= 0 && run.length - tail.length - at - 3 >= 20 ? run.slice(0, at) + "[redacted]" : run;
  });

/** JSON Web Tokens: three dotted parts, the first starting eyJ. Each dotted chain is found once and looked through once. */
const webTokens = (text: string): string =>
  text.replace(/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*/g, (chain: string) => {
    if (!chain.includes("eyJ")) return chain;
    const parts = chain.split(".");
    const kept: string[] = [];
    for (let i = 0; i < parts.length; i++) {
      const at = parts[i].search(/\beyJ/);
      if (at >= 0 && parts[i].length - at >= 8 && (parts[i + 1]?.length ?? 0) >= 8 && (parts[i + 2]?.length ?? 0) >= 8) {
        kept.push(`${parts[i].slice(0, at)}[redacted]`);
        i += 2;
      } else {
        kept.push(parts[i]);
      }
    }
    return kept.join(".");
  });

const PEM_BEGIN = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/g;
const PEM_END = /-----END [A-Z ]{0,40}PRIVATE KEY-----/g;

/** Private keys, from BEGIN to END. One pass: without an END, the rest of the text goes too (it is the rest of a key). */
function privateKeys(text: string): string {
  if (!text.includes("PRIVATE KEY-----")) return text;
  let out = "";
  let at = 0;
  PEM_BEGIN.lastIndex = 0;
  for (let m = PEM_BEGIN.exec(text); m; m = PEM_BEGIN.exec(text)) {
    out += `${text.slice(at, m.index)}[redacted]`;
    PEM_END.lastIndex = PEM_BEGIN.lastIndex;
    const end = PEM_END.exec(text);
    if (!end) return out;
    at = PEM_BEGIN.lastIndex = PEM_END.lastIndex;
  }
  return out + text.slice(at);
}

export function redactText(text: string): string {
  let out = webTokens(signedTokens(privateKeys(text)));
  for (const [re, by] of PATTERNS) out = out.replace(re, by);
  return out;
}

/** A field whose name says its value is a credential: the value goes, whatever it looks like. */
const SECRET_FIELD = /^(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?token|refresh[_-]?token|authorization|x-api-key|cookie|set-cookie)$/i;

/** The same value with every string (object keys included) passed through {@link redactText}. Depth is checked first. */
export function redactSecrets<T>(value: T): T {
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      // defineProperty: a key called __proto__ stays plain data.
      const clean = typeof v === "string" && SECRET_FIELD.test(k) ? "[redacted]" : redactSecrets(v);
      Object.defineProperty(out, redactText(k), { value: clean, enumerable: true, writable: true, configurable: true });
    }
    return out as T;
  }
  return value;
}
