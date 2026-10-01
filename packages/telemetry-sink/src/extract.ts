import { verify, type KeyObject } from "node:crypto";

import { bodyDigest, canonicalDigest, canonicalJson } from "./canonical.js";
import type { ContractRole } from "./tokens.js";
import {
  verifyRecords,
  ANNEX_SCHEMA,
  type RecordEntry,
  type RefusalAnnex,
  type SignedHead,
  type SinkRecord,
  type VerifyFailureCode,
} from "./sink.js";

/**
 * Stored OTLP records → `TelemetrySpan` rows (N4c; LLD §9 `TelemetrySpan
 * {role, runtime, ts, tool, serverNonce?, argsDigest?, sinkRef}`), the input
 * to R13(d) nonce-matching.
 *
 * Post-review semantics (N4C-CHANGES-1):
 *  - `role` is stamped from the SINK RECORD's token binding — never caller
 *    input — and the extracted runtime must equal the pinned runtime for
 *    that role (`roleRuntime`), else the row is refused.
 *  - Every row carries `receivedAt` (the sink's clock). Matching uses it;
 *    the body's own `ts` is informational only.
 *  - Bodies are re-hashed: a record whose bytes don't match `bodyDigest` is
 *    refused, not parsed.
 *  - Nonces are extracted STRUCTURALLY: the tool result is JSON-parsed
 *    (including double-encoded `content[].text` parts) and exactly one
 *    `serverNonce` must exist; more is flagged ambiguous. A result with
 *    `isError: true` yields NO nonce and is flagged `error_result`.
 *  - The tool name comes only from the dedicated tool-name attribute
 *    (`tool.name` / `tool_name` / `function_name`) — never from
 *    `arguments.name` or `arguments.tool`.
 *
 * Post-review (N4C-CHANGES-2): the ONLY public entry is `verifyAndExtract` —
 * it verifies the full chain against a FINAL head under pinned sink keys
 * first and returns rows only if that passes. `extractTelemetrySpans` is
 * internal. No chain, no rows.
 */

export interface TelemetrySpan {
  /** Stamped from the record's token binding. */
  role: ContractRole;
  runtime: string;
  /** Event time from the OTLP body — informational only, never used to match. */
  ts: number;
  /** The sink's clock — the timestamp matching MUST use. */
  receivedAt: string;
  receivedAtMs: number;
  tool: string;
  serverNonce?: string;
  argsDigest?: string;
  /** recordDigest of the sink record this span was extracted from. */
  sinkRef: string;
  flags?: string[];
}

export type ExtractRefusalCode = "BODY_DIGEST" | "ROLE_MISSING" | "RUNTIME_MISMATCH";

export interface ExtractRefusal {
  sinkRef: string;
  code: ExtractRefusalCode;
  tool?: string;
}

export interface ExtractInput {
  records: readonly RecordEntry[];
  /** Pinned runtime per role — a mismatched runtime is refused, not relabelled. */
  roleRuntime: Record<ContractRole, string>;
  /** Declared run window; rows outside it are flagged (still emitted). */
  window?: { fromMs?: number; toMs?: number };
}

export interface ExtractResult {
  spans: TelemetrySpan[];
  refused: ExtractRefusal[];
}

const NONCE_RE = /^0x[0-9a-f]{32}$/;

type OtlpAttr = { key?: unknown; value?: { stringValue?: unknown; intValue?: unknown; boolValue?: unknown } };

function attrMap(attrs: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (!Array.isArray(attrs)) return out;
  for (const a of attrs as OtlpAttr[]) {
    if (typeof a?.key !== "string") continue;
    const v = a.value;
    if (typeof v?.stringValue === "string") out.set(a.key, v.stringValue);
    else if (typeof v?.intValue === "number" || typeof v?.intValue === "string") out.set(a.key, String(v.intValue));
    else if (typeof v?.boolValue === "boolean") out.set(a.key, String(v.boolValue));
  }
  return out;
}

/** `mcp__contract__tool` / `contract__tool` / `mcp_tool_call` → bare tool name. */
function bareToolName(name: string): string {
  const mcp = /^mcp__[^_]+__(.+)$/.exec(name);
  if (mcp !== null) return mcp[1];
  const scoped = /^[^_]+__(.+)$/.exec(name);
  if (scoped !== null) return scoped[1];
  return name;
}

const nsToMs = (v: unknown): number =>
  typeof v === "string" || typeof v === "number" ? Math.floor(Number(v) / 1e6) : 0;

/**
 * Structural nonce scan: walks parsed JSON, collecting every `serverNonce`
 * string. Strings that themselves parse as JSON are recursed into — this is
 * how MCP `content[].text` double-encoding is unwound. Returns all candidate
 * values; the caller requires EXACTLY ONE.
 */
function collectNonces(value: unknown, depth: number, out: string[]): void {
  if (depth > 8 || out.length > 8) return;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        collectNonces(JSON.parse(trimmed), depth + 1, out);
      } catch { /* not embedded JSON */ }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectNonces(item, depth + 1, out);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === "serverNonce" && typeof v === "string" && NONCE_RE.test(v)) {
        out.push(v);
      } else {
        collectNonces(v, depth + 1, out);
      }
    }
  }
}

/**
 * Parse the tool-result output and return its serverNonce iff exactly one
 * well-formed nonce exists in the entire structure. An `isError: true`
 * result yields NO nonce — it is flagged `error_result` instead.
 */
interface NonceResult {
  nonce?: string;
  ambiguous: boolean;
  errorResult: boolean;
  /** Output looked wrapped but matched no known wrapper — flagged, never guessed. */
  unrecognized?: boolean;
}

function nonceOf(output: string | undefined): NonceResult {
  if (output === undefined) return { ambiguous: false, errorResult: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    return { ambiguous: false, errorResult: false }; // non-JSON output carries no structured nonce
  }
  if (
    parsed !== null &&
    typeof parsed === "object" &&
    (parsed as Record<string, unknown>).isError === true
  ) {
    return { ambiguous: false, errorResult: true };
  }
  const found: string[] = [];
  collectNonces(parsed, 0, found);
  if (found.length === 1) return { nonce: found[0], ambiguous: false, errorResult: false };
  return { ambiguous: found.length > 1, errorResult: false };
}

function argsDigestOf(argsJson: string | undefined): string | undefined {
  if (argsJson === undefined) return undefined;
  try {
    const parsed = JSON.parse(argsJson) as Record<string, unknown>;
    const inner = parsed !== null && typeof parsed === "object" && "arguments" in parsed
      ? parsed.arguments
      : parsed;
    return canonicalDigest(inner);
  } catch {
    return undefined;
  }
}

function* eachSpan(doc: Record<string, unknown>) {
  const resourceSpans = Array.isArray(doc.resourceSpans) ? doc.resourceSpans : [];
  for (const rs of resourceSpans as Record<string, unknown>[]) {
    const scopeSpans = Array.isArray(rs?.scopeSpans) ? rs.scopeSpans : [];
    for (const ss of scopeSpans as Record<string, unknown>[]) {
      const spans = Array.isArray(ss?.spans) ? ss.spans : [];
      for (const span of spans) yield span as Record<string, unknown>;
    }
  }
}

function* eachLogRecord(doc: Record<string, unknown>) {
  const resourceLogs = Array.isArray(doc.resourceLogs) ? doc.resourceLogs : [];
  for (const rl of resourceLogs as Record<string, unknown>[]) {
    const scopeLogs = Array.isArray(rl?.scopeLogs) ? rl.scopeLogs : [];
    for (const sl of scopeLogs as Record<string, unknown>[]) {
      const logRecords = Array.isArray(sl?.logRecords) ? sl.logRecords : [];
      for (const rec of logRecords) yield rec as Record<string, unknown>;
    }
  }
}

type RawRow = {
  runtime: string;
  ts: number;
  tool: string;
  nonce: NonceResult;
  argsDigest?: string;
};

function claudeSpanToRow(span: Record<string, unknown>): RawRow | null {
  // Two wire shapes (N4C-CHANGES-6): the fixture-era `claude_code.mcp.rpc`
  // span (tool name in `tool.name`) and Claude Code ≥2.1.284's
  // `claude_code.tool` span (tool name in `tool_name`). Both carry the tool
  // result in a `tool.output` span event's `output`/`content` attribute.
  const isToolSpan = span.name === "claude_code.tool";
  if (span.name !== "claude_code.mcp.rpc" && !isToolSpan) return null;
  const attrs = attrMap(span.attributes);
  // Dedicated tool-name attribute only.
  const tool = (isToolSpan ? attrs.get("tool_name") : attrs.get("tool.name")) ?? "";
  let output: string | undefined;
  const events = Array.isArray(span.events) ? span.events : [];
  for (const ev of events as Record<string, unknown>[]) {
    if (ev?.name !== "tool.output") continue;
    const evAttrs = attrMap(ev.attributes);
    output = evAttrs.get("output") ?? evAttrs.get("content") ?? output;
  }
  return {
    runtime: "claude-code",
    ts: nsToMs(span.startTimeUnixNano),
    tool: bareToolName(tool),
    nonce: nonceOf(output),
    ...(argsDigestOf(attrs.get("args")) !== undefined ? { argsDigest: argsDigestOf(attrs.get("args")) } : {}),
  };
}

/**
 * Codex's `tool_result` output is exec-wrapped (observed live on 0.154.0):
 *   MCP tool call:  "Wall time: <s> seconds\nOutput:\n<json>"
 *   script exec:    "Script completed\nWall time <s> seconds\nOutput:\n\n<jsonl>"
 * The preamble is deterministic — strip ONLY that exact prefix, then apply
 * the one-structural-nonce rule to the remainder. A remainder that is not one
 * JSON document but several (one CallToolResult per JSONL line) is
 * `nonce_ambiguous` — it cannot be bound to a single call. Output that looks
 * wrapped but matches neither preamble is `codex_output_unrecognized`. Never
 * a substring search for nonces.
 */
const CODEX_OUTPUT_PREAMBLE_RE = /^(?:Script completed\n)?Wall time:? \d+(?:\.\d+)? seconds\nOutput:\n+/;

function codexNonceOf(output: string | undefined): NonceResult {
  if (output === undefined) return { ambiguous: false, errorResult: false };
  try {
    JSON.parse(output);
    return nonceOf(output); // clean JSON — no wrapper
  } catch { /* wrapped or non-JSON */ }
  const m = CODEX_OUTPUT_PREAMBLE_RE.exec(output);
  if (m === null) return { ambiguous: false, errorResult: false, unrecognized: true };
  const rest = output.slice(m[0].length);
  try {
    JSON.parse(rest);
    return nonceOf(rest);
  } catch { /* not a single document */ }
  let bodies = 0;
  for (const line of rest.split("\n")) {
    if (line.trim() === "") continue;
    try {
      JSON.parse(line);
      bodies++;
    } catch { /* not a JSON line */ }
  }
  if (bodies >= 2) return { ambiguous: true, errorResult: false };
  return { ambiguous: false, errorResult: false, unrecognized: true };
}

function codexLogToRow(rec: Record<string, unknown>): RawRow | null {
  const attrs = attrMap(rec.attributes);
  const body = (rec.body as { stringValue?: unknown } | undefined)?.stringValue;
  if (attrs.get("event.name") !== "codex.tool_result" && body !== "codex.tool_result") return null;
  // Dedicated tool-name attribute only — arguments.name/tool never wins.
  const tool = attrs.get("tool_name") ?? "";
  const argsJson = attrs.get("arguments");
  return {
    runtime: "codex",
    ts: nsToMs(rec.timeUnixNano ?? rec.observedTimeUnixNano),
    tool: bareToolName(tool),
    nonce: codexNonceOf(attrs.get("output")),
    ...(argsDigestOf(argsJson) !== undefined ? { argsDigest: argsDigestOf(argsJson) } : {}),
  };
}

function geminiLogToRow(rec: Record<string, unknown>): RawRow | null {
  const attrs = attrMap(rec.attributes);
  if (attrs.get("event.name") !== "gemini_cli.tool_call") return null;
  return {
    runtime: "gemini-cli",
    ts: nsToMs(rec.timeUnixNano ?? rec.observedTimeUnixNano),
    tool: bareToolName(attrs.get("function_name") ?? ""),
    nonce: nonceOf(attrs.get("function_response") ?? attrs.get("output")),
    ...(argsDigestOf(attrs.get("function_args")) !== undefined
      ? { argsDigest: argsDigestOf(attrs.get("function_args")) }
      : {}),
  };
}

/**
 * Hermes ac_telemetry plugin records (N4d @ 6707767; N4C-CHANGES-5). One
 * `hermes.tool_call` logRecord per `post_tool_call`. The tool name comes ONLY
 * from the dedicated `tool_name` attribute; `args_digest` (emitter-computed)
 * is never trusted — the digest is recomputed from `function_args`. An
 * `error_type` attribute means the call failed: no nonce, `error_result`.
 */
function hermesLogToRow(rec: Record<string, unknown>): RawRow | null {
  const attrs = attrMap(rec.attributes);
  if (attrs.get("event.name") !== "hermes.tool_call") return null;
  const errored = attrs.get("error_type") !== undefined;
  return {
    runtime: "hermes",
    ts: nsToMs(rec.timeUnixNano ?? rec.observedTimeUnixNano),
    tool: bareToolName(attrs.get("tool_name") ?? ""),
    nonce: errored
      ? { ambiguous: false, errorResult: true }
      : nonceOf(attrs.get("output")),
    ...(argsDigestOf(attrs.get("function_args")) !== undefined
      ? { argsDigest: argsDigestOf(attrs.get("function_args")) }
      : {}),
  };
}

function rowFlags(row: RawRow, receivedAtMs: number, window?: ExtractInput["window"]): string[] | undefined {
  const flags: string[] = [];
  if (row.nonce.errorResult) flags.push("error_result");
  if (row.nonce.ambiguous) flags.push("nonce_ambiguous");
  if (row.nonce.unrecognized) flags.push("codex_output_unrecognized");
  if (window !== undefined) {
    if (window.fromMs !== undefined && receivedAtMs < window.fromMs) flags.push("outside_window");
    if (window.toMs !== undefined && receivedAtMs > window.toMs) flags.push("outside_window");
  }
  return flags.length === 0 ? undefined : [...new Set(flags)];
}

/** Internal — reachable only through verifyAndExtract (no chain, no rows). */
function extractTelemetrySpans(input: ExtractInput): ExtractResult {
  const spans: TelemetrySpan[] = [];
  const refused: ExtractRefusal[] = [];

  for (const { record, body } of input.records) {
    const sinkRef = record.recordDigest;
    // Integrity first: the stored bytes must hash to the recorded digest.
    const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
    if (bodyDigest(bytes) !== record.bodyDigest) {
      refused.push({ sinkRef, code: "BODY_DIGEST" });
      continue;
    }
    if (record.role === null) {
      refused.push({ sinkRef, code: "ROLE_MISSING" });
      continue;
    }
    const role = record.role;
    const receivedAtMs = Date.parse(record.receivedAt);

    let doc: Record<string, unknown>;
    try {
      const parsed = JSON.parse(typeof body === "string" ? body : Buffer.from(body).toString("utf8"));
      if (parsed === null || typeof parsed !== "object") continue;
      doc = parsed as Record<string, unknown>;
    } catch {
      continue;
    }

    const rows: RawRow[] = [];
    for (const span of eachSpan(doc)) {
      const row = claudeSpanToRow(span);
      if (row !== null && row.tool !== "") rows.push(row);
    }
    for (const rec of eachLogRecord(doc)) {
      for (const row of [codexLogToRow(rec), geminiLogToRow(rec), hermesLogToRow(rec)]) {
        if (row !== null && row.tool !== "") rows.push(row);
      }
    }

    for (const row of rows) {
      if (row.runtime !== input.roleRuntime[role]) {
        refused.push({ sinkRef, code: "RUNTIME_MISMATCH", tool: row.tool });
        continue;
      }
      const flags = rowFlags(row, receivedAtMs, input.window);
      spans.push({
        role,
        runtime: row.runtime,
        ts: row.ts,
        receivedAt: record.receivedAt,
        receivedAtMs,
        tool: row.tool,
        ...(row.nonce.nonce !== undefined ? { serverNonce: row.nonce.nonce } : {}),
        ...(row.argsDigest !== undefined ? { argsDigest: row.argsDigest } : {}),
        sinkRef,
        ...(flags !== undefined ? { flags } : {}),
      });
    }
  }
  return { spans, refused };
}

export type VerifyAndExtractResult =
  | { ok: true; spans: TelemetrySpan[]; refused: ExtractRefusal[]; refusedAfterClose: number }
  | { ok: false; code: VerifyFailureCode | "NOT_FINAL" };

/**
 * Verify the signed refusal annex binds to THIS head and carries a sink
 * signature — the annex is the verifier's refusal ledger (monotonic; always
 * fetched fresh, never from an attacker-held earlier copy).
 */
function checkAnnex(
  annex: RefusalAnnex | null | undefined,
  head: SignedHead,
  sinkPublicKeys: Record<string, KeyObject>,
): VerifyFailureCode | null {
  if (annex === null || annex === undefined || annex.schema !== ANNEX_SCHEMA) {
    return "ANNEX_MISSING";
  }
  if (annex.runId !== head.runId) return "ANNEX_MISMATCH";
  if (!Number.isSafeInteger(annex.refusedAfterClose) || annex.refusedAfterClose < 0) {
    return "ANNEX_MISMATCH";
  }
  // The annex must be bound to the whole signed head it accompanies.
  if (annex.finalHeadDigest !== canonicalDigest(head)) return "ANNEX_MISMATCH";
  const { signature, ...annexFields } = annex;
  if (signature.alg !== "ed25519") return "ANNEX_SIGNATURE";
  const sigBytes = Buffer.from(signature.sig.slice(2), "hex");
  if (sigBytes.length !== 64) return "ANNEX_SIGNATURE";
  const publicKey = sinkPublicKeys[signature.keyId];
  if (publicKey === undefined) return "ANNEX_KEY_UNKNOWN";
  const message = { ...annexFields, alg: signature.alg, keyId: signature.keyId };
  if (!verify(null, Buffer.from(canonicalJson(message), "utf8"), publicKey, sigBytes)) {
    return "ANNEX_SIGNATURE";
  }
  return null;
}

/**
 * The only extraction entry point (N4C-CHANGES-2/3): verify the complete
 * chain against a FINAL head under pinned sink keys AND check the latest
 * signed refusal annex binds to that head — only then extract rows. A forged
 * record, a missing/non-final head, a missing/mismatched/unsigned annex, or a
 * bad signature returns `{ok: false}` — no rows ever leave an unverified
 * chain. On success the annex's `refusedAfterClose` is surfaced; the verifier
 * requires it to be 0 for ACCEPT.
 */
export function verifyAndExtract(
  records: readonly (RecordEntry | (SinkRecord & { body?: string | Uint8Array }))[],
  finalHead: SignedHead | null | undefined,
  annex: RefusalAnnex | null | undefined,
  sinkPublicKeys: Record<string, KeyObject>,
  opts: { roleRuntime: Record<ContractRole, string>; window?: ExtractInput["window"] },
): VerifyAndExtractResult {
  const verified = verifyRecords(records, finalHead, sinkPublicKeys);
  if (verified.ok === "incomplete") return { ok: false, code: "NOT_FINAL" };
  if (verified.ok === false) return { ok: false, code: verified.code };
  const annexCode = checkAnnex(annex, verified.head, sinkPublicKeys);
  if (annexCode !== null) return { ok: false, code: annexCode };
  const entries = records
    .map((r) => ("record" in r ? r : r.body === undefined ? null : { record: r, body: r.body }))
    .filter((e): e is RecordEntry => e !== null);
  const { spans, refused } = extractTelemetrySpans({ records: entries, ...opts });
  return { ok: true, spans, refused, refusedAfterClose: annex?.refusedAfterClose ?? 0 };
}

export type { SinkRecord, RecordEntry };
