// Hosted Shadow recorder: the step, checkpoint, packet and pin construction of the library's recorder
// (clockchain-shadow/ts/src/recorder.ts, source sha256 6d7a94bf37b67156e44ec2dd605b5a918790022fba539bda18992046bd8d1210),
// over the hosted store instead of SQLite. recorder.ts itself cannot be vendored (it imports node:sqlite), so the
// pure helpers below (normalize, the hidden-reasoning checks, asRecorded) are copied from it verbatim, and the
// append, checkpoint, close, packet and pin rules follow its Session class line for line. scripts/sync-shadow-lib.mjs
// warns when the library's recorder.ts no longer has the hash above, so this file is reviewed on every re-sync.
//
// The vendored verifier (lib/verify.ts) is the arbiter: test/shadow-hosted.test.mjs verifies hosted packets with it.
import { randomUUID } from "node:crypto";
import { canonical, clip, DOMAIN, hash, merkle, PROFILE, type Clipped, type Json } from "./lib/profile.js";
import { coverage, isCollectorKind, isTranscriptKind } from "./lib/kinds.js";
import { fingerprint, type KeyProvider } from "./lib/keys.js";
import type { Checkpoint, CheckpointBody, EventBody, Network, Packet, PendingCheckpoint, Pin, ShadowEvent, Source } from "./lib/types.js";
import type { SessionMeta } from "./store.js";

export const LIBRARY = "@clockchain/mcp-server/shadow";
export const VERSION = "1.0.0";
export const START_LABEL = "shadow session opened";
export const ANCHOR_LABEL = "shadow checkpoint";

/** The library's DEFAULT_LIMITS, plus what is different when the server holds the record and the key. */
export const HOSTED_LIMITS = [
  "Steps are recorded as reported by the runtime adapter; activity outside the captured boundary is not covered.",
  "Hidden model reasoning is never captured.",
  "collectedAt is the operator clock; only Clockchain receipts bound time.",
  "Runs the adapter never reported cannot be detected from the record alone.",
  "Hosted: the agent reported each step to the Clockchain MCP server, which keeps the record and holds the signing key on the agent's behalf.",
];

/** Every hosted text field keeps the whole content: shadow_record accepts at most 32 KB, which is at most 32,768 UTF-16 units. */
export const HOSTED_MAX_TEXT = 32_768;

export class RecordError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "RecordError";
    this.code = code;
  }
}

// ---- copied verbatim from the library's recorder.ts -------------------------------------------------------------

// Adapters report costs and timings as floats; the profile only carries safe integers, so other numbers become
// decimal strings. undefined is dropped, Dates become ISO strings. A `__proto__` key is kept as an ordinary key, as
// Python keeps it. Values that are not plain data (functions, symbols, class instances, maps) are refused rather than
// guessed at (v1.1 correction C18).
export function normalize(v: unknown, depth = 0): Json {
  if (depth > 40) throw new Error("Value nested too deeply");
  if (v === null || typeof v === "string" || typeof v === "boolean") return v;
  if (typeof v === "number") return Number.isSafeInteger(v) && !Object.is(v, -0) ? v : String(v);
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map((x) => (x === undefined ? null : normalize(x, depth + 1)));
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new TypeError(`Cannot record a value of type ${proto?.constructor?.name ?? "object"}; pass plain data`);
    const out: Record<string, Json> = {};
    for (const [k, x] of Object.entries(v as object))
      if (x !== undefined) Object.defineProperty(out, k, { value: normalize(x, depth + 1), enumerable: true, writable: true, configurable: true });
    return out;
  }
  if (v === undefined) return null;
  throw new TypeError(`Cannot record a value of type ${typeof v}`);
}

// Hidden reasoning (spec §3.4, v1.1 correction C18) is any of:
//   - text under a key starting with reasoning, thinking or thought (reasoning_content, reasoning, thinking, thoughtSignature);
//   - a content block whose type names thinking or reasoning (thinking, redacted_thinking, thinking_delta, reasoning,
//     reasoning_text, response.reasoning_summary_text.delta) or is signature_delta, whether alone or in a list;
//   - a Gemini part marked {thought: true};
//   - in agent message and tool result text, an inline <think>, <thinking> or <reasoning> section.
// Counts such as reasoningTokens are numbers and are allowed.
const REASONING_KEY = /^(reasoning|thinking|thought)/i;
const HIDDEN_TYPE = /(?:^|[._-])(?:thinking|reasoning)|^signature_delta$/i;
const THINK_TAG = /<\/?(think|thinking|reasoning)\b[^>]*>/i;
const isText = (x: unknown) => typeof x === "string" || (typeof x === "object" && x !== null);
const isHiddenBlock = (x: unknown) =>
  typeof x === "object" && x !== null && !Array.isArray(x) && ((typeof (x as any).type === "string" && HIDDEN_TYPE.test((x as any).type)) || (x as any).thought === true);

function rejectReasoning(v: unknown, path = "payload", tags = false) {
  if (typeof v === "string") {
    if (tags && THINK_TAG.test(v)) throw new Error(`Reasoning is never recorded (${path} has a <think> section)`);
    return;
  }
  if (!v || typeof v !== "object") return;
  if (isHiddenBlock(v)) throw new Error(`Reasoning is never recorded (${path})`);
  for (const [k, x] of Object.entries(v)) {
    if (REASONING_KEY.test(k) && isText(x)) throw new Error(`Reasoning is never recorded (${path}.${k})`);
    rejectReasoning(x, `${path}.${k}`, tags);
  }
}

// What JSON.stringify will actually write for a value, so the reasoning checks see exactly what is recorded (a toJSON
// method cannot hide anything from them).
const asRecorded = (v: unknown): unknown => (v == null || typeof v === "string" ? v : JSON.parse(JSON.stringify(v) ?? "null"));

// ---- end of the verbatim copy ------------------------------------------------------------------------------------

function refuseReasoning(fn: () => void): void {
  try {
    fn();
  } catch (e) {
    const where = (/\((.*)\)$/.exec((e as Error).message)?.[1] ?? "content").replace(/ has a <think> section$/, "");
    throw new RecordError(
      "SHADOW_REASONING_REFUSED",
      `Nothing was recorded: ${where} looks like hidden model reasoning, which Shadow never records. Shadow refuses a ` +
        "<think>, <thinking> or <reasoning> tag, a thinking or reasoning block, and any field whose name starts with " +
        "reasoning, thinking or thought, in every kind of step. Record what you showed or did; if this is ordinary " +
        "visible content, remove the tag or rename the field.",
    );
  }
}

/** Run.text(): the content exactly as it will be serialised, checked for hidden reasoning, then clipped. */
function text(v: unknown, tags = false): Clipped {
  const recorded = asRecorded(v);
  refuseReasoning(() => rejectReasoning(recorded, "content", tags));
  return clip(recorded, HOSTED_MAX_TEXT);
}

export const referenceId = (sessionId: string) => "shadow:v1:" + sessionId;
export const startHashOf = (operatorId: string, sessionId: string, nonce: string) =>
  hash(DOMAIN.sessionStart, { operatorId, sessionId, nonce });

export type WriteReceipt = { ledgerId: string; blockHeight: string | null; blockTime: string | null; submittedAt: string | null };

export function receiptPayload(sessionId: string, r: WriteReceipt): Record<string, Json> {
  return {
    referenceId: referenceId(sessionId), ledgerId: r.ledgerId, blockHeight: r.blockHeight,
    blockTime: r.blockTime, submittedAt: r.submittedAt, status: r.blockHeight ? "anchored" : "pending",
  };
}

/**
 * Session.append(): one step, with the library's boundary, inventory, hidden-reasoning and order rules. The caller
 * persists the event and then advances the session's head (meta.seq / meta.head / meta.runs / meta.state).
 */
export function buildEvent(meta: SessionMeta, kind: string, actor: string, payload: Record<string, unknown>, source: Partial<Source>, now: Date): ShadowEvent {
  const boundary = source.boundary ?? "collector";
  if (boundary === "collector" ? !isCollectorKind(kind) : !isTranscriptKind(kind)) throw new Error(`Kind ${kind} is not allowed at the ${boundary} boundary`);
  const agents = meta.agents.map((a) => a.id);
  if (actor !== "collector" && !agents.includes(actor)) throw new Error(`Agent ${actor} is not in this session's inventory`);
  if (boundary === "transcript" && actor === "collector") throw new Error("Transcript steps belong to an agent");
  refuseReasoning(() => rejectReasoning(payload));
  const p = normalize(payload) as Record<string, Json>;
  const run = source.agentRunId ?? null;
  if (meta.state === "closed" && !kind.startsWith("clockchain.")) throw new Error("Session is closed");
  if (meta.seq === 0 && kind !== "session.opened") throw new Error("The first step of a session is session.opened");
  if (meta.seq > 0 && kind === "session.opened") throw new Error("A session is opened once");
  if (kind === "task.assigned") {
    if (!run) throw new Error("A run needs an id");
    if (meta.runs.some((r) => r.id === run)) throw new Error(`Run ${run} already exists`);
  } else if (run) {
    const st = meta.runs.find((r) => r.id === run);
    if (!st) throw new Error(`Run ${run} was never assigned`);
    if (!st.open) throw new Error("Run has ended");
  } else if (kind === "execution.receipt") throw new Error("A receipt belongs to a run");
  const body: EventBody = {
    profile: PROFILE, operatorId: meta.operatorId, sessionId: meta.sessionId, streamId: "collector",
    seq: meta.seq + 1, previousHash: meta.head, eventId: randomUUID(),
    kind, actor, collectedAt: now.toISOString(),
    source: { boundary, agentRunId: source.agentRunId ?? null, taskId: source.taskId ?? null, transcriptId: source.transcriptId ?? null },
    payload: p,
  };
  try {
    canonical(body);
  } catch {
    throw new RecordError("SHADOW_BAD_CONTENT", "Content must be valid Unicode text or JSON (no lone surrogates).");
  }
  return { body, hash: hash(DOMAIN.event, body) };
}

/** Advances the session head after `event` was durably appended (the store side of Session.append). */
export function advance(meta: SessionMeta, event: ShadowEvent, bytes: number): void {
  const b = event.body;
  meta.seq = b.seq;
  meta.head = event.hash;
  meta.eventsBytes += bytes;
  if (b.kind === "task.assigned" && b.source.agentRunId) meta.runs.push({ id: b.source.agentRunId, agent: b.actor, open: true });
  if (b.kind === "execution.receipt") {
    const r = meta.runs.find((x) => x.id === b.source.agentRunId);
    if (r) r.open = false;
  }
  if (b.kind === "session.closed") meta.state = "closed";
}

/** Session.checkpoint(): the previous checkpoint when nothing changed, else a new one signed over every step. */
export function checkpointOver(meta: SessionMeta, events: ShadowEvent[], keys: KeyProvider, now: Date): Checkpoint {
  const prev = meta.checkpoint;
  if (prev && prev.body.count === events.length) return prev;
  const agents = meta.agents.map((a) => a.id);
  const body: CheckpointBody = {
    profile: PROFILE, operatorId: meta.operatorId, sessionId: meta.sessionId, streamId: "collector",
    count: events.length, head: events.at(-1)?.hash ?? null, merkleRoot: merkle(events.map((e) => e.hash)).root,
    previousCheckpointHash: prev?.hash ?? null, createdAt: now.toISOString(), network: meta.network,
    inventory: { profile: "shadow-inventory-v1", agents },
    coverage: coverage(events, agents), knownLimits: HOSTED_LIMITS,
  };
  const h = hash(DOMAIN.checkpoint, body);
  return { body, hash: h, publicKey: keys.publicKey(), signature: keys.sign(h) };
}

/** Session.pendingCheckpoints(): checkpoints queued for Clockchain whose receipt is not among the steps. */
export function pendingCheckpoints(meta: SessionMeta, cp: Checkpoint, events: ShadowEvent[]): PendingCheckpoint[] {
  const receipted = new Set(events.filter((e) => e.body.kind === "clockchain.anchored").map((e) => (e.body.payload as any).checkpointHash));
  const out = new Map<string, PendingCheckpoint>();
  for (const r of meta.outbox)
    if (r.kind === "checkpoint" && r.body && r.hash !== cp.hash && !receipted.has(r.hash)) out.set(r.hash, { hash: r.hash, body: r.body });
  return [...out.values()];
}

/** Session.packet(), for a checkpoint that already covers `events`. Hosted agents have no minted identities. */
export function buildPacket(meta: SessionMeta, cp: Checkpoint, events: ShadowEvent[], network: Network, now: Date): Packet {
  return {
    format: "shadow-evidence-v2", profile: PROFILE, events, checkpoint: cp, proofs: merkle(events.map((e) => e.hash)).proofs,
    identities: [],
    pendingCheckpoints: pendingCheckpoints(meta, cp, events),
    manifest: { library: LIBRARY, version: VERSION, network, createdAt: now.toISOString() },
  };
}

export function buildPin(meta: SessionMeta, cp: Checkpoint): Pin {
  return {
    format: "shadow-trust-pin-v2", checkpointHash: cp.hash, publicKeyFingerprint: fingerprint(cp.publicKey),
    operatorId: meta.operatorId, sessionId: meta.sessionId,
  };
}

// ---- the hosted record kinds --------------------------------------------------------------------------------------

export const RECORD_KINDS = ["task", "prompt", "message", "tool_call", "tool_result", "file", "note"] as const;
export type RecordKind = (typeof RECORD_KINDS)[number];

export type StepSpec = {
  kind: string;
  boundary: "collector" | "transcript";
  payload: Record<string, unknown>;
};

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const label = (v: unknown, max: number): string | null => {
  if (typeof v !== "string" && typeof v !== "number") return null;
  const s = String(v).trim();
  return s ? s.slice(0, max).toWellFormed() : null;
};
const firstOf = (o: Record<string, unknown>, keys: string[]) => {
  for (const k of keys) if (o[k] !== undefined) return o[k];
  return undefined;
};
const without = (o: Record<string, unknown>, keys: string[]) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));

/**
 * Maps a hosted record onto the library's step kinds and payloads (Session.startRun and the Run methods):
 *   task -> task.assigned (starts a run), prompt -> agent.prompt, message -> agent.message, tool_call ->
 *   agent.tool.call, tool_result -> agent.tool.result, file -> artifact.created, note -> agent.message {note: true}.
 */
export function stepFor(kind: RecordKind, content: unknown): StepSpec {
  // Hosted policy, stricter than the library's (which lets tool arguments and file contents through): every field of
  // every kind is checked, inline <think> sections included, before anything is mapped (security review finding 6).
  refuseReasoning(() => rejectReasoning(asRecorded(content), "content", true));
  switch (kind) {
    case "task": {
      const recorded = asRecorded(content);
      refuseReasoning(() => rejectReasoning(recorded, "content"));
      const full = typeof recorded === "string" ? recorded : JSON.stringify(recorded) ?? "";
      const title = clip(full, 500);
      return { kind: "task.assigned", boundary: "collector", payload: { title, instructions: title.truncated ? clip(full, HOSTED_MAX_TEXT) : null } };
    }
    case "prompt":
      return { kind: "agent.prompt", boundary: "transcript", payload: { content: text(content) } };
    case "message":
      return { kind: "agent.message", boundary: "transcript", payload: { content: text(content, true), finishReason: null } };
    case "note":
      return { kind: "agent.message", boundary: "transcript", payload: { content: text(content, true), finishReason: null, note: true } };
    case "tool_call": {
      if (!isObj(content)) return { kind: "agent.tool.call", boundary: "transcript", payload: { callId: null, tool: "unnamed", args: clip(content, HOSTED_MAX_TEXT) } };
      const tool = label(firstOf(content, ["tool", "name"]), 200) ?? "unnamed";
      const callId = label(firstOf(content, ["call_id", "callId"]), 200);
      const named = firstOf(content, ["args", "arguments", "input"]);
      const rest = without(content, ["tool", "name", "call_id", "callId"]);
      const args = named !== undefined ? named : Object.keys(rest).length ? rest : undefined;
      return { kind: "agent.tool.call", boundary: "transcript", payload: { callId, tool, args: clip(args, HOSTED_MAX_TEXT) } };
    }
    case "tool_result": {
      if (!isObj(content)) return { kind: "agent.tool.result", boundary: "transcript", payload: { callId: null, tool: null, content: text(content, true), isError: false } };
      const tool = label(firstOf(content, ["tool", "name"]), 200);
      const callId = label(firstOf(content, ["call_id", "callId"]), 200);
      const isError = firstOf(content, ["is_error", "isError"]) === true;
      const named = firstOf(content, ["result", "content", "output"]);
      const rest = without(content, ["tool", "name", "call_id", "callId", "is_error", "isError"]);
      const result = named !== undefined ? named : Object.keys(rest).length ? rest : undefined;
      return { kind: "agent.tool.result", boundary: "transcript", payload: { callId, tool, content: text(result, true), isError } };
    }
    case "file": {
      if (!isObj(content)) throw new RecordError("SHADOW_BAD_CONTENT", 'For kind "file", pass content as {path, content}.');
      const path = label(firstOf(content, ["path", "name", "filename"]), 1000);
      if (!path) throw new RecordError("SHADOW_BAD_CONTENT", 'For kind "file", content needs a "path".');
      const body = firstOf(content, ["content", "text", "data"]);
      const t = typeof body === "string" ? body : body === undefined ? "" : JSON.stringify(body) ?? "";
      return { kind: "artifact.created", boundary: "collector", payload: { path, bytes: Buffer.byteLength(t), content: clip(t, HOSTED_MAX_TEXT) } };
    }
  }
}
