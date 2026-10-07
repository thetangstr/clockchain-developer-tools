/**
 * O-1 (sealed-log lanes), contract side. Three signed objects the telemetry
 * sink's close listener accepts (packages/telemetry-sink src/lanes.ts and
 * sink.ts checkReceiptV2 are the verifying halves):
 *
 *   ac-lane-open/v1      {schema, aud, keyId, role, mcpSessionId, ts, signature}
 *     signed message = canonicalJson({schema, aud, keyId, role, mcpSessionId, ts,
 *     signature: {alg, keyId: <contract signer keyId>}}). The body's `keyId`
 *     is the PRINCIPAL, so the signer keyId rides nested (no collision).
 *   ac-run-link/v1       {schema, aud, runId, lanes: {buyer, provider}, ts, signature}
 *     signed message = canonicalJson({schema, aud, runId, lanes, ts, alg, keyId}).
 *   ac-lane-release/v1   {schema, aud, laneId, keyId, role, mcpSessionId, ts, signature}
 *     lane-open style. CDT-SEC L5: sent when an MCP session drops above cap 1
 *     before any run captured it, so a reconnecting client never exhausts
 *     its own LANE_LIMIT with lanes no run can link.
 *   `aud` (CDT-SEC L5) is the sink's signing keyId (TELEMETRY_SINK_KEY_ID),
 *   so a body signed for one sink is refused by any other.
 *   ac-terminal-receipt/v2 {schema, runId, terminalState, ts, lanes, linkDigest, signature}
 *     signed message = canonicalJson({...fields, alg, keyId}); linkDigest =
 *     canonicalDigest({schema: "ac-run-link/v1", runId, lanes}).
 *
 * Authority split (unchanged by this module): the SINK alone mints ingest
 * tokens and seals each one to the key the sink admin enrolled for the
 * keyId. This service only signs the request and relays the CIPHERTEXT —
 * it never holds a party private key or a usable ingest token, and it never
 * sends a public key (it has none to send).
 *
 * Lane bookkeeping is per (keyId, mcpSessionId): one lane per MCP session,
 * cached so an adapter retry in the same session gets the same box (the
 * sink refuses a second open for a session — LANE_REUSED). At bind (both
 * seats taken) every unlinked lane each bound principal opened inside the
 * lane window is linked to the run, write-once, and POSTed with retries.
 * Above CONTRACT_MAX_RUNS_PER_KEY=1 (O-3) only lanes of the MCP sessions
 * routed to THAT run are linked, so concurrent runs of one keyId never
 * capture each other's lanes.
 * A linked run's terminal receipt is v2; an unlinked run keeps v1, so a
 * deployment that never calls telemetry_open behaves exactly as before.
 */
import { sign as edSign } from "node:crypto";
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync,
} from "node:fs";
import path from "node:path";

import { canonicalDigest, canonicalJson } from "./canonical.js";
import { mintTerminalReceipt, refusalErrorOf, type TerminalReceipt, type TerminalReceiptFields } from "./close-emitter.js";
import type { ContractSigner } from "./envelope.js";
import type { ContractRole } from "./schemas.js";

export const TELEMETRY_OPEN_TOOL = "telemetry_open";
export const LANE_OPEN_SCHEMA = "ac-lane-open/v1" as const;
export const RUN_LINK_SCHEMA = "ac-run-link/v1" as const;
export const LANE_RELEASE_SCHEMA = "ac-lane-release/v1" as const;
export const TERMINAL_RECEIPT_V2_SCHEMA = "ac-terminal-receipt/v2" as const;
const LANES_STATE_SCHEMA = "ac-contract.telemetry-lanes/v1";
const LANES_STATE_FILE = "telemetry-lanes.json";
const LANE_ID_RE = /^lane:[0-9a-f]{32}$/;
/** The sink's per-role cap on a link (lanes.ts). */
const MAX_LANES_PER_ROLE = 8;

export interface LinkedLanes {
  buyer: string[];
  provider: string[];
}

type Ed25519Signature = { alg: "ed25519"; keyId: string; sig: `0x${string}` };

export interface LaneOpenRequest {
  schema: typeof LANE_OPEN_SCHEMA;
  aud: string;
  keyId: string;
  role: ContractRole;
  mcpSessionId: string;
  ts: string;
  signature: Ed25519Signature;
}

export interface RunLinkRequest {
  schema: typeof RUN_LINK_SCHEMA;
  aud: string;
  runId: string;
  lanes: LinkedLanes;
  ts: string;
  signature: Ed25519Signature;
}

export interface TerminalReceiptV2 {
  schema: typeof TERMINAL_RECEIPT_V2_SCHEMA;
  runId: string;
  terminalState: string;
  ts: string;
  lanes: LinkedLanes;
  linkDigest: string;
  signature: Ed25519Signature;
}

/**
 * CDT-SEC L9: what a refused link delivery persists — the HTTP status and
 * the sink's refusal code, never the body (shared with the close emitter).
 */
export const linkErrorOf = refusalErrorOf;

const signHex = (message: string, signer: ContractSigner): `0x${string}` =>
  `0x${edSign(null, Buffer.from(message, "utf8"), signer.privateKey).toString("hex")}`;

export function linkDigestOf(runId: string, lanes: LinkedLanes): string {
  return canonicalDigest({ schema: RUN_LINK_SCHEMA, runId, lanes });
}

export function mintLaneOpen(
  fields: { aud: string; keyId: string; role: ContractRole; mcpSessionId: string; ts: string },
  signer: ContractSigner,
): LaneOpenRequest {
  const body = {
    schema: LANE_OPEN_SCHEMA, aud: fields.aud, keyId: fields.keyId, role: fields.role,
    mcpSessionId: fields.mcpSessionId, ts: fields.ts,
  };
  const sig = signHex(canonicalJson({ ...body, signature: { alg: "ed25519", keyId: signer.keyId } }), signer);
  return { ...body, signature: { alg: "ed25519", keyId: signer.keyId, sig } };
}

export function mintLaneRelease(
  fields: { aud: string; laneId: string; keyId: string; role: ContractRole; mcpSessionId: string; ts: string },
  signer: ContractSigner,
): { schema: typeof LANE_RELEASE_SCHEMA; aud: string; laneId: string; keyId: string; role: ContractRole; mcpSessionId: string; ts: string; signature: Ed25519Signature } {
  const body = {
    schema: LANE_RELEASE_SCHEMA, aud: fields.aud, laneId: fields.laneId, keyId: fields.keyId,
    role: fields.role, mcpSessionId: fields.mcpSessionId, ts: fields.ts,
  };
  const sig = signHex(canonicalJson({ ...body, signature: { alg: "ed25519", keyId: signer.keyId } }), signer);
  return { ...body, signature: { alg: "ed25519", keyId: signer.keyId, sig } };
}

export function mintRunLink(fields: { aud: string; runId: string; lanes: LinkedLanes; ts: string }, signer: ContractSigner): RunLinkRequest {
  const body = { schema: RUN_LINK_SCHEMA, aud: fields.aud, runId: fields.runId, lanes: fields.lanes, ts: fields.ts };
  const sig = signHex(canonicalJson({ ...body, alg: "ed25519", keyId: signer.keyId }), signer);
  return { ...body, signature: { alg: "ed25519", keyId: signer.keyId, sig } };
}

export function mintTerminalReceiptV2(
  fields: TerminalReceiptFields & { lanes: LinkedLanes; linkDigest: string },
  signer: ContractSigner,
): TerminalReceiptV2 {
  const body = {
    schema: TERMINAL_RECEIPT_V2_SCHEMA,
    runId: fields.runId,
    terminalState: fields.terminalState,
    ts: fields.ts,
    lanes: fields.lanes,
    linkDigest: fields.linkDigest,
  };
  const sig = signHex(canonicalJson({ ...body, alg: "ed25519", keyId: signer.keyId }), signer);
  return { ...body, signature: { alg: "ed25519", keyId: signer.keyId, sig } };
}

// --- lane bookkeeping --------------------------------------------------------

interface LaneEntry {
  laneId: string;
  keyId: string;
  role: ContractRole;
  mcpSessionId: string;
  openedAtMs: number;
  /** Ciphertext sealed by the sink to the enrolled key — useless to this service. */
  sealedBox: unknown;
  runId: string | null;
}

export interface RunLinkState {
  lanes: LinkedLanes;
  ts: string;
  linkDigest: string;
  status: "delivering" | "delivered" | "failed";
  attempts: number;
  lastError?: string;
}

export type TelemetryOpenResult =
  | { ok: true; laneId: string; role: ContractRole; sealedBox: unknown }
  | { ok: false; code: "NOT_FOUND" | "STATE_REFUSED" | "RATE_LIMITED" | "CONTRACT_UNAVAILABLE" | "PAYLOAD_INVALID"; retryable: boolean };

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) =>
  Promise<{ status: number; text(): Promise<string> }>;

export interface TelemetryLanesOptions {
  signer: ContractSigner;
  /** L5: the sink's signing keyId (TELEMETRY_SINK_KEY_ID) — the `aud` of every signed body. */
  sinkAudience: string;
  /** Base URL of the sink CLOSE listener (TELEMETRY_CLOSE_URL). */
  closeUrl: string;
  stateDir?: string;
  now?: () => number;
  fetchImpl?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Link retry schedule; last value repeats. */
  backoffMs?: readonly number[];
  attemptTimeoutMs?: number;
  /** Total link delivery deadline (default 90s). */
  deadlineMs?: number;
  /** Lanes older than this are never linked (the sink's lane window; default 6h). */
  laneWindowMs?: number;
}

export interface TelemetryLanes {
  /** The adapter's per-session call. Returns ciphertext only. */
  open(principal: { keyId: string; role: ContractRole }, mcpSessionId: string | undefined): Promise<TelemetryOpenResult>;
  /**
   * Service hook at bind (both seats taken): link + deliver, write-once.
   * `sessions` (O-3, cap > 1): per role, only lanes opened by these MCP
   * sessions are linked; absent, every unlinked lane of the bound keyId is.
   */
  onRunBound(
    run: { runId: string; bound: Partial<Record<ContractRole, { principalKeyId: string }>> },
    sessions?: Readonly<Record<ContractRole, readonly string[]>>,
  ): void;
  /** v2 for a linked run, v1 otherwise. */
  terminalReceiptFor(fields: TerminalReceiptFields, signer: ContractSigner): TerminalReceipt;
  linkFor(runId: string): RunLinkState | undefined;
  /**
   * L5: the MCP session dropped and no run can capture its lane any more
   * (the service calls this only above cap 1, for an unrouted session).
   * Forgets the unlinked lane locally (so no later link names it) and asks
   * the sink, once and best-effort, to stop counting it toward LANE_LIMIT.
   */
  release(keyId: string, mcpSessionId: string): void;
  /** Resolve when in-flight link deliveries settle (tests + shutdown). */
  flush(): Promise<void>;
}

function readState(file: string): { lanes: LaneEntry[]; links: Record<string, RunLinkState> } {
  const raw = JSON.parse(readFileSync(file, "utf8")) as { schema?: unknown; lanes?: unknown; links?: unknown };
  if (raw === null || typeof raw !== "object" || raw.schema !== LANES_STATE_SCHEMA
    || !Array.isArray(raw.lanes) || raw.links === null || typeof raw.links !== "object") {
    throw new Error(`corrupt ${file}`);
  }
  for (const l of raw.lanes as LaneEntry[]) {
    if (typeof l !== "object" || l === null || typeof l.laneId !== "string" || !LANE_ID_RE.test(l.laneId)
      || typeof l.keyId !== "string" || (l.role !== "buyer" && l.role !== "provider")
      || typeof l.mcpSessionId !== "string" || typeof l.openedAtMs !== "number"
      || (l.runId !== null && typeof l.runId !== "string")) {
      throw new Error(`corrupt ${file}: lane entry`);
    }
  }
  return { lanes: raw.lanes as LaneEntry[], links: raw.links as Record<string, RunLinkState> };
}

export function createTelemetryLanes(options: TelemetryLanesOptions): TelemetryLanes {
  const now = options.now ?? Date.now;
  const fetchImpl: FetchLike = options.fetchImpl ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  }));
  const backoff = options.backoffMs ?? [500, 1_000, 2_000, 4_000, 8_000];
  const attemptTimeoutMs = options.attemptTimeoutMs ?? 10_000;
  const deadlineMs = options.deadlineMs ?? 90_000;
  const laneWindowMs = options.laneWindowMs ?? 6 * 3600_000;
  const base = options.closeUrl.replace(/\/+$/, "");
  const file = options.stateDir === undefined ? undefined : path.join(options.stateDir, LANES_STATE_FILE);

  const lanes = new Map<string, LaneEntry>(); // `${keyId}\n${mcpSessionId}` → lane
  const links = new Map<string, RunLinkState>();
  if (file !== undefined && existsSync(file)) {
    // Corrupt state fails closed — construction throws (config → misconfigured).
    const state = readState(file);
    for (const l of state.lanes) lanes.set(`${l.keyId}\n${l.mcpSessionId}`, l);
    for (const [runId, link] of Object.entries(state.links)) links.set(runId, link);
  }
  const opening = new Map<string, Promise<TelemetryOpenResult>>();
  const inFlight = new Map<string, Promise<void>>();

  const persist = (): void => {
    if (file === undefined) return;
    mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeFileSync(fd, JSON.stringify({
        schema: LANES_STATE_SCHEMA,
        lanes: [...lanes.values()],
        links: Object.fromEntries(links),
      }));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, file);
    // The rename is durable only once the directory entry is (L4).
    const dirFd = openSync(path.dirname(file), "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  };

  /**
   * L4: a lane past the window can never be linked (onRunBound filters it
   * out), so its entry is dead weight — drop it, linked or not. The link
   * record itself stays: the run's v2 terminal receipt is built from it.
   */
  const prune = (t: number): boolean => {
    let dropped = false;
    for (const [key, l] of lanes) {
      if (l.openedAtMs + laneWindowMs <= t) {
        lanes.delete(key);
        dropped = true;
      }
    }
    return dropped;
  };
  if (prune(now())) {
    try { persist(); } catch { /* the pruned in-memory view is authoritative; the next write retries */ }
  }

  async function post(url: string, body: unknown): Promise<{ status: number; text: string }> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error(`attempt deadline ${attemptTimeoutMs}ms exceeded`));
      }, attemptTimeoutMs);
      timer.unref?.();
    });
    const work = (async () => {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      return { status: res.status, text: await res.text() };
    })();
    try {
      return await Promise.race([work, timedOut]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      work.catch(() => {});
      timedOut.catch(() => {});
    }
  }

  async function openOnce(principal: { keyId: string; role: ContractRole }, mcpSessionId: string): Promise<TelemetryOpenResult> {
    const request = mintLaneOpen(
      { aud: options.sinkAudience, keyId: principal.keyId, role: principal.role, mcpSessionId, ts: new Date(now()).toISOString() },
      options.signer,
    );
    let res: { status: number; text: string };
    try {
      res = await post(`${base}/v1/lanes/open`, request);
    } catch {
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: true };
    }
    if (res.status !== 200) {
      // Sink refusal → generic contract codes; sink internals never reach the agent.
      if (res.status === 404) return { ok: false, code: "NOT_FOUND", retryable: false };
      if (res.status === 409) return { ok: false, code: "STATE_REFUSED", retryable: false };
      if (res.status === 429) return { ok: false, code: "RATE_LIMITED", retryable: false };
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: res.status >= 500 };
    }
    let out: { laneId?: unknown; role?: unknown; keyId?: unknown; mcpSessionId?: unknown; sealedBox?: unknown };
    try {
      out = JSON.parse(res.text) as typeof out;
    } catch {
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: false };
    }
    // The sink must echo exactly what was asked — never accept a lane for
    // another principal or session.
    if (typeof out.laneId !== "string" || !LANE_ID_RE.test(out.laneId) || out.role !== principal.role
      || out.keyId !== principal.keyId || out.mcpSessionId !== mcpSessionId
      || typeof out.sealedBox !== "object" || out.sealedBox === null) {
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: false };
    }
    const entry: LaneEntry = {
      laneId: out.laneId, keyId: principal.keyId, role: principal.role, mcpSessionId,
      openedAtMs: now(), sealedBox: out.sealedBox, runId: null,
    };
    lanes.set(`${principal.keyId}\n${mcpSessionId}`, entry);
    prune(entry.openedAtMs);
    try {
      persist();
    } catch {
      // The lane is cached in memory (a same-session retry gets the same
      // box); the caller is told the record is not durable yet.
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: true };
    }
    return { ok: true, laneId: entry.laneId, role: entry.role, sealedBox: entry.sealedBox };
  }

  async function deliverLink(runId: string): Promise<void> {
    const link = links.get(runId);
    if (link === undefined) return;
    const request = mintRunLink({ aud: options.sinkAudience, runId, lanes: link.lanes, ts: link.ts }, options.signer);
    const startedAt = now();
    let attempt = 0;
    for (;;) {
      if (attempt > 0) {
        const delay = backoff[Math.min(attempt - 1, backoff.length - 1)];
        if (delay > 0) await sleep(delay);
      }
      attempt += 1;
      try {
        const res = await post(`${base}/v1/runs/${encodeURIComponent(runId)}/link`, request);
        if (res.status === 200) {
          link.status = "delivered";
          link.attempts = attempt;
          delete link.lastError;
          break;
        }
        link.lastError = linkErrorOf(res.status, res.text);
      } catch (err) {
        link.lastError = err instanceof Error ? err.message : String(err);
      }
      link.attempts = attempt;
      if (attempt > backoff.length || now() - startedAt >= deadlineMs) {
        // Permanently failed: the link stays recorded, the v2 close will be
        // refused by the sink and that failure surfaces on contract_status.
        link.status = "failed";
        break;
      }
    }
    try { persist(); } catch { /* the in-memory state is still authoritative for this process */ }
  }

  const startDelivery = (runId: string): void => {
    if (inFlight.has(runId)) return;
    inFlight.set(runId, deliverLink(runId).finally(() => inFlight.delete(runId)));
  };
  // Boot: resume links that never resolved (the sink's link is idempotent
  // for an identical lane set).
  for (const [runId, link] of links) if (link.status === "delivering") startDelivery(runId);

  return {
    async open(principal, mcpSessionId) {
      if (mcpSessionId === undefined || mcpSessionId === "") {
        return { ok: false, code: "PAYLOAD_INVALID", retryable: false };
      }
      const key = `${principal.keyId}\n${mcpSessionId}`;
      const cached = lanes.get(key);
      if (cached !== undefined) {
        if (cached.role !== principal.role) return { ok: false, code: "STATE_REFUSED", retryable: false };
        return { ok: true, laneId: cached.laneId, role: cached.role, sealedBox: cached.sealedBox };
      }
      const pending = opening.get(key);
      if (pending !== undefined) return pending;
      const p = openOnce(principal, mcpSessionId).finally(() => opening.delete(key));
      opening.set(key, p);
      return p;
    },

    onRunBound(run, sessions) {
      if (links.has(run.runId)) return;
      const t = now();
      const pick = (role: ContractRole): LaneEntry[] => {
        const keyId = run.bound[role]?.principalKeyId;
        if (keyId === undefined) return [];
        const only = sessions?.[role];
        return [...lanes.values()]
          .filter((l) => l.keyId === keyId && l.role === role && l.runId === null && l.openedAtMs + laneWindowMs > t)
          .filter((l) => only === undefined || only.includes(l.mcpSessionId))
          .sort((a, b) => a.openedAtMs - b.openedAtMs)
          .slice(-MAX_LANES_PER_ROLE);
      };
      const buyer = pick("buyer");
      const provider = pick("provider");
      // No lanes at all → no link → the run keeps the v1 close (Track A).
      if (buyer.length + provider.length === 0) return;
      const linked: LinkedLanes = { buyer: buyer.map((l) => l.laneId), provider: provider.map((l) => l.laneId) };
      for (const l of [...buyer, ...provider]) l.runId = run.runId;
      prune(t);
      links.set(run.runId, {
        lanes: linked,
        ts: new Date(t).toISOString(),
        linkDigest: linkDigestOf(run.runId, linked),
        status: "delivering",
        attempts: 0,
      });
      try { persist(); } catch { /* delivery below still carries the link */ }
      startDelivery(run.runId);
    },

    terminalReceiptFor(fields, signer) {
      const link = links.get(fields.runId);
      if (link === undefined) return mintTerminalReceipt(fields, signer);
      return mintTerminalReceiptV2({ ...fields, lanes: link.lanes, linkDigest: link.linkDigest }, signer);
    },

    linkFor(runId) {
      return links.get(runId);
    },

    release(keyId, mcpSessionId) {
      const key = `${keyId}\n${mcpSessionId}`;
      const lane = lanes.get(key);
      if (lane === undefined || lane.runId !== null) return;
      lanes.delete(key);
      try { persist(); } catch { /* the in-memory removal already keeps it out of any link */ }
      const request = mintLaneRelease({
        aud: options.sinkAudience, laneId: lane.laneId, keyId, role: lane.role, mcpSessionId,
        ts: new Date(now()).toISOString(),
      }, options.signer);
      const p = post(`${base}/v1/lanes/release`, request).then(() => {}, () => {});
      const id = `release:${lane.laneId}`;
      inFlight.set(id, p.finally(() => inFlight.delete(id)));
    },

    async flush() {
      await Promise.allSettled([...inFlight.values(), ...opening.values()]);
    },
  };
}
