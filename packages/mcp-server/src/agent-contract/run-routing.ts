/**
 * O-3 (mcp-coordination-design.md): live-run routing keyed by
 * (keyId, mcpSessionId) with a per-keyId concurrency cap.
 *
 * `CONTRACT_MAX_RUNS_PER_KEY` (default 1) bounds how many LIVE runs one
 * bearer keyId may hold at once. At the default cap of 1 every MCP session of
 * a keyId shares the single routing slot `*` — exactly the pre-O-3
 * behaviour (one live run per keyId, any session of the token reaches it).
 * Above 1, each MCP session gets its own slot, so two sessions under one
 * token route to two distinct runs and never cross-route.
 */

export const DEFAULT_MAX_RUNS_PER_KEY = 1;
/** Hard upper bound accepted from config. */
export const MAX_RUNS_PER_KEY_LIMIT = 64;
/** The shared routing slot: every session at cap 1, or a call with no session id. */
export const SHARED_SLOT = "*";

export interface RunRouter {
  readonly cap: number;
  /** The routing slot a call lands in. */
  slotFor(mcpSessionId: string | undefined): string;
  /** Resolve a call's run: its own slot, else the shared slot. */
  get(keyId: string, mcpSessionId: string | undefined): string | undefined;
  getSlot(keyId: string, slot: string): string | undefined;
  set(keyId: string, slot: string, runId: string): void;
  deleteSlot(keyId: string, slot: string): void;
  /** Distinct runIds currently mapped for a keyId (any slot). */
  runIds(keyId: string): string[];
  /** The per-session slots (never `*`) of a keyId that route to `runId`. */
  sessionSlotsFor(keyId: string, runId: string): string[];
  /** Forget every mapping that points at `runId`. */
  dropRun(runId: string): void;
  /**
   * The pre-bind chain key for a call. At cap 1 (or with no session id) it
   * is the keyId — the pre-O-3 per-keyId chain. Above 1 it is per session.
   */
  chainKey(keyId: string, mcpSessionId: string | undefined): string;
}

/** Separator for per-session chain keys; env-sourced keyIds can never contain NUL. */
const CHAIN_SEP = "\u0000";

/** The keyId a pre-bind chain key belongs to. */
export function keyIdOfChain(chainKey: string): string {
  const i = chainKey.indexOf(CHAIN_SEP);
  return i === -1 ? chainKey : chainKey.slice(0, i);
}

/** The MCP session a per-session chain key belongs to (undefined for a per-keyId chain). */
export function sessionOfChain(chainKey: string): string | undefined {
  const i = chainKey.indexOf(CHAIN_SEP);
  return i === -1 ? undefined : chainKey.slice(i + 1);
}

export function normalizeMaxRunsPerKey(raw: number | undefined): number {
  if (raw === undefined) return DEFAULT_MAX_RUNS_PER_KEY;
  if (!Number.isInteger(raw) || raw < 1 || raw > MAX_RUNS_PER_KEY_LIMIT) {
    throw new Error(`maxRunsPerKey must be an integer 1..${MAX_RUNS_PER_KEY_LIMIT}`);
  }
  return raw;
}

export function createRunRouter(maxRunsPerKey: number | undefined): RunRouter {
  const cap = normalizeMaxRunsPerKey(maxRunsPerKey);
  const slots = new Map<string, Map<string, string>>();
  const slotFor = (mcpSessionId: string | undefined): string =>
    cap > 1 && mcpSessionId !== undefined && mcpSessionId !== "" ? mcpSessionId : SHARED_SLOT;
  return {
    cap,
    slotFor,
    get(keyId, mcpSessionId) {
      const m = slots.get(keyId);
      if (m === undefined) return undefined;
      return m.get(slotFor(mcpSessionId)) ?? m.get(SHARED_SLOT);
    },
    getSlot(keyId, slot) {
      return slots.get(keyId)?.get(slot);
    },
    set(keyId, slot, runId) {
      let m = slots.get(keyId);
      if (m === undefined) {
        m = new Map();
        slots.set(keyId, m);
      }
      m.set(slot, runId);
    },
    deleteSlot(keyId, slot) {
      const m = slots.get(keyId);
      if (m === undefined) return;
      m.delete(slot);
      if (m.size === 0) slots.delete(keyId);
    },
    runIds(keyId) {
      return [...new Set(slots.get(keyId)?.values() ?? [])];
    },
    sessionSlotsFor(keyId, runId) {
      return [...(slots.get(keyId) ?? [])]
        .filter(([slot, rid]) => rid === runId && slot !== SHARED_SLOT)
        .map(([slot]) => slot);
    },
    dropRun(runId) {
      for (const [keyId, m] of slots) {
        for (const [slot, rid] of m) if (rid === runId) m.delete(slot);
        if (m.size === 0) slots.delete(keyId);
      }
    },
    chainKey(keyId, mcpSessionId) {
      const slot = slotFor(mcpSessionId);
      return slot === SHARED_SLOT ? keyId : `${keyId}${CHAIN_SEP}${slot}`;
    },
  };
}
