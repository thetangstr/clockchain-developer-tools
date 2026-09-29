/**
 * N4b-8 (gap 3): the terminal close emitter. When a run reaches a
 * terminal state the contract server mints the signed
 * `ac-terminal-receipt/v1` the telemetry sink's close-only listener
 * accepts (packages/telemetry-sink checkReceipt) and POSTs it to
 * `TELEMETRY_CLOSE_URL` — a Compose DNS name on clockchain_edge, never
 * a public route.
 *
 * Guarantees:
 *  - one delivery task per run (idempotent: the sink's closeRun is
 *    idempotent, so retries/replays are safe);
 *  - bounded retries with backoff on transport errors AND non-2xx
 *    refusals;
 *  - every outcome lands on the run (run.telemetryClose) and as a
 *    run-chain receipt via recordOutcome — a permanently failed close
 *    is visible evidence, never silent.
 */
import { sign as edSign } from "node:crypto";

import { canonicalJson, canonicalDigest } from "./canonical.js";
import type { ContractSigner } from "./envelope.js";

/** The signed close authority the sink verifies. */
export interface TerminalReceipt {
  schema: "ac-terminal-receipt/v1";
  runId: string;
  terminalState: string;
  ts: string;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

export interface TerminalReceiptFields {
  runId: string;
  terminalState: string;
  ts: string;
}

/**
 * Mint a signed terminal receipt — the exact wire shape the sink verifies
 * (`ac-terminal-receipt/v1`; the signature covers the canonical JSON of
 * `{schema, runId, terminalState, ts, alg, keyId}` per sink checkReceipt).
 */
export function mintTerminalReceipt(fields: TerminalReceiptFields, signer: ContractSigner): TerminalReceipt {
  const message = {
    schema: "ac-terminal-receipt/v1" as const,
    runId: fields.runId,
    terminalState: fields.terminalState,
    ts: fields.ts,
    alg: "ed25519" as const,
    keyId: signer.keyId,
  };
  const sig = edSign(null, Buffer.from(canonicalJson(message), "utf8"), signer.privateKey);
  return {
    schema: message.schema,
    runId: message.runId,
    terminalState: message.terminalState,
    ts: message.ts,
    signature: { alg: "ed25519", keyId: signer.keyId, sig: `0x${sig.toString("hex")}` },
  };
}

export interface CloseDeliveryState {
  status: "delivering" | "delivered" | "failed";
  attempts: number;
  lastError?: string;
  deliveredAt?: string;
  /** sha256 of the canonical receipt — evidence of exactly what was posted. */
  receiptDigest: string;
}

export interface CloseEmitterOptions {
  signer: ContractSigner;
  /** Base URL of the sink close listener, e.g. http://telemetry-sink:8083 */
  closeUrl: string;
  now?: () => number;
  /** Injectable for tests — defaults to global fetch. */
  fetchImpl?: (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ status: number; text(): Promise<string> }>;
  /** Injectable for tests — defaults to setTimeout-based sleep. */
  sleep?: (ms: number) => Promise<void>;
  /** Backoff schedule per retry; last value repeats. Default ~5 tries over ~30s. */
  backoffMs?: readonly number[];
  /** Server-receipt hook — delivery success AND permanent failure are receipted. */
  recordOutcome?: (
    outcome: "delivered" | "failed",
    detail: {
      runId: string;
      receiptDigest: string;
      attempts: number;
      lastError?: string;
      /** The sink's 2xx body ({closed, head} or {pending, closedAt}) when delivered. */
      response?: unknown;
    },
  ) => void;
  /** Written back onto the run so contract_status can surface it. */
  setState?: (runId: string, state: CloseDeliveryState) => void;
  /** Read back for tests / status reconstruction. */
  getState?: (runId: string) => CloseDeliveryState | undefined;
}

export interface CloseEmitter {
  /**
   * Queue delivery of the signed terminal receipt for `runId`. Idempotent:
   * a second notify for the same run is a no-op while delivering, and the
   * sink tolerates a replayed receipt once delivered.
   */
  notify(input: TerminalReceiptFields): void;
  /** Resolve when every queued delivery has settled (tests + shutdown). */
  flush(): Promise<void>;
  state(runId: string): CloseDeliveryState | undefined;
}

export function createCloseEmitter(options: CloseEmitterOptions): CloseEmitter {
  const now = options.now ?? Date.now;
  const fetchImpl = options.fetchImpl ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const backoff = options.backoffMs ?? [500, 1_000, 2_000, 4_000, 8_000];
  const states = new Map<string, CloseDeliveryState>();
  const inFlight = new Map<string, Promise<void>>();

  const setState = (runId: string, state: CloseDeliveryState): void => {
    states.set(runId, state);
    options.setState?.(runId, state);
  };

  async function deliver(runId: string, receipt: TerminalReceipt): Promise<void> {
    const receiptDigest = canonicalDigest(receipt);
    const url = `${options.closeUrl.replace(/\/+$/, "")}/v1/runs/${encodeURIComponent(runId)}/close`;
    setState(runId, { status: "delivering", attempts: 0, receiptDigest });
    let lastError = "unreachable";
    for (let attempt = 1; ; attempt++) {
      const delay = attempt === 1 ? 0 : backoff[Math.min(attempt - 2, backoff.length - 1)];
      if (delay > 0) await sleep(delay);
      try {
        const res = await fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(receipt),
        });
        if (res.status >= 200 && res.status < 300) {
          let response: unknown;
          try { response = JSON.parse(await res.text()); } catch { response = null; }
          // A sink `pending:true` reply means the signed receipt was accepted —
          // the run seals at its deterministic boundary. That IS delivery.
          setState(runId, { status: "delivered", attempts: attempt, deliveredAt: new Date(now()).toISOString(), receiptDigest });
          options.recordOutcome?.("delivered", { runId, receiptDigest, attempts: attempt, response });
          return;
        }
        lastError = `http ${res.status}: ${(await res.text()).slice(0, 200)}`;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      }
      setState(runId, { status: "delivering", attempts: attempt, lastError, receiptDigest });
      if (attempt > backoff.length) break;
    }
    // Permanently failed — receipted and left visible on the run.
    setState(runId, { status: "failed", attempts: backoff.length + 1, lastError, receiptDigest });
    options.recordOutcome?.("failed", { runId, receiptDigest, attempts: backoff.length + 1, lastError });
  }

  return {
    notify(input) {
      const runId = input.runId;
      if (inFlight.has(runId)) return;
      const receipt = mintTerminalReceipt(input, options.signer);
      inFlight.set(runId, deliver(runId, receipt).finally(() => inFlight.delete(runId)));
    },
    async flush() {
      await Promise.allSettled([...inFlight.values()]);
    },
    state(runId) {
      return options.getState?.(runId) ?? states.get(runId);
    },
  };
}
