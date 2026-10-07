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
 *  - N4b-9 (F11): write-once — a delivered or permanently failed job is
 *    NEVER re-submitted; notify() dedupes on any recorded state;
 *  - N4b-9 (F12): every attempt has a deadline covering connect, response
 *    headers AND the response body, and the whole job has a total delivery
 *    deadline — a stalled sink can never hang an attempt or the shutdown;
 *  - every outcome lands on the run (run.telemetryClose) and as a
 *    run-chain receipt via recordOutcome — a permanently failed close
 *    is visible evidence, never silent.
 */
import { sign as edSign } from "node:crypto";

import { canonicalJson, canonicalDigest } from "./canonical.js";
import type { ContractSigner } from "./envelope.js";
import type { TerminalReceiptV2 } from "./telemetry-lanes.js";

/**
 * CDT-SEC L9 / CDT-GAPS gap 4: what a refused delivery persists — the HTTP
 * status and the sink's refusal code (`{"error": "<code>"}` or
 * `{"code": "<code>"}`) when it is a plain lowercase code, never the body
 * itself. Shared by the close emitter and the O-1 link delivery.
 */
export function refusalErrorOf(status: number, text: string): string {
  let code: unknown;
  try {
    const parsed = JSON.parse(text) as { error?: unknown; code?: unknown };
    code = parsed?.error ?? parsed?.code;
  } catch { /* not JSON: status only */ }
  return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? `http ${status} ${code}` : `http ${status}`;
}

/** The signed close authority the sink verifies. */
export interface TerminalReceiptV1 {
  schema: "ac-terminal-receipt/v1";
  runId: string;
  terminalState: string;
  ts: string;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

/**
 * O-1: a run whose lanes were linked at bind closes with the v2 receipt
 * (minted in telemetry-lanes.ts); the emitter delivers either verbatim.
 */
export type TerminalReceipt = TerminalReceiptV1 | TerminalReceiptV2;

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
export function mintTerminalReceipt(fields: TerminalReceiptFields, signer: ContractSigner): TerminalReceiptV1 {
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
  fetchImpl?: (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{ status: number; text(): Promise<string> }>;
  /** Injectable for tests — defaults to setTimeout-based sleep. */
  sleep?: (ms: number) => Promise<void>;
  /** Backoff schedule per retry; last value repeats. Default ~5 tries over ~30s. */
  backoffMs?: readonly number[];
  /**
   * N4b-9 (F12): per-attempt deadline covering connect + response headers
   * + response body (default 10s). The attempt is aborted on expiry.
   */
  attemptTimeoutMs?: number;
  /**
   * N4b-9 (F12): total delivery deadline measured from first dispatch
   * (default 90s). On expiry the job fails with a bounded error even if
   * retries remain.
   */
  deadlineMs?: number;
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
   * a second notify for the same run is a no-op — in-flight, delivered AND
   * permanently failed jobs all dedupe (the receipt identity is
   * write-once). Returns the minted receipt synchronously, BEFORE any
   * response can be observed — the caller durably enqueues it.
   */
  notify(input: TerminalReceiptFields): TerminalReceipt | undefined;
  /**
   * N4b-9 (F14): deliver an already-minted receipt — the restart-recovery
   * path. Same dedupe: a run with any recorded state is not re-delivered.
   */
  resume(receipt: TerminalReceipt): void;
  /** Resolve when every queued delivery has settled (tests + shutdown). */
  flush(): Promise<void>;
  /**
   * N4b-9 (F14): bounded drain — resolves when in-flight deliveries settle
   * or `deadlineMs` passes, whichever comes first. A deadline expiry never
   * hangs shutdown; unfinished jobs stay "delivering" for boot recovery.
   */
  drain(deadlineMs: number): Promise<void>;
  state(runId: string): CloseDeliveryState | undefined;
}

export function createCloseEmitter(options: CloseEmitterOptions): CloseEmitter {
  const now = options.now ?? Date.now;
  const fetchImpl = options.fetchImpl ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  }));
  const backoff = options.backoffMs ?? [500, 1_000, 2_000, 4_000, 8_000];
  const attemptTimeoutMs = options.attemptTimeoutMs ?? 10_000;
  const deadlineMs = options.deadlineMs ?? 90_000;
  const states = new Map<string, CloseDeliveryState>();
  const receipts = new Map<string, TerminalReceipt>();
  const inFlight = new Map<string, Promise<void>>();

  const setState = (runId: string, state: CloseDeliveryState): void => {
    states.set(runId, state);
    options.setState?.(runId, state);
  };

  /**
   * F12: ONE attempt with a hard deadline covering the whole exchange —
   * connect, response headers AND the body read. The AbortController
   * cancels a real fetch; the race bounds a transport that ignores it.
   */
  async function attemptOnce(url: string, body: string): Promise<{ status: number; text: string }> {
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
        body,
        signal: controller.signal,
      });
      return { status: res.status, text: await res.text() };
    })();
    try {
      return await Promise.race([work, timedOut]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // The losing branch may settle later — swallow it so an abandoned
      // fetch never reports as an unhandled rejection.
      work.catch(() => {});
      timedOut.catch(() => {});
    }
  }

  async function deliver(receipt: TerminalReceipt): Promise<void> {
    const runId = receipt.runId;
    const receiptDigest = canonicalDigest(receipt);
    const url = `${options.closeUrl.replace(/\/+$/, "")}/v1/runs/${encodeURIComponent(runId)}/close`;
    const body = JSON.stringify(receipt);
    const startedAt = now();
    setState(runId, { status: "delivering", attempts: 0, receiptDigest });
    let lastError = "unreachable";
    let attempt = 0;
    for (;;) {
      if (now() - startedAt >= deadlineMs) {
        lastError = `delivery deadline ${deadlineMs}ms exceeded`;
        break;
      }
      attempt += 1;
      const delay = attempt === 1 ? 0 : backoff[Math.min(attempt - 2, backoff.length - 1)];
      if (delay > 0) await sleep(delay);
      if (now() - startedAt >= deadlineMs) {
        lastError = `delivery deadline ${deadlineMs}ms exceeded`;
        break;
      }
      // F12: the attempt is counted at DISPATCH — a stalled request that
      // is aborted still consumed an attempt.
      setState(runId, { status: "delivering", attempts: attempt, receiptDigest });
      try {
        const res = await attemptOnce(url, body);
        if (res.status >= 200 && res.status < 300) {
          let response: unknown;
          try { response = JSON.parse(res.text); } catch { response = null; }
          // A sink `pending:true` reply means the signed receipt was accepted —
          // the run seals at its deterministic boundary. That IS delivery.
          setState(runId, { status: "delivered", attempts: attempt, deliveredAt: new Date(now()).toISOString(), receiptDigest });
          options.recordOutcome?.("delivered", { runId, receiptDigest, attempts: attempt, response });
          return;
        }
        // CDT-GAPS gap 4 (L9 treatment): the HTTP status and the sink's
        // refusal code only — never the response body, which a sink (or
        // anything answering at its address) could fill with request
        // content that would then reach contract_status, the outbox job
        // and the failed-close receipt.
        lastError = refusalErrorOf(res.status, res.text);
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      }
      setState(runId, { status: "delivering", attempts: attempt, lastError, receiptDigest });
      if (attempt > backoff.length) break;
    }
    // Permanently failed — receipted and left visible on the run.
    setState(runId, { status: "failed", attempts: attempt, lastError, receiptDigest });
    options.recordOutcome?.("failed", { runId, receiptDigest, attempts: attempt, lastError });
  }

  const enqueue = (receipt: TerminalReceipt): void => {
    const runId = receipt.runId;
    if (states.has(runId) || inFlight.has(runId)) return;
    receipts.set(runId, receipt);
    inFlight.set(runId, deliver(receipt).finally(() => inFlight.delete(runId)));
  };

  return {
    notify(input) {
      if (states.has(input.runId) || inFlight.has(input.runId)) return undefined;
      const receipt = mintTerminalReceipt(input, options.signer);
      enqueue(receipt);
      return receipt;
    },
    resume(receipt) {
      enqueue(receipt);
    },
    async flush() {
      await Promise.allSettled([...inFlight.values()]);
    },
    async drain(deadline) {
      const timeout = new Promise<"timeout">((resolve) => {
        const t = setTimeout(() => resolve("timeout"), deadline);
        t.unref?.();
      });
      await Promise.race([Promise.allSettled([...inFlight.values()]).then(() => "settled" as const), timeout]);
    },
    state(runId) {
      return options.getState?.(runId) ?? states.get(runId);
    },
  };
}
