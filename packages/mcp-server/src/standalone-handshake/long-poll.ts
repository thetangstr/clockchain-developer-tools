import { AsyncLocalStorage } from "node:async_hooks";

// handshake_next holds a request open while it waits. Holds are a shared resource, so
// they are bounded three ways: one per role (a new call supersedes the old hold), a cap
// per client, and a global cap. A hold also ends when its HTTP request goes away.

/**
 * Per-request context set by the public HTTP handler. It travels through the MCP SDK and
 * the http.ts invoke wrapper implicitly, so neither needs to know about it.
 */
export interface StandaloneRequestContext {
  /** Aborted when the HTTP request or response closes. */
  signal?: AbortSignal;
  /** Rate/hold bucket for the caller, e.g. the client IP. */
  clientKey: string;
}

export const standaloneRequestContext = new AsyncLocalStorage<StandaloneRequestContext>();

export const MAX_HOLDS = 512;
// Several agents can share one egress IP (a hosted assistant's sandbox fleet), so the
// per-client cap leaves room for a handful of concurrent handshakes behind one address.
export const MAX_HOLDS_PER_CLIENT = 16;

export interface Hold {
  /** Resolves after `ms`, or early on a session change, supersession or abort. */
  sleep(ms: number): Promise<void>;
  /** True once a newer hold for the same role replaced this one. */
  readonly superseded: boolean;
  /** True once the request that owns this hold went away. */
  readonly aborted: boolean;
  release(): void;
}

export function createHoldRegistry(options: { maxHolds?: number; maxHoldsPerClient?: number } = {}) {
  const maxHolds = options.maxHolds ?? MAX_HOLDS;
  const maxHoldsPerClient = options.maxHoldsPerClient ?? MAX_HOLDS_PER_CLIENT;
  const byRole = new Map<string, HoldImpl>();
  const bySession = new Map<string, Set<HoldImpl>>();
  const perClient = new Map<string, number>();
  let total = 0;

  class HoldImpl implements Hold {
    superseded = false;
    private released = false;
    private wake: (() => void) | undefined;
    private readonly onAbort = () => this.wakeUp();

    constructor(readonly roleKey: string, readonly sessionId: string, readonly clientKey: string, private readonly signal: AbortSignal | undefined) {
      signal?.addEventListener("abort", this.onAbort);
    }

    get aborted(): boolean {
      return this.signal?.aborted === true;
    }

    sleep(ms: number): Promise<void> {
      if (this.superseded || this.aborted) return Promise.resolve();
      return new Promise((resolvePromise) => {
        const timer = setTimeout(done, ms);
        const self = this;
        function done() {
          clearTimeout(timer);
          self.wake = undefined;
          resolvePromise();
        }
        this.wake = done;
      });
    }

    wakeUp(): void {
      this.wake?.();
    }

    supersede(): void {
      this.superseded = true;
      this.release();
      this.wakeUp();
    }

    release(): void {
      if (this.released) return;
      this.released = true;
      this.signal?.removeEventListener("abort", this.onAbort);
      total -= 1;
      const clientCount = (perClient.get(this.clientKey) ?? 1) - 1;
      if (clientCount <= 0) perClient.delete(this.clientKey);
      else perClient.set(this.clientKey, clientCount);
      if (byRole.get(this.roleKey) === this) byRole.delete(this.roleKey);
      const sessionHolds = bySession.get(this.sessionId);
      sessionHolds?.delete(this);
      if (sessionHolds?.size === 0) bySession.delete(this.sessionId);
    }
  }

  return {
    /** A new hold for this role, superseding any older one; undefined when a cap is reached. */
    acquire(input: { roleKey: string; sessionId: string; clientKey: string; signal?: AbortSignal }): Hold | undefined {
      byRole.get(input.roleKey)?.supersede();
      if (total >= maxHolds || (perClient.get(input.clientKey) ?? 0) >= maxHoldsPerClient) return undefined;
      const hold = new HoldImpl(input.roleKey, input.sessionId, input.clientKey, input.signal);
      total += 1;
      perClient.set(input.clientKey, (perClient.get(input.clientKey) ?? 0) + 1);
      byRole.set(input.roleKey, hold);
      let sessionHolds = bySession.get(input.sessionId);
      if (sessionHolds === undefined) bySession.set(input.sessionId, (sessionHolds = new Set()));
      sessionHolds.add(hold);
      return hold;
    },

    /** Wakes every hold on a session so it re-evaluates now instead of at its next slice. */
    notify(sessionId: string): void {
      for (const hold of bySession.get(sessionId) ?? []) hold.wakeUp();
    },

    size(): number {
      return total;
    },
  };
}
