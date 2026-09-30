// F4 webhook nudges. Reuses the timer tools' delivery stack from @clockchain/keeper as is:
// Standard-Webhooks signing (deriveOwnerSecret / deliverWebhook), the SSRF destination
// policy (assertSafeWebhookUrl at registration, ssrfOptionsFromEnv: allow-listed in HTTP
// mode), and the DNS-pinned deliverer (pinnedFetch: every resolved address range-checked,
// no redirects, bounded timeout). Standalone adds only: https-only targets and the notice.
import { randomUUID } from "node:crypto";

import {
  assertSafeWebhookUrl,
  deliverWebhook,
  deriveOwnerSecret,
  pinnedFetch,
  type FetchLike,
  type Resolver,
  type SsrfOptions,
} from "@clockchain/keeper";

import { StandaloneAdmissionError } from "./session-store.js";

export const NOTICE_TIMEOUT_MS = 5_000;
// A role is "quiet" (not already polling) when unseen this long; only then is a turn pushed.
export const NOTICE_QUIET_MS = 30_000;
// Never more than one notice to the same role within this window, whatever the trigger.
export const NOTICE_MIN_INTERVAL_MS = 60_000;

export interface StandaloneNotifierOptions {
  /** Server signing secret (raw or whsec_). Without it, webhooks are unavailable. */
  serverSecret?: string;
  ssrf?: SsrfOptions;
  /** Test seams: the POST and the DNS resolver behind the pinned deliverer. */
  fetchFn?: FetchLike;
  resolver?: Resolver;
  nowSec?: () => number;
}

export interface TurnNotice {
  type: "clockchain.standalone-handshake.turn";
  sessionId: string;
  role: string;
  pendingAction: string;
  trigger: "turn" | "nudge";
  callTool: "handshake_next";
}

export function createStandaloneNotifier(options: StandaloneNotifierOptions) {
  const serverSecret = options.serverSecret ?? "";
  const ssrf = options.ssrf ?? {};
  const fetchFn = options.fetchFn ?? pinnedFetch({ ...ssrf, resolver: options.resolver, timeoutMs: NOTICE_TIMEOUT_MS });
  const nowSec = options.nowSec ?? (() => Math.floor(Date.now() / 1000));

  return {
    enabled(): boolean {
      return serverSecret.length > 0;
    },

    /**
     * Validates a party's webhook and returns its per-registration signing secret (shown
     * only to that party). Refuses non-https and private/loopback/non-allow-listed hosts.
     */
    register(input: { sessionId: string; role: string; webhookUrl: unknown }): { webhookUrl: string; secret: string } {
      if (!this.enabled()) throw new StandaloneAdmissionError("WEBHOOKS_UNAVAILABLE");
      const url = input.webhookUrl;
      if (typeof url !== "string" || url.length > 2048) throw new StandaloneAdmissionError("WEBHOOK_REFUSED");
      try {
        const parsed = assertSafeWebhookUrl(url, ssrf);
        if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("https only, no credentials");
      } catch {
        throw new StandaloneAdmissionError("WEBHOOK_REFUSED");
      }
      return { webhookUrl: url, secret: this.secretFor(input.sessionId, input.role, url) };
    },

    /** The per-registration signing secret: derived, so it is never stored at rest. */
    secretFor(sessionId: string, role: string, webhookUrl: string): string {
      return deriveOwnerSecret(serverSecret, `standalone-handshake:${sessionId}:${role}:${webhookUrl}`);
    },

    /** One signed POST; never throws. The notice carries no bodies, secrets or URLs. */
    async deliver(target: { webhookUrl: string; secret: string }, notice: TurnNotice): Promise<{ ok: boolean; status: number | null }> {
      const result = await deliverWebhook({
        target: target.webhookUrl,
        body: notice,
        secret: target.secret,
        idempotencyKey: `csh_${randomUUID()}`,
        nowSec: nowSec(),
        fetchFn,
      });
      return { ok: result.ok, status: result.status };
    },
  };
}

export type StandaloneNotifier = ReturnType<typeof createStandaloneNotifier>;
