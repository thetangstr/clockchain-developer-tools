import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { SERVER_KEYS_PATH, type buildServerKeysDoc } from "./server-card.js";
import type { ContractService } from "./service.js";

/**
 * N4b-6: the agent-contract evidence routes as ONE exported code path —
 * `GET /contract/receipts` (observer feed), `GET /contract/keys` (published
 * signing keys) and `GET /contract/run-salt` (verifier-scoped salt
 * disclosure). `http.ts` mounts these exact handlers; the l-stack mounts the
 * same code via `startContractEvidenceServer`, so neither can drift.
 *
 * Semantics are byte-identical to the inline handlers they replace:
 *   - surface off / token unset → 404 {error:"not_found"}
 *   - non-GET                → 403 {error:"forbidden"}     (receipts, run-salt)
 *   - bad/missing bearer     → 401 {error:"unauthorized"}  (sha256 + constant-time)
 *   - feed limiter           → 429 {error:"rate_limited"}  (+onRateLimited)
 *   - unknown run/key        → 404
 * `/contract/keys` is public and serves the caller-built keysDoc verbatim.
 */

const pathOf = (url: string | undefined): string => (url ?? "").split("?")[0];
const firstHeader = (h: string | string[] | undefined): string =>
  (Array.isArray(h) ? h[0] : h) ?? "";

const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store" } as const;

function refuse(res: ServerResponse, status: number, error: string): void {
  res.writeHead(status, JSON_HEADERS);
  res.end(JSON.stringify({ error }));
}

/** sha256 + timingSafeEqual bearer check — same pattern as the metrics token. */
function bearerOk(req: IncomingMessage, token: string): boolean {
  const expected = createHash("sha256").update(token).digest();
  const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(req.headers.authorization));
  const presented = bearer ? createHash("sha256").update(bearer[1].trim()).digest() : null;
  return presented !== null && timingSafeEqual(presented, expected);
}

export interface ContractEvidenceRoutesOptions {
  /** The contract service; when absent every route answers 404. */
  service?: ContractService;
  /** Observer-feed bearer token (`CONTRACT_OBSERVER_TOKEN`); unset → closed. */
  observerToken?: string;
  /** Salt-disclosure bearer token (`CONTRACT_VERIFIER_TOKEN`); unset → closed. */
  verifierToken?: string;
  /** Prebuilt `GET /contract/keys` document; absent → the route 404s. */
  keysDoc?: ReturnType<typeof buildServerKeysDoc>;
  /**
   * Feed limiter — `(scope, subject) => allowed`. http.ts injects
   * `createObserverFeedLimiter` (CONTRACT_OBSERVER_PER_MINUTE global, optional
   * CONTRACT_OBSERVER_PER_KEY_PER_MINUTE per subject); the default is the same
   * 30/min global bucket. `subject` is `k:<keyId>` or `r:<runId>` from the query.
   */
  allowFeed?: (scope: "observer" | "verifier", subject?: string) => boolean;
  /** Metrics hook invoked on a rate-limited feed request. */
  onRateLimited?: () => void;
}

export type ContractEvidenceRoutes = (req: IncomingMessage, res: ServerResponse) => boolean;

/** Strict positive integer from an env string; "" / unset / invalid -> undefined. */
export function parsePerMinute(raw: string | undefined): number | undefined {
  const v = (raw ?? "").trim();
  if (!/^[1-9][0-9]{0,6}$/.test(v)) return undefined;
  return Number(v);
}

/**
 * The observer/verifier feed limiter (COUNTER window follow-up, 2026-10-08).
 * - `globalPerMinute`: one bucket per scope, exactly today's behaviour.
 * - `perSubjectPerMinute` (optional): an extra bucket per scope + queried
 *   keyId/runId, checked FIRST; a request refused there does not consume the
 *   global bucket. Unset = the old single global bucket, byte for byte.
 */
export function createObserverFeedLimiter(o: {
  globalPerMinute: number;
  perSubjectPerMinute?: number;
  now?: () => number;
}): (scope: "observer" | "verifier", subject?: string) => boolean {
  const now = o.now ?? Date.now;
  const global = keyedWindowLimiter(o.globalPerMinute, 60_000, now);
  const perSubject = o.perSubjectPerMinute !== undefined
    ? keyedWindowLimiter(o.perSubjectPerMinute, 60_000, now)
    : undefined;
  return (scope, subject) => {
    if (perSubject !== undefined && subject !== undefined && subject !== "") {
      if (!perSubject(`${scope}|${subject}`)) return false;
    }
    return global(scope);
  };
}

const subjectOf = (url: string | undefined): string | undefined => {
  const q = new URL(url ?? "/", "http://localhost").searchParams;
  const keyId = q.get("keyId");
  if (keyId !== null && keyId !== "") return `k:${keyId}`;
  const runId = q.get("runId");
  if (runId !== null && runId !== "") return `r:${runId}`;
  return undefined;
};

export function createContractEvidenceRoutes(
  options: ContractEvidenceRoutesOptions,
): ContractEvidenceRoutes {
  const allowFeed = options.allowFeed ?? keyedWindowLimiter(30, 60_000, Date.now);
  const onRateLimited = options.onRateLimited ?? (() => {});

  return (req, res) => {
    const path = pathOf(req.url);

    // `GET /contract/keys` — the standalone key-discovery document. Public
    // (public-key material only); 404 when no document was supplied.
    if (path === SERVER_KEYS_PATH) {
      if (req.method !== "GET" || options.keysDoc === undefined) {
        refuse(res, 404, "not_found");
        return true;
      }
      res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=300" });
      res.end(JSON.stringify(options.keysDoc));
      return true;
    }

    // `GET /contract/receipts?runId=` — the read-only observer receipt feed.
    if (path === "/contract/receipts") {
      const token = options.observerToken;
      if (options.service === undefined || token === undefined) {
        refuse(res, 404, "not_found");
        return true;
      }
      if (req.method !== "GET") {
        refuse(res, 403, "forbidden");
        return true;
      }
      if (!bearerOk(req, token)) {
        refuse(res, 401, "unauthorized");
        return true;
      }
      if (!allowFeed("observer", subjectOf(req.url))) {
        onRateLimited();
        refuse(res, 429, "rate_limited");
        return true;
      }
      const params = new URL(req.url ?? "/", "http://localhost").searchParams;
      // `?keyId=` serves a principal's PRE-BIND chain; `?runId=` serves the
      // run chain plus both bound principals' pre-bind chains.
      const keyId = params.get("keyId");
      const runId = params.get("runId") ?? "";
      // O-3: above CONTRACT_MAX_RUNS_PER_KEY=1 a keyId's pre-bind chain is
      // per MCP session — `&mcpSessionId=` selects it.
      const feedSession = params.get("mcpSessionId") ?? undefined;
      const feed = keyId !== null
        ? options.service.preBindFeed(keyId, feedSession)
        : options.service.receiptFeed(runId);
      if (feed === undefined) {
        refuse(res, 404, "not_found");
        return true;
      }
      res.writeHead(200, JSON_HEADERS);
      res.end(JSON.stringify(feed));
      return true;
    }

    // `GET /contract/run-salt?runId=…|keyId=…` — verifier-scoped salt
    // disclosure; deliberately a different credential from the observer token.
    if (path === "/contract/run-salt") {
      const token = options.verifierToken;
      if (options.service === undefined || token === undefined) {
        refuse(res, 404, "not_found");
        return true;
      }
      if (req.method !== "GET") {
        refuse(res, 403, "forbidden");
        return true;
      }
      if (!bearerOk(req, token)) {
        refuse(res, 401, "unauthorized");
        return true;
      }
      if (!allowFeed("verifier", subjectOf(req.url))) {
        onRateLimited();
        refuse(res, 429, "rate_limited");
        return true;
      }
      const q = new URL(req.url ?? "/", "http://localhost").searchParams;
      const keyIdQ = q.get("keyId");
      const runIdQ = q.get("runId");
      const sessionQ = q.get("mcpSessionId");
      const salt = options.service.saltFor(
        keyIdQ !== null
          ? { keyId: keyIdQ, ...(sessionQ !== null ? { mcpSessionId: sessionQ } : {}) }
          : runIdQ !== null ? { runId: runIdQ } : {},
      );
      if (salt === undefined) {
        refuse(res, 404, "not_found");
        return true;
      }
      res.writeHead(200, JSON_HEADERS);
      res.end(JSON.stringify(salt));
      return true;
    }

    return false;
  };
}

/**
 * A standalone loopback-only server mounting just the evidence routes — the
 * l-stack's mount point. `listenHost` defaults to 127.0.0.1 so a verifier
 * harness never accidentally exposes the feed off-host.
 */
export async function startContractEvidenceServer(
  options: ContractEvidenceRoutesOptions & { port?: number; listenHost?: string },
): Promise<{ server: Server; url: string; close(): Promise<void> }> {
  const routes = createContractEvidenceRoutes(options);
  const host = options.listenHost ?? "127.0.0.1";
  const server = createServer((req, res) => {
    if (!routes(req, res)) {
      refuse(res, 404, "not_found");
    }
  });
  await new Promise<void>((resolve) => server.listen(options.port ?? 0, host, resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    server,
    url: `http://${host}:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
