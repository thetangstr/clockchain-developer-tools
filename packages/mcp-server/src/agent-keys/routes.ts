// The public book of agent keys over HTTP (MCP_AGENT_KEYS=1). Anyone, without signing in, can look a key up by its
// fingerprint: GET /agent-keys/<fp>.json. An agent replaces its key (POST /agent-keys/<fp>/replace, signed by the old key)
// or cancels it (POST /agent-keys/<fp>/revoke, signed by the key itself) with an RFC 7523 assertion whose audience is that
// action's own URL; a replace assertion also names the new key's fingerprint in its `new_key` claim. A change takes effect
// in the book at once, so the old key's tokens stop on their next call, and is then filed on Clockchain under the key's
// reference. A filing that waits (the ledger is slow, down, or over an allowance) is shown as pending and tried again when
// the change is asked for again, or on a lookup at most once a minute per event.
// Errors are {error, error_description}, and nothing here ever echoes or logs an assertion.
import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ExpiringSet } from "../oauth-replay.js";
import { ed25519PublicKeyDer, fingerprint } from "../shadow/lib/keys.js";
import { limiter } from "../standalone-handshake/public-server.js";
import { AgentKeyError, type AgentKeyBook, type KeyEntry } from "./book.js";
import type { FilingResult } from "./filing.js";
import type { KeyProof } from "./proof.js";

type Change = "replaced" | "revoked";

export interface AgentKeyRoutesOptions {
  /** The server's one key book (the token grant's). */
  book: AgentKeyBook;
  proof: KeyProof;
  /** The token grant's spent-assertion set (OAuthHandler.usedAssertions). Unset: replace and revoke refuse closed (503). */
  usedAssertions: ExpiringSet | undefined;
  /** The base the OAuth metadata's token_endpoint is built from (MCP_PUBLIC_URL). */
  publicUrl: string;
  /** The rate-limit bucket for a request (the OAuth handler's: the real client behind the trusted proxy, IPv6 by /64). */
  ipOf: (req: IncomingMessage) => string;
  readJsonBody: (req: IncomingMessage, maxBytes?: number) => Promise<unknown>;
  /** Files a change on Clockchain (ShadowService.fileAgentKeyEvent). Unset (Shadow off): changes stand and wait as pending. */
  file?: (fp: string, event: Change, extra: { newFp?: string }) => Promise<FilingResult>;
  /** Lookups per address per minute (SHADOW_ANON_PER_MINUTE). */
  lookupsPerMinute: number;
  /** Replaces and revokes per address per hour (default 20). */
  changesPerHour?: number;
  now?: () => number;
  log?: (event: Record<string, unknown>) => void;
  onRateLimited?: () => void;
}

const LOOKUP = /^\/agent-keys\/([0-9a-f]{64})\.json$/;
const ACTION = /^\/agent-keys\/([0-9a-f]{64})\/(replace|revoke)$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const MAX_BODY_BYTES = 16 * 1024;
const RETRY_MS = 60_000;
const MAX_RETRY_KEYS = 10_000;
const CHANGE_OF = { replace: "replaced", revoke: "revoked" } as const;

type EventView = { action: KeyEntry["events"][number]["action"]; at: string; state: "filed" | "pending"; ledgerId?: string; block?: number; filedAt?: string };

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const latest = (entry: KeyEntry, action: Change) => [...entry.events].reverse().find((e) => e.action === action);

function eventView(e: KeyEntry["events"][number]): EventView {
  return {
    action: e.action, at: e.at,
    // A key's own "filed" event is written only once it is on the ledger; a change is filed once it has filedAt.
    state: e.action === "filed" || e.filedAt !== undefined ? "filed" : "pending",
    ...(e.ledgerId !== undefined ? { ledgerId: e.ledgerId } : {}),
    ...(e.block !== undefined ? { block: e.block } : {}),
    ...(e.filedAt !== undefined ? { filedAt: e.filedAt } : {}),
  };
}

/** The public face of a key: named fields only, so nothing else stored with it can leak. */
export function keyView(e: KeyEntry) {
  const f = e.filing;
  return {
    fingerprint: e.fingerprint,
    agentId: e.root.slice(0, 16),
    publicKey: e.publicKeyPem,
    status: e.status,
    root: e.root,
    firstSeenAt: e.firstSeenAt,
    filing: {
      state: f.state,
      ...(f.ledgerId !== undefined ? { ledgerId: f.ledgerId } : {}),
      ...(f.block !== undefined ? { block: f.block } : {}),
      ...(f.filedAt !== undefined ? { filedAt: f.filedAt } : {}),
    },
    ...(e.replacedBy !== undefined ? { replacedBy: e.replacedBy } : {}),
    ...(e.revokedAt !== undefined ? { revokedAt: e.revokedAt } : {}),
    events: e.events.map(eventView),
  };
}

/** Serves /agent-keys/*: true when the path is under /agent-keys (answered, 404 if not one of ours), false otherwise. */
export function createAgentKeyRoutes(o: AgentKeyRoutesOptions): (req: IncomingMessage, res: ServerResponse) => Promise<boolean> {
  const now = o.now ?? Date.now;
  const log = o.log ?? ((event) => console.error(JSON.stringify(event)));
  const base = o.publicUrl;
  const allowLookup = limiter(o.lookupsPerMinute, 60_000, now);
  const allowChange = limiter(o.changesPerHour ?? 20, 60 * 60_000, now);
  /** One filing per key event at a time, and the earliest a lookup may try one again. */
  const inFlight = new Map<string, Promise<FilingResult>>();
  const nextTry = new Map<string, number>();

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  }
  const fail = (res: ServerResponse, status: number, error: string, description: string, headers: Record<string, string> = {}): void =>
    send(res, status, { error, error_description: description }, headers);
  const unavailable = (res: ServerResponse): void =>
    fail(res, 503, "temporarily_unavailable", "The agent key book is unavailable. Try again shortly.", { "retry-after": "60" });
  const limited = (res: ServerResponse, surface: string, description: string, retryAfter: string): void => {
    o.onRateLimited?.();
    log({ event: "agent_keys_rate_limited", surface });
    fail(res, 429, "temporarily_unavailable", description, { "retry-after": retryAfter });
  };

  /** Files the change and records where it landed on the key's event. Never throws: a filing that can't run is pending. */
  function fileChange(fp: string, change: Change, newFp: string | undefined): Promise<FilingResult> {
    const key = `${fp}:${change}`;
    const running = inFlight.get(key);
    if (running) return running;
    if (nextTry.size >= MAX_RETRY_KEYS) {
      const t = now();
      for (const [k, at] of nextTry) if (at <= t) nextTry.delete(k);
      if (nextTry.size >= MAX_RETRY_KEYS) nextTry.clear();
    }
    nextTry.set(key, now() + RETRY_MS);
    const file = o.file;
    const p = (async (): Promise<FilingResult> => {
      if (!file) return { state: "pending" };
      let result: FilingResult;
      try {
        result = await file(fp, change, change === "replaced" && newFp ? { newFp } : {});
      } catch (e) {
        log({ event: "agent_key_filing_error", change, error: (e as Error)?.name ?? "error" });
        return { state: "pending" };
      }
      try {
        o.book.setEventFiling(fp, change, result);
      } catch (e) {
        log({ event: "agent_key_filing_unsaved", change, error: (e as Error)?.name ?? "error" });
      }
      return result;
    })().finally(() => inFlight.delete(key));
    inFlight.set(key, p);
    return p;
  }

  /** A lookup of a key whose change still waits for Clockchain tries it again behind the answer, at most once a minute. */
  function retryWaiting(entry: KeyEntry): void {
    if (!o.file) return;
    for (const change of ["replaced", "revoked"] as const) {
      const event = latest(entry, change);
      if (!event || event.filedAt !== undefined) continue;
      if (now() < (nextTry.get(`${entry.fingerprint}:${change}`) ?? 0)) continue;
      void fileChange(entry.fingerprint, change, entry.replacedBy);
    }
  }

  function lookup(req: IncomingMessage, res: ServerResponse, fp: string): void {
    if (!allowLookup(`lookup:${o.ipOf(req)}`)) {
      return limited(res, "agent_key_lookup", "Too many lookups from this address. Try again in a minute.", "60");
    }
    let entry: KeyEntry | null;
    try {
      entry = o.book.get(fp);
    } catch {
      log({ event: "agent_keys_unavailable" });
      return unavailable(res);
    }
    if (!entry) return fail(res, 404, "not_found", "No agent key has this fingerprint.");
    retryWaiting(entry);
    send(res, 200, keyView(entry), { "cache-control": "public, max-age=60" });
  }

  async function changeKey(req: IncomingMessage, res: ServerResponse, fp: string, action: "replace" | "revoke"): Promise<void> {
    const change = CHANGE_OF[action];
    const refuse = (outcome: string, status: number, error: string, description: string, agentId?: string): void => {
      log({ event: "agent_key_change_refused", change, outcome, ...(agentId ? { agent_id: agentId } : {}) });
      fail(res, status, error, description);
    };
    if (!allowChange(`change:${o.ipOf(req)}`)) {
      return limited(res, "agent_key_change", "Too many key changes from this address. Try again later.", "3600");
    }
    const usedAssertions = o.usedAssertions;
    // Without the spent-assertion set an assertion could be used twice: refuse closed.
    if (!usedAssertions) return unavailable(res);

    let body: unknown;
    try {
      body = await o.readJsonBody(req, MAX_BODY_BYTES);
    } catch {
      return refuse("bad_body", 400, "invalid_request", "Send a JSON body of at most 16 KB.");
    }
    const members = action === "replace" ? ["assertion", "new_public_key"] : ["assertion"];
    if (!isObj(body) || Object.keys(body).length !== members.length || !members.every((m) => typeof body[m] === "string")) {
      return refuse("bad_body", 400, "invalid_request", action === "replace"
        ? "Send {\"assertion\": ..., \"new_public_key\": ...}: an assertion signed by this key, and the new public key."
        : "Send {\"assertion\": ...}: an assertion signed by this key.");
    }
    const newPem = action === "replace" ? body.new_public_key as string : undefined;
    if (newPem !== undefined && !ed25519PublicKeyDer(newPem)) {
      return refuse("bad_new_key", 400, "invalid_request", "new_public_key must be an Ed25519 public key as a canonical SPKI PEM.");
    }

    let proven: ReturnType<KeyProof["verify"]>;
    try {
      proven = o.proof.verify({ assertion: body.assertion as string, audience: `${base}/agent-keys/${fp}/${action}`, nowSec: Math.floor(now() / 1000) });
    } catch (e) {
      // The proof's reasons never echo the assertion.
      if (e instanceof AgentKeyError) return refuse("bad_proof", 401, "invalid_client", e.message);
      throw e;
    }
    if (fingerprint(proven.publicKeyPem) !== fp) {
      return refuse("other_key", 401, "invalid_client", action === "replace"
        ? "The assertion must be signed by the key being replaced."
        : "The assertion must be signed by the key being cancelled.");
    }
    // A replace assertion names the new key it was signed for, so one that is captured can't be sent with another key. A
    // refusal here doesn't spend it: the agent's own request with it still goes through.
    if (newPem !== undefined) {
      const named = proven.claims.new_key;
      if (typeof named !== "string" || !FINGERPRINT.test(named)) {
        return refuse("no_new_key", 401, "invalid_client", "The assertion must name the new key: put its fingerprint (64 lowercase hex) in the new_key claim.");
      }
      if (named !== fingerprint(newPem)) {
        return refuse("other_new_key", 401, "invalid_client", "The assertion's new_key names a different key than new_public_key.");
      }
    }
    const replayKey = createHash("sha256").update(`${fp}:${proven.jti}`, "utf8").digest("base64url");
    if (usedAssertions.has(replayKey)) {
      return refuse("replayed", 401, "invalid_client", "This assertion was already used. Sign a new one with a fresh jti.");
    }

    // From here to the change, everything is synchronous, so single use and the book's checks hold under concurrency.
    let entry: KeyEntry | null;
    let newFp: string | undefined;
    try {
      entry = o.book.get(fp);
      newFp = newPem !== undefined ? fingerprint(newPem) : undefined;
      if (!entry) return refuse("unknown_key", 404, "not_found", "No agent key has this fingerprint.");
      const agentId = entry.root.slice(0, 16);
      // The same replacement asked for again (a lost answer, or an interrupted one) finishes it and files it again.
      const resuming = action === "replace" && entry.status === "replaced" && entry.replacedBy === newFp;
      if (entry.status !== "active" && !resuming) {
        return refuse(`key_${entry.status}`, 409, "key_not_active", entry.status === "revoked" ? "This agent key was cancelled." : "This agent key was already replaced.", agentId);
      }
      if (newFp !== undefined && !resuming && o.book.get(newFp)) {
        return refuse("key_exists", 409, "key_exists", "That public key already belongs to an agent. Make a new key.", agentId);
      }
    } catch {
      log({ event: "agent_keys_unavailable" });
      return unavailable(res);
    }
    try {
      usedAssertions.add(replayKey, proven.exp);
    } catch {
      log({ event: "agent_keys_replay_write_failed" });
      return unavailable(res);
    }
    let changed: KeyEntry;
    try {
      changed = newPem !== undefined ? o.book.replace(fp, newPem) : o.book.revoke(fp);
    } catch (e) {
      if (e instanceof AgentKeyError && e.code === "key_exists") return refuse("key_exists", 409, "key_exists", "That public key already belongs to an agent. Make a new key.");
      if (e instanceof AgentKeyError && e.code.startsWith("already_")) return refuse(e.code, 409, "key_not_active", "This agent key is no longer active.");
      log({ event: "agent_keys_unavailable" });
      return unavailable(res);
    }
    log({ event: `agent_key_${change}`, agent_id: entry.root.slice(0, 16) });

    await fileChange(fp, change, newFp);
    let after: KeyEntry = changed;
    let event: EventView | null = null;
    try {
      const old = o.book.get(fp);
      const e = old ? latest(old, change) : undefined;
      event = e ? eventView(e) : null;
      if (action === "revoke" && old) after = old;
      else after = o.book.get(changed.fingerprint) ?? changed;
    } catch {
      // The change stands; the answer shows it as it was made.
    }
    send(res, 200, action === "replace" ? { ...keyView(after), replaces: fp, event } : { ...keyView(after), event });
  }

  async function route(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
    const found = LOOKUP.exec(path);
    if (found) {
      if (req.method !== "GET" && req.method !== "HEAD") return fail(res, 405, "method_not_allowed", "Use GET.", { allow: "GET, HEAD" });
      return lookup(req, res, found[1]);
    }
    const act = ACTION.exec(path);
    if (act) {
      if (req.method !== "POST") return fail(res, 405, "method_not_allowed", "Use POST.", { allow: "POST" });
      return changeKey(req, res, act[1], act[2] as "replace" | "revoke");
    }
    fail(res, 404, "not_found", "Look a key up at /agent-keys/<fingerprint>.json.");
  }

  return async (req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path !== "/agent-keys" && !path.startsWith("/agent-keys/")) return false;
    try {
      await route(req, res, path);
    } catch {
      log({ event: "agent_keys_internal_error" });
      if (!res.headersSent) fail(res, 500, "server_error", "Something went wrong. Try again.");
      else res.end();
    }
    return true;
  };
}
