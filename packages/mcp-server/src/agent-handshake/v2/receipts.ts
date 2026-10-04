import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  timingSafeEqual,
} from "node:crypto";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { canonicalDigest } from "../../agent-contract/canonical.js";
import type { ContractSigner } from "../../agent-contract/envelope.js";
import {
  RECEIPT_CHAIN_GENESIS,
  makeReceipt,
  serverReceiptSchema,
  verifyChain,
  type ServerReceipt,
} from "../../agent-contract/receipts.js";
import { buildServerKeysDoc, type PublishedServerKey } from "../../agent-contract/server-card.js";
import { authorizeV2RoleAccess, readV2RoleAccessPayload, type V2AccessKey, type V2Role } from "./access.js";

/**
 * Agent Handshake v2 per-call receipts (travel R14 / R8 / R13a evidence).
 *
 * ADDITIVE AND OPT-IN. With `HANDSHAKE_V2_RECEIPTS` unset the loader returns
 * `{ kind: "disabled" }`, http.ts passes no recorder, and the v2 handler runs
 * the exact code it ran before. When on, recording is a pure side effect:
 * tool arguments, results and errors are returned to the caller untouched
 * (no nonce echoed into any tool result, no tool schema or description
 * change), and a failure inside the recorder never reaches the caller.
 *
 * Mirrors agent-contract/receipts.ts: one signed, hash-chained
 * `agent-contract.server-receipt/v1` chain per handshake session
 * (`runId` = handshakeSessionId, `surface: "handshake"`), a fresh
 * `serverNonce` per call, `prevHash` links and an Ed25519 `serverSignature`
 * under a DEDICATED handshake receipt key (never the contract server key).
 *
 * The receipt schema's `principal.role` is the contract enum, so the
 * handshake roles map `initiator -> buyer`, `responder -> provider`; the
 * feed discloses the map (`principalRoleMap`). `principal.keyId` is the
 * role label (`hs-initiator` / `hs-responder`), never a credential.
 *
 * Privacy: a receipt carries digests only. The role-access bearer and the
 * invitation are stripped before hashing and are never stored; the response
 * digest covers the response minus the access fields the public broker
 * replaces anyway.
 */

export const HANDSHAKE_RECEIPT_FEED_SCHEMA = "agent-handshake.v2.receipt-feed/v1";
export const HANDSHAKE_RECEIPTS_PATH = "/handshake/receipts";
export const HANDSHAKE_RECEIPT_KEYS_PATH = "/handshake/receipt-keys";
export const HANDSHAKE_PRINCIPAL_ROLE_MAP = Object.freeze({ initiator: "buyer", responder: "provider" } as const);

export const MAX_RECEIPTS_PER_SESSION = 1_000;
export const MAX_SESSIONS = 5_000;

const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STRIPPED_ARG_KEYS = new Set(["access", "invitation"]);
const STRIPPED_RESULT_KEYS = new Set(["initiatorAccess", "responderAccess", "roleAccess"]);
const ROLE_SCOPED = new Set([
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

export type HandshakeReceiptsConfig =
  | { kind: "disabled" }
  | { kind: "misconfigured"; reason: string }
  | {
      kind: "ready";
      signer: ContractSigner;
      signerEphemeral: boolean;
      serverKeys: readonly PublishedServerKey[];
      /** Feed bearer; undefined → the feed is closed (404) while recording continues. */
      observerToken?: string;
      /** Only calls whose `x-forwarded-prefix` equals this are recorded; "*" = every path. */
      prefix: string;
      /** Append-only JSONL persistence; undefined → memory only. */
      file?: string;
    };

/**
 * Env, exactly like the contract server key:
 *   HANDSHAKE_V2_RECEIPTS=1                          enable
 *   HANDSHAKE_V2_RECEIPT_ED25519_SEED                canonical base64 32-byte seed (required)
 *   HANDSHAKE_V2_RECEIPT_KEY_ID                      default "handshake-v2-receipts"
 *   HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM              pinned ISO-8601 (required, never boot time)
 *   HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL             optional ISO-8601
 *   HANDSHAKE_V2_RECEIPTS_ALLOW_EPHEMERAL_KEY=1      disposable dev signer (keyId forced ephemeral-dev-*)
 *   HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN              feed bearer; falls back to CONTRACT_OBSERVER_TOKEN
 *   HANDSHAKE_V2_RECEIPTS_PREFIX                     default "/next"; "*" records on every path
 *   HANDSHAKE_V2_RECEIPTS_FILE                       optional JSONL path
 */
export function loadHandshakeReceiptsConfig(env: Record<string, string | undefined>): HandshakeReceiptsConfig {
  if (env.HANDSHAKE_V2_RECEIPTS !== "1") return { kind: "disabled" };
  const bad = (reason: string): HandshakeReceiptsConfig => ({ kind: "misconfigured", reason });

  const seedB64 = (env.HANDSHAKE_V2_RECEIPT_ED25519_SEED ?? "").trim();
  let signer: ContractSigner;
  let signerEphemeral = false;
  if (seedB64) {
    const seed = Buffer.from(seedB64, "base64");
    if (seed.length !== 32 || seed.toString("base64") !== seedB64) {
      return bad("HANDSHAKE_V2_RECEIPT_ED25519_SEED must be a canonical base64 32-byte seed");
    }
    const keyId = (env.HANDSHAKE_V2_RECEIPT_KEY_ID ?? "").trim() || "handshake-v2-receipts";
    if (keyId.length > 64 || keyId.startsWith("ephemeral-dev-")) return bad("HANDSHAKE_V2_RECEIPT_KEY_ID is invalid");
    signer = {
      keyId,
      privateKey: createPrivateKey({
        key: Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), seed]),
        format: "der",
        type: "pkcs8",
      }),
    };
  } else if (env.HANDSHAKE_V2_RECEIPTS_ALLOW_EPHEMERAL_KEY === "1") {
    const keys = generateKeyPairSync("ed25519");
    signerEphemeral = true;
    const pubHex = Buffer.from(keys.publicKey.export({ format: "der", type: "spki" }).subarray(12)).toString("hex");
    signer = { keyId: `ephemeral-dev-${pubHex.slice(0, 16)}`, privateKey: keys.privateKey };
  } else {
    return bad("HANDSHAKE_V2_RECEIPT_ED25519_SEED is required (or HANDSHAKE_V2_RECEIPTS_ALLOW_EPHEMERAL_KEY=1 for a dev signer)");
  }

  const validFrom = (env.HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM ?? "").trim();
  const validUntil = (env.HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL ?? "").trim();
  if (validFrom === "" || Number.isNaN(Date.parse(validFrom))) {
    return bad("HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM is required (pinned ISO-8601 — never boot time)");
  }
  if (validUntil !== "") {
    if (Number.isNaN(Date.parse(validUntil))) return bad("HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL is not an ISO-8601 timestamp");
    if (Date.parse(validUntil) <= Date.now()) return bad("HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL is already in the past");
  }
  const publicKeyHex = `0x${Buffer.from(
    createPublicKey(signer.privateKey as Parameters<typeof createPublicKey>[0]).export({ format: "der", type: "spki" }).subarray(-32),
  ).toString("hex")}`;
  const serverKeys: readonly PublishedServerKey[] = [{
    keyId: signer.keyId,
    alg: "Ed25519",
    publicKeyHex,
    validFrom,
    validUntil: validUntil === "" ? null : validUntil,
    ...(signerEphemeral ? { ephemeral: true as const } : {}),
  }];

  const observerToken = (env.HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN || env.CONTRACT_OBSERVER_TOKEN || "").trim();
  const prefix = (env.HANDSHAKE_V2_RECEIPTS_PREFIX ?? "").trim() || "/next";
  const file = (env.HANDSHAKE_V2_RECEIPTS_FILE ?? "").trim();
  return {
    kind: "ready",
    signer,
    signerEphemeral,
    serverKeys,
    ...(observerToken !== "" ? { observerToken } : {}),
    prefix,
    ...(file !== "" ? { file } : {}),
  };
}

/* ------------------------------------------------------------------ */
/* Store                                                                */
/* ------------------------------------------------------------------ */

export interface HandshakeReceiptStore {
  append(sessionId: string, fields: HandshakeCallFields): ServerReceipt | undefined;
  receipts(sessionId: string): readonly ServerReceipt[] | undefined;
  truncated(sessionId: string): boolean;
  head(sessionId: string): string | null;
}

export interface HandshakeCallFields {
  role: V2Role;
  tool: string;
  argsDigest: string;
  outcome: string;
  responseDigest: string;
  mcpSessionId?: string;
  clientInfo?: { name: string; version: string };
  sourceIp?: string;
  ts?: number;
}

export function createHandshakeReceiptStore(options: {
  signer: ContractSigner;
  file?: string;
  now?: () => number;
}): HandshakeReceiptStore {
  const chains = new Map<string, ServerReceipt[]>();
  const capped = new Set<string>();
  const { signer, file } = options;

  if (file !== undefined && existsSync(file)) {
    try {
      for (const line of readFileSync(file, "utf8").split("\n")) {
        if (line.trim() === "") continue;
        const parsed = serverReceiptSchema.safeParse(JSON.parse(line));
        if (!parsed.success || parsed.data.surface !== "handshake") continue;
        const chain = chains.get(parsed.data.runId) ?? [];
        chain.push(parsed.data);
        chains.set(parsed.data.runId, chain);
      }
    } catch {
      // A corrupt receipts file never blocks the handshake; chains reload empty.
      chains.clear();
    }
  }

  function persist(receipt: ServerReceipt): void {
    if (file === undefined) return;
    try {
      const dir = dirname(file);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
      const fresh = !existsSync(file);
      appendFileSync(file, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
      if (fresh) chmodSync(file, 0o600);
    } catch {
      // Persistence is best effort; the in-memory chain stays authoritative.
    }
  }

  return {
    append(sessionId, fields) {
      if (!UUID.test(sessionId)) return undefined;
      let chain = chains.get(sessionId);
      if (chain === undefined) {
        if (chains.size >= MAX_SESSIONS) {
          const oldest = chains.keys().next().value;
          if (oldest !== undefined) { chains.delete(oldest); capped.delete(oldest); }
        }
        chain = [];
        chains.set(sessionId, chain);
      }
      if (chain.length >= MAX_RECEIPTS_PER_SESSION) {
        capped.add(sessionId);
        return undefined;
      }
      const receipt = makeReceipt(chain.at(-1) ?? null, {
        runId: sessionId,
        surface: "handshake",
        tool: fields.tool,
        argsDigest: fields.argsDigest,
        argsDigestScheme: "canonical",
        principal: { role: HANDSHAKE_PRINCIPAL_ROLE_MAP[fields.role], keyId: `hs-${fields.role}` },
        outcome: fields.outcome,
        responseDigest: fields.responseDigest,
        responseDigestScheme: "canonical",
        ...(fields.mcpSessionId !== undefined ? { mcpSessionId: fields.mcpSessionId } : {}),
        ...(fields.clientInfo !== undefined ? { clientInfo: fields.clientInfo } : {}),
        ...(fields.sourceIp !== undefined ? { sourceIp: fields.sourceIp } : {}),
        ts: fields.ts ?? (options.now ?? Date.now)(),
      }, signer);
      chain.push(receipt);
      persist(receipt);
      return receipt;
    },
    receipts: (sessionId) => chains.get(sessionId),
    truncated: (sessionId) => capped.has(sessionId),
    head: (sessionId) => {
      const last = chains.get(sessionId)?.at(-1);
      return last === undefined ? null : canonicalDigest(last);
    },
  };
}

/* ------------------------------------------------------------------ */
/* Recording hook (wraps the RAW coordinator invoke, pre-broker)        */
/* ------------------------------------------------------------------ */

export type RawInvoke = (name: string, args: Record<string, unknown>) => Promise<unknown>;
/** Receives the raw call and the thunk that performs it; MUST return/throw exactly what the thunk does. */
export type RawInvokeHook = (name: string, args: Record<string, unknown>, call: RawInvoke) => Promise<unknown>;

function strip(value: Record<string, unknown>, keys: ReadonlySet<string>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([k]) => !keys.has(k)));
}

function digestOrNull(value: unknown): string | null {
  try { return canonicalDigest(value); } catch { return null; }
}

function errorOutcome(error: unknown): string {
  const name = error instanceof Error ? error.name : "Error";
  const safe = /^[A-Za-z][A-Za-z0-9_]{0,40}$/.test(name) ? name : "Error";
  return `refused:${safe}`;
}

export interface HandshakeReceiptRecorder {
  /** The feed + key routes (GET only); returns true when it handled the request. */
  routes: (req: IncomingMessage, res: ServerResponse) => boolean;
  /** Per-request hook, or undefined when this request's path is not opted in. */
  hookFor(request: { headers: IncomingHttpHeaders; ip: string; clientInfo?: { name: string; version: string } }): RawInvokeHook | undefined;
  store: HandshakeReceiptStore;
}

export function createHandshakeReceiptRecorder(options: {
  config: Extract<HandshakeReceiptsConfig, { kind: "ready" }>;
  accessKeys: readonly V2AccessKey[];
  /** Fetch the host-signed result envelope for a session (the relay's result). */
  getCertificate?: (sessionId: string) => Promise<unknown>;
  allowFeed?: (scope: "observer") => boolean;
  onRateLimited?: () => void;
  now?: () => number;
}): HandshakeReceiptRecorder {
  const { config } = options;
  const now = options.now ?? Date.now;
  const store = createHandshakeReceiptStore({
    signer: config.signer,
    ...(config.file !== undefined ? { file: config.file } : {}),
    now,
  });
  const keysDoc = buildServerKeysDoc(config.serverKeys);

  function record(name: string, args: Record<string, unknown>, outcomeOf: { result: unknown } | { error: unknown }, ip: string): void {
    try {
      let scope: { sessionId: string; role: V2Role } | undefined;
      const ok = "result" in outcomeOf;
      if (ROLE_SCOPED.has(name)) {
        if (typeof args.access !== "string") return;
        // Only a bearer that verifies under the configured access keys is attributable
        // (time-agnostic: the coordinator already enforced freshness), so forged or
        // foreign access can never create or grow a session chain.
        const claimed = readV2RoleAccessPayload(args.access);
        const at = Math.min(Math.max(now(), Number(claimed.nbfMs)), Number(claimed.expMs) - 1);
        const v = authorizeV2RoleAccess(args.access, { keys: options.accessKeys, nowMs: at, requiredTool: name });
        scope = { sessionId: v.payload.sessionId, role: v.payload.role };
      } else if (ok && (name === "agent_handshake_invite" || name === "agent_handshake_accept_invitation")) {
        const r = outcomeOf.result as Record<string, unknown> | null;
        if (r === null || typeof r !== "object" || typeof r.sessionId !== "string") return;
        scope = { sessionId: r.sessionId, role: name === "agent_handshake_invite" ? "initiator" : "responder" };
      }
      if (scope === undefined) return;
      const argsDigest = digestOrNull(strip(args, STRIPPED_ARG_KEYS));
      const responseDigest = ok
        ? digestOrNull(
            outcomeOf.result !== null && typeof outcomeOf.result === "object" && !Array.isArray(outcomeOf.result)
              ? strip(outcomeOf.result as Record<string, unknown>, STRIPPED_RESULT_KEYS)
              : outcomeOf.result ?? null,
          )
        : canonicalDigest({ refused: errorOutcome((outcomeOf as { error: unknown }).error) });
      if (argsDigest === null || responseDigest === null) return;
      store.append(scope.sessionId, {
        role: scope.role,
        tool: name,
        argsDigest: argsDigest.toLowerCase(),
        outcome: ok ? "ok" : errorOutcome((outcomeOf as { error: unknown }).error),
        responseDigest: responseDigest.toLowerCase(),
        sourceIp: ip.slice(0, 64),
        ts: now(),
      });
    } catch {
      // Recording must never affect the handshake call.
    }
  }

  const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store" } as const;
  const refuse = (res: ServerResponse, status: number, error: string): void => {
    res.writeHead(status, JSON_HEADERS);
    res.end(JSON.stringify({ error }));
  };
  const bearerOk = (req: IncomingMessage, token: string): boolean => {
    const header = req.headers.authorization;
    const m = /^Bearer\s+(.+)$/i.exec((Array.isArray(header) ? header[0] : header) ?? "");
    if (!m) return false;
    return timingSafeEqual(
      createHash("sha256").update(m[1].trim()).digest(),
      createHash("sha256").update(token).digest(),
    );
  };

  const routes: HandshakeReceiptRecorder["routes"] = (req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === HANDSHAKE_RECEIPT_KEYS_PATH) {
      if (req.method !== "GET") { refuse(res, 404, "not_found"); return true; }
      res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=300" });
      res.end(JSON.stringify(keysDoc));
      return true;
    }
    if (path !== HANDSHAKE_RECEIPTS_PATH) return false;
    const token = config.observerToken;
    if (token === undefined) { refuse(res, 404, "not_found"); return true; }
    if (req.method !== "GET") { refuse(res, 403, "forbidden"); return true; }
    if (!bearerOk(req, token)) { refuse(res, 401, "unauthorized"); return true; }
    if (options.allowFeed !== undefined && !options.allowFeed("observer")) {
      options.onRateLimited?.();
      refuse(res, 429, "rate_limited");
      return true;
    }
    const params = new URL(req.url ?? "/", "http://localhost").searchParams;
    const sessionId = params.get("sessionId") ?? params.get("runId") ?? "";
    const chain = UUID.test(sessionId) ? store.receipts(sessionId) : undefined;
    if (chain === undefined) { refuse(res, 404, "not_found"); return true; }
    void (async () => {
      let certificate: unknown;
      try {
        const envelope = options.getCertificate ? await options.getCertificate(sessionId) : undefined;
        const e = envelope as { result?: { sessionId?: unknown } } | null | undefined;
        if (e && typeof e === "object" && e.result?.sessionId === sessionId) certificate = envelope;
      } catch {
        certificate = undefined;
      }
      res.writeHead(200, JSON_HEADERS);
      res.end(JSON.stringify({
        schema: HANDSHAKE_RECEIPT_FEED_SCHEMA,
        sessionId,
        receipts: chain,
        head: store.head(sessionId),
        ...(store.truncated(sessionId) ? { truncated: true } : {}),
        principalRoleMap: HANDSHAKE_PRINCIPAL_ROLE_MAP,
        ...(certificate !== undefined ? { certificate } : {}),
      }));
    })();
    return true;
  };

  return {
    store,
    routes,
    hookFor({ headers, ip }) {
      const raw = headers["x-forwarded-prefix"];
      const prefix = (Array.isArray(raw) ? raw[0] : raw) ?? "";
      if (config.prefix !== "*" && prefix !== config.prefix) return undefined;
      return async (name, args, call) => {
        let result: unknown;
        try {
          result = await call(name, args);
        } catch (error) {
          record(name, args, { error }, ip);
          throw error;
        }
        record(name, args, { result }, ip);
        return result;
      };
    },
  };
}

export { RECEIPT_CHAIN_GENESIS, verifyChain };
