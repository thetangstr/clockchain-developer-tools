// The /shadow/* routes: the /shadow/mcp MCP endpoint (its own McpServer and instructions, seven tools, authenticated
// like /mcp) and the two public capability links, /shadow/s/<cap> (the static evidence summary) and
// /shadow/p/<cap>.json (the packet and its pin). http.ts supplies authentication, the body reader and the rate
// limiter, so this module never re-implements them.
import { createHash } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { VERSION } from "./recorder.js";
import { SUMMARY_CSP } from "./lib/summary.js";
import { ShadowError, type ShadowService } from "./service.js";
import { accountCreatedDay, AccountUnavailableError, cleanAccountName, displayAccountName, looksLikeAccountKey, shortAccountId, type Account, type AccountStore } from "../accounts.js";

export const SHADOW_INSTRUCTIONS = [
  "Shadow is a flight recorder for your work. It keeps a tamper-evident record of each step you take (tasks, prompts,",
  "messages, tool calls and results, files, notes), signs it, anchors fingerprints of it on Clockchain, and gives you",
  "links anyone can open to check the record. Only hashes go to Clockchain. The record is kept on this server for 30",
  "days and then deleted. Anyone who has a session's viewer or packet link can read the whole record until then, and",
  "links cannot be revoked, so share them only with people who may see everything recorded. Sessions belong to the",
  "signed-in account that started them.",
  "",
  "Order of calls:",
  "1. shadow_start_session {title, agents?} once, before you start. Keep the session_id.",
  "2. shadow_record {session_id, agent, kind, content} after every step, in the order the steps happened.",
  "   kind: task (what you were asked to do; starts a run), prompt, message, tool_call ({tool, args}),",
  "   tool_result ({tool, result, is_error}), file ({path, content}), note.",
  "3. shadow_checkpoint {session_id} after important steps (optional): anchors the record so far on Clockchain.",
  "4. shadow_close_session {session_id, status} when the work is done. If you recorded a task, pass status",
  "   (succeeded, failed, cancelled, timed_out or unknown) to report how it ended.",
  "5. shadow_get_session and shadow_verify show the result. Share the viewer or packet link, and give the pin",
  "   to the person checking through a different channel.",
  "",
  "Record what you showed or did, as it happened. Never record hidden reasoning. Shadow refuses any step that contains",
  "a <think>, <thinking> or <reasoning> tag, a thinking or reasoning block, or a field whose name starts with",
  "reasoning, thinking or thought, in any kind of step, tool arguments and files included. Each step's content is at",
  "most 32 KB. Send one JSON-RPC message per request (batches are refused).",
].join("\n");

/** Added on the chat sign-in endpoint (SHADOW_LAZY_AUTH), which also carries the three account tools. */
export const ACCOUNT_INSTRUCTIONS = [
  "",
  "Clockchain account: Shadow records belong to a free Clockchain account (testnet, no email needed).",
  "- When the person asks to create or set up a Clockchain account (for example \"create a Clockchain account for",
  "  Acme\"), call clockchain_create_account {name: \"Acme\"}. If this connection is not signed in yet, the person is",
  "  asked to connect: they click Create account in the Clockchain window, save their account key there, and the",
  "  call is retried on its own. Any other tool also asks them to connect first.",
  "- clockchain_whoami {} says which account this connection uses; clockchain_signup_help {} explains sign-up.",
  "- The account key is shown only in the Clockchain window. Never ask for it, repeat it or put it in a tool call.",
  "  If someone pastes one into the chat, tell them to keep it private and not to share it again.",
].join("\n");

/** Retention and sharing, said wherever a tool hands out or describes links. */
const RETENTION = "Records are kept 30 days, then deleted; anyone with a link can read the record until then, and links cannot be revoked.";

export type ShadowAuth = { ok: true; ownerId: string; rateKey: string } | { ok: false; accountRequired?: boolean };

/** Bounds on the public link responses (security review finding 1). */
export type LinkLimits = { concurrent: number; perClient: number; idleMs: number; maxMs: number };

export interface ShadowHttpDeps {
  service: ShadowService;
  /** Resolves the authenticated owner exactly as /mcp authenticates (never from the unauthenticated `sub`). */
  authenticate(req: IncomingMessage): ShadowAuth;
  /** Writes /mcp's JSON 401 (given the request, it can add /shadow/mcp's OAuth challenge header). */
  unauthorized(res: ServerResponse, req?: IncomingMessage): void;
  /** Writes the 403 for an authenticated caller that is not a signed-in account. */
  accountRequired(res: ServerResponse, req: IncomingMessage): void;
  readJsonBody(req: IncomingMessage, maxBytes: number): Promise<unknown>;
  /** /mcp's per-caller limit: false when it already answered 429. */
  allowCall(rateKey: string, body: unknown, res: ServerResponse): boolean;
  /** The client a link request counts against: its IP behind the trusted proxy, IPv6 by /64. */
  linkClient(req: IncomingMessage): string;
  /** Per-client limit on the public links (per minute). */
  allowLink(req: IncomingMessage): boolean;
  onLinkRateLimited?(): void;
  links?: Partial<LinkLimits>;
  /**
   * The chat sign-in endpoint (SHADOW_LAZY_AUTH=1; absent = off, and its path is a 404 like any unknown /shadow path).
   * It serves the same Shadow tools plus the account tools. Without any credential, initialize, tools/list and ping go
   * through so a client can connect before sign-in; everything else (every tools/call) gets the same 401 and
   * challenge as /shadow/mcp, which starts the client's sign-in and its retry of the call.
   */
  chat?: {
    path: string;
    /** The OAuth account store (shared with the sign-in page). */
    accounts?: AccountStore;
    /** True when the request carries no credential header at all (a refused credential stays a 401). */
    anonymous(req: IncomingMessage): boolean;
    /** Per-client limit on anonymous requests: false = answer 429. */
    allowAnonymous(req: IncomingMessage): boolean;
  };
}

/** What a client may do on the chat endpoint before signing in. */
const ANONYMOUS_METHODS = new Set(["initialize", "notifications/initialized", "tools/list", "ping"]);

/** The page a 403 points at: how to connect to hosted Shadow with sign-in. Plain text, for people and agents. */
export function connectInstructions(base: string): string {
  return [
    "Hosted Shadow: connect with sign-in",
    "",
    `Endpoint: ${base}/shadow/mcp (Streamable HTTP)`,
    "",
    "Hosted Shadow keeps records for signed-in Clockchain accounts only. Add the endpoint above to your MCP client as",
    "a connector or remote MCP server with OAuth sign-in, then approve the Clockchain sign-in page it opens. ChatGPT",
    "connectors and Claude (claude.ai connectors, or `claude mcp add --transport http shadow <endpoint>` in Claude Code,",
    "then /mcp to sign in) discover sign-in on their own from the server's 401.",
    "",
    "A token from POST /token or a static MCP token is not accepted on /shadow/mcp; it gets 403 account_required.",
    "",
    "Records are kept 30 days, then deleted. Anyone with a session's viewer or packet link can read the whole record",
    "until then, and links cannot be revoked.",
    "",
  ].join("\n");
}

const first = (h: string | string[] | undefined): string => (Array.isArray(h) ? h[0] : h) ?? "";
const ACCT = /^acct_[A-Za-z0-9_-]{22}$/;
let warnedAcct = false;

/**
 * The owner of a session, from a signed cc_ token's verified claims: the OAuth account (`acct`) when present, else
 * the token's own id. The `sub` label is supplied unauthenticated at POST /token and is never used. verifyToken already
 * refuses a token whose `acct` is malformed; the check here is defence in depth.
 */
export function shadowOwnerFromClaims(claims: { jti?: unknown; acct?: unknown }, rawToken: string): string {
  const acct = claims.acct;
  if (typeof acct === "string" && ACCT.test(acct)) return acct;
  if (acct !== undefined && !warnedAcct) {
    warnedAcct = true;
    console.warn(JSON.stringify({ event: "shadow_acct_claim_malformed", note: "a signed token carries an acct claim that is not acct_ + 22 base64url characters; owning by jti" }));
  }
  if (typeof claims.jti === "string" && claims.jti.length > 0) return `jti:${claims.jti}`;
  return `tok:${createHash("sha256").update(rawToken).digest("hex")}`;
}

/** The public origin (and any X-Forwarded-Prefix mount) the caller reached, for the links Shadow hands out. */
export function publicBaseUrl(headers: IncomingHttpHeaders): string {
  const host = (first(headers["x-forwarded-host"]) || first(headers.host)).split(",")[0].trim();
  if (!/^[A-Za-z0-9.-]+(:\d{1,5})?$/.test(host) && !/^\[[0-9a-fA-F:]+\](:\d{1,5})?$/.test(host)) return "https://mcp.clockchain.network";
  let prefix = first(headers["x-forwarded-prefix"]).trim().replace(/\/+$/, "");
  if (prefix && !/^(\/[A-Za-z0-9._-]+)+$/.test(prefix)) prefix = "";
  const local = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
  const proto = first(headers["x-forwarded-proto"]).split(",")[0].trim() === "http" || (local && !headers["x-forwarded-proto"]) ? "http" : "https";
  return `${proto}://${host}${prefix}`;
}

function ok(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
}

function toolError(e: unknown) {
  const err = e instanceof ShadowError ? e : null;
  if (!err) console.error(JSON.stringify({ event: "shadow_tool_error", error: (e as Error)?.name ?? "error" }));
  return {
    isError: true as const,
    content: [{
      type: "text" as const,
      text: JSON.stringify(err
        ? { error: err.code, message: err.message }
        : { error: "SHADOW_INTERNAL", message: "Shadow could not complete this call. Try again; if it keeps failing, close this session and start a new one." }),
    }],
  };
}

const sessionId = z.string().describe("The session_id from shadow_start_session.");
const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } as const;
const READ = { readOnlyHint: true, openWorldHint: false } as const;

/**
 * One McpServer per request, bound to the authenticated owner (stateless, like /mcp). `ownerId` null is the chat
 * endpoint's anonymous server, which only answers initialize and tools/list: the HTTP gate refuses any tools/call
 * without a token (401) before this server runs, and its tools fail closed anyway. `accounts` adds the account tools.
 */
export function buildShadowServer(service: ShadowService, ownerId: string | null, base: string, accounts?: AccountStore): McpServer {
  const server = new McpServer(
    { name: "clockchain-shadow", version: VERSION },
    { instructions: accounts ? SHADOW_INSTRUCTIONS + "\n" + ACCOUNT_INSTRUCTIONS : SHADOW_INSTRUCTIONS },
  );
  const owner = ownerId ?? "";
  const run = <A>(fn: (a: A) => Promise<unknown>) => async (a: A) => {
    if (ownerId === null) return toolError(signInRequired());
    try {
      return ok(await fn(a));
    } catch (e) {
      return toolError(e);
    }
  };

  server.registerTool("shadow_start_session", {
    title: "Start a Shadow session",
    description: `Start recording. Call once before your first step. Returns the session_id for the other Shadow tools, the session's viewer and packet links, and anchors a start marker on Clockchain. ${RETENTION}`,
    inputSchema: {
      title: z.string().describe("What this session is about, up to 200 characters."),
      agents: z.array(z.object({
        id: z.string().describe('A short id, e.g. "researcher". Letters, digits and . _ : @ -.'),
        role: z.string().optional().describe("What this agent does (kept on this server, never sent to Clockchain)."),
      })).optional().describe('Who will act in this session. Default: one agent with id "agent".'),
    },
    annotations: WRITE,
  }, run((a) => service.startSession(owner, a, base)));

  server.registerTool("shadow_record", {
    title: "Record a step",
    description:
      "Record one step, right after it happens. kind: task (starts a run), prompt, message, tool_call ({tool, args}), " +
      "tool_result ({tool, result, is_error}), file ({path, content}), note. Never include hidden reasoning: a step with " +
      "a <think>/<thinking>/<reasoning> tag or a reasoning*, thinking* or thought* field is refused, whatever its kind. " +
      "Returns seq and hash.",
    inputSchema: {
      session_id: sessionId,
      agent: z.string().describe("Which declared agent took the step."),
      kind: z.enum(["task", "prompt", "message", "tool_call", "tool_result", "file", "note"]).describe("The kind of step."),
      content: z.union([z.string(), z.record(z.unknown()), z.array(z.unknown())]).describe("The step itself: text, or JSON. At most 32 KB."),
      run_id: z.string().optional().describe("Optional. A task step starts a run (returned as run_id); other steps join the agent's latest open run unless you pass one."),
    },
    annotations: WRITE,
  }, run((a) => service.record(owner, a)));

  server.registerTool("shadow_checkpoint", {
    title: "Anchor a checkpoint",
    description: "Sign a checkpoint over every step so far and anchor it on Clockchain. Returns the step count, block, block time and ledger id, or pending if Clockchain is slow (the steps are safe either way).",
    inputSchema: { session_id: sessionId },
    annotations: WRITE,
  }, run((a) => service.checkpoint(owner, a)));

  server.registerTool("shadow_close_session", {
    title: "Close the session",
    description: `Finish the session: a final checkpoint, anchored on Clockchain, then close. Returns the pin and the links to share. No steps can be added afterwards. ${RETENTION}`,
    inputSchema: {
      session_id: sessionId,
      status: z.enum(["succeeded", "failed", "cancelled", "timed_out", "unknown"]).optional()
        .describe("How the recorded task(s) ended, as you report it. Without it, runs still open are recorded as capture gaps."),
    },
    annotations: WRITE,
  }, run((a) => service.close(owner, a, base)));

  server.registerTool("shadow_get_session", {
    title: "Get a session",
    description: `A session's status, step count, Clockchain anchors, time windows, and its viewer and packet links (and its pin once closed). ${RETENTION}`,
    inputSchema: { session_id: sessionId },
    annotations: READ,
  }, run((a) => service.getSession(owner, a, base)));

  server.registerTool("shadow_list_sessions", {
    title: "List sessions",
    description: "Your Shadow sessions, newest first.",
    inputSchema: {},
    annotations: READ,
  }, run(() => service.listSessions(owner)));

  server.registerTool("shadow_verify", {
    title: "Verify a session",
    description: "Run the Shadow verifier on the session's evidence packet, online against Clockchain where possible. Returns pass, indeterminate or fail, with each check.",
    inputSchema: { session_id: sessionId },
    annotations: READ,
  }, run((a) => service.verify(owner, a, base)));

  if (accounts) registerAccountTools(server, accounts, ownerId);
  return server;
}

const signInRequired = () => new ShadowError("SIGN_IN_REQUIRED", "Sign in to Clockchain first: connect this server with sign-in, then try again.");
const accountError = (code: string, message: string) => toolError(new ShadowError(code, message));
/** What the account tools say about an account: its name ("an unnamed account" until named), short id, creation day. */
const accountView = (account: Account) => ({
  name: displayAccountName(account), short_id: shortAccountId(account.acct), named: account.unnamed !== true, created: accountCreatedDay(account),
});
/** "an unnamed account (abc123, created 3 Nov)" or "Acme (abc123)", for status lines. */
const accountLine = (v: ReturnType<typeof accountView>) => (v.named ? `${v.name} (${v.short_id})` : `${v.name} (${v.short_id}, created ${v.created})`);

/**
 * clockchain_create_account, clockchain_whoami and clockchain_signup_help (chat sign-in endpoint only). They see the
 * account through the token's verified acct and return only its name, short id and a status line: never the account
 * key, a token, a cookie or a link.
 */
function registerAccountTools(server: McpServer, accounts: AccountStore, ownerId: string | null): void {
  const withAccount = <A>(fn: (acct: string, a: A) => unknown) => async (a: A) => {
    if (ownerId === null) return toolError(signInRequired());
    if (!ACCT.test(ownerId)) return accountError("ACCOUNT_REQUIRED", "This connection is not signed in with a Clockchain account. Connect with sign-in, then try again.");
    try {
      return ok(fn(ownerId, a));
    } catch (e) {
      if (e instanceof AccountUnavailableError) return accountError("ACCOUNT_UNAVAILABLE", "Clockchain can't read this account right now. Try again in a few minutes.");
      return toolError(e);
    }
  };
  const SIGNED_IN = { readOnlyHint: true, openWorldHint: false } as const;

  server.registerTool("clockchain_create_account", {
    title: "Create a Clockchain account",
    description:
      "Create the person's free Clockchain account (Shadow needs one) and name it, for example after their company. " +
      "If this connection is not signed in, the person is first asked to connect and creates the account in the " +
      "Clockchain window; the call is then retried. An account that already has a name keeps it. Returns the name " +
      "and a short account id, never the account key.",
    inputSchema: { name: z.string().describe("The company or account name, 1 to 40 characters.") },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, withAccount((acct, a: { name: string }) => {
    if (looksLikeAccountKey(a.name)) {
      throw new ShadowError("ACCOUNT_NAME_IS_A_KEY", "That looks like an account key, not a name. It was not stored. Account keys must never go in the chat or a tool call; ask the person for a company or account name instead.");
    }
    const name = cleanAccountName(a.name);
    if (name === undefined) throw new ShadowError("ACCOUNT_NAME_INVALID", "Choose a name of 1 to 40 characters with at least one letter or digit.");
    const result = accounts.nameOnce(acct, name);
    if (!result) throw new ShadowError("ACCOUNT_REQUIRED", "This connection's Clockchain account no longer exists. Connect with sign-in again.");
    const view = accountView(result.account);
    if (result.outcome === "too_late") {
      throw new ShadowError("ACCOUNT_NAMING_CLOSED",
        `This connection uses ${accountLine(view)}, which was created more than 15 minutes ago without a name, so it was not named. ` +
        "An account gets its name when it is created: from the chat within 15 minutes of signing up, or typed on the Clockchain sign-in page.");
    }
    if (result.outcome === "named") console.log(JSON.stringify({ event: "shadow_account_named", acct })); // the id only, never the name
    return result.outcome === "named"
      ? { status: "created", account: view, message: `The Clockchain account ${accountLine(view)} is ready and this connection uses it. Its account key was shown once in the Clockchain sign-in window, not here.` }
      : { status: "already_named", account: view, message: `This connection already uses the Clockchain account ${accountLine(view)}. It keeps that name; nothing was renamed.` };
  }));

  server.registerTool("clockchain_whoami", {
    title: "Which Clockchain account",
    description: "The Clockchain account this connection uses: its name and short id. Asks the person to connect first if they are not signed in.",
    inputSchema: {},
    annotations: SIGNED_IN,
  }, withAccount((acct) => {
    const account = accounts.get(acct);
    if (!account) throw new ShadowError("ACCOUNT_REQUIRED", "This connection's Clockchain account no longer exists. Connect with sign-in again.");
    const view = accountView(account);
    return {
      status: "signed_in",
      account: view,
      message: view.named
        ? `This connection uses the Clockchain account ${accountLine(view)}.`
        : `This connection uses ${accountLine(view)}. If it was created in the last 15 minutes, ask the person for a name and call clockchain_create_account {name}; after that it can no longer be named from the chat.`,
    };
  }));

  server.registerTool("clockchain_signup_help", {
    title: "How Clockchain sign-up works",
    description: "Explains, in plain words, how to get a Clockchain account from this chat and where the account key is shown.",
    inputSchema: {},
    annotations: SIGNED_IN,
  }, withAccount(() => ({
    status: "help",
    message: [
      "Clockchain accounts are free (testnet) and need no email.",
      "To get one from this chat: ask for it (for example \"create a Clockchain account for Acme\"). A Connect button appears; in the Clockchain window that opens, click Create account. The window shows the account key once, with a Download key file link: save it there. Then the chat carries on and names the account.",
      "The account key is shown only in that window. It never appears in this chat, and nobody should ask for it here. It signs you in on another device or app: choose \"I have an account key\" in the Clockchain window.",
      "Already have an account? When the Clockchain window opens, choose \"I have an account key\", or click Allow if it shows your account.",
    ].join("\n"),
  })));
}

const LINK_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-robots-tag": "noindex, nofollow",
};
// The summary's own policy (only its one stylesheet, by hash), plus what a meta tag cannot say.
const HTML_CSP = `${SUMMARY_CSP}; frame-ancestors 'none'`;

function notFound(res: ServerResponse): void {
  res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify({ error: "not_found" }));
}

/** Handles every /shadow and /shadow/* request (http.ts only routes here when SHADOW_ENABLED=1). */
export function createShadowHttpHandler(deps: ShadowHttpDeps): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const limits: LinkLimits = { concurrent: 4, perClient: 1, idleMs: 20_000, maxMs: 120_000, ...(deps.links ?? {}) };
  // Link responses in flight, globally and per client: each holds a socket and a reference to a (shared) body.
  let active = 0;
  const perClient = new Map<string, number>();

  function busy(res: ServerResponse): void {
    res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store", "retry-after": "5", connection: "close" });
    res.end(JSON.stringify({ error: "busy" }));
  }

  async function link(req: IncomingMessage, res: ServerResponse, kind: "packet" | "summary", cap: string): Promise<void> {
    if (!deps.allowLink(req)) {
      deps.onLinkRateLimited?.();
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store", "retry-after": "60" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    const client = deps.linkClient(req);
    if (active >= limits.concurrent || (perClient.get(client) ?? 0) >= limits.perClient) {
      deps.onLinkRateLimited?.();
      return busy(res);
    }
    active++;
    perClient.set(client, (perClient.get(client) ?? 0) + 1);
    // A client that stops reading is dropped: idle (no bytes moving) for idleMs, or still not done after maxMs. The
    // connection closes after the response, so these timers never carry over to another request on the socket.
    const socket = req.socket;
    socket.setTimeout(limits.idleMs, () => socket.destroy());
    const deadline = setTimeout(() => socket.destroy(), limits.maxMs);
    deadline.unref();
    let released = false;
    res.on("close", () => {
      if (released) return;
      released = true;
      clearTimeout(deadline);
      active--;
      const n = (perClient.get(client) ?? 1) - 1;
      if (n <= 0) perClient.delete(client);
      else perClient.set(client, n);
    });
    let body: Buffer | undefined;
    try {
      body = await deps.service.linkBody(cap, kind);
    } catch (e) {
      if (res.writableEnded || res.destroyed) return;
      const isBusy = e instanceof ShadowError && e.code === "SHADOW_BUSY";
      res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store", connection: "close", ...(isBusy ? { "retry-after": "5" } : {}) });
      res.end(JSON.stringify({ error: isBusy ? "busy" : "shadow_unavailable" }));
      return;
    }
    if (res.destroyed) return;
    if (body === undefined) return notFound(res);
    res.writeHead(200, {
      ...LINK_HEADERS,
      connection: "close",
      "content-length": String(body.length),
      ...(kind === "summary"
        ? { "content-type": "text/html; charset=utf-8", "content-security-policy": HTML_CSP }
        : { "content-type": "application/json; charset=utf-8", "content-security-policy": "default-src 'none'; frame-ancestors 'none'" }),
    });
    // The shared Buffer itself: no per-reader copy.
    res.end(body);
  }

  return async (req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === "/shadow/mcp") return mcp(req, res);
    if (deps.chat && path === deps.chat.path) return mcp(req, res, deps.chat);
    if (path === "/shadow/connect" && req.method === "GET") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=300", "x-content-type-options": "nosniff" });
      res.end(connectInstructions(publicBaseUrl(req.headers)));
      return;
    }
    const view = /^\/shadow\/s\/([A-Za-z0-9_-]{22})$/.exec(path);
    const packet = /^\/shadow\/p\/([A-Za-z0-9_-]{22})\.json$/.exec(path);
    if ((!view && !packet) || req.method !== "GET") return notFound(res);
    return view ? link(req, res, "summary", view[1]) : link(req, res, "packet", packet![1]);
  };

  async function mcp(req: IncomingMessage, res: ServerResponse, chat?: NonNullable<ShadowHttpDeps["chat"]>): Promise<void> {
    const auth = deps.authenticate(req);
    if (!auth.ok) {
      if (chat && !auth.accountRequired && chat.anonymous(req)) return anonymous(req, res, chat);
      return auth.accountRequired ? deps.accountRequired(res, req) : deps.unauthorized(res, req);
    }
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await deps.readJsonBody(req, 512 * 1024);
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_json_body" }));
        return;
      }
      // JSON-RPC batches were removed from MCP in 2025-06-18; here they would multiply one rate-limited request
      // into many tool calls (security review finding 4), so one message per request.
      if (Array.isArray(body)) {
        res.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({
          jsonrpc: "2.0", id: null,
          error: { code: -32600, message: "JSON-RPC batches are not supported on /shadow/mcp. Send one message per request." },
        }));
        return;
      }
    }
    if (!deps.allowCall(auth.rateKey, body, res)) return;
    await serve(req, res, body, buildShadowServer(deps.service, auth.ownerId, publicBaseUrl(req.headers), chat?.accounts));
  }

  /** The chat endpoint without a credential: one discovery message per request, or the 401 that starts sign-in. */
  async function anonymous(req: IncomingMessage, res: ServerResponse, chat: NonNullable<ShadowHttpDeps["chat"]>): Promise<void> {
    if (req.method !== "POST") return deps.unauthorized(res, req);
    let body: unknown;
    try {
      body = await deps.readJsonBody(req, 512 * 1024);
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_json_body" }));
      return;
    }
    const method = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as { method?: unknown }).method : undefined;
    // Before the SDK runs: a tool handler can only answer 200, and only a 401 starts the client's sign-in.
    if (typeof method !== "string" || !ANONYMOUS_METHODS.has(method)) return deps.unauthorized(res, req);
    if (!chat.allowAnonymous(req)) {
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store", "retry-after": "60" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    await serve(req, res, body, buildShadowServer(deps.service, null, publicBaseUrl(req.headers), chat.accounts));
  }

  async function serve(req: IncomingMessage, res: ServerResponse, body: unknown, server: McpServer): Promise<void> {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  }
}
