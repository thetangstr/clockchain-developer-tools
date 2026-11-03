import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import { AccountStore, cleanAccountName, DEFAULT_MAX_ACCOUNTS, type Account } from "./accounts.js";
import { clientBucket, limiter, standaloneClientIp } from "./standalone-handshake/public-server.js";
import { isAcctId, mintToken } from "./token.js";

/**
 * OAuth 2.1 sign-in for MCP clients (ChatGPT custom connectors, Claude Code).
 *
 * A thin, stateless authorization server in front of the existing self-serve
 * testnet tokens. Someone adds the connector, sees a Clockchain approval page,
 * approves, and the app receives an ordinary `cc_` demo token (minted by the
 * same `mintToken` as `POST /token`) plus a rotating refresh token.
 *
 *   discovery     RFC 9728 protected-resource metadata, RFC 8414 server metadata
 *   registration  RFC 7591, stateless: the client_id IS the signed registration
 *   authorize     code flow, PKCE S256 required. Every error is a page, never a
 *                 redirect: only the person's own Approve (code) or Cancel
 *                 (access_denied) sends them to the redirect URI, with state + iss.
 *   accounts      the approval page doubles as sign-up / sign-in (src/accounts.ts):
 *                 a person names an account once, no email, and every app they
 *                 approve gets that account's `acct`. An HttpOnly __Host- cookie
 *                 only selects the account; each app still needs its own click.
 *                 An account key (shown once) signs in on other devices.
 *   token         authorization_code + refresh_token (rotating, reuse-detected)
 *
 * Every artifact is `<prefix><b64url(json)>.<b64url(hmac)>`, keyed by a key
 * derived from MCP_TOKEN_SIGNING_SECRET under its own label, so no artifact can
 * be replayed as another kind or as an access token. Prefixes all start `cc_`,
 * so one presented to /mcp is refused (401) instead of falling through to the
 * bring-your-own-key path. The only state is in memory: the single-use sets for
 * codes and refresh tokens, and revoked refresh-token families.
 *
 * Logs carry only event names, client_name and acct ids: never codes, tokens,
 * refresh tokens, verifiers or client_id blobs.
 */

export const DEFAULT_PUBLIC_URL = "https://mcp.clockchain.network";

const CODE_TTL_S = 5 * 60;
const REQUEST_TTL_S = 10 * 60;
const REFRESH_TTL_S = 60 * 24 * 60 * 60;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_REDIRECT_URIS = 5;
const MAX_URI_LENGTH = 512;
const MAX_STATE_LENGTH = 2048;
const MAX_ARTIFACT_LENGTH = 8192;
const CLIENT_NAME_MAX = 60;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MCP_PATHS = ["/mcp", "/shadow/mcp"] as const;
const COOKIE_MAX_AGE_S = 365 * 24 * 60 * 60;

export type OAuthConfig =
  | { kind: "disabled" }
  | { kind: "misconfigured"; reason: string }
  | { kind: "ready"; publicUrl: string; approvalsPerHour: number; accountsDir: string; trustedProxy?: string };

/** An https origin (http only on loopback, for local runs) with no path, query or credentials. */
export function normalizePublicUrl(raw: string): string | undefined {
  try {
    const url = new URL(raw.trim());
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") return undefined;
    if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) return url.origin;
  } catch {
    // fall through
  }
  return undefined;
}

/**
 * Off unless MCP_OAUTH=1 and a signing secret exists. "" / "0" / absent = off;
 * any other value, or a bad MCP_PUBLIC_URL / MCP_OAUTH_APPROVALS_PER_HOUR, is
 * "misconfigured": the routes stay off and the reason is logged at boot.
 */
export function loadOAuthConfig(env: Record<string, string | undefined>, signingSecret: string): OAuthConfig {
  const flag = (env.MCP_OAUTH ?? "").trim();
  if (flag === "" || flag === "0") return { kind: "disabled" };
  if (flag !== "1") return { kind: "misconfigured", reason: "MCP_OAUTH must be 1 or 0" };
  if (!signingSecret) return { kind: "misconfigured", reason: "MCP_OAUTH=1 needs MCP_TOKEN_SIGNING_SECRET" };
  const publicUrl = normalizePublicUrl(env.MCP_PUBLIC_URL || DEFAULT_PUBLIC_URL);
  if (!publicUrl) return { kind: "misconfigured", reason: "MCP_PUBLIC_URL must be an https origin with no path" };
  const rawApprovals = (env.MCP_OAUTH_APPROVALS_PER_HOUR ?? "").trim();
  if (rawApprovals !== "" && !/^[1-9][0-9]{0,4}$/.test(rawApprovals)) {
    return { kind: "misconfigured", reason: "MCP_OAUTH_APPROVALS_PER_HOUR must be a whole number from 1 to 99999" };
  }
  const trustedProxy = (env.MCP_OAUTH_TRUSTED_PROXY ?? "").trim();
  return {
    kind: "ready",
    publicUrl,
    approvalsPerHour: rawApprovals === "" ? 10 : Number(rawApprovals),
    // Accounts live on the state volume, next to the handshake and Shadow state.
    accountsDir: join((env.MCP_STATE_DIR ?? "").trim() || "/app/state", "accounts"),
    ...(trustedProxy ? { trustedProxy } : {}),
  };
}

export interface OAuthOptions {
  signingSecret: string;
  /** Normalized public origin (see {@link normalizePublicUrl}); never derived from Host. */
  publicUrl: string;
  /** Access-token lifetime, the same as POST /token's. */
  tokenTtlSeconds: number;
  trustedProxy?: string;
  /** Per-IP approvals per hour (default 10, like POST /token). */
  approvalsPerHour?: number;
  /** Per-IP registrations per minute (default 30). ChatGPT registers from shared egress. */
  registrationsPerMinute?: number;
  /** Per-IP token-endpoint calls per minute (default 120). */
  tokenCallsPerMinute?: number;
  /** Where accounts are stored (src/accounts.ts). Unset or unusable: the approval page answers 503. */
  accountsDir?: string;
  /** Global account cap (default 50,000); creation is refused past it. */
  maxAccounts?: number;
  /** Per-IP account creations per hour (default 10). */
  accountCreationsPerHour?: number;
  /** Per-IP account-key sign-in attempts per hour (default 20). */
  keyAttemptsPerHour?: number;
  /** Milliseconds clock, injectable for tests. */
  now?: () => number;
  log?: (event: Record<string, unknown>) => void;
  onRateLimited?: () => void;
}

export interface OAuthHandler {
  /** Serves the request and returns true when it is an OAuth route; false leaves it untouched. */
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  /**
   * The WWW-Authenticate header for a 401 on an MCP path (/mcp, /shadow/mcp),
   * or undefined for any other path. `tokenPresented` adds error="invalid_token".
   */
  challenge(path: string, tokenPresented: boolean): Record<string, string> | undefined;
}

type ArtifactKind = "client" | "request" | "code" | "refresh" | "grant" | "cookie";
const PREFIXES: Record<ArtifactKind, string> = {
  client: "cc_client_",
  request: "cc_req_",
  code: "cc_code_",
  refresh: "cc_rt_",
  grant: "cc_grant_",
  cookie: "cc_ac_",
};

interface ClientBlob { t: "client"; ru: string[]; n: string; iat: number }
interface RequestBlob { t: "request"; cid: string; n: string; ru: string; rx: 0 | 1; cc: string; st?: string; rs?: string; iat: number; exp: number }
interface CodeBlob { t: "code"; cid: string; n: string; ru: string; rx: 0 | 1; cc: string; rs?: string; acct: string; iat: number; exp: number; jti: string }
interface RefreshBlob { t: "refresh"; cid: string; n: string; acct: string; rs?: string; fam: string; iat: number; exp: number; jti: string }
/**
 * Binds one account to one request token (`rid` = its hash) for one click: "session" on the signed-in page (the
 * cookie must still name the same account when Approve arrives), "create" on the key page's Continue.
 */
interface GrantBlob { t: "grant"; acct: string; rid: string; via: "session" | "create"; iat: number; exp: number }
/** The account cookie's value: it selects an account and nothing else. */
interface CookieBlob { t: "cookie"; acct: string; iat: number }
type Blob = ClientBlob | RequestBlob | CodeBlob | RefreshBlob | GrantBlob | CookieBlob;

const firstHeader = (h: string | string[] | undefined): string => (Array.isArray(h) ? h[0] : h) ?? "";
const pathOf = (url: string | undefined): string => (url ?? "").split("?")[0];
const sha256b64url = (value: string): string => createHash("sha256").update(value, "utf8").digest("base64url");

/** Constant-time string equality (length is not secret here: every compared value has a fixed or public length). */
function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Validation error text for a redirect URI, or undefined when it is acceptable. */
function redirectUriProblem(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URI_LENGTH) return `each redirect URI must be 1 to ${MAX_URI_LENGTH} characters`;
  if (/[^\x21-\x7e]/.test(raw)) return "redirect URIs must be plain ASCII with no spaces";
  if (raw.includes("#")) return "redirect URIs must not contain a fragment";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "redirect URIs must be absolute URLs";
  }
  if (url.username || url.password) return "redirect URIs must not contain credentials";
  if (url.hostname !== "[::1]" && !/^(?:[a-z0-9-]+\.)*[a-z0-9-]+$/i.test(url.hostname)) return "redirect URI host is not supported";
  if (url.protocol === "https:") return undefined;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) return undefined;
  return "redirect URIs must use https (http only on localhost, 127.0.0.1 or [::1])";
}

/**
 * Exact string match against a registered URI, except that an http loopback URI
 * may use any port (RFC 8252 §7.3, OAuth 2.1 §8.4.2): native clients such as
 * Claude Code bind a fresh random port for each sign-in.
 */
function redirectUriMatches(registered: readonly string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  if (redirectUriProblem(requested) !== undefined) return false;
  const req = new URL(requested);
  if (req.protocol !== "http:" || !LOOPBACK_HOSTS.has(req.hostname)) return false;
  const portless = (u: URL) => `${u.protocol}//${u.hostname}${u.pathname}${u.search}`;
  return registered.some((uri) => {
    const reg = new URL(uri);
    return reg.protocol === "http:" && LOOPBACK_HOSTS.has(reg.hostname) && portless(reg) === portless(req);
  });
}

/** Display-safe client name: control and format characters dropped, whitespace collapsed, 60 characters. */
function cleanClientName(raw: unknown): string {
  if (typeof raw !== "string") return "";
  const text = raw.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/g, " ").trim();
  return Array.from(text).slice(0, CLIENT_NAME_MAX).join("");
}

const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

// ---- HTML -------------------------------------------------------------------

const STYLE = `:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--text:#14181f;--muted:#5a6372;--line:#e1e4ea;--accent:#1d4ed8;--on-accent:#fff;--note:#6b4600;--note-bg:#fff5e0}
@media (prefers-color-scheme:dark){:root{--bg:#0d1015;--card:#161a21;--text:#e7eaef;--muted:#9aa3b1;--line:#2a303b;--accent:#4f7cff;--on-accent:#fff;--note:#f2c46d;--note-bg:#2a2214}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{width:100%;max-width:460px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
.eyebrow{margin:0 0 12px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
h1{margin:0 0 6px;font-size:20px;line-height:1.35;font-weight:600;overflow-wrap:anywhere}
.sub{margin:0 0 20px;color:var(--muted)}
dl{margin:0 0 20px;border:1px solid var(--line);border-radius:10px}
dl div{display:flex;gap:12px;padding:10px 14px}
dl div+div{border-top:1px solid var(--line)}
dt{flex:0 0 110px;color:var(--muted)}
dd{margin:0;min-width:0;overflow-wrap:anywhere}
.muted{color:var(--muted);font-size:13px}
h2{margin:0 0 8px;font-size:14px;font-weight:600}
ul{margin:0 0 20px;padding-left:20px}
li{margin:6px 0}
.note{margin:0 0 20px;padding:10px 14px;border-radius:10px;background:var(--note-bg);color:var(--note);font-size:14px}
.actions{display:flex;gap:10px}
button{flex:1;padding:11px 16px;border-radius:10px;font:inherit;font-weight:600;cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--text)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.foot{margin:18px 0 0;font-size:12px;color:var(--muted)}
label,.label{display:block;margin:0 0 6px;font-size:14px;font-weight:600}
input[type=text],input[type=password]{display:block;width:100%;padding:10px 12px;margin:0 0 8px;border:1px solid var(--line);border-radius:10px;font:inherit;background:var(--bg);color:var(--text)}
input:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.hint{margin:0 0 14px;font-size:13px;color:var(--muted)}
.stack button{width:100%}
.choice{display:flex;flex-direction:column}
.choice .create{order:1}
.havekey{order:2;margin:14px 0 0}
.havekey[open]~.create{display:none}
summary{cursor:pointer;color:var(--accent);font-size:14px;margin:0 0 12px}
.havekey:not([open]) .when-open,.havekey[open] .when-closed{display:none}
button.link{flex:none;width:auto;padding:0;border:0;background:none;color:var(--accent);font-weight:500;font-size:14px;text-decoration:underline}
.switch{margin:14px 0 0}
.key{margin:0 0 14px;padding:12px 14px;border:1px dashed var(--muted);border-radius:10px;overflow-wrap:anywhere;user-select:all}
.key code{font-size:15px}`;
const STYLE_HASH = createHash("sha256").update(STYLE, "utf8").digest("base64");

function htmlDocument(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
}

/** `form-action` must allow the post-submit redirect target too (Chrome checks redirects against it). */
function formActionSources(redirectUri: string): string {
  const url = new URL(redirectUri);
  // CSP host-source grammar has no IPv6 literals; [::1] needs the scheme-source.
  const target = url.hostname === "[::1]" ? "http:" : url.origin;
  return `'self' ${target}`;
}

function pageHeaders(formAction: string): Record<string, string> {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    pragma: "no-cache",
    "content-security-policy":
      `default-src 'none'; style-src 'sha256-${STYLE_HASH}'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    // same-origin keeps a non-null Origin on the form POST (the CSRF check) and sends no Referer off-site.
    "referrer-policy": "same-origin",
  };
}

/**
 * An error page: never a redirect, and no link back to the app's redirect URI.
 * Registration is open, so redirecting on an error would let anyone bounce a
 * visitor from our domain to an address of their choosing without a click.
 */
function sendErrorPage(res: ServerResponse, status: number, title: string, message: string, code?: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { ...pageHeaders("'none'"), ...extra });
  res.end(htmlDocument(title, `<p class="eyebrow">Clockchain sign-in</p>
<h1>${escapeHtml(title)}</h1>
<p class="sub">${escapeHtml(message)}</p>${code ? `
<p class="muted">Error code: ${escapeHtml(code)}</p>` : ""}`));
}

interface ConsentView {
  appName: string;
  redirectHost: string;
  requestToken: string;
  /** The signed-in account and the grant binding it to this request; absent = the create-account page. */
  signedIn?: { name: string; grant: string };
  error?: string;
  /** Show the account-key form (after a rejected key). */
  keyOpen?: boolean;
}

const requestField = (token: string): string => `<input type="hidden" name="request" value="${escapeHtml(token)}">`;

function appFacts(app: string, redirectHost: string): string {
  return `<dl>
<div><dt>App</dt><dd>${app}<br><span class="muted">Name supplied by the app, not verified by Clockchain</span></dd></div>
<div><dt>Sends you back to</dt><dd><code>${escapeHtml(redirectHost)}</code></dd></div>
</dl>
<h2>If you approve</h2>
<ul>
<li>The app gets free Clockchain testnet credits from a shared pool.</li>
<li>Shadow keeps the records of your agents’ work for 30 days.</li>
<li>Only fingerprints go on the Clockchain ledger, never the content itself.</li>
</ul>
<p class="note">Only continue if you just started connecting from this app and the address above is where you expect to return.</p>`;
}

/** The approval page: sign-up (no account cookie) or "Signed in as" (a valid one). No script; plain forms. */
function consentPage(v: ConsentView): string {
  const app = escapeHtml(v.appName || "An unnamed app");
  const alert = v.error ? `<p class="note" role="alert">${escapeHtml(v.error)}</p>\n` : "";
  if (v.signedIn) {
    return htmlDocument(`Connect ${v.appName || "an app"} to Clockchain`, `<p class="eyebrow">Clockchain sign-in</p>
<h1>Allow ${app} to record and anchor your agents’ work on Clockchain?</h1>
<p class="sub">Signed in as <strong>${escapeHtml(v.signedIn.name)}</strong>. Free testnet credits.</p>
${alert}${appFacts(app, v.redirectHost)}
<form method="post" action="/oauth/authorize">
${requestField(v.requestToken)}
<input type="hidden" name="grant" value="${escapeHtml(v.signedIn.grant)}">
<div class="actions">
<button type="submit" name="decision" value="cancel">Cancel</button>
<button type="submit" name="decision" value="approve" class="primary">Allow ${app}</button>
</div>
</form>
<form method="post" action="/oauth/authorize" class="switch">
${requestField(v.requestToken)}
<button type="submit" name="decision" value="switch" class="link">Not you? Use a different account</button>
</form>
<p class="foot">Clockchain testnet</p>`);
  }
  return htmlDocument("Create your Clockchain account", `<p class="eyebrow">Clockchain sign-in</p>
<h1>Create your Clockchain account</h1>
<p class="sub">Then allow ${app} to record and anchor your agents’ work on Clockchain. Free testnet credits, no email needed.</p>
${alert}${appFacts(app, v.redirectHost)}
<div class="choice">
<details class="havekey"${v.keyOpen ? " open" : ""}>
<summary><span class="when-closed">I have an account key</span><span class="when-open">Create a new account instead</span></summary>
<form method="post" action="/oauth/authorize" class="stack">
${requestField(v.requestToken)}
<label for="key">Account key</label>
<input id="key" name="key" type="password" required autocomplete="current-password" spellcheck="false">
<button type="submit" name="decision" value="signin" class="primary">Sign in and allow ${app}</button>
</form>
</details>
<form method="post" action="/oauth/authorize" class="stack create">
${requestField(v.requestToken)}
<label for="name">Account name</label>
<input id="name" name="name" type="text" maxlength="40" required autocomplete="nickname" spellcheck="false">
<p class="hint">Shown to you when you sign in. Any name works.</p>
<button type="submit" name="decision" value="create" class="primary">Create account and allow ${app}</button>
</form>
</div>
<form method="post" action="/oauth/authorize" class="switch">
${requestField(v.requestToken)}
<button type="submit" name="decision" value="cancel" class="link">Cancel</button>
</form>
<p class="foot">Clockchain testnet</p>`);
}

/** Shown once, right after the create click: the account key, then Continue on to the app. */
function accountKeyPage(appName: string, accountName: string, key: string, requestToken: string, grant: string): string {
  return htmlDocument("Save your Clockchain account key", `<p class="eyebrow">Clockchain sign-in</p>
<h1>Your Clockchain account is ready</h1>
<p class="sub">Signed in as <strong>${escapeHtml(accountName)}</strong>.</p>
<p class="label">Your account key</p>
<p class="key"><code>${escapeHtml(key)}</code></p>
<p class="note">Save this key to sign in on another device. We can’t show it again.</p>
<form method="post" action="/oauth/authorize" class="stack">
${requestField(requestToken)}
<input type="hidden" name="grant" value="${escapeHtml(grant)}">
<button type="submit" name="decision" value="continue" class="primary">Continue</button>
</form>
<p class="foot">Continue sends you back to ${escapeHtml(appName || "the app")}.</p>`);
}

// ---- request plumbing ---------------------------------------------------------

type BodyResult = { ok: true; text: string } | { ok: false; status: 400 | 413 };

function readBody(req: IncomingMessage): Promise<BodyResult> {
  return new Promise((resolve) => {
    const declared = Number(firstHeader(req.headers["content-length"]) || "0");
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      req.resume();
      resolve({ ok: false, status: 413 });
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const settle = (result: BodyResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        settle({ ok: false, status: 413 });
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => settle({ ok: true, text: Buffer.concat(chunks).toString("utf8") }));
    req.on("error", () => settle({ ok: false, status: 400 }));
  });
}

const mediaType = (req: IncomingMessage): string =>
  firstHeader(req.headers["content-type"]).split(";")[0].trim().toLowerCase();

/** Form or JSON body as a flat string map; undefined when malformed or a parameter repeats. */
function parseParams(type: string, text: string): Map<string, string> | undefined {
  const out = new Map<string, string>();
  if (type === "application/x-www-form-urlencoded") {
    for (const [key, value] of new URLSearchParams(text)) {
      if (out.has(key)) return undefined;
      out.set(key, value);
    }
    return out;
  }
  if (type === "application/json") {
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return undefined;
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) return undefined;
    for (const [key, value] of Object.entries(body)) {
      if (typeof value !== "string") return undefined;
      out.set(key, value);
    }
    return out;
  }
  return undefined;
}

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, mcp-protocol-version",
  "access-control-max-age": "600",
};

// ---- the handler -------------------------------------------------------------

export function createOAuthHandler(options: OAuthOptions): OAuthHandler {
  const base = options.publicUrl;
  const origin = new URL(base).origin;
  const now = options.now ?? Date.now;
  const nowSec = () => Math.floor(now() / 1000);
  const log = options.log ?? ((event) => console.error(JSON.stringify(event)));
  const tokenTtl = Number.isFinite(options.tokenTtlSeconds) && options.tokenTtlSeconds > 0
    ? Math.floor(options.tokenTtlSeconds)
    : 7 * 24 * 60 * 60;

  const allowApproval = limiter(options.approvalsPerHour ?? 10, 60 * 60_000, now);
  const allowRegistration = limiter(options.registrationsPerMinute ?? 30, 60_000, now);
  const allowTokenCall = limiter(options.tokenCallsPerMinute ?? 120, 60_000, now);
  const allowAccountCreate = limiter(options.accountCreationsPerHour ?? 10, 60 * 60_000, now);
  const allowKeyAttempt = limiter(options.keyAttemptsPerHour ?? 20, 60 * 60_000, now);

  // Accounts (src/accounts.ts). Opened once at boot; if that fails the approval page answers 503 and the rest of
  // OAuth (discovery, registration, refresh) keeps working.
  let accounts: AccountStore | undefined;
  if (options.accountsDir) {
    try {
      accounts = new AccountStore(options.accountsDir, options.maxAccounts ?? DEFAULT_MAX_ACCOUNTS, now);
      log({ event: "oauth_accounts_ready", accounts: accounts.count() });
    } catch (e) {
      log({ event: "oauth_accounts_unavailable", error: (e as Error)?.name ?? "error" });
    }
  }

  // One key per artifact kind, each derived from the signing secret under its own label.
  const keys = Object.fromEntries(
    (Object.keys(PREFIXES) as ArtifactKind[]).map((kind) => [
      kind,
      createHmac("sha256", options.signingSecret).update(`clockchain-mcp/oauth/v1/${kind}`, "utf8").digest(),
    ]),
  ) as Record<ArtifactKind, Buffer>;

  const mac = (kind: ArtifactKind, seg: string): string =>
    createHmac("sha256", keys[kind]).update(`${PREFIXES[kind]}${seg}`, "utf8").digest("base64url");

  function seal(blob: Blob): string {
    const seg = Buffer.from(JSON.stringify(blob), "utf8").toString("base64url");
    return `${PREFIXES[blob.t]}${seg}.${mac(blob.t, seg)}`;
  }

  function unseal<T extends Blob>(kind: T["t"], value: unknown): T | undefined {
    if (typeof value !== "string" || value.length > MAX_ARTIFACT_LENGTH || !value.startsWith(PREFIXES[kind])) return undefined;
    const body = value.slice(PREFIXES[kind].length);
    const dot = body.indexOf(".");
    if (dot <= 0 || body.indexOf(".", dot + 1) !== -1) return undefined;
    const seg = body.slice(0, dot);
    if (!safeEqual(body.slice(dot + 1), mac(kind, seg))) return undefined;
    let blob: unknown;
    try {
      blob = JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
    } catch {
      return undefined;
    }
    if (blob === null || typeof blob !== "object" || (blob as { t?: unknown }).t !== kind) return undefined;
    if (kind === "cookie") {
      // {acct, iat}: valid for a year from iat (Max-Age is only advice to the browser).
      const { acct, iat } = blob as { acct?: unknown; iat?: unknown };
      if (!isAcctId(acct) || typeof iat !== "number" || !Number.isSafeInteger(iat) || iat > nowSec() + 300 || nowSec() >= iat + COOKIE_MAX_AGE_S) return undefined;
    } else if (kind !== "client") {
      const exp = (blob as { exp?: unknown }).exp;
      if (typeof exp !== "number" || !Number.isSafeInteger(exp) || nowSec() >= exp) return undefined;
    }
    return blob as T;
  }

  // Single-use bookkeeping. Entries live until the artifact itself expires;
  // the size cap evicts the oldest entry first (best effort under a flood).
  function expiringSet(cap: number) {
    const entries = new Map<string, number>();
    let nextSweep = 0;
    return {
      has: (key: string) => {
        const exp = entries.get(key);
        return exp !== undefined && nowSec() < exp;
      },
      add: (key: string, exp: number) => {
        const t = nowSec();
        if (t >= nextSweep || entries.size >= cap) {
          for (const [k, e] of entries) if (t >= e) entries.delete(k);
          nextSweep = t + 60;
        }
        while (entries.size >= cap) entries.delete(entries.keys().next().value as string);
        entries.set(key, exp);
      },
    };
  }
  const usedCodes = expiringSet(100_000);
  const usedRefreshTokens = expiringSet(200_000);
  const revokedFamilies = expiringSet(100_000);

  const resourceHrefs = new Set([`${base}/`, ...MCP_PATHS.map((p) => `${base}${p}`)]);
  /** undefined = absent; null = not one of ours; else the normalized href. */
  function resourceParam(values: string[]): string | undefined | null {
    if (values.length === 0) return undefined;
    if (values.length > 1) return null;
    const raw = values[0];
    if (raw.length > MAX_URI_LENGTH || raw.includes("#")) return null;
    try {
      const href = new URL(raw).href;
      return resourceHrefs.has(href) ? href : null;
    } catch {
      return null;
    }
  }

  const ipOf = (req: IncomingMessage): string =>
    clientBucket(standaloneClientIp(req.headers, req.socket.remoteAddress, options.trustedProxy));

  function rateLimited(surface: string): void {
    options.onRateLimited?.();
    log({ event: "oauth_rate_limited", surface });
  }

  function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
    res.writeHead(status, { "content-type": "application/json", ...extra });
    res.end(JSON.stringify(body));
  }

  function sendOAuthError(res: ServerResponse, status: number, error: string, description: string, extra: Record<string, string> = {}): void {
    sendJson(res, status, { error, error_description: description }, { "cache-control": "no-store", pragma: "no-cache", ...extra });
  }

  /**
   * Redirect to the client with the given response parameters plus `iss` (RFC 9207),
   * preserving its query. Used ONLY for the outcome of the person's own click on
   * the approval page: Approve (code) or Cancel (access_denied).
   */
  function redirectToClient(res: ServerResponse, redirectUri: string, params: Record<string, string | undefined>, extra: Record<string, string> = {}): void {
    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined) query.set(k, v);
    query.set("iss", base);
    const sep = redirectUri.endsWith("?") ? "" : redirectUri.includes("?") ? "&" : "?";
    res.writeHead(303, { location: `${redirectUri}${sep}${query.toString()}`, "cache-control": "no-store", "referrer-policy": "no-referrer", ...extra });
    res.end();
  }

  function sameOriginPost(req: IncomingMessage): boolean {
    const originHeader = firstHeader(req.headers.origin);
    if (originHeader) return originHeader === origin;
    const referer = firstHeader(req.headers.referer);
    if (!referer) return false;
    try {
      return new URL(referer).origin === origin;
    } catch {
      return false;
    }
  }

  // ---- discovery ----------------------------------------------------------

  const serverMetadata = {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    authorization_response_iss_parameter_supported: true,
    service_documentation: `${base}/llms.txt`,
  };
  const protectedResource = (resource: string) => ({
    resource,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    resource_name: "Clockchain MCP",
    resource_documentation: `${base}/llms.txt`,
  });
  const metadataRoutes = new Map<string, unknown>([
    ["/.well-known/oauth-protected-resource", protectedResource(base)],
    ...MCP_PATHS.map((p): [string, unknown] => [`/.well-known/oauth-protected-resource${p}`, protectedResource(`${base}${p}`)]),
    ["/.well-known/oauth-authorization-server", serverMetadata],
    ["/.well-known/openid-configuration", serverMetadata],
  ]);

  // ---- registration (RFC 7591) ------------------------------------------------

  async function register(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!allowRegistration(`register:${ipOf(req)}`)) {
      rateLimited("register");
      sendOAuthError(res, 429, "temporarily_unavailable", "Too many registrations from this address. Try again in a minute.", { "retry-after": "60" });
      return;
    }
    if (mediaType(req) !== "application/json") {
      sendOAuthError(res, 400, "invalid_client_metadata", "Send the registration as application/json.");
      return;
    }
    const body = await readBody(req);
    if (!body.ok) {
      sendOAuthError(res, body.status, "invalid_client_metadata", body.status === 413 ? "Registration body is larger than 16 KB." : "Could not read the request body.", body.status === 413 ? { connection: "close" } : {});
      return;
    }
    let meta: unknown;
    try {
      meta = JSON.parse(body.text);
    } catch {
      meta = undefined;
    }
    if (meta === null || typeof meta !== "object" || Array.isArray(meta)) {
      sendOAuthError(res, 400, "invalid_client_metadata", "The registration body must be a JSON object.");
      return;
    }
    const m = meta as Record<string, unknown>;
    const uris = m.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > MAX_REDIRECT_URIS) {
      sendOAuthError(res, 400, "invalid_redirect_uri", `redirect_uris must list 1 to ${MAX_REDIRECT_URIS} URIs.`);
      return;
    }
    for (const uri of uris) {
      const problem = redirectUriProblem(uri);
      if (problem) {
        sendOAuthError(res, 400, "invalid_redirect_uri", `${problem[0].toUpperCase()}${problem.slice(1)}.`);
        return;
      }
    }
    if (m.grant_types !== undefined && !(Array.isArray(m.grant_types) && m.grant_types.includes("authorization_code"))) {
      sendOAuthError(res, 400, "invalid_client_metadata", "grant_types must include authorization_code.");
      return;
    }
    if (m.response_types !== undefined && !(Array.isArray(m.response_types) && m.response_types.includes("code"))) {
      sendOAuthError(res, 400, "invalid_client_metadata", "response_types must include code.");
      return;
    }
    const redirectUris = [...new Set(uris as string[])];
    const name = cleanClientName(m.client_name);
    const iat = nowSec();
    const clientId = seal({ t: "client", ru: redirectUris, n: name, iat });
    log({ event: "oauth_client_registered", client_name: name });
    // Public clients only: whatever auth method was asked for, the answer is "none"
    // (RFC 7591 §3.2.1 lets the server replace requested metadata).
    sendJson(res, 201, {
      client_id: clientId,
      client_id_issued_at: iat,
      ...(name ? { client_name: name } : {}),
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, { "cache-control": "no-store", pragma: "no-cache" });
  }

  // ---- accounts: cookie, consent page, code issuance ---------------------------

  // __Host- requires Secure; only a loopback http public URL (local runs and tests) drops both.
  const secureCookie = base.startsWith("https:");
  const COOKIE_NAME = secureCookie ? "__Host-cc_acct" : "cc_acct";
  const cookieAttributes = `Path=/;${secureCookie ? " Secure;" : ""} HttpOnly; SameSite=Lax`;
  const setAccountCookie = (acct: string): string =>
    `${COOKIE_NAME}=${seal({ t: "cookie", acct, iat: nowSec() })}; Max-Age=${COOKIE_MAX_AGE_S}; ${cookieAttributes}`;
  const clearAccountCookie = `${COOKIE_NAME}=; Max-Age=0; ${cookieAttributes}`;

  /** The account the cookie selects. `stale` = a cookie of ours was sent but is invalid, expired or unknown. */
  function cookieAccount(req: IncomingMessage): { account?: Account; stale: boolean } {
    for (const part of firstHeader(req.headers.cookie).split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0 || part.slice(0, eq).trim() !== COOKIE_NAME) continue;
      const blob = unseal<CookieBlob>("cookie", part.slice(eq + 1).trim());
      const account = blob ? accounts?.get(blob.acct) : undefined;
      return account ? { account, stale: false } : { stale: true };
    }
    return { stale: false };
  }

  function sendConsent(
    res: ServerResponse,
    request: RequestBlob,
    requestToken: string,
    o: { account?: Account; status?: number; error?: string; keyOpen?: boolean; headers?: Record<string, string> } = {},
  ): void {
    const iat = nowSec();
    const signedIn = o.account
      ? { name: o.account.name, grant: seal({ t: "grant", acct: o.account.acct, rid: sha256b64url(requestToken), via: "session", iat, exp: iat + REQUEST_TTL_S }) }
      : undefined;
    res.writeHead(o.status ?? 200, { ...pageHeaders(formActionSources(request.ru)), ...o.headers });
    res.end(consentPage({
      appName: request.n,
      redirectHost: new URL(request.ru).host,
      requestToken,
      ...(signedIn ? { signedIn } : {}),
      ...(o.error ? { error: o.error } : {}),
      ...(o.keyOpen ? { keyOpen: true } : {}),
    }));
  }

  const ACCOUNTS_UNAVAILABLE: [string, string] = ["Sign-in is unavailable", "Clockchain can’t open its account store right now. Try again in a few minutes."];

  /** The outcome of an approving click: a code for this account, redirected to the app (with state and iss). */
  function issueCode(req: IncomingMessage, res: ServerResponse, request: RequestBlob, account: Account, extra: Record<string, string> = {}): void {
    if (!allowApproval(`approve:${ipOf(req)}`)) {
      rateLimited("approve");
      // A page, not a redirect: only a code or access_denied ever goes to the app.
      sendErrorPage(res, 429, "Too many approvals", "Too many apps were approved from this network in the last hour. Wait a while, then go back to the app and try connecting again.", "temporarily_unavailable", { "retry-after": "3600", ...extra });
      return;
    }
    const iat = nowSec();
    const code = seal({
      t: "code",
      cid: request.cid,
      n: request.n,
      ru: request.ru,
      rx: request.rx,
      cc: request.cc,
      ...(request.rs !== undefined ? { rs: request.rs } : {}),
      acct: account.acct,
      iat,
      exp: iat + CODE_TTL_S,
      jti: randomUUID(),
    });
    log({ event: "oauth_approved", client_name: request.n, acct: account.acct });
    redirectToClient(res, request.ru, { code, state: request.st }, extra);
  }

  // ---- authorize: the consent page (GET) --------------------------------------

  const INVALID_LINK_TITLE = "This sign-in link isn’t valid";
  const TRY_AGAIN = "Go back to the app and try connecting again.";

  function authorizePage(req: IncomingMessage, res: ServerResponse): void {
    const q = new URL(req.url ?? "/", "http://localhost").searchParams;
    const repeated = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state"]
      .find((name) => q.getAll(name).length > 1);
    // Nothing on this GET ever redirects: every error is a 400 page. Only the
    // person's click on the approval page (POST below) can send them onward.
    const client = repeated === "client_id" ? undefined : unseal<ClientBlob>("client", q.get("client_id"));
    if (!client) {
      sendErrorPage(res, 400, INVALID_LINK_TITLE, "The app that sent you here isn’t registered with Clockchain, or its registration is no longer valid. Go back to the app and try connecting again.");
      return;
    }
    const requestedRedirect = q.get("redirect_uri");
    let redirectUri: string;
    let explicitRedirect: 0 | 1;
    if (repeated === "redirect_uri") {
      sendErrorPage(res, 400, INVALID_LINK_TITLE, "The sign-in link has more than one return address. Go back to the app and try again.");
      return;
    } else if (requestedRedirect === null) {
      if (client.ru.length !== 1) {
        sendErrorPage(res, 400, INVALID_LINK_TITLE, "The sign-in link doesn’t say where to send you back. Go back to the app and try again.");
        return;
      }
      redirectUri = client.ru[0];
      explicitRedirect = 0;
    } else if (redirectUriMatches(client.ru, requestedRedirect)) {
      redirectUri = requestedRedirect;
      explicitRedirect = 1;
    } else {
      sendErrorPage(res, 400, INVALID_LINK_TITLE, "The return address in this sign-in link doesn’t match the one the app registered, so Clockchain won’t send you there.");
      return;
    }

    const state = q.get("state") ?? undefined;
    const fail = (error: string, problem: string) => sendErrorPage(res, 400, INVALID_LINK_TITLE, `${problem} ${TRY_AGAIN}`, error);
    if (repeated) return fail("invalid_request", `The sign-in link has the ${repeated} setting more than once.`);
    // RFC 6749 §A.5: state is VSCHAR (printable ASCII); bounded so the request token stays small.
    if (state !== undefined && (state.length > MAX_STATE_LENGTH || !/^[\x20-\x7e]*$/.test(state))) {
      return fail("invalid_request", "The sign-in link’s state value is too long or has characters Clockchain doesn’t accept.");
    }
    const responseType = q.get("response_type");
    if (responseType === null) return fail("invalid_request", "The sign-in link doesn’t say what kind of sign-in it wants (response_type is missing).");
    if (responseType !== "code") return fail("unsupported_response_type", "The app asked for a kind of sign-in Clockchain doesn’t offer (only response_type=code).");
    const challenge = q.get("code_challenge");
    if (!challenge) return fail("invalid_request", "The sign-in link is missing its security check (PKCE code_challenge), which Clockchain requires.");
    if (q.get("code_challenge_method") !== "S256") return fail("invalid_request", "The sign-in link’s security check must use the S256 method.");
    if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) return fail("invalid_request", "The sign-in link’s security check (code_challenge) is malformed.");
    const resource = resourceParam(q.getAll("resource"));
    if (resource === null) return fail("invalid_target", "The sign-in link asks for access to a server other than this Clockchain MCP endpoint.");

    if (!accounts) return sendErrorPage(res, 503, ...ACCOUNTS_UNAVAILABLE, "temporarily_unavailable");

    const iat = nowSec();
    const request: RequestBlob = {
      t: "request",
      cid: sha256b64url(q.get("client_id") as string),
      n: client.n,
      ru: redirectUri,
      rx: explicitRedirect,
      cc: challenge,
      ...(state !== undefined ? { st: state } : {}),
      ...(resource !== undefined ? { rs: resource } : {}),
      iat,
      exp: iat + REQUEST_TTL_S,
    };
    const fromCookie = cookieAccount(req);
    sendConsent(res, request, seal(request), {
      ...(fromCookie.account ? { account: fromCookie.account } : {}),
      ...(fromCookie.stale ? { headers: { "set-cookie": clearAccountCookie } } : {}),
    });
  }

  // ---- authorize: the decision (POST) -----------------------------------------

  async function authorizeDecision(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!sameOriginPost(req)) {
      sendErrorPage(res, 403, "Approval blocked", "This approval didn’t come from the Clockchain sign-in page. Go back to the app and start again.");
      return;
    }
    if (mediaType(req) !== "application/x-www-form-urlencoded") {
      sendErrorPage(res, 400, "Approval not understood", "Go back to the app and start connecting again.");
      return;
    }
    const body = await readBody(req);
    const form = body.ok ? parseParams("application/x-www-form-urlencoded", body.text) : undefined;
    const request = form ? unseal<RequestBlob>("request", form.get("request")) : undefined;
    if (!request) {
      sendErrorPage(res, 400, "This approval form has expired", "Approval forms are valid for 10 minutes and can’t be changed. Go back to the app and start connecting again.");
      return;
    }
    const decision = form?.get("decision");
    if (decision === "cancel") {
      redirectToClient(res, request.ru, { error: "access_denied", error_description: "The request was cancelled.", state: request.st });
      return;
    }
    if (!accounts) return sendErrorPage(res, 503, ...ACCOUNTS_UNAVAILABLE, "temporarily_unavailable");
    const requestToken = form!.get("request") as string;
    const rid = sha256b64url(requestToken);
    const fromCookie = cookieAccount(req);
    const staleCookie: Record<string, string> = fromCookie.stale ? { "set-cookie": clearAccountCookie } : {};

    if (decision === "approve") {
      // The account the page showed (bound in the grant) must still be the one the cookie selects.
      const grant = unseal<GrantBlob>("grant", form!.get("grant"));
      const account = fromCookie.account;
      if (!grant || grant.via !== "session" || !safeEqual(grant.rid, rid) || !account || account.acct !== grant.acct) {
        sendConsent(res, request, requestToken, {
          ...(account ? { account } : {}),
          status: 409,
          error: "Your sign-in changed since this page loaded. Check the account below and try again.",
          headers: staleCookie,
        });
        return;
      }
      issueCode(req, res, request, account);
      return;
    }

    if (decision === "create") {
      const name = cleanAccountName(form!.get("name"));
      if (!name) {
        sendConsent(res, request, requestToken, { status: 400, error: "Choose an account name of 1 to 40 characters." });
        return;
      }
      if (!allowAccountCreate(`create:${ipOf(req)}`)) {
        rateLimited("account_create");
        sendErrorPage(res, 429, "Too many new accounts", "Too many Clockchain accounts were created from this network in the last hour. Wait a while, or sign in with an account key.", "temporarily_unavailable", { "retry-after": "3600" });
        return;
      }
      let created: ReturnType<AccountStore["create"]>;
      try {
        created = accounts.create(name);
      } catch {
        log({ event: "oauth_account_create_failed" });
        sendErrorPage(res, 503, ...ACCOUNTS_UNAVAILABLE, "temporarily_unavailable");
        return;
      }
      if (!created.ok) {
        log({ event: "oauth_accounts_full", accounts: accounts.count() });
        sendErrorPage(res, 503, "Clockchain isn’t taking new accounts right now", "Try again later, or sign in with an account key you already have.", "temporarily_unavailable");
        return;
      }
      log({ event: "oauth_account_created", acct: created.account.acct, accounts: accounts.count() });
      const iat = nowSec();
      const grant = seal({ t: "grant", acct: created.account.acct, rid, via: "create", iat, exp: iat + REQUEST_TTL_S });
      res.writeHead(200, { ...pageHeaders(formActionSources(request.ru)), "set-cookie": setAccountCookie(created.account.acct) });
      res.end(accountKeyPage(request.n, created.account.name, created.key, requestToken, grant));
      return;
    }

    if (decision === "continue") {
      // After the key page: the grant (minted by the create click) names the new account, cookie or not.
      const grant = unseal<GrantBlob>("grant", form!.get("grant"));
      const account = grant && grant.via === "create" && safeEqual(grant.rid, rid) ? accounts.get(grant.acct) : undefined;
      if (!account) {
        sendErrorPage(res, 400, "This step has expired", "Go back to the app and start connecting again. Your account still works: sign in with its key.");
        return;
      }
      issueCode(req, res, request, account);
      return;
    }

    if (decision === "signin") {
      if (!allowKeyAttempt(`key:${ipOf(req)}`)) {
        rateLimited("account_key");
        sendErrorPage(res, 429, "Too many sign-in attempts", "Too many account keys were tried from this network in the last hour. Wait a while, then try again.", "temporarily_unavailable", { "retry-after": "3600" });
        return;
      }
      const account = accounts.findByKey((form!.get("key") ?? "").trim());
      if (!account) {
        log({ event: "oauth_account_key_rejected" });
        sendConsent(res, request, requestToken, { status: 400, error: "That account key wasn’t recognized. Check it and try again.", keyOpen: true, headers: staleCookie });
        return;
      }
      log({ event: "oauth_account_signin", acct: account.acct });
      issueCode(req, res, request, account, { "set-cookie": setAccountCookie(account.acct) });
      return;
    }

    if (decision === "switch") {
      sendConsent(res, request, requestToken, { headers: { "set-cookie": clearAccountCookie } });
      return;
    }

    sendErrorPage(res, 400, "Approval not understood", "Choose an option on the sign-in page.");
  }

  // ---- token ------------------------------------------------------------------

  function issueTokens(res: ServerResponse, grant: string, args: { cid: string; n: string; acct: string; rs?: string; fam: string }): void {
    const iat = nowSec();
    const { token } = mintToken(options.signingSecret, tokenTtl, iat, undefined, randomUUID(), args.acct);
    const refreshToken = seal({
      t: "refresh",
      cid: args.cid,
      n: args.n,
      acct: args.acct,
      ...(args.rs !== undefined ? { rs: args.rs } : {}),
      fam: args.fam,
      iat,
      exp: iat + REFRESH_TTL_S,
      jti: randomUUID(),
    });
    log({ event: "oauth_token_issued", grant, client_name: args.n, acct: args.acct });
    sendJson(res, 200, {
      access_token: token,
      token_type: "Bearer",
      expires_in: tokenTtl,
      refresh_token: refreshToken,
    }, { "cache-control": "no-store", pragma: "no-cache" });
  }

  async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!allowTokenCall(`token:${ipOf(req)}`)) {
      rateLimited("token");
      sendOAuthError(res, 429, "temporarily_unavailable", "Too many token requests from this address. Try again in a minute.", { "retry-after": "60" });
      return;
    }
    const type = mediaType(req);
    if (type !== "application/x-www-form-urlencoded" && type !== "application/json") {
      sendOAuthError(res, 400, "invalid_request", "Send application/x-www-form-urlencoded (or application/json).");
      return;
    }
    const body = await readBody(req);
    if (!body.ok) {
      sendOAuthError(res, body.status, "invalid_request", body.status === 413 ? "Request body is larger than 16 KB." : "Could not read the request body.", body.status === 413 ? { connection: "close" } : {});
      return;
    }
    const params = parseParams(type, body.text);
    if (!params) {
      sendOAuthError(res, 400, "invalid_request", "Malformed body, or a parameter appears more than once.");
      return;
    }

    // Public clients send client_id in the body; tolerate HTTP Basic carrying it (no secret exists).
    let clientId = params.get("client_id");
    const basic = /^Basic\s+(.+)$/i.exec(firstHeader(req.headers.authorization));
    if (basic) {
      const decoded = Buffer.from(basic[1].trim(), "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      let user: string;
      try {
        user = decodeURIComponent(colon >= 0 ? decoded.slice(0, colon) : decoded);
      } catch {
        user = "";
      }
      if (clientId !== undefined && clientId !== user) {
        sendOAuthError(res, 400, "invalid_request", "client_id in the body and the Authorization header differ.");
        return;
      }
      clientId = user;
    }
    const client = unseal<ClientBlob>("client", clientId);
    if (!client || clientId === undefined) {
      sendOAuthError(res, 401, "invalid_client", "Unknown client_id. Register again.");
      return;
    }
    const cid = sha256b64url(clientId);
    const resource = resourceParam(params.has("resource") ? [params.get("resource") as string] : []);
    if (resource === null) {
      sendOAuthError(res, 400, "invalid_target", "resource must be this server's MCP endpoint.");
      return;
    }

    const grant = params.get("grant_type");
    if (grant === "authorization_code") {
      const code = unseal<CodeBlob>("code", params.get("code"));
      if (!code || !safeEqual(code.cid, cid)) {
        sendOAuthError(res, 400, "invalid_grant", "The authorization code is invalid, expired, or was issued to another client.");
        return;
      }
      const redirectUri = params.get("redirect_uri");
      if (redirectUri !== undefined ? !safeEqual(redirectUri, code.ru) : code.rx === 1) {
        sendOAuthError(res, 400, "invalid_grant", "redirect_uri does not match the authorization request.");
        return;
      }
      const verifier = params.get("code_verifier");
      if (verifier === undefined || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !safeEqual(sha256b64url(verifier), code.cc)) {
        sendOAuthError(res, 400, "invalid_grant", "PKCE verification failed.");
        return;
      }
      if (resource !== undefined && code.rs !== undefined && resource !== code.rs) {
        sendOAuthError(res, 400, "invalid_target", "resource differs from the one approved.");
        return;
      }
      // Check-then-mark with no await in between: single use holds under concurrency.
      if (usedCodes.has(code.jti)) {
        // A replayed code: refuse it and kill the refresh tokens the first use produced.
        revokedFamilies.add(code.jti, nowSec() + REFRESH_TTL_S);
        log({ event: "oauth_code_reuse", acct: code.acct });
        sendOAuthError(res, 400, "invalid_grant", "The authorization code was already used.");
        return;
      }
      usedCodes.add(code.jti, code.exp);
      issueTokens(res, "authorization_code", { cid, n: client.n, acct: code.acct, rs: code.rs ?? resource, fam: code.jti });
      return;
    }
    if (grant === "refresh_token") {
      const refresh = unseal<RefreshBlob>("refresh", params.get("refresh_token"));
      if (!refresh || !safeEqual(refresh.cid, cid) || revokedFamilies.has(refresh.fam)) {
        sendOAuthError(res, 400, "invalid_grant", "The refresh token is invalid, expired, or revoked.");
        return;
      }
      if (resource !== undefined && refresh.rs !== undefined && resource !== refresh.rs) {
        sendOAuthError(res, 400, "invalid_target", "resource differs from the one approved.");
        return;
      }
      if (usedRefreshTokens.has(refresh.jti)) {
        // Rotation reuse (RFC 9700 §4.14.2): revoke the whole family.
        revokedFamilies.add(refresh.fam, nowSec() + REFRESH_TTL_S);
        log({ event: "oauth_refresh_reuse", acct: refresh.acct });
        sendOAuthError(res, 400, "invalid_grant", "The refresh token was already used.");
        return;
      }
      usedRefreshTokens.add(refresh.jti, refresh.exp);
      issueTokens(res, "refresh_token", { cid, n: client.n, acct: refresh.acct, rs: refresh.rs ?? resource, fam: refresh.fam });
      return;
    }
    sendOAuthError(res, 400, grant === undefined ? "invalid_request" : "unsupported_grant_type",
      grant === undefined ? "grant_type is required." : "Only authorization_code and refresh_token are supported.");
  }

  // ---- dispatch ---------------------------------------------------------------

  const CORS_ROUTES = new Set([...metadataRoutes.keys(), "/oauth/register", "/oauth/token"]);

  async function route(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
    const method = req.method ?? "GET";
    if (method === "OPTIONS" && CORS_ROUTES.has(path)) {
      res.writeHead(204);
      res.end();
      return;
    }
    const doc = metadataRoutes.get(path);
    if (doc !== undefined) {
      if (method !== "GET") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET, OPTIONS" });
      return sendJson(res, 200, doc, { "cache-control": "public, max-age=300" });
    }
    if (path === "/oauth/register") {
      if (method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST, OPTIONS" });
      return register(req, res);
    }
    if (path === "/oauth/token") {
      if (method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST, OPTIONS" });
      return token(req, res);
    }
    // /oauth/authorize: a browser page, deliberately without CORS.
    if (method === "GET") return authorizePage(req, res);
    if (method === "POST") return authorizeDecision(req, res);
    res.writeHead(405, { "content-type": "text/plain; charset=utf-8", allow: "GET, POST" });
    res.end("method not allowed");
  }

  return {
    async handle(req, res) {
      const path = pathOf(req.url);
      if (!metadataRoutes.has(path) && path !== "/oauth/register" && path !== "/oauth/token" && path !== "/oauth/authorize") return false;
      // CORS for the metadata, register and token routes only, on every response they give.
      if (CORS_ROUTES.has(path)) for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);
      try {
        await route(req, res, path);
      } catch {
        log({ event: "oauth_internal_error" });
        if (!res.headersSent) sendJson(res, 500, { error: "server_error" }, { "cache-control": "no-store" });
        else res.end();
      }
      return true;
    },
    challenge(path, tokenPresented) {
      if (!(MCP_PATHS as readonly string[]).includes(path)) return undefined;
      const metadataUrl = `${base}/.well-known/oauth-protected-resource${path}`;
      return {
        "www-authenticate": `Bearer resource_metadata="${metadataUrl}"${tokenPresented ? ', error="invalid_token"' : ""}`,
      };
    },
  };
}
