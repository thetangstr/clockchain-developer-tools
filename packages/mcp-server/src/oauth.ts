import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import {
  AccountStore, AccountUnavailableError, cleanAccountName, cleanDisplayText, DEFAULT_MAX_ACCOUNTS, displayAccountName,
  hasLetterOrDigit, looksLikeAccountKey, shortAccountId, type Account,
} from "./accounts.js";
import { durableExpiringSet, memoryExpiringSet, type ExpiringSet } from "./oauth-replay.js";
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
 * bring-your-own-key path. The only server state is the accounts and the replay
 * state (spent codes, spent refresh tokens, revoked families; src/oauth-replay.ts),
 * both on the state volume so they survive restarts.
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
  | {
      kind: "ready";
      publicUrl: string;
      approvalsPerHour: number;
      /** All account creations per hour, across every address (MCP_OAUTH_ACCOUNTS_PER_HOUR, default 200). */
      accountsPerHour: number;
      /** Account creations per IP per hour (MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR, default 10). */
      accountsPerIpPerHour: number;
      /** Account-key sign-in attempts per IP per hour (MCP_OAUTH_KEY_ATTEMPTS_PER_IP_PER_HOUR, default 20). */
      keyAttemptsPerIpPerHour: number;
      accountsDir: string;
      replayDir: string;
      /** The account cookie's name (see accountCookieName). */
      cookieName: string;
      trustedProxy?: string;
    };

/** An https origin (http only on loopback, for local runs) with no path, query or credentials. */
/**
 * An https base URL (http only on loopback, for local runs) with no query, fragment or credentials. It may carry a
 * path for a prefixed mount (staging is https://mcp.clockchain.network/staging, behind Caddy's handle_path): every
 * URL the OAuth pages and metadata emit then carries it. Returned without a trailing slash.
 */
export function normalizePublicUrl(raw: string): string | undefined {
  try {
    const url = new URL(raw.trim());
    if (url.username || url.password || url.search || url.hash || raw.includes("#") || raw.includes("?")) return undefined;
    const path = url.pathname.replace(/\/+$/, "");
    if (path !== "" && !/^(\/[A-Za-z0-9._~-]+)+$/.test(path)) return undefined;
    if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) return `${url.origin}${path}`;
  } catch {
    // fall through
  }
  return undefined;
}

/**
 * The account cookie's name. Production (no path): __Host-cc_acct. A prefixed base gets its own name derived from
 * the path (/staging -> __Host-cc_acct_staging), so a staging mount on the same host never reads or clears
 * production's cookie; MCP_OAUTH_COOKIE_NAME overrides it. __Host- needs https, so loopback http drops the prefix.
 */
export function accountCookieName(publicUrl: string, override?: string): string | undefined {
  const secure = publicUrl.startsWith("https:");
  if (override !== undefined && override !== "") {
    if (!/^(__Host-)?[A-Za-z0-9_]{1,64}$/.test(override)) return undefined;
    if (secure && !override.startsWith("__Host-")) return undefined;
    if (!secure && override.startsWith("__Host-")) return undefined;
    return override;
  }
  const suffix = new URL(publicUrl).pathname.replace(/^\/+|\/+$/g, "").replace(/[^A-Za-z0-9]+/g, "_");
  return `${secure ? "__Host-" : ""}cc_acct${suffix ? `_${suffix}` : ""}`;
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
  if (!publicUrl) return { kind: "misconfigured", reason: "MCP_PUBLIC_URL must be an https URL (an optional path, no query or fragment)" };
  const cookieName = accountCookieName(publicUrl, (env.MCP_OAUTH_COOKIE_NAME ?? "").trim());
  if (!cookieName) return { kind: "misconfigured", reason: "MCP_OAUTH_COOKIE_NAME must be letters, digits and _ (with __Host- on https, without it on http)" };
  // Per-hour limits: "" or unset = the default; anything but a whole number from 1 to 99999 is misconfigured.
  const counts: Record<string, number> = {};
  for (const [name, fallback] of [
    ["MCP_OAUTH_APPROVALS_PER_HOUR", 10],
    ["MCP_OAUTH_ACCOUNTS_PER_HOUR", 200],
    ["MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR", 10],
    ["MCP_OAUTH_KEY_ATTEMPTS_PER_IP_PER_HOUR", 20],
  ] as const) {
    const raw = (env[name] ?? "").trim();
    if (raw !== "" && !/^[1-9][0-9]{0,4}$/.test(raw)) return { kind: "misconfigured", reason: `${name} must be a whole number from 1 to 99999` };
    counts[name] = raw === "" ? fallback : Number(raw);
  }
  const trustedProxy = (env.MCP_OAUTH_TRUSTED_PROXY ?? "").trim();
  return {
    kind: "ready",
    publicUrl,
    approvalsPerHour: counts.MCP_OAUTH_APPROVALS_PER_HOUR,
    accountsPerHour: counts.MCP_OAUTH_ACCOUNTS_PER_HOUR,
    accountsPerIpPerHour: counts.MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR,
    keyAttemptsPerIpPerHour: counts.MCP_OAUTH_KEY_ATTEMPTS_PER_IP_PER_HOUR,
    // Accounts and replay state live on the state volume, next to the handshake and Shadow state.
    accountsDir: join((env.MCP_STATE_DIR ?? "").trim() || "/app/state", "accounts"),
    replayDir: join((env.MCP_STATE_DIR ?? "").trim() || "/app/state", "oauth"),
    cookieName,
    ...(trustedProxy ? { trustedProxy } : {}),
  };
}

export interface OAuthOptions {
  signingSecret: string;
  /** Normalized public base URL, possibly with a path (see {@link normalizePublicUrl}); never derived from Host. */
  publicUrl: string;
  /** The account cookie's name; default from {@link accountCookieName}. */
  cookieName?: string;
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
  /** Account creations per hour across every address (default 200): a brake on free accounts filling storage. */
  accountCreationsPerHourGlobal?: number;
  /** Per-IP account-key sign-in attempts per hour (default 20). */
  keyAttemptsPerHour?: number;
  /**
   * MCP paths for sign-up from the chat (SHADOW_LAZY_AUTH): served and challenged like /mcp and /shadow/mcp, and a
   * sign-in for one of them (its `resource`) gets the one-click create page, the name coming later from the chat.
   */
  chatPaths?: readonly string[];
  /**
   * Where spent codes, spent refresh tokens and revoked families are kept across restarts (src/oauth-replay.ts).
   * Unset: memory only (tests). Set but unusable: the token endpoint refuses closed (503).
   */
  replayDir?: string;
  /** Refresh grants per refresh-token family per hour (default 30). */
  refreshesPerFamilyPerHour?: number;
  /** Refresh grants per IP per hour (default 30). */
  refreshesPerIpPerHour?: number;
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
  /** The account store the sign-in page uses (undefined when unusable), shared with the chat account tools. */
  readonly accounts: AccountStore | undefined;
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
/**
 * Display-safe app name: the same hygiene as account names (cleanDisplayText: no control or invisible characters,
 * blank look-alikes as spaces, at most 2 combining marks per character), cut to 60 characters. A name with no visible
 * letter or digit is no name ("An unnamed app" on the page).
 */
function cleanClientName(raw: unknown): string {
  if (typeof raw !== "string" || raw.length > 2000) return "";
  const text = Array.from(cleanDisplayText(raw)).slice(0, CLIENT_NAME_MAX).join("").trim();
  return hasLetterOrDigit(text) ? text : "";
}

const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

// ---- HTML -------------------------------------------------------------------
//
// The sign-in pages follow clockchain.network: its daylight and eclipse palettes (picked here by
// prefers-color-scheme, since the site's toggle is a script), Inter and JetBrains Mono, the green logo and
// pill buttons. No script anywhere; one stylesheet, allowed by its hash. Both fonts are served from this
// origin (FONT_FILES) and the logo is inline SVG, so the policy adds only font-src 'self'.

/**
 * Self-hosted fonts (SIL OFL 1.1, licences beside them in assets/fonts): the latin subsets of Inter and
 * JetBrains Mono that clockchain.network uses. Read once at boot; a missing file is a 404, never a crash.
 * The page refers to them relative to /oauth/authorize, so a prefixed mount (/staging) finds them too.
 */
const FONT_FILES: ReadonlyMap<string, Buffer | null> = new Map(
  ["inter-latin-v20.woff2", "jetbrains-mono-latin-v24.woff2"].map((name): [string, Buffer | null] => {
    let body: Buffer | null = null;
    try {
      body = readFileSync(new URL(`../assets/fonts/${name}`, import.meta.url));
    } catch {
      body = null;
    }
    return [`/oauth/assets/${name}`, body];
  }),
);

const LATIN =
  "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD";

const STYLE = `@font-face{font-family:Inter;font-style:normal;font-weight:300 600;font-display:swap;src:url(assets/inter-latin-v20.woff2) format("woff2");unicode-range:${LATIN}}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:400 500;font-display:swap;src:url(assets/jetbrains-mono-latin-v24.woff2) format("woff2");unicode-range:${LATIN}}
:root{color-scheme:light dark;--bg:#f5f5f7;--surface:#fff;--field:#fff;--fg:#1d1d1f;--fg-2:#6e6e73;--fg-3:#86868b;--line:#e9e9ee;--line-2:#d8d8df;--accent:#00cc00;--on-accent:#fff;--logo:#00cc00;--error:#d9534f;--shadow:0 1px 2px rgba(0,0,0,.04),0 12px 40px -24px rgba(0,0,0,.25);--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#050905;--surface:#0e130f;--field:#050905;--fg:#f3f6f3;--fg-2:#a7ada7;--fg-3:#808680;--line:rgba(255,255,255,.09);--line-2:rgba(255,255,255,.16);--logo:#fff;--error:#e8716d;--shadow:0 1px 2px rgba(0,0,0,.4),0 24px 60px -30px rgba(0,0,0,.8)}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;padding:40px 16px;background:var(--bg);color:var(--fg);font:300 15px/1.55 var(--sans);letter-spacing:-.01em;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:440px;margin:auto;padding:36px 32px 26px;background:var(--surface);border:1px solid transparent;border-radius:18px;box-shadow:var(--shadow)}
@media (prefers-color-scheme:dark){main{border-color:var(--line)}}
.logo{display:block;width:auto;height:24px;margin:0 0 34px;color:var(--logo)}
h1{margin:0;font-size:28px;font-weight:300;line-height:1.15;letter-spacing:-.025em;overflow-wrap:anywhere;text-wrap:balance}
p{margin:0;text-wrap:pretty}
.app,.lead{margin:10px 0 0;color:var(--fg-2);overflow-wrap:anywhere}
.app{font-size:14px}
code,.id{font-family:var(--mono);font-size:.9em;letter-spacing:0}
.app code{color:var(--fg)}
.id{color:var(--fg-3)}
.alert{margin:20px 0 0;color:var(--error);font-size:14px;font-weight:400}
.who{margin:26px 0 0;color:var(--fg-2);font-size:14px;overflow-wrap:anywhere}
.who strong,.foot strong{color:var(--fg);font-weight:500}
.flow{margin:28px 0 0}
.who+.flow{margin-top:14px}
label{display:block;margin:0 0 8px;color:var(--fg-3);font:500 12px/1.3 var(--mono);letter-spacing:.05em;text-transform:uppercase}
input[type=text],input[type=password]{display:block;width:100%;height:48px;margin:0;padding:0 14px;border:1px solid var(--line-2);border-radius:10px;background:var(--field);color:var(--fg);font:400 16px var(--sans);letter-spacing:-.01em}
input:focus{outline:none;border-color:var(--accent)}
button{margin:0;font:inherit;color:inherit;cursor:pointer}
.primary{display:block;width:100%;min-height:48px;margin:16px 0 0;padding:12px 24px;border:0;border-radius:980px;background:var(--accent);color:var(--on-accent);font-size:15px;font-weight:500;letter-spacing:-.01em;transition:transform .18s ease,filter .18s ease}
.primary:hover{transform:translateY(-1px);filter:brightness(1.06)}
.row{display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:2px 28px;margin:12px 0 0}
.link,.havekey>summary,.download{display:inline-block;padding:6px 2px;border:0;border-radius:6px;background:none;color:var(--fg-2);font-size:14px;font-weight:400;text-decoration:none;cursor:pointer}
.link:hover,.havekey>summary:hover,.download:hover,.more>summary:hover{color:var(--fg)}
summary{list-style:none}
summary::-webkit-details-marker{display:none}
.primary:focus-visible,.link:focus-visible,summary:focus-visible,.download:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.havekey:not([open]) .when-open,.havekey[open] .when-closed{display:none}
.flow:has(.havekey[open])>.create{display:none}
.flow:has(.havekey[open])>.row{display:block;margin:0}
.havekey[open]>summary{margin:-6px 0 14px -2px}
.havekey[open]>summary::before{content:"\\2190\\00a0"}
.flow:has(.havekey[open]) .cancel{margin:12px 0 0;text-align:center}
.foot{margin:30px 0 0;padding:16px 0 0;border-top:1px solid var(--line);color:var(--fg-3);font-size:13px;overflow-wrap:anywhere}
.foot p+p{margin-top:4px}
.more{margin:6px 0 0}
.more>summary{display:inline-flex;align-items:center;gap:8px;padding:4px 0;border-radius:6px;color:var(--fg-2);cursor:pointer}
.more>summary::after{content:"";width:6px;height:6px;margin-top:-3px;border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;transform:rotate(45deg)}
.more[open]>summary::after{margin-top:3px;transform:rotate(225deg)}
.more ul{margin:10px 0 0;padding:0 0 0 18px;color:var(--fg-2);font-size:13.5px;line-height:1.5}
.more li{margin:6px 0;padding-left:2px}
.more li::marker{color:var(--accent)}
.more p{margin:12px 0 2px}
.keyfield[type=text]{height:54px;margin:26px 0 0;padding:0 12px;font:500 clamp(10px,calc((100vw - 130px)/21.6),15px) var(--mono);letter-spacing:0;text-align:center;-webkit-user-select:all;user-select:all}
.download{margin:8px 0 0}
.code{margin:18px 0 0;color:var(--fg-3);font:400 12px var(--mono);letter-spacing:.02em}
@media (max-width:480px){body{padding:20px 16px}main{margin:0 auto auto;padding:28px 22px 20px;border-radius:16px}h1{font-size:25px}.logo{margin-bottom:28px}}
@media (prefers-reduced-motion:reduce){.primary{transition:none}.primary:hover{transform:none}}`;
const STYLE_HASH = createHash("sha256").update(STYLE, "utf8").digest("base64");

/** clockchain.network's logo (the mark and the wordmark), drawn inline so the policy needs no img-src. */
const LOGO = `<svg class="logo" viewBox="0 0 1613 286" role="img" aria-label="Clockchain" fill="currentColor"><path fill-rule="evenodd" d="M143 0a143 143 0 1 0 0 286a143 143 0 1 0 0-286zm0 0a111 111 0 1 0 0 222a111 111 0 1 0 0-222z"/><circle cx="143" cy="56" r="56"/><path transform="matrix(1 0 0-1 0 286)" d="M468 229c-42-7-65-36-65-82-1-36 13-61 40-76 26-13 65-11 89 5 14 10 28 33 28 48l0 3-16 0-15 0-2-6c-5-18-17-28-35-31-21-3-41 6-49 23-9 18-9 48 0 66 17 34 71 32 83-3l1-5 17 0 16 0-1 3c-6 27-24 46-51 53-9 2-31 3-40 2zM583 146l0-80 15 0 15 0 0 80 0 80-15 0-15 0 0-80zM916 146l0-80 15 0 15 0 0 18 0 19 9 8c4 4 8 8 9 8 0 0 8-12 18-26l17-27 18 0 17 0-10 15c-6 9-17 25-25 36l-14 21 14 13c7 8 18 17 23 22l9 9-18 0-18 0-24-23-24-24-1 46 0 45-15 0-15 0 0-80zM1174 146l0-80 15 0 16 0 0 38c1 42 0 41 8 48 11 12 33 10 39-2 2-4 2-8 2-44l0-40 15 0 15 0 0 45 0 46-4 6c-11 25-49 30-70 10l-5-5 0 29 0 29-15 0-16 0 0-80zM1444 211l0-14 15 0 15 0 0 14 0 13-15 0-15 0 0-13zM683 183c-30-6-49-32-47-63 3-35 26-56 63-56 38 0 61 23 61 61 0 42-34 67-77 58zm25-23c27-7 30-58 4-70-12-6-30-2-38 8-7 10-9 31-4 44 6 15 22 22 38 18zM824 184c-31-7-48-31-46-64 2-33 23-54 57-57 30-2 58 18 60 44l1 3-15 0-15 0-2-6c-7-21-40-23-50-2-7 14-6 36 1 48 12 17 43 14 49-6l1-4 15 0c17 0 17-1 13 10-5 16-17 27-33 32-9 3-28 4-36 2zM1082 184c-29-7-45-28-45-60 0-37 23-60 60-60 28 0 49 14 55 38 1 3 2 7 1 7 0 1-6 1-15 1l-14 0-1-3c-6-26-46-26-54 0-4 17-2 36 7 46 12 12 35 10 43-3 2-2 3-6 4-7l0-3 15 0 15 0 0 2c0 4-4 14-6 19-11 18-40 28-65 23zM1353 184c-24-3-38-16-41-35l0-4 15 0 14 1 1 4c3 10 9 13 24 13 6 0 12 0 14-1 7-3 10-10 8-17-2-6-7-8-27-10-25-2-37-6-46-14-14-15-11-41 8-51 12-7 32-9 46-4 7 2 17 9 18 12 1 2 3 0 3-2 0-1 1-4 1-6l1-4 16 0 15 0-2 4c-2 4-3 6-3 47-1 47-1 46-8 54-8 10-19 13-40 13-8 1-16 1-17 0zm36-71c-2-20-11-28-31-28-14-1-21 5-21 14 0 11 6 15 29 18 7 0 15 2 18 3 2 1 5 2 5 2 0 0 0-4 0-9zM1558 184c-8-2-15-6-21-12l-5-5 0 8 0 7-14 0-15 0 0-58 0-58 15 0 15 0 0 38c1 42 0 42 9 49 12 11 33 9 38-3 2-4 2-7 2-44l0-40 16 0 15 0 0 38c0 43-1 51-5 60-8 16-29 25-50 20zM1444 124l0-58 15 0 15 0 0 58 0 58-15 0-15 0 0-58z"/></svg>`;

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
${LOGO}
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
      `default-src 'none'; style-src 'sha256-${STYLE_HASH}'; font-src 'self'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
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
  res.end(htmlDocument(title, `<h1>${escapeHtml(title)}</h1>
<p class="lead">${escapeHtml(message)}</p>${code ? `
<p class="code">Error code: ${escapeHtml(code)}</p>` : ""}`));
}

/** A self-hosted font: public, cacheable for a year (the names carry the version), and only for this origin. */
function sendFont(req: IncomingMessage, res: ServerResponse, body: Buffer | null): void {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "content-type": "text/plain; charset=utf-8", allow: "GET, HEAD" });
    res.end("method not allowed");
    return;
  }
  if (!body) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }
  res.writeHead(200, {
    "content-type": "font/woff2",
    "content-length": body.length,
    "cache-control": "public, max-age=31536000, immutable",
    "x-content-type-options": "nosniff",
    "cross-origin-resource-policy": "same-origin",
  });
  res.end(req.method === "HEAD" ? undefined : body);
}

interface ConsentView {
  /** Where every form posts: <base path>/oauth/authorize, so a prefixed mount (/staging) posts to itself. */
  action: string;
  appName: string;
  redirectHost: string;
  requestToken: string;
  /** The signed-in account (name and short id) and the grant binding it to this request; absent = the create page. */
  signedIn?: { name: string; shortId: string; grant: string };
  error?: string;
  /** Show the account-key form (after a rejected key). */
  keyOpen?: boolean;
  /** A sign-in from the chat: Create account needs no name (the chat names the account afterwards). */
  oneClick?: boolean;
}

const requestField = (token: string): string => `<input type="hidden" name="request" value="${escapeHtml(token)}">`;

/** The app and where Continue/Allow sends you, as plain text: the return host is the phishing check, always shown. */
function appLine(app: string, redirectHost: string): string {
  return `<p class="app">${app} · returns you to <code>${escapeHtml(redirectHost)}</code></p>`;
}

/** The small print: testnet, then what allowing means (the reviewed wording, unchanged), folded. */
function smallPrint(app: string, redirectHost: string): string {
  return `<footer class="foot">
<p>Free testnet · only fingerprints go on the Clockchain ledger</p>
<details class="more">
<summary>What this allows</summary>
<ul>
<li>${app} can use Clockchain’s testnet tools on this account: recording, anchoring and timestamps.</li>
<li>${app} can read and add to every Shadow record in this account, including records made from other apps.</li>
<li>Its writes are paid from Clockchain’s free testnet pool, not by you.</li>
<li>Shadow keeps the records of your agents’ work for 30 days.</li>
<li>Only fingerprints go on the Clockchain ledger, never the content itself.</li>
</ul>
<p>Only continue if you just started connecting from this app and <code>${escapeHtml(redirectHost)}</code> is where you expect to return. The app’s name comes from the app; Clockchain doesn’t verify it.</p>
</details>
</footer>`;
}

/**
 * The approval page: create an account (no account cookie) or "Signed in as" (a valid one). No script; plain
 * forms. The account-key form is a native <details> that, open, takes the create form's place (CSS :has()).
 */
function consentPage(v: ConsentView): string {
  const app = escapeHtml(v.appName || "An unnamed app");
  const title = `Connect ${v.appName || "an unnamed app"} to Clockchain`;
  const action = escapeHtml(v.action);
  const head = `<h1>${escapeHtml(title)}</h1>
${appLine(app, v.redirectHost)}${v.error ? `
<p class="alert" role="alert">${escapeHtml(v.error)}</p>` : ""}`;
  if (v.signedIn) {
    return htmlDocument(title, `${head}
<p class="who">Signed in as <strong>${escapeHtml(v.signedIn.name)}</strong> <span class="id">(${escapeHtml(v.signedIn.shortId)})</span></p>
<form method="post" action="${action}" class="flow">
${requestField(v.requestToken)}
<input type="hidden" name="grant" value="${escapeHtml(v.signedIn.grant)}">
<button type="submit" name="decision" value="approve" class="primary">Allow</button>
<div class="row">
<button type="submit" name="decision" value="switch" class="link">Not you?</button>
<button type="submit" name="decision" value="cancel" class="link">Cancel</button>
</div>
</form>
${smallPrint(app, v.redirectHost)}`);
  }
  return htmlDocument(title, `${head}
<div class="flow">
<form method="post" action="${action}" class="create">
${requestField(v.requestToken)}${v.oneClick ? "" : `
<label for="name">Company or account name</label>
<input id="name" name="name" type="text" maxlength="40" required autocomplete="organization" spellcheck="false">`}
<button type="submit" name="decision" value="create" class="primary">Create account</button>
</form>
<div class="row">
<details class="havekey"${v.keyOpen ? " open" : ""}>
<summary><span class="when-closed">I have an account key</span><span class="when-open">Create a new account instead</span></summary>
<form method="post" action="${action}">
${requestField(v.requestToken)}
<label for="key">Account key</label>
<input id="key" name="key" type="password" required autocomplete="current-password" spellcheck="false">
<button type="submit" name="decision" value="signin" class="primary">Sign in</button>
</form>
</details>
<form method="post" action="${action}" class="cancel">
${requestField(v.requestToken)}
<button type="submit" name="decision" value="cancel" class="link">Cancel</button>
</form>
</div>
</div>
${smallPrint(app, v.redirectHost)}`);
}

interface KeyView {
  action: string;
  appName: string;
  redirectHost: string;
  accountName: string;
  shortId: string;
  key: string;
  requestToken: string;
  grant: string;
}

/**
 * Shown once, right after the create click: the account key, then Continue on to the app. The key file is a
 * data: link with the download attribute (no script, nothing fetched, so nothing for the CSP to allow).
 */
function accountKeyPage(v: KeyView): string {
  const file = [
    "Clockchain account key",
    "",
    `Account: ${v.accountName} (${v.shortId})`,
    `Key: ${v.key}`,
    "",
    "Keep this key private: anyone who has it can use this Clockchain account.",
    "To sign in on another device, choose “I have an account key” when you connect an app to Clockchain.",
    "",
  ].join("\n");
  return htmlDocument("Save your Clockchain account key", `<h1>Save your account key</h1>
<p class="lead">You’ll need it to sign in on another device. We can’t show it again.</p>
<input class="keyfield" type="text" value="${escapeHtml(v.key)}" readonly aria-label="Your account key" spellcheck="false" autocomplete="off" autocapitalize="off">
<a class="download" href="${escapeHtml(`data:text/plain;charset=utf-8,${encodeURIComponent(file)}`)}" download="clockchain-account-key.txt">Download key file</a>
<form method="post" action="${escapeHtml(v.action)}" class="flow">
${requestField(v.requestToken)}
<input type="hidden" name="grant" value="${escapeHtml(v.grant)}">
<button type="submit" name="decision" value="continue" class="primary">Continue</button>
</form>
<footer class="foot">
<p>Signed in as <strong>${escapeHtml(v.accountName)}</strong> <span class="id">(${escapeHtml(v.shortId)})</span></p>
<p>Continue returns you to ${escapeHtml(v.appName || "the app")} at <code>${escapeHtml(v.redirectHost)}</code>.</p>
</footer>`);
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
  // A prefixed mount (/staging): Caddy strips the prefix before the request reaches us, so our routes stay at the
  // root, but every URL the browser or a client is given must carry it.
  const basePath = new URL(base).pathname.replace(/\/+$/, "");
  const AUTHORIZE_ACTION = `${basePath}/oauth/authorize`;
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
  const allowAccountCreateGlobal = limiter(options.accountCreationsPerHourGlobal ?? 200, 60 * 60_000, now);
  const allowKeyAttempt = limiter(options.keyAttemptsPerHour ?? 20, 60 * 60_000, now);
  // Every refresh mints a fresh access token, so refreshes are capped per family (one approval's chain) and per IP.
  const allowFamilyRefresh = limiter(options.refreshesPerFamilyPerHour ?? 30, 60 * 60_000, now);
  const allowIpRefresh = limiter(options.refreshesPerIpPerHour ?? 30, 60 * 60_000, now);

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

  // Single-use and revocation bookkeeping. Entries live until the artifact itself expires. Durable when replayDir
  // is set (production: <MCP_STATE_DIR>/oauth), so a restart cannot resurrect a spent or revoked token.
  let replay: { usedCodes: ExpiringSet; usedRefreshTokens: ExpiringSet; revokedFamilies: ExpiringSet } | undefined;
  try {
    const make = (name: string, cap: number): ExpiringSet =>
      options.replayDir ? durableExpiringSet(options.replayDir, name, cap, nowSec) : memoryExpiringSet(cap, nowSec);
    replay = {
      usedCodes: make("used-codes", 100_000),
      usedRefreshTokens: make("used-refresh", 200_000),
      revokedFamilies: make("revoked-families", 100_000),
    };
  } catch (e) {
    log({ event: "oauth_replay_state_unavailable", error: (e as Error)?.name ?? "error" });
  }

  const mcpPaths: readonly string[] = [...MCP_PATHS, ...(options.chatPaths ?? [])];
  const chatResources = new Set((options.chatPaths ?? []).map((p) => `${base}${p}`));
  /** A sign-in started by a chat endpoint's 401 (its resource): the create page needs no name. */
  const fromChat = (request: RequestBlob): boolean => request.rs !== undefined && chatResources.has(request.rs);
  const resourceHrefs = new Set([`${base}/`, ...mcpPaths.map((p) => `${base}${p}`)]);
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
    ...mcpPaths.map((p): [string, unknown] => [`/.well-known/oauth-protected-resource${p}`, protectedResource(`${base}${p}`)]),
    ["/.well-known/oauth-authorization-server", serverMetadata],
    ["/.well-known/openid-configuration", serverMetadata],
    // An issuer with a path: RFC 8414 and RFC 9728 insert it after /.well-known/<name>. Behind a prefix-stripping proxy
    // those URLs reach this server only if the proxy routes them here (see the follow-up report's Caddy note); the
    // path-appended forms above (<base>/.well-known/...) always do, and the 401 names the resource metadata URL.
    ...(basePath
      ? [
          [`/.well-known/oauth-authorization-server${basePath}`, serverMetadata],
          [`/.well-known/openid-configuration${basePath}`, serverMetadata],
          [`/.well-known/oauth-protected-resource${basePath}`, protectedResource(base)],
          ...mcpPaths.map((p): [string, unknown] => [`/.well-known/oauth-protected-resource${basePath}${p}`, protectedResource(`${base}${p}`)]),
        ] as [string, unknown][]
      : []),
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
  const COOKIE_NAME = options.cookieName ?? accountCookieName(base) ?? (secureCookie ? "__Host-cc_acct" : "cc_acct");
  const cookieAttributes = `Path=/;${secureCookie ? " Secure;" : ""} HttpOnly; SameSite=Lax`;
  const setAccountCookie = (acct: string): string =>
    `${COOKIE_NAME}=${seal({ t: "cookie", acct, iat: nowSec() })}; Max-Age=${COOKIE_MAX_AGE_S}; ${cookieAttributes}`;
  const clearAccountCookie = `${COOKIE_NAME}=; Max-Age=0; ${cookieAttributes}`;

  /**
   * The account the cookie selects. `stale` = a cookie of ours was sent but is invalid, expired or names no account
   * (it is cleared). `unavailable` = it names an account whose record cannot be read right now (it is kept).
   */
  function cookieAccount(req: IncomingMessage): { account?: Account; stale: boolean; unavailable?: boolean } {
    for (const part of firstHeader(req.headers.cookie).split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0 || part.slice(0, eq).trim() !== COOKIE_NAME) continue;
      const blob = unseal<CookieBlob>("cookie", part.slice(eq + 1).trim());
      if (!blob) return { stale: true };
      try {
        const account = accounts?.get(blob.acct);
        return account ? { account, stale: false } : { stale: true };
      } catch (e) {
        if (e instanceof AccountUnavailableError) return { stale: false, unavailable: true };
        throw e;
      }
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
      ? {
          name: displayAccountName(o.account),
          shortId: shortAccountId(o.account.acct),
          grant: seal({ t: "grant", acct: o.account.acct, rid: sha256b64url(requestToken), via: "session", iat, exp: iat + REQUEST_TTL_S }),
        }
      : undefined;
    res.writeHead(o.status ?? 200, { ...pageHeaders(formActionSources(request.ru)), ...o.headers });
    res.end(consentPage({
      action: AUTHORIZE_ACTION,
      appName: request.n,
      redirectHost: new URL(request.ru).host,
      requestToken,
      ...(signedIn ? { signedIn } : {}),
      ...(o.error ? { error: o.error } : {}),
      ...(o.keyOpen ? { keyOpen: true } : {}),
      ...(fromChat(request) ? { oneClick: true } : {}),
    }));
  }

  const ACCOUNTS_UNAVAILABLE: [string, string] = ["Sign-in is unavailable", "Clockchain can’t open its account store right now. Try again in a few minutes."];
  /** A record that exists but cannot be read: 503, and the cookie is kept (never cleared for this). */
  const ACCOUNT_RECORD_UNAVAILABLE: [string, string] = ["Your account is temporarily unavailable", "Clockchain can’t read your account right now. You stay signed in; try again in a few minutes."];
  const accountRecordUnavailable = (res: ServerResponse) => sendErrorPage(res, 503, ...ACCOUNT_RECORD_UNAVAILABLE, "temporarily_unavailable", { "retry-after": "60" });

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
    if (fromCookie.unavailable) return accountRecordUnavailable(res);
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
      if (fromCookie.unavailable) return accountRecordUnavailable(res);
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
      if (looksLikeAccountKey(form!.get("name"))) {
        // A returning person pasted their key into the name box: point them at the key form, keep nothing.
        sendConsent(res, request, requestToken, {
          status: 400,
          error: "That looks like an account key, not a name. To sign in with it, paste it below.",
          keyOpen: true,
        });
        return;
      }
      // A sign-in from a chat endpoint creates the account with one click and no name; the chat names it afterwards
      // (clockchain_create_account). Every other sign-in still needs a name.
      const name = fromChat(request) && !(form!.get("name") ?? "").trim() ? null : cleanAccountName(form!.get("name"));
      if (name === undefined) {
        sendConsent(res, request, requestToken, { status: 400, error: "Choose an account name of 1 to 40 characters." });
        return;
      }
      if (!allowAccountCreate(`create:${ipOf(req)}`)) {
        rateLimited("account_create");
        sendErrorPage(res, 429, "Too many new accounts", "Too many Clockchain accounts were created from this network in the last hour. Wait a while, or sign in with an account key.", "temporarily_unavailable", { "retry-after": "3600" });
        return;
      }
      if (!allowAccountCreateGlobal("create:all")) {
        rateLimited("account_create_global");
        sendErrorPage(res, 429, "Clockchain isn’t taking new accounts right now", "Many Clockchain accounts were created in the last hour. Try again later, or sign in with an account key you already have.", "temporarily_unavailable", { "retry-after": "3600" });
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
      res.end(accountKeyPage({
        action: AUTHORIZE_ACTION,
        appName: request.n,
        redirectHost: new URL(request.ru).host,
        accountName: displayAccountName(created.account),
        shortId: shortAccountId(created.account.acct),
        key: created.key,
        requestToken,
        grant,
      }));
      return;
    }

    if (decision === "continue") {
      // After the key page: the grant (minted by the create click) names the new account, cookie or not.
      const grant = unseal<GrantBlob>("grant", form!.get("grant"));
      let account: Account | undefined;
      try {
        account = grant && grant.via === "create" && safeEqual(grant.rid, rid) ? accounts.get(grant.acct) : undefined;
      } catch (e) {
        if (e instanceof AccountUnavailableError) return accountRecordUnavailable(res);
        throw e;
      }
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
      let account: Account | undefined;
      try {
        account = accounts.findByKey((form!.get("key") ?? "").trim());
      } catch (e) {
        // The key matched an index entry, but a record cannot be read: say so, not "key not recognized".
        if (e instanceof AccountUnavailableError) return accountRecordUnavailable(res);
        throw e;
      }
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
    if ((grant === "authorization_code" || grant === "refresh_token") && !replay) {
      // Without durable replay state a spent token could come back after a restart: refuse closed.
      sendOAuthError(res, 503, "temporarily_unavailable", "The token service is unavailable. Try again shortly.", { "retry-after": "60" });
      return;
    }
    const { usedCodes, usedRefreshTokens, revokedFamilies } = replay ?? ({} as NonNullable<typeof replay>);
    /** Records a spent or revoked id durably before anything is issued; false (after a 503) when it cannot. */
    const mark = (set: ExpiringSet, key: string, exp: number, failStatus = true): boolean => {
      try {
        set.add(key, exp);
        return true;
      } catch {
        log({ event: "oauth_replay_state_write_failed" });
        if (failStatus) sendOAuthError(res, 503, "temporarily_unavailable", "The token service is unavailable. Try again shortly.", { "retry-after": "60" });
        return false;
      }
    };
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
        mark(revokedFamilies, code.jti, nowSec() + REFRESH_TTL_S, false);
        log({ event: "oauth_code_reuse", acct: code.acct });
        sendOAuthError(res, 400, "invalid_grant", "The authorization code was already used.");
        return;
      }
      if (!mark(usedCodes, code.jti, code.exp)) return;
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
        mark(revokedFamilies, refresh.fam, nowSec() + REFRESH_TTL_S, false);
        log({ event: "oauth_refresh_reuse", acct: refresh.acct });
        sendOAuthError(res, 400, "invalid_grant", "The refresh token was already used.");
        return;
      }
      // Checked before the token is spent, so a limited refresh can be retried later with the same token.
      if (!allowIpRefresh(`refresh:${ipOf(req)}`) || !allowFamilyRefresh(`family:${refresh.fam}`)) {
        rateLimited("refresh");
        sendOAuthError(res, 429, "temporarily_unavailable", "Too many token refreshes. Try again later; this refresh token stays valid.", { "retry-after": "3600" });
        return;
      }
      if (!mark(usedRefreshTokens, refresh.jti, refresh.exp)) return;
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
      const font = FONT_FILES.get(path);
      if (font !== undefined) {
        sendFont(req, res, font);
        return true;
      }
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
    accounts,
    challenge(path, tokenPresented) {
      if (!mcpPaths.includes(path)) return undefined;
      const metadataUrl = `${base}/.well-known/oauth-protected-resource${path}`;
      return {
        "www-authenticate": `Bearer resource_metadata="${metadataUrl}"${tokenPresented ? ', error="invalid_token"' : ""}`,
      };
    },
  };
}
