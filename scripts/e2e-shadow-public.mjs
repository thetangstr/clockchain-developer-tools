#!/usr/bin/env node
// Checks hosted Shadow from the outside, the way an agent finds and connects to it.
//
//   node scripts/e2e-shadow-public.mjs [--base URL] [--write [--allow-production]]
//
// Default (read-only), against --base (default https://mcp.clockchain.network): health, the discovery files, OAuth
// metadata, the expected 401s and 403s, tools/list on the chat endpoint, and a free key on /mcp. It mints that free
// key with POST /token (a signed token, no account and no ledger write) and calls only get_time with it. The tool it
// sends without a credential is clockchain_whoami, which writes nothing even if a server wrongly let it through.
//
// --write also creates an account and spends ledger writes: one full record, from sign-in to verify. It refuses any
// base that is not local or staging unless --allow-production is passed. Unknown hosts count as production.
//
// Exit codes: 0 every check passed; 1 a check failed or was skipped; 2 bad arguments or a refused --write.
// Output never contains a key, a token or a viewer link.
import { createHash, randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DEFAULT_BASE = "https://mcp.clockchain.network";
const TIMEOUT_MS = 30_000;
const ACCEPT = "application/json, text/event-stream";
const SHADOW_TOOLS = ["shadow_start_session", "shadow_record", "shadow_checkpoint", "shadow_close_session", "shadow_get_session", "shadow_list_sessions", "shadow_verify"];
const ACCOUNT_TOOLS = ["clockchain_create_account", "clockchain_whoami", "clockchain_signup_help"];
const REDIRECT_URI = "http://localhost:54321/callback";

/** "local", "staging" or "production". Fails closed: anything not known to be local or staging is production. */
export function baseKind(raw) {
  const url = new URL(raw);
  if (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) return "local";
  if (url.hostname === "mcp.clockchain.network" && url.pathname.replace(/\/+$/, "") === "/staging") return "staging";
  return "production";
}

/** The parsed command line, or { error } for anything this script does not understand. */
export function parseArgs(argv) {
  const opts = { base: DEFAULT_BASE, write: false, allowProduction: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--write") opts.write = true;
    else if (arg === "--allow-production") opts.allowProduction = true;
    else if (arg === "--help" || arg === "-h") opts.help = true;
    else if (arg === "--base") {
      if (argv[i + 1] === undefined) return { error: "--base needs a URL" };
      opts.base = argv[++i];
    } else if (arg.startsWith("--base=")) opts.base = arg.slice("--base=".length);
    else return { error: `unknown argument: ${arg}` };
  }
  let url;
  try {
    url = new URL(opts.base);
  } catch {
    return { error: `not a URL: ${opts.base}` };
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    return { error: "--base must be a plain http or https URL" };
  }
  opts.base = `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
  return opts;
}

class Report {
  passed = 0;
  failed = 0;
  skipped = 0;
  pass(name, detail = "") { this.passed++; this.#line("PASS", name, detail); }
  fail(name, detail = "") { this.failed++; this.#line("FAIL", name, detail); }
  skip(name, detail = "") { this.skipped++; this.#line("SKIP", name, detail); }
  check(name, ok, detail = "") { if (ok) this.pass(name, detail); else this.fail(name, detail); return ok; }
  #line(word, name, detail) { console.log(`${word}  ${name}${detail ? `: ${detail}` : ""}`); }
}

/** One HTTP call. Never follows a redirect; a network failure comes back as status 0. */
async function http(url, init = {}) {
  try {
    const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS), ...init });
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch (e) {
    return { status: 0, headers: new Headers(), text: "", error: e?.cause?.code ?? e?.name ?? "network error" };
  }
}

function jsonOf(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** The status, plus the server's short error code when it has one. Never the body: it may hold a key. */
function brief(res) {
  if (res.status === 0) return `no response (${res.error})`;
  const code = jsonOf(res.text)?.error;
  return `HTTP ${res.status}${typeof code === "string" && /^[a-z_]{1,40}$/.test(code) ? ` ${code}` : ""}`;
}

/** One JSON-RPC message over Streamable HTTP. `message` is the parsed reply, from plain JSON or an SSE data line. */
async function rpc(url, method, params, headers = {}) {
  const res = await http(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT, ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const data = res.text.split("\n").find((l) => l.startsWith("data:"));
  return { ...res, message: jsonOf(data ? data.slice(5) : res.text) };
}

const initializeParams = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e-shadow-public", version: "1" } };

/** A tool result's JSON, or undefined when the call failed. */
async function callTool(url, name, args, headers) {
  const res = await rpc(url, "tools/call", { name, arguments: args }, headers);
  const result = res.message?.result;
  if (res.status !== 200 || !result || result.isError) return { res, value: undefined };
  return { res, value: jsonOf(result.content?.[0]?.text ?? "") };
}

/** The phrases not in the text, ignoring how the text is wrapped. */
const missing = (text, phrases) => {
  const flat = text.replace(/\s+/g, " ");
  return phrases.filter((p) => !flat.includes(p));
};

async function checkDiscovery(r, base) {
  const shadow = `${base}/shadow/mcp`;
  const chat = `${base}/shadow/chat/mcp`;
  const facts = [shadow, chat, "Sign in when needed", "Register automatically", `${base}/token`, "An account is required", "30 days", "cannot be revoked"];

  const llms = await http(`${base}/llms.txt`);
  const gaps = missing(llms.text, facts);
  r.check("/llms.txt names Shadow and how to connect", llms.status === 200 && gaps.length === 0, llms.status === 200 ? (gaps.length ? `missing: ${gaps.join(", ")}` : "") : brief(llms));

  const install = await http(`${base}/install.txt`);
  r.check("/install.txt matches /llms.txt", install.status === 200 && install.text === llms.text, brief(install));

  const res = await http(`${base}/.well-known/mcp.json`);
  const manifest = jsonOf(res.text);
  const block = manifest?.shadow;
  r.check("/.well-known/mcp.json parses and names /mcp", res.status === 200 && typeof manifest?.endpoint === "string", brief(res));
  r.check(
    "/.well-known/mcp.json has a shadow block",
    block?.endpoints?.signIn === shadow &&
      block?.endpoints?.chat === chat &&
      block?.authentication?.accountRequired === true &&
      block?.clients?.claudeAi?.settings?.includes("Sign in when needed") &&
      block?.clients?.claudeAi?.settings?.includes("Register automatically"),
    block ? "" : "no shadow block",
  );

  const connect = await http(`${base}/shadow/connect`);
  const connectGaps = missing(connect.text, facts);
  r.check("/shadow/connect explains how to connect", connect.status === 200 && connectGaps.length === 0, connect.status === 200 ? (connectGaps.length ? `missing: ${connectGaps.join(", ")}` : "") : brief(connect));
}

async function checkOAuthMetadata(r, base) {
  const as = await http(`${base}/.well-known/oauth-authorization-server`);
  const meta = jsonOf(as.text);
  r.check(
    "OAuth server metadata",
    as.status === 200 &&
      meta?.issuer === base &&
      meta?.authorization_endpoint === `${base}/oauth/authorize` &&
      meta?.token_endpoint === `${base}/oauth/token` &&
      meta?.registration_endpoint === `${base}/oauth/register` &&
      meta?.code_challenge_methods_supported?.includes("S256"),
    brief(as),
  );
  for (const p of ["/shadow/mcp", "/shadow/chat/mcp"]) {
    const res = await http(`${base}/.well-known/oauth-protected-resource${p}`);
    const doc = jsonOf(res.text);
    r.check(`OAuth resource metadata for ${p}`, res.status === 200 && doc?.resource === `${base}${p}` && doc?.authorization_servers?.includes(base), brief(res));
  }
}

async function checkRefusals(r, base) {
  const noKey = await rpc(`${base}/mcp`, "tools/list", {});
  r.check("/mcp without a credential is 401", noKey.status === 401, brief(noKey));

  const challengeOf = (res) => res.headers.get("www-authenticate") ?? "";
  const shadow = await rpc(`${base}/shadow/mcp`, "tools/list", {});
  r.check(
    "/shadow/mcp without a credential is 401 and starts sign-in",
    shadow.status === 401 && challengeOf(shadow).includes(`${base}/.well-known/oauth-protected-resource/shadow/mcp`),
    brief(shadow),
  );
  const chat = await rpc(`${base}/shadow/chat/mcp`, "tools/call", { name: "clockchain_whoami", arguments: {} });
  r.check(
    "/shadow/chat/mcp tool call without a credential is 401 and starts sign-in",
    chat.status === 401 && challengeOf(chat).includes(`${base}/.well-known/oauth-protected-resource/shadow/chat/mcp`),
    brief(chat),
  );

  const link = await http(`${base}/shadow/s/AAAAAAAAAAAAAAAAAAAAAA`);
  r.check("An unknown viewer link is 404", link.status === 404, brief(link));
}

async function checkChatDiscovery(r, base) {
  const url = `${base}/shadow/chat/mcp`;
  const init = await rpc(url, "initialize", initializeParams);
  r.check("/shadow/chat/mcp initialize works before sign-in", init.status === 200 && typeof init.message?.result?.instructions === "string", brief(init));
  const list = await rpc(url, "tools/list", {});
  const names = list.message?.result?.tools?.map((t) => t.name) ?? [];
  const gaps = [...SHADOW_TOOLS, ...ACCOUNT_TOOLS].filter((n) => !names.includes(n));
  r.check("/shadow/chat/mcp tools/list works before sign-in", list.status === 200 && gaps.length === 0, list.status === 200 ? (gaps.length ? `missing: ${gaps.join(", ")}` : `${names.length} tools`) : brief(list));
}

async function checkFreeKey(r, base) {
  const minted = await http(`${base}/token`, { method: "POST" });
  const token = jsonOf(minted.text)?.token;
  const dependents = ["/mcp tools/list with the free key", "get_time with the free key", "/shadow/mcp refuses the free key with 403", "/shadow/chat/mcp refuses the free key with 403"];
  if (minted.status === 429) {
    r.skip("POST /token gives a free key", "HTTP 429, the per-address limit; try again later");
    for (const name of dependents) r.skip(name, "no key");
    return;
  }
  if (!r.check("POST /token gives a free key", minted.status === 200 && typeof token === "string", brief(minted))) {
    for (const name of dependents) r.skip(name, "no key");
    return;
  }
  const headers = { "x-api-key": token };
  const list = await rpc(`${base}/mcp`, "tools/list", {}, headers);
  const names = list.message?.result?.tools?.map((t) => t.name) ?? [];
  const advertised = /(\d+) tools/.exec(jsonOf((await http(`${base}/.well-known/mcp.json`)).text)?.description ?? "")?.[1];
  r.check(
    dependents[0],
    list.status === 200 && names.includes("get_time") && (advertised === undefined || Number(advertised) === names.length),
    list.status === 200 ? `${names.length} tools${advertised === undefined ? "" : `, manifest says ${advertised}`}` : brief(list),
  );
  const time = await callTool(`${base}/mcp`, "get_time", {}, headers);
  r.check(dependents[1], time.value !== undefined, time.value === undefined ? brief(time.res) : "");
  for (const [name, p] of [[dependents[2], "/shadow/mcp"], [dependents[3], "/shadow/chat/mcp"]]) {
    const res = await rpc(`${base}${p}`, "tools/list", {}, headers);
    r.check(name, res.status === 403 && jsonOf(res.text)?.error === "account_required", brief(res));
  }
}

/** Sign up through the real pages, as a person's browser would: one new account. Returns an access token, or undefined. */
async function signIn(r, base, resource) {
  const origin = new URL(base).origin;
  const reg = await http(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Shadow public check", redirect_uris: [REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }),
  });
  const clientId = jsonOf(reg.text)?.client_id;
  if (!r.check("Register an OAuth client", reg.status === 201 && typeof clientId === "string", brief(reg))) return undefined;

  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: randomBytes(8).toString("hex"),
    resource,
  });
  const page = await http(`${base}/oauth/authorize?${query}`, { headers: { accept: "text/html" } });
  const request = /name="request" value="([^"]+)"/.exec(page.text)?.[1];
  if (!r.check("Open the sign-in page", page.status === 200 && request !== undefined, brief(page))) return undefined;

  const click = (fields) =>
    http(`${base}/oauth/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin },
      body: new URLSearchParams({ request, ...fields }),
    });
  const created = await click({ decision: "create", ...(/name="name"/.test(page.text) ? { name: "Shadow public check" } : {}) });
  const grant = /name="grant" value="([^"]+)"/.exec(created.text)?.[1];
  const shownOnce = /cck_[A-Za-z0-9_-]{32}/.test(created.text);
  if (!r.check("Create an account; the page shows its key", created.status === 200 && grant !== undefined && shownOnce, brief(created))) return undefined;

  const cont = await click({ decision: "continue", grant });
  const code = cont.headers.get("location") ? new URL(cont.headers.get("location")).searchParams.get("code") : null;
  if (!r.check("Continue to the app with a code", cont.status === 303 && code !== null, brief(cont))) return undefined;

  const exchanged = await http(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier, resource }),
  });
  const token = jsonOf(exchanged.text)?.access_token;
  r.check("Exchange the code for a token", exchanged.status === 200 && typeof token === "string", brief(exchanged));
  return token;
}

/** One full record on a new account: start, record, checkpoint, close, verify, and open both links. */
async function checkWriteCycle(r, base) {
  const url = `${base}/shadow/chat/mcp`;
  const token = await signIn(r, base, url);
  if (!token) {
    r.skip("Record, anchor, close and verify", "no sign-in");
    return;
  }
  const headers = { authorization: `Bearer ${token}` };

  const who = await callTool(url, "clockchain_whoami", {}, headers);
  r.check("clockchain_whoami names the new account", who.value?.status === "signed_in", brief(who.res));

  const started = await callTool(url, "shadow_start_session", { title: "e2e-shadow-public check", agents: [{ id: "check" }] }, headers);
  const id = started.value?.session_id;
  if (!r.check("shadow_start_session", typeof id === "string", brief(started.res))) {
    r.skip("Record, anchor, close and verify", "no session");
    return;
  }
  for (const [kind, content] of [["task", "Scripted check of hosted Shadow"], ["message", "The scripted check ran."]]) {
    const step = await callTool(url, "shadow_record", { session_id: id, agent: "check", kind, content }, headers);
    r.check(`shadow_record ${kind}`, typeof step.value?.hash === "string", brief(step.res));
  }
  const anchored = await callTool(url, "shadow_checkpoint", { session_id: id }, headers);
  r.check("shadow_checkpoint anchors", anchored.value?.checkpoint?.status === "anchored", anchored.value?.checkpoint?.status ?? brief(anchored.res));
  const closed = await callTool(url, "shadow_close_session", { session_id: id, status: "succeeded" }, headers);
  r.check("shadow_close_session", closed.value?.status === "closed", brief(closed.res));
  const verified = await callTool(url, "shadow_verify", { session_id: id }, headers);
  const notPassing = (verified.value?.checks ?? []).filter((c) => c.status === "fail" || c.status === "indeterminate").map((c) => c.name);
  r.check("shadow_verify passes", verified.value?.result === "pass", verified.value ? [verified.value.result, ...notPassing].join(" ") : brief(verified.res));

  const links = closed.value?.links;
  if (!links) {
    r.skip("The viewer link opens", "no links");
    r.skip("The packet link opens", "no links");
  } else {
    const viewer = await http(links.viewer);
    r.check("The viewer link opens", viewer.status === 200, brief(viewer));
    const packet = await http(links.packet);
    r.check("The packet link opens", packet.status === 200 && jsonOf(packet.text) !== undefined, brief(packet));
  }

  const other = await rpc(`${base}/shadow/mcp`, "tools/list", {}, headers);
  r.check("The same account works on /shadow/mcp", other.status === 200, brief(other));
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) {
    console.error(`${opts.error}\nUsage: node scripts/e2e-shadow-public.mjs [--base URL] [--write [--allow-production]]`);
    return 2;
  }
  if (opts.help) {
    console.log("Usage: node scripts/e2e-shadow-public.mjs [--base URL] [--write [--allow-production]]");
    return 0;
  }
  const kind = baseKind(opts.base);
  if (opts.write && kind === "production" && !opts.allowProduction) {
    console.error(`Refusing --write against ${opts.base}: it creates an account and spends ledger writes, and this is not a local or staging base. Pass --allow-production to override.`);
    return 2;
  }
  console.log(`Shadow public check: ${opts.base} (${kind}), ${opts.write ? "WRITE: creates an account and spends ledger writes" : "read-only"}`);

  const r = new Report();
  const health = await http(`${opts.base}/health`);
  r.check("/health", health.status === 200 && jsonOf(health.text)?.status === "ok", brief(health));
  await checkDiscovery(r, opts.base);
  await checkOAuthMetadata(r, opts.base);
  await checkRefusals(r, opts.base);
  await checkChatDiscovery(r, opts.base);
  await checkFreeKey(r, opts.base);
  if (opts.write) await checkWriteCycle(r, opts.base);

  console.log(`\n${r.passed} passed, ${r.failed} failed, ${r.skipped} skipped`);
  return r.failed === 0 && r.skipped === 0 ? 0 : 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
