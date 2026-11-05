#!/usr/bin/env node
// A test account for directory reviewers, with fictional sample records. Safe to run again: records are deleted 30 days
// after they start and a review can take longer, so re-running replaces the samples close to expiry and leaves the rest.
//
//   node scripts/seed-reviewer-account.mjs --base URL --key-file PATH [--name NAME] [--refresh-days 10] [--allow-production]
//
// First run: creates an account through the real sign-in pages and writes its key to --key-file (mode 0600; the file must
// not exist). Later runs: signs in with the key in that file. The key is printed nowhere and no token is ever stored, so
// keep the file in a password manager and enter the key only in the portal's secure review form.
//
// It refuses any base that is not local or staging unless --allow-production is passed. Unknown hosts count as production.
// Each new sample spends 3 ledger writes (start, checkpoint, close), and those hashes can't be removed.
//
// Exit codes: 0 done, and every sample checked out; 1 a step failed; 2 bad arguments or a refused base.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { baseKind } from "./e2e-shadow-public.mjs";

const REDIRECT_URI = "http://localhost:54321/callback";
const TIMEOUT_MS = 60_000;
const ACCEPT = "application/json, text/event-stream";
const KEY = /cck_[A-Za-z0-9_-]{32}/;
const DAY_MS = 86_400_000;
const USAGE = "Usage: node scripts/seed-reviewer-account.mjs --base URL --key-file PATH [--name NAME] [--refresh-days 10] [--allow-production]";

/** Fictional, and said to be. Each record is a small task an agent did, the way a real session looks. */
export const SAMPLES = [
  {
    title: "Sample (fictional): summarize a vendor invoice",
    steps: [
      ["task", "Summarize invoice 1042 from the fictional vendor Example Supplies."],
      ["tool_call", { tool: "read_file", args: { path: "invoices/1042.txt" } }],
      ["tool_result", { tool: "read_file", result: "Invoice 1042. Three lines. Total 310.00.", is_error: false }],
      ["message", "Invoice 1042 has three lines and totals 310.00."],
    ],
  },
  {
    title: "Sample (fictional): draft a reply to a customer",
    steps: [
      ["task", "Draft a short reply to a fictional customer who asked about delivery times."],
      ["message", "Thanks for asking. Orders usually arrive in five working days."],
      ["note", "Draft only. Nothing was sent."],
    ],
  },
  {
    title: "Sample (fictional): check a release note",
    steps: [
      ["task", "Check that a fictional release note names every change."],
      ["tool_call", { tool: "list_changes", args: { release: "1.2.0" } }],
      ["tool_result", { tool: "list_changes", result: ["Fix login", "Add export"], is_error: false }],
      ["message", "The note names both changes."],
    ],
  },
];

/** The parsed command line, or { error }. */
export function parseArgs(argv) {
  const opts = { base: undefined, keyFile: undefined, name: "Directory reviewer", refreshDays: 10, allowProduction: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    if (arg === "--base") opts.base = next();
    else if (arg === "--key-file") opts.keyFile = next();
    else if (arg === "--name") opts.name = next();
    else if (arg === "--refresh-days") opts.refreshDays = Number(next());
    else if (arg === "--allow-production") opts.allowProduction = true;
    else return { error: `unknown argument: ${arg}` };
  }
  if (!opts.base) return { error: "--base is required" };
  if (!opts.keyFile) return { error: "--key-file is required: the key goes there, and nowhere else" };
  if (!Number.isInteger(opts.refreshDays) || opts.refreshDays < 0 || opts.refreshDays > 29) return { error: "--refresh-days must be a whole number from 0 to 29" };
  let url;
  try {
    url = new URL(opts.base);
  } catch {
    return { error: `not a URL: ${opts.base}` };
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return { error: "--base must be a plain http or https URL" };
  opts.base = `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
  return opts;
}

class Failed extends Error {}

async function http(url, init = {}) {
  let res;
  try {
    res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS), ...init });
  } catch (e) {
    throw new Failed(`no response from ${new URL(url).pathname} (${e?.cause?.code ?? e?.name ?? "network error"})`);
  }
  return { status: res.status, headers: res.headers, text: await res.text() };
}
const jsonOf = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};
/** The status, and the server's error code if it gave one. Never a body: a page here can hold a key. */
const brief = (res) => {
  const code = jsonOf(res.text)?.error;
  return `HTTP ${res.status}${typeof code === "string" && /^[a-z_]{1,40}$/.test(code) ? ` ${code}` : ""}`;
};

/** Signs in through the real pages: with `key` if given, else by creating an account. Returns { token, key? }. */
export async function signIn(base, { key, name }) {
  const resource = `${base}/shadow/mcp`;
  const origin = new URL(base).origin;
  const reg = await http(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Reviewer account seeding", redirect_uris: [REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }),
  });
  const clientId = jsonOf(reg.text)?.client_id;
  if (reg.status !== 201 || !clientId) throw new Failed(`registering a client: ${brief(reg)}`);
  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT_URI, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: randomBytes(8).toString("hex"), resource });
  const page = await http(`${base}/oauth/authorize?${query}`, { headers: { accept: "text/html" } });
  const request = /name="request" value="([^"]+)"/.exec(page.text)?.[1];
  if (page.status !== 200 || !request) throw new Failed(`opening the sign-in page: ${brief(page)}`);
  const click = (fields) => http(`${base}/oauth/authorize`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin }, body: new URLSearchParams({ request, ...fields }) });

  let created;
  let done;
  if (key) {
    done = await click({ decision: "signin", key });
    if (done.status !== 303) throw new Failed(`signing in with the key in the key file: ${brief(done)}. If this account was deleted, move the key file away to create a new one.`);
  } else {
    const made = await click({ decision: "create", name });
    created = KEY.exec(made.text)?.[0];
    const grant = /name="grant" value="([^"]+)"/.exec(made.text)?.[1];
    if (made.status !== 200 || !created || !grant) throw new Failed(`creating the account: ${brief(made)}`);
    done = await click({ decision: "continue", grant });
    if (done.status !== 303) throw new Failed(`continuing to the app: ${brief(done)}`);
  }
  const code = new URL(done.headers.get("location")).searchParams.get("code");
  const exchanged = await http(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier, resource }) });
  const token = jsonOf(exchanged.text)?.access_token;
  if (exchanged.status !== 200 || !token) throw new Failed(`exchanging the code: ${brief(exchanged)}`);
  return { token, key: created };
}

/** A caller for one MCP endpoint with a signed-in token. Tool errors come back as { error, message }. */
export function toolCaller(base, token, path = "/shadow/mcp") {
  let id = 0;
  return async (name, args = {}) => {
    const res = await http(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name, arguments: args } }),
    });
    if (res.status !== 200) throw new Failed(`${name}: ${brief(res)}`);
    const data = res.text.split("\n").find((l) => l.startsWith("data:"));
    const result = jsonOf(data ? data.slice(5) : res.text)?.result;
    const value = jsonOf(result?.content?.[0]?.text ?? "");
    if (value === undefined) throw new Failed(`${name}: an answer that could not be read`);
    return value;
  };
}

/** Adds one sample session, closed and anchored. */
export async function addSample(call, sample) {
  const started = await call("shadow_start_session", { title: sample.title });
  if (!started.session_id) throw new Failed(`shadow_start_session: ${started.error ?? "no session"}`);
  for (const [kind, content] of sample.steps) {
    const step = await call("shadow_record", { session_id: started.session_id, agent: "agent", kind, content });
    if (!step.hash) throw new Failed(`shadow_record: ${step.error ?? "no hash"}`);
  }
  const checkpoint = await call("shadow_checkpoint", { session_id: started.session_id });
  if (checkpoint.error) throw new Failed(`shadow_checkpoint: ${checkpoint.error}`);
  const closed = await call("shadow_close_session", { session_id: started.session_id, status: "succeeded" });
  if (closed.status !== "closed") throw new Failed(`shadow_close_session: ${closed.error ?? "not closed"}`);
  return started.session_id;
}

/** Keeps a fresh copy of each sample: replaces one close to expiry, and adds one that's missing. */
export async function topUpSamples(call, { refreshDays, nowMs = Date.now(), log = () => {} }) {
  const listed = await call("shadow_list_sessions");
  if (!Array.isArray(listed.sessions)) throw new Failed(`shadow_list_sessions: ${listed.error ?? "no list"}`);
  let added = 0, kept = 0, removed = 0;
  for (const sample of SAMPLES) {
    const copies = listed.sessions.filter((s) => s.title === sample.title);
    const fresh = copies.filter((s) => Date.parse(s.expires_at) - nowMs > refreshDays * DAY_MS);
    if (fresh.length === 0) {
      await addSample(call, sample);
      added++;
    } else kept++;
    for (const stale of copies.filter((s) => !fresh.includes(s))) {
      const gone = await call("shadow_delete_session", { session_id: stale.session_id });
      if (gone.status !== "deleted") throw new Failed(`shadow_delete_session: ${gone.error ?? "not deleted"}`);
      removed++;
    }
  }
  log(`samples: ${added} added, ${kept} still fresh, ${removed} old ones deleted`);
  return { added, kept, removed };
}

function keyFileText(base, key, name) {
  return [
    "Clockchain directory reviewer account",
    "",
    `Account: ${name}`,
    `Server: ${base}`,
    `Key: ${key}`,
    "",
    "Keep this file private. Anyone with this key can use the account, and read and delete its records.",
    "Enter the key only in the directory portal's secure review form. Never put it in a plugin package or a chat.",
    "",
    "For the reviewer: when the Clockchain window opens, choose \"I have an account key\", paste the key and click Sign in.",
    "Do not choose Create account. All records in this account are fictional. Please use only fictional data:",
    "hashes written to the testnet ledger can't be removed.",
    "",
    `To refresh the samples: node scripts/seed-reviewer-account.mjs --base ${base} --key-file THIS_FILE`,
    "To retire the account: ask for \"delete my Clockchain account\" in a connected chat, or call clockchain_delete_account {confirm: true}.",
    "",
  ].join("\n");
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) {
    console.error(`${opts.error}\n${USAGE}`);
    return 2;
  }
  const kind = baseKind(opts.base);
  if (kind === "production" && !opts.allowProduction) {
    console.error(`Refusing ${opts.base}: this creates an account and spends ledger writes, whose hashes can't be removed, and this is not a local or staging base. Pass --allow-production to override.`);
    return 2;
  }
  let key;
  if (existsSync(opts.keyFile)) {
    key = KEY.exec(readFileSync(opts.keyFile, "utf8"))?.[0];
    if (!key) {
      console.error(`${opts.keyFile} holds no account key. Give a path that doesn't exist yet to create a new account.`);
      return 2;
    }
  }
  try {
    console.log(`Reviewer account on ${opts.base} (${kind}): ${key ? "signing in with the key file" : "creating a new account"}`);
    const session = await signIn(opts.base, { key, name: opts.name });
    if (session.key) {
      writeFileSync(opts.keyFile, keyFileText(opts.base, session.key, opts.name), { mode: 0o600, flag: "wx" });
      console.log(`The account key is in ${opts.keyFile}, mode 0600.`);
    }
    const call = toolCaller(opts.base, session.token);
    await topUpSamples(call, { refreshDays: opts.refreshDays, log: console.log });

    // What to paste into the review forms, and a check that each sample really checks out.
    const { sessions } = await call("shadow_list_sessions");
    let bad = 0;
    console.log("\nSample records in this account:");
    for (const s of sessions.filter((x) => SAMPLES.some((sample) => sample.title === x.title))) {
      const report = await call("shadow_verify", { session_id: s.session_id });
      if (report.result !== "pass") bad++;
      console.log(`- ${s.title}: started ${s.created_at.slice(0, 10)}, deleted by ${s.expires_at.slice(0, 10)}, verify ${report.result ?? report.error}`);
    }
    console.log(`\nRun this again before ${sessions.map((s) => s.expires_at).sort()[0]?.slice(0, 10) ?? "they expire"}: records are deleted 30 days after they start.`);
    if (bad) {
      console.error(`${bad} sample(s) didn't pass verify.`);
      return 1;
    }
    return 0;
  } catch (e) {
    if (!(e instanceof Failed)) throw e;
    console.error(`Failed: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
