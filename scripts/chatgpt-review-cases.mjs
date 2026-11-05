#!/usr/bin/env node
// Drives the tools behind the test cases in infra/chatgpt-plugin/clockchain-shadow/plugin.json against a server, and checks
// what the server returns. No model runs: this can't show that ChatGPT picks the right tool or answers well. See
// infra/chatgpt-plugin/README.md.
//
//   node scripts/chatgpt-review-cases.mjs --base URL --key-file PATH [--allow-production]
//
// It signs in with the account key in --key-file (scripts/seed-reviewer-account.mjs writes one) and expects sample records
// there. The sessions it starts spend ledger writes, whose hashes can't be removed, and it deletes those sessions at the
// end. It refuses any base that is not local or staging unless --allow-production is passed.
//
// Exit codes: 0 every case passed; 1 a case failed; 2 bad arguments or a refused base. Output holds no key, token or link.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { baseKind } from "./e2e-shadow-public.mjs";
import { parseArgs as seedArgs, signIn, toolCaller } from "./seed-reviewer-account.mjs";

export const PLUGIN = fileURLToPath(new URL("../infra/chatgpt-plugin/clockchain-shadow/plugin.json", import.meta.url));
const ACCEPT = "application/json, text/event-stream";
const KEY = /cck_[A-Za-z0-9_-]{32}/;
/** Anything a tool could use to move value. Shadow has none, and a description can't suggest it. */
const MONEY = /\b(transfer|payment|pay|wallet|purchase|trade|send (money|crypto|funds))\b/i;
const VERDICT = /not a verdict on truth, compliance/i;

const rpc = async (base, path, token, method, params) => {
  const res = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT, ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(data ? data.slice(5) : text).result;
};

const within = (url, base) => (url ? `${base}${new URL(url).pathname}` : undefined);

/** One check per test case, by its description in plugin.json. Each returns what is wrong, or nothing. */
function caseChecks(base, call, created) {
  const start = async (title) => {
    const s = await call("shadow_start_session", { title });
    if (!s.session_id) throw new Error(`shadow_start_session: ${s.error}`);
    created.push(s.session_id);
    return s;
  };
  const newest = async () => (await call("shadow_list_sessions")).sessions[0];
  return {
    positive: {
      "Record and close a short task": async () => {
        const s = await start("A flight recorder summary");
        for (const [kind, content] of [["task", "Write a two-line summary of what a flight recorder does."], ["message", "A flight recorder keeps a record of what happened.\nAnyone can check it later."]]) {
          const step = await call("shadow_record", { session_id: s.session_id, agent: "agent", kind, content });
          if (!step.hash) return `shadow_record ${kind}: ${step.error}`;
        }
        const closed = await call("shadow_close_session", { session_id: s.session_id, status: "succeeded" });
        if (closed.status !== "closed") return `not closed: ${closed.error}`;
        if (!closed.pin) return "no pin";
        if (!closed.links?.viewer || !closed.links?.packet) return "no links";
        if (!/Anyone with these links can read the whole record/.test(closed.links_note ?? "")) return "it doesn't say that anyone with the link can read the record";
        const page = await fetch(within(closed.links.viewer, base));
        if (page.status !== 200) return `the viewer link answers ${page.status}`;
        return undefined;
      },
      "Verify a session": async () => {
        const closed = (await call("shadow_list_sessions")).sessions.find((s) => s.status === "closed");
        if (!closed) return "no closed session to verify";
        const report = await call("shadow_verify", { session_id: closed.session_id });
        if (!["pass", "indeterminate", "fail"].includes(report.result)) return `no result: ${report.error}`;
        if (!Array.isArray(report.checks) || report.checks.length === 0) return "no checks";
        if (!VERDICT.test(report.interpretation ?? "")) return "it doesn't say a pass is no verdict on truth or compliance";
        return undefined;
      },
      "List sessions": async () => {
        const { sessions } = await call("shadow_list_sessions");
        if (!sessions?.length) return "no sessions";
        for (const s of sessions) if (!s.title || !s.status || typeof s.steps !== "number" || !s.expires_at) return "a session lacks its title, status, step count or expiry";
        const dates = sessions.map((s) => s.created_at);
        if (dates.some((d, i) => i > 0 && dates[i - 1] < d)) return "not newest first";
        return undefined;
      },
      "Inspect a session": async () => {
        const first = await newest();
        if (!first) return "no sessions";
        const s = await call("shadow_get_session", { session_id: first.session_id });
        if (typeof s.steps !== "number" || !s.expires_at) return "no step count or deletion date";
        if (!s.anchors?.length || !s.anchors.every((a) => a.ledger_id && a.block)) return "no anchors with a block and a ledger id";
        if (!s.links?.viewer) return "no links";
        return undefined;
      },
      "Checkpoint mid-task": async () => {
        const s = await start("Review test");
        await call("shadow_record", { session_id: s.session_id, agent: "agent", kind: "note", content: "started review" });
        const { checkpoint } = await call("shadow_checkpoint", { session_id: s.session_id });
        if (checkpoint?.status === "anchored") return checkpoint.block && checkpoint.ledger_id ? undefined : "anchored, but no block or ledger id";
        return checkpoint?.status === "pending" ? undefined : `checkpoint status: ${checkpoint?.status}`;
      },
    },
    negative: {
      "No recording unless asked": async ({ token }) => {
        const before = (await call("shadow_list_sessions")).sessions.length;
        await rpc(base, "/shadow/mcp", token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "review-cases", version: "1" } });
        await rpc(base, "/shadow/mcp", token, "tools/list", {});
        if ((await call("shadow_list_sessions")).sessions.length !== before) return "connecting started a session";
        const { instructions } = await rpc(base, "/shadow/mcp", token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "review-cases", version: "1" } });
        if (!/records a task only when the person asks/.test(instructions ?? "")) return "the instructions don't say that it records only when asked";
        const { tools } = await rpc(base, "/shadow/mcp", token, "tools/list", {});
        if (tools.some((t) => t.name.startsWith("shadow_log_") || t.name === "clockchain_logging")) return "this endpoint carries logging by default, which a listed endpoint must not";
        return undefined;
      },
      "No money": async ({ token }) => {
        const { tools } = await rpc(base, "/shadow/mcp", token, "tools/list", {});
        const bad = tools.filter((t) => MONEY.test(`${t.name} ${t.title}`) || MONEY.test(t.description));
        return bad.length ? `tools that read as moving money: ${bad.map((t) => t.name).join(", ")}` : undefined;
      },
      "No verdict on truth": async () => {
        const closed = (await call("shadow_list_sessions")).sessions.find((s) => s.status === "closed");
        if (!closed) return "no closed session to check";
        const report = await call("shadow_verify", { session_id: closed.session_id });
        if (!VERDICT.test(report.interpretation ?? "")) return "a check doesn't say it is no verdict on truth or compliance";
        return undefined;
      },
    },
  };
}

/** Runs every case in plugin.json, in order. Returns one row per case. A case with no check here is a failure. */
export async function runCases(base, key) {
  const plugin = JSON.parse(readFileSync(PLUGIN, "utf8"));
  const cases = plugin.extensions["com.openai"].review.test_cases;
  const { token } = await signIn(base, { key });
  const call = toolCaller(base, token);
  const created = [];
  const checks = caseChecks(base, call, created);
  const rows = [];
  const run = async (group, description, fn) => {
    let problem;
    try {
      problem = fn ? await fn({ token }) : "no check for this case";
    } catch (e) {
      problem = e.message;
    }
    rows.push({ group, description, problem });
  };
  for (const c of cases.positive) await run("positive", c.description, checks.positive[c.description]);
  for (const c of cases.negative) {
    const name = c.description.split(". Expected")[0];
    await run("negative", name, checks.negative[name]);
  }
  // Leave the account as it was: only its samples.
  for (const id of created) await call("shadow_delete_session", { session_id: id });
  return rows;
}

async function main(argv) {
  const opts = seedArgs(argv);
  if (opts.error) {
    console.error(`${opts.error}\nUsage: node scripts/chatgpt-review-cases.mjs --base URL --key-file PATH [--allow-production]`);
    return 2;
  }
  if (baseKind(opts.base) === "production" && !opts.allowProduction) {
    console.error(`Refusing ${opts.base}: these cases spend ledger writes, and this is not a local or staging base. Pass --allow-production to override.`);
    return 2;
  }
  const key = KEY.exec(readFileSync(opts.keyFile, "utf8"))?.[0];
  if (!key) {
    console.error(`${opts.keyFile} holds no account key.`);
    return 2;
  }
  const rows = await runCases(opts.base, key);
  for (const r of rows) console.log(`${r.problem ? "FAIL" : "PASS"}  ${r.group}: ${r.description}${r.problem ? `: ${r.problem}` : ""}`);
  const failed = rows.filter((r) => r.problem).length;
  console.log(`\n${rows.length - failed} passed, ${failed} failed. No model ran: this checks each tool, not what ChatGPT chooses to do.`);
  return failed ? 1 : 0;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
