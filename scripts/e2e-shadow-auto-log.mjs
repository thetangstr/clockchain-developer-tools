#!/usr/bin/env node
// End-to-end check of automatic logging (SHADOW_AUTO_LOG=1) against a running server: a task of 50 steps with
// shadow_log_step, each anchored in its own call, then close and verify. Every step is a real testnet write if the
// server's ledger is real: about steps + 2 anchors for one run, on one account.
//
//   SHADOW_TOKEN=<signed-in account token> node scripts/e2e-shadow-auto-log.mjs <base url> [token] [--path /shadow/mcp] [--steps 50] [--cli <shadow-verify.ts>] [--show-links]
//
// The token must come from sign-in (a POST /token token gets 403 account_required). Prints no token, and hides the
// viewer link's capability unless --show-links. Exit code 0 only if every step anchored and the record verifies.
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  const [, value] = args.splice(i, 2);
  return value;
};
const showLinks = args.includes("--show-links");
if (showLinks) args.splice(args.indexOf("--show-links"), 1);
const mcpPath = option("--path", "/shadow/mcp");
const steps = Number(option("--steps", "50"));
const cli = option("--cli", undefined);
const [baseArg, tokenArg] = args;
const token = tokenArg ?? process.env.SHADOW_TOKEN;
if (!baseArg || !token || !Number.isInteger(steps) || steps < 1) {
  console.error("Usage: SHADOW_TOKEN=<token> node scripts/e2e-shadow-auto-log.mjs <base url> [token] [--path /shadow/mcp] [--steps 50] [--cli <shadow-verify.ts>] [--show-links]");
  process.exit(64);
}
const base = baseArg.replace(/\/+$/, "");
const hide = (s) => (showLinks ? s : String(s).replace(/\/shadow\/([sp])\/[A-Za-z0-9_-]{22}/g, "/shadow/$1/<capability>"));
const problems = [];
const check = (ok, what) => {
  if (!ok) problems.push(what);
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}`);
};

let id = 0;
async function rpc(method, params) {
  const r = await fetch(`${base}${mcpPath}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
  });
  const text = await r.text();
  if (r.status !== 200) throw new Error(`${method}: HTTP ${r.status} ${text.slice(0, 200)}`);
  const body = JSON.parse(r.headers.get("content-type")?.includes("json") ? text : text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error).slice(0, 300)}`);
  return body.result;
}
async function tool(name, args = {}) {
  for (;;) {
    const r = await rpc("tools/call", { name, arguments: args });
    const value = JSON.parse(r.content[0].text);
    if (r.isError && value.error === "SHADOW_LOG_RATE") {
      // What the tool tells an agent to do: wait, then log the same step again.
      console.log("  (over the per-account step limit for this minute: waiting 30 s, as the tool says, and retrying)");
      await new Promise((resolve) => setTimeout(resolve, 30_000));
      continue;
    }
    if (r.isError) throw new Error(`${name}: ${value.error}: ${value.message}`);
    return value;
  }
}
const stepOf = (i) => {
  if (i === 0) return { kind: "task", content: `Build a small website (e2e run of ${steps} steps, ${new Date().toISOString()})` };
  if (i === steps - 1) return { kind: "message", content: "The site is finished." };
  switch (i % 4) {
    case 1: return { kind: "tool_call", content: { tool: "write_file", args: { path: `site/page-${i}.html` } } };
    case 2: return { kind: "tool_result", content: { tool: "write_file", result: `wrote page ${i}`, is_error: false } };
    case 3: return { kind: "file", content: { path: `site/page-${i}.html`, content: `<h1>Page ${i}</h1>` } };
    default: return { kind: "message", content: `Finished part ${i} of the site.` };
  }
};

console.log(`Automatic logging, ${steps} steps, on ${base}${mcpPath}`);
const tools = (await rpc("tools/list", {})).tools.map((t) => t.name);
check(tools.includes("shadow_log_step") && tools.includes("clockchain_logging"), "the server lists shadow_log_step and clockchain_logging");
check((await tool("clockchain_logging", { enabled: true })).logging.enabled === true, "logging is on for this account");

let sessionId;
const results = [];
const times = [];
for (let i = 0; i < steps; i++) {
  const t = performance.now();
  const r = await tool("shadow_log_step", { ...(sessionId ? { session_id: sessionId } : { title: "e2e: automatic logging" }), ...stepOf(i) });
  times.push(performance.now() - t);
  sessionId ??= r.session_id;
  results.push(r);
  console.log(`  step ${String(i + 1).padStart(3)}  seq ${String(r.seq).padStart(4)}  ${r.kind.padEnd(11)} hash ${r.hash.slice(0, 16)}…  block ${r.block_height ?? "-"}  ledger ${r.ledger_id ?? "-"}  ${r.anchor_status}  ${Math.round(times[i])} ms`);
}
const sorted = [...times].sort((a, b) => a - b);
console.log(`Time per step: median ${Math.round(sorted[sorted.length >> 1])} ms, slowest ${Math.round(sorted.at(-1))} ms, first ${Math.round(times[0])} ms (it also starts the session)`);
const distinct = (key) => new Set(results.map((r) => r[key])).size;
check(results.every((r) => r.anchor_status === "anchored"), `all ${steps} steps anchored (${results.filter((r) => r.anchor_status !== "anchored").length} not)`);
check(distinct("hash") === steps, "each step has its own hash");
check(distinct("ledger_id") === steps && results.every((r) => r.ledger_id), "each step has its own ledger ID");
check(results.every((r) => r.block_height), "each step has a block height");
check(results.every((r) => r.anchored_hash && r.anchored_hash !== r.hash && r.covers_steps === r.seq), "each anchor is a checkpoint over the steps up to and including that step");
console.log("\nFooter from the last step:\n" + hide(results.at(-1).show_user) + "\n");

const viewerOpen = await fetch(results.at(-1).viewer);
const viewerHtml = await viewerOpen.text();
check(viewerOpen.status === 200, `viewer while open: HTTP ${viewerOpen.status}, ${viewerHtml.length} bytes`);
const shown = results.filter((r) => viewerHtml.includes(r.hash) && (!r.ledger_id || viewerHtml.includes(r.ledger_id))).length;
check(shown === steps, `viewer shows hash and ledger ID for ${shown} of ${steps} steps`);

let t = performance.now();
const closed = await tool("shadow_close_session", { session_id: sessionId, status: "succeeded" });
check(closed.status === "closed" && closed.final_checkpoint.status === "anchored", `closed in ${Math.round(performance.now() - t)} ms; final checkpoint ${closed.final_checkpoint.status}, block ${closed.final_checkpoint.block ?? "-"}`);
t = performance.now();
const verified = await tool("shadow_verify", { session_id: sessionId });
console.log(`shadow_verify in ${Math.round(performance.now() - t)} ms: ${verified.result}. ${verified.online}`);
console.log(`Receipts checked online: ${verified.receipts_checked_online} of ${verified.receipts_total}`);
for (const c of verified.checks) console.log(`    ${String(c.status).padEnd(14)} ${String(c.name).padEnd(11)} ${c.reason ?? ""}`);
check(verified.result === "pass", `shadow_verify says ${verified.result}`);
const witness = verified.checks.find((c) => c.name === "witness")?.status;
check(witness === "pass", `witness is ${witness}${witness === "pass" ? "" : " (not every receipt could be confirmed online; see above)"}`);

const packetRes = await fetch(closed.links.packet);
const packetText = await packetRes.text();
check(packetRes.status === 200, `packet: HTTP ${packetRes.status}, ${packetText.length} bytes`);
if (cli) {
  const doc = JSON.parse(packetText);
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-e2e-"));
  writeFileSync(path.join(dir, "packet.json"), JSON.stringify(doc.packet, null, 1));
  writeFileSync(path.join(dir, "pin.json"), JSON.stringify(doc.pin, null, 2));
  const run = spawnSync(process.execPath, [cli, path.join(dir, "packet.json"), "--pin", path.join(dir, "pin.json")], { encoding: "utf8" });
  check(run.status === 0, `library CLI exit code ${run.status}: ${run.stdout.split("\n")[0]}`);
}
console.log(problems.length ? `\nFAILED: ${problems.join("; ")}` : `\nPASS: session ${sessionId}, ${steps} steps, ${results.length + 2} anchors or more.`);
process.exit(problems.length ? 1 : 0);
