// Execution-scored agent eval for the Clockchain MCP.
// Drives the `claude` CLI as an MCP client over the live HTTP endpoint, captures
// the tool-call trajectory + token usage, and scores each task with a
// deterministic, on-chain check (no LLM judge).
//
// Run:  MCP_TOKEN=<tester token> node eval/run.mjs
//   env: MCP_URL (default mcp.clockchain.network), SAMPLES, MAX_TURNS, TASK (filter)
import { writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { callTool, listTools, MCP_URL, round } from "./lib.mjs";
import { tasks } from "./tasks.mjs";

const TOKEN = process.env.MCP_TOKEN || process.env.MCP_API_KEY || "";
const MAX_TURNS = Number(process.env.MAX_TURNS || 12);
const FILTER = process.env.TASK || "";

function runClaude(prompt, allowed) {
  return new Promise((resolve) => {
    const cfg = "/tmp/cc-eval-mcp.json";
    writeFileSync(cfg, JSON.stringify({ mcpServers: { clockchain: { type: "http", url: MCP_URL, headers: { "x-api-key": TOKEN } } } }));
    const args = ["-p", prompt, "--mcp-config", cfg, "--allowedTools", allowed,
      "--output-format", "stream-json", "--verbose", "--max-turns", String(MAX_TURNS)];
    const cp = spawn("claude", args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const timer = setTimeout(() => cp.kill("SIGKILL"), 180_000);
    cp.stdout.on("data", (d) => (out += d));
    cp.stderr.on("data", (d) => (err += d));
    cp.on("close", () => { clearTimeout(timer); resolve({ out, err }); });
  });
}

// Parse stream-json (JSONL) -> { trajectory:[{name,input,result}], usage, finalText }
function parseStream(out) {
  const calls = new Map(); // tool_use_id -> {name,input,result}
  const order = [];
  let usage = {}, finalText = "";
  for (const line of out.split("\n")) {
    const s = line.trim(); if (!s.startsWith("{")) continue;
    let ev; try { ev = JSON.parse(s); } catch { continue; }
    if (ev.type === "assistant") {
      for (const b of ev.message?.content ?? []) {
        if (b.type === "tool_use") { const c = { name: b.name, input: b.input, result: null }; calls.set(b.id, c); order.push(c); }
      }
    } else if (ev.type === "user") {
      for (const b of ev.message?.content ?? []) {
        if (b.type === "tool_result") {
          const c = calls.get(b.tool_use_id);
          if (c) c.result = Array.isArray(b.content) ? b.content.map((x) => x.text ?? "").join("") : b.content;
        }
      }
    } else if (ev.type === "result") { usage = ev.usage ?? {}; finalText = ev.result ?? ""; }
  }
  return { trajectory: order, usage, finalText };
}

async function main() {
  if (!TOKEN) { console.error("Set MCP_TOKEN"); process.exit(1); }
  const { tools } = await listTools();
  const allowed = tools.map((t) => `mcp__clockchain__${t.name}`).join(",");
  const runId = String(Date.now()).slice(-8);
  let suite = tasks(runId);
  if (FILTER) suite = suite.filter((t) => t.id.includes(FILTER));

  console.log(`# Clockchain MCP — agent eval\nendpoint: ${MCP_URL} | tools: ${tools.length} | runId: ${runId}\n`);
  const rows = [];
  for (const task of suite) {
    process.stdout.write(`▶ ${task.id} … `);
    const { out, err } = await runClaude(task.prompt, allowed);
    const { trajectory, usage, finalText } = parseStream(out);
    let pass = false, detail = "";
    try { ({ pass, detail } = await task.check({ callTool, trajectory, finalText })); }
    catch (e) { detail = "check error: " + e.message; }
    const usedTools = trajectory.map((c) => (c.name || "").replace("mcp__clockchain__", ""));
    const expected = task.expectTools.filter((t) => usedTools.includes(t));
    const selOk = expected.length === task.expectTools.length;
    const toks = (usage.input_tokens ?? 0) + (usage.output_tokens ?? 0);
    rows.push({ id: task.id, pass, selOk, calls: trajectory.length, toks, detail });
    console.log(`${pass ? "PASS" : "FAIL"}  [tools ${selOk ? "ok" : "miss"}, ${trajectory.length} calls, ~${toks} tok]  ${detail}`);
    if (!out.trim() && err) console.log(`   (claude stderr: ${err.slice(0, 200)})`);
  }
  const p = rows.filter((r) => r.pass).length, s = rows.filter((r) => r.selOk).length;
  console.log(`\n==== completion ${p}/${rows.length} | tool-selection ${s}/${rows.length} | avg ${round(rows.reduce((a, r) => a + r.calls, 0) / rows.length)} calls, ~${Math.round(rows.reduce((a, r) => a + r.toks, 0) / rows.length)} tok/task ====`);
}
main().catch((e) => { console.error("eval failed:", e.message); process.exit(1); });
