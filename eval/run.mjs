// Execution-scored agent eval for the Clockchain MCP.
// Drives an agent as an MCP client over the live HTTP endpoint, captures the
// tool-call trajectory + token usage, and scores each task with a deterministic,
// on-chain check (no LLM judge). Writes a test report (JSON + Markdown) per run.
//
// Agents (EVAL_AGENT):
//   claude  (default) — the `claude` CLI, headless, stream-json trajectory.
//   hermes            — a Hermes profile (e.g. Clark's), headless `hermes chat -q`;
//                       the trajectory is read from Hermes's own session store
//                       (profiles/<p>/state.db), so nothing depends on stdout parsing
//                       or on a given Hermes version's export flags.
//                       HERMES_PROFILE (default "clark"), HERMES_BIN (default "hermes"),
//                       HERMES_PY (python used to read the store; default python3).
//                       HERMES_SSM_INSTANCE=<i-…> runs the same commands ON that
//                       EC2 box via AWS SSM (Clark's real runtime) — the profile there
//                       must already have the clockchain MCP configured.
//
// Run:  MCP_TOKEN=<tester token> node eval/run.mjs
//   env: MCP_URL (default mcp.clockchain.network), MAX_TURNS, TASK (id filter),
//        EVAL_REPORT_DIR (default eval/reports)
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { callTool, listTools, MCP_URL, round } from "./lib.mjs";
import { tasks } from "./tasks.mjs";
import { writeReport, parses } from "./report.mjs";

const TOKEN = process.env.MCP_TOKEN || process.env.MCP_API_KEY || "";
const MAX_TURNS = Number(process.env.MAX_TURNS || 12);
const FILTER = process.env.TASK || "";
const AGENT = (process.env.EVAL_AGENT || "claude").toLowerCase();
const HERMES_PROFILE = process.env.HERMES_PROFILE || "clark";
const HERMES_BIN = process.env.HERMES_BIN || "hermes";
const HERMES_SSM_INSTANCE = process.env.HERMES_SSM_INSTANCE || "";
// Prefix for every hermes invocation (e.g. `sudo -u clockchain env HERMES_HOME=/opt/clockchain/.hermes`)
// so a remote run executes as Clark's user against Clark's profile store.
const HERMES_CMD_PREFIX = process.env.HERMES_CMD_PREFIX || "";
const HERMES_PY = process.env.HERMES_PY || "python3";
const AWS_REGION = process.env.AWS_REGION || "us-west-2";
const REPORT_DIR = process.env.EVAL_REPORT_DIR || path.join(path.dirname(new URL(import.meta.url).pathname), "reports");
const TASK_TIMEOUT_MS = Number(process.env.TASK_TIMEOUT_MS || 240_000);

function sh(cmd, args, { input, timeoutMs = TASK_TIMEOUT_MS, env } = {}) {
  return new Promise((resolve) => {
    const cp = spawn(cmd, args, { stdio: [input ? "pipe" : "ignore", "pipe", "pipe"], env: env ?? process.env });
    let out = "", err = "";
    const timer = setTimeout(() => cp.kill("SIGKILL"), timeoutMs);
    cp.stdout.on("data", (d) => (out += d));
    cp.stderr.on("data", (d) => (err += d));
    cp.on("close", (code) => { clearTimeout(timer); resolve({ out, err, code }); });
    if (input) { cp.stdin.write(input); cp.stdin.end(); }
  });
}

// ---------------------------------------------------------------- claude runner
async function runClaude(prompt, allowed) {
  const cfg = path.join(mkdtempSync(path.join(tmpdir(), "cc-eval-")), "mcp.json");
  writeFileSync(cfg, JSON.stringify({ mcpServers: { clockchain: { type: "http", url: MCP_URL, headers: { "x-api-key": TOKEN } } } }));
  const args = ["-p", prompt, "--mcp-config", cfg, "--allowedTools", allowed,
    "--output-format", "stream-json", "--verbose", "--max-turns", String(MAX_TURNS)];
  const { out, err } = await sh("claude", args);
  return { ...parseStream(out), stderr: err, model: "claude (CLI default)" };
}

// ---------------------------------------------------------------- hermes runner
/** Unwrap Hermes's untrusted-tool-result envelope to the tool's own JSON text. */
function unwrapHermesResult(content) {
  const text = Array.isArray(content) ? content.map((x) => x.text ?? "").join("") : String(content ?? "");
  const m = /<untrusted_tool_result[^>]*>\s*([\s\S]*?)\s*<\/untrusted_tool_result>/.exec(text);
  const inner = m ? m[1] : text;
  // The envelope body is "<preamble>\n\n{"result": "<tool json text>"}" — take the last JSON object.
  const start = inner.lastIndexOf("\n{");
  const candidate = start >= 0 ? inner.slice(start + 1) : inner;
  try {
    const obj = JSON.parse(candidate);
    if (obj && typeof obj === "object" && "result" in obj) return typeof obj.result === "string" ? obj.result : JSON.stringify(obj.result);
    // Hermes wraps a tool error as {"error": "..."}: hand back the plain message so checks
    // and the coverage matrix see an error result, not a JSON "success" object.
    if (obj && typeof obj === "object" && "error" in obj) return `ERROR: ${typeof obj.error === "string" ? obj.error : JSON.stringify(obj.error)}`;
    return candidate;
  } catch {
    return inner;
  }
}

/** Run a shell script either locally or on an EC2 instance via SSM (Clark's box). */
async function hermesExec(script, { timeoutMs = TASK_TIMEOUT_MS } = {}) {
  if (!HERMES_SSM_INSTANCE) {
    return sh("bash", ["-s"], { input: script, env: { ...process.env, HERMES_ACCEPT_HOOKS: "1" }, timeoutMs });
  }
  const params = JSON.stringify({ commands: [`bash -s <<'EOS'\n${script}\nEOS\n`], executionTimeout: [String(Math.ceil(timeoutMs / 1000) + 60)] });
  const id = execFileSync("aws", ["--region", AWS_REGION, "ssm", "send-command", "--instance-ids", HERMES_SSM_INSTANCE,
    "--document-name", "AWS-RunShellScript", "--comment", "clockchain agent eval (Clark)", "--parameters", params,
    "--query", "Command.CommandId", "--output", "text"], { encoding: "utf8" }).trim();
  let status = "InProgress", out = "", err = "";
  const deadline = Date.now() + timeoutMs + 60_000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 4000));
    let inv;
    try {
      inv = JSON.parse(execFileSync("aws", ["--region", AWS_REGION, "ssm", "get-command-invocation", "--command-id", id,
        "--instance-id", HERMES_SSM_INSTANCE, "--output", "json"], { encoding: "utf8" }));
    } catch { continue; }
    status = inv.Status; out = inv.StandardOutputContent ?? ""; err = inv.StandardErrorContent ?? "";
    if (!["InProgress", "Pending", "Delayed"].includes(status)) break;
  }
  return { out, err, code: status === "Success" ? 0 : 1 };
}

/** Normalize an MCP tool name from any client's prefix convention to the bare tool name. */
export function bareTool(name) {
  return String(name || "").replace(/^mcp_{1,2}clockchain_{1,2}/, "");
}

// Reads one session's messages straight from Hermes's SQLite store and prints a
// Claude-Code trace JSONL (assistant tool_use / user tool_result / final text).
// Version-independent: `sessions export` flags differ across Hermes releases, the
// messages table does not. Runs with the same python Hermes runs on.
const TRACE_PY = `import sqlite3, json, os, sys
home = os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes")
db = os.path.join(home, "profiles", sys.argv[1], "state.db")
sid = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
c = sqlite3.connect(db)
if not sid:
    row = c.execute("select id from sessions where source='tool' order by started_at desc limit 1").fetchone()
    sid = row[0] if row else None
if not sid: sys.exit(0)
rows = c.execute("select role, content, tool_calls, tool_call_id from messages where session_id=? order by rowid", (sid,)).fetchall()
out = []
for role, content, tool_calls, tcid in rows:
    if role == "assistant":
        blocks = []
        if content: blocks.append({"type": "text", "text": content})
        for tc in (json.loads(tool_calls) if tool_calls else []):
            fn = tc.get("function", {})
            try: args = json.loads(fn.get("arguments") or "{}")
            except Exception: args = {"_raw": fn.get("arguments")}
            blocks.append({"type": "tool_use", "id": tc.get("id") or tc.get("call_id"), "name": fn.get("name"), "input": args})
        out.append({"type": "assistant", "message": {"content": blocks}})
    elif role == "tool":
        out.append({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tcid, "content": content or ""}]}})
for o in out: print(json.dumps(o))
`;

/** Page a (possibly large) remote file back through SSM's 24 kB output window. */
async function readRemoteFile(file) {
  const PAGE = 20000;
  let offset = 0, data = "";
  for (;;) {
    const { out } = await hermesExec(`tail -c +${offset + 1} '${file}' | head -c ${PAGE}`, { timeoutMs: 60_000 });
    data += out;
    if (out.length < PAGE) return data;
    offset += out.length;
  }
}

async function runHermes(prompt) {
  const q = prompt.replace(/'/g, `'"'"'`);
  // One script: chat headless, then dump THAT session's trace from the store. Locally
  // everything streams back on stdout; remotely the trace is written to a file on the
  // box and paged back, because SSM truncates command output at 24 kB.
  const H = `${HERMES_CMD_PREFIX} ${HERMES_BIN} -p ${HERMES_PROFILE}`.trim();
  const PY = `${HERMES_CMD_PREFIX} ${HERMES_PY}`.trim();
  const remote = !!HERMES_SSM_INSTANCE;
  const T = remote ? `/tmp/cc-eval-${Date.now()}` : "$(mktemp -d)";
  const script = `set -o pipefail
export HERMES_ACCEPT_HOOKS=1
T=${T}; mkdir -p "$T"; chmod 777 "$T"
cat > "$T/trace.py" <<'PYEOF'
${TRACE_PY}
PYEOF
chmod 644 "$T/trace.py"
${H} chat -q '${q}' -Q --yolo --source tool --max-turns ${MAX_TURNS} > "$T/final.txt" 2> "$T/stderr.txt" || true
SID=$(grep -m1 -oE 'session_id: *[A-Za-z0-9_-]+' "$T/final.txt" | sed 's/session_id: *//')
${PY} "$T/trace.py" ${HERMES_PROFILE} "$SID" > "$T/trace.jsonl" 2>> "$T/stderr.txt" || true
echo "=====FINAL====="; grep -v '^session_id:' "$T/final.txt"
echo "=====MODEL====="; echo "${process.env.HERMES_MODEL_LABEL ?? ""}"
echo "=====SIZE====="; wc -c < "$T/trace.jsonl" 2>/dev/null || echo 0
echo "=====TRACE====="
${remote ? "true" : 'cat "$T/trace.jsonl" 2>/dev/null'}
echo "=====END====="
echo "=====STDERR====="; tail -c 1500 "$T/stderr.txt"; ${remote ? "true" : 'rm -rf "$T"'}`;
  const { out, err } = await hermesExec(script);
  const seg = (a, b) => { const i = out.indexOf(a), j = out.indexOf(b); return i >= 0 && j > i ? out.slice(i + a.length, j) : ""; };
  const finalText = seg("=====FINAL=====", "=====MODEL=====").trim();
  const model = seg("=====MODEL=====", "=====SIZE=====").trim() || `hermes:${HERMES_PROFILE}`;
  let trace = seg("=====TRACE=====", "=====END=====");
  if (remote) {
    trace = await readRemoteFile(`${T}/trace.jsonl`);
    await hermesExec(`rm -rf '${T}'`, { timeoutMs: 60_000 });
  }
  const parsed = parseStream(trace, unwrapHermesResult);
  const stderrTail = out.includes("=====STDERR=====") ? out.slice(out.indexOf("=====STDERR=====") + 16) : "";
  return { ...parsed, finalText: finalText || parsed.finalText, stderr: err + stderrTail, model };
}

// ---------------------------------------------------------------- trajectory parsing
// Claude Code stream-json / Hermes trace JSONL -> { trajectory:[{name,input,result}], usage, finalText }
function parseStream(out, resultMapper = (c) => (Array.isArray(c) ? c.map((x) => x.text ?? "").join("") : c)) {
  const calls = new Map();
  const order = [];
  let usage = {}, finalText = "";
  for (const line of out.split("\n")) {
    const s = line.trim(); if (!s.startsWith("{")) continue;
    let ev; try { ev = JSON.parse(s); } catch { continue; }
    if (ev.type === "assistant") {
      for (const b of ev.message?.content ?? []) {
        if (b.type === "tool_use") { const c = { name: b.name, input: b.input, result: null }; calls.set(b.id, c); order.push(c); }
        else if (b.type === "text" && b.text) finalText = b.text;
      }
      if (ev.message?.usage) usage = ev.message.usage;
    } else if (ev.type === "user") {
      for (const b of ev.message?.content ?? []) {
        if (b && b.type === "tool_result") {
          const c = calls.get(b.tool_use_id);
          if (c) c.result = resultMapper(b.content);
        }
      }
    } else if (ev.type === "result") { usage = ev.usage ?? usage; finalText = ev.result ?? finalText; }
  }
  return { trajectory: order, usage, finalText };
}

// ---------------------------------------------------------------- main
async function main() {
  if (!TOKEN) { console.error("Set MCP_TOKEN"); process.exit(1); }
  const { tools } = await listTools();
  const toolNames = tools.map((t) => t.name);
  const allowed = toolNames.map((t) => `mcp__clockchain__${t}`).join(",");
  const runId = String(Date.now()).slice(-8);
  let suite = tasks(runId);
  if (FILTER) suite = suite.filter((t) => t.id.includes(FILTER));
  const agentLabel = AGENT === "hermes" ? `hermes:${HERMES_PROFILE}${HERMES_SSM_INSTANCE ? "@" + HERMES_SSM_INSTANCE : ""}` : "claude";
  const startedAt = new Date().toISOString();

  console.log(`# Clockchain MCP — agent eval\nagent: ${agentLabel} | endpoint: ${MCP_URL} | tools: ${tools.length} | tasks: ${suite.length} | runId: ${runId}\n`);
  const rows = [];
  let model = agentLabel;
  for (const task of suite) {
    process.stdout.write(`▶ ${task.id} … `);
    const r = AGENT === "hermes" ? await runHermes(task.prompt) : await runClaude(task.prompt, allowed);
    if (r.model) model = r.model;
    const { trajectory, usage, finalText } = r;
    let pass = false, detail = "";
    try { ({ pass, detail } = await task.check({ callTool, trajectory, finalText })); }
    catch (e) { detail = "check error: " + e.message; }
    const usedTools = trajectory.map((c) => bareTool(c.name));
    const expected = task.expectTools.filter((t) => usedTools.includes(t));
    const selOk = expected.length === task.expectTools.length;
    const toks = (usage.input_tokens ?? usage.prompt_tokens ?? 0) + (usage.output_tokens ?? usage.completion_tokens ?? 0);
    rows.push({ id: task.id, pass, selOk, expectTools: task.expectTools, usedTools, calls: trajectory.length, toks, detail, finalText: String(finalText).slice(0, 2000), trajectory: trajectory.map((c) => ({ name: c.name, input: c.input, ok: parses(c.result), result: typeof c.result === "string" ? c.result.slice(0, 4000) : c.result })) });
    console.log(`${pass ? "PASS" : "FAIL"}  [tools ${selOk ? "ok" : "miss"}, ${trajectory.length} calls, ~${toks} tok]  ${detail}`);
    if (trajectory.length === 0 && r.stderr) console.log(`   (agent stderr: ${r.stderr.slice(-300).replace(/\s+/g, " ")})`);
  }
  const p = rows.filter((r) => r.pass).length, s = rows.filter((r) => r.selOk).length;
  console.log(`\n==== completion ${p}/${rows.length} | tool-selection ${s}/${rows.length} | avg ${round(rows.reduce((a, r) => a + r.calls, 0) / rows.length)} calls, ~${Math.round(rows.reduce((a, r) => a + r.toks, 0) / rows.length)} tok/task ====`);
  const rep = writeReport({ dir: REPORT_DIR, runId, agent: agentLabel, model, endpoint: MCP_URL, toolNames, rows, startedAt, finishedAt: new Date().toISOString() });
  console.log(`report: ${rep.md} (${rep.verdict}; ${rep.exercisedOk} tools exercised OK, ${rep.exercisedErr} with error results${rep.notExercised.length ? `; not exercised: ${rep.notExercised.join(", ")}` : ""})`);
  process.exit(rep.verdict === "PASS" ? 0 : 1);
}
main().catch((e) => { console.error("eval failed:", e.message); process.exit(1); });
