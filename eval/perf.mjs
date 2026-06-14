// Layer-A: server/transport performance for the Clockchain MCP.
// Measures per-tool latency (p50/p95/p99 over N samples) for cheap reads, plus
// the "token tax" — how many tokens the full tool-definition set costs per request.
// Reads only (no credit spend). Run: MCP_TOKEN=... node eval/perf.mjs
import { callTool, listTools, estTokens, pct, round, MCP_URL } from "./lib.mjs";

const N = Number(process.env.SAMPLES || 8);
const READS = ["get_time", "get_timestamp", "get_contract_types", "list_schedules"];

async function main() {
  console.log(`# Clockchain MCP — Layer-A performance\nendpoint: ${MCP_URL}  samples/tool: ${N}\n`);

  // Token tax: size of the full tool list the model must ingest every request.
  const { tools, raw, ms } = await listTools();
  console.log(`tools/list: ${tools.length} tools, ~${estTokens(raw)} tokens of schema (${round(ms)}ms)`);
  const perTool = tools.map((t) => estTokens(JSON.stringify(t))).sort((a, b) => b - a);
  console.log(`  heaviest tool def ~${perTool[0]} tok; avg ~${round(perTool.reduce((a, b) => a + b, 0) / perTool.length)} tok\n`);

  // Latency per read tool.
  console.log(`tool                  p50     p95     p99   (ms)`);
  for (const name of READS) {
    const times = [];
    let ok = true;
    for (let i = 0; i < N; i++) {
      const r = await callTool(name, {}, i + 1);
      times.push(r.ms);
      if (!r.ok) ok = false;
    }
    const tag = ok ? "" : "  (some errors)";
    console.log(`${name.padEnd(20)} ${String(round(pct(times, 50))).padStart(6)} ${String(round(pct(times, 95))).padStart(7)} ${String(round(pct(times, 99))).padStart(7)}${tag}`);
  }
  console.log(`\nNote: write/anchor tools (log_action, attest_action, tsa_*) wait ~0.6–15s for a block — measure separately; they spend credits.`);
}
main().catch((e) => { console.error("perf failed:", e.message); process.exit(1); });
