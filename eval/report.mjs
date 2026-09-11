// Test-report writer for the agent eval: one JSON + one Markdown per run under
// eval/reports/. The Markdown is the human artifact ("did the agent pass, which
// tools did it exercise"); the JSON is the machine record (trajectories included).
//
// Tool coverage is computed against the LIVE tools/list, so the matrix is always
// the deployment's real surface: a tool is "exercised" when the agent called it;
// "ok" when the result parsed as the server's JSON success payload (errors come
// back as plain text); tools that cannot be driven by a single agent are named
// with the reason and the suite that does cover them, so "all tools" is honest.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

/** Tools a lone agent cannot legitimately complete, and where they ARE covered. */
export const NOT_SINGLE_AGENT = {
  create_schedule: "needs the caller's EVM wallet signature (non-custodial; the server never fabricates one) — covered by tools.test.mjs + the protocol team's signing spec",
  handshake_join: "bilateral protocol: a counterparty must join — covered by handshake-*.test.mjs and the M3 live demo",
  handshake_next: "bilateral protocol step — covered by handshake-*.test.mjs and the M3 live demo",
  handshake_submit: "requires a party-produced EIP-191 signature — covered by handshake-*.test.mjs and the M3 live demo",
  handshake_get_certificate: "issued only after both parties complete — covered by handshake-*.test.mjs and the M3 live demo",
  agent_handshake_invite: "creates a live single-use stakeholder invitation on the public surface; not something an eval should mint — covered by agent-handshake-v2-*.test.mjs and the M3 live demo",
  agent_handshake_join: "two-stakeholder protocol with local signing — covered by agent-handshake-v2-*.test.mjs and the M3 live demo",
  agent_handshake_next: "two-stakeholder protocol step — covered by agent-handshake-v2-*.test.mjs",
  agent_handshake_submit: "requires a stakeholder-produced signature — covered by agent-handshake-v2-*.test.mjs",
  agent_handshake_get_certificate: "issued only after both stakeholders complete — covered by agent-handshake-v2-*.test.mjs",
};

function parses(text) {
  if (text == null) return false;
  try { const v = typeof text === "string" ? JSON.parse(text) : text; return v !== null && typeof v === "object"; } catch { return false; }
}

/** Build the coverage matrix: every live tool → exercised/ok/error/not-testable. */
export function coverage(toolNames, rows) {
  const calls = new Map(); // tool -> { calls, ok, err }
  for (const r of rows) {
    for (const c of r.trajectory ?? []) {
      const name = (c.name || "").replace("mcp__clockchain__", "");
      const e = calls.get(name) ?? { calls: 0, ok: 0, err: 0 };
      e.calls++;
      if (parses(c.result)) e.ok++; else e.err++;
      calls.set(name, e);
    }
  }
  return toolNames.map((name) => {
    const e = calls.get(name);
    let status;
    if (e && e.ok > 0) status = "exercised-ok";
    else if (e) status = "exercised-error";
    else if (NOT_SINGLE_AGENT[name]) status = "not-single-agent";
    else status = "not-exercised";
    return { tool: name, status, calls: e?.calls ?? 0, ok: e?.ok ?? 0, err: e?.err ?? 0, note: NOT_SINGLE_AGENT[name] ?? "" };
  });
}

export function writeReport({ dir, runId, agent, model, endpoint, toolNames, rows, startedAt, finishedAt }) {
  mkdirSync(dir, { recursive: true });
  const cov = coverage(toolNames, rows);
  const passed = rows.filter((r) => r.pass).length;
  const selected = rows.filter((r) => r.selOk).length;
  const exercisedOk = cov.filter((c) => c.status === "exercised-ok").length;
  const exercisedErr = cov.filter((c) => c.status === "exercised-error").length;
  const notSingle = cov.filter((c) => c.status === "not-single-agent").length;
  const notExercised = cov.filter((c) => c.status === "not-exercised");
  const stem = `${startedAt.replace(/[:.]/g, "-")}-${agent}`;
  const json = { schema: "clockchain.eval-report/v1", runId, agent, model, endpoint, startedAt, finishedAt,
    summary: { tasks: rows.length, passed, toolSelection: selected, tools: toolNames.length, exercisedOk, exercisedErr, notSingleAgent: notSingle, notExercised: notExercised.length },
    tasks: rows, coverage: cov };
  writeFileSync(path.join(dir, `${stem}.json`), JSON.stringify(json, null, 2));

  const verdict = passed === rows.length && notExercised.length === 0 ? "PASS" : "FAIL";
  const md = [];
  md.push(`# Clockchain MCP — agent test report: ${verdict}`);
  md.push("");
  md.push(`| | |`); md.push(`|---|---|`);
  md.push(`| Agent | \`${agent}\` (${model}) |`);
  md.push(`| Endpoint | ${endpoint} |`);
  md.push(`| Run | \`${runId}\` · ${startedAt} → ${finishedAt} |`);
  md.push(`| Tasks | **${passed} / ${rows.length} passed** (on-chain checks, no LLM judge); tool selection ${selected} / ${rows.length} |`);
  md.push(`| Tools | ${toolNames.length} on the live surface: **${exercisedOk} exercised OK**, ${exercisedErr} exercised with an error result, ${notSingle} not single-agent testable (covered elsewhere), ${notExercised.length} not exercised |`);
  md.push("");
  md.push("## Tasks");
  md.push("");
  md.push("| Task | Result | Tools | Calls | Evidence |");
  md.push("|---|---|---|---|---|");
  for (const r of rows) {
    md.push(`| \`${r.id}\` | ${r.pass ? "✅ PASS" : "❌ FAIL"} | ${r.selOk ? "as expected" : "missed: " + r.expectTools.filter((t) => !r.usedTools.includes(t)).join(", ")} | ${r.calls} | ${String(r.detail).replace(/\|/g, "\\|")} |`);
  }
  md.push("");
  md.push("## Tool coverage (live `tools/list`)");
  md.push("");
  md.push("| Tool | Status | Calls | Note |");
  md.push("|---|---|---|---|");
  const icon = { "exercised-ok": "✅", "exercised-error": "⚠️", "not-single-agent": "◻️", "not-exercised": "❌" };
  for (const c of cov) md.push(`| \`${c.tool}\` | ${icon[c.status]} ${c.status} | ${c.calls} | ${c.note} |`);
  md.push("");
  md.push("Legend: ✅ called and returned the server's JSON success payload · ⚠️ called, returned an error/text result (see the task's evidence — expected where the substrate lacks the API) · ◻️ cannot be completed by one agent; covered by the named suites · ❌ not exercised in this run.");
  md.push("");
  md.push("Verdict rule: PASS = every task's on-chain check passed AND every single-agent-testable tool was exercised.");
  writeFileSync(path.join(dir, `${stem}.md`), md.join("\n") + "\n");
  return { json: path.join(dir, `${stem}.json`), md: path.join(dir, `${stem}.md`), verdict, passed, exercisedOk, exercisedErr, notExercised: notExercised.map((c) => c.tool) };
}
