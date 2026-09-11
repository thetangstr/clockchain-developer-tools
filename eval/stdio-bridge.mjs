#!/usr/bin/env node
// Dependency-free stdio -> Streamable-HTTP bridge for the hosted Clockchain MCP.
//
// For MCP clients that can only spawn a stdio server (e.g. a Hermes runtime whose
// `mcp` package predates HTTP transport). Reads JSON-RPC messages line by line on
// stdin, POSTs each to the hosted endpoint with the token, and writes every
// JSON-RPC response (JSON or SSE `data:` frames) back on stdout, one per line.
//
//   CC_MCP_URL=https://mcp.clockchain.network/mcp CC_MCP_TOKEN=<x-api-key> node eval/stdio-bridge.mjs
//
// Messages are forwarded strictly in order; notifications (no id) get no reply.
// The hosted server is stateless (no mcp-session-id), so there is no session to keep.
import { createInterface } from "node:readline";

const URL_ = process.env.CC_MCP_URL || "https://mcp.clockchain.network/mcp";
const TOKEN = process.env.CC_MCP_TOKEN || "";
if (!TOKEN) { process.stderr.write("stdio-bridge: CC_MCP_TOKEN is required\n"); process.exit(2); }

let chain = Promise.resolve();
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  const s = line.trim();
  if (!s) return;
  chain = chain.then(() => forward(s)).catch((e) => process.stderr.write(`stdio-bridge: ${e.message}\n`));
});
rl.on("close", () => { chain.finally(() => process.exit(0)); });

async function forward(raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch { return; }
  const res = await fetch(URL_, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "x-api-key": TOKEN },
    body: raw,
  });
  const ct = res.headers.get("content-type") || "";
  if (res.status === 202 || res.status === 204) return;
  if (!res.ok) {
    if (msg.id !== undefined) emit({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: `HTTP ${res.status} from ${URL_}` } });
    return;
  }
  const body = await res.text();
  if (ct.includes("text/event-stream")) {
    for (const frame of body.split(/\n\n+/)) {
      const data = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("\n");
      if (data) emitRaw(data);
    }
  } else if (body.trim()) {
    emitRaw(body.trim());
  }
}
function emit(obj) { process.stdout.write(JSON.stringify(obj) + "\n"); }
function emitRaw(text) { try { emit(JSON.parse(text)); } catch { /* not JSON: drop */ } }
