// Shared helpers for the Clockchain MCP eval harness.
// Talks to the live MCP server over StreamableHTTP (stateless), parses SSE,
// and provides scoring/verification utilities. No external deps.

export const MCP_URL = process.env.MCP_URL || "https://mcp.clockchain.network/mcp";
const TOKEN = process.env.MCP_TOKEN || process.env.MCP_API_KEY || "";

const HEADERS = () => ({
  "content-type": "application/json",
  accept: "application/json, text/event-stream",
  ...(TOKEN ? { "x-api-key": TOKEN } : {}),
});

/** One JSON-RPC call to the MCP server. Returns { json, ms }. */
export async function rpc(method, params = {}, id = 1) {
  const t0 = performance.now();
  const res = await fetch(MCP_URL, {
    method: "POST",
    headers: HEADERS(),
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const raw = await res.text();
  const ms = performance.now() - t0;
  let json;
  for (const line of raw.split("\n")) {
    let s = line.trim();
    if (s.startsWith("data:")) s = s.slice(5).trim();
    if (s.startsWith("{")) { try { json = JSON.parse(s); break; } catch { /* keep scanning */ } }
  }
  return { json, ms, status: res.status };
}

/** Call a tool; returns { ok, text, data, ms, error }. `data` = parsed JSON text if parseable. */
export async function callTool(name, args = {}, id = 1) {
  const { json, ms } = await rpc("tools/call", { name, arguments: args }, id);
  const result = json?.result;
  if (json?.error) return { ok: false, error: json.error.message, ms };
  const text = result?.content?.[0]?.text ?? "";
  if (result?.isError) return { ok: false, error: text, text, ms };
  let data;
  try { data = JSON.parse(text); } catch { data = undefined; }
  return { ok: true, text, data, ms };
}

/** List the server's tools. */
export async function listTools() {
  const { json, ms } = await rpc("tools/list", {});
  return { tools: json?.result?.tools ?? [], ms, raw: JSON.stringify(json?.result ?? {}) };
}

/** Rough token estimate (~4 chars/token) — for the "token tax" of tool defs. */
export const estTokens = (s) => Math.ceil((s || "").length / 4);

/** Percentile of a numeric array (p in 0..100). */
export function pct(arr, p) {
  if (!arr.length) return NaN;
  const a = [...arr].sort((x, y) => x - y);
  const i = Math.min(a.length - 1, Math.floor((p / 100) * a.length));
  return a[i];
}

export const round = (n) => Math.round(n * 10) / 10;
