#!/usr/bin/env node
// Post-deploy check for multi-session hosting: N concurrent agent_handshake_invite calls on the
// PUBLIC v2 handshake endpoint must land in N DIFFERENT host sessions.
//
//   node scripts/verify-multi-session-invite.mjs [--endpoint URL] [--relay URL] [--count 2]
//
// Invite-only by design: nothing is accepted, no agent joins, so no host funds anything (zero
// Sepolia spend) and no ERC-8004 registration happens. Each unclaimed invitation lapses at its
// claim expiry (<= 180 s) and that host rotates to a fresh session. Costs `count` of the
// endpoint's per-IP invite budget (20/h). Run it in a quiet window: it occupies `count` host
// sessions for up to ~3 minutes. Prints session ids only (no role access, no invitations).
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    endpoint: { type: "string", default: "https://mcp.clockchain.network/next/handshake/mcp" },
    relay: { type: "string", default: "http://44.249.47.220:8080" },
    count: { type: "string", default: "2" },
  },
});
const count = Number(values.count);
if (!Number.isInteger(count) || count < 2 || count > 3) throw new Error("--count must be 2 or 3");

// The fixed published terms (the endpoint refuses anything else with terms_mismatch).
const current = await (await fetch(`${values.relay}/v1/discovery/current`)).json();
const terms = current.terms;
if (!terms) throw new Error("relay current session publishes no terms");

async function rpc(sessionHeader, body) {
  const response = await fetch(values.endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(sessionHeader ? { "mcp-session-id": sessionHeader } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const json = text.trimStart().startsWith("{")
    ? JSON.parse(text)
    : JSON.parse(text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5)).join(""));
  return { json, session: response.headers.get("mcp-session-id"), status: response.status };
}

async function oneInvite(i) {
  const init = await rpc(null, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "verify-multi-session", version: "0" } } });
  if (init.status !== 200) throw new Error(`initialize HTTP ${init.status}`);
  await rpc(init.session, { jsonrpc: "2.0", method: "notifications/initialized" }).catch(() => {});
  const call = await rpc(init.session, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "agent_handshake_invite", arguments: terms } });
  const content = call.json?.result?.content?.[0]?.text;
  let parsed = null;
  try { parsed = JSON.parse(content); } catch { /* error text */ }
  return { i, isError: call.json?.result?.isError === true, sessionId: parsed?.sessionId ?? null, reason: parsed?.reason ?? parsed?.error ?? (parsed ? null : String(content).slice(0, 120)) };
}

const started = Date.now();
const results = await Promise.all(Array.from({ length: count }, (_, i) => oneInvite(i)));
const ids = results.map((r) => r.sessionId).filter(Boolean);
const distinct = new Set(ids).size;
console.log(JSON.stringify({
  elapsedMs: Date.now() - started,
  results: results.map((r) => ({ i: r.i, sessionId: r.sessionId, isError: r.isError, reason: r.reason })),
  verdict: distinct === count ? `PASS: ${count} concurrent invites in ${distinct} distinct sessions` : `FAIL: ${distinct}/${count} distinct sessions`,
}, null, 2));
process.exitCode = distinct === count ? 0 : 1;
