#!/usr/bin/env node
/**
 * probe-staging (N7b) — read-only conformance probe for a `/contract/mcp`
 * surface. Usage:
 *
 *   CONTRACT_PROBE_TOKENS="buyer:<tok>,provider:<tok>" \
 *     node scripts/agent-contract/probe-staging.mjs <baseUrl>
 *
 *   <baseUrl> is the surface root, e.g. https://mcp.clockchain.network/staging
 *   (card at <base>/.well-known/mcp/server-card.json, keys at
 *   <base>/contract/keys, MCP at <base>/contract/mcp).
 *
 * Checks: server card + self-consistent cardDigest, the published keys doc,
 * initialize + tools/list per supplied role token (result canonical-digest
 * compared to the card's published toolsListDigest — a jq -cS equivalent),
 * and contract_status pre-bind (the rendezvous-shape refusal). No mutating
 * tool is ever called. Exit 0 only when every check passes.
 */

import { createHash } from "node:crypto";

/** jq -cS equivalent: recursively key-sorted compact JSON. */
function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort()
    .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
}
const digestOf = (v) => `0x${createHash("sha256").update(canon(v), "utf8").digest("hex")}`;

const ACCEPT = "application/json, text/event-stream";

/** Parse a possibly-SSE JSON-RPC response body. */
function parseBody(text) {
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(data !== undefined ? data.slice(5).trim() : text);
}

async function rpc(base, token, sessionId, method, params, fetchImpl) {
  const headers = { "content-type": "application/json", accept: ACCEPT };
  if (token) headers.authorization = `Bearer ${token}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetchImpl(`${base}/contract/mcp`, {
    method: "POST", headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  let body = null;
  try { body = parseBody(await res.text()); } catch { /* non-JSON */ }
  return { status: res.status, sessionId: res.headers.get("mcp-session-id"), body };
}

async function get(base, path, fetchImpl) {
  const res = await fetchImpl(`${base}${path}`, { headers: { accept: "application/json" } });
  let body = null;
  try { body = JSON.parse(await res.text()); } catch { /* non-JSON */ }
  return { status: res.status, body };
}

/**
 * @param {string} baseUrl  surface root (no trailing slash tolerated)
 * @param {Record<string,string>} tokens  { buyer?, provider? } bearer tokens
 * @returns {{ok: boolean, checks: {name: string, ok: boolean, detail?: string}[]}}
 */
export async function probeSurface(baseUrl, tokens, { fetchImpl = fetch } = {}) {
  const base = baseUrl.replace(/\/+$/, "");
  const checks = [];
  const check = (name, ok, detail) => { checks.push({ name, ok, ...(detail ? { detail } : {}) }); return ok; };

  // 1. Server card + digest self-consistency.
  const card = await get(base, "/.well-known/mcp/server-card.json", fetchImpl);
  check("server-card",
    card.status === 200 && card.body?.schema === "agent-contract.server-card/v1");
  const cardBody = card.body ?? {};
  const { cardDigest, ...cardSansDigest } = cardBody;
  check("card-digest",
    typeof cardDigest === "string" && digestOf(cardSansDigest) === cardDigest,
    cardDigest);

  // 2. Published keys document.
  const keys = await get(base, "/contract/keys", fetchImpl);
  check("keys",
    keys.status === 200 && keys.body?.schema === "agent-contract.server-keys/v1"
      && Array.isArray(keys.body.keys) && keys.body.keys.length > 0
      && keys.body.keys.every((k) => k.alg === "Ed25519" && /^0x[0-9a-f]{64}$/.test(k.publicKeyHex)));

  // 3. initialize + tools/list per role token; compare the digest to the card.
  for (const role of ["buyer", "provider"]) {
    const token = tokens[role];
    if (token === undefined) {
      check(`initialize:${role}`, false, "no token supplied");
      check(`tools-list:${role}`, false, "no token supplied");
      continue;
    }
    const init = await rpc(base, token, null, "initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "ac-staging-probe", version: "0.1.0" },
    }, fetchImpl);
    const sid = init.sessionId;
    check(`initialize:${role}`, init.status === 200 && typeof sid === "string" && sid.length > 0);
    if (init.status !== 200 || !sid) { check(`tools-list:${role}`, false, "no session"); continue; }

    const list = await rpc(base, token, sid, "tools/list", {}, fetchImpl);
    const result = list.body?.result;
    const expected = cardBody?.guidance?.[role]?.toolsListDigest;
    const actual = result !== undefined ? digestOf(result) : undefined;
    check(`tools-list:${role}`,
      list.status === 200 && result !== undefined
        && typeof expected === "string" && actual === expected,
      actual !== undefined && actual !== expected ? `digest ${actual} != card ${expected}` : undefined);

    // Read-only status call — pre-bind must answer the rendezvous shape.
    if (role === "buyer") {
      const status = await rpc(base, token, sid, "tools/call",
        { name: "contract_status", arguments: {} }, fetchImpl);
      const sc = status.body?.result?.structuredContent;
      check("contract-status-no-run",
        status.status === 200 && sc?.stage === "rendezvous"
          && sc.terminalState === null && typeof sc.serverNonce === "string",
        sc?.stage);
    }

    // Best-effort session close; a refused DELETE doesn't fail the probe.
    try {
      await fetchImpl(`${base}/contract/mcp`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}`, "mcp-session-id": sid, accept: ACCEPT },
      });
    } catch { /* ignore */ }
  }

  return { ok: checks.every((c) => c.ok), checks };
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const baseUrl = process.argv[2];
  if (!baseUrl) {
    process.stderr.write("usage: CONTRACT_PROBE_TOKENS='buyer:<tok>,provider:<tok>' node probe-staging.mjs <baseUrl>\n");
    process.exit(64);
  }
  const tokens = {};
  for (const entry of (process.env.CONTRACT_PROBE_TOKENS ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = entry.indexOf(":");
    if (i === -1) { process.stderr.write(`bad CONTRACT_PROBE_TOKENS entry: ${entry.slice(0, i === -1 ? 12 : i)}…\n`); process.exit(64); }
    const role = entry.slice(0, i);
    if (role !== "buyer" && role !== "provider") { process.stderr.write(`unknown role "${role}"\n`); process.exit(64); }
    tokens[role] = entry.slice(i + 1);
  }
  try {
    const out = await probeSurface(baseUrl, tokens);
    for (const c of out.checks) {
      process.stdout.write(`${c.ok ? "PASS" : "FAIL"} ${c.name}${c.detail ? ` — ${c.detail}` : ""}\n`);
    }
    process.exit(out.ok ? 0 : 1);
  } catch (err) {
    process.stderr.write(`probe error: ${String(err)}\n`);
    process.exit(1);
  }
}
