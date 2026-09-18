// Public status page renderer: GET /status serves live-computed HTML (people),
// GET /status.json serves the same report as JSON (agents/monitoring). Same
// stylesheet and chrome as the landing/SOP pages. The page is generated per
// request from the cached StatusReport — every number carries its observation
// time, and the observation window is labeled honestly ("since process start").
import { BASE_CSS, LOGO_SVG, SUBSTRATE_LABEL } from "./landing.js";
import type { ComponentState, OverallState, StatusReport } from "./status.js";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const STATE_LABEL: Record<ComponentState, string> = {
  ok: "Operational", degraded: "Degraded", down: "Down", unknown: "Unknown",
};
const OVERALL_LABEL: Record<OverallState, string> = {
  operational: "All systems operational", degraded: "Partial degradation", outage: "Outage",
};

const CSS = `
  .banner { border-radius: 16px; padding: 26px 30px; margin: 48px auto 34px; max-width: 880px; display: flex; align-items: center; gap: 16px; border: 1px solid var(--line); }
  .banner .dot { width: 14px; height: 14px; border-radius: 50%; flex: none; }
  .banner h1 { font-size: 24px; margin: 0; font-weight: 600; }
  .banner .ts { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--fg-3); text-align: right; }
  .b-operational { background: var(--green-soft); border-color: #bfe6cf; }
  .b-operational .dot { background: var(--green); }
  .b-degraded { background: #fef8e6; border-color: #f0d98c; }
  .b-degraded .dot { background: #d9a514; }
  .b-outage { background: #fef3f2; border-color: #f3c2bb; }
  .b-outage .dot { background: #b42318; }
  .st-table { width: 100%; border-collapse: collapse; max-width: 880px; margin: 0 auto; font-size: 14px; }
  .st-table th { text-align: left; font-family: var(--mono); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-3); border-bottom: 2px solid var(--line); padding: 8px 10px 8px 0; }
  .st-table td { border-bottom: 1px solid var(--line); padding: 12px 10px 12px 0; vertical-align: top; color: var(--fg-2); }
  .st-state { font-weight: 600; white-space: nowrap; }
  .st-ok { color: var(--green); } .st-degraded { color: #b07d0a; } .st-down { color: #b42318; } .st-unknown { color: var(--fg-3); }
  .st-meta { font-family: var(--mono); font-size: 11.5px; color: var(--fg-3); margin-top: 3px; overflow-wrap: anywhere; }
  .cards { max-width: 880px; margin: 26px auto 0; display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .card { border: 1px solid var(--line); border-radius: 14px; padding: 18px 20px; background: #fff; }
  .card h3 { font-family: var(--mono); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-3); margin: 0 0 10px; font-weight: 500; }
  .card .big { font-size: 17px; font-weight: 600; color: var(--ink); }
  .card .sub-line { font-size: 13px; color: var(--fg-2); margin-top: 6px; }
  .card code { font-family: var(--mono); font-size: 12px; word-break: break-all; }
  .st-note { max-width: 880px; margin: 26px auto 0; font-size: 13px; color: var(--fg-3); line-height: 1.6; }
  .st-note code { font-family: var(--mono); font-size: 11.5px; }
  .perf-head { max-width: 880px; margin: 34px auto 14px; font-family: var(--mono); font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-3); }
  .perf-head .perf-window { color: var(--fg-2); letter-spacing: normal; text-transform: none; }
  .perf-table { margin-top: 14px; }
  .perf-table td { font-family: var(--mono); font-size: 12.5px; }
  .perf-table td:first-child { font-family: inherit; font-size: 14px; }
  @media (max-width: 760px) {
    .cards { grid-template-columns: 1fr; }
    .banner, .st-table, .cards, .st-note, .perf-head { margin-left: 14px; margin-right: 14px; }
    .banner { flex-wrap: wrap; padding: 20px 18px; }
    .banner .ts { margin-left: 0; }
    .st-table { width: auto; font-size: 13px; }
    .st-table thead { display: none; }
    .st-table tbody, .st-table tr, .st-table td { display: block; width: auto; }
    .st-table tr { border-bottom: 1px solid var(--line); padding: 10px 0; }
    .st-table td { border-bottom: none; padding: 2px 0; }
    .st-table td.st-state { padding: 4px 0; }
    .banner h1 { font-size: 19px; }
    .nav-links a:not(.pill) { display: none; }
  }
`;

function ago(seconds: number): string {
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m ago`;
}

function metaLine(meta: Record<string, string | number | boolean> | undefined): string {
  if (!meta) return "";
  const parts = Object.entries(meta).map(([k, v]) => `${k}=${String(v)}`);
  return parts.length ? `<div class="st-meta">${esc(parts.join(" · "))}</div>` : "";
}

const COMPONENT_ORDER: [string, string][] = [
  ["mcp_host", "MCP host"],
  ["handshake_surface", "Handshake surface"],
  ["relay_supervisor", "Relay / session supervisor"],
  ["anchoring_gateway", "Anchoring gateway"],
  ["pool_participation", "Clockchain pool participation"],
  ["evm_rpc", "EVM RPC (Sepolia ERC-8004)"],
];

export function renderStatusPage(r: StatusReport): string {
  const computedIso = new Date(r.computedAtMs).toISOString();
  const uptimeS = Math.max(0, Math.floor((r.computedAtMs - r.processStartedAtMs) / 1000));
  const rows = COMPONENT_ORDER.map(([key, label]) => {
    const c = r.components[key];
    if (!c) return "";
    const ageS = Math.max(0, Math.floor((r.computedAtMs - c.observedAtMs) / 1000));
    const lat = c.latencyMs !== undefined ? ` · ${c.latencyMs}ms` : "";
    return `<tr>
      <td>${esc(label)}</td>
      <td class="st-state st-${c.state}">${STATE_LABEL[c.state]}</td>
      <td>${esc(c.detail)}${metaLine(c.meta)}<div class="st-meta">observed ${ago(ageS)}${lat}</div></td>
    </tr>`;
  }).join("");

  const lv = r.lastVerifiedHandshake;
  const lvCard = lv.evidence === "fresh" || lv.evidence === "stale"
    ? `<div class="big ${lv.evidence === "fresh" ? "st-ok" : "st-degraded"}">VERIFIED${lv.evidence === "stale" ? " — stale" : ""}</div>
       <div class="sub-line">Certificate issued ${ago(lv.ageSeconds ?? 0)} (observed at ${esc(lv.observedAtMs !== undefined ? new Date(lv.observedAtMs).toISOString() : "unknown")})${lv.evidence === "stale" ? " — older than the evidence window" : ""}</div>`
    : lv.evidence === "unavailable"
      ? `<div class="big st-degraded">Evidence unavailable</div>
         <div class="sub-line">The evidence probe failed — distinct from "no certificate". Does not affect availability.</div>`
      : `<div class="big">None observed</div>
         <div class="sub-line">No completed handshake certificate in the current session window — normal on an idle service; not an availability signal.</div>`;

  // Public performance block — real bounded aggregates since process start.
  // Percentiles render as ms; absent percentiles (no samples) render as —.
  const ms = (s: number | undefined) => s === undefined ? "—" : s < 1 ? `${Math.round(s * 1000)}ms` : `${s.toFixed(2)}s`;
  const perf = r.performance;
  const pct = (rate: number) => `${(rate * 100).toFixed(rate > 0 && rate < 0.01 ? 2 : 1)}%`;
  const perfRows = perf.http.routes.map((row) => `<tr>
    <td>${esc(row.route)}</td>
    <td>${row.requests}</td>
    <td>${row.errors}</td>
    <td>${ms(row.p50Seconds)}</td>
    <td>${ms(row.p95Seconds)}</td>
    <td>${ms(row.p99Seconds)}</td>
  </tr>`).join("");
  const perfTable = perfRows
    ? `<table class="st-table perf-table">
  <thead><tr><th>Route</th><th>Requests</th><th>5xx</th><th>p50</th><th>p95</th><th>p99</th></tr></thead>
  <tbody>${perfRows}</tbody>
</table>`
    : `<p class="st-note">No HTTP traffic observed since process start — aggregates appear here as requests arrive.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain Status — MCP + Agent Handshake</title>
<meta name="description" content="Live operational status for the Clockchain MCP host and Agent Handshake surface — dependency probes, pool participation, and the last verified handshake." />
<meta http-equiv="refresh" content="60" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
<style>
${BASE_CSS}
${CSS}</style>
</head>
<body>
<nav><div class="wrap nav-in">
  <div class="nav-left"><a class="brand" href="/">${LOGO_SVG}Clockchain</a><span class="tnet">Testnet</span></div>
  <div class="nav-links">
    <a href="/">Overview</a>
    <a href="/clock-tools">Clock tools</a>
    <a href="/handshake/sop">Handshake SOP</a>
    <a href="/status.json">status.json</a>
  </div>
</div></nav>

<div class="banner b-${r.overall}">
  <span class="dot"></span>
  <h1>${OVERALL_LABEL[r.overall]}</h1>
  <span class="ts">computed ${esc(computedIso)}<br/>live probes · ${r.window.cacheTtlMs ? `cached ≤ ${r.window.cacheTtlMs / 1000}s` : "uncached"}</span>
</div>

<table class="st-table">
  <thead><tr><th>Component</th><th>State</th><th>Detail</th></tr></thead>
  <tbody>${rows}</tbody>
</table>

<div class="cards">
  <div class="card">
    <h3>Last verified handshake</h3>
    ${lvCard}
  </div>
  <div class="card">
    <h3>Deployed build</h3>
    <div class="big">mcp-server ${esc(r.build.service)} · helper ${esc(r.build.helperVersion)}</div>
    <div class="sub-line">protocol repository <code>${esc(r.build.protocolRepositorySha ? `${r.build.protocolRepositorySha.slice(0, 12)}…` : "unreported")}</code> (relay-reported)</div>
    <div class="sub-line">process uptime ${ago(uptimeS).replace(" ago", "")} · since ${esc(new Date(r.processStartedAtMs).toISOString())}</div>
  </div>
</div>

<div class="perf-head">Performance — <span class="perf-window">${esc(perf.windowLabel)}</span></div>
<div class="cards">
  <div class="card">
    <h3>HTTP requests</h3>
    <div class="big">${perf.http.totalRequests} total · ${perf.http.activeRequests} active</div>
    <div class="sub-line">${perf.http.totalErrors} server errors (${pct(perf.http.errorRate)} error rate) · uptime ${ago(perf.uptimeSeconds).replace(" ago", "")}</div>
  </div>
  <div class="card">
    <h3>Handshake tools</h3>
    <div class="big">${perf.handshakeTools.totalCalls} calls · ${perf.handshakeTools.activeCalls} active</div>
    <div class="sub-line">${perf.handshakeTools.totalFailures} failures · ${perf.handshakeTools.completions} completions · ${perf.handshakeTools.inflightSessions} sessions in flight</div>
  </div>
</div>
${perfTable}

<p class="st-note">Component states come from live dependency probes run at the observation times shown —
a probe that fails reports down/degraded, never a remembered "healthy". The machine-readable view is
<code>GET /status.json</code>; the cheap liveness probe is <code>GET /health</code>. Readiness is split:
<code>GET /readyz</code> reports core MCP-host readiness and stays ready while the host can serve,
even if handshake dependencies are down; <code>GET /readyz/handshake</code> is the dependency-gated
handshake readiness view. Last-verified evidence is informational only — an idle
service with no recent canary stays operational; only a scheduled read-only synthetic protocol probe
may feed protocol readiness. Counter data covers <b>since process start</b> only — no
long-term history is fabricated. Anchored on the ${SUBSTRATE_LABEL}.</p>

<footer><div class="wrap">
  <div class="foot-row">
    <a class="brand" href="/">${LOGO_SVG}Clockchain</a>
    <div class="foot-links">
      <a href="/">Overview</a>
      <a href="/handshake/sop">Handshake SOP</a>
      <a href="/status.json">status.json</a>
      <a href="/health">Health</a>
    </div>
  </div>
  <p class="disclaimer">Clockchain MCP + Agent Handshake · public operational status · computed live ${esc(computedIso)} · observation window: ${esc(r.window.label)}.</p>
</div></footer>
</body>
</html>`;
}
