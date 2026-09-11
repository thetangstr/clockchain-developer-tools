// The verified-time tools guide: /clock-tools (HTML for people) and /clock-tools.txt
// (plain text for agents). Same stylesheet and chrome as the landing page, same facts
// in both renderings — every argument name, bound and field below is the one the tool
// schemas in tools.ts publish, and the example numbers are from real runs against
// production (GATES.md, eval/reports).
import { BASE_CSS, LOGO_SVG, SUBSTRATE_LABEL } from "./landing.js";

const ENDPOINT = "https://mcp.clockchain.network/mcp";
const REPO = "https://github.com/thetangstr/clockchain-developer-tools";

/** The three tool families as one table of facts: rendered to HTML and to text below. */
const TOOLS = [
  {
    key: "stopwatch",
    name: "Stopwatch",
    tagline: "Elapsed time between two anchored markers — measured on consensus time, re-verifiable by anyone.",
    how:
      "stopwatch_start anchors a START marker and waits for its block; stopwatch_stop anchors a STOP marker " +
      "and returns elapsedMs = stop − start from the ledger's consensus timestamps, never your clock. " +
      "stopwatch_verify recomputes the elapsed time from the two immutable block times with no key at all.",
    ask: 'Using Clockchain, start a stopwatch labelled "build-42", do the work, stop it, then verify the measurement keylessly and report elapsedOnChainMs.',
    tools: [
      { name: "stopwatch_start", args: "{ label, wait_ms?, idempotency_key?, allow_degraded? }", returns: "start.ledgerId, start.blockHeight, start.createdTimestamp", cost: "1 credit" },
      { name: "stopwatch_stop", args: "{ label, start_ledger_id, wait_ms?, idempotency_key?, allow_degraded? }", returns: "elapsedMs, start, stop, status (\"anchored\" only when both markers have a block)", cost: "1 credit" },
      { name: "stopwatch_verify", args: "{ start_ledger_id, stop_ledger_id, start_block_height?, stop_block_height? }", returns: "verified, elapsedOnChainMs, elapsedRecordedMs, per-marker verifiedAgainst", cost: "free, keyless" },
    ],
    example: `stopwatch_start { "label": "build-42" }
→ { "start": { "ledgerId": "a1c3…", "blockHeight": "702", "createdTimestamp": "2026-09-11T06:08:57.101Z" } }

stopwatch_stop { "label": "build-42", "start_ledger_id": "a1c3…" }
→ { "elapsedMs": 6937, "status": "anchored", "stop": { "ledgerId": "9f0e…", "blockHeight": "704" } }

stopwatch_verify { "start_ledger_id": "a1c3…", "stop_ledger_id": "9f0e…" }
→ { "verified": true, "elapsedOnChainMs": 6937, "elapsedRecordedMs": 6937 }`,
    notes: [
      "Two credits per measurement (one per marker). The stop marker re-reads the start marker from the ledger by id — a wrong start_ledger_id is refused, not silently accepted.",
      "Resolution is the block time: on the current substrate a block seals within ~1 s of the write, so expect elapsed to be within about a second of wall-clock.",
    ],
  },
  {
    key: "timer",
    name: "Timer",
    tagline: "A countdown that fires on verified time while your agent is offline — never early — and anchors the fire.",
    how:
      "timer_set arms a one-shot trigger delay_ms from now on the hosted keeper (consensus time, not the host clock). " +
      "You can disconnect; the keeper fires it, anchors the fire as an Agent Attested Receipt, and holds the result. " +
      "Poll timer_status { id } until status is \"done\"; the fire's anchor (ledgerId + blockHeight) verifies keylessly.",
    ask: 'Using the Clockchain hosted timer: set a 5 second timer labelled "cooldown", poll its status until it fires (do not set a second timer), then report the fire\'s ledger id and block height and verify it keylessly.',
    tools: [
      { name: "timer_set", args: "{ delay_ms (1000 … 2592000000), label?, payload?, webhook_url? }", returns: "id, fireAtIso, status \"scheduled\", delivery poll|webhook, webhookSecret (once, if a webhook was given)", cost: "1 credit per fire" },
      { name: "timer_status", args: "{ id }", returns: "status scheduled|firing|done|cancelled|dead, fires[] with anchor.ledgerId, anchor.blockHeight, firedAtIso, receipt", cost: "free" },
      { name: "timer_cancel", args: "{ id }", returns: "status \"cancelled\" (idempotent on a finished one)", cost: "free" },
      { name: "timer_list", args: "{ }", returns: "count, triggers[] (yours only, soonest first)", cost: "free" },
    ],
    example: `timer_set { "delay_ms": 5000, "label": "cooldown" }
→ { "id": "5596f3a4-…", "status": "scheduled", "fireAtIso": "2026-09-11T05:55:54.076Z", "delivery": "poll" }

timer_status { "id": "5596f3a4-…" }        (poll every 3–5 s)
→ { "status": "done", "fires": [ { "firedAtIso": "2026-09-11T05:55:54.895Z",
     "anchor": { "status": "anchored", "ledgerId": "2ff5589c-…", "blockHeight": "689" }, "receipt": { … } } ] }

verify_cross_party { "ledger_id": "2ff5589c-…", "block_height": 689 }
→ { "onChain": { "verifiedAgainst": "on-chain block", … } }`,
    notes: [
      "Never early: the fire waits for consensus time to pass the target, then lands on the next keeper tick (1 s). Observed lateness in production runs: +87 ms to +922 ms.",
      "One timer per job: poll the id you were given instead of arming another. The fire's receipt also verifies with verify_receipt { receipt } — both checks are keyless.",
    ],
  },
  {
    key: "alarm",
    name: "Alarm",
    tagline: "Fire at an absolute time — once or on an interval — on verified time, with the same anchored receipt.",
    how:
      "alarm_set takes fire_at (ISO-8601 UTC or epoch milliseconds) up to 30 days out. Add every_ms (≥ 60000) to make it " +
      "recurring: it re-arms after each anchored fire until you cancel it. Everything else is the timer's: timer_status, " +
      "timer_cancel, timer_list work on alarms too — an alarm is a trigger with an absolute target.",
    ask: 'Using the Clockchain hosted alarm: set an alarm labelled "standup" for 2026-09-12T09:00:00Z, confirm it appears in my timer list, then cancel it and report its final status.',
    tools: [
      { name: "alarm_set", args: "{ fire_at (ISO-8601 | epoch ms), every_ms? (≥ 60000), label?, payload?, webhook_url? }", returns: "id, fireAtIso, mode once|interval, delivery, a warning if fire_at is already past (fires on the next tick, once)", cost: "1 credit per fire" },
      { name: "timer_status / timer_cancel / timer_list", args: "as for timers", returns: "the same trigger view", cost: "free" },
    ],
    example: `alarm_set { "fire_at": "2026-09-12T09:00:00Z", "label": "standup" }
→ { "id": "797070c9-…", "kind": "alarm", "status": "scheduled", "fireAtIso": "2026-09-12T09:00:00.000Z", "mode": "once" }

timer_list { }
→ { "count": 1, "triggers": [ { "id": "797070c9-…", "label": "standup", "status": "scheduled", … } ] }

timer_cancel { "id": "797070c9-…" }
→ { "id": "797070c9-…", "status": "cancelled", "cancelled": true }`,
    notes: [
      "Interval alarms spend a credit on every fire; the minimum interval is 60 s. Cancel to stop.",
      "Triggers are scoped to the caller: another token cannot see, poll or cancel yours (timer_status returns 404 for an id that is not yours).",
    ],
  },
] as const;

const LIMITS = [
  ["Rate", "30 tool calls per minute per token; the MCP handshake and tools/list are free."],
  ["Triggers", "Up to 20 active timers/alarms per caller; a fire is 1 s … 30 days out; intervals ≥ 60 s."],
  ["Credits", "Each anchor spends one testnet log credit: two per stopwatch measurement, one per timer/alarm fire. Reads and verification are free."],
  ["Webhooks", "Optional webhook_url on timer_set / alarm_set. Each fire is POSTed with Standard-Webhooks headers (webhook-id, webhook-timestamp, webhook-signature = HMAC-SHA256 with the per-caller secret returned once at registration). Destinations are DNS-pinned and allow-listed on this deployment — ask to have a host added."],
  ["Honest claims", `Fires are anchored on the ${SUBSTRATE_LABEL}: the event hash, block anchor and block time are real and keyless-verifiable, and receipts say so in attestation.substrate. Multi-validator attestation activates at mainnet.`],
] as const;

const EVIDENCE = [
  ["Live gates G0–G4 on production", "12 / 12 — stopwatch, timer, alarm (soft, confirmed, hosted), freshness", `${REPO}/blob/main/packages/clock-sdk/GATES.md`],
  ["Clark, the production agent (Hermes + Bedrock Nova), all 50 tools", "24 / 24 tasks", `${REPO}/tree/main/eval/reports`],
  ["Fresh Claude Code (Opus, Sonnet, Haiku), Codex and Hermes on a demo token", "4 / 4 clock tasks each", `${REPO}/tree/main/eval/reports`],
] as const;

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** For a double-quoted HTML attribute holding a JS string literal. */
const attr = (s: string) => esc(s).replace(/"/g, "&quot;");

// ------------------------------------------------------------------ plain text (agents)
export const CLOCK_TOOLS_TXT = `Clockchain MCP — verified time tools: stopwatch, timer, alarm
============================================================

Three tool families on the hosted Clockchain MCP (${ENDPOINT}) that measure and
schedule on consensus time instead of a machine clock, and anchor every result on
the ledger so anyone can re-verify it without a key. The full page for people is
https://mcp.clockchain.network/clock-tools; this text is the same guide for agents.

CONNECT (once)
  1. Token, no signup:        curl -X POST https://mcp.clockchain.network/token
  2. Add the server to your MCP client config with header x-api-key: <token>
     (all clients: https://mcp.clockchain.network/llms.txt — includes the Codex TOML)
  3. New session, confirm "clockchain" is connected with its tools, then ask.

${TOOLS.map((t) => `${t.name.toUpperCase()}
  ${t.tagline}
  How: ${t.how}
  Ask your agent: ${t.ask}
  Tools:
${t.tools.map((x) => `    ${x.name} ${x.args}\n      returns: ${x.returns}   cost: ${x.cost}`).join("\n")}
  Example:
${t.example.split("\n").map((l) => "    " + l).join("\n")}
  Notes:
${t.notes.map((n) => `    - ${n}`).join("\n")}
`).join("\n")}
AGENT RECIPE (do exactly this; report ledgerId + blockHeight + the verify result)
  stopwatch: stopwatch_start {label} -> work -> stopwatch_stop {label, start_ledger_id}
             -> stopwatch_verify {start_ledger_id, stop_ledger_id}; pass = verified true.
  timer:     timer_set {delay_ms, label} -> poll timer_status {id} every 3-5 s until
             status "done" (never arm a second timer) -> verify_cross_party
             {ledger_id: fires[0].anchor.ledgerId, block_height: fires[0].anchor.blockHeight}
             (or verify_receipt {receipt: fires[0].receipt}); pass = verifiedAgainst "on-chain block".
  alarm:     alarm_set {fire_at ISO-8601 UTC, label} -> timer_list {} shows it ->
             timer_cancel {id} -> status "cancelled". Recurring: add every_ms >= 60000.
  A fire that has not happened yet is status "scheduled" — say so; do not invent a fire.

LIMITS AND HONEST CLAIMS
${LIMITS.map(([k, v]) => `  ${k}: ${v}`).join("\n")}

EVIDENCE (real runs against production, 2026-09-11)
${EVIDENCE.map(([what, result, url]) => `  ${what}: ${result}\n    ${url}`).join("\n")}

More: install and every other module — https://mcp.clockchain.network/llms.txt
`;

// ------------------------------------------------------------------ HTML (people)
export const CLOCK_TOOLS_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clock tools — stopwatch, timer, alarm on Clockchain MCP</title>
<meta name="description" content="How to use Clockchain's verified-time tools from any MCP agent: a stopwatch measured on consensus time, timers and alarms that fire while you are offline, every result anchored and keyless-verifiable." />
<meta property="og:title" content="Clockchain MCP — clock tools" />
<link rel="alternate" type="text/plain" href="/clock-tools.txt" title="Agent-readable version" />
<style>
${BASE_CSS}
  /* page-specific: reference tables and the family sections */
  .hero { padding: 76px 0 48px; }
  .fam { padding: 84px 0; }
  .fam + .fam { border-top: 1px solid var(--line); }
  .fam-head { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; margin-bottom: 10px; }
  .fam-head h2 { font-size: clamp(28px, 4vw, 38px); }
  .fam-head .n { font-family: var(--mono); font-size: 12px; color: var(--green); letter-spacing: .12em; }
  .fam .tag { font-size: 18px; color: var(--fg-2); max-width: 720px; }
  .fam .how { margin: 22px 0 0; max-width: 760px; color: var(--ink); font-size: 15.5px; }
  .ask { margin-top: 22px; background: var(--green-soft); border: 1px solid rgba(10,157,68,.25); border-radius: 12px; padding: 14px 16px; display: flex; gap: 12px; align-items: flex-start; }
  .ask .k { font-family: var(--mono); font-size: 10.5px; letter-spacing: .16em; text-transform: uppercase; color: var(--green); white-space: nowrap; margin-top: 4px; }
  .ask p { font-size: 14.5px; color: var(--ink); font-style: italic; }
  .ask button { margin-left: auto; flex: none; font-family: var(--mono); font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--green); background: #fff; border: 1px solid var(--line); border-radius: 99px; padding: 6px 12px; cursor: pointer; }
  .ref { width: 100%; border-collapse: collapse; margin-top: 26px; font-size: 14px; }
  .ref th { text-align: left; font-family: var(--mono); font-size: 10.5px; letter-spacing: .14em; text-transform: uppercase; color: var(--fg-3); font-weight: 500; padding: 0 12px 10px 0; border-bottom: 1px solid var(--line); }
  .ref td { vertical-align: top; padding: 12px 12px 12px 0; border-bottom: 1px solid var(--line); color: var(--fg-2); }
  .ref td:first-child { font-family: var(--mono); color: var(--ink); white-space: nowrap; font-size: 13px; }
  .ref td.args { font-family: var(--mono); font-size: 12.5px; color: var(--ink); }
  .ref td.cost { white-space: nowrap; color: var(--green); font-weight: 500; }
  .ref-wrap { overflow-x: auto; }
  /* the example is full width (long JSON lines scroll inside the block, never the page);
     the notes sit under it as a two-up list */
  .twocol { margin-top: 26px; min-width: 0; }
  .twocol .code { min-width: 0; }
  .notes { list-style: none; display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px 36px; margin-top: 18px; }
  .notes li { color: var(--fg-2); font-size: 14px; padding-left: 18px; position: relative; }
  .notes li::before { content: ""; position: absolute; left: 0; top: .6em; width: 7px; height: 7px; border-radius: 99px; background: var(--green); }
  .limits { display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px 36px; max-width: 980px; margin: 0 auto; }
  .limit .k { font-family: var(--mono); font-size: 10.5px; letter-spacing: .16em; text-transform: uppercase; color: var(--green); }
  .limit p { color: var(--fg-2); font-size: 14.5px; margin-top: 6px; }
  .ev { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
  .ev .card .v { font-family: var(--display); font-size: 26px; font-weight: 600; margin: 8px 0 6px; }
  .ev .card a { color: var(--green); font-size: 13.5px; }
  .agent { max-width: 820px; margin: 0 auto; }
  .agent .code { margin-top: 18px; }
  .crumbs { font-size: 13px; color: var(--fg-3); margin-bottom: 18px; }
  .crumbs a { color: var(--green); }
  .limits, .ev, .limit, .ev .card { min-width: 0; }
  @media (max-width: 760px) { .notes, .limits, .ev { grid-template-columns: 1fr; } .ask { flex-direction: column; } .ask button { margin-left: 0; } }
</style>
</head>
<body>
<nav><div class="wrap nav-in">
  <div class="nav-left"><a class="brand" href="/">${LOGO_SVG}Clockchain</a><span class="tnet">Testnet</span></div>
  <div class="nav-links">
    <a href="#stopwatch">Stopwatch</a>
    <a href="#timer">Timer</a>
    <a href="#alarm">Alarm</a>
    <a href="#agents">For agents</a>
    <a href="/clock-tools.txt">Text version</a>
    <a class="pill" href="/#install">Add to your agent</a>
  </div>
</div></nav>

<header class="hero"><div class="wrap">
  <span class="eyebrow">Verified time tools · module 07</span>
  <h1>Stopwatch, timer, alarm — <span class="green">on time you can prove.</span></h1>
  <p class="sub">Measure and schedule on Clockchain consensus time instead of a machine clock. Timers and alarms fire while your agent is offline, never early; every result is anchored on the ledger and re-verifiable by anyone, with no key.</p>
  <div class="cta">
    <a class="btn btn-green" href="/#install">Connect in a minute</a>
    <a class="btn btn-ghost" href="/clock-tools.txt">Agent-readable version</a>
  </div>
  <div class="endpoint">
    <code>mcp.clockchain.network/mcp</code>
    <button onclick="copyText('${ENDPOINT}','Endpoint copied')">Copy</button>
  </div>
</div></header>

<div class="strip"><div class="wrap strip-in">
  <div class="stat"><div class="k">Tools</div><div class="v">8</div></div>
  <div class="stat"><div class="k">Fires while offline</div><div class="v">Yes</div></div>
  <div class="stat"><div class="k">Early fires</div><div class="v">Never</div></div>
  <div class="stat"><div class="k">Horizon</div><div class="v">1 s – 30 d</div></div>
  <div class="stat"><div class="k">Verification</div><div class="v">Keyless</div></div>
</div></div>

${TOOLS.map((t, i) => `
<section class="fam" id="${t.key}"><div class="wrap">
  <div class="fam-head"><span class="n">0${i + 1}</span><h2>${t.name}</h2></div>
  <p class="tag">${esc(t.tagline)}</p>
  <p class="how">${esc(t.how)}</p>
  <div class="ask"><span class="k">Ask your agent</span><p>“${esc(t.ask)}”</p><button onclick="copyText(${attr(JSON.stringify(t.ask))},'Prompt copied')">Copy</button></div>
  <div class="ref-wrap"><table class="ref">
    <thead><tr><th>Tool</th><th>Arguments</th><th>Returns</th><th>Cost</th></tr></thead>
    <tbody>${t.tools.map((x) => `
      <tr><td>${esc(x.name)}</td><td class="args">${esc(x.args)}</td><td>${esc(x.returns)}</td><td class="cost">${esc(x.cost)}</td></tr>`).join("")}
    </tbody>
  </table></div>
  <div class="twocol">
    <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(t.example)}</code></pre></div>
    <ul class="notes">${t.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
  </div>
</div></section>`).join("")}

<section class="tint" id="agents"><div class="wrap agent">
  <div class="head"><span class="eyebrow">For agents</span><h2>The recipe, exactly</h2><p>If you are an agent reading this page: connect (see <a href="/llms.txt" style="color:var(--green)">/llms.txt</a>), then do these steps and report the ledger id, block height and the verify result. Never invent a fire — a trigger that has not fired yet says <span class="mono">scheduled</span>.</p></div>
  <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(`stopwatch:  stopwatch_start {label} → work → stopwatch_stop {label, start_ledger_id}
            → stopwatch_verify {start_ledger_id, stop_ledger_id}          pass = verified: true

timer:      timer_set {delay_ms, label} → poll timer_status {id} every 3–5 s until status "done"
            (never arm a second timer)
            → verify_cross_party {ledger_id: fires[0].anchor.ledgerId, block_height: fires[0].anchor.blockHeight}
              or verify_receipt {receipt: fires[0].receipt}                 pass = verifiedAgainst: "on-chain block"

alarm:      alarm_set {fire_at ISO-8601 UTC, label} → timer_list {} shows it → timer_cancel {id}
            → status "cancelled".   Recurring: every_ms ≥ 60000; cancel to stop.`)}</code></pre></div>
  <p class="hint" style="text-align:center;margin-top:14px">The same guide as plain text, for context windows and curl: <a href="/clock-tools.txt" style="color:var(--green)">mcp.clockchain.network/clock-tools.txt</a></p>
</div></section>

<section id="limits"><div class="wrap">
  <div class="head"><span class="eyebrow">Limits and honest claims</span><h2>What you are getting</h2></div>
  <div class="limits">${LIMITS.map(([k, v]) => `
    <div class="limit"><div class="k">${esc(k)}</div><p>${esc(v)}</p></div>`).join("")}
  </div>
</div></section>

<section class="tint" id="evidence"><div class="wrap">
  <div class="head"><span class="eyebrow">Evidence</span><h2>Tested the way you will use it</h2><p>Real runs against this endpoint on 2026-09-11 — every check is an on-chain re-read, not a screenshot.</p></div>
  <div class="ev">${EVIDENCE.map(([what, result, url]) => `
    <div class="card"><p>${esc(what)}</p><div class="v">${esc(result)}</div><a href="${url}">See the record →</a></div>`).join("")}
  </div>
</div></section>

<footer><div class="wrap">
  <div class="foot-row">
    <a class="brand" href="/">${LOGO_SVG}Clockchain</a>
    <div class="foot-links">
      <a href="/">All modules</a>
      <a href="/clock-tools.txt">Text version</a>
      <a href="https://clockchain-research.vercel.app/dashboard">Status</a>
      <a href="${REPO}">Docs</a>
    </div>
  </div>
  <p class="disclaimer">Presently anchored on the ${SUBSTRATE_LABEL}: the event hash, block anchor, and block time are real and keyless-verifiable against the sealed block, but not yet attested by an independent validator set. Multi-validator supermajority attestation activates at mainnet. Not yet a court-of-law evidentiary claim.</p>
</div></footer>

<div class="toast" id="toast"></div>
<script>
  function copyText(t, msg){ navigator.clipboard.writeText(t).then(function(){toast(msg||'Copied');}).catch(function(){toast('Copy failed — select manually');}); }
  function copyEl(btn){ var c = btn.parentElement.querySelector('code'); copyText(c.innerText, 'Copied'); }
  function toast(m){ var e=document.getElementById('toast'); e.textContent=m; e.classList.add('show'); clearTimeout(window.__t); window.__t=setTimeout(function(){e.classList.remove('show');},1800); }
</script>
</body>
</html>`;
