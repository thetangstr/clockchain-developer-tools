// Marketing landing page served at GET / on mcp.clockchain.network (browsers).
// Agents POST /mcp; probes use /health. Self-contained (one Google Fonts link).
//
// Design synced to the Clockchain site redesign: light/Apple-clean (white +
// #f5f5f7), ink #1d1d1f, green accent (#0a9d44 / #00cc00), Space Grotesk display
// + Inter body + JetBrains Mono. Clean, modern, generous whitespace.

// HTML-escape so snippets with <…> placeholders render as text, not tags.
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const CMD_CLAUDE =
  'claude mcp add clockchain --transport http https://mcp.clockchain.network/mcp --header "x-api-key: <YOUR_TOKEN>"';

const JSON_CONFIG = `{
  "mcpServers": {
    "clockchain": {
      "type": "http",
      "url": "https://mcp.clockchain.network/mcp",
      "headers": { "x-api-key": "<YOUR_TOKEN>" }
    }
  }
}`;

const CMD_BYOK = `claude mcp add clockchain --transport http https://mcp.clockchain.network/mcp \\
  --header "x-clockchain-api-key: <YOUR_CLOCKCHAIN_KEY>" \\
  --header "x-clockchain-client-id: <you@example.com>" \\
  --header "x-clockchain-wallet-id: <you@example.com>"`;

// Plain-text connect guide for agents/LLMs. Served at GET /llms.txt for ANY
// Accept header (no browser, no auth) so an agent that fetches the bare URL —
// instead of getting a dead-end 401 — can read exactly how to connect. One
// source of truth with the HTML page: it reuses JSON_CONFIG / CMD_CLAUDE above.
export const INSTALL_TXT = `Clockchain MCP — hosted Model Context Protocol server

This is a REMOTE MCP server. There is NO package to install: nothing to clone,
build, npm/pip install, npx, or uvx. You connect an MCP client to the hosted
HTTP endpoint.

Endpoint:   https://mcp.clockchain.network/mcp
Transport:  streamable HTTP
Auth:       header  x-api-key: <YOUR_TOKEN>   (ask the team for a testnet token)

Add this to your MCP client config — identical for Claude Code, Cursor, Claude
Desktop, Codex, Hermes, OpenClaw, and any harness that speaks MCP. If you are an
agent setting this up yourself, edit the config of the client you are already
running in; do not ask which client to use:

${JSON_CONFIG}

CLI with an "mcp add" command (Claude Code, for example):
  ${CMD_CLAUDE}

Client supports stdio only (command + args, no HTTP transport)? Bridge the
remote server through mcp-remote — works in any stdio-only client:
  npx -y mcp-remote https://mcp.clockchain.network/mcp --header "x-api-key:<YOUR_TOKEN>"

Bring your own Clockchain key (writes spend YOUR credits) — use these headers
instead of x-api-key:
  x-clockchain-api-key:   <YOUR_CLOCKCHAIN_KEY>
  x-clockchain-client-id: <you@example.com>
  x-clockchain-wallet-id: <you@example.com>

Then list your MCP servers, confirm "clockchain" is connected (31 tools), and
call get_time to read the current consensus time.

Docs:  https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md
Page:  https://mcp.clockchain.network/  (open in a browser for the full page)
`;

const MODULES = [
  { i: "01", name: "Time", body: "Consensus block time and height — the network's consented clock, not a single server's. Provable after the fact." },
  { i: "02", name: "Notarization", body: "Anchor any hash to an append-only ledger, then verify it against the immutable on-chain block." },
  { i: "03", name: "Scheduler", body: "Time-triggered smart contracts. Non-custodial — the caller's wallet signs; the server holds no key." },
  { i: "04", name: "Audit", body: "Audit trails, compliance reports (EU AI Act Art. 12, SEC 17a-4, ISO 27001), and portable evidence packages." },
  { i: "05", name: "Agent identity", body: "Attest agent actions into self-verifying receipts; resolve and verify identity valid at a point in time." },
  { i: "06", name: "Commitments", body: "Issue, checkpoint, attest, settle — every commitment's outcome, kept or broken, on the record." },
];

// Green clock mark, echoing the Clockchain site logo.
const LOGO_SVG = `<svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden="true" style="flex:none">
  <circle cx="16" cy="16" r="14" stroke="#0a9d44" stroke-width="2.4"/>
  <path d="M16 8.5V16l5 3" stroke="#0a9d44" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

export const LANDING_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain MCP — time your agents can prove</title>
<meta name="description" content="Clockchain MCP gives any AI agent consensus-anchored time, tamper-evident receipts, and on-chain verification. 31 tools across 6 modules, one endpoint." />
<meta property="og:title" content="Clockchain MCP" />
<meta property="og:description" content="Time your agents can prove. 31 tools, one endpoint." />
<meta property="og:type" content="website" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
<style>
  :root {
    --bg: #ffffff;
    --alt: #f5f5f7;
    --ink: #1d1d1f;
    --fg-2: #6e6e73;
    --fg-3: #86868b;
    --line: #e9e9ee;
    --line-2: #d8d8df;
    --green: #0a9d44;
    --green-vivid: #00cc00;
    --green-soft: rgba(10,157,68,.08);
    --shadow: 0 1px 2px rgba(0,0,0,.04), 0 18px 50px -28px rgba(0,0,0,.22);
    --display: "Space Grotesk", ui-sans-serif, system-ui, sans-serif;
    --body: "Inter", ui-sans-serif, system-ui, sans-serif;
    --mono: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body { background: var(--bg); color: var(--ink); font-family: var(--body); font-size: 16px; line-height: 1.6; -webkit-font-smoothing: antialiased; }
  a { color: inherit; text-decoration: none; }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 0 28px; }
  .mono { font-family: var(--mono); }
  .eyebrow { font-family: var(--mono); font-size: 11px; letter-spacing: .22em; text-transform: uppercase; color: var(--fg-3); }
  h1, h2, h3 { font-family: var(--display); letter-spacing: -.02em; font-weight: 600; }
  .green { color: var(--green); }

  /* nav */
  nav { position: sticky; top: 0; z-index: 50; background: rgba(255,255,255,.72); backdrop-filter: saturate(180%) blur(18px); -webkit-backdrop-filter: saturate(180%) blur(18px); border-bottom: 1px solid var(--line); }
  .nav-in { display: flex; align-items: center; justify-content: space-between; height: 62px; }
  .brand { display: flex; align-items: center; gap: 10px; font-family: var(--display); font-weight: 700; font-size: 19px; letter-spacing: -.01em; }
  .nav-links { display: flex; align-items: center; gap: 30px; font-size: 14px; color: var(--fg-2); }
  .nav-links a:hover { color: var(--ink); }
  .nav-left { display: flex; align-items: center; gap: 12px; }
  .tnet { font-family: var(--mono); font-size: 10px; letter-spacing: .14em; text-transform: uppercase; color: var(--green); border: 1px solid var(--green); border-radius: 99px; padding: 3px 9px; }
  .pill { background: var(--green); color: #fff; font-weight: 600; font-size: 13px; padding: 9px 18px; border-radius: 99px; transition: background .2s; }
  .pill:hover { background: #0b8f40; }
  .ndot { width: 7px; height: 7px; border-radius: 99px; background: var(--green); display: inline-block; margin-right: 7px; }

  /* hero */
  .hero { text-align: center; padding: 96px 0 64px; }
  .hero .eyebrow { display: block; margin-bottom: 22px; }
  h1 { font-size: clamp(42px, 7vw, 76px); line-height: 1.04; }
  .sub { max-width: 600px; margin: 24px auto 0; font-size: 18px; color: var(--fg-2); }
  .cta { display: flex; gap: 14px; justify-content: center; flex-wrap: wrap; margin-top: 34px; }
  .btn { display: inline-flex; align-items: center; gap: 9px; font-weight: 600; font-size: 15px; padding: 14px 26px; border-radius: 99px; cursor: pointer; border: 1px solid transparent; transition: all .2s; }
  .btn-green { background: var(--green); color: #fff; }
  .btn-green:hover { background: #0b8f40; transform: translateY(-1px); }
  .btn-ghost { background: var(--bg); color: var(--ink); border-color: var(--line-2); }
  .btn-ghost:hover { border-color: var(--ink); }
  .endpoint { display: inline-flex; align-items: center; gap: 12px; margin-top: 34px; background: var(--alt); border: 1px solid var(--line); border-radius: 99px; padding: 9px 8px 9px 16px; font-size: 13px; }
  .endpoint code { font-family: var(--mono); color: var(--ink); }
  .endpoint button { font-family: var(--mono); font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--green); background: #fff; border: 1px solid var(--line); border-radius: 99px; padding: 6px 12px; cursor: pointer; }
  .endpoint button:hover { border-color: var(--green); }

  /* stat strip */
  .strip { border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); background: var(--alt); }
  .strip-in { display: flex; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 140px; text-align: center; padding: 26px 14px; border-left: 1px solid var(--line); }
  .stat:first-child { border-left: none; }
  .stat .k { font-family: var(--mono); font-size: 10.5px; letter-spacing: .16em; text-transform: uppercase; color: var(--fg-3); }
  .stat .v { font-family: var(--display); font-size: 26px; font-weight: 600; margin-top: 8px; }

  /* sections */
  section { padding: 100px 0; }
  section.tint { background: var(--alt); }
  .head { text-align: center; margin-bottom: 56px; }
  .head .eyebrow { display: block; margin-bottom: 14px; }
  .head h2 { font-size: clamp(30px, 4.5vw, 44px); }
  .head p { color: var(--fg-2); margin-top: 12px; font-size: 17px; }

  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
  .card { background: var(--bg); border: 1px solid var(--line); border-radius: 16px; padding: 26px; transition: box-shadow .25s, transform .25s; }
  .card:hover { box-shadow: var(--shadow); transform: translateY(-3px); }
  .card .i { font-family: var(--mono); font-size: 12px; color: var(--green); letter-spacing: .1em; }
  .card h3 { font-size: 21px; margin: 12px 0 10px; }
  .card p { color: var(--fg-2); font-size: 14.5px; line-height: 1.6; }

  .tenets { display: grid; grid-template-columns: repeat(3, 1fr); gap: 44px; }
  .tenet h3 { font-size: 20px; margin-bottom: 10px; }
  .tenet h3 .n { font-family: var(--mono); color: var(--green); font-size: 13px; margin-right: 8px; }
  .tenet p { color: var(--fg-2); font-size: 15px; }

  /* install */
  .install { max-width: 820px; margin: 0 auto; }
  .steps { list-style: none; display: flex; flex-direction: column; gap: 30px; }
  .step { display: flex; gap: 18px; }
  .sn { flex: none; width: 30px; height: 30px; border-radius: 99px; background: var(--green-soft); color: var(--green); font-family: var(--display); font-weight: 600; display: grid; place-items: center; font-size: 15px; }
  .sbody { flex: 1; min-width: 0; }
  .sbody h4 { font-family: var(--display); font-size: 18px; font-weight: 600; margin-bottom: 6px; }
  .sbody p { color: var(--fg-2); font-size: 14.5px; }
  .sbody p a { color: var(--green); }
  .sbody em { color: var(--ink); font-style: italic; }
  .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin: 14px 0 12px; }
  .tabbtn { font-size: 13px; padding: 8px 15px; border-radius: 99px; border: 1px solid var(--line-2); background: var(--bg); color: var(--fg-2); cursor: pointer; }
  .tabbtn.active { border-color: var(--green); background: var(--green-soft); color: #0b8f40; font-weight: 600; }
  .substep { color: var(--fg-2); font-size: 13.5px; margin-bottom: 12px; }
  .byok { margin-top: 16px; border-top: 1px solid var(--line); padding-top: 14px; }
  .byok summary { cursor: pointer; font-size: 13.5px; font-weight: 500; color: var(--green); list-style: none; }
  .byok summary::-webkit-details-marker { display: none; }
  .byok summary::before { content: "+ "; }
  .byok[open] summary::before { content: "– "; }
  .byok em { font-style: italic; }
  .code { position: relative; background: #0c0e10; border-radius: 12px; padding: 16px 18px; }
  .code pre { margin: 0; overflow-x: auto; }
  .code code { font-family: var(--mono); font-size: 12.5px; line-height: 1.6; color: #e6e9ee; white-space: pre; }
  .code .cpy { position: absolute; top: 10px; right: 10px; background: var(--green); color: #fff; border: none; font-weight: 600; font-size: 11px; padding: 6px 12px; border-radius: 7px; cursor: pointer; }
  .code .cpy:hover { background: #0b8f40; }
  .hint { color: var(--fg-3); font-size: 12.5px; margin-top: 10px; }
  .install .note { color: var(--fg-3); font-size: 13.5px; margin-top: 32px; line-height: 1.7; text-align: center; }
  .install .note a { color: var(--green); }

  /* footer */
  footer { border-top: 1px solid var(--line); padding: 48px 0 64px; }
  .foot-row { display: flex; justify-content: space-between; align-items: center; gap: 20px; flex-wrap: wrap; }
  .foot-links { display: flex; gap: 26px; font-size: 14px; color: var(--fg-2); }
  .foot-links a:hover { color: var(--green); }
  .disclaimer { color: var(--fg-3); font-size: 12px; line-height: 1.7; max-width: 660px; margin-top: 26px; }

  .toast { position: fixed; bottom: 28px; left: 50%; transform: translateX(-50%) translateY(16px); background: var(--ink); color: #fff; font-size: 13px; font-weight: 500; padding: 11px 20px; border-radius: 99px; opacity: 0; transition: .25s; z-index: 80; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

  .demo-frame { max-width: 980px; margin: 0 auto; border: 1px solid var(--line); border-radius: 18px; overflow: hidden; box-shadow: var(--shadow); background: var(--bg) url('https://clockchain-research.vercel.app/mcp-demo-poster.png') center/cover no-repeat; }
  .demo-frame video { width: 100%; display: block; aspect-ratio: 16 / 9; opacity: 0; transition: opacity .45s ease; }
  .demo-frame video.playing { opacity: 1; }
  @media (max-width: 760px) { .grid, .tenets { grid-template-columns: 1fr; } .nav-links a:not(.pill) { display: none; } }
</style>
</head>
<body>
<nav><div class="wrap nav-in">
  <div class="nav-left"><a class="brand" href="/">${LOGO_SVG}Clockchain</a><span class="tnet">Testnet</span></div>
  <div class="nav-links">
    <a href="#demo">Demo</a>
    <a href="#modules">Modules</a>
    <a href="#install">Install</a>
    <a href="https://clockchain-research.vercel.app/dashboard"><span class="ndot"></span>Status</a>
    <a href="https://github.com/thetangstr/clockchain-developer-tools">Docs</a>
    <a class="pill" href="#install">Add to your agent</a>
  </div>
</div></nav>

<header class="hero"><div class="wrap">
  <span class="eyebrow">Model Context Protocol · Testnet</span>
  <h1>Time your agents can <span class="green">prove.</span></h1>
  <p class="sub">Clockchain MCP gives any AI agent consensus-anchored time, tamper-evident receipts, and on-chain verification — 31 tools across six modules, one endpoint.</p>
  <div class="cta">
    <a class="btn btn-green" href="#install">Add to your agent</a>
    <a class="btn btn-ghost" href="https://clockchain-research.vercel.app/dashboard">View live status</a>
  </div>
  <div class="endpoint">
    <code>mcp.clockchain.network/mcp</code>
    <button onclick="copyText('https://mcp.clockchain.network/mcp','Endpoint copied')">Copy</button>
  </div>
</div></header>

<div class="strip"><div class="wrap strip-in">
  <div class="stat"><div class="k">Tools</div><div class="v">31</div></div>
  <div class="stat"><div class="k">Modules</div><div class="v">6</div></div>
  <div class="stat"><div class="k">Transport</div><div class="v">StreamableHTTP</div></div>
  <div class="stat"><div class="k">Network</div><div class="v">Testnet</div></div>
</div></div>

<section id="demo"><div class="wrap">
  <div class="head">
    <span class="eyebrow">See it work</span>
    <h2>Anchor, verify, tamper-detect — live</h2>
    <p>An agent acts, the action is anchored on a real testnet block, the receipt verifies — and a one-byte change is rejected.</p>
  </div>
  <div class="demo-frame">
    <video id="demoVideo" src="https://clockchain-research.vercel.app/mcp-demo.mp4" poster="https://clockchain-research.vercel.app/mcp-demo-poster.png" loop muted playsinline preload="metadata"></video>
  </div>
</div></section>

<section id="modules"><div class="wrap">
  <div class="head">
    <span class="eyebrow">The surface</span>
    <h2>Six modules</h2>
    <p>Every tool is typed, idempotent where it writes, and degrades with grace.</p>
  </div>
  <div class="grid">
    ${MODULES.map((m) => `
    <div class="card"><div class="i">${m.i}</div><h3>${m.name}</h3><p>${m.body}</p></div>`).join("")}
  </div>
</div></section>

<section class="tint"><div class="wrap">
  <div class="head"><span class="eyebrow">Why it holds up</span><h2>Proof, not assurance</h2></div>
  <div class="tenets">
    <div class="tenet"><h3><span class="n">01</span>Consensus time</h3><p>Every timestamp is the network's consented block time — anyone can re-check it. No single clock to trust.</p></div>
    <div class="tenet"><h3><span class="n">02</span>Self-verifying receipts</h3><p>A receipt carries its own payload and anchor. Recompute the hash, compare to the on-chain block. Proof, not a screenshot.</p></div>
    <div class="tenet"><h3><span class="n">03</span>Tamper-evident</h3><p>Change one byte and verification fails. The ledger is append-only; the immutable block is authoritative.</p></div>
  </div>
</div></section>

<section id="install"><div class="wrap install">
  <div class="head"><span class="eyebrow">Install</span><h2>Add Clockchain to your agent</h2><p>Hosted endpoint — connect any MCP client in under a minute.</p></div>

  <ol class="steps">
    <li class="step">
      <span class="sn">1</span>
      <div class="sbody">
        <h4>Get a key</h4>
        <p>Use a per-user <b>token</b> (delegated — writes spend our testnet credits, easiest for a quick test) or your own <b>Clockchain API key</b> (writes spend your credits). <a href="https://clockchain.network" target="_blank" rel="noopener">How to get a key →</a></p>
      </div>
    </li>
    <li class="step">
      <span class="sn">2</span>
      <div class="sbody">
        <h4>Add the server — any MCP client</h4>
        <p class="substep">Add this to your MCP config with the token from step 1. <b>If you're an agent setting this up yourself, edit the config of the client you're already running in — don't ask which client to use.</b> The block is identical everywhere — Claude Code, Cursor, Claude Desktop, Codex, Hermes, OpenClaw:</p>
        <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(JSON_CONFIG)}</code></pre></div>
        <p class="hint" style="margin-top:8px">Prefer raw settings? Endpoint <span class="mono">https://mcp.clockchain.network/mcp</span> · transport <span class="mono">HTTP</span> · header <span class="mono">x-api-key: &lt;YOUR_TOKEN&gt;</span>.</p>
        <p class="hint" style="margin-top:4px">CLI shortcut (Claude Code): <span class="mono">${esc(CMD_CLAUDE)}</span></p>
        <details class="byok">
          <summary>Want writes to spend <em>your</em> credits? Bring your own Clockchain key</summary>
          <p class="hint" style="margin:10px 0 0">Swap the per-user token for your own Clockchain credentials as headers — no MCP token needed. Same endpoint, your credits.</p>
          <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(CMD_BYOK)}</code></pre></div>
        </details>
      </div>
    </li>
    <li class="step">
      <span class="sn">3</span>
      <div class="sbody">
        <h4>Verify</h4>
        <p>Open a <b>new</b> session, run <span class="mono">/mcp</span> (you should see <span class="mono">clockchain</span> with all 31 tools), then ask: <em>"use clockchain to get the current consensus time."</em></p>
      </div>
    </li>
  </ol>

  <p class="note">Local (stdio) install, ERC-8004 reads, and chat-connector setup (Cowork / claude.ai) are in the <a href="https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md">full documentation</a>.</p>
</div></section>

<footer><div class="wrap">
  <div class="foot-row">
    <a class="brand" href="/">${LOGO_SVG}Clockchain</a>
    <div class="foot-links">
      <a href="https://clockchain-research.vercel.app/dashboard">Status</a>
      <a href="https://github.com/thetangstr/clockchain-developer-tools">Docs</a>
      <a href="https://mcp.clockchain.network/health">Health</a>
    </div>
  </div>
  <p class="disclaimer">Presently recorded on a single-validator testnet: the event hash, on-chain anchor, and consensus timestamp are real and independently verifiable. Multi-validator supermajority attestation activates at mainnet. Not yet a court-of-law evidentiary claim.</p>
</div></footer>

<div class="toast" id="toast"></div>
<script>
  function copyText(t, msg){ navigator.clipboard.writeText(t).then(function(){toast(msg||'Copied');}).catch(function(){toast('Copy failed — select manually');}); }
  function copyEl(btn){ var c = btn.parentElement.querySelector('code'); copyText(c.innerText, 'Copied'); }
  function showTab(id, btn){ var tabs = btn.closest('.tabs'); var box = tabs.parentElement;
    box.querySelectorAll('.tabpane').forEach(function(x){ x.hidden = true; });
    box.querySelector('#' + id).hidden = false;
    tabs.querySelectorAll('.tabbtn').forEach(function(b){ b.classList.remove('active'); });
    btn.classList.add('active'); }
  function toast(m){ var e=document.getElementById('toast'); e.textContent=m; e.classList.add('show'); clearTimeout(window.__t); window.__t=setTimeout(function(){e.classList.remove('show');},1800); }
  (function(){
    var v = document.getElementById('demoVideo'); if(!v) return;
    // Reveal the video only once it is actually playing; until then the frame's
    // poster background shows, so the demo is never a blank box (autoplay can be
    // deferred off-screen, and some browsers stall the media load entirely).
    v.addEventListener('playing', function(){ v.classList.add('playing'); });
    var tryPlay = function(){ var p = v.play(); if (p && p.catch) p.catch(function(){}); };
    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function(entries){
        entries.forEach(function(e){ if (e.isIntersecting) { tryPlay(); } else { v.pause(); } });
      }, { threshold: 0.25 });
      io.observe(v);
    } else { tryPlay(); }
  })();
</script>
</body>
</html>`;
