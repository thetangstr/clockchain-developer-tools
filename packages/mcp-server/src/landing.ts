// Marketing landing page served at GET / on mcp.clockchain.network (browsers).
// Agents keep using POST /mcp; probes keep using /health. Self-contained — no
// external assets beyond a Google Fonts link — so it ships with the Node server.

const INSTALL_CMD =
  'claude mcp add --transport http clockchain https://mcp.clockchain.network/mcp --header "x-api-key: <YOUR_KEY>"';

export const LANDING_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain MCP — verifiable time &amp; proof for AI agents</title>
<meta name="description" content="Clockchain MCP gives any AI agent consensus-anchored time, tamper-evident receipts, and on-chain verification. 31 tools across 6 modules over one StreamableHTTP endpoint." />
<meta property="og:title" content="Clockchain MCP" />
<meta property="og:description" content="Verifiable time, identity, and proof for AI agents. 31 tools, one endpoint." />
<meta property="og:type" content="website" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
<style>
  :root {
    --bg: #07080f;
    --surface: #11131f;
    --surface-2: #161927;
    --border: rgba(255,255,255,.08);
    --border-bright: rgba(255,255,255,.14);
    --text: #e9ebf5;
    --muted: #9aa1b8;
    --faint: #6a7088;
    --indigo: #818cf8;
    --cyan: #22d3ee;
    --grad: linear-gradient(115deg, #a5b4fc 0%, #818cf8 35%, #22d3ee 100%);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    font-family: "Inter", system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.55; -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
  }
  /* ambient glow */
  body::before {
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background:
      radial-gradient(60rem 40rem at 70% -10%, rgba(129,140,248,.16), transparent 60%),
      radial-gradient(50rem 36rem at 10% 0%, rgba(34,211,238,.10), transparent 55%);
  }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }
  a { color: inherit; text-decoration: none; }
  .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }

  /* nav */
  nav { display: flex; align-items: center; justify-content: space-between; padding: 22px 0; }
  .brand { font-weight: 700; letter-spacing: -.02em; font-size: 17px; }
  .brand b { background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .nav-links { display: flex; gap: 26px; font-size: 14px; color: var(--muted); }
  .nav-links a:hover { color: var(--text); }
  .dot-live { width: 7px; height: 7px; border-radius: 99px; background: #34d399; display: inline-block; box-shadow: 0 0 0 0 rgba(52,211,153,.5); animation: pulse 2.4s infinite; vertical-align: middle; margin-right: 7px; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(52,211,153,.5)} 70%{box-shadow:0 0 0 7px rgba(52,211,153,0)} 100%{box-shadow:0 0 0 0 rgba(52,211,153,0)} }

  /* hero */
  .hero { padding: 70px 0 56px; text-align: center; }
  .eyebrow {
    display: inline-flex; align-items: center; gap: 8px; font-size: 12.5px; letter-spacing: .08em;
    text-transform: uppercase; color: var(--muted); border: 1px solid var(--border);
    background: rgba(255,255,255,.02); padding: 6px 14px; border-radius: 99px; margin-bottom: 26px;
  }
  h1 { font-size: clamp(38px, 7vw, 68px); line-height: 1.04; letter-spacing: -.035em; font-weight: 800; }
  h1 .grad { background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .sub { max-width: 620px; margin: 22px auto 0; font-size: clamp(16px, 2.3vw, 19px); color: var(--muted); }
  .cta { display: flex; gap: 14px; justify-content: center; flex-wrap: wrap; margin-top: 34px; }
  .btn { display: inline-flex; align-items: center; gap: 9px; font-weight: 600; font-size: 15px; padding: 13px 22px; border-radius: 12px; cursor: pointer; border: 1px solid transparent; transition: transform .12s ease, box-shadow .2s ease, background .2s; }
  .btn-primary { background: var(--grad); color: #0a0a14; box-shadow: 0 8px 30px rgba(129,140,248,.28); }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 12px 38px rgba(129,140,248,.40); }
  .btn-ghost { background: rgba(255,255,255,.03); border-color: var(--border-bright); color: var(--text); }
  .btn-ghost:hover { background: rgba(255,255,255,.07); }

  .endpoint {
    display: inline-flex; align-items: center; gap: 12px; margin-top: 30px;
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 11px 14px; font-size: 13.5px; color: var(--muted);
  }
  .endpoint code { color: var(--text); }
  .copy-ep { cursor: pointer; color: var(--indigo); font-size: 12px; border: 1px solid var(--border-bright); background: transparent; padding: 4px 9px; border-radius: 7px; transition: .15s; }
  .copy-ep:hover { background: rgba(129,140,248,.12); }

  .stats { display: flex; gap: 34px; justify-content: center; flex-wrap: wrap; margin-top: 46px; color: var(--faint); font-size: 14px; }
  .stats b { color: var(--text); font-weight: 700; font-size: 17px; display: block; }

  /* sections */
  section { padding: 60px 0; }
  .section-head { text-align: center; margin-bottom: 40px; }
  .section-head h2 { font-size: clamp(26px, 4vw, 34px); letter-spacing: -.025em; font-weight: 700; }
  .section-head p { color: var(--muted); margin-top: 10px; font-size: 16px; }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; transition: border-color .2s, transform .2s, background .2s; }
  .card:hover { border-color: var(--border-bright); transform: translateY(-2px); background: var(--surface-2); }
  .card .ic { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; margin-bottom: 14px; background: rgba(129,140,248,.12); border: 1px solid rgba(129,140,248,.25); font-size: 18px; }
  .card h3 { font-size: 16.5px; font-weight: 650; letter-spacing: -.01em; }
  .card h3 .tag { font-size: 11px; color: var(--faint); font-weight: 500; margin-left: 8px; }
  .card p { color: var(--muted); font-size: 14.5px; margin-top: 7px; }

  /* install */
  .install { background: linear-gradient(180deg, var(--surface) 0%, var(--surface-2) 100%); border: 1px solid var(--border); border-radius: 20px; padding: 32px; }
  .code-block { background: #0a0b13; border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 18px; }
  .code-block code { font-size: 13px; color: #cdd2e6; overflow-x: auto; white-space: nowrap; }
  .code-block .copy { flex: none; }
  .install .note { color: var(--faint); font-size: 13.5px; margin-top: 14px; }

  /* footer */
  footer { border-top: 1px solid var(--border); padding: 40px 0 60px; margin-top: 40px; color: var(--faint); font-size: 13.5px; }
  .foot-row { display: flex; justify-content: space-between; gap: 20px; flex-wrap: wrap; align-items: center; }
  .foot-links { display: flex; gap: 22px; }
  .foot-links a:hover { color: var(--text); }
  .disclaimer { margin-top: 20px; max-width: 640px; line-height: 1.6; }
  .toast { position: fixed; bottom: 26px; left: 50%; transform: translateX(-50%) translateY(20px); background: var(--text); color: #0a0a14; font-weight: 600; font-size: 13px; padding: 10px 18px; border-radius: 99px; opacity: 0; transition: .25s; z-index: 10; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <div class="brand">Clockchain <b>MCP</b></div>
    <div class="nav-links">
      <a href="#tools">Tools</a>
      <a href="#install">Install</a>
      <a href="https://status.clockchain.network"><span class="dot-live"></span>Status</a>
      <a href="https://github.com/thetangstr/clockchain-developer-tools">Docs</a>
    </div>
  </nav>

  <header class="hero">
    <div class="eyebrow"><span class="dot-live"></span>Model Context Protocol server · live on testnet</div>
    <h1>Verifiable time &amp; proof,<br /><span class="grad">built for AI agents.</span></h1>
    <p class="sub">Clockchain MCP gives any agent consensus-anchored time, tamper-evident receipts, and on-chain verification — <b style="color:var(--text)">31 tools</b> across 6 modules over a single endpoint. Drop it into Claude, Cursor, or any MCP client.</p>
    <div class="cta">
      <button class="btn btn-primary" onclick="copyText(window.__INSTALL__,'Install command copied')">Add to your agent</button>
      <a class="btn btn-ghost" href="https://status.clockchain.network">View live status →</a>
    </div>
    <div class="endpoint">
      <span>endpoint</span><code class="mono">https://mcp.clockchain.network/mcp</code>
      <button class="copy-ep" onclick="copyText('https://mcp.clockchain.network/mcp','Endpoint copied')">copy</button>
    </div>
    <div class="stats">
      <div><b>31</b>tools</div>
      <div><b>6</b>modules</div>
      <div><b>StreamableHTTP</b>stateless</div>
      <div><b>On-chain</b>verifiable</div>
    </div>
  </header>

  <section id="tools">
    <div class="section-head">
      <h2>One endpoint. Six capabilities.</h2>
      <p>Every tool is typed, idempotent where it writes, and degrades gracefully.</p>
    </div>
    <div class="grid">
      <div class="card"><div class="ic">🕒</div><h3>Time <span class="tag">4 tools</span></h3><p>Consensus block time &amp; height — the network's consented clock, not your server's. Provable after the fact.</p></div>
      <div class="card"><div class="ic">🔗</div><h3>Logging <span class="tag">4 tools</span></h3><p>Notarize any hash to an append-only ledger and verify it later against the immutable on-chain block.</p></div>
      <div class="card"><div class="ic">⏱️</div><h3>Scheduler <span class="tag">4 tools</span></h3><p>Time-triggered smart contracts. Non-custodial — the caller's wallet signs; the server never holds a key.</p></div>
      <div class="card"><div class="ic">📋</div><h3>Audit <span class="tag">4 tools</span></h3><p>Audit trails, compliance reports (EU AI Act Art. 12, SEC 17a-4, ISO 27001), and portable evidence packages.</p></div>
      <div class="card"><div class="ic">🪪</div><h3>Agent identity <span class="tag">10 tools</span></h3><p>Attest agent actions into verifiable receipts; resolve and verify identity valid-at-a-point-in-time.</p></div>
      <div class="card"><div class="ic">🤝</div><h3>Commitments <span class="tag">5 tools</span></h3><p>Issue → checkpoint → attest → settle. Every commitment's outcome — kept or broken — on the record.</p></div>
    </div>
  </section>

  <section>
    <div class="section-head"><h2>Why agents need it</h2></div>
    <div class="grid">
      <div class="card"><h3>Consensus time, not "trust me"</h3><p>Every timestamp is the network's consented block time — anyone can re-check it independently. No reliance on a single server clock.</p></div>
      <div class="card"><h3>Receipts that verify themselves</h3><p>An Agent Attested Receipt carries its own payload and anchor. Recompute the hash, compare it to the immutable on-chain block — proof, not a screenshot.</p></div>
      <div class="card"><h3>Tamper-evident by design</h3><p>Change one byte and verification fails. The ledger is append-only; the on-chain block is authoritative over any mutable cache.</p></div>
    </div>
  </section>

  <section id="install">
    <div class="install">
      <div class="section-head" style="text-align:left;margin-bottom:6px">
        <h2 style="font-size:24px">Add it in one line</h2>
        <p>Hosted and ready. Bring your Clockchain API key.</p>
      </div>
      <div class="code-block">
        <code class="mono" id="installcmd"></code>
        <button class="btn btn-ghost copy" style="padding:8px 14px;font-size:13px" onclick="copyText(window.__INSTALL__,'Install command copied')">Copy</button>
      </div>
      <p class="note">Works with Claude Code, Claude Desktop, Cursor, and any MCP-compatible client. Or point your client at <code class="mono">https://mcp.clockchain.network/mcp</code> with an <code class="mono">x-api-key</code> header. See the <a href="https://github.com/thetangstr/clockchain-developer-tools" style="color:var(--indigo)">docs</a>.</p>
    </div>
  </section>

  <footer>
    <div class="foot-row">
      <div class="brand">Clockchain <b>MCP</b></div>
      <div class="foot-links">
        <a href="https://status.clockchain.network">Status</a>
        <a href="https://github.com/thetangstr/clockchain-developer-tools">Docs</a>
        <a href="https://mcp.clockchain.network/health">Health</a>
      </div>
    </div>
    <p class="disclaimer">Currently on a single-validator testnet: the event hash, on-chain anchor, and consensus timestamp are real and independently verifiable. Multi-validator supermajority attestation activates at mainnet. Not yet a court-of-law evidentiary claim.</p>
  </footer>
</div>

<div class="toast" id="toast"></div>
<script>
  window.__INSTALL__ = ${JSON.stringify(INSTALL_CMD)};
  document.getElementById('installcmd').textContent = window.__INSTALL__;
  function copyText(t, msg) {
    navigator.clipboard.writeText(t).then(function(){ toast(msg || 'Copied'); }).catch(function(){ toast('Copy failed — select manually'); });
  }
  function toast(m) {
    var el = document.getElementById('toast'); el.textContent = m; el.classList.add('show');
    clearTimeout(window.__t); window.__t = setTimeout(function(){ el.classList.remove('show'); }, 1800);
  }
</script>
</body>
</html>`;
