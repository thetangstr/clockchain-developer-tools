// Marketing landing page served at GET / on mcp.clockchain.network (browsers).
// Agents POST /mcp; probes use /health. Self-contained (one Google Fonts link).
//
// Design language: haute horlogerie — deep warm black, ivory, champagne gold,
// a high-contrast serif (Cormorant), Roman numerals, hairline rules, restraint.

const INSTALL_CMD =
  'claude mcp add --transport http clockchain https://mcp.clockchain.network/mcp --header "x-api-key: <YOUR_KEY>"';

const COMPLICATIONS = [
  { n: "I", name: "Time", body: "Consensus block time and height — the network's consented clock, not a single server's. Provable after the fact." },
  { n: "II", name: "Notarization", body: "Anchor any hash to an append-only ledger, then verify it against the immutable on-chain block." },
  { n: "III", name: "Scheduler", body: "Time-triggered smart contracts. Non-custodial — the caller's wallet signs; the server holds no key." },
  { n: "IV", name: "Audit", body: "Audit trails, compliance reports (EU AI Act Art. 12, SEC 17a-4, ISO 27001), and portable evidence packages." },
  { n: "V", name: "Agent identity", body: "Attest agent actions into self-verifying receipts; resolve and verify identity valid at a point in time." },
  { n: "VI", name: "Commitments", body: "Issue, checkpoint, attest, settle. Every commitment's outcome — kept or broken — entered on the record." },
];

// A minimal engraved dial — gold hairlines, twelve ticks, hands at the classic
// 10:10 advertising position. Pure SVG, no assets.
const DIAL_SVG = `<svg class="dial" width="92" height="92" viewBox="0 0 130 130" fill="none" aria-hidden="true">
  <circle cx="65" cy="65" r="60" stroke="#c2a36b" stroke-opacity="0.45" stroke-width="0.75"/>
  <circle cx="65" cy="65" r="54" stroke="#c2a36b" stroke-opacity="0.16" stroke-width="0.5"/>
  <g stroke="#c2a36b" stroke-opacity="0.9" stroke-width="1.4" stroke-linecap="round">
    <line x1="65" y1="7" x2="65" y2="18"/><line x1="123" y1="65" x2="112" y2="65"/>
    <line x1="65" y1="123" x2="65" y2="112"/><line x1="7" y1="65" x2="18" y2="65"/>
  </g>
  <g stroke="#c2a36b" stroke-opacity="0.55" stroke-width="0.9" stroke-linecap="round">
    <line x1="94" y1="14.8" x2="91.5" y2="19.1"/><line x1="115.2" y1="36" x2="110.9" y2="38.5"/>
    <line x1="115.2" y1="94" x2="110.9" y2="91.5"/><line x1="94" y1="115.2" x2="91.5" y2="110.9"/>
    <line x1="36" y1="115.2" x2="38.5" y2="110.9"/><line x1="14.8" y1="94" x2="19.1" y2="91.5"/>
    <line x1="14.8" y1="36" x2="19.1" y2="38.5"/><line x1="36" y1="14.8" x2="38.5" y2="19.1"/>
  </g>
  <g stroke="#ddc28a" stroke-linecap="round">
    <line x1="65" y1="65" x2="40.4" y2="47.8" stroke-width="2.2"/>
    <line x1="65" y1="65" x2="103.1" y2="43" stroke-width="1.6"/>
  </g>
  <circle cx="65" cy="65" r="2.2" fill="#ddc28a"/>
</svg>`;

export const LANDING_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain MCP — verifiable time for autonomous agents</title>
<meta name="description" content="Clockchain MCP gives autonomous agents consensus-anchored time, tamper-evident receipts, and on-chain verification. Thirty-one instruments, one endpoint." />
<meta property="og:title" content="Clockchain MCP" />
<meta property="og:description" content="Verifiable time for autonomous agents. Thirty-one instruments. One endpoint." />
<meta property="og:type" content="website" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;500;600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet" />
<style>
  :root {
    --ink: #0a0a0b;
    --ink-2: #100f10;
    --ink-3: #161514;
    --ivory: #f3efe6;
    --muted: #a39d90;
    --faint: #726c61;
    --gold: #c2a36b;
    --gold-bright: #ddc28a;
    --line: rgba(255,255,255,.08);
    --line-gold: rgba(194,163,107,.30);
    --serif: "Cormorant Garamond", Georgia, "Times New Roman", serif;
    --sans: "Inter", system-ui, -apple-system, Segoe UI, sans-serif;
    --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--ink); color: var(--ivory);
    font-family: var(--sans); font-size: 16px; line-height: 1.6;
    -webkit-font-smoothing: antialiased; overflow-x: hidden;
  }
  body::before {
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background: radial-gradient(75rem 50rem at 50% -8%, rgba(194,163,107,.09), transparent 60%);
  }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 0 28px; position: relative; z-index: 1; }
  a { color: inherit; text-decoration: none; }
  .mono { font-family: var(--mono); }
  .label {
    font-family: var(--sans); font-size: 11px; font-weight: 500;
    letter-spacing: .28em; text-transform: uppercase; color: var(--gold);
  }
  .rule { width: 44px; height: 1px; background: var(--gold); opacity: .65; margin: 22px auto; }

  /* nav */
  nav { display: flex; align-items: center; justify-content: space-between; padding: 30px 0 14px; }
  .brand { font-family: var(--serif); font-size: 23px; font-weight: 500; letter-spacing: .01em; }
  .brand b { color: var(--gold); font-weight: 500; }
  .nav-links { display: flex; gap: 32px; font-size: 13px; letter-spacing: .04em; color: var(--muted); }
  .nav-links a { transition: color .2s; }
  .nav-links a:hover { color: var(--ivory); }
  .live { display: inline-block; width: 6px; height: 6px; border-radius: 99px; background: var(--gold); margin-right: 7px; vertical-align: middle; box-shadow: 0 0 8px rgba(194,163,107,.8); }

  /* hero */
  .hero { text-align: center; padding: 64px 0 30px; }
  .dial { margin: 0 auto 30px; display: block; }
  h1 { font-family: var(--serif); font-weight: 300; font-size: clamp(46px, 9vw, 94px); line-height: .98; letter-spacing: -.01em; margin-top: 24px; }
  h1 em { font-style: italic; color: var(--gold-bright); }
  .sub { max-width: 540px; margin: 26px auto 0; font-size: 17px; color: var(--muted); line-height: 1.7; }
  .cta { display: flex; gap: 14px; justify-content: center; flex-wrap: wrap; margin-top: 38px; }
  .btn {
    display: inline-flex; align-items: center; gap: 9px; font-family: var(--sans);
    font-size: 13px; font-weight: 500; letter-spacing: .08em; text-transform: uppercase;
    padding: 15px 28px; border-radius: 2px; cursor: pointer; transition: all .22s ease; border: 1px solid;
  }
  .btn-gold { background: var(--gold); color: #15120c; border-color: var(--gold); }
  .btn-gold:hover { background: var(--gold-bright); border-color: var(--gold-bright); }
  .btn-ghost { background: transparent; color: var(--ivory); border-color: var(--line-gold); }
  .btn-ghost:hover { border-color: var(--gold); color: var(--gold-bright); }

  .endpoint { display: inline-flex; align-items: center; gap: 14px; margin-top: 40px; font-size: 13px; color: var(--faint); }
  .endpoint code { color: var(--muted); letter-spacing: .02em; }
  .endpoint .sep { width: 1px; height: 13px; background: var(--line); }
  .endpoint button { background: none; border: none; color: var(--gold); cursor: pointer; font-family: var(--sans); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; }
  .endpoint button:hover { color: var(--gold-bright); }

  /* spec row */
  .specs { display: flex; justify-content: center; gap: 0; margin: 72px auto 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); max-width: 760px; }
  .spec { flex: 1; text-align: center; padding: 26px 12px; border-left: 1px solid var(--line); }
  .spec:first-child { border-left: none; }
  .spec .v { font-family: var(--serif); font-size: 34px; font-weight: 400; color: var(--ivory); line-height: 1; }
  .spec .k { font-size: 10.5px; letter-spacing: .18em; text-transform: uppercase; color: var(--faint); margin-top: 10px; }

  /* sections */
  section { padding: 96px 0; }
  .head { text-align: center; margin-bottom: 56px; }
  .head h2 { font-family: var(--serif); font-weight: 400; font-size: clamp(30px, 5vw, 44px); margin-top: 16px; letter-spacing: -.005em; }
  .head p { color: var(--muted); margin-top: 12px; font-size: 16px; }

  .complications { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0; border-top: 1px solid var(--line); }
  .comp { padding: 34px 30px; border-bottom: 1px solid var(--line); border-left: 1px solid var(--line); transition: background .25s; }
  .comp:nth-child(odd) { border-left: none; }
  .comp:hover { background: var(--ink-2); }
  .comp .num { font-family: var(--serif); font-size: 26px; color: var(--gold); font-weight: 400; }
  .comp h3 { font-family: var(--serif); font-size: 25px; font-weight: 500; margin: 6px 0 12px; }
  .comp p { color: var(--muted); font-size: 15px; line-height: 1.65; }

  /* tenets */
  .tenets { display: grid; grid-template-columns: repeat(3, 1fr); gap: 40px; }
  .tenet { text-align: center; }
  .tenet .mk { font-family: var(--serif); font-style: italic; font-size: 21px; color: var(--gold); }
  .tenet h3 { font-family: var(--serif); font-size: 24px; font-weight: 500; margin: 14px 0 10px; }
  .tenet p { color: var(--muted); font-size: 15px; }

  /* install */
  .install { text-align: center; max-width: 760px; margin: 0 auto; }
  .code { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-top: 32px; background: var(--ink-2); border: 1px solid var(--line); border-radius: 3px; padding: 18px 20px; text-align: left; }
  .code code { font-family: var(--mono); font-size: 12.5px; color: var(--ivory); overflow-x: auto; white-space: nowrap; opacity: .9; }
  .code button { flex: none; }
  .install .note { color: var(--faint); font-size: 13.5px; margin-top: 18px; line-height: 1.7; }
  .install .note a { color: var(--gold); }

  /* footer */
  footer { border-top: 1px solid var(--line); padding: 50px 0 70px; }
  .foot-row { display: flex; justify-content: space-between; align-items: center; gap: 20px; flex-wrap: wrap; }
  .foot-links { display: flex; gap: 28px; font-size: 13px; color: var(--muted); letter-spacing: .03em; }
  .foot-links a:hover { color: var(--gold); }
  .heritage { font-family: var(--serif); font-style: italic; font-size: 19px; color: var(--muted); text-align: center; margin: 0 auto 40px; max-width: 520px; line-height: 1.5; }
  .disclaimer { color: var(--faint); font-size: 12px; line-height: 1.7; max-width: 640px; margin-top: 26px; }

  .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(16px); background: var(--gold); color: #15120c; font-size: 12px; font-weight: 600; letter-spacing: .04em; padding: 11px 20px; border-radius: 2px; opacity: 0; transition: .25s; z-index: 20; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

  @media (max-width: 680px) {
    .complications, .tenets { grid-template-columns: 1fr; }
    .comp { border-left: none; }
    .tenets { gap: 48px; }
    .specs { flex-wrap: wrap; }
  }
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <div class="brand">Clockchain <b>·</b> MCP</div>
    <div class="nav-links">
      <a href="#instruments">Instruments</a>
      <a href="#install">Install</a>
      <a href="https://status.clockchain.network"><span class="live"></span>Status</a>
      <a href="https://github.com/thetangstr/clockchain-developer-tools">Documentation</a>
    </div>
  </nav>

  <header class="hero">
    ${DIAL_SVG}
    <div class="label">Model Context Protocol</div>
    <h1>Time, made <em>provable.</em></h1>
    <p class="sub">Clockchain MCP gives autonomous agents consensus-anchored time, tamper-evident receipts, and on-chain verification. Thirty-one instruments, a single endpoint.</p>
    <div class="cta">
      <button class="btn btn-gold" onclick="copyText(window.__INSTALL__,'Install command copied')">Add to your agent</button>
      <a class="btn btn-ghost" href="https://status.clockchain.network">View live status</a>
    </div>
    <div class="endpoint">
      <code class="mono">mcp.clockchain.network/mcp</code>
      <span class="sep"></span>
      <button onclick="copyText('https://mcp.clockchain.network/mcp','Endpoint copied')">Copy endpoint</button>
    </div>
    <div class="specs">
      <div class="spec"><div class="v">31</div><div class="k">Instruments</div></div>
      <div class="spec"><div class="v">VI</div><div class="k">Complications</div></div>
      <div class="spec"><div class="v">∞</div><div class="k">Permanence</div></div>
    </div>
  </header>

  <section id="instruments">
    <div class="head">
      <div class="label">The Movement</div>
      <h2>Six complications</h2>
      <p>Every instrument is typed, idempotent where it writes, and degrades with grace.</p>
    </div>
    <div class="complications">
      ${COMPLICATIONS.map((c) => `
      <div class="comp">
        <div class="num">${c.n}</div>
        <h3>${c.name}</h3>
        <p>${c.body}</p>
      </div>`).join("")}
    </div>
  </section>

  <section>
    <div class="head"><div class="label">Why it endures</div><h2>Proof, not assurance</h2></div>
    <div class="tenets">
      <div class="tenet"><div class="mk">i.</div><h3>Consensus time</h3><p>Every timestamp is the network's consented block time — anyone may re-check it. No single clock to trust.</p></div>
      <div class="tenet"><div class="mk">ii.</div><h3>Self-verifying receipts</h3><p>A receipt carries its own payload and anchor. Recompute the hash, compare to the on-chain block. Proof, not a screenshot.</p></div>
      <div class="tenet"><div class="mk">iii.</div><h3>Tamper-evident</h3><p>Alter one byte and verification fails. The ledger is append-only; the immutable block is authoritative.</p></div>
    </div>
  </section>

  <section id="install">
    <div class="install">
      <div class="head" style="margin-bottom:0"><div class="label">Acquisition</div><h2>Fitted in a single line</h2><p>Hosted and ready. Bring your Clockchain key.</p></div>
      <div class="code">
        <code id="installcmd"></code>
        <button class="btn btn-ghost" style="padding:10px 16px" onclick="copyText(window.__INSTALL__,'Install command copied')">Copy</button>
      </div>
      <p class="note">Works with Claude Code, Claude Desktop, Cursor, and any MCP-compatible client — or point your client at <span class="mono">mcp.clockchain.network/mcp</span> with an <span class="mono">x-api-key</span> header. See the <a href="https://github.com/thetangstr/clockchain-developer-tools">documentation</a>.</p>
    </div>
  </section>

  <footer>
    <p class="heritage">"A record is not owned. It is kept — for whoever must verify it next."</p>
    <div class="foot-row">
      <div class="brand">Clockchain <b>·</b> MCP</div>
      <div class="foot-links">
        <a href="https://status.clockchain.network">Status</a>
        <a href="https://github.com/thetangstr/clockchain-developer-tools">Documentation</a>
        <a href="https://mcp.clockchain.network/health">Health</a>
      </div>
    </div>
    <p class="disclaimer">Presently recorded on a single-validator testnet: the event hash, on-chain anchor, and consensus timestamp are real and independently verifiable. Multi-validator supermajority attestation activates at mainnet. Not yet a court-of-law evidentiary claim.</p>
  </footer>
</div>

<div class="toast" id="toast"></div>
<script>
  window.__INSTALL__ = ${JSON.stringify(INSTALL_CMD)};
  document.getElementById('installcmd').textContent = window.__INSTALL__;
  function copyText(t, msg){ navigator.clipboard.writeText(t).then(function(){toast(msg||'Copied');}).catch(function(){toast('Copy failed — select manually');}); }
  function toast(m){ var e=document.getElementById('toast'); e.textContent=m; e.classList.add('show'); clearTimeout(window.__t); window.__t=setTimeout(function(){e.classList.remove('show');},1800); }
</script>
</body>
</html>`;
