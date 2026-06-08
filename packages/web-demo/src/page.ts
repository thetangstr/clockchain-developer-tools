/** Chatbot-driven demo UI, served as a string (no static-file copy step). */
export const PAGE = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain · MCP Playground</title>
<style>
  :root {
    --bg:#0a0c12; --panel:#141925; --panel-2:#0e121b; --line:#232b3c; --line-soft:#1b2230;
    --text:#e8ecf3; --muted:#8893a6; --faint:#5b6678; --accent:#5b8cff; --accent-press:#4a7af0;
    --ok:#4cd07d; --bad:#ff6b6b; --warn:#e8b339; --radius:14px;
  }
  * { box-sizing:border-box; } html,body { margin:0; height:100%; }
  body { background:radial-gradient(1100px 520px at 50% -220px,#131a2b 0%,var(--bg) 60%); color:var(--text);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; -webkit-font-smoothing:antialiased; }
  .app { max-width:760px; margin:0 auto; height:100vh; display:flex; flex-direction:column; padding:0 16px; }
  header { padding:20px 4px 12px; }
  .brand { display:flex; align-items:center; gap:9px; letter-spacing:.14em; font-size:11.5px; font-weight:600; color:var(--muted); text-transform:uppercase; }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 10px var(--ok); }
  h1 { font-size:20px; font-weight:650; margin:9px 0 3px; letter-spacing:-.01em; }
  .sub { color:var(--muted); margin:0; font-size:13px; }
  .sub b { color:#cdd6e3; }
  .meta { display:flex; flex-wrap:wrap; gap:8px; margin-top:11px; }
  .tag { font-size:11.5px; color:var(--muted); background:var(--panel-2); border:1px solid var(--line);
    border-radius:999px; padding:4px 11px; }
  .tag.link { color:var(--accent); text-decoration:none; cursor:pointer; }
  .tag.link:hover { border-color:var(--accent); background:rgba(91,140,255,.08); }
  .netbar { display:flex; align-items:center; gap:9px; margin-top:10px; padding:7px 11px; background:var(--panel-2);
    border:1px solid var(--line); border-radius:10px; font-size:12px; color:var(--muted); flex-wrap:wrap; }
  .ndot { width:8px; height:8px; border-radius:50%; background:var(--faint); }
  .ndot.up { background:var(--ok); box-shadow:0 0 8px var(--ok); } .ndot.down { background:var(--bad); box-shadow:0 0 8px var(--bad); }
  .nlabel { font-weight:700; letter-spacing:.06em; text-transform:uppercase; font-size:11px; padding:2px 8px; border-radius:999px; }
  .nlabel.mainnet { color:#0a0c12; background:var(--ok); }
  .nlabel.testnet { color:#0a0c12; background:var(--warn); }
  .nfields { color:#9aa6ba; }
  .about { margin:4px 2px 0; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:0 14px; }
  .about summary { cursor:pointer; padding:12px 0; font-size:13.5px; font-weight:600; color:#cdd6e3; list-style:none; }
  .about summary::-webkit-details-marker { display:none; }
  .about summary::before { content:"›"; display:inline-block; margin-right:8px; color:var(--accent); transition:transform .15s; }
  .about[open] summary::before { transform:rotate(90deg); }
  .about ul { margin:0 0 8px; padding-left:18px; color:var(--muted); font-size:13px; }
  .about li { margin:6px 0; } .about li b { color:#cdd6e3; }
  .about .tip { color:var(--faint); font-size:12.5px; margin:6px 0 14px; }

  #log { flex:1; overflow-y:auto; padding:8px 2px 12px; display:flex; flex-direction:column; gap:12px; }
  .msg { display:flex; gap:10px; max-width:100%; }
  .msg.user { justify-content:flex-end; }
  .bubble { padding:10px 13px; border-radius:13px; max-width:84%; white-space:pre-wrap; word-wrap:break-word; }
  .user .bubble { background:var(--accent); color:#fff; border-bottom-right-radius:4px; }
  .bot .bubble { background:var(--panel); border:1px solid var(--line); border-bottom-left-radius:4px; }
  .who { font-size:11px; color:var(--faint); margin:0 4px 4px; }

  .think { font-size:12.5px; color:var(--faint); font-style:italic; border-left:2px solid var(--line); padding:2px 0 2px 10px; margin:2px 0; }
  .tool { font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--panel-2); border:1px solid var(--line-soft);
    border-radius:9px; padding:8px 10px; margin:6px 0; color:#aeb9cd; }
  .tool .name { color:var(--accent); font-weight:600; } .tool .res { color:#7e8aa0; }
  .receipt { background:var(--panel-2); border:1px solid var(--line); border-left:3px solid var(--ok); border-radius:10px;
    padding:11px 12px; margin:7px 0; font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; color:#bcc7d8; }
  .receipt b { color:var(--text); } .warn { color:var(--warn); } .ok { color:var(--ok); } .bad { color:var(--bad); }
  .receipt a { color:var(--accent); cursor:pointer; }

  .chips { display:flex; flex-wrap:wrap; gap:8px; padding:6px 2px 10px; }
  .chip { background:var(--panel); border:1px solid var(--line); color:var(--text); border-radius:999px; padding:7px 13px;
    font-size:13px; cursor:pointer; transition:border-color .12s,background .12s; }
  .chip:hover { border-color:var(--accent); background:rgba(91,140,255,.08); }

  .composer { display:flex; gap:9px; padding:10px 2px 16px; }
  #input { flex:1; background:var(--panel-2); color:var(--text); border:1px solid var(--line); border-radius:12px;
    padding:12px 13px; font:inherit; font-size:14px; resize:none; max-height:140px; }
  #input:focus { outline:none; border-color:var(--accent); }
  button.send { background:var(--accent); color:#fff; border:0; border-radius:12px; padding:0 18px; font:inherit; font-weight:600; cursor:pointer; }
  button.send:disabled { opacity:.45; cursor:default; }
  .typing { color:var(--faint); font-size:13px; font-style:italic; }
  .foot { text-align:center; color:var(--faint); font-size:11.5px; padding:0 0 8px; }
  .foot a { color:var(--muted); cursor:pointer; }

  /* guided journey rail */
  .journey { margin:6px 2px 2px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:11px 13px; }
  .jhead { font-size:11px; letter-spacing:.1em; text-transform:uppercase; color:var(--faint); font-weight:700; margin-bottom:9px; }
  .jhead span { color:var(--faint); font-weight:500; letter-spacing:.02em; text-transform:none; }
  .jsteps { display:flex; gap:7px; flex-wrap:wrap; }
  .jstep { flex:1 1 0; min-width:96px; display:flex; align-items:center; gap:8px; background:var(--panel-2); border:1px solid var(--line);
    color:var(--text); border-radius:10px; padding:8px 10px; font:inherit; font-size:12.5px; cursor:pointer; transition:border-color .12s,background .12s; text-align:left; }
  .jstep:hover { border-color:var(--accent); background:rgba(91,140,255,.08); }
  .jstep b { display:inline-flex; align-items:center; justify-content:center; width:19px; height:19px; flex-shrink:0; border-radius:50%;
    background:var(--accent); color:#fff; font-size:11px; font-weight:700; }
  .jstep.done b { background:var(--ok); } .jstep.done { opacity:.85; }

  /* connect modal */
  .ov { position:fixed; inset:0; background:rgba(4,6,11,.72); display:none; align-items:center; justify-content:center; z-index:50; padding:18px; }
  .ov.open { display:flex; }
  .modal { background:var(--panel); border:1px solid var(--line); border-radius:16px; max-width:560px; width:100%; max-height:88vh; overflow:auto; padding:20px 22px; }
  .modal h2 { margin:0 0 4px; font-size:18px; } .modal .lead { color:var(--muted); font-size:13px; margin:0 0 14px; }
  .ostep { display:flex; gap:11px; padding:11px 0; border-top:1px solid var(--line-soft); }
  .ostep:first-of-type { border-top:0; }
  .onum { flex-shrink:0; width:22px; height:22px; border-radius:50%; background:var(--panel-2); border:1px solid var(--line); color:var(--accent); font-weight:700; font-size:12px; display:flex; align-items:center; justify-content:center; }
  .otext { font-size:13px; color:var(--text); } .otext b { color:#fff; } .otext .m { color:var(--muted); }
  .code { position:relative; margin:8px 0 2px; background:var(--panel-2); border:1px solid var(--line-soft); border-radius:9px;
    padding:9px 11px; font:11.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; color:#bcc7d8; white-space:pre-wrap; word-break:break-all; }
  .copy { position:absolute; top:6px; right:6px; background:var(--panel); border:1px solid var(--line); color:var(--muted); border-radius:6px; font-size:10.5px; padding:2px 7px; cursor:pointer; }
  .copy:hover { border-color:var(--accent); color:var(--accent); }
  .modal .close { float:right; background:none; border:0; color:var(--muted); font-size:20px; cursor:pointer; line-height:1; }
  .modal .mnote { margin:14px 0 0; font-size:12px; color:var(--faint); }
  .modal a { color:var(--accent); }
</style>
</head>
<body>
<div class="app">
  <header>
    <div class="brand"><span class="dot"></span> Clockchain</div>
    <h1>MCP Playground</h1>
    <p class="sub">Chat with an AI agent that uses Clockchain's <b>existing network APIs</b> - verifiable time, notarization, agent identity - exposed as tools through <b>MCP</b>. Every result is independently verifiable, on-chain proof.</p>
    <div class="meta">
      <span class="tag">MCP turns Clockchain's live network APIs into tools any AI agent can use</span>
      <a class="tag link" href="__RESEARCH_URL__" target="_blank" rel="noopener">Plan &amp; architecture ↗</a>
    </div>
    <div class="netbar" id="netbar" title="Live network status">
      <span class="ndot" id="ndot"></span>
      <span class="nlabel" id="nlabel">…</span>
      <span class="nfields" id="nfields">checking network…</span>
    </div>
  </header>

  <details class="about">
    <summary>What can I do here? (business use cases)</summary>
    <ul>
      <li><b>EU AI Act compliance (for a CISO)</b> - high-risk AI systems must keep tamper-evident, traceable logs (Art. 12), retain them (Art. 26), document the system (Annex IV), and show human oversight (Art. 14). We give you an <b>independently verifiable</b> evidence trail a regulator can check <b>without trusting you</b>. Tap the 🏛 path below.</li>
      <li><b>Verifiable time</b> - regulatory / SLA / incident-reporting timestamps against a clock the validator network agrees on, not one server you control.</li>
      <li><b>Agent attested receipt</b> - when an AI agent takes a high-stakes action (a trade, a payment, a decision), get a tamper-evident, on-chain proof of <b>who</b> acted, <b>what</b> they did, and <b>when</b> - an artifact an auditor can hold.</li>
      <li><b>Independent verification</b> - anyone can re-check the record later without trusting you; post-hoc tampering is caught.</li>
      <li><b>Proof of existence (TSA-style)</b> - timestamp any document (e.g. your Annex IV technical documentation) so you can later prove it existed at a verifiable time and is unaltered.</li>
    </ul>
    <p class="tip">New here? Tap a suggestion below - the agent will walk you through it.</p>
  </details>

  <div class="journey" id="journey">
    <div class="jhead">Guided journey <span>· follow the steps, or just chat below</span></div>
    <div class="jsteps">
      <button class="jstep" data-step="understand"><b>1</b> Understand</button>
      <button class="jstep" data-step="see"><b>2</b> See it work</button>
      <button class="jstep" data-step="prove"><b>3</b> Prove &amp; tamper</button>
      <button class="jstep" data-step="connect"><b>4</b> Connect</button>
      <button class="jstep" data-step="golive"><b>5</b> Go live</button>
    </div>
  </div>

  <div id="log"></div>

  <div class="chips" id="chips">
    <div class="chip" data-msg="I'm a CISO at an EU bank preparing for the EU AI Act. Our high-risk credit-scoring AI just DENIED applicant-8831 (reasons: DTI over 45%, thin file), and a human reviewer confirmed it under Article 14. Attest this decision on Clockchain so we have a tamper-evident, independently verifiable record of what the AI decided, when, and that a human confirmed it - the kind of Article 12 log a market-surveillance auditor can check without trusting us. Then explain which EU AI Act obligations this satisfies.">🏛 EU AI Act: prove a high-risk AI decision</div>
    <div class="chip" data-msg="What time does the Clockchain network agree it is right now?">⏱ Read consensus time</div>
    <div class="chip" data-msg="Execute a 250,000 USDC/ETH treasury trade triggered because price is below 3000, and attest it on Clockchain so we have proof.">💸 Attest a treasury trade</div>
    <div class="chip" data-msg="Verify the receipt you just created is genuine and unaltered.">✓ Verify the receipt</div>
    <div class="chip" data-msg="Now imagine someone changed the trade size to 999,999 after the fact - check whether that altered record still verifies.">⚠ Tamper test</div>
    <div class="chip" data-msg="Resolve the ERC-8004 on-chain identity of agent #1 - who owns it and what's its agent URI?">🪪 Resolve an agent identity</div>
    <div class="chip" data-msg="Timestamp this document on Clockchain so we can later prove it existed and is unaltered: 'Master Services Agreement v3 - approved by the board, 2026'. Give me the proof (the hash, block, and consensus time), then show what happens if someone alters one word.">📄 Timestamp a document (TSA)</div>
  </div>

  <div class="composer">
    <textarea id="input" rows="1" placeholder="Ask the agent to do something..."></textarea>
    <button class="send" id="send" onclick="sendMsg()">Send</button>
  </div>
  <div class="foot"><a onclick="rateDemo()">Rate this demo</a> · test network - workflow real, multi-validator attestation at mainnet</div>
</div>

<div class="ov" id="connectOv">
  <div class="modal">
    <button class="close" onclick="closeConnect()" aria-label="Close">×</button>
    <h2>Connect your agent to the network</h2>
    <p class="lead">Three steps to make your own AI agent emit Clockchain proof. You're on <b>testnet</b> today.</p>
    <div class="ostep"><div class="onum">1</div><div class="otext"><b>Get testnet access.</b> <span class="m">Request an API key + client/wallet id - provisioned for you today (self-serve coming with v3).</span></div></div>
    <div class="ostep"><div class="onum">2</div><div class="otext"><b>Add the Clockchain MCP server to your agent.</b> <span class="m">Claude Code / Cursor / LangChain / AgentDash - anything that speaks MCP.</span>
      <div class="code"><button class="copy" data-copy="cli">copy</button><span id="cfg-cli">claude mcp add clockchain \\
  --command node \\
  --args /path/to/clockchain-developer-tools/packages/mcp-server/dist/stdio.js \\
  --env CLOCKCHAIN_API_KEY=YOUR_KEY \\
  --env CLOCKCHAIN_CLIENT_ID=YOUR_ID \\
  --env CLOCKCHAIN_WALLET_ID=YOUR_WALLET \\
  --env CLOCKCHAIN_ENDPOINT=https://node.clockchain.network</span></div>
    </div></div>
    <div class="ostep"><div class="onum">3</div><div class="otext"><b>Make your first attested call - then verify it.</b> <span class="m">Ask your agent:</span>
      <div class="code"><button class="copy" data-copy="call">copy</button><span id="cfg-call">"Timestamp this document on Clockchain and give me a verifiable receipt, then re-verify it independently."</span></div>
    </div></div>
    <p class="mnote">Testnet now (single validator). Mainnet adds the multi-validator supermajority + permanence - the strongest court-grade claim.
      Full setup: <a href="https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md" target="_blank" rel="noopener">INSTALL.md ↗</a></p>
  </div>
</div>

<script>
  let sessionId = null, busy = false, lastReceipt = null;
  const API_OF = {
    get_time: "GET /api/time/time", get_timestamp: "GET /api/time/timestamp",
    get_block: "GET /api/time/block", get_validation: "GET /getValidationBlock/{h}",
    log_action: "POST /log", search_actions: "GET /searchAsset", get_log_entry: "GET /ledger/{id}",
    verify_asset: "GET /ledger/{id}", resolve_agent: "eth_call → ERC-8004 registry",
    attest_action: "POST /log → poll /ledger → /api/time/block → /getValidationBlock",
    verify_receipt: "GET /ledger/{id}",
  };
  const log = document.getElementById("log"), input = document.getElementById("input");

  function el(cls, html) { const d = document.createElement("div"); if (cls) d.className = cls; if (html != null) d.innerHTML = html; return d; }
  function scroll() { log.scrollTop = log.scrollHeight; }
  function esc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;" }[c])); }

  function addUser(text) { const m = el("msg user"); m.appendChild(el("bubble", esc(text))); log.appendChild(m); scroll(); }
  function botRow() { const m = el("msg bot"); const b = el("bubble"); m.appendChild(b); log.appendChild(m); scroll(); return b; }

  function renderReceipt(b, r) {
    lastReceipt = r; const a = r.anchor, at = r.attestation;
    const d = el("receipt",
      "<b>Agent Attested Receipt</b>\\n" +
      "event hash  " + r.eventHash.slice(0, 40) + "…\\n" +
      "block       <b>" + (a.blockHeight || "pending") + "</b>\\n" +
      "when        " + (a.consensusTime || a.recordedAt) + "\\n" +
      "attestation <span class='warn'>" + at.validators + " validator · " + at.status + "</span>\\n" +
      "<a id='dl'>↓ Download receipt (JSON)</a>");
    b.appendChild(d);
    d.querySelector("#dl").onclick = () => {
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
      const u = URL.createObjectURL(blob), x = document.createElement("a");
      x.href = u; x.download = "clockchain-receipt-" + a.ledgerId + ".json"; x.click(); URL.revokeObjectURL(u);
    };
  }

  async function renderEvents(b, events, receipt) {
    for (const ev of events) {
      if (ev.type === "thinking") b.appendChild(el("think", "💭 " + esc(ev.text)));
      else if (ev.type === "text") b.appendChild(el(null, esc(ev.text)));
      else if (ev.type === "tool_use") b.appendChild(el("tool",
        "⚙ <span class='name'>" + esc(ev.name) + "</span>(" + esc(JSON.stringify(ev.input || {}, null, 0)) + ")" +
        (API_OF[ev.name] ? "\\n   <span class='res'>↗ Clockchain API: " + API_OF[ev.name] + "</span>" : "")));
      else if (ev.type === "tool_result") b.appendChild(el("tool",
        "↳ <span class='res'>response:</span>\\n<span class='res'>" + esc(ev.content).slice(0, 1200) + "</span>"));
      scroll(); await new Promise((r) => setTimeout(r, 250)); // reveal step-by-step
    }
    if (receipt) renderReceipt(b, receipt);
  }

  async function send(text) {
    if (busy || !text.trim()) return;
    busy = true; document.getElementById("send").disabled = true;
    addUser(text);
    const b = botRow(); b.appendChild(el("typing", "agent is thinking…"));
    try {
      const r = await fetch("/api/agent", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sessionId, message: text }) });
      const data = await r.json();
      b.innerHTML = "";
      if (!r.ok) { b.appendChild(el("bad", esc(data.error || ("HTTP " + r.status)))); }
      else { sessionId = data.sessionId; await renderEvents(b, data.events, data.receipt); if (!data.events.length) b.appendChild(el(null, "(no response)")); }
    } catch (e) { b.innerHTML = ""; b.appendChild(el("bad", esc(e.message))); }
    finally { busy = false; document.getElementById("send").disabled = false; scroll(); }
  }
  function sendMsg() { const t = input.value; input.value = ""; input.style.height = "auto"; send(t); }

  document.getElementById("chips").addEventListener("click", (e) => { const c = e.target.closest(".chip"); if (c) send(c.dataset.msg); });

  // ---- guided journey ----
  function botInfo(html) { const b = botRow(); b.appendChild(el(null, html)); scroll(); }
  function markDone(step) { const el2 = document.querySelector('.jstep[data-step="' + step + '"]'); if (el2) el2.classList.add("done"); }
  const J_SEE = "I'm a CISO at an EU bank preparing for the EU AI Act. Our high-risk credit-scoring AI just DENIED applicant-8831 (reasons: DTI over 45%, thin file), and a human reviewer confirmed it under Article 14. Attest this decision on Clockchain so we have a tamper-evident, independently verifiable record of what the AI decided, when, and that a human confirmed it. Then explain which EU AI Act obligations (Art. 12 logging, Art. 14 oversight) this satisfies.";
  const J_PROVE = "Verify the receipt you just created is genuine and unaltered. Then re-verify a copy of it where the decision was changed from DENY to APPROVE after the fact, and show whether that altered record still verifies.";
  function journey(step) {
    if (step === "understand") { markDone("understand"); botInfo(
      "<b>The problem.</b> When your AI agent takes a high-stakes action - a trade, a payment, an automated decision - your own logs are self-attested. In a dispute or an audit (e.g. the <b>EU AI Act</b>), they're not proof: you could have edited them.<br><br>" +
      "<b>What Clockchain gives you.</b> Every action gets a neutral, tamper-evident, <b>independently verifiable</b> receipt - <b>who</b> acted, <b>what</b> they did, <b>when</b> - that an outsider can check without trusting you.<br><br>Tap <b>2 See it work</b> and I'll attest a real high-risk AI decision on-chain."); }
    else if (step === "see") { markDone("see"); send(J_SEE); }
    else if (step === "prove") { markDone("prove"); send(J_PROVE); }
    else if (step === "connect") { markDone("connect"); openConnect(); }
    else if (step === "golive") { markDone("golive"); botInfo(
      "You're on the <b>testnet</b> (single validator) - the workflow and proofs are real; <b>mainnet</b> adds the multi-validator supermajority + permanence (the strongest court-grade claim).<br><br>To wire this into your own agent, tap <b>4 Connect</b>. Plan &amp; architecture: <a href='__RESEARCH_URL__' target='_blank' rel='noopener'>research site ↗</a>."); }
  }
  document.getElementById("journey").addEventListener("click", (e) => { const s = e.target.closest(".jstep"); if (s) journey(s.dataset.step); });

  // ---- connect modal ----
  function openConnect() { document.getElementById("connectOv").classList.add("open"); }
  function closeConnect() { document.getElementById("connectOv").classList.remove("open"); }
  document.getElementById("connectOv").addEventListener("click", (e) => { if (e.target.id === "connectOv") closeConnect(); });
  document.querySelectorAll(".copy").forEach((btn) => { btn.onclick = () => {
    const span = document.getElementById("cfg-" + btn.dataset.copy); if (!span) return;
    navigator.clipboard.writeText(span.innerText); const t = btn.textContent; btn.textContent = "copied"; setTimeout(() => (btn.textContent = t), 1200);
  }; });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMsg(); } });
  input.addEventListener("input", () => { input.style.height = "auto"; input.style.height = Math.min(input.scrollHeight, 140) + "px"; });

  async function rateDemo() {
    const msg = prompt("Quick feedback - what worked, what's missing, would you use this?");
    if (msg == null) return;
    const rating = parseInt(prompt("Rate 1-5 (optional):", "5") || "0", 10) || 0;
    try { await fetch("/api/feedback", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ rating, message: msg, role: "" }) });
      alert("Thank you - your feedback was recorded."); } catch { alert("Could not send feedback."); }
  }

  // Greeting
  // Live network status strip (cached server-side; poll every 12s).
  async function refreshStatus() {
    try {
      const s = await (await fetch("/api/status")).json();
      const net = String(s.network || "").toLowerCase();
      const nlabel = document.getElementById("nlabel");
      nlabel.textContent = s.network || "network";
      nlabel.className = "nlabel " + (net.includes("main") ? "mainnet" : "testnet");
      document.getElementById("ndot").className = "ndot " + (s.ok ? "up" : "down");
      if (s.ok) {
        const parts = ["block <b>" + Number(s.blockHeight).toLocaleString() + "</b>"];
        if (s.validators != null) parts.push(s.validators + " validator" + (s.validators == 1 ? "" : "s"));
        if (s.participationPct != null) parts.push(s.participationPct + "% participation");
        if (s.consensusTime) { const p = Date.parse(s.consensusTime); parts.push("consensus " + (isNaN(p) ? String(s.consensusTime).replace(/^.*_/, "") : new Date(p).toLocaleTimeString())); }
        parts.push(s.latencyMs + "ms · " + s.gateway);
        document.getElementById("nfields").innerHTML = parts.join("  ·  ");
      } else {
        document.getElementById("nfields").innerHTML = "<span class='bad'>unreachable</span> · " + esc(s.error || "") + " · " + s.gateway;
      }
    } catch { document.getElementById("ndot").className = "ndot down"; document.getElementById("nfields").textContent = "status unavailable"; }
  }
  refreshStatus(); setInterval(refreshStatus, 12000);

  (function greet() {
    const b = botRow();
    b.appendChild(el(null, "Welcome to the Clockchain MCP Playground. I'm an AI agent - through MCP, I can use Clockchain's existing network APIs (consensus time, notarization, agent identity) and turn them into independently verifiable, on-chain proof. Tap a suggestion below and I'll walk you through it."));
  })();
</script>
</body>
</html>`;
