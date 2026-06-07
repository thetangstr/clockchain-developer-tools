/** Chatbot-driven demo UI, served as a string (no static-file copy step). */
export const PAGE = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain · Agent</title>
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
</style>
</head>
<body>
<div class="app">
  <header>
    <div class="brand"><span class="dot"></span> Clockchain</div>
    <h1>Talk to the agent</h1>
    <p class="sub">An autonomous agent (MiniMax) that proves its high-stakes actions on-chain. Ask it to do something - it drives the Clockchain tools over MCP and shows its work.</p>
  </header>

  <div id="log"></div>

  <div class="chips" id="chips">
    <div class="chip" data-msg="What time does the Clockchain network agree it is right now?">⏱ Read consensus time</div>
    <div class="chip" data-msg="Execute a 250,000 USDC/ETH treasury trade triggered because price is below 3000, and attest it on Clockchain so we have proof.">💸 Attest a treasury trade</div>
    <div class="chip" data-msg="Verify the receipt you just created is genuine and unaltered.">✓ Verify the receipt</div>
    <div class="chip" data-msg="Now imagine someone changed the trade size to 999,999 after the fact - check whether that altered record still verifies.">⚠ Tamper test</div>
  </div>

  <div class="composer">
    <textarea id="input" rows="1" placeholder="Ask the agent to do something..."></textarea>
    <button class="send" id="send" onclick="sendMsg()">Send</button>
  </div>
  <div class="foot"><a onclick="rateDemo()">Rate this demo</a> · test network - workflow real, multi-validator attestation at mainnet</div>
</div>
<script>
  let sessionId = null, busy = false, lastReceipt = null;
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
      else if (ev.type === "tool_use") b.appendChild(el("tool", "⚙ <span class='name'>" + esc(ev.name) + "</span>(" + esc(JSON.stringify(ev.input)).slice(0, 160) + ")"));
      else if (ev.type === "tool_result") b.appendChild(el("tool", "↳ <span class='res'>" + esc(ev.content.split("\\n")[0]).slice(0, 140) + "</span>"));
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
  (function greet() {
    const b = botRow();
    b.appendChild(el(null, "Hi - I'm an autonomous agent. I can read Clockchain's decentralized consensus time and attest high-stakes actions on-chain so they're independently verifiable. Try a suggestion below, or ask me to do something."));
  })();
</script>
</body>
</html>`;
