/** The single-page demo UI, served as a string (no static-file copy step). */
export const PAGE = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain · Agent Attested Receipt</title>
<style>
  :root {
    --bg:#0a0c12; --panel:#141925; --panel-2:#0e121b; --line:#232b3c; --line-soft:#1b2230;
    --text:#e8ecf3; --muted:#8893a6; --faint:#5b6678; --accent:#5b8cff; --accent-press:#4a7af0;
    --ok:#4cd07d; --bad:#ff6b6b; --warn:#e8b339; --radius:14px;
  }
  * { box-sizing:border-box; } html,body { margin:0; }
  body { background:radial-gradient(1200px 600px at 50% -200px,#131a2b 0%,var(--bg) 60%);
    color:var(--text); font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased; min-height:100vh; }
  .wrap { max-width:680px; margin:0 auto; padding:48px 22px 72px; }
  header { margin-bottom:28px; }
  .brand { display:flex; align-items:center; gap:10px; letter-spacing:.14em; font-size:12px;
    font-weight:600; color:var(--muted); text-transform:uppercase; }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 10px var(--ok); }
  h1 { font-size:26px; font-weight:650; margin:14px 0 6px; letter-spacing:-.01em; }
  .lede { color:var(--muted); margin:0; max-width:58ch; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:var(--radius); padding:20px; margin:16px 0; }
  .card-head { display:flex; align-items:center; gap:12px; margin-bottom:14px; }
  .num { flex:0 0 26px; height:26px; border-radius:8px; background:var(--panel-2); border:1px solid var(--line);
    color:var(--muted); font-size:13px; font-weight:600; display:grid; place-items:center; }
  .card-head h2 { font-size:15px; font-weight:600; margin:0; }
  .card-head .hint { margin-left:auto; font-size:12px; color:var(--faint); }
  label { display:block; font-size:12px; color:var(--muted); margin:10px 0 5px; }
  textarea, input[type=text] { width:100%; background:var(--panel-2); color:var(--text); border:1px solid var(--line);
    border-radius:10px; padding:11px 12px; font:inherit; font-size:14px; resize:vertical; }
  textarea.code { font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; min-height:54px; }
  textarea:focus, input:focus { outline:none; border-color:var(--accent); }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  @media (max-width:520px){ .grid2{ grid-template-columns:1fr; } }
  .row { display:flex; flex-wrap:wrap; gap:9px; margin-top:13px; }
  button { appearance:none; border:1px solid transparent; border-radius:10px; padding:9px 15px; font:inherit;
    font-size:14px; font-weight:550; cursor:pointer; background:var(--accent); color:#fff; transition:background .12s,opacity .12s,border-color .12s; }
  button:hover { background:var(--accent-press); }
  button.ghost { background:transparent; border-color:var(--line); color:var(--text); }
  button.ghost:hover { border-color:var(--accent); background:rgba(91,140,255,.08); }
  button:disabled { opacity:.4; cursor:default; background:var(--accent); }
  .out { font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; word-break:break-all;
    background:var(--panel-2); border:1px solid var(--line-soft); border-radius:10px; padding:12px; margin-top:13px; color:#aeb9cd; }
  .out.empty { color:var(--faint); }
  b { color:var(--text); font-weight:600; }
  .ok { color:var(--ok); font-weight:600; } .bad { color:var(--bad); font-weight:600; } .warn { color:var(--warn); }
  .rate { display:flex; gap:8px; margin:4px 0 6px; }
  .rate button { flex:1; background:var(--panel-2); border:1px solid var(--line); color:var(--muted); padding:10px 0; font-weight:600; }
  .rate button[aria-pressed=true] { background:rgba(91,140,255,.16); border-color:var(--accent); color:#fff; }
  .scale { display:flex; justify-content:space-between; font-size:11.5px; color:var(--faint); margin-bottom:12px; }
  .thanks { color:var(--ok); font-weight:600; }
  footer { margin-top:30px; color:var(--faint); font-size:12.5px; text-align:center; line-height:1.7; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><span class="dot"></span> Clockchain</div>
    <h1>Agent Attested Receipt</h1>
    <p class="lede">When an autonomous agent takes a high-stakes action, generate independently verifiable proof of <b>who</b> acted, <b>what</b> they did, and <b>when</b> - then prove it is unaltered.</p>
  </header>

  <div class="card">
    <div class="card-head"><span class="num">1</span><h2>Read the decentralized clock</h2></div>
    <div class="row"><button onclick="getTime()">Read consensus time</button></div>
    <div id="timeOut" class="out empty">Not read yet.</div>
  </div>

  <div class="card">
    <div class="card-head"><span class="num">2</span><h2>Agent acts → attested receipt</h2><span class="hint">SHA-256 anchored on-chain</span></div>
    <div class="grid2">
      <div><label>Agent (who)</label><input type="text" id="agentId" value="agent:treasury-bot" /></div>
      <div><label>Action (what)</label><input type="text" id="action" value="execute_trade" /></div>
    </div>
    <label>Inputs</label>
    <textarea id="inputs" class="code">{ "pair": "USDC/ETH", "size": "250000", "trigger": "price &lt; 3000" }</textarea>
    <label>Outputs</label>
    <textarea id="outputs" class="code">{ "decision": "EXECUTE", "txIntent": "0xabc123" }</textarea>
    <div class="row"><button id="attestBtn" onclick="attest()">Attest action on-chain</button></div>
    <div id="attestOut" class="out empty">Fill the action and attest. A receipt is generated and anchored.</div>
    <div class="row" id="receiptActions" style="display:none">
      <button class="ghost" onclick="downloadReceipt()">Download receipt (JSON)</button>
    </div>
  </div>

  <div class="card">
    <div class="card-head"><span class="num">3</span><h2>Verify &amp; tamper test</h2></div>
    <div class="row">
      <button id="verifyBtn" class="ghost" onclick="verify()" disabled>Verify receipt</button>
      <button id="tamperBtn" class="ghost" onclick="tamper()" disabled>Simulate tampering</button>
    </div>
    <div id="verifyOut" class="out empty">Attest first, then verify.</div>
  </div>

  <div class="card">
    <div class="card-head"><span class="num">★</span><h2>How was it?</h2><span class="hint">30 seconds</span></div>
    <div id="fbForm">
      <div class="rate" id="rate">
        <button type="button" data-v="1">1</button><button type="button" data-v="2">2</button>
        <button type="button" data-v="3">3</button><button type="button" data-v="4">4</button>
        <button type="button" data-v="5">5</button>
      </div>
      <div class="scale"><span>Not useful</span><span>Very useful</span></div>
      <textarea id="fbText" placeholder="What worked? What's missing? Would you use this - and for what?"></textarea>
      <input type="text" id="fbRole" placeholder="Your role (optional)" style="margin-top:9px" />
      <div class="row"><button id="fbBtn" onclick="sendFeedback()">Send feedback</button></div>
    </div>
    <div id="fbOut" class="out empty">Your rating and notes go straight to the team.</div>
  </div>

  <footer>
    Test network - the event hash, on-chain anchor and consensus timestamp are real and verifiable.<br/>
    Multi-validator signature attestation activates at mainnet.
  </footer>
</div>
<script>
  let receipt = null, rating = 0;
  const $ = (id) => document.getElementById(id);
  async function post(path, body) {
    const r = await fetch(path, { method:"POST", headers:{ "content-type":"application/json" }, body:JSON.stringify(body||{}) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }
  const set = (id, html, cls) => { const e = $(id); e.innerHTML = html; e.className = "out" + (cls ? " " + cls : ""); };
  const parseJson = (s, label) => { try { return JSON.parse(s); } catch { throw new Error("Invalid JSON in " + label); } };

  async function getTime() {
    set("timeOut", "Reading...");
    try { const t = await post("/api/time");
      set("timeOut", "Latest block <b>" + t.latestBlockHeight + "</b>\\nConsensus time " + t.latestBlockTime);
    } catch (e) { set("timeOut", e.message, "bad"); }
  }
  async function attest() {
    let inputs, outputs;
    try { inputs = parseJson($("inputs").value, "Inputs"); outputs = parseJson($("outputs").value, "Outputs"); }
    catch (e) { set("attestOut", e.message, "bad"); return; }
    $("attestBtn").disabled = true;
    set("attestOut", "Fingerprinting and anchoring on-chain (waiting for confirmation)...");
    try {
      receipt = await post("/api/attest", { agentId: $("agentId").value, action: $("action").value, inputs, outputs });
      const a = receipt.anchor, at = receipt.attestation;
      set("attestOut",
        "Event hash  " + receipt.eventHash +
        "\\nLedger ID   " + a.ledgerId +
        "\\nBlock       " + (a.blockHeight ? "<b>" + a.blockHeight + "</b>  (anchored on-chain)" : "<span class='bad'>pending</span>") +
        "\\nWhen        " + (a.consensusTime || a.recordedAt) +
        "\\nAttestation <span class='warn'>" + at.validators + " validator · " + at.status + "</span>");
      $("receiptActions").style.display = "flex";
      $("verifyBtn").disabled = false; $("tamperBtn").disabled = false;
    } catch (e) { set("attestOut", e.message, "bad"); }
    finally { $("attestBtn").disabled = false; }
  }
  function downloadReceipt() {
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a");
    a.href = url; a.download = "clockchain-receipt-" + receipt.anchor.ledgerId + ".json"; a.click();
    URL.revokeObjectURL(url);
  }
  async function runVerify(rcpt) {
    try { const d = await post("/api/verify-receipt", { receipt: rcpt });
      set("verifyOut", (d.match ? "<span class='ok'>MATCH - the receipt is genuine and unaltered</span>"
                                : "<span class='bad'>NO MATCH - the receipt or action was altered</span>") +
        "\\nanchored  " + d.anchoredHash + "\\ncomputed  " + d.eventHash);
    } catch (e) { set("verifyOut", e.message, "bad"); }
  }
  const verify = () => runVerify(receipt);
  function tamper() {
    const t = JSON.parse(JSON.stringify(receipt));
    t.payload.inputs = { ...(t.payload.inputs || {}), size: "999999999" };
    runVerify(t);
  }

  $("rate").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-v]"); if (!b) return;
    rating = +b.dataset.v; [...$("rate").children].forEach((c) => c.setAttribute("aria-pressed", c === b));
  });
  async function sendFeedback() {
    const message = $("fbText").value.trim();
    if (!rating && !message) { set("fbOut", "Add a rating or a note first.", "bad"); return; }
    $("fbBtn").disabled = true;
    try { await post("/api/feedback", { rating, message, role: $("fbRole").value.trim() });
      $("fbForm").style.display = "none"; set("fbOut", "<span class='thanks'>Thank you - your feedback was recorded.</span>");
    } catch (e) { set("fbOut", e.message, "bad"); $("fbBtn").disabled = false; }
  }
</script>
</body>
</html>`;
