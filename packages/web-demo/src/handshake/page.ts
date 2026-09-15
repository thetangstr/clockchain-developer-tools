export const HANDSHAKE_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Standalone Handshake — live theater</title>
<style>
  :root {
    --bg:#0b0e14; --panel:#12161f; --edge:#1e2532; --ink:#e6ebf4; --dim:#8b96ab;
    --a:#5aa2ff; --b:#7ee0a3; --l:#f0b45a; --bad:#ff6b6b; --mono:"SF Mono",Menlo,Consolas,monospace;
  }
  * { box-sizing:border-box; margin:0 }
  body { background:var(--bg); color:var(--ink); font:14px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif; min-height:100vh; display:flex; flex-direction:column }
  header { padding:14px 18px; border-bottom:1px solid var(--edge); display:flex; gap:14px; align-items:center; flex-wrap:wrap }
  header h1 { font-size:16px; font-weight:650; letter-spacing:.2px }
  header .sub { color:var(--dim); font-size:12px }
  .controls { margin-left:auto; display:flex; gap:8px; align-items:center; flex-wrap:wrap }
  button, select { background:#1a2130; color:var(--ink); border:1px solid var(--edge); border-radius:8px; padding:7px 12px; font:600 12px inherit; cursor:pointer }
  button:hover { border-color:var(--a) } button:disabled { opacity:.45; cursor:default }
  button.primary { background:var(--a); color:#061020; border-color:var(--a) }
  .faults { display:flex; gap:10px; flex-wrap:wrap; padding:8px 18px; border-bottom:1px solid var(--edge); background:#0e121b }
  .faults label { display:flex; gap:5px; align-items:center; font-size:12px; color:var(--dim); cursor:pointer }
  .faults input { accent-color:var(--bad) }
  main { flex:1; display:grid; grid-template-columns:1fr 1.15fr 1fr; min-height:0 }
  .pane { border-right:1px solid var(--edge); display:flex; flex-direction:column; min-height:0 }
  .pane:last-child { border-right:0 }
  .pane h2 { padding:10px 14px; font-size:12px; text-transform:uppercase; letter-spacing:1.2px; border-bottom:1px solid var(--edge); position:sticky; top:0; background:var(--panel) }
  .pane[data-p=initiator] h2 { color:var(--a) } .pane[data-p=responder] h2 { color:var(--b) } .pane[data-p=ledger] h2 { color:var(--l) }
  .feed { overflow-y:auto; padding:10px; display:flex; flex-direction:column; gap:6px; flex:1 }
  .ev { background:var(--panel); border:1px solid var(--edge); border-left:3px solid var(--dim); border-radius:8px; padding:7px 10px; animation:in .25s ease }
  @keyframes in { from { opacity:0; transform:translateY(6px) } }
  .ev .l { font:600 12.5px var(--mono); word-break:break-all }
  .ev .d { color:var(--dim); font:11.5px var(--mono); margin-top:2px; word-break:break-all; white-space:pre-wrap }
  .ev.sign { border-left-color:#c792ea } .ev.anchor { border-left-color:var(--l) } .ev.refusal,.ev.error { border-left-color:var(--bad) }
  .ev.message { border-left-color:var(--b) } .ev.check { border-left-color:#56c8d8 } .ev.verify { border-left-color:#9ccc65 }
  .ev.verify.ok .d { color:#9ccc65 }
  #statusbar { padding:8px 18px; border-top:1px solid var(--edge); font:12px var(--mono); color:var(--dim); display:flex; gap:16px }
  #statusbar .dot { color:var(--b) }
</style>
</head>
<body>
<header>
  <h1>Standalone Handshake</h1>
  <span class="sub">two unconnected agents · mutual readiness · dual consent · witnessed bounded channel · anchored receipts</span>
  <div class="controls">
    <select id="replay" title="Replay a past run"><option value="">replay…</option></select>
    <button id="verifyAll" disabled>verify anchors keylessly</button>
    <button id="run" class="primary">▶ run live handshake</button>
  </div>
</header>
<div class="faults">
  fault injection:
  <label><input type="checkbox" data-f="forgedSignature">forged signature</label>
  <label><input type="checkbox" data-f="mismatchedManifest">mismatched manifest</label>
  <label><input type="checkbox" data-f="preOpenSend">send before open</label>
  <label><input type="checkbox" data-f="outOfScope" checked>out-of-scope kind</label>
  <label><input type="checkbox" data-f="oversized">oversized body</label>
  <label><input type="checkbox" data-f="replayInvitation">replay invitation</label>
  <label><input type="checkbox" data-f="forgedHandle">forged handle</label>
  <label><input type="checkbox" data-f="sendAfterRevoke" checked>send after revoke</label>
</div>
<main>
  <section class="pane" data-p="initiator"><h2>Agent A · initiator</h2><div class="feed" id="f-initiator"></div></section>
  <section class="pane" data-p="ledger"><h2>Clockchain · witness</h2><div class="feed" id="f-ledger"></div></section>
  <section class="pane" data-p="responder"><h2>Agent B · responder</h2><div class="feed" id="f-responder"></div></section>
</main>
<div id="statusbar"><span id="conn">connecting…</span><span id="sid"></span><span id="stage"></span></div>
<script>
const feeds = { initiator: f("f-initiator"), responder: f("f-responder"), ledger: f("f-ledger"), control: f("f-ledger") };
function f(id){ return document.getElementById(id); }
const runBtn = f("run"), verifyBtn = f("verifyAll"), replaySel = f("replay"), conn = f("conn"), sidEl = f("sid"), stageEl = f("stage");
let anchors = [];
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function add(e){
  const d = document.createElement("div");
  d.className = "ev " + e.kind;
  d.innerHTML = '<div class="l">' + esc(e.label) + '</div>' + (e.detail ? '<div class="d">' + esc(e.detail) + '</div>' : "");
  (feeds[e.pane] || feeds.control).appendChild(d);
  (feeds[e.pane] || feeds.control).scrollTop = 1e9;
}
function onEvent(e){
  add(e);
  if (e.kind === "anchor" && e.detail && /block \\d+/.test(e.detail)) anchors.push(e);
  if (e.label === "handshake_invite") { sidEl.textContent = ""; }
  if (e.pane === "control" && e.label === "final stage") stageEl.textContent = e.detail;
  if (e.kind === "info" && e.label === "run complete" ) { runBtn.disabled = false; verifyBtn.disabled = anchors.length === 0; loadRuns(); }
}
const es = new EventSource("/handshake/events");
es.onopen = () => conn.innerHTML = '<span class="dot">●</span> live';
es.onerror = () => conn.textContent = "reconnecting…";
es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch {} };
runBtn.onclick = async () => {
  anchors = []; verifyBtn.disabled = true; runBtn.disabled = true; stageEl.textContent = "";
  for (const k of Object.keys(feeds)) feeds[k].innerHTML = "";
  const faults = {}; document.querySelectorAll(".faults input").forEach(i => faults[i.dataset.f] = i.checked);
  await fetch("/handshake/api/run", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify({ faults }) });
};
verifyBtn.onclick = async () => {
  verifyBtn.disabled = true;
  const r = await fetch("/handshake/api/verify", { method:"POST" });
  const j = await r.json();
  for (const v of j.results || []) {
    add({ ts:Date.now(), pane:"ledger", kind:"verify", label:"keyless verify · " + (v.assetReferenceId || v.ledgerId || "?").split(":").pop(),
          detail: v.verifiedAgainst === "on-chain block" ? "VERIFIED on-chain · block " + v.blockHeight + " · " + (v.anchoredHash||"").slice(0,16) + "… · GET " + (v.url||"") : "NOT VERIFIED — " + (v.note||"") });
    document.querySelector("#f-ledger").scrollTop = 1e9;
  }
  verifyBtn.disabled = false;
};
async function loadRuns(){
  const j = await (await fetch("/handshake/api/runs")).json();
  replaySel.innerHTML = '<option value="">replay…</option>' + (j.runs||[]).map(r => '<option value="'+esc(r.id)+'">'+esc(r.label)+'</option>').join("");
}
replaySel.onchange = async () => {
  if (!replaySel.value) return;
  const j = await (await fetch("/handshake/api/runs/" + encodeURIComponent(replaySel.value))).json();
  for (const k of Object.keys(feeds)) feeds[k].innerHTML = "";
  anchors = [];
  for (const e of j.events || []) { add(e); if (e.kind === "anchor" && e.detail && /block \\d+/.test(e.detail)) anchors.push(e); }
  verifyBtn.disabled = anchors.length === 0;
};
loadRuns();
</script>
</body>
</html>`;
