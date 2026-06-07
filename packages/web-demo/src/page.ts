/** The single-page demo UI, served as a string (no static-file copy step). */
export const PAGE = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain - Proof of Action (test)</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; background: #0b0e14; color: #e6e6e6; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #9aa4b2; margin: 0 0 28px; font-size: 14px; }
  .card { background: #131824; border: 1px solid #222a3a; border-radius: 12px;
          padding: 18px 18px 20px; margin: 0 0 18px; }
  .card h2 { font-size: 15px; margin: 0 0 10px; color: #c9d4e3; }
  .step { color: #6f7d92; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  textarea { width: 100%; min-height: 70px; resize: vertical; background: #0b0e14;
             color: #e6e6e6; border: 1px solid #2a3344; border-radius: 8px; padding: 10px;
             font: 14px/1.4 inherit; }
  button { background: #2f6df6; color: #fff; border: 0; border-radius: 8px; padding: 9px 14px;
           font-size: 14px; cursor: pointer; margin: 8px 8px 0 0; }
  button.secondary { background: #2a3344; }
  button:disabled { opacity: .5; cursor: default; }
  .out { font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap;
         word-break: break-all; background: #0b0e14; border: 1px solid #222a3a; border-radius: 8px;
         padding: 10px; margin-top: 12px; color: #b8c4d6; }
  .ok { color: #46d369; } .bad { color: #ff6b6b; } .muted { color: #6f7d92; }
  a { color: #5b8cff; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Clockchain - Proof of Action</h1>
  <p class="sub">A live test: anchor a document on-chain with a consensus timestamp, then prove it is unaltered - and catch a tampered copy. Test network; the workflow is real, the data is not yet authoritative.</p>

  <div class="card">
    <div class="step">Step 1</div>
    <h2>Read the decentralized clock</h2>
    <button onclick="getTime()">Read consensus time</button>
    <div id="timeOut" class="out muted">Not read yet.</div>
  </div>

  <div class="card">
    <div class="step">Step 2</div>
    <h2>Notarize a document</h2>
    <textarea id="text">Q3 board resolution - approved.</textarea>
    <button id="notarizeBtn" onclick="notarize()">Notarize on-chain</button>
    <div id="noteOut" class="out muted">Enter text and notarize. Its SHA-256 hash is anchored on-chain.</div>
  </div>

  <div class="card">
    <div class="step">Step 3</div>
    <h2>Verify &amp; tamper test</h2>
    <button id="verifyBtn" class="secondary" onclick="verify()" disabled>Verify current text</button>
    <button id="tamperBtn" class="secondary" onclick="tamper()" disabled>Simulate tampering</button>
    <div id="verifyOut" class="out muted">Notarize first, then verify.</div>
  </div>
</div>
<script>
  let ledgerId = null;
  const $ = (id) => document.getElementById(id);
  async function post(path, body) {
    const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }
  async function getTime() {
    $("timeOut").textContent = "Reading...";
    try { const t = await post("/api/time");
      $("timeOut").innerHTML = "Latest block <b>" + t.latestBlockHeight + "</b>\\nConsensus time " + t.latestBlockTime;
    } catch (e) { $("timeOut").innerHTML = '<span class="bad">' + e.message + "</span>"; }
  }
  async function notarize() {
    const text = $("text").value;
    $("notarizeBtn").disabled = true;
    $("noteOut").textContent = "Hashing and anchoring on-chain (waiting for confirmation)...";
    try { const d = await post("/api/notarize", { text });
      ledgerId = d.ledgerId;
      $("noteOut").innerHTML = "SHA-256  " + d.hash + "\\nLedger ID  " + d.ledgerId +
        "\\nBlock height  " + (d.blockHeight ? "<b>" + d.blockHeight + "</b> (anchored on-chain)" : '<span class="muted">pending</span>');
      $("verifyBtn").disabled = false; $("tamperBtn").disabled = false;
    } catch (e) { $("noteOut").innerHTML = '<span class="bad">' + e.message + "</span>"; }
    finally { $("notarizeBtn").disabled = false; }
  }
  async function runVerify(text) {
    try { const d = await post("/api/verify", { ledgerId, text });
      const verdict = d.match ? '<span class="ok">MATCH - the document is unchanged</span>'
                              : '<span class="bad">NO MATCH - the document was altered</span>';
      $("verifyOut").innerHTML = verdict + "\\nanchored  " + d.anchoredHash + "\\ncurrent   " + d.currentHash;
    } catch (e) { $("verifyOut").innerHTML = '<span class="bad">' + e.message + "</span>"; }
  }
  function verify() { runVerify($("text").value); }
  function tamper() { $("text").value = $("text").value + " [edited]"; runVerify($("text").value); }
</script>
</body>
</html>`;
