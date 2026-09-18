// The Agent Handshake operator SOP: /handshake/sop (HTML for people) and
// /handshake/sop.txt (plain text for agents). Same stylesheet and chrome as
// the landing page; every fact below is the one the v2 public surface
// publishes — the tool list is V2_PUBLIC_TOOL_NAMES, the helper pin derives
// from instructions.ts, and the authoritative digests are always read from
// the live /.well-known/agent-handshake.json manifest, never hardcoded here.
import { BASE_CSS, LOGO_SVG, SUBSTRATE_LABEL } from "./landing.js";
import { V2_HELPER_ASSET_PREFIX, V2_HELPER_VERSION } from "./agent-handshake/v2/instructions.js";
import { V2_PUBLIC_TOOL_NAMES } from "./agent-handshake/v2/public-tools.js";

const ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const MANIFEST = "https://mcp.clockchain.network/.well-known/agent-handshake.json";
const MANIFEST_URL = `${V2_HELPER_ASSET_PREFIX}manifest.json`;
const HELPER_URL = `${V2_HELPER_ASSET_PREFIX}clockchain-agent-handshake.cjs`;
const TOOL_LIST = V2_PUBLIC_TOOL_NAMES.join(", ");

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Scoped additions to BASE_CSS for SOP content (notes, fact tables).
const SOP_CSS = `
  .sop-note { border-left: 3px solid var(--green); background: var(--green-soft); padding: 13px 18px; border-radius: 0 12px 12px 0; margin: 16px 0; font-size: 14px; color: var(--ink); }
  .sop-note.warn { border-color: #b42318; background: #fef3f2; }
  .sop-table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 14px; }
  .sop-table th { text-align: left; font-family: var(--mono); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--fg-3); border-bottom: 2px solid var(--line); padding: 8px 10px 8px 0; }
  .sop-table td { border-bottom: 1px solid var(--line); padding: 10px 10px 10px 0; vertical-align: top; color: var(--fg-2); }
  .sop-table td code { word-break: break-all; }
  .sop h3 { font-size: 20px; margin: 34px 0 12px; }
  .sop h3 .n { font-family: var(--mono); color: var(--green); font-size: 13px; margin-right: 8px; }
  .sop p, .sop li { color: var(--fg-2); font-size: 15px; }
  .sop ul { padding-left: 22px; }
  .sop li { margin: 6px 0; }
  .sop code { font-family: var(--mono); font-size: 12.5px; }
  .sop .role { display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; padding: 3px 10px; border-radius: 5px; margin-bottom: 6px; }
  .sop .role-a { background: var(--green); color: #fff; }
  .sop .role-b { background: var(--ink); color: #fff; }
  .sop .playbook { list-style: none; }
  /* The hero endpoint pill is inline-flex with an unbreakable code child;
     the 36-char handshake URL overflows narrow viewports without this. */
  .endpoint { max-width: 100%; }
  .endpoint code { min-width: 0; overflow-wrap: anywhere; }
  @media (max-width: 760px) { .sop-table { font-size: 12.5px; } .sop-table td, .sop-table th { padding: 8px 6px 8px 0; } }
`;

export const HANDSHAKE_SOP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clockchain Agent Handshake — Operator SOP</title>
<meta name="description" content="Run a mutually signed, independently verifiable handshake between two agents on the public Clockchain endpoint — helper ${V2_HELPER_VERSION}, protocol clockchain.agent-handshake/v2." />
<link rel="alternate" type="text/plain" href="/handshake/sop.txt" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
<style>
${BASE_CSS}
${SOP_CSS}</style>
</head>
<body>
<nav><div class="wrap nav-in">
  <div class="nav-left"><a class="brand" href="/">${LOGO_SVG}Clockchain</a><span class="tnet">Testnet</span></div>
  <div class="nav-links">
    <a href="/">Overview</a>
    <a href="/clock-tools">Clock tools</a>
    <a href="/llms.txt">llms.txt</a>
    <a href="/status">Status</a>
    <a class="pill" href="${MANIFEST}">Manifest</a>
  </div>
</div></nav>

<header class="hero"><div class="wrap">
  <span class="eyebrow">Agent Handshake · Production SOP · protocol v2 · helper ${V2_HELPER_VERSION}</span>
  <h1>Two agents prove control — <span class="green">mutually signed.</span></h1>
  <p class="sub">The Agent Handshake lets two independently controlled agents prove live signing-key control inside a bounded session and sign the same ordered exchange. The output is a VERIFIED certificate binding both identities, the session, message digests, ordering, and freshness.</p>
  <div class="endpoint">
    <code>mcp.clockchain.network/handshake/mcp</code>
    <button onclick="copyText('${ENDPOINT}','Endpoint copied')">Copy</button>
  </div>
</div></header>

<section class="sop"><div class="wrap" style="max-width:880px">

  <div class="sop-note warn">
    <b>Scope boundary — read before integrating.</b> The certificate proves identity, live key control, ordering, freshness, and peer binding. It does <b>not</b> prove employment, organizational delegation, spending limits, payment authority, or contract authority, and it authorizes nothing downstream. <code>externalBusinessActionPerformed</code> is always <code>false</code>. The server never receives a private key and never signs for either stakeholder.
  </div>

  <h3><span class="n">0</span>What you need</h3>
  <table class="sop-table">
    <tr><th>You need</th><th>Why</th></tr>
    <tr><td><b>Node.js 24.x</b> on each agent's machine</td><td>The pinned helper refuses any other major version.</td></tr>
    <tr><td><b>Two agent runtimes</b> (two processes, machines, or operators)</td><td>Any MCP-capable client that can POST JSON-RPC. Each side uses its own keys and state — never share one runtime across both roles.</td></tr>
    <tr><td><b>An out-of-band channel</b> between the two agents</td><td>Chat, ticket, queue — anything. Used once, to carry the responder invitation.</td></tr>
    <tr><td><b>A bounded session window</b></td><td>Signature payloads have a ≤90-second validity window each — act on signing requests immediately.</td></tr>
  </table>

  <h3><span class="n">1</span>Discover the service</h3>
  <p>Everything is self-describing. Fetch the public manifest — it carries the authoritative helper pin (manifest URL, helper URL, manifest digest), the trusted host roots, and the exact endpoint:</p>
  <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>curl -s ${MANIFEST}</code></pre></div>
  <table class="sop-table">
    <tr><th>Field</th><th>Production value</th></tr>
    <tr><td>MCP endpoint</td><td><code>${ENDPOINT}</code></td></tr>
    <tr><td>Discovery manifest</td><td><code>${MANIFEST}</code></td></tr>
    <tr><td>Helper manifest</td><td><code>${MANIFEST_URL}</code></td></tr>
    <tr><td>Helper binary</td><td><code>${HELPER_URL}</code></td></tr>
    <tr><td>Helper manifest SHA-256</td><td>Read <code>helper.manifestDigest</code> from the live manifest — the pin is authoritative, never transcribe it secondhand.</td></tr>
    <tr><td>Host roots</td><td><code>hostRoots[]</code> in the manifest — kid + Ed25519 fingerprint pairs.</td></tr>
    <tr><td>Tool surface</td><td>Exactly eight tools: <code>${esc(TOOL_LIST)}</code></td></tr>
  </table>

  <h3><span class="n">2</span>The pinned helper — local signing only</h3>
  <p>The helper is a single audited Node file that generates your session key, commits your exact local policy, registers a fresh ERC-8004 identity when the Initiator mandates it, signs payloads, and verifies the certificate — <b>all signing happens locally</b>. The server returns the authoritative instructions in every response; follow them exactly.</p>
  <ul>
    <li><b>Adapter path (preferred).</b> When a <code>localAction</code> carries <code>approvalTool</code>, the client-side harness adapter has already downloaded and digest-verified both assets. Call the fixed zero-input tool <code>authorize_local_action</code> once per helper step, in order — the adapter executes the exact digest-bound action without model transcription.</li>
    <li><b>Portable fallback.</b> Without an adapter, download <code>manifest.json</code> and <code>clockchain-agent-handshake.cjs</code> over HTTPS as two separate commands, inspect both, then run every helper operation through the <code>verifiedBootstrapPrefix</code> from the manifest — it re-hashes the manifest against the pinned digest and the helper against the manifest before compiling, exiting <code>86</code> on any mismatch.</li>
  </ul>
  <div class="sop-note">Never run the helper file directly, invent bytes, or substitute a wallet, policy, session, or role. The manifest digest pins only <code>manifest.json</code>; the helper's own digest lives inside that verified manifest.</div>

  <h3><span class="n">3</span>Connect</h3>
  <p>Streamable HTTP, plain JSON-RPC over POST. No account, API key, or Clockchain credential — authorization is per-call via the <code>access</code> capability the server issues to each role. Client setup:</p>
  <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>codex mcp add clockchain-handshake --url ${ENDPOINT}
claude mcp add --transport http --scope user clockchain-handshake ${ENDPOINT}</code></pre></div>

  <h3><span class="n">4</span>Playbook — Initiator</h3>
  <ol class="steps playbook">
    <li class="step"><span class="sn">1</span><div class="sbody"><span class="role role-a">Initiator</span><h4>Invite</h4><p>Call <code>agent_handshake_invite</code> with <code>{reference, statement, validForSeconds, identityPolicy}</code>. Keep <code>roleAccess</code> private and byte-for-byte stable; copy only <code>responderInvitation</code> to the other stakeholder.</p></div></li>
    <li class="step"><span class="sn">2</span><div class="sbody"><h4>Run the setup localAction</h4><p>Helper <code>init</code> → <code>policy</code> → <code>inspect</code> via <code>approvalTool</code> (or the verified shell commands). Record <code>sessionKeyAddress</code> and <code>policyDigest</code>.</p></div></li>
    <li class="step"><span class="sn">3</span><div class="sbody"><h4>Join</h4><p>Call <code>agent_handshake_join</code> with <code>{access, helperVersion: "${V2_HELPER_VERSION}", sessionKeyAddress, policyDigest}</code>. Do not register before join — the coordinator funds the observed seat only when registration is mandated.</p></div></li>
    <li class="step"><span class="sn">4</span><div class="sbody"><h4>Drive the loop</h4><p>Poll <code>agent_handshake_next</code> and dispatch on <code>needed</code>: signing steps return a payload-bearing <code>localAction</code> — perform it immediately, submit the private checkpoint via <code>agent_handshake_submit_checkpoint</code>, then the signature via <code>agent_handshake_submit</code>. <code>erc8004_registration</code> → run helper <code>register</code>, then poll <code>next</code> again. Waits return <code>retryAfterMs</code>.</p></div></li>
    <li class="step"><span class="sn">5</span><div class="sbody"><h4>Collect</h4><p>At <code>certificate_available</code>, call <code>agent_handshake_get_certificate</code>, then run the <code>verify-certificate</code> local action — expect <code>certificateVerified: true</code>, <code>outcome: "VERIFIED"</code>.</p></div></li>
  </ol>

  <h3><span class="n">5</span>Playbook — Responder</h3>
  <ol class="steps playbook">
    <li class="step"><span class="sn">1</span><div class="sbody"><span class="role role-b">Responder</span><h4>Accept</h4><p>Generate one fresh <code>acceptanceIdempotencyKey</code> (UUIDv4 or ≥16-byte base64url), then call <code>agent_handshake_accept_invitation</code> once with the invitation code. Retry only a retryable failure, with the same key. Keep the returned <code>roleAccess</code>; the invitation is consumed.</p></div></li>
    <li class="step"><span class="sn">2</span><div class="sbody"><h4>Identical from here</h4><p>Setup localAction → <code>agent_handshake_join</code> → <code>agent_handshake_next</code> loop → <code>agent_handshake_get_certificate</code> + local <code>verify-certificate</code>.</p></div></li>
  </ol>

  <div class="sop-note">
    <b>Pass criteria.</b> Both roles hold a certificate over the same session with the same result-object digest, <code>outcome: "VERIFIED"</code>, three ordered anchors (proposal → acceptance → acknowledgment), distinct session-key addresses and policy digests, and <code>externalBusinessActionPerformed: false</code>.
  </div>

  <h3><span class="n">6</span>Timing, limits, and errors</h3>
  <table class="sop-table">
    <tr><th>Constraint</th><th>Value</th><th>What it means</th></tr>
    <tr><td>Invitation lifetime</td><td>single-use · own <code>invitationExpiresAtMs</code></td><td>Read <code>invitationExpiresAtMs</code> from the invite response: the coordinator refuses to mint a new invitation when the window has under 30 seconds of runway remaining, and the responder must claim before <code>invitationExpiresAtMs</code>. <code>sessionDeadlineMs</code> bounds the session overall; a consumed or expired code is terminal.</td></tr>
    <tr><td>Signature validity</td><td>≤ 90 seconds</td><td>Perform each signing localAction the moment it is returned.</td></tr>
    <tr><td>Rate limits</td><td>5 invites/hr · 120 calls/min per IP</td><td>429 carries <code>rate_limited</code>; poll on <code>retryAfterMs</code>, don't burst.</td></tr>
    <tr><td><code>HANDSHAKE_TEMPORARILY_UNAVAILABLE</code></td><td><code>retryable: true</code></td><td>Transient — wait <code>retryAfterMs</code> and retry the same call with the same <code>access</code>.</td></tr>
    <tr><td><code>HANDSHAKE_UNAVAILABLE</code></td><td><code>retryable: false</code></td><td>Terminal — expired invitation, replayed code, wrong role, bad digest. Diagnose, then start a new session.</td></tr>
  </table>

  <h3><span class="n">7</span>Trust and hygiene</h3>
  <ul>
    <li>Treat <code>roleAccess</code>, the invitation code, signatures, and private keys as sensitive: never log them and never paste them into tickets or chat beyond the one out-of-band invitation delivery. The server never receives a private key.</li>
    <li>The local workspace is disposable: fresh empty directory, session-scoped <code>$TMPDIR</code>, no repository clone, no plugin, no browser, no general Clockchain credential.</li>
    <li><code>statementDigest</code> covers the canonical full terms object — preserve the returned digest rather than recomputing it from the statement text.</li>
    <li>The three ordered anchor receipts land on the ${SUBSTRATE_LABEL} and are keyless-re-verifiable from the ledger. The certificate and role artifacts additionally depend on local signature verification against the manifest's trusted host roots.</li>
  </ul>

</div></section>

<footer><div class="wrap">
  <div class="foot-row">
    <a class="brand" href="/">${LOGO_SVG}Clockchain</a>
    <div class="foot-links">
      <a href="/">Overview</a>
      <a href="${MANIFEST}">Manifest</a>
      <a href="/llms.txt">llms.txt</a>
      <a href="/status">Status</a>
      <a href="/health">Health</a>
    </div>
  </div>
  <p class="disclaimer">Clockchain Agent Handshake · production SOP · protocol clockchain.agent-handshake/v2 · helper ${V2_HELPER_VERSION}. Anchored on the ${SUBSTRATE_LABEL}. The certificate proves identity, live key control, ordering, freshness, and peer binding — it authorizes nothing downstream.</p>
</div></footer>

<div class="toast" id="toast"></div>
<script>
  function copyText(t, msg){ navigator.clipboard.writeText(t).then(function(){toast(msg||'Copied');}).catch(function(){toast('Copy failed — select manually');}); }
  function copyEl(btn){ var c = btn.parentElement.querySelector('code'); copyText(c.innerText, 'Copied'); }
  function toast(m){ var e=document.getElementById('toast'); e.textContent=m; e.classList.add('show'); clearTimeout(window.__t); window.__t=setTimeout(function(){e.classList.remove('show');},1800); }
</script>
</body>
</html>`;

// Plain-text SOP for agents — same facts, no markup.
export const HANDSHAKE_SOP_TXT = `Clockchain Agent Handshake — Operator SOP (production)

Endpoint:   ${ENDPOINT}
Manifest:   ${MANIFEST}   (authoritative helper pin + host roots — read it live)
Helper:     v${V2_HELPER_VERSION} · Node.js 24 only
            ${MANIFEST_URL}
            ${HELPER_URL}
Tools:      ${TOOL_LIST}

SCOPE BOUNDARY
  The certificate proves identity, live key control, ordering, freshness, and
  peer binding. It does NOT prove employment, delegation, spending limits,
  payment or contract authority, and authorizes nothing downstream.
  externalBusinessActionPerformed is always false. The server never receives
  a private key and never signs for either stakeholder.

YOU NEED
  - Node.js 24.x on each agent's machine (the helper refuses other majors)
  - Two agent runtimes — any MCP-capable client; never share one runtime
  - One out-of-band channel to carry the responder invitation
  - A bounded session window; signature payloads are valid <= 90 seconds

FLOW — INITIATOR
  1. agent_handshake_invite {reference, statement, validForSeconds, identityPolicy}
     Keep roleAccess private and byte-for-byte stable; copy ONLY
     responderInvitation to the other stakeholder.
  2. Run the setup localAction: helper init -> policy -> inspect.
     With an adapter, call the fixed zero-input authorize_local_action tool
     once per helper step in order. Without one, download both pinned assets
     as two separate commands, inspect them, and run every operation through
     the manifest's verifiedBootstrapPrefix (re-hashes manifest then helper;
     exits 86 on mismatch).
  3. agent_handshake_join {access, helperVersion: "${V2_HELPER_VERSION}",
     sessionKeyAddress, policyDigest} — do not register before join.
  4. Poll agent_handshake_next and dispatch on needed:
       signing step -> perform localAction immediately, then
         agent_handshake_submit_checkpoint, then agent_handshake_submit;
       erc8004_registration -> helper register, then poll next again;
       wait/stage -> sleep retryAfterMs, poll again.
  5. At certificate_available: agent_handshake_get_certificate, then the
     verify-certificate local action -> certificateVerified: true,
     outcome: "VERIFIED".

FLOW — RESPONDER
  1. Generate one fresh acceptanceIdempotencyKey (UUIDv4 or >=16-byte
     base64url), then agent_handshake_accept_invitation {invitation,
     acceptanceIdempotencyKey} — once. Retry only retryable failures with
     the same key. Keep the returned roleAccess; the invitation is consumed.
  2. Identical from here: setup -> join -> next loop -> get_certificate +
     verify-certificate.

PASS CRITERIA
  Same sessionId and same result-object certificate digest on both roles,
  outcome VERIFIED, three ordered anchors (proposal -> acceptance ->
  acknowledgment), distinct session-key addresses and policy digests,
  externalBusinessActionPerformed false.

LIMITS AND ERRORS
  5 invites/hour, 120 calls/minute per IP. Signature payloads <= 90 s.
  The invitation is single-use with its own invitationExpiresAtMs — read it
  from the invite response. Minting is refused when the window has under 30
  seconds of runway remaining; the responder must claim before
  invitationExpiresAtMs. sessionDeadlineMs bounds the overall session.
  HANDSHAKE_TEMPORARILY_UNAVAILABLE (retryable: true) -> wait retryAfterMs,
    retry the same call unchanged.
  HANDSHAKE_UNAVAILABLE (retryable: false) -> terminal; start a new session.

HYGIENE
  Treat roleAccess, the invitation, signatures, and private keys as
  sensitive: never log them and never paste them beyond the one out-of-band
  invitation delivery. The server never receives a private key. Fresh
  disposable workspace and session-scoped TMPDIR; no repo clone, plugin,
  browser, or general Clockchain credential. statementDigest covers the
  canonical full terms object — preserve the returned digest.
`;
