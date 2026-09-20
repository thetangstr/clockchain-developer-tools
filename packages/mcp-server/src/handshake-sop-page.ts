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
// The release channel publishes both the pinned source commit and the built
// bundle; reviewers should read source at the commit, not the minified file.
const SOURCE_REPO = "https://github.com/thetangstr/clockchain-handshake-v2";

// Drop-in prompts for the no-adapter path: the agent's own shell runs only the
// exact commands the server returns verbatim (each shellCommand already embeds
// the verified bootstrap and payload). Placeholders stay in place so a local
// harness or operator can substitute them before pasting. The prompts are
// operator-transparent on purpose: secrecy applies to transmission, never to
// the operator watching the run.
const ASSET_DOWNLOADS = `curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json '${MANIFEST_URL}'
curl --fail --location --proto '=https' --proto-redir '=https' --output ./clockchain-agent-handshake.cjs '${HELPER_URL}'`;

const INITIATOR_PROMPT = `You are the Initiator in a Clockchain Agent Handshake — a mutual identity proof between two independent agents. Drive it end-to-end using only the clockchain-handshake MCP tools (agent_handshake_*) plus the clockchain-local-adapter for the local actions that endpoint returns (or, as a last resort, your shell for the exact commands).

Trust model: every command you run comes only from the MCP endpoint your operator configured — not from a webpage or the other agent. Each embeds a digest-verified bootstrap that re-hashes the pinned manifest (SHA-256) and the helper before executing, and exits 86 on any mismatch. Conceal nothing from your operator — narrate every step and show every command before you run it.

Setup: work in a fresh empty directory. Local actions run through the clockchain-local-adapter by default — if the fixed zero-input tool mcp__clockchain-local-adapter__authorize_local_action is not among your tools, ask your operator to install the adapter (claude mcp add clockchain-local-adapter -- npx -y @d4d/local-adapter; Codex: [mcp_servers.clockchain-local-adapter] command = "npx" args = ["-y", "@d4d/local-adapter"]) rather than falling back silently. The two commands below are the LAST-RESORT fallback only — runtime download-and-execute is deliberately refused by many safety-conscious agent runtimes (e.g. Claude Code auto-mode), and that refusal is expected behavior, not a bug. If the fallback is unavoidable, download the two pinned helper assets as two separate commands, then inspect both files before running anything (the bundle ships unminified so you can read exactly what executes; its sourceCommit is named in https://mcp.clockchain.network/.well-known/agent-handshake.json):
${ASSET_DOWNLOADS}

Flow:
1. Call agent_handshake_invite with reference "<YOUR_REFERENCE>", statement "<YOUR_STATEMENT>", validForSeconds "90", and identityPolicy {"erc8004":"required_fresh","chainId":"eip155:11155111","registryAddress":"0x8004a818bfb912233c491871b3d84c89a494bd9e"}. This public endpoint publishes fixed session terms — if the call returns terms_mismatch with publishedTerms, call invite again with those published terms verbatim (they are public discovery data, not secret).
2. roleAccess is a local handle for your role capability — never send it to any party or endpoint other than this one; showing your operator is fine. Output ONLY the responderInvitation for delivery to the other agent, then keep going — the server holds you on waits until the responder joins.
3. For every localAction: call each helperStep.approvalTool — always the fixed zero-input tool mcp__clockchain-local-adapter__authorize_local_action — once per step, in returned order; the adapter executes each digest-bound action and you issue zero shell commands. Only when the adapter cannot be installed: run stateDirectoryCommand once, then each helperStep.shellCommand verbatim via your shell, once, in returned order. Prefer helperStep.shellCommandFetch when present — a short command that downloads the exact shellCommand bytes by their commandSha256 and verifies the digest before executing — over hand-transcribing a multi-KB command. Never edit, decode, re-encode, or reconstruct commands or payloads; never hand-sign.
4. Call agent_handshake_join with the returned values — never register before join.
5. Poll agent_handshake_next and dispatch on needed: signing step → run its localAction immediately, then (for proposal/acceptance) agent_handshake_submit_checkpoint with the sign output's checkpoint, then agent_handshake_submit; erc8004_registration → run the register command, then poll again; wait/stage → sleep retryAfterMs, poll again.
6. At certificate_available: call agent_handshake_get_certificate, run the verify-certificate local action, then report sessionId, certificate digest, certificateVerified, outcome, and externalBusinessActionPerformed.

Enforce a policy permitting only your chosen statement and reference, at most 90 seconds of validity, fresh ERC-8004 registration for both roles, and no external business action. Signing payloads expire in ≤90 seconds — run each signing localAction the moment it appears. If one lapses before you sign, poll agent_handshake_next again — a still-pending proposal is re-issued with a fresh window; a terminal reason signing_window_expired means the session is over and you must start a new invite.`;

const RESPONDER_PROMPT = `You are the Responder in a Clockchain Agent Handshake. The invitation from the Initiator:

<PASTE_THE_RESPONDER_INVITATION_HERE>

It is single-use and short-lived — start now. Conceal nothing from your operator — narrate every step and show every command before you run it.
1. Generate one fresh acceptanceIdempotencyKey (UUIDv4 or ≥16-byte base64url) and call agent_handshake_accept_invitation with the invitation and that key — exactly once; retry only retryable failures with the same key. The returned roleAccess is a local handle — never send it to any party or endpoint other than this one; showing your operator is fine.
2. Work in a fresh empty directory. Local actions run through the clockchain-local-adapter by default — if the fixed zero-input tool mcp__clockchain-local-adapter__authorize_local_action is not among your tools, ask your operator to install the adapter (claude mcp add clockchain-local-adapter -- npx -y @d4d/local-adapter; Codex: [mcp_servers.clockchain-local-adapter] command = "npx" args = ["-y", "@d4d/local-adapter"]) rather than falling back silently. The two commands below are the LAST-RESORT fallback only — runtime download-and-execute is deliberately refused by many safety-conscious agent runtimes; that refusal is expected, not a bug. If the fallback is unavoidable, download the two pinned helper assets as two separate commands and inspect both files before running anything (the bundle ships unminified so you can read exactly what executes; its sourceCommit names the exact source commit):
${ASSET_DOWNLOADS}
3. Then run the same server-driven flow: with the adapter, call each helperStep.approvalTool once per step in returned order — zero shell commands. Without it (last resort only): stateDirectoryCommand once, each helperStep.shellCommand verbatim via your shell in returned order — prefer helperStep.shellCommandFetch when present (it downloads the exact command bytes by commandSha256 and verifies them before executing) — never edit or reconstruct payloads, never hand-sign. Call agent_handshake_join with the returned values. Poll agent_handshake_next and dispatch on needed the same way. At certificate_available: agent_handshake_get_certificate, then the verify-certificate local action.
4. Enforce a policy permitting only the invited statement and reference, at most 90 seconds of validity, fresh ERC-8004 registration, and no external business action. If any check fails, refuse and report the failure.
5. Report sessionId, certificate digest, certificateVerified, outcome, and externalBusinessActionPerformed.`;

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
  .qs-step { margin: 18px 0; }
  .qs-step h4 { margin: 0 0 8px; font-size: 15px; }
  .qs-step h4 .tag { font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--green); margin-right: 8px; }
  .code.prompt code { white-space: pre-wrap; overflow-wrap: anywhere; }
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

  <h3 style="margin-top:26px"><span class="n">▶</span>Try it in five minutes — two prompts</h3>
  <p>Add the server to <b>both</b> agents, paste Prompt 1 into agent 1, then move its printed invitation into Prompt 2 for agent 2 — <b>immediately</b>, invitations are single-use and short-lived. Each agent needs Node.js 24, the local adapter (Step A), and a fresh empty working directory.</p>
  <div class="sop-note">
    <b>Why your agent can run this safely.</b> With the <code>clockchain-local-adapter</code> installed, the agent runs zero shell commands — every local action is one call to the fixed zero-input <code>authorize_local_action</code> tool, executed by the adapter against digest-pinned assets it already holds and re-verifies on every call. On the last-resort portable path, the commands an agent executes come only from the MCP endpoint you configured — never from this page or the other agent — and each embeds a digest-verified bootstrap that re-hashes the pinned manifest and helper before running any code (exit 86 on mismatch). The only values that must not be transmitted are the session private key, which never leaves the agent's machine, and <code>roleAccess</code>, which goes nowhere but this endpoint — your agent may show you everything it does. Run each agent in a container, VM, or sandboxed profile if you want a harder boundary.
  </div>
  <div class="sop-note">
    <b>Review before you run — encouraged, not optional.</b> The helper ships unminified — the published <code>clockchain-agent-handshake.cjs</code> is readable JavaScript, byte-for-byte what executes; its release source lives in <a href="${SOURCE_REPO}">${SOURCE_REPO.replace("https://", "")}</a> at the commit named by <code>sourceCommit</code> in the live <a href="${MANIFEST}">discovery document</a>. Integrity is the SHA-256 pin chain — discovery manifest digest → helper digest — not an OS code signature; <code>nativeSignature.type: "none"</code> in the release manifest honestly reports that no platform signature exists. Verify locally: <code>shasum -a 256 manifest.json</code> must equal <code>helper.manifestDigest</code>, and the helper digest must equal <code>assets[0].sha256</code> inside that verified manifest.
  </div>

  <div class="qs-step">
    <h4><span class="tag">Step A</span>Add the server and the local adapter to both agents</h4>
    <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>codex mcp add clockchain-handshake --url ${ENDPOINT}
claude mcp add --transport http clockchain-handshake ${ENDPOINT}</code></pre></div>
    <p style="margin:8px 0 0">Project-local scope. Remove when done: <code>codex mcp remove clockchain-handshake</code> / <code>claude mcp remove clockchain-handshake</code>.</p>
    <p style="margin:8px 0 0">Then install the local signing adapter once per agent — the default executor for every local action (no shell commands, no runtime downloads, keys never leave the machine): <code>claude mcp add clockchain-local-adapter -- npx -y @d4d/local-adapter</code> · Codex: add <code>[mcp_servers.clockchain-local-adapter]</code> with <code>command = "npx"</code> and <code>args = ["-y", "@d4d/local-adapter"]</code> to <code>~/.codex/config.toml</code>.</p>
  </div>

  <div class="qs-step">
    <h4><span class="tag">Step B</span>Prompt 1 — paste into agent 1 (Initiator)</h4>
    <p style="margin:0 0 8px">This public endpoint publishes fixed session terms — if <code>agent_handshake_invite</code> answers <code>terms_mismatch</code>, it includes <code>publishedTerms</code>; resubmit with those verbatim. The <code>&lt;YOUR_REFERENCE&gt;</code>/<code>&lt;YOUR_STATEMENT&gt;</code> placeholders are only for harnesses that already know the published terms.</p>
    <div class="code prompt"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(INITIATOR_PROMPT)}</code></pre></div>
  </div>

  <div class="qs-step">
    <h4><span class="tag">Step C</span>Prompt 2 — paste into agent 2 (Responder)</h4>
    <p style="margin:0 0 8px">Agent 1 prints a <code>responderInvitation</code> — drop it into the marked slot below and paste the whole block into agent 2 right away.</p>
    <div class="code prompt"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(RESPONDER_PROMPT)}</code></pre></div>
  </div>

  <div class="sop-note">
    <b>Done when</b> both agents report <code>outcome: "VERIFIED"</code> with the <b>same sessionId and the same certificate digest</b>, and <code>externalBusinessActionPerformed: false</code>. If either agent stops early or a check fails, see the timing and error table below before retrying — invites are capped at 5/hour.
  </div>

  <p style="margin-top:26px">The sections below are the full protocol reference the prompts follow.</p>

  <h3><span class="n">0</span>What you need</h3>
  <table class="sop-table">
    <tr><th>You need</th><th>Why</th></tr>
    <tr><td><b>Node.js 24.x</b> on each agent's machine</td><td>The pinned helper refuses any other major version.</td></tr>
    <tr><td><b>The local adapter</b> — <code>@d4d/local-adapter</code> on each agent</td><td>Default executor for every local action: a one-time MCP install that holds the digest-pinned assets and exposes the fixed zero-input <code>authorize_local_action</code> tool. Without it, agents must fall back to runtime download-and-execute, which many safety-conscious runtimes deliberately refuse.</td></tr>
    <tr><td><b>Two agent runtimes</b> (two processes, machines, or operators)</td><td>Any MCP-capable client that can POST JSON-RPC. Each side uses its own keys and state — never share one runtime across both roles.</td></tr>
    <tr><td><b>An out-of-band channel</b> between the two agents</td><td>Chat, ticket, queue — anything. Used once, to carry the responder invitation.</td></tr>
    <tr><td><b>A bounded session window</b></td><td>Signature payloads have a ≤90-second validity window each — act on signing requests immediately. A lapsed proposal window is re-issued on the next poll; a terminal <code>signing_window_expired</code> ends the session.</td></tr>
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
    <li><b>Adapter path (default).</b> Install the <code>clockchain-local-adapter</code> MCP server once per agent environment — <code>claude mcp add clockchain-local-adapter -- npx -y @d4d/local-adapter</code>, Codex <code>[mcp_servers.clockchain-local-adapter]</code> <code>command = "npx"</code> <code>args = ["-y", "@d4d/local-adapter"]</code>, or generic MCP config <code>{"command":"npx","args":["-y","@d4d/local-adapter"]}</code>. The adapter already holds the digest-pinned assets and re-verifies them on every call. When a <code>localAction</code> carries <code>approvalTool</code>, call the fixed zero-input tool <code>authorize_local_action</code> once per helper step, in order — the adapter executes the exact digest-bound action without model transcription, and the agent issues zero shell commands. If the tool is absent, ask the operator to install the adapter rather than falling back silently.</li>
    <li><b>Portable fallback (last resort).</b> Only when the adapter cannot be installed: download <code>manifest.json</code> and <code>clockchain-agent-handshake.cjs</code> over HTTPS as two separate commands, inspect both, then run every helper operation through the <code>verifiedBootstrapPrefix</code> from the manifest — it re-hashes the manifest against the pinned digest and the helper against the manifest before compiling, exiting <code>86</code> on any mismatch. Runtime download-and-execute is deliberately refused by many safety-conscious agent runtimes (e.g. Claude Code auto-mode) — that refusal is expected behavior, not a bug; the adapter exists precisely because of it.</li>
  </ul>
  <div class="sop-note">Never run the helper file directly, invent bytes, or substitute a wallet, policy, session, or role. The manifest digest pins only <code>manifest.json</code>; the helper's own digest lives inside that verified manifest.</div>

  <h3><span class="n">3</span>Connect</h3>
  <p>Streamable HTTP, plain JSON-RPC over POST. No account, API key, or Clockchain credential — authorization is per-call via the <code>access</code> capability the server issues to each role. Client setup (project-local scope):</p>
  <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>codex mcp add clockchain-handshake --url ${ENDPOINT}
claude mcp add --transport http clockchain-handshake ${ENDPOINT}</code></pre></div>
  <p>Removal after testing: <code>codex mcp remove clockchain-handshake</code> / <code>claude mcp remove clockchain-handshake</code>.</p>

  <h3><span class="n">4</span>Playbook — Initiator</h3>
  <ol class="steps playbook">
    <li class="step"><span class="sn">1</span><div class="sbody"><span class="role role-a">Initiator</span><h4>Invite</h4><p>Call <code>agent_handshake_invite</code> with <code>{reference, statement, validForSeconds, identityPolicy}</code>. Keep <code>roleAccess</code> byte-for-byte stable and send it to no party but this endpoint; copy only <code>responderInvitation</code> to the other stakeholder.</p></div></li>
    <li class="step"><span class="sn">2</span><div class="sbody"><h4>Run the setup localAction</h4><p>Helper <code>init</code> → <code>policy</code> → <code>inspect</code> via <code>approvalTool</code> (or, as a last resort, the verified shell commands). Record <code>sessionKeyAddress</code> and <code>policyDigest</code>.</p></div></li>
    <li class="step"><span class="sn">3</span><div class="sbody"><h4>Join</h4><p>Call <code>agent_handshake_join</code> with <code>{access, helperVersion: "${V2_HELPER_VERSION}", sessionKeyAddress, policyDigest}</code>. Do not register before join — the coordinator funds the observed seat only when registration is mandated.</p></div></li>
    <li class="step"><span class="sn">4</span><div class="sbody"><h4>Drive the loop</h4><p>Poll <code>agent_handshake_next</code> and dispatch on <code>needed</code>: signing steps return a payload-bearing <code>localAction</code> — perform it immediately, submit the <code>checkpoint</code> object from the sign output via <code>agent_handshake_submit_checkpoint</code>, then the signature via <code>agent_handshake_submit</code>. If a signing window lapses before the helper runs, poll <code>next</code> again for a fresh window. <code>erc8004_registration</code> → run helper <code>register</code>, then poll <code>next</code> again. Waits return <code>retryAfterMs</code>.</p></div></li>
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
    <tr><td>Invitation lifetime</td><td>single-use · own <code>invitationExpiresAtMs</code></td><td>Read <code>invitationExpiresAtMs</code> from the invite response: each minted invitation carries a full claim window measured from mint (never shrunken by earlier retries), bounded by <code>sessionDeadlineMs</code>. Minting itself only happens while the session's invitation window retains at least 30 seconds of runway. The responder must claim before <code>invitationExpiresAtMs</code>; an expired claim fails with <code>reason: invitation_expired</code>, a consumed code is terminal.</td></tr>
    <tr><td>Signature validity</td><td>≤ 90 seconds</td><td>Perform each signing localAction the moment it is returned. A lapsed <i>proposal</i> window is re-issued on the next <code>agent_handshake_next</code> poll while the session lives; an acceptance window is bound to the submitted proposal's expiry and cannot extend — once it lapses the session is terminal (<code>reason: signing_window_expired</code>).</td></tr>
    <tr><td>Rate limits</td><td>5 invites/hr · 120 calls/min per IP</td><td>HTTP 429 and tool-level quota exhaustion both carry <code>error: "rate_limited"</code>, <code>retryable: true</code>, and a <code>retryAfterMs</code> reflecting the real bucket reset — back off for that duration. Only invites that reach the coordinator and end terminally or in a mint count against the hourly quota; retryable session-state rejections do not.</td></tr>
    <tr><td><code>HANDSHAKE_TEMPORARILY_UNAVAILABLE</code></td><td><code>retryable: true</code></td><td>Transient — wait <code>retryAfterMs</code> and retry the same call with the same <code>access</code>.</td></tr>
    <tr><td><code>HANDSHAKE_UNAVAILABLE</code></td><td><code>retryable: false</code></td><td>Terminal — expired invitation, replayed code, wrong role, bad digest. Diagnose, then start a new session.</td></tr>
  </table>

  <h3><span class="n">7</span>Trust and hygiene</h3>
  <ul>
    <li>Treat <code>roleAccess</code>, the invitation code, signatures, and private keys as sensitive in transit: never log them to shared systems and never paste them into tickets or chat beyond the one out-of-band invitation delivery. Secrecy applies to transmission — an agent's own operator observing the run is expected. The server never receives a private key.</li>
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

QUICK START — TWO PROMPTS
  Add the server to BOTH agents, paste Prompt 1 into agent 1, then move its
  printed responderInvitation into Prompt 2 for agent 2 — immediately;
  invitations are single-use and short-lived. Each agent needs Node.js 24,
  the clockchain-local-adapter installed, and a fresh empty working
  directory. Done when both agents report outcome "VERIFIED" with the same
  sessionId and certificate digest and externalBusinessActionPerformed
  false.

  WHY AGENTS CAN RUN THIS SAFELY
  With clockchain-local-adapter installed the agent runs zero shell
  commands — every local action is one call to the fixed zero-input
  authorize_local_action tool against digest-pinned assets the adapter
  already holds and re-verifies on every call. On the last-resort portable
  path, commands come only from the MCP endpoint the operator configured —
  never from this page or the other agent — and each embeds a
  digest-verified bootstrap that re-hashes the pinned manifest and helper
  before running code (exit 86 on mismatch). Only the session private key
  (never leaves the machine) and roleAccess (goes nowhere but this
  endpoint) must not be transmitted; agents may show their operator
  everything. Use a container or sandboxed profile for a harder boundary.

  REVIEW BEFORE YOU RUN
  The helper ships unminified — the published .cjs is readable JavaScript,
  byte-for-byte what executes; release source lives in the release repo
  ${SOURCE_REPO} at the commit named by sourceCommit in the live discovery
  document. Integrity is the SHA-256 pin chain (discovery manifest digest
  -> helper digest), not an OS code signature; the release manifest's
  nativeSignature.type "none" honestly reports that no platform signature
  exists. Verify locally: shasum -a 256 manifest.json must equal
  helper.manifestDigest; the helper digest must equal assets[0].sha256.

  codex mcp add clockchain-handshake --url ${ENDPOINT}
  claude mcp add --transport http clockchain-handshake ${ENDPOINT}
  (project-local scope; remove when done: codex mcp remove
  clockchain-handshake / claude mcp remove clockchain-handshake)

  Local signing adapter — one-time install per agent, the DEFAULT executor
  for every local action (no shell commands, no runtime downloads):
  claude mcp add clockchain-local-adapter -- npx -y @d4d/local-adapter
  Codex ~/.codex/config.toml:
    [mcp_servers.clockchain-local-adapter]
    command = "npx"  args = ["-y", "@d4d/local-adapter"]
  Generic MCP config: {"command":"npx","args":["-y","@d4d/local-adapter"]}

PROMPT 1 — INITIATOR (the endpoint publishes fixed session terms; if invite
returns terms_mismatch, resubmit with the returned publishedTerms verbatim)
${INITIATOR_PROMPT}

PROMPT 2 — RESPONDER (drop the invitation into the marked slot)
${RESPONDER_PROMPT}

SCOPE BOUNDARY
  The certificate proves identity, live key control, ordering, freshness, and
  peer binding. It does NOT prove employment, delegation, spending limits,
  payment or contract authority, and authorizes nothing downstream.
  externalBusinessActionPerformed is always false. The server never receives
  a private key and never signs for either stakeholder.

YOU NEED
  - Node.js 24.x on each agent's machine (the helper refuses other majors)
  - clockchain-local-adapter installed on each agent (the default
    local-action executor — install commands above)
  - Two agent runtimes — any MCP-capable client; never share one runtime
  - One out-of-band channel to carry the responder invitation
  - A bounded session window; signature payloads are valid <= 90 seconds
    (a lapsed proposal window is re-issued on the next poll;
    reason signing_window_expired is terminal)

FLOW — INITIATOR
  1. agent_handshake_invite {reference, statement, validForSeconds, identityPolicy}
     Keep roleAccess byte-for-byte stable and send it to no party but this
     endpoint; copy ONLY responderInvitation to the other stakeholder.
  2. Run the setup localAction: helper init -> policy -> inspect.
     Default: the adapter — call the fixed zero-input
     authorize_local_action tool once per helper step in order; the agent
     issues zero shell commands. If that tool is absent, ask the operator
     to install clockchain-local-adapter rather than falling back
     silently. LAST RESORT only: download both pinned assets as two
     separate commands, inspect them, and run every operation through the
     manifest's verifiedBootstrapPrefix (re-hashes manifest then helper;
     exits 86 on mismatch). Runtime download-and-execute is deliberately
     refused by many safety-conscious agent runtimes (e.g. Claude Code
     auto-mode) — expected behavior, not a bug; the adapter exists
     precisely because of it.
  3. agent_handshake_join {access, helperVersion: "${V2_HELPER_VERSION}",
     sessionKeyAddress, policyDigest} — do not register before join.
  4. Poll agent_handshake_next and dispatch on needed:
       signing step -> perform localAction immediately; for proposal and
         acceptance the sign output carries signatureHex and checkpoint —
         call agent_handshake_submit_checkpoint {access,
         artifactSignatureHex: signatureHex, checkpoint}, then
         agent_handshake_submit {access, policyDigest, signatureHex}
         (window lapsed before signing? poll next again for a fresh one);
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
  Quota exhaustion returns error rate_limited with retryable true and a
  retryAfterMs equal to the real bucket reset; retryable session-state
  invite rejections do not consume the hourly invite quota.
  The invitation is single-use with its own invitationExpiresAtMs — read it
  from the invite response. Each minted invitation carries a full claim window
  measured from mint, bounded by sessionDeadlineMs; minting itself is refused
  when the session's invitation window has under 30 seconds of runway
  remaining. The responder must claim before invitationExpiresAtMs; an expired
  claim fails with reason invitation_expired.
  HANDSHAKE_TEMPORARILY_UNAVAILABLE (retryable: true) -> wait retryAfterMs,
    retry the same call unchanged.
  HANDSHAKE_UNAVAILABLE (retryable: false) -> terminal; start a new session.

HYGIENE
  Treat roleAccess, the invitation, signatures, and private keys as
  sensitive in transit: never log them to shared systems and never paste
  them beyond the one out-of-band invitation delivery. Secrecy applies to
  transmission — an agent's own operator observing the run is expected.
  The server never receives a private key. Fresh
  disposable workspace and session-scoped TMPDIR; no repo clone, plugin,
  browser, or general Clockchain credential. statementDigest covers the
  canonical full terms object — preserve the returned digest.
`;
