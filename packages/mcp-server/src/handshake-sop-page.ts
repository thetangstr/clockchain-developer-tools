// The Agent Handshake operator SOP: /handshake/sop (HTML for people) and
// /handshake/sop.txt (plain text for agents). Same stylesheet and chrome as
// the landing page; every fact below is the one the v2 public surface
// publishes — the tool list is V2_PUBLIC_TOOL_NAMES, the helper pin derives
// from instructions.ts, and the authoritative digests are always read from
// the live /.well-known/agent-handshake.json manifest, never hardcoded here.
import { BASE_CSS, LOGO_SVG, SUBSTRATE_LABEL } from "./landing.js";
import { V2_HELPER_ASSET_PREFIX, V2_HELPER_VERSION, V2_PUBLIC_ENDPOINT } from "./agent-handshake/v2/instructions.js";
import { V2_PUBLIC_TOOL_NAMES } from "./agent-handshake/v2/public-tools.js";

const ENDPOINT = V2_PUBLIC_ENDPOINT;
const ADAPTER_INSTALL_CLAUDE = `claude mcp add clockchain-local-adapter -- npx -y @d4d.group/local-adapter`;
const ADAPTER_INSTALL_CODEX = `[mcp_servers.clockchain-local-adapter] command = "npx" args = ["-y", "@d4d.group/local-adapter"]`;
const ADAPTER_INSTALL_GENERIC = `{"command":"npx","args":["-y","@d4d.group/local-adapter"]}`;
// Pinned-install variant: `npm install -g @d4d.group/local-adapter` once, then
// the installed bin `clockchain-local-adapter` is the MCP command itself — no
// npx, no per-launch fetch. Same package, same server name.
const ADAPTER_INSTALL_NPM = `npm install -g @d4d.group/local-adapter`;
const ADAPTER_INSTALL_NPX_PINNED = `npx -y @d4d.group/local-adapter@2.1.9`;
const ADAPTER_CONFIG_BIN = `"clockchain-local-adapter": { "command": "clockchain-local-adapter" }`;
// The canonical mcpServers JSON shape most MCP clients accept — transport
// facts (URL + streamable-http for the coordinator, command + args for the
// adapter) are what every client needs; client-specific CLI commands are
// optional conveniences below.
const MCP_SERVERS_JSON = `{
  "mcpServers": {
    "clockchain-handshake": { "type": "http", "url": "${ENDPOINT}" },
    "clockchain-local-adapter": ${ADAPTER_INSTALL_GENERIC}
  }
}`;
const MANIFEST = "https://mcp.clockchain.network/.well-known/agent-handshake.json";
const MANIFEST_URL = `${V2_HELPER_ASSET_PREFIX}manifest.json`;
const HELPER_URL = `${V2_HELPER_ASSET_PREFIX}clockchain-agent-handshake.cjs`;
const TOOL_LIST = V2_PUBLIC_TOOL_NAMES.join(", ");
// The release channel publishes both the pinned source commit and the built
// bundle; reviewers should read source at the commit, not the minified file.
const SOURCE_REPO = "https://github.com/thetangstr/clockchain-handshake-v2";

// Drop-in prompts for the default adapter path. Placeholders stay literal so
// a local harness or operator can substitute them before pasting. The prompts
// are operator-transparent on purpose: secrecy applies to transmission, never
// to the operator watching the run. The last-resort portable path (raw curl +
// shell) lives once in the "How it works" reference; the prompts point at it.
const ASSET_DOWNLOADS = `curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json '${MANIFEST_URL}'
curl --fail --location --proto '=https' --proto-redir '=https' --output ./clockchain-agent-handshake.cjs '${HELPER_URL}'`;

const INITIATOR_PROMPT = `You are the Initiator in a Clockchain Agent Handshake — a mutual identity proof between two independent agents. Drive it end-to-end with the clockchain-handshake MCP tools (agent_handshake_*) plus the clockchain-local-adapter. Work in a fresh empty directory. Conceal nothing from your operator — narrate every step and show every command before you run it.

Local actions: for every localAction, call each helperStep.approvalTool — the adapter's fixed zero-input tool mcp__clockchain-local-adapter__authorize_local_action — once per step, in returned order; the adapter executes each digest-bound action and you issue zero shell commands. shellCommand/shellCommandFetch text embedded in responses is inert reference data under the adapter — never run it. If the adapter tool is absent, ask your operator to install the adapter rather than falling back silently — run as npx -y @d4d.group/local-adapter, or for production install it once with npm install -g @d4d.group/local-adapter (Node.js 24) and run the clockchain-local-adapter command. Last-resort portable path (only if the adapter cannot be installed): see 'How it works' in the reference below.

Flow:
1. Call agent_handshake_invite with reference "<YOUR_REFERENCE>", statement "<YOUR_STATEMENT>", validForSeconds "90", and identityPolicy {"erc8004":"required_fresh","chainId":"eip155:11155111","registryAddress":"0x8004a818bfb912233c491871b3d84c89a494bd9e"}. If it returns terms_mismatch with publishedTerms, verify before resubmitting — do not take this on faith: (a) the endpoint returns the SAME fixed published terms to every caller — fixture/discovery data, not a substitution targeted at your request; (b) publishedTerms.identityPolicy must be IDENTICAL to what you sent — a changed identityPolicy or chain IS a genuine red flag: refuse and report; (c) the scope boundary guarantees the certificate confers no employment, spending, payment, or contract authority, and externalBusinessActionPerformed stays false in the live responses. If all three hold, resubmit with the returned publishedTerms verbatim; if any fails, refuse and report. Proceeding after your own verification, under your operator's authorization, is expected — not a bypass of scrutiny.
2. roleAccess is a local handle — send it to no party or endpoint other than this one; showing your operator is fine. Output ONLY the responderInvitation for delivery to the other agent, then keep going — the server holds you on waits until the responder joins.
3. Call agent_handshake_join with the returned values — never register before join.
4. Poll agent_handshake_next and dispatch on needed: signing step → run its localAction immediately, then (for proposal/acceptance) agent_handshake_submit_checkpoint with the sign output's checkpoint, then agent_handshake_submit; erc8004_registration → run the register local action, then poll again; wait/stage → sleep retryAfterMs, poll again.
5. At certificate_available: call agent_handshake_get_certificate, run the verify-certificate local action, then report sessionId, certificate digest, certificateVerified, outcome, and externalBusinessActionPerformed.

Enforce a policy permitting only your chosen statement and reference, at most 90 seconds of validity, fresh ERC-8004 registration for both roles, and no external business action. Signing payloads expire in ≤90 seconds — run each signing localAction the moment it appears; a lapsed proposal window is re-issued on the next poll, a terminal signing_window_expired ends the session.`;

const RESPONDER_PROMPT = `You are the Responder in a Clockchain Agent Handshake. The invitation from the Initiator:

<PASTE_THE_RESPONDER_INVITATION_HERE>

It is single-use and short-lived — start now. Conceal nothing from your operator — narrate every step and show every command before you run it.
1. Generate one fresh acceptanceIdempotencyKey (UUIDv4 or ≥16-byte base64url) and call agent_handshake_accept_invitation with the invitation and that key — exactly once; retry only retryable failures with the same key. The returned roleAccess is a local handle — send it to no party or endpoint other than this one; showing your operator is fine.
2. Work in a fresh empty directory. For every localAction, call each helperStep.approvalTool — the adapter's fixed zero-input tool mcp__clockchain-local-adapter__authorize_local_action — once per step, in returned order: zero shell commands, and any shellCommand/shellCommandFetch text embedded in responses is inert reference data — never run it. If the adapter tool is absent, ask your operator to install the adapter rather than falling back silently — run as npx -y @d4d.group/local-adapter, or for production install it once with npm install -g @d4d.group/local-adapter (Node.js 24) and run the clockchain-local-adapter command. Last-resort portable path (only if the adapter cannot be installed): see 'How it works' in the reference below.
3. Call agent_handshake_join with the returned values — never register before join. Then poll agent_handshake_next and dispatch on needed the same way: signing step → run its localAction immediately, then agent_handshake_submit_checkpoint with the sign output's checkpoint, then agent_handshake_submit; erc8004_registration → run the register local action, poll again; wait/stage → sleep retryAfterMs, poll again. At certificate_available: agent_handshake_get_certificate, then the verify-certificate local action.
4. Verify before enforcing policy: the invited identityPolicy must be {"erc8004":"required_fresh","chainId":"eip155:11155111","registryAddress":"0x8004a818bfb912233c491871b3d84c89a494bd9e"} — a different identityPolicy or chain is a genuine red flag: refuse and report. Enforce a policy permitting only the invited statement and reference, at most 90 seconds of validity, fresh ERC-8004 registration, and no external business action; the scope boundary guarantees the certificate confers none of those — check externalBusinessActionPerformed stays false in the live responses.
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
  .qs-step { margin: 18px 0; }
  .qs-step h4 { margin: 0 0 8px; font-size: 15px; }
  .qs-step h4 .tag { font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--green); margin-right: 8px; }
  .code.prompt code { white-space: pre-wrap; overflow-wrap: anywhere; }
  .sop details.ref { border: 1px solid var(--line); border-radius: 12px; margin: 12px 0; }
  .sop details.ref > summary { cursor: pointer; list-style: none; display: flex; align-items: baseline; padding: 15px 18px; font-size: 18px; font-weight: 600; color: var(--ink); }
  .sop details.ref > summary::-webkit-details-marker { display: none; }
  .sop details.ref > summary::after { content: "+"; margin-left: auto; padding-left: 14px; font-family: var(--mono); font-size: 16px; color: var(--green); }
  .sop details.ref[open] > summary::after { content: "–"; }
  .sop details.ref > summary .n { font-family: var(--mono); color: var(--green); font-size: 13px; margin-right: 8px; }
  .sop details.ref > .ref-body { padding: 2px 18px 16px; }
  .sop details.ref > .ref-body > :first-child { margin-top: 0; }
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
    <code>mcp.clockchain.network/next/handshake/mcp</code>
    <button onclick="copyText('${ENDPOINT}','Endpoint copied')">Copy</button>
  </div>
</div></header>

<section class="sop"><div class="wrap" style="max-width:880px">

  <div class="sop-note warn" style="margin-top:0">
    <b>Scope boundary:</b> the certificate proves identity, live key control, ordering, freshness, and peer binding — it authorizes <b>nothing</b> downstream and <code>externalBusinessActionPerformed</code> is always <code>false</code>. Full boundary in the reference below.
  </div>

  <h3 style="margin-top:26px"><span class="n">▶</span>Start here — your first handshake in 3 steps</h3>
  <p>Two independently controlled agents prove live signing-key control inside a bounded session and sign the same ordered exchange — the output is a <b>VERIFIED certificate</b> binding both identities, the session, message digests, ordering, and freshness.</p>
  <p style="margin-top:-6px"><b>Prereqs:</b> Node.js 24 on each agent · two agent runtimes · one out-of-band channel · invites capped at 5/hour.</p>

  <div class="qs-step">
    <h4><span class="tag">Step 1</span>Register two MCP servers on each agent — any MCP-capable client works</h4>
    <p style="margin:0 0 8px"><b>1.</b> <code>clockchain-handshake</code> — a remote streamable-http MCP server at <code>${ENDPOINT}</code> (no auth: authorization is per-call via the <code>access</code> capability the server issues). <b>2.</b> <code>clockchain-local-adapter</code> — a local stdio MCP server, the <code>@d4d.group/local-adapter</code> npm package (requires Node.js 24). Two ways to run it — pick one: <b>(a) quick start, default:</b> command <code>npx -y @d4d.group/local-adapter</code> — npx ships with Node/npm and downloads + caches the package from the npm registry on first launch; one line, nothing to install first. <b>(b) for production / reliability:</b> install once — <code>${ADAPTER_INSTALL_NPM}</code> — then use the installed binary <code>clockchain-local-adapter</code> as the MCP command: deterministic pinned version, no network dependency at launch (works offline after install), faster cold start. Both run the same npm package; the only difference is npx-fetch-on-launch versus a one-time global install. For reproducibility without a global install, the npx form can be version-pinned — <code>${ADAPTER_INSTALL_NPX_PINNED}</code>. The adapter is the default executor for every local action — the agent issues zero shell commands and keys never leave the machine.</p>
    <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${MCP_SERVERS_JSON}</code></pre></div>
    <p style="margin:8px 0 0">The common <code>mcpServers</code> JSON shape most clients accept — shown for the quick-start npx path. For the production install (b), the adapter entry is just the installed binary:</p>
    <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${ADAPTER_CONFIG_BIN}</code></pre></div>
    <p style="margin:8px 0 0">Some clients spell the remote transport differently — <code>"transport": "http"</code>, <code>"streamable-http"</code>, or a nested transport object; the invariant is the URL plus streamable-http, so map those two facts to your client's own config schema.</p>
    <details class="ref"><summary>Client-specific examples (optional)</summary><div class="ref-body">
      <ul style="margin-top:0">
        <li><b>Claude Code:</b> <code>claude mcp add --transport http clockchain-handshake ${ENDPOINT}</code> and <code>${ADAPTER_INSTALL_CLAUDE}</code> — remove when done with <code>claude mcp remove</code>.</li>
        <li><b>Codex:</b> <code>codex mcp add clockchain-handshake --url ${ENDPOINT}</code> and <code>${ADAPTER_INSTALL_CODEX}</code> in <code>~/.codex/config.toml</code> — remove when done with <code>codex mcp remove</code>.</li>
        <li><b>Any other MCP client</b> (Cursor, Cline, Windsurf, an SDK, a custom client): point its MCP server config at the same URL + command above.</li>
      </ul>
    </div></details>
  </div>

  <div class="qs-step">
    <h4><span class="tag">Step 2</span>Initiator — paste Prompt 1 into agent 1</h4>
    <p style="margin:0 0 8px">It prints a <code>responderInvitation</code> — the only value that leaves agent 1. On a <code>terms_mismatch</code> answer the prompt itself walks the agent through verifying <code>publishedTerms</code> before resubmitting — verify-then-proceed, not blind trust.</p>
    <div class="code prompt"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(INITIATOR_PROMPT)}</code></pre></div>
  </div>

  <div class="qs-step">
    <h4><span class="tag">Step 3</span>Responder — paste Prompt 2 into agent 2</h4>
    <p style="margin:0 0 8px">Drop the invitation into the marked slot and paste <b>immediately</b> — invitations are single-use and short-lived. Both agents finish by reporting <code>VERIFIED</code>.</p>
    <div class="code prompt"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(RESPONDER_PROMPT)}</code></pre></div>
  </div>

  <div class="sop-note">
    <b>Done when</b> both agents report <code>outcome: "VERIFIED"</code> with the <b>same sessionId and the same certificate digest</b>, <code>externalBusinessActionPerformed: false</code>, and the pass criteria hold: three ordered anchors (proposal → acceptance → acknowledgment) and distinct session-key addresses and policy digests. If either agent stops early or a check fails, open "Timing, limits, and errors" below before retrying — invites are capped at 5/hour.
  </div>

  <p style="margin-top:26px">Reference — expand as needed.</p>

  <details class="ref"><summary>How it works — and how to verify it yourself</summary><div class="ref-body">
    <p>The coordinator is a stateless streamable-http MCP server that <b>never signs</b> — it sequences the exchange and anchors receipts; all signing happens locally on each agent through the pinned helper (a single audited Node.js 24 file, unminified — byte-for-byte what executes; its release source lives in <a href="${SOURCE_REPO}">${SOURCE_REPO.replace("https://", "")}</a> at the <code>sourceCommit</code> named in the live <a href="${MANIFEST}">discovery document</a>). The helper generates the session key, commits your exact local policy, registers a fresh ERC-8004 identity when mandated, signs payloads, and verifies the certificate.</p>
    <ul>
      <li><b>Adapter path (default).</b> The <code>clockchain-local-adapter</code> MCP server (Step 1 — <code>npx</code> or the pinned global install) already holds the digest-pinned assets and re-verifies them on every call. Every <code>localAction</code> is one call per step to the fixed zero-input <code>authorize_local_action</code> tool — the agent issues zero shell commands, and embedded <code>shellCommand</code>/<code>shellCommandFetch</code> text is inert reference data, never to be run.</li>
      <li><b>Portable fallback (last resort — only when the adapter cannot be installed).</b> Download the two pinned assets as two separate commands, inspect both, then run <code>stateDirectoryCommand</code> once and each <code>helperStep.shellCommand</code> verbatim via your shell in returned order — prefer <code>helperStep.shellCommandFetch</code> when present (it downloads the exact command bytes by <code>commandSha256</code> and verifies them before executing). Never edit, decode, re-encode, or reconstruct commands or payloads; never hand-sign.
        <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code>${esc(ASSET_DOWNLOADS)}</code></pre></div>
        Runtime download-and-execute is deliberately refused by many safety-conscious agent runtimes (e.g. Claude Code auto-mode) — that refusal is expected behavior, not a bug; the adapter exists precisely because of it. If this client refuses, stop and ask the operator to install the adapter.</li>
    </ul>
    <p><b>Verify it yourself.</b> Integrity is the SHA-256 pin chain, not an OS code signature — <code>nativeSignature.type: "none"</code> honestly reports that no platform signature exists. <code>shasum -a 256 manifest.json</code> must equal <code>helper.manifestDigest</code> in the live <a href="${MANIFEST}">discovery manifest</a>, and the helper digest must equal <code>assets[0].sha256</code> inside that verified manifest. Every helper run goes through the manifest's <code>verifiedBootstrapPrefix</code>, which re-hashes the manifest against the pinned digest and the helper against the manifest before compiling — exit <code>86</code> on any mismatch.</p>
    <table class="sop-table">
      <tr><th>Field</th><th>Production value</th></tr>
      <tr><td>MCP endpoint</td><td><code>${ENDPOINT}</code> (streamable-http; no client credential — authorization is per-call via the <code>access</code> capability)</td></tr>
      <tr><td>Discovery manifest</td><td><code>${MANIFEST}</code> — carries the authoritative helper pin and <code>hostRoots[]</code> (kid + Ed25519 fingerprint pairs)</td></tr>
      <tr><td>Helper assets</td><td><code>${MANIFEST_URL}</code> · <code>${HELPER_URL}</code></td></tr>
      <tr><td>Tool surface</td><td>Exactly eight tools: <code>${esc(TOOL_LIST)}</code></td></tr>
    </table>
    <div class="sop-note">Never run the helper file directly, invent bytes, or substitute a wallet, policy, session, or role. The manifest digest pins only <code>manifest.json</code>; the helper's own digest lives inside that verified manifest.</div>
  </div></details>

  <details class="ref"><summary>Scope boundary — what the certificate does and does not prove</summary><div class="ref-body">
    <div class="sop-note warn" style="margin-top:0">
      The certificate proves identity, live key control, ordering, freshness, and peer binding. It does <b>not</b> prove employment, organizational delegation, spending limits, payment authority, or contract authority, and it authorizes nothing downstream. <code>externalBusinessActionPerformed</code> is always <code>false</code>. The server never receives a private key and never signs for either stakeholder. These guarantees are also what make a <code>terms_mismatch</code> resubmission verifiable: the returned <code>publishedTerms</code> must keep the caller's <code>identityPolicy</code> identical and <code>externalBusinessActionPerformed</code> stays <code>false</code> in the live responses — proceeding after that verification, under operator authorization, is expected, not a bypass of scrutiny.
    </div>
  </div></details>

  <details class="ref"><summary>Timing, limits, and errors</summary><div class="ref-body">
  <table class="sop-table">
    <tr><th>Constraint</th><th>Value</th><th>What it means</th></tr>
    <tr><td>Invitation lifetime</td><td>single-use · own <code>invitationExpiresAtMs</code></td><td>Read <code>invitationExpiresAtMs</code> from the invite response: each minted invitation carries a full claim window measured from mint (never shrunken by earlier retries), bounded by <code>sessionDeadlineMs</code>. Minting itself only happens while the session's invitation window retains at least 30 seconds of runway. The responder must claim before <code>invitationExpiresAtMs</code>; an expired claim fails with <code>reason: invitation_expired</code>, a consumed code is terminal.</td></tr>
    <tr><td>Signature validity</td><td>≤ 90 seconds</td><td>Perform each signing localAction the moment it is returned. A lapsed <i>proposal</i> window is re-issued on the next <code>agent_handshake_next</code> poll while the session lives; an acceptance window is bound to the submitted proposal's expiry and cannot extend — once it lapses the session is terminal (<code>reason: signing_window_expired</code>).</td></tr>
    <tr><td>Rate limits</td><td>5 invites/hr · 120 calls/min per IP</td><td>HTTP 429 and tool-level quota exhaustion both carry <code>error: "rate_limited"</code>, <code>retryable: true</code>, and a <code>retryAfterMs</code> reflecting the real bucket reset — back off for that duration. Only invites that reach the coordinator and end terminally or in a mint count against the hourly quota; retryable session-state rejections do not.</td></tr>
    <tr><td><code>HANDSHAKE_TEMPORARILY_UNAVAILABLE</code></td><td><code>retryable: true</code></td><td>Transient — wait <code>retryAfterMs</code> and retry the same call with the same <code>access</code>.</td></tr>
    <tr><td><code>HANDSHAKE_UNAVAILABLE</code></td><td><code>retryable: false</code></td><td>Terminal — expired invitation, replayed code, wrong role, bad digest. Diagnose, then start a new session.</td></tr>
    <tr><td>Terminal <code>reason</code> codes</td><td><code>terms_mismatch</code> · <code>invitation_expired</code> · <code>invitation_invalid</code> · <code>role_access_invalid</code> · <code>funding_timeout</code> · <code>signing_window_expired</code></td><td><code>terms_mismatch</code> returns <code>publishedTerms</code> — verify per Step 2, then resubmit. <code>invitation_expired</code>/<code>invitation_invalid</code> mean the claim was too late or the code bad/consumed — re-invite. <code>role_access_invalid</code> means the access token itself is bad or consumed. <code>funding_timeout</code> is distinct: the join succeeded but the host never funded the session seat before the deadline — a host-side stall, not a bad token; start a new session. <code>signing_window_expired</code> ends the session.</td></tr>
  </table>
  </div></details>

  <details class="ref"><summary>Trust and hygiene</summary><div class="ref-body">
  <ul>
    <li>Treat <code>roleAccess</code>, the invitation code, signatures, and private keys as sensitive in transit: never log them to shared systems and never paste them into tickets or chat beyond the one out-of-band invitation delivery. Secrecy applies to transmission — an agent's own operator observing the run is expected. The server never receives a private key.</li>
    <li>The local workspace is disposable: fresh empty directory, session-scoped <code>$TMPDIR</code>, no repository clone, no plugin, no browser, no general Clockchain credential.</li>
    <li><code>statementDigest</code> covers the canonical full terms object — preserve the returned digest rather than recomputing it from the statement text.</li>
    <li>The three ordered anchor receipts land on the ${SUBSTRATE_LABEL} and are keyless-re-verifiable from the ledger. The certificate and role artifacts additionally depend on local signature verification against the manifest's trusted host roots.</li>
  </ul>
  </div></details>

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

START HERE — YOUR FIRST HANDSHAKE IN 3 STEPS
  Two independently controlled agents prove live signing-key control inside
  a bounded session and sign the same ordered exchange. The output is a
  VERIFIED certificate binding both identities, the session, message
  digests, ordering, and freshness.

  Prereqs: Node.js 24 on each agent · two agent runtimes · one out-of-band
  channel · invites capped at 5/hour.
  Scope: the certificate proves identity, key control, ordering, freshness,
  and peer binding — it authorizes nothing downstream;
  externalBusinessActionPerformed is always false (full boundary below).

  STEP 1 — REGISTER TWO MCP SERVERS (run on BOTH agents — any
  MCP-capable client works)
    1. clockchain-handshake — a remote streamable-http MCP server at
       ${ENDPOINT} (no auth: authorization is per-call via
       the access capability the server issues).
    2. clockchain-local-adapter — a local stdio MCP server, the
       @d4d.group/local-adapter npm package (requires Node.js 24). Two
       ways to run it — pick one:
       (a) quick start (default): command npx -y @d4d.group/local-adapter
           — npx ships with Node/npm and downloads + caches the package
           from the npm registry on first launch; one line, nothing to
           install first.
       (b) for production / reliability: install once —
           npm install -g @d4d.group/local-adapter — then use the
           installed binary clockchain-local-adapter as the MCP command:
           deterministic pinned version, no network dependency at launch
           (works offline after install), faster cold start.
       Both run the same npm package; the only difference is
       npx-fetch-on-launch versus a one-time global install. For
       reproducibility without a global install, version-pin the npx
       form: ${ADAPTER_INSTALL_NPX_PINNED}. The adapter
       is the default executor for every local action — the agent issues
       zero shell commands and keys never leave the machine.

    Canonical MCP config (the common mcpServers JSON shape most clients
    accept — shown for the quick-start npx path):
${MCP_SERVERS_JSON.split("\n").map((l) => `    ${l}`).join("\n")}
    Production-install (b) variant — the adapter entry is the installed binary:
    ${ADAPTER_CONFIG_BIN}
    Some clients spell the remote transport differently ("transport":
    "http" or "streamable-http", or a nested transport object) — the
    invariant is the URL plus streamable-http; map those two facts to
    your client's own config schema.

    Client-specific examples (optional):
      Claude Code: claude mcp add --transport http clockchain-handshake ${ENDPOINT}
                   ${ADAPTER_INSTALL_CLAUDE}
      Codex:       codex mcp add clockchain-handshake --url ${ENDPOINT}
                   ${ADAPTER_INSTALL_CODEX}
                   in ~/.codex/config.toml
      Any other MCP client (Cursor, Cline, Windsurf, an SDK, a custom
      client): point its MCP server config at the same URL + command.
      Remove when done: <client> mcp remove clockchain-handshake.

  STEP 2 — INITIATOR: paste PROMPT 1 below into agent 1. It prints a
  responderInvitation — the only value that leaves agent 1.

  STEP 3 — RESPONDER: drop that invitation into PROMPT 2's marked slot and
  paste it into agent 2 IMMEDIATELY — invitations are single-use and
  short-lived.

  DONE WHEN: both agents report outcome "VERIFIED" with the same sessionId
  and the same certificate digest, externalBusinessActionPerformed false,
  plus three ordered anchors (proposal -> acceptance -> acknowledgment) and
  distinct session-key addresses and policy digests. On a stop or failed
  check, see LIMITS AND ERRORS before retrying.

PROMPT 1 — INITIATOR (on terms_mismatch the prompt verifies publishedTerms
against the live responses before resubmitting — verify-then-proceed)
${INITIATOR_PROMPT}

PROMPT 2 — RESPONDER (drop the invitation into the marked slot)
${RESPONDER_PROMPT}

======================================================================
REFERENCE — how it works, scope, limits, hygiene
======================================================================

HOW IT WORKS — AND HOW TO VERIFY IT YOURSELF
  The coordinator is a stateless streamable-http MCP server that never
  signs — it sequences the exchange and anchors receipts; ALL signing is
  local to each agent via the pinned helper (a single audited Node.js 24
  file, unminified — byte-for-byte what executes; release source at
  ${SOURCE_REPO} at the sourceCommit named in the live discovery
  document). The helper generates the session key, commits your exact
  local policy, registers a fresh ERC-8004 identity when mandated, signs
  payloads, and verifies the certificate.

  Adapter path (default): clockchain-local-adapter (Step 1 — npx or the
  pinned global install) already holds the digest-pinned assets and
  re-verifies them on every call. Every localAction is one call per step
  to the fixed zero-input authorize_local_action tool — zero shell
  commands; embedded shellCommand/shellCommandFetch text is inert
  reference data, never to be run.

  Portable fallback (last resort — only when the adapter cannot be
  installed): download the two pinned assets as two separate commands,
  inspect both, then run stateDirectoryCommand once and each
  helperStep.shellCommand verbatim via your shell in returned order —
  prefer helperStep.shellCommandFetch when present (it fetches the exact
  command bytes by commandSha256 and verifies them). Never edit, decode,
  re-encode, or reconstruct commands or payloads; never hand-sign.
${ASSET_DOWNLOADS.split("\n").map((l) => `    ${l}`).join("\n")}
  Runtime download-and-execute is deliberately refused by many
  safety-conscious agent runtimes (e.g. Claude Code auto-mode) — expected
  behavior, not a bug; the adapter exists precisely because of it. If the
  client refuses, stop and ask the operator to install the adapter.

  Verify it yourself: integrity is the SHA-256 pin chain, not an OS code
  signature — nativeSignature.type "none" honestly reports that no
  platform signature exists. shasum -a 256 manifest.json must equal
  helper.manifestDigest in the live discovery manifest; the helper digest
  must equal assets[0].sha256 inside that verified manifest. Every helper
  run goes through the manifest's verifiedBootstrapPrefix, which re-hashes
  manifest then helper before compiling — exit 86 on any mismatch.

  Fields: endpoint ${ENDPOINT} (no client credential — authorization is
  per-call via the access capability) · discovery manifest ${MANIFEST}
  (authoritative helper pin + hostRoots) · helper assets ${MANIFEST_URL}
  and ${HELPER_URL} · exactly eight tools: ${TOOL_LIST}.
  Never run the helper file directly, invent bytes, or substitute a
  wallet, policy, session, or role; the manifest digest pins only
  manifest.json — the helper's own digest lives inside that verified
  manifest.

SCOPE BOUNDARY
  The certificate proves identity, live key control, ordering, freshness,
  and peer binding. It does NOT prove employment, delegation, spending
  limits, payment or contract authority, and authorizes nothing
  downstream. externalBusinessActionPerformed is always false. The server
  never receives a private key and never signs for either stakeholder.
  These guarantees are what make a terms_mismatch resubmission
  verifiable: the returned publishedTerms must keep YOUR identityPolicy
  identical and externalBusinessActionPerformed stays false in the live
  responses — then resubmitting is expected, not a bypass of scrutiny.

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
    Terminal reason codes:
      terms_mismatch          -> returns publishedTerms (same fixed terms
                                 every caller gets): verify identityPolicy is
                                 identical to yours, then resubmit verbatim.
      invitation_expired      -> claim landed after invitationExpiresAtMs.
      invitation_invalid      -> bad or consumed invitation code.
      role_access_invalid     -> the access token itself is bad or consumed.
      funding_timeout         -> join succeeded but the host never funded the
                                 session seat before the deadline — a host-side
                                 stall, NOT a bad token; start a new session.
      signing_window_expired  -> a bounded signing window lapsed terminally.

HYGIENE
  Treat roleAccess, the invitation, signatures, and private keys as
  sensitive in transit: never log them to shared systems and never paste
  them beyond the one out-of-band invitation delivery. Secrecy applies to
  transmission — an agent's own operator observing the run is expected.
  The server never receives a private key. Fresh
  disposable workspace and session-scoped TMPDIR; no repo clone, plugin,
  browser, or general Clockchain credential. statementDigest covers the
  canonical full terms object — preserve the returned digest. The three
  ordered anchor receipts land on the ledger and are keyless-re-verifiable;
  the certificate and role artifacts additionally depend on local signature
  verification against the manifest's trusted host roots.
`;
