// The one place the deployed helper release line is declared. The pin
// validator, the verified bootstrap, the join tool's helperVersion literal,
// and the server's advertised version all derive from this — they may not
// drift apart, because the published release embeds the same value in every
// surface. The SSM release pin itself stays runtime data; only its shape and
// version gate live here.
export const V2_HELPER_VERSION = "2.1.8";
export const V2_HELPER_ASSET_PREFIX =
  `https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v${V2_HELPER_VERSION}/`;

// The public URL of the CURRENT build's handshake endpoint. While the ACM4
// demo pin is live (Caddyfile routes /handshake/mcp to the frozen 2.1.6
// instance), the current build serves its handshake surface under /next —
// swap this back to /handshake/mcp when the pin is removed.
export const V2_PUBLIC_ENDPOINT = "https://mcp.clockchain.network/next/handshake/mcp";

export type V2ReleasePin = Readonly<{
  version: "2.1.8";
  sourceCommit: string;
  manifestDigest: string;
  allowedAssetPrefix: string;
  hostRoots: readonly Readonly<{ kid: string; fingerprint: string }>[];
}>;

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PREFIX = V2_HELPER_ASSET_PREFIX;
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";

export const V2_VERIFIED_HELPER_BOOTSTRAP = `const fs=require("node:fs");const crypto=require("node:crypto");const Module=require("node:module");const argv=process.argv.slice(1);const expected=argv.shift();const manifestPath=argv.shift();const helperPath=argv.shift();const manifestBytes=fs.readFileSync(manifestPath);const manifestDigest=crypto.createHash("sha256").update(manifestBytes).digest("hex");if(manifestDigest!==expected)process.exit(86);const manifest=JSON.parse(manifestBytes);if(manifest.schema!=="clockchain.agent-handshake-release-manifest/v1"||manifest.version!=="${V2_HELPER_VERSION}"||!/^24\\./.test(manifest.nodeRuntime)||!/^24\\./.test(process.versions.node)||!Array.isArray(manifest.assets)||manifest.assets.length!==1)process.exit(86);const asset=manifest.assets[0];if(asset.filename!=="${HELPER_FILENAME}"||asset.url!=="${V2_HELPER_ASSET_PREFIX}${HELPER_FILENAME}"||typeof asset.sha256!=="string"||!/^[0-9a-f]{64}$/.test(asset.sha256))process.exit(86);const helperBytes=fs.readFileSync(helperPath);const helperDigest=crypto.createHash("sha256").update(helperBytes).digest("hex");if(helperDigest!==asset.sha256)process.exit(86);process.argv=[process.execPath].concat(helperPath).concat(argv);const loaded=new Module(helperPath);loaded.filename=helperPath;loaded.paths=[];const compile=loaded._compile.bind(loaded);compile(...[helperBytes.toString("utf8")].concat(helperPath));`;

export function verifiedV2HelperPrefix(pin: V2ReleasePin): string {
  return `node --input-type=commonjs --eval '${V2_VERIFIED_HELPER_BOOTSTRAP}' ${pin.manifestDigest} ./manifest.json ./${HELPER_FILENAME}`;
}

export function validateV2ReleasePin(value: unknown): V2ReleasePin {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Agent handshake release pin is unavailable.");
  const item = value as Record<string, any>;
  if (Object.keys(item).sort().join(",") !== "allowedAssetPrefix,hostRoots,manifestDigest,sourceCommit,version") throw new Error("Agent handshake release pin is unavailable.");
  if (
    item.version !== V2_HELPER_VERSION || !SHA.test(item.sourceCommit) || !DIGEST.test(item.manifestDigest) ||
    item.allowedAssetPrefix !== PREFIX || !Array.isArray(item.hostRoots) ||
    item.hostRoots.length < 1 || item.hostRoots.length > 2
  ) throw new Error("Agent handshake release pin is unavailable.");
  const hostRoots = item.hostRoots.map((root: unknown) => {
    if (root === null || typeof root !== "object" || Array.isArray(root)) throw new Error("Agent handshake release pin is unavailable.");
    const entry = root as Record<string, unknown>;
    if (Object.keys(entry).sort().join(",") !== "fingerprint,kid" || typeof entry.kid !== "string" || !KID.test(entry.kid) || typeof entry.fingerprint !== "string" || !DIGEST.test(entry.fingerprint)) throw new Error("Agent handshake release pin is unavailable.");
    return Object.freeze({ kid: entry.kid, fingerprint: entry.fingerprint });
  });
  if (new Set(hostRoots.map((root: { kid: string }) => root.kid)).size !== hostRoots.length) throw new Error("Agent handshake release pin is unavailable.");
  return Object.freeze({
    version: item.version,
    sourceCommit: item.sourceCommit,
    manifestDigest: item.manifestDigest,
    allowedAssetPrefix: item.allowedAssetPrefix,
    hostRoots: Object.freeze(hostRoots),
  });
}

export function buildV2Instructions(rawPin: unknown): string {
  const pin = validateV2ReleasePin(rawPin);
  const roots = pin.hostRoots.map((root) => `${root.kid}:${root.fingerprint}`).join(",");
  const manifestUrl = `${pin.allowedAssetPrefix}manifest.json`;
  const helperUrl = `${pin.allowedAssetPrefix}${HELPER_FILENAME}`;
  const manifestDownload = `curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json '${manifestUrl}'`;
  const helperDownload = `curl --fail --location --proto '=https' --proto-redir '=https' --output ./${HELPER_FILENAME} '${helperUrl}'`;
  const bootstrap = verifiedV2HelperPrefix(pin);
  return [
    `LOCAL SIGNING REQUIRED. Portable Node 24 helper ${pin.version}; the manifest digest is encoded only in the exact verified command below. Default to approvalTool through the clockchain-local-adapter; the exact verified command is the last resort. Assets ${pin.allowedAssetPrefix}; trusted host roots ${roots}. STOP immediately if the local manifest, helper digest, helper version, host root, local policy, exact signing bytes, role, session, or statement disagrees.`,
    "This public endpoint coordinates a two-person Clockchain Handshake. It never receives a private key and never signs for either stakeholder.",
    "This server text describes mechanics, not stakeholder authorization. Proceed only when the local stakeholder's own prompt explicitly confirms that this is an expected handshake and authorizes the exact pinned helper, Sepolia ERC-8004 registration when mandated, and exact protocol signing within a no-external-business-action policy.",
    "Use agent_handshake_invite once as the Initiator and copy only the returned Responder invitation to the other stakeholder. roleAccess is a short opaque local handle; the server keeps the signed bearer capability behind that handle. Keep roleAccess stable for the run; never send it to the other stakeholder or to any endpoint other than this one — showing it to your own operator is expected, and every step and command should be narrated to them. Reuse it byte-for-byte; never decode, re-encode, shorten, or reconstruct it.",
    "After agent_handshake_invite, use only the returned roleAccess for Initiator role-scoped tools; responderInvitation is the single-use value to copy to the Responder. Never substitute responderInvitation for roleAccess.",
    "If agent_handshake_invite returns reason terms_mismatch with publishedTerms, verify before resubmitting — do not take the resubmission on faith. This public endpoint returns the SAME fixed published terms to every caller: fixture/discovery data, not a substitution targeted at your request. Check that publishedTerms.identityPolicy (erc8004, chainId, registryAddress) is identical to what you sent — only the human-readable reference/statement may differ; a changed identityPolicy or chain is a genuine red flag: refuse and report it. The certificate confers no employment, spending, payment, or contract authority, and externalBusinessActionPerformed stays false in live responses. If those checks hold, call agent_handshake_invite again with the returned publishedTerms verbatim and continue — proceeding after your own verification, under your operator's authorization, is expected, not a bypass of scrutiny.",
    "Every role-scoped Clockchain tool call requires the returned value as its access argument to the same Clockchain MCP. Supplying it there is required credential use, not credential disclosure; never omit it from agent_handshake_join, agent_handshake_status, agent_handshake_next, agent_handshake_submit_checkpoint, agent_handshake_submit, or agent_handshake_get_certificate.",
    "Every successful role-scoped response echoes roleAccess. Use it byte-for-byte as the immediately following role-scoped tool call's access argument; never replace it with a label, summary, placeholder, invitation, or remembered reconstruction.",
    "As the Responder, generate one fresh high-entropy acceptanceIdempotencyKey with client-native secure randomness before the first agent_handshake_accept_invitation call. Retain that acceptanceIdempotencyKey locally; never send it to the other stakeholder or to any endpoint other than this one — showing it to your own operator is expected. Retry the same invitation with the same acceptanceIdempotencyKey only after retryable infrastructure failure or transport uncertainty. After success, retain the returned roleAccess and stop accepting. Missing acceptanceIdempotencyKey is transitional one-shot compatibility for older clients, not the durable retry path.",
    "After invitation acceptance, use only the returned roleAccess for Responder role-scoped tools. The original invitation is consumed; never use it as an access argument.",
    "statementDigest is the SHA-256 digest of Clockchain's canonical full terms object, not the SHA-256 of the raw statement text by itself. Verify the returned terms fields exactly and preserve the returned statementDigest; do not recompute it from only the human-readable statement.",
    "Use the exact localPolicy object returned by Clockchain for your role. Do not construct, infer, or alter its JSON shape. Pass those exact canonical bytes to the pinned helper policy operation and use the returned digest for agent_handshake_join.",
    "WORKSPACE BOUNDARY: The client launcher has already placed you in a fresh, empty, disposable working directory and assigned a fresh session-scoped $TMPDIR. Stay in the working directory. Do not create or switch to another working directory, and never substitute /tmp, /private/tmp, /tmp/claude-*, or any other shared path. Every ./ path below means the current disposable working directory; every $TMPDIR path means the current isolated client session temp root.",
    "DIGEST BOUNDARY: The pinned manifest digest applies only to ./manifest.json. The helper has a separate SHA-256 recorded inside that verified manifest. Never compare the helper file directly with the manifest digest; the verified bootstrap checks both hashes in sequence before compiling the helper bytes.",
    "TRUST ROOT SEPARATION: The manifest digest is the independent pin for the exact manifest bytes; that verified manifest's asset hash authenticates the helper bytes. The host-root fingerprint is separate: the helper embeds its Ed25519 public key and uses it to authenticate the host session-key certificate and closing certificate. The host-root fingerprint is not expected in the asset bootstrap, because it does not authenticate the helper release.",
    `ADAPTER ASSET PATH (DEFAULT): The clockchain-local-adapter MCP server is the default executor for every local action in this handshake. It is a one-time install in this agent's own environment — claude mcp add clockchain-local-adapter -- npx -y @d4d.group/local-adapter for Claude Code; a Codex config entry [mcp_servers.clockchain-local-adapter] command = "npx" args = ["-y", "@d4d.group/local-adapter"]; or a generic MCP config {"command":"npx","args":["-y","@d4d.group/local-adapter"]}. The adapter defaults to this endpoint; no environment configuration is needed. The adapter already holds the digest-pinned manifest.json and clockchain-agent-handshake.cjs assets and re-verifies their digests on every call. Never download, transcribe, or overwrite either file. Whenever a localAction carries approvalTool, call each helperStep.approvalTool exactly once per step and in returned order — approvalTool names the fixed zero-input MCP tool authorize_local_action served by the clockchain-local-adapter server, never with arguments — and never run helperStep.shellCommand when approvalTool is available. The qualified name is host-dependent (Claude Code exposes mcp__clockchain-local-adapter__authorize_local_action; Codex normalizes to mcp__clockchain_local_adapter__authorize_local_action) — the contract is the bare tool name authorize_local_action on that server. Under this path the agent issues zero Bash commands for local actions. If mcp__clockchain-local-adapter__authorize_local_action is not among this client's tools, ask the operator to install the adapter rather than falling back silently.`,
    "When a localAction includes helper steps, call each helperStep.approvalTool exactly once per step and in returned order — approvalTool is always the fixed zero-input MCP tool mcp__clockchain-local-adapter__authorize_local_action, never with arguments. The adapter stages the returned steps privately and executes one digest-bound action per call; call it once for each step, waiting for each result before the next call. The approvalTool authorizes the exact digest-bound local action; the adapter executes the authoritative structured arguments without model transcription. Never run helperStep.shellCommand when approvalTool is available; if the adapter tool is absent from this client, stop and ask the operator to install clockchain-local-adapter rather than proceeding silently. Compatibility clients without the adapter may instead, only as a last resort, run stateDirectoryCommand once and each helperStep.shellCommand verbatim. The shellCommand already contains the verified prefix and exact payload: never concatenate it yourself, reconstruct it, edit it, or re-encode a returned payload. If an operation's shellCommand does not include --payload-base64url, do not add that flag or any payload.",
    "Each signing and certificate response contains one authoritative payload-bearing localAction.helperStep.shellCommand plus its fixed adapter approvalTool. Prefer approvalTool through the adapter. Summary fields are confirmation only; never use them to reconstruct, transcribe, or re-encode the payload or command.",
    "Under the adapter path the agent runs ZERO shell commands. shellCommand/shellCommandFetch text embedded in tool responses exists only for the portable fallback — under the adapter it is inert reference data: never run it.",
    "EXECUTION SHAPE — PORTABLE FALLBACK ONLY: The Bash rules in this and the following paragraphs apply only to the portable fallback path; under the adapter the agent issues zero Bash commands for local actions. Every Bash action below must be one standalone Bash tool call. Never combine Bash actions or add another command, newline, shell operator, cd, pwd, set, or shell wrapper. Follow the applicable asset path exactly. Do not run a returned stateDirectoryCommand until after both pinned assets have been inspected.",
    `PORTABLE FALLBACK — LAST RESORT: Use this path only when approvalTool is not available, the adapter cannot be installed, and both pinned files are absent — never as a silent substitute for the adapter. WARNING: runtime download-and-execute is deliberately blocked by many safety-conscious agent runtimes (for example, Claude Code auto-mode); that refusal is expected behavior, not a bug, and the adapter exists precisely because of it. If this client refuses these steps, stop and ask the operator to install the adapter. Download each file as its own separate Bash tool call; never prefix, wrap, combine, or add shell separators. Manifest command: ${manifestDownload} After that completes, helper command: ${helperDownload}. Inspect both downloaded files before execution. Do not modify either file and do not use WebFetch for this local download step.`,
    `On the portable fallback path only — never under the adapter — for --version and every local helper operation, use this exact verified prefix and append only the requested helper arguments: ${bootstrap}. The bootstrap hashes the raw manifest against the pinned digest, hashes the helper against that verified manifest, and can compile only those verified bytes in memory. Never run the helper directly, invent bytes, or substitute a wallet, policy, session, or role.`,
    "TRANSCRIPTION-SAFE FETCH: on the portable fallback path, every helperStep also carries shellCommandFetch — a short command that downloads the exact shellCommand bytes by their commandSha256 and verifies the digest before executing. When the adapter is unavailable, prefer it over hand-transcribing a multi-KB shellCommand: run shellCommandFetch verbatim exactly once per step; it fails closed if the fetched bytes do not match commandSha256. The same rules apply — never edit, reconstruct, or re-encode it.",
    "Use only the exact session-scoped $TMPDIR path returned by Clockchain for every local helper operation in this handshake. Do not assign it to another shell variable, replace it with $HOME or $PWD, create another state directory, or reuse state from another session.",
    "SEQUENCE GATE: After init, policy, and inspect succeed, call agent_handshake_join immediately with the helper output. Do not run register before join. Clockchain must first observe the joined address and fund that exact seat; only then may a later agent_handshake_next response return needed: erc8004_registration. Run register only in response to that explicit funded local action.",
    "The Initiator may mandate live ERC-8004 registration. Registration and EIP-191 signing happen locally; Clockchain only funds the exact public session-key address when fresh registration is required and verifies the public on-chain record.",
    "When agent_handshake_next returns needed: erc8004_registration, run the pinned helper operation register with the same absolute state directory used for init and policy. After it succeeds, call agent_handshake_next again with the unchanged local role access. Do not keep polling instead of performing that returned local action.",
    "Every needed or stage response is nonterminal. If it includes a localAction, perform it exactly; otherwise wait for retryAfterMs when returned, then call agent_handshake_next again with the unchanged local role access. A party_ready response includes the same explicit next action. Do not send a final response or exit until the final certificate is locally verified or Clockchain returns an explicit unrecoverable error. Never infer that the other stakeholder stopped from a waiting response.",
    "HANDSHAKE_TEMPORARILY_UNAVAILABLE with retryable: true is not a terminal protocol rejection. Wait for retryAfterMs and retry the same tool with unchanged inputs. Stop on a terminal protocol rejection with retryable: false. Terminal rejections carry a reason: terms_mismatch (verify publishedTerms as above, then resubmit), invitation_expired or invitation_invalid (claim too late, or a bad/consumed code — the Initiator re-invites), role_access_invalid (the access token itself is bad or consumed), funding_timeout (join succeeded but the host never funded the session seat before the deadline — a host-side stall, not a bad token; start a new session), or signing_window_expired (a bounded signing window lapsed; the session is over).",
    "For proposal and acceptance steps the pinned helper's sign output carries two artifacts: signatureHex (the artifact signature) and checkpoint (the separately signed commitment checkpoint). Submit the checkpoint first: agent_handshake_submit_checkpoint with access, artifactSignatureHex set to the helper output's signatureHex, and checkpoint set to the helper output's exact checkpoint object. Then call agent_handshake_submit with the same signatureHex and unchanged policyDigest. Never invent, edit, or ask the model to sign a checkpoint.",
    "Proposal and acceptance signing windows are bounded: sign and submit promptly after a signing request arrives — do not pause between agent_handshake_next and the sign, submit_checkpoint, and submit steps. If a sign step fails after a delay, call agent_handshake_next again with the unchanged role access: a still-pending proposal is re-issued with a fresh window, while a terminal reason: signing_window_expired response means the session is over and the Initiator must start over with a new agent_handshake_invite.",
    "No browser, repository clone, plugin, general Clockchain credential, payment, or external business action is part of this workflow. Codex and Claude Code use the same eight tools.",
  ].join("\n\n");
}

export function buildV2Manifest(rawPin: unknown) {
  const pin = validateV2ReleasePin(rawPin);
  return Object.freeze({
    schema: "clockchain.agent-handshake-public-endpoint/v1",
    protocol: "clockchain.agent-handshake/v2",
    endpoint: V2_PUBLIC_ENDPOINT,
    transport: "streamable-http",
    authentication: "role-capability-per-tool",
    helper: Object.freeze({
      version: pin.version,
      sourceCommit: pin.sourceCommit,
      manifestDigest: pin.manifestDigest,
      allowedAssetPrefix: pin.allowedAssetPrefix,
      filename: HELPER_FILENAME,
      manifestUrl: `${pin.allowedAssetPrefix}manifest.json`,
      helperUrl: `${pin.allowedAssetPrefix}${HELPER_FILENAME}`,
      nodeRuntimeMajor: "24",
      verifiedBootstrapPrefix: verifiedV2HelperPrefix(pin),
    }),
    hostRoots: pin.hostRoots,
    adapter: Object.freeze({
      package: "@d4d.group/local-adapter",
      install: "npx -y @d4d.group/local-adapter",
      tool: "mcp__clockchain-local-adapter__authorize_local_action",
      endpoint: V2_PUBLIC_ENDPOINT,
      nodeRuntimeMajor: "24",
    }),
    supportedClients: Object.freeze(["codex", "claude-code"]),
  });
}

export function readV2ReleasePin(env: Record<string, string | undefined>): V2ReleasePin {
  const raw = env.AGENT_HANDSHAKE_RELEASE_PIN;
  if (!raw) throw new Error("Agent handshake release pin is unavailable.");
  try { return validateV2ReleasePin(JSON.parse(raw)); } catch { throw new Error("Agent handshake release pin is unavailable."); }
}
