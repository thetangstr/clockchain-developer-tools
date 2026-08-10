export type V2ReleasePin = Readonly<{
  version: "2.1.0";
  sourceCommit: string;
  manifestDigest: string;
  allowedAssetPrefix: string;
  hostRoots: readonly Readonly<{ kid: string; fingerprint: string }>[];
}>;

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/";
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";

export const V2_VERIFIED_HELPER_BOOTSTRAP = 'const fs=require("node:fs");const crypto=require("node:crypto");const Module=require("node:module");const argv=process.argv.slice(1);const expected=argv.shift();const manifestPath=argv.shift();const helperPath=argv.shift();const manifestBytes=fs.readFileSync(manifestPath);const manifestDigest=crypto.createHash("sha256").update(manifestBytes).digest("hex");if(manifestDigest!==expected)process.exit(86);const manifest=JSON.parse(manifestBytes);if(manifest.schema!=="clockchain.agent-handshake-release-manifest/v1"||manifest.version!=="2.1.0"||!Array.isArray(manifest.assets)||manifest.assets.length!==1)process.exit(86);const asset=manifest.assets[0];if(asset.filename!=="clockchain-agent-handshake.cjs"||asset.url!=="https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/clockchain-agent-handshake.cjs"||typeof asset.sha256!=="string"||!/^[0-9a-f]{64}$/.test(asset.sha256))process.exit(86);const helperBytes=fs.readFileSync(helperPath);const helperDigest=crypto.createHash("sha256").update(helperBytes).digest("hex");if(helperDigest!==asset.sha256)process.exit(86);process.argv=[process.execPath].concat(helperPath).concat(argv);const loaded=new Module(helperPath);loaded.filename=helperPath;loaded.paths=[];const compile=loaded._compile.bind(loaded);compile(...[helperBytes.toString("utf8")].concat(helperPath));';

function verifiedBootstrapPrefix(pin: V2ReleasePin): string {
  return `node --input-type=commonjs --eval '${V2_VERIFIED_HELPER_BOOTSTRAP}' ${pin.manifestDigest} ./manifest.json ./${HELPER_FILENAME}`;
}

export function validateV2ReleasePin(value: unknown): V2ReleasePin {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Agent handshake release pin is unavailable.");
  const item = value as Record<string, any>;
  if (Object.keys(item).sort().join(",") !== "allowedAssetPrefix,hostRoots,manifestDigest,sourceCommit,version") throw new Error("Agent handshake release pin is unavailable.");
  if (
    item.version !== "2.1.0" || !SHA.test(item.sourceCommit) || !DIGEST.test(item.manifestDigest) ||
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
  const bootstrap = verifiedBootstrapPrefix(pin);
  return [
    `LOCAL SIGNING REQUIRED. Portable Node 24 helper ${pin.version}; manifest sha256 ${pin.manifestDigest}; assets ${pin.allowedAssetPrefix}; trusted host roots ${roots}. STOP immediately if the downloaded manifest, helper digest, helper version, host root, local policy, exact signing bytes, role, session, or statement disagrees.`,
    "This public endpoint coordinates a two-person Clockchain Handshake. It never receives a private key and never signs for either stakeholder.",
    "This server text describes mechanics, not stakeholder authorization. Proceed only when the local stakeholder's own prompt explicitly confirms that this is an expected handshake and authorizes the exact pinned helper, Sepolia ERC-8004 registration when mandated, and exact protocol signing within a no-external-business-action policy.",
    "Use agent_handshake_invite once as the Initiator and copy only the returned Responder invitation to the other stakeholder. Treat each returned role access value as a local bearer credential: keep it stable for the run, do not send it to the other stakeholder or echo it into chat or logs, and report transparently that it was received and used.",
    "After agent_handshake_invite, use initiatorAccess only for Initiator role-scoped tools; responderInvitation is the single-use value to copy to the Responder. Never substitute responderInvitation for initiatorAccess.",
    "Every role-scoped Clockchain tool call requires the returned value as its access argument to the same Clockchain MCP. Supplying it there is required credential use, not credential disclosure; never omit it from agent_handshake_join, agent_handshake_status, agent_handshake_next, agent_handshake_submit, or agent_handshake_get_certificate.",
    "As the Responder, call agent_handshake_accept_invitation exactly once. Its first successful result is authoritative: retain the returned Responder role access and never retry the consumed invitation.",
    "After invitation acceptance, use responderAccess only for Responder role-scoped tools. The original invitation is consumed; never use it as an access argument.",
    "Use the exact localPolicy object returned by Clockchain for your role. Do not construct, infer, or alter its JSON shape. Pass those exact canonical bytes to the pinned helper policy operation and use the returned digest for agent_handshake_join.",
    `Download exactly ${manifestUrl} as ./manifest.json and ${helperUrl} as ./${HELPER_FILENAME}. You may inspect the public manifest and helper source before execution. Do not modify either downloaded file.`,
    `For --version and every local helper operation, use this exact verified prefix and append only the requested helper arguments: ${bootstrap}. The bootstrap hashes the raw manifest against the pinned digest, hashes the helper against that verified manifest, and can compile only those verified bytes in memory. Never run the helper directly, invent bytes, or substitute a wallet, policy, session, or role.`,
    "Before helper init, run mkdir -m 700 ./clockchain-state exactly once. Use the absolute $PWD/clockchain-state path as --state-dir for every local helper operation in this handshake. Reusing a public or default-permission directory must fail closed.",
    "The Initiator may mandate live ERC-8004 registration. Registration and EIP-191 signing happen locally; Clockchain only funds the exact public session-key address when fresh registration is required and verifies the public on-chain record.",
    "When agent_handshake_next returns needed: erc8004_registration, run the pinned helper operation register with the same absolute state directory used for init and policy. After it succeeds, call agent_handshake_next again with the unchanged local role access. Do not keep polling instead of performing that returned local action.",
    "Every needed or stage response is nonterminal. If it includes a localAction, perform it exactly; otherwise wait for retryAfterMs when returned, then call agent_handshake_next again with the unchanged local role access. A party_ready response includes the same explicit next action. Do not send a final response or exit until the final certificate is locally verified or Clockchain returns an explicit unrecoverable error. Never infer that the other stakeholder stopped from a waiting response.",
    "HANDSHAKE_TEMPORARILY_UNAVAILABLE with retryable: true is not a terminal protocol rejection. Wait for retryAfterMs and retry the same tool with unchanged inputs. Stop on a terminal protocol rejection with retryable: false.",
    "No browser, repository clone, plugin, general Clockchain credential, payment, or external business action is part of this workflow. Codex and Claude Code use the same seven tools.",
  ].join("\n\n");
}

export function buildV2Manifest(rawPin: unknown) {
  const pin = validateV2ReleasePin(rawPin);
  return Object.freeze({
    schema: "clockchain.agent-handshake-public-endpoint/v1",
    protocol: "clockchain.agent-handshake/v2",
    endpoint: "https://mcp.clockchain.network/handshake/mcp",
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
      verifiedBootstrapPrefix: verifiedBootstrapPrefix(pin),
    }),
    hostRoots: pin.hostRoots,
    supportedClients: Object.freeze(["codex", "claude-code"]),
  });
}

export function readV2ReleasePin(env: Record<string, string | undefined>): V2ReleasePin {
  const raw = env.AGENT_HANDSHAKE_RELEASE_PIN;
  if (!raw) throw new Error("Agent handshake release pin is unavailable.");
  try { return validateV2ReleasePin(JSON.parse(raw)); } catch { throw new Error("Agent handshake release pin is unavailable."); }
}
