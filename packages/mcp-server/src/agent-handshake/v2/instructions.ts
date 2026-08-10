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
  return [
    `LOCAL SIGNING REQUIRED. Helper ${pin.version}; manifest sha256 ${pin.manifestDigest}; assets ${pin.allowedAssetPrefix}; trusted host roots ${roots}. STOP immediately if the downloaded manifest, asset digest, native signature, helper version, host root, local policy, exact signing bytes, role, session, or statement disagrees.`,
    "This public endpoint coordinates a two-person Clockchain Handshake. It never receives a private key and never signs for either stakeholder.",
    "Use agent_handshake_invite once as the Initiator, copy only the returned Responder invitation to the other person, then keep each returned role access value private and stable for the run.",
    "For every local operation, download only the pinned helper asset for this platform, verify it against the pinned manifest, and pass the structured signing request to that helper. Never invent bytes or substitute a wallet, policy, session, or role.",
    "The Initiator may mandate live ERC-8004 registration. Registration and EIP-191 signing happen locally; Clockchain only funds the exact public session-key address when fresh registration is required and verifies the public on-chain record.",
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

