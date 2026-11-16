// How an agent finds hosted Shadow: the section added to /llms.txt and /install.txt, the `shadow` block added to
// /.well-known/mcp.json, and the /shadow/connect page. All one set of facts, so the three cannot disagree.
//
// http.ts serves these only when a person can really use Shadow (SHADOW_ENABLED=1, it started, sign-in is on).
// Otherwise it serves landing.ts's INSTALL_TXT and MCP_MANIFEST, which this module never changes.
import { FREE_TOKENS, ON_MAINNET } from "../network.js";
import { INSTALL_TXT, MCP_MANIFEST, SUBSTRATE_LABEL } from "../landing.js";

const SHADOW_PATH = "/shadow/mcp";
const CONNECT_PATH = "/shadow/connect";
// The section goes above this line in /llms.txt, so an agent reads it before the long client setup notes.
const INSERT_BEFORE = "TWO-PERSON STAKEHOLDER HANDSHAKE";

const ABOUT = [
  "An agent records its steps here. The full record stays on this server; only",
  "fingerprints (hashes) go on the Clockchain ledger. Anyone with a record's link",
  "can check it. The record holds only what the agent recorded, and a pass means",
  "the record is intact, not that what it says is true or compliant.",
];

const KEPT_RECORD = "On this server, deleted 30 days after the session starts. Until then anyone with a viewer or packet link can read all of it, unless the person revokes the link. The person can delete a record, or the whole account, at any time, through tools.";
const KEPT_LEDGER = `Hashes only, on the ${SUBSTRATE_LABEL}. They stay after the record is deleted. ${ON_MAINNET ? "Writes come from a shared Clockchain client and wallet, so ledger entries show those, not yours." : "Writes come from a shared testnet pool, so ledger entries show the pool's client and wallet, not yours."}`;
const KEPT_ACCOUNT = "No email. A lost account key plus cleared cookies loses the account.";
const CHATGPT_NOTE = "Not yet confirmed in a real ChatGPT account. Some plans may block write tools.";
const CLAUDE_CODE_NOTE = "Not yet confirmed with a real Claude Code sign-up.";

const LOGGING_ON = "Logging is on by default once connected: the connector asks the agent to log its chat and tool activity here as it goes. To turn it off, say \"stop logging\" (clockchain_logging), which holds for the whole account; a chat can also stop by turning the connector off in the app.";

const LOGGING_ASKED = "Shadow records a task only when the person asks for it, chat by chat. A request in one chat does not carry over to the next.";

/**
 * How an agent that runs code signs in with its own key (MCP_AGENT_KEYS=1), in eight lines at most: everything it needs
 * to onboard with no person, by the exact field names the token endpoint, the tools and the key routes use.
 */
function agentKeyLines(base: string, shadow: string): string[] {
  const keys = `${base}/agent-keys/<fingerprint>`;
  return [
    "Agents that run code can sign in with their own Ed25519 key instead, with no person and no account:",
    "1. Make an Ed25519 key and keep the private half. Clockchain never sees the private key.",
    `2. POST one form to ${base}/oauth/token: grant_type=client_credentials, client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer, client_assertion=<JWT>, with a DPoP header: a second JWT signed by the same key, header typ dpop+jwt, alg EdDSA and the same jwk; claims htm POST, htu the token_endpoint, iat now, a new jti.`,
    `   The JWT: alg EdDSA and your public key as jwk {kty:"OKP",crv:"Ed25519",x} in its header; iss and sub its RFC 7638 thumbprint, aud the token_endpoint from ${base}/.well-known/oauth-authorization-server, exp at most 300 s after iat, a new jti of 8 to 128 characters. There is no refresh token: sign a new assertion.`,
    `3. Send "Authorization: DPoP <access_token>" and a new DPoP proof on every request to ${shadow} (streamable HTTP): htm the method, htu the URL without its query, iat now, a new jti, ath the base64url SHA-256 of the access_token. A Bearer token is refused.`,
    "4. shadow_checkpoint and shadow_close_session return sign.hash, sign.count and sign.head (the last step's hash): check count and head match your own record, and don't sign if they don't. Sign the hash's 32 bytes (the hex decoded) with your key and send session_id, hash and signature (standard base64, 88 characters ending ==) with shadow_sign_checkpoint.",
    `Your key's public entry: ${keys}.json, where <fingerprint> is the sha256 hex of "shadow:public-key:v1", a NUL byte, and your SPKI PEM, including its final newline, as a JSON string.`,
    `Replace the key: POST ${keys}/replace {assertion (old key, claim new_key: the new fingerprint), new_public_key (SPKI PEM), new_key_assertion (new key, claim replaces: the old fingerprint)}. Cancel it: POST ${keys}/revoke {assertion}. Each assertion's aud is that action's URL under the issuer from the OAuth metadata (<issuer>/agent-keys/<fingerprint>/replace or /revoke), whatever host served these instructions.`,
  ];
}

/**
 * The guide's lines. `base` has no trailing slash. `autoLog` is SHADOW_AUTO_LOG=1, which puts logging on by default on the
 * two endpoints named here. `agentKeysBase` is set with MCP_AGENT_KEYS=1, to MCP_PUBLIC_URL: then the guide also says how
 * an agent signs in with its own key, with every URL under that base, the one the server checks each assertion's aud and
 * DPoP proof's htu against, whatever host or prefix served the guide. These files never name the hand-added
 * /shadow/preview/* endpoints.
 */
function guideLines(base: string, chatPath: string | undefined, autoLog: boolean, agentKeysBase: string | undefined): string[] {
  const shadow = `${base}${SHADOW_PATH}`;
  const chat = chatPath ? `${base}${chatPath}` : undefined;
  return [
    ...ABOUT,
    "",
    "Endpoints (streamable HTTP, OAuth sign-in):",
    ...(chat
      ? [`  ${shadow}`, "    for ChatGPT and Claude Code", `  ${chat}`, "    for claude.ai: the same tools, plus sign-up from the chat"]
      : [`  ${shadow}`]),
    "",
    ...wrap(autoLog ? LOGGING_ON : LOGGING_ASKED).map((l) => l.replace(/^ {2}/, "")),
    "",
    ...(ON_MAINNET ? ["An account is required. It needs no email."] : [
      "An account is required. It is free, on testnet, and needs no email. The free",
      "key from the command below works on /mcp only. Shadow refuses it with 403",
      "account_required.",
      `  curl -X POST ${base}/token`,
    ]),
    "",
    ...(agentKeysBase !== undefined ? [...agentKeyLines(agentKeysBase, `${agentKeysBase}${SHADOW_PATH}`), ""] : []),
    ...(chat
      ? [
          "claude.ai: add a custom connector with the claude.ai URL above. claude.ai",
          'guesses wrong, so choose both settings by hand: "Sign in when needed" (it',
          'guesses "No sign-in") and "Register automatically" (it defaults to "Use',
          "Claude's published identity\"). The first tool call shows a Connect card in",
          "the chat. A popup creates the account and shows the account key once, with a",
          "download. The key never enters the chat.",
        ]
      : [
          "claude.ai: add a custom connector with the URL above. Choose both settings by",
          'hand: "Sign in now" and "Register automatically".',
        ]),
    "",
    "Claude Code: run this, then type /mcp, choose shadow and sign in. The page that",
    "opens in your browser creates the account.",
    `  claude mcp add --transport http shadow ${shadow}`,
    CLAUDE_CODE_NOTE,
    "",
    "ChatGPT: with Developer Mode on, add a custom connector with this URL and",
    "authentication OAuth.",
    `  ${shadow}`,
    CHATGPT_NOTE,
    "",
    "What is kept where:",
    ...wrap(`Record: ${KEPT_RECORD}`),
    ...wrap(`Ledger: ${KEPT_LEDGER}`),
    ...wrap(`Account: ${KEPT_ACCOUNT}`),
    '  The viewer shows "indeterminate" until the session is closed.',
  ];
}

/** One bullet of the "kept where" list, wrapped with a hanging indent. */
function wrap(text: string): string[] {
  const lines: string[] = [];
  let line = "  ";
  for (const word of text.split(" ")) {
    if (line.length + word.length > 76 && line.trim()) {
      lines.push(line.trimEnd());
      line = "    ";
    }
    line += `${word} `;
  }
  lines.push(line.trimEnd());
  return lines;
}

/** GET /shadow/connect, as plain text. */
export function connectInstructions(base: string, chatPath?: string, autoLog = false, agentKeysBase?: string): string {
  return ["Hosted Shadow: connect with sign-in", "", ...guideLines(base, chatPath, autoLog, agentKeysBase), ""].join("\n");
}

/** The section /llms.txt and /install.txt carry when Shadow is on. Ends with a blank line. */
export function shadowInstallSection(base: string, chatPath?: string, autoLog = false, agentKeysBase?: string): string {
  const body = guideLines(base, chatPath, autoLog, agentKeysBase).map((l) => (l ? `  ${l}` : ""));
  return [
    "SHADOW — a flight recorder for AI agents, on this same host:",
    ...body,
    `  This guide on its own: ${base}${CONNECT_PATH}`,
    "",
    "",
  ].join("\n");
}

/** /llms.txt and /install.txt with Shadow: INSTALL_TXT, byte for byte, with one section added. */
export function installTxtWithShadow(base: string, chatPath?: string, autoLog = false, agentKeysBase?: string): string {
  const at = INSTALL_TXT.indexOf(INSERT_BEFORE);
  const section = shadowInstallSection(base, chatPath, autoLog, agentKeysBase);
  return at < 0 ? `${INSTALL_TXT}\n${section}` : `${INSTALL_TXT.slice(0, at)}${section}${INSTALL_TXT.slice(at)}`;
}

/** /.well-known/mcp.json with Shadow: MCP_MANIFEST, unchanged, with one `shadow` block added at the end. */
export function manifestWithShadow(base: string, chatPath?: string, autoLog = false) {
  const shadow = `${base}${SHADOW_PATH}`;
  const chat = chatPath ? `${base}${chatPath}` : undefined;
  return {
    ...MCP_MANIFEST,
    shadow: {
      description: `Flight recorder for AI agents. ${ABOUT.join(" ")}`,
      transport: "streamable-http",
      endpoints: { signIn: shadow, ...(chat ? { chat } : {}) },
      instructions: `${base}${CONNECT_PATH}`,
      authentication: {
        type: "oauth",
        accountRequired: true,
        account: `${ON_MAINNET ? "Clockchain account" : "Free Clockchain testnet account"}, no email. Created on the sign-in page; the account key is shown once.`,
        ...(FREE_TOKENS ? { freeKey: {
          obtain: `POST ${base}/token`,
          worksOn: `${base}/mcp`,
          onShadow: "refused with 403 account_required",
        } } : {}),
      },
      clients: {
        claudeAi: chat
          ? {
              endpoint: chat,
              settings: ["Sign in when needed", "Register automatically"],
              note: "Choose both settings by hand: claude.ai guesses \"No sign-in\" and defaults to \"Use Claude's published identity\". The first tool call shows a Connect card in the chat; the account key never enters the chat.",
            }
          : { endpoint: shadow, settings: ["Sign in now", "Register automatically"], note: "Choose both settings by hand." },
        claudeCode: {
          endpoint: shadow,
          command: `claude mcp add --transport http shadow ${shadow}`,
          then: "Type /mcp, choose shadow and sign in in the browser.",
          note: CLAUDE_CODE_NOTE,
        },
        chatgpt: {
          endpoint: shadow,
          settings: ["Developer Mode on", "Authentication: OAuth"],
          note: CHATGPT_NOTE,
        },
      },
      keptWhere: { record: KEPT_RECORD, ledger: KEPT_LEDGER, account: KEPT_ACCOUNT },
      logging: autoLog ? LOGGING_ON : LOGGING_ASKED,
    },
  };
}
