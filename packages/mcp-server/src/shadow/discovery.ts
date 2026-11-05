// How an agent finds hosted Shadow: the section added to /llms.txt and /install.txt, the `shadow` block added to
// /.well-known/mcp.json, and the /shadow/connect page. All one set of facts, so the three cannot disagree.
//
// http.ts serves these only when a person can really use Shadow (SHADOW_ENABLED=1, it started, sign-in is on).
// Otherwise it serves landing.ts's INSTALL_TXT and MCP_MANIFEST, which this module never changes.
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

const KEPT_RECORD = "On this server, deleted 30 days after the session starts. Until then anyone with a viewer or packet link can read all of it, and links cannot be revoked.";
const KEPT_LEDGER = `Hashes only, on the ${SUBSTRATE_LABEL}. They stay after the record is deleted. Writes come from a shared testnet pool, so ledger entries show the pool's client and wallet, not yours.`;
const KEPT_ACCOUNT = "No email. A lost account key plus cleared cookies loses the account.";
const CHATGPT_NOTE = "Not yet confirmed in a real ChatGPT account. Some plans may block write tools.";
const CLAUDE_CODE_NOTE = "Not yet confirmed with a real Claude Code sign-up.";

/** The guide's lines. `base` has no trailing slash. */
function guideLines(base: string, chatPath: string | undefined): string[] {
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
    "An account is required. It is free, on testnet, and needs no email. The free",
    "key from the command below works on /mcp only. Shadow refuses it with 403",
    "account_required.",
    `  curl -X POST ${base}/token`,
    "",
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
export function connectInstructions(base: string, chatPath?: string): string {
  return ["Hosted Shadow: connect with sign-in", "", ...guideLines(base, chatPath), ""].join("\n");
}

/** The section /llms.txt and /install.txt carry when Shadow is on. Ends with a blank line. */
export function shadowInstallSection(base: string, chatPath?: string): string {
  const body = guideLines(base, chatPath).map((l) => (l ? `  ${l}` : ""));
  return [
    "SHADOW — a flight recorder for AI agents, on this same host:",
    ...body,
    `  This guide on its own: ${base}${CONNECT_PATH}`,
    "",
    "",
  ].join("\n");
}

/** /llms.txt and /install.txt with Shadow: INSTALL_TXT, byte for byte, with one section added. */
export function installTxtWithShadow(base: string, chatPath?: string): string {
  const at = INSTALL_TXT.indexOf(INSERT_BEFORE);
  const section = shadowInstallSection(base, chatPath);
  return at < 0 ? `${INSTALL_TXT}\n${section}` : `${INSTALL_TXT.slice(0, at)}${section}${INSTALL_TXT.slice(at)}`;
}

/** /.well-known/mcp.json with Shadow: MCP_MANIFEST, unchanged, with one `shadow` block added at the end. */
export function manifestWithShadow(base: string, chatPath?: string) {
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
        account: "Free Clockchain testnet account, no email. Created on the sign-in page; the account key is shown once.",
        freeKey: {
          obtain: `POST ${base}/token`,
          worksOn: `${base}/mcp`,
          onShadow: "refused with 403 account_required",
        },
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
    },
  };
}
