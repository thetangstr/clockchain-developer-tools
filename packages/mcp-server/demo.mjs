// Clockchain MCP - live demo.
//
// Drives the built stdio MCP server end to end as a real MCP client and narrates
// each step: read consensus time -> notarize a hash -> wait for on-chain
// confirmation -> verify (match) -> tamper-detect (no match). Finishes by
// printing the snippet to register this server with an agent runtime.
//
// Run (from packages/mcp-server):
//   npm run build
//   CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=you@example.com \
//   CLOCKCHAIN_WALLET_ID=you@example.com npm run demo
//
// The API key is read from the environment and never written to disk.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createHash } from "node:crypto";

const line = (s = "") => console.log(s);
const hr = () => line("-".repeat(64));

function need(name) {
  if (!process.env[name]) {
    console.error(`Missing env ${name}. Set CLOCKCHAIN_API_KEY/CLIENT_ID/WALLET_ID.`);
    process.exit(1);
  }
}
["CLOCKCHAIN_API_KEY", "CLOCKCHAIN_CLIENT_ID", "CLOCKCHAIN_WALLET_ID"].forEach(need);

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/stdio.js"],
  env: { ...process.env, MCP_LOG: "off" }, // quiet trace lines for a clean demo
});
const client = new Client({ name: "clockchain-demo", version: "1.0.0" }, { capabilities: {} });

async function call(name, args) {
  const r = await client.callTool({ name, arguments: args || {} });
  const text = (r.content || []).map((c) => c.text).join("\n");
  return { isError: !!r.isError, text, json: safeJson(text) };
}
function safeJson(t) {
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

hr();
line("Clockchain MCP - live demo");
hr();

await client.connect(transport);
const { tools } = await client.listTools();
line(`Connected. ${tools.length} tools available:`);
line("  " + tools.map((t) => t.name).join(", "));
line();

// 1. Read consensus time.
line("1) Read the decentralized clock  (get_time)");
const t = await call("get_time");
line(`   latest block ${t.json?.latestBlockHeight} @ ${t.json?.latestBlockTime}`);
line();

// 2. Notarize a hash, waiting for on-chain confirmation.
const ref = "demo-" + Date.now();
const content = "the document we are notarizing - " + ref;
const hash = createHash("sha256").update(content).digest("hex");
line("2) Notarize a document hash and wait for confirmation  (log_action wait=true)");
line(`   sha256 = ${hash}`);
const log = await call("log_action", {
  asset_hash: hash,
  asset_reference_id: ref,
  additional_info: "clockchain mcp demo",
  wait: true,
  wait_ms: 20000,
});
const ledgerId = log.json?.ledgerId;
const blockHeight = log.json?.blockHeight;
line(`   ledgerId   = ${ledgerId}`);
line(`   blockHeight= ${blockHeight ?? "(still pending)"} ${blockHeight ? "(confirmed on-chain)" : ""}`);
line();

// 3. Verify the genuine document.
line("3) Verify the original document  (verify_asset)");
const v = await call("verify_asset", { ledger_id: ledgerId, current_hash: hash });
line(`   match = ${v.json?.match}  <- genuine document verifies`);
line();

// 4. Tamper detection.
line("4) Verify a tampered document  (verify_asset, altered hash)");
const tampered = createHash("sha256").update(content + " [TAMPERED]").digest("hex");
const vt = await call("verify_asset", { ledger_id: ledgerId, current_hash: tampered });
line(`   match = ${vt.json?.match}  <- tampering detected`);
line();

const pass =
  !t.isError &&
  !log.isError &&
  !!ledgerId &&
  v.json?.match === true &&
  vt.json?.match === false;

hr();
line(`RESULT: ${pass ? "PASS - demo flow works end to end" : "FAIL - see output above"}`);
hr();
line();
line("To run this from an agent (Claude Code / AgentDash), register the server:");
line();
line(JSON.stringify(
  {
    mcpServers: {
      clockchain: {
        command: "node",
        args: ["<path>/packages/mcp-server/dist/stdio.js"],
        env: {
          CLOCKCHAIN_API_KEY: "<your key>",
          CLOCKCHAIN_CLIENT_ID: "<you@example.com>",
          CLOCKCHAIN_WALLET_ID: "<you@example.com>",
        },
      },
    },
  },
  null,
  2,
));

await client.close();
process.exit(pass ? 0 : 1);
