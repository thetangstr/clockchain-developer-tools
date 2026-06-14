// All-tools coverage + adversarial error-path eval (AGE-185), run offline as a
// CI gate (it's part of `npm test`, which the deploy is gated on).
//
// Two guarantees across the ENTIRE 31-tool surface:
//   1. Completeness — the set of tools we assert on equals the set the server
//      registers. Add a tool without covering it here and CI fails.
//   2. Resilience — every tool, when the upstream gateway fails on every call,
//      returns a well-formed MCP result (a `content` text block) and never
//      throws. Tools that actually reach the gateway must surface `isError`;
//      the few that short-circuit without a network call (ERC-8004 unconfigured)
//      must still return a clean, well-formed result.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };
const HEX = "a".repeat(64);

function collectTools() {
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg);
  return tools;
}

const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");

// Minimal VALID arguments for every tool (required fields satisfied). Values are
// shape-correct; the point is to drive each handler, not to pass the gateway.
const ARGS = {
  get_time: {},
  get_timestamp: {},
  get_block: { height: 5 },
  get_validation: { height: 5 },
  log_action: { asset_hash: HEX, asset_reference_id: "r" },
  search_actions: { asset_reference_id: "r" },
  get_log_entry: { ledger_id: "L1" },
  verify_asset: { ledger_id: "L1", current_hash: HEX },
  resolve_agent: { agent_id: "a1" },
  attest_action: { agent_id: "agent:bot", action: "act", inputs: { a: 1 } },
  verify_receipt: { receipt: { anchor: { ledgerId: "L1", blockHeight: "5" }, agentId: "a", action: "x", payload: { inputs: null, outputs: null }, eventHash: HEX, network: "testnet" } },
  complete_attestation: { receipt: { anchor: { ledgerId: "L1", blockHeight: null }, agentId: "a", action: "x", payload: { inputs: null, outputs: null }, eventHash: HEX, network: "testnet" } },
  get_contract_types: {},
  estimate_schedule: { params: { contractName: "C", contractType: "treasury" } },
  create_schedule: { params: { contractName: "C" }, gas_fees: "1", total_payable_price: "1", nonce: "1", signature: "0xabc" },
  list_schedules: {},
  generate_audit_trail: { asset_reference_id: "r" },
  generate_compliance_report: { asset_reference_id: "r", format: "eu-ai-act" },
  build_evidence_package: { ledger_id: "L1" },
  verify_package: { package: { schema: "clockchain.evidence/v1", entries: [] } },
  mint_identity: { did: "did:x:1", document: { id: "did:x:1" } },
  revoke_identity: { did: "did:x:1" },
  delegate_authority: { parent_did: "did:x:1", child_did: "did:x:2", scope: "sign", until: "2027-01-01" },
  get_identity_history: { did: "did:x:1" },
  verify_identity_at: { did: "did:x:1", at: "2026-06-14T00:00:00Z" },
  verify_cross_party: { ledger_id: "L1" },
  tsa_issue: { agent_id: "a", commitment: "deliver", deadline: "2027-01-01" },
  tsa_checkpoint: { commitment_id: "L1", note: "progress" },
  tsa_attest: { commitment_id: "L1", outcome: "kept", deadline: "2027-01-01" },
  tsa_settle: { commitment_id: "L1", outcome: "kept", consequence: "none" },
  tsa_status: { commitment_id: "L1" },
};

// Read/verify tools that, by design, degrade GRACEFULLY to a clean
// (non-isError) result on upstream failure instead of erroring:
//   - resolve_agent      → "unknown" when ERC-8004 is unconfigured (no call)
//   - verify_cross_party → "unknown"/no-match when sources are unreachable
//   - verify_identity_at → not-found/unverified rather than a hard error
//   - get_identity_history → empty history (searchAsset swallowed → [])
//   - list_schedules     → empty list (client.listScheduled swallows → [])
// All must still return a well-formed, non-throwing MCP result.
const GRACEFUL_OK = new Set([
  "resolve_agent",
  "verify_cross_party",
  "verify_identity_at",
  "get_identity_history",
  "list_schedules",
]);

// Fail every upstream call so we exercise each tool's error handling. Use 400
// (a client error) rather than 5xx so resilientFetch does NOT retry — the test
// stays fast and deterministic while still driving the error path.
function failAllFetch() {
  globalThis.fetch = async () => ({
    status: 400, ok: false, statusText: "bad request",
    text: async () => JSON.stringify({ message: "upstream rejected" }),
  });
}

test("coverage completeness: every registered tool is in the ARGS matrix", () => {
  const registered = Object.keys(collectTools()).sort();
  const covered = Object.keys(ARGS).sort();
  assert.deepEqual(registered, covered,
    "ARGS must list exactly the registered tools — add new tools here so they get coverage");
  assert.ok(registered.length >= 31, `expected >= 31 tools, got ${registered.length}`);
});

test("resilience: no tool throws on upstream failure; gateway tools surface isError", async () => {
  const tools = collectTools();
  for (const [name, handler] of Object.entries(tools)) {
    failAllFetch();
    let res;
    try {
      res = await handler(ARGS[name]);
    } catch (e) {
      assert.fail(`${name} threw instead of returning an MCP result: ${e.message}`);
    }
    // Always a well-formed MCP result with text content.
    assert.ok(res && Array.isArray(res.content), `${name} returned a malformed result`);
    assert.ok(textOf(res).length > 0, `${name} returned an empty result`);
    if (!GRACEFUL_OK.has(name)) {
      assert.equal(res.isError, true, `${name} should surface isError on upstream failure`);
    }
  }
});
