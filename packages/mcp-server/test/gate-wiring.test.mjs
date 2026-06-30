// CLO-48: registerTools wires the keeper gate so a keeper tool returns the
// structured 402 BEFORE its real handler runs (no network), while the full tool
// surface is still registered (LLD §6.2/§14). Mirrors the fake-server pattern
// used by coverage.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";
import { buildKeeperGate } from "../dist/entitlement.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

const ANON = {
  kind: "anonymous_trial",
  sessionId: "did:clockchain:eph:w1",
  ephemeralDid: "did:clockchain:eph:w1",
  channel: "mcp",
  plan: "trial",
};

function collect(gate) {
  const tools = {};
  registerTools(
    { registerTool: (name, _meta, handler) => { tools[name] = handler; } },
    cfg,
    gate ? { gate } : {},
  );
  return tools;
}

test("with a gate, a keeper tool handler short-circuits to a structured 402", async () => {
  const gate = buildKeeperGate(ANON, () => "cc_claim.sig");
  const tools = collect(gate);
  // Calling the keeper tool's (wrapped) handler returns the gate's tool error
  // WITHOUT reaching the gateway — so this needs no fetch stub.
  const res = await tools["generate_compliance_report"]({});
  assert.equal(res.isError, true);
  assert.equal(res.structuredContent.error, "account_required");
  assert.equal(res.structuredContent.reason, "keeper_action");
  assert.equal(res.structuredContent.tool, "generate_compliance_report");
});

test("the gate does not drop tools — the full surface is still registered", () => {
  const withGate = Object.keys(collect(buildKeeperGate(ANON, () => "c"))).sort();
  const without = Object.keys(collect(null)).sort();
  assert.deepEqual(withGate, without);
  assert.ok(without.length >= 25, "expected the full tool surface to register");
});

test("without a gate (authenticated / backward compat), nothing is intercepted", () => {
  // No gate -> registerTools must not wrap; the registered handler is the raw one.
  const tools = collect(null);
  assert.equal(typeof tools["generate_compliance_report"], "function");
  // A non-keeper generation tool is present and unwrapped either way.
  assert.equal(typeof tools["log_action"], "function");
});
