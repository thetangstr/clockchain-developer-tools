// CLO-48: keeper classification + structured 402 gate (LLD §6.1/§6.2/§11/§14).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyTool,
  KEEPER_TOOLS,
  FREE_TOOLS,
  isClassified,
  assertToolClassified,
  buildAccountRequired,
  buildKeeperGate,
  keeperToolError,
} from "../dist/entitlement.js";

const ANON = {
  kind: "anonymous_trial",
  sessionId: "did:clockchain:eph:abc",
  ephemeralDid: "did:clockchain:eph:abc",
  channel: "mcp",
  plan: "trial",
};
const AUTHED = { kind: "authenticated", reason: "static_token", plan: "pro" };

test("keeper tools are classified keeper/paid (LLD §6.1)", () => {
  for (const t of [
    "get_log_entry",
    "search_actions",
    "verify_receipt",
    "verify_package",
    "generate_compliance_report",
    "generate_audit_trail",
    "create_schedule",
    "delegate_authority",
  ]) {
    assert.equal(classifyTool(t).keeper, true, `${t} should be keeper`);
    assert.equal(classifyTool(t).tier, "paid");
    assert.ok(KEEPER_TOOLS.has(t));
  }
});

test("generation/read tools are NOT keeper (value lands before the wall)", () => {
  for (const t of [
    "mint_identity",
    "log_action",
    "attest_action",
    "tsa_issue",
    "build_evidence_package",
    "get_time",
    "get_block",
    "verify_cross_party",
  ]) {
    assert.equal(classifyTool(t).keeper, false, `${t} must not be keeper`);
  }
});

test("FIX 2: unclassified tools FAIL CLOSED — classifyTool treats them as keeper", () => {
  // A future tool added without classifying it must NOT silently run free.
  assert.equal(classifyTool("some_future_tool").keeper, true);
  assert.equal(classifyTool("some_future_tool").tier, "paid");
  assert.equal(isClassified("some_future_tool"), false);
});

test("FIX 2: assertToolClassified throws for an unclassified tool (boot guard)", () => {
  assert.throws(
    () => assertToolClassified("totally_unknown_tool"),
    /unclassified/,
    "registering an unclassified tool must throw at boot",
  );
  // every explicitly classified tool passes the assertion
  for (const t of [...KEEPER_TOOLS, ...FREE_TOOLS]) {
    assert.doesNotThrow(() => assertToolClassified(t), `${t} should be classified`);
  }
});

test("anonymous keeper action -> structured 402 account_required (NOT a 500)", async () => {
  const gate = buildKeeperGate(ANON, () => "cc_claim.sig");
  const blocked = await gate.check("generate_compliance_report");
  assert.ok(blocked, "keeper tool must be blocked for an anonymous trial");
  assert.equal(blocked.isError, true);
  // model-readable structured error
  assert.equal(blocked.structuredContent.error, "account_required");
  assert.equal(blocked.structuredContent.reason, "keeper_action");
  assert.equal(blocked.structuredContent.tool, "generate_compliance_report");
  assert.ok(blocked.structuredContent.claim, "carries a forwardable claim");
  assert.match(blocked.structuredContent.upgradeUrl, /claim=/);
  // the text content is the same JSON (a tool error, never a raw throw/500)
  const parsed = JSON.parse(blocked.content[0].text);
  assert.equal(parsed.error, "account_required");
});

test("generation tool below ceiling does NOT 402 for an anonymous trial", async () => {
  const gate = buildKeeperGate(ANON, () => "cc_claim.sig");
  assert.equal(await gate.check("log_action"), undefined);
  assert.equal(await gate.check("mint_identity"), undefined);
  assert.equal(await gate.check("build_evidence_package"), undefined);
  assert.equal(await gate.check("attest_action"), undefined);
});

test("authenticated callers bypass the keeper layer entirely (LLD §13)", async () => {
  const gate = buildKeeperGate(AUTHED, () => "cc_claim.sig");
  // even a keeper tool is allowed for an authenticated principal
  assert.equal(await gate.check("generate_compliance_report"), undefined);
  assert.equal(await gate.check("delegate_authority"), undefined);
  assert.equal(await gate.check("log_action"), undefined);
});

test("claim is minted lazily — only when a keeper tool is actually hit", async () => {
  let mints = 0;
  const gate = buildKeeperGate(ANON, () => {
    mints += 1;
    return "cc_claim.sig";
  });
  await gate.check("log_action"); // non-keeper -> no mint
  assert.equal(mints, 0);
  await gate.check("generate_compliance_report"); // keeper -> one mint
  assert.equal(mints, 1);
});

test("buildAccountRequired / keeperToolError shapes (LLD §6.2)", () => {
  const body = buildAccountRequired("generate_audit_trail", "cc_x.y", "keeper_action");
  assert.equal(body.error, "account_required");
  assert.equal(body.claim, "cc_x.y");
  assert.match(body.upgradeUrl, /claim=cc_x\.y/);
  const err = keeperToolError(body);
  assert.equal(err.isError, true);
  assert.deepEqual(err.structuredContent, body);
});
