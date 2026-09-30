import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";

import { contractRefusalSchema } from "../dist/agent-contract/refusals.js";
import {
  CONTRACT_TOOL_DEFS,
  CONTRACT_TOOL_NAMES,
  contractToolDef,
  toolDefsForRole,
} from "../dist/agent-contract/schemas.js";
import {
  CONTRACT_SERVER_INSTRUCTIONS,
  guidanceDigests,
  toolsListForRole,
} from "../dist/agent-contract/tools-list.js";
import {
  buildServerCard,
  HANDSHAKE_MCP_ENDPOINT,
  CONTRACT_MCP_ENDPOINT,
  CONTRACT_MCP_STAGING_ENDPOINT,
} from "../dist/agent-contract/server-card.js";

const BUYER_ONLY = [
  "rendezvous_search",
  "rendezvous_send_invitation",
  "mandate_prepare",
  "mandate_submit",
  "booking_lookup",
  "verification_prepare",
  "verification_submit",
  "settlement_prepare",
  "settlement_authorize",
];
const PROVIDER_ONLY = [
  "rendezvous_publish_listing",
  "catalog_quote",
  "booking_prepare",
  "booking_execute",
  "booking_cancel_prepare",
  "booking_cancel_submit",
];
const SHARED = [
  "rendezvous_inbox",
  "contract_bind_challenge",
  "contract_bind",
  "offer_prepare",
  "offer_submit",
  "offer_accept_prepare",
  "offer_accept_submit",
  "offer_reject",
  "contract_withdraw",
  "agreement_get",
  "settlement_status",
  "contract_status",
];

test("every LLD §3 tool exists exactly once, role-scoped", () => {
  assert.equal(CONTRACT_TOOL_DEFS.length, 27);
  assert.equal(new Set(CONTRACT_TOOL_NAMES).size, 27);
  for (const name of BUYER_ONLY) assert.equal(contractToolDef(name).role, "buyer", name);
  for (const name of PROVIDER_ONLY) assert.equal(contractToolDef(name).role, "provider", name);
  for (const name of SHARED) assert.equal(contractToolDef(name).role, "both", name);
});

test("role-scoped tools/list hides the other role's tools", () => {
  const buyerTools = toolsListForRole("buyer").tools.map((t) => t.name);
  const providerTools = toolsListForRole("provider").tools.map((t) => t.name);
  assert.equal(buyerTools.length, 21);
  assert.equal(providerTools.length, 18);
  for (const name of PROVIDER_ONLY) assert.ok(!buyerTools.includes(name), name);
  for (const name of BUYER_ONLY) assert.ok(!providerTools.includes(name), name);
  for (const name of SHARED) {
    assert.ok(buyerTools.includes(name) && providerTools.includes(name), name);
  }
});

test("guidance has no ordered steps and no cross-tool references", () => {
  const ordered = /\bfirst\b[\s\S]*\bthen\b|\bstep\s+\d|\b\d+\s*[.)]\s+[a-z]/i;
  const named = (text) => CONTRACT_TOOL_NAMES.some((name) => text.includes(name));
  for (const role of ["buyer", "provider"]) {
    for (const tool of toolsListForRole(role).tools) {
      assert.ok(!ordered.test(tool.description), `${tool.name}: ordered-steps phrasing`);
      assert.ok(!/\d+\.\s/.test(tool.description), `${tool.name}: numbered list`);
      for (const other of CONTRACT_TOOL_NAMES) {
        assert.ok(!tool.description.includes(other), `${tool.name} references ${other}`);
      }
    }
  }
  assert.ok(!ordered.test(CONTRACT_SERVER_INSTRUCTIONS));
  assert.ok(!named(CONTRACT_SERVER_INSTRUCTIONS), "instructions name a tool");
});

test("guidance digests are stable and identical across calls", () => {
  for (const role of ["buyer", "provider"]) {
    const a = guidanceDigests(role);
    const b = guidanceDigests(role);
    assert.deepEqual(a, b);
    assert.match(a.toolsListDigest, /^0x[0-9a-f]{64}$/);
    assert.match(a.instructionsDigest, /^0x[0-9a-f]{64}$/);
  }
  // Buyer and provider see different tool sets → different tools digests.
  assert.notEqual(guidanceDigests("buyer").toolsListDigest, guidanceDigests("provider").toolsListDigest);
  // Instructions are uniform (R10): same digest for both roles.
  assert.equal(
    guidanceDigests("buyer").instructionsDigest,
    guidanceDigests("provider").instructionsDigest,
  );
});

const validator = (name) => z.object(contractToolDef(name).schema).strict();

test("input schemas reject malformed calls per tool", () => {
  // Every tool rejects an unknown extra key (strict) — and tools with
  // required fields reject an empty body.
  for (const def of CONTRACT_TOOL_DEFS) {
    const v = validator(def.name);
    assert.equal(v.safeParse({ unexpectedField: 1 }).success, false, `${def.name} accepted extra key`);
    const hasRequired = Object.values(def.schema).some((field) => !(field instanceof z.ZodOptional));
    if (hasRequired) {
      assert.equal(v.safeParse({}).success, false, `${def.name} accepted empty body`);
    }
  }
  // Targeted rejects on the highest-risk fields.
  assert.equal(validator("offer_submit").safeParse({
    envelope: "not-an-envelope",
    signatureHex: "0x" + "a".repeat(130),
  }).success, false);
  assert.equal(validator("offer_prepare").safeParse({
    itineraryId: "IT-ZX118-ECON",
    feeMinor: -5,
  }).success, false);
  assert.equal(validator("rendezvous_send_invitation").safeParse({
    listingId: "lst-1",
    sealedInvitation: { alg: "plain", ciphertextHex: "0xabcd" },
  }).success, false);
  assert.equal(validator("verification_prepare").safeParse({
    orderRef: "ORD-1",
    result: "maybe",
  }).success, false);
  assert.equal(validator("contract_bind").safeParse({
    certificate: { cert: "yes" },
    signerKey: { keyId: "k1", publicKeyHex: "not-hex" },
    approvalKey: { keyId: "k2", publicKeyHex: "0x" + "a".repeat(64) },
  }).success, false);
  // And the corresponding well-formed inputs pass.
  assert.equal(validator("offer_prepare").safeParse({
    itineraryId: "IT-ZX118-ECON",
    feeMinor: 12000,
    note: "window seat",
  }).success, true);
  assert.equal(validator("rendezvous_send_invitation").safeParse({
    listingId: "lst-1",
    sealedInvitation: {
      v: 2,
      epk: `0x${"ab".repeat(32)}`,
      iv: `0x${"cd".repeat(12)}`,
      ct: `0x${"ef".repeat(32)}`,
      tag: `0x${"01".repeat(16)}`,
    },
  }).success, true);
});

test("MANDATE_REFUSED and refusals cannot carry the cap or extras", () => {
  const ok = contractRefusalSchema.safeParse({ error: "MANDATE_REFUSED", retryable: false });
  assert.equal(ok.success, true);
  const leaks = contractRefusalSchema.safeParse({
    error: "MANDATE_REFUSED",
    retryable: false,
    capMinor: 500000,
    detail: "cap is 500000",
  });
  assert.equal(leaks.success, false);
  assert.equal(
    contractRefusalSchema.safeParse({ error: "cap is 500000", retryable: false }).success,
    false,
  );
});

test("sim-backed outputs require simulated:true; every output carries serverNonce", () => {
  const simBacked = ["catalog_quote", "booking_execute", "booking_lookup", "booking_cancel_submit", "settlement_authorize", "settlement_status"];
  const shapeOf = (schema) => (typeof schema._def.shape === "function" ? schema._def.shape() : undefined);
  // N4b-10 (D13): settlement_prepare's output is a union (envelope | status
  // body) — every variant must satisfy the same invariants.
  const variantsOf = (schema) => {
    const shape = shapeOf(schema);
    if (shape !== undefined) return [shape];
    if (Array.isArray(schema._def.options)) return schema._def.options.map((o) => shapeOf(o));
    return [];
  };
  for (const def of CONTRACT_TOOL_DEFS) {
    assert.equal(def.simulated, simBacked.includes(def.name), def.name);
    const variants = variantsOf(def.outputSchema);
    assert.ok(variants.length > 0 && variants.every((s) => s !== undefined), `${def.name} output shape unreadable`);
    for (const shape of variants) {
      assert.ok("serverNonce" in shape, `${def.name} output lacks serverNonce`);
      if (def.simulated) {
        assert.equal(shape.simulated._def.typeName, "ZodLiteral", `${def.name} simulated flag`);
        assert.equal(shape.simulated._def.value, true, `${def.name} simulated value`);
      }
    }
  }
});

test("server card pins the published endpoints and per-role guidance digests", () => {
  const card = buildServerCard();
  assert.equal(HANDSHAKE_MCP_ENDPOINT, "https://mcp.clockchain.network/next/handshake/mcp");
  assert.equal(CONTRACT_MCP_ENDPOINT, "https://mcp.clockchain.network/contract/mcp");
  assert.equal(CONTRACT_MCP_STAGING_ENDPOINT, "https://mcp.clockchain.network/staging/contract/mcp");
  assert.equal(card.schema, "agent-contract.server-card/v1");
  const endpoints = card.surfaces.map((s) => s.endpoint);
  assert.ok(endpoints.includes(HANDSHAKE_MCP_ENDPOINT));
  assert.ok(endpoints.includes(CONTRACT_MCP_ENDPOINT));
  assert.deepEqual(card.guidance.buyer, guidanceDigests("buyer"));
  assert.deepEqual(card.guidance.provider, guidanceDigests("provider"));
  assert.match(card.cardDigest, /^0x[0-9a-f]{64}$/);
});

test("tools/list wire schemas render strict objects with required fields", () => {
  const tools = toolsListForRole("buyer").tools;
  const bind = tools.find((t) => t.name === "contract_bind");
  assert.equal(bind.inputSchema.type, "object");
  assert.equal(bind.inputSchema.additionalProperties, false);
  assert.deepEqual(bind.inputSchema.required.sort(), ["approvalKey", "certificate", "signerKey"]);
  const search = tools.find((t) => t.name === "rendezvous_search");
  assert.deepEqual(search.inputSchema.required.sort(), ["destination", "origin"]);
  // optional fields must not appear in required
  assert.ok(!search.inputSchema.required.includes("departDate"));
});
