// The Agent Handshake SOP (/handshake/sop for people, /handshake/sop.txt for
// agents) must present the production 2.1.6 surface: the same endpoint, tool
// list, and helper pin the public server publishes — no staging or 2.1.3
// leftovers, and both renderings carrying the same facts.
import assert from "node:assert/strict";
import { test } from "node:test";

import { HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT } from "../dist/handshake-sop-page.js";
import { INSTALL_TXT, MCP_MANIFEST, LANDING_HTML } from "../dist/landing.js";
import { V2_HELPER_VERSION, V2_HELPER_ASSET_PREFIX } from "../dist/agent-handshake/v2/instructions.js";
import { V2_PUBLIC_TOOL_NAMES } from "../dist/agent-handshake/v2/public-tools.js";

const ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const MANIFEST = "https://mcp.clockchain.network/.well-known/agent-handshake.json";

test("the SOP names the production endpoint, manifest, and helper release in both renderings", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    assert.ok(body.includes(ENDPOINT));
    assert.ok(body.includes(MANIFEST));
    assert.ok(body.includes(V2_HELPER_VERSION));
    assert.ok(body.includes(`${V2_HELPER_ASSET_PREFIX}manifest.json`));
    assert.ok(body.includes(`${V2_HELPER_ASSET_PREFIX}clockchain-agent-handshake.cjs`));
  }
});

test("the SOP lists exactly the eight public tools", () => {
  assert.equal(V2_PUBLIC_TOOL_NAMES.length, 8);
  for (const name of V2_PUBLIC_TOOL_NAMES) {
    assert.ok(HANDSHAKE_SOP_HTML.includes(name), name);
    assert.ok(HANDSHAKE_SOP_TXT.includes(name), name);
  }
});

test("the SOP carries the authorization-only scope boundary", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    assert.ok(body.includes("externalBusinessActionPerformed"));
    assert.ok(/never (receives|sees) a private key/.test(body.replace(/\s+/g, " ")));
  }
});

test("the SOP states the invitation's own expiry and the mint-only 30s runway", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    const flat = body.replace(/<[a-zA-Z/][^>]*>/g, " ").replace(/\s+/g, " ");
    assert.ok(flat.includes("invitationExpiresAtMs"), "names the invitation expiry field");
    assert.ok(flat.includes("sessionDeadlineMs"), "names the session bound");
    assert.ok(flat.includes("30 seconds"), "states the minimum runway");
    assert.ok(!flat.includes("expires with the session"), "must not collapse invitation expiry into the session deadline");
    // The 30-second guard is mint-side only: claims are permitted until
    // invitationExpiresAtMs. Forbid wording that applies it to claims.
    assert.ok(!/claim with under 30 seconds/.test(flat), "runway guard must not be described as claim-side");
    assert.ok(/claim before\s+invitationExpiresAtMs/.test(flat), "must tell responders to claim before invitationExpiresAtMs");
  }
});

test("the SOP scopes keyless ledger verification to the anchor receipts", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    const flat = body.replace(/\s+/g, " ");
    assert.ok(!flat.includes("every artifact is keyless"), "must not claim every artifact is keyless-verifiable");
    assert.ok(flat.includes("anchor receipts") || flat.includes("anchors"), "names the keyless-verifiable artifact");
  }
});

test("the SOP states the operator hygiene rule without claiming server-log guarantees", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    const flat = body.replace(/\s+/g, " ");
    assert.ok(flat.includes("never log"), "requires operators not to log credentials");
    assert.ok(!flat.includes("never appear in server logs"), "no unproven server-log claim");
  }
});

test("the SOP ships drop-in initiator and responder prompts with placeholders", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    const flat = body.replace(/<[a-zA-Z/][^>]*>/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/\s+/g, " ");
    // Entity-decoded form keeps the literal angle-bracket placeholders the
    // tag-stripper would otherwise remove.
    const decoded = body.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/\s+/g, " ");
    // Both roles get a paste-ready prompt, marked as such.
    assert.ok(flat.includes("You are the Initiator"), "initiator prompt present");
    assert.ok(flat.includes("You are the Responder"), "responder prompt present");
    // Placeholders stay literal so a local harness or operator substitutes them.
    assert.ok(decoded.includes("<YOUR_REFERENCE>"), "reference placeholder");
    assert.ok(decoded.includes("<YOUR_STATEMENT>"), "statement placeholder");
    assert.ok(decoded.includes("<PASTE_THE_RESPONDER_INVITATION_HERE>"), "invitation slot");
    // The prompts carry the no-adapter contract: verbatim shellCommands, no hand-signing.
    assert.ok(flat.includes("helperStep.shellCommand verbatim"), "verbatim shellCommand rule");
    assert.ok(flat.includes("never hand-sign"), "no hand-signing rule");
    // The responder prompt demands a fresh idempotency key and single acceptance.
    assert.ok(flat.includes("acceptanceIdempotencyKey"), "idempotency key instruction");
    // The operator-facing pass check names the shared evidence fields.
    assert.ok(flat.includes("same sessionId"), "same-session check");
    // The prompts drive the real invite shape: string validity, fresh ERC-8004.
    assert.ok(flat.includes('validForSeconds "90"'), "string validForSeconds in prompt");
    assert.ok(flat.includes('"required_fresh"'), "fresh ERC-8004 policy in prompt");
  }
});

test("the SOP contains no staging or superseded-helper language", () => {
  for (const body of [HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT]) {
    assert.ok(!body.includes("sslip.io"), "staging host");
    assert.ok(!body.includes("2.1.3"), "old helper version");
    assert.ok(!body.includes("STAGING"), "staging lane");
    assert.ok(!body.includes("root-staging"), "staging root");
    assert.ok(!body.includes("44.249.47.220"), "internal canary relay IP stays out of the public SOP");
  }
});

test("the HTML SOP is discoverable and mobile-responsive", () => {
  assert.ok(HANDSHAKE_SOP_HTML.includes('<meta name="viewport" content="width=device-width, initial-scale=1"'));
  assert.ok(HANDSHAKE_SOP_HTML.includes("@media (max-width: 760px)"));
  assert.ok(HANDSHAKE_SOP_HTML.includes('rel="alternate" type="text/plain" href="/handshake/sop.txt"'));
  assert.ok(HANDSHAKE_SOP_HTML.includes("authorization") || HANDSHAKE_SOP_HTML.includes("authorizes nothing"));
});

test("llms.txt, the manifest, and the landing page all link the SOP", () => {
  assert.ok(INSTALL_TXT.includes("https://mcp.clockchain.network/handshake/sop.txt"));
  assert.equal(MCP_MANIFEST.agentHandshake.sop, "https://mcp.clockchain.network/handshake/sop");
  assert.equal(MCP_MANIFEST.agentHandshake.sopText, "https://mcp.clockchain.network/handshake/sop.txt");
  assert.ok((LANDING_HTML.match(/href="\/handshake\/sop"/g) || []).length >= 3, "linked from nav, section, and footer");
});
