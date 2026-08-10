import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_HANDSHAKE_PROTOCOL,
  agentHandshakeStatementDigest,
  agentTransitionDigest,
  buildAgentAcceptanceTransition,
  buildAgentAcknowledgment,
  buildAgentProposal,
  buildAgentProposalTransition,
  normalizeAgentHandshakeTerms,
} from "../dist/agent-handshake/protocol.js";

const TERMS = {
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.",
  validForMinutes: 45,
};
const INITIATOR = { address: "0x7564105e977516c53be337314c7e53838967bdac", agentId: "9452" };
const RESPONDER = { address: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9", agentId: "9453" };

test("MCP generic terms and transition bytes match the canonical Handshake kit", () => {
  const normalized = normalizeAgentHandshakeTerms(TERMS);
  assert.deepEqual(normalized, { ...TERMS, validForMinutes: "45" });
  assert.equal(agentHandshakeStatementDigest(normalized), "ad03e63431012934efe73884cce7e8f4e961aabc48dbaf4b47c8c14462d38add");
  const proposal = buildAgentProposal({
    expiresAtMs: "1786339800000",
    initiator: INITIATOR,
    issuedAtMs: "1786337100000",
    repositorySha: "d".repeat(40),
    responder: RESPONDER,
    sessionId: "22222222-3333-4444-8555-666666666666",
    terms: normalized,
  });
  assert.equal(proposal.protocol, AGENT_HANDSHAKE_PROTOCOL);
  const base = {
    expiresAtMs: proposal.expiresAtMs,
    initiator: INITIATOR,
    reference: TERMS.reference,
    responder: RESPONDER,
    sessionDigest: "a".repeat(64),
    statementDigest: proposal.statementDigest,
  };
  const proposed = buildAgentProposalTransition(base);
  const accepted = buildAgentAcceptanceTransition(base, proposed);
  const acknowledged = buildAgentAcknowledgment(base, accepted);
  assert.deepEqual([proposed, accepted, acknowledged].map(agentTransitionDigest), [
    "de189eb3c31e696107a7e42a02a564a357818dfe8467474da4b590eedeef0ef5",
    "c833fa52c50c79b3ff0e301ea44ebaa0501ee25d58af3fe71861c74360bcc8c7",
    "393bc0e21a19f864061e3b32e59587487a8316e5c4c15dc9232a61e92760be53",
  ]);
});

test("generic MCP artifacts reject payment vocabulary and malformed terms", () => {
  for (const value of [
    { ...TERMS, amount: "0" },
    { ...TERMS, reference: "" },
    { ...TERMS, validForMinutes: 0 },
    { ...TERMS, validForMinutes: 61 },
  ]) {
    assert.throws(() => normalizeAgentHandshakeTerms(value));
  }
  const text = JSON.stringify(normalizeAgentHandshakeTerms(TERMS)).toLowerCase();
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor"]) {
    assert.equal(text.includes(word), false, word);
  }
});
