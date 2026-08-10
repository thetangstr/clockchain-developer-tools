import assert from "node:assert/strict";
import test from "node:test";

import { createHandshakeStateStore, __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { createAgentHandshakeCoordinator } from "../dist/agent-handshake/coordinator.js";

test("two distinct principals advance through identity, statement, anchors, and evidence", async () => {
  __resetHandshakeStateStore();
  const stateStore = createHandshakeStateStore({});
  const messages = [];
  const relay = {
    async fetchDiscovery() {
      return {
        expiresAtMs: "1786339900000",
        issuedAtMs: "1786337000000",
        operatorPublicKey: "A".repeat(43) + "=",
        relayUrl: "https://relay.test",
        repositorySha: "d".repeat(40),
        sessionId: "22222222-3333-4444-8555-666666666666",
      };
    },
    async getMessages() { return { messages }; },
    async postMessage(input) {
      messages.push({ body: input.body, kind: input.kind, role: input.role, senderKey: input.senderKey });
    },
    async getResult() { throw Object.assign(new Error("pending"), { code: "RESULT_PENDING" }); },
  };
  const terms = {
    reference: "NS-1847",
    statement: "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.",
    validForMinutes: 45,
  };
  const identities = {
    initiator: { address: "0x7564105e977516c53be337314c7e53838967bdac", agentId: "9452" },
    responder: { address: "0xe1fae9b4fab2f5726677ecfa912d96b0b683e6a9", agentId: "9453" },
  };
  const coordinators = Object.fromEntries(Object.entries(identities).map(([role, identity]) => [role,
    createAgentHandshakeCoordinator({
      advanceTransitions: async ({ data }) => data.testTransitions ?? [],
      now: () => 1786337100000,
      principal: `principal-${role}`,
      recoverEip191Address: async () => identity.address,
      relay,
      resolveOwnedAgentId: async ({ address }) =>
        Object.values(identities).find((entry) => entry.address === address)?.agentId ?? null,
      stateStore,
    }),
  ]));

  for (const role of ["initiator", "responder"]) {
    const joined = await coordinators[role].join(role, undefined, terms);
    assert.equal(joined.sessionId, "22222222-3333-4444-8555-666666666666");
    assert.equal((await coordinators[role].next(joined.sessionId, role)).action, "sign_identity");
    await coordinators[role].submit(joined.sessionId, role, `0x${"1".repeat(130)}`);
  }
  messages.push(
    ...Object.entries(identities).map(([role, identity]) => ({
      body: { funded: identity.address, role }, kind: "funding_record", role: "host", senderKey: "host",
    })),
  );
  for (const role of ["initiator", "responder"]) {
    assert.equal((await coordinators[role].next("22222222-3333-4444-8555-666666666666", role)).stage, "party_ready");
  }
  const proposal = await coordinators.initiator.next("22222222-3333-4444-8555-666666666666", "initiator");
  assert.equal(proposal.action, "sign_proposal");
  await coordinators.initiator.submit(proposal.sessionId, "initiator", `0x${"2".repeat(130)}`);
  const acceptance = await coordinators.responder.next(proposal.sessionId, "responder");
  assert.equal(acceptance.action, "sign_acceptance");
  await coordinators.responder.submit(proposal.sessionId, "responder", `0x${"3".repeat(130)}`);
  assert.ok(messages.some((entry) => entry.kind === "agent_proposal"));
  assert.ok(messages.some((entry) => entry.kind === "agent_acceptance"));
});
