// H-REQ-07: once the host's descriptor is on the relay, agent_handshake_next
// anchors the agreement's transitions to the ledger, the initiator reports
// them, and each role is handed its evidence signing request. None of that
// happens at or after the descriptor's agreementExpiresAtMs. The expiry is
// read on one non-decreasing clock (the one the call's authorization read):
// before anchoring, immediately before each ledger write, before the report
// and every attempt to post it, before the evidence request and inside the
// state write that stores it. At the expiry the call is refused with
// signing_window_expired; a clock read earlier than the one before it, or not
// an integer, is refused with coordination_failed. A role whose evidence is
// already uploaded still reaches its certificate after the expiry, without
// anchoring anything.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { __advanceRuntimeV2 } from "../dist/agent-handshake/v2/coordinator.js";
import {
  ACCEPT_AT_MS,
  F,
  HOST_SESSION_KEY_CERTIFICATE,
  OPENED_MS,
  PROPOSAL_EXPIRES_MS,
  REPOSITORY_SHA,
  SESSION_ID,
  TERMS,
  clone,
  createFixtureHarness,
  fixtureTransitions,
  sig,
  signingRequestOf,
} from "./helpers/agent-handshake-v2-fixture-harness.mjs";

const EXPIRES_MS = PROPOSAL_EXPIRES_MS;
const isWindowExpired = (error) => error?.name === "V2SigningWindowExpiredError";
const refusedWith = (detail) => (error) => error?.name === "V2CoordinatorError" && error.detail === detail;

// A ledger stand-in for the coordinator's advanceTransitions: each transition
// not yet on the ledger is written, and the coordinator's guard runs
// immediately before each write (as the production anchoring does).
// `beforeWrite(index)` runs first, while the write's preceding reads are
// "in flight"; `afterAnchoring()` runs once all three are on the ledger.
function ledgerStandIn() {
  const ledger = { calls: 0, writes: [], beforeWrite: null, afterAnchoring: null };
  ledger.advanceTransitions = async ({ descriptor, beforeAnchor }) => {
    ledger.calls += 1;
    const transitions = fixtureTransitions(descriptor);
    for (const [index, transition] of transitions.entries()) {
      if (ledger.writes.includes(transition.digest)) continue;
      await ledger.beforeWrite?.(index);
      beforeAnchor?.();
      ledger.writes.push(transition.digest);
    }
    await ledger.afterAnchoring?.();
    return transitions;
  };
  return ledger;
}

// Both roles joined and party_ready, the initiator's proposal and the
// responder's acceptance on the relay, then the host's descriptor, whose
// agreementExpiresAtMs is the proposal's expiry.
async function descriptorPublished(harnessOptions = {}) {
  const ledger = ledgerStandIn();
  const harness = await createFixtureHarness({ ...harnessOptions, advanceTransitions: (input) => ledger.advanceTransitions(input) });
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(ACCEPT_AT_MS);
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_acceptance");
  await harness.submitAcceptance(signingRequestOf(response));
  const descriptor = harness.publishDescriptor();
  assert.equal(descriptor.agreementExpiresAtMs, String(EXPIRES_MS));
  return { harness, ledger, next: (role) => harness.coordinator.next({ access: harness.accesses[role] }) };
}

async function assertNothingAnchoredOrRequested({ harness, ledger }, role, writes) {
  assert.equal(ledger.writes.length, writes, "no ledger write after the refusal");
  assert.equal(harness.posted("agent_v2_anchor_report").length, 0, "no anchor report");
  assert.equal(harness.sends.filter((send) => send.kind === "agent_v2_anchor_report").length, 0, "no anchor-report send");
  const record = await harness.record(role);
  assert.notEqual(record.data.pending?.operation, "evidence", "no evidence request is stored");
  assert.notEqual(record.data.stage, "sign_evidence");
}

for (const role of ["initiator", "responder"]) {
  test(`H-REQ-07: ${role} — next() at the agreement expiry is refused before anything is anchored or requested`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS);
    await assert.rejects(() => setup.next(role), isWindowExpired);
    assert.equal(setup.ledger.calls, 0, "anchoring is not started");
    await assertNothingAnchoredOrRequested(setup, role, 0);

    setup.harness.setClock(EXPIRES_MS + 60_000);
    await assert.rejects(() => setup.next(role), isWindowExpired);
    assert.equal(setup.ledger.calls, 0, "a later call anchors nothing either");
    await assertNothingAnchoredOrRequested(setup, role, 0);
  });

  test(`H-REQ-07: ${role} — next() 1 ms before the agreement expiry anchors and returns the evidence request`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS - 1);
    const response = await setup.next(role);
    assert.equal(response.stage, "sign_evidence");
    assert.equal(setup.ledger.writes.length, 3);
    assert.equal(setup.harness.posted("agent_v2_anchor_report").length, role === "initiator" ? 1 : 0);
    assert.equal((await setup.harness.record(role)).data.pending?.operation, "evidence");
  });

  test(`H-REQ-07: ${role} — the expiry reached while anchoring refuses the next ledger write`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS - 1);
    setup.ledger.beforeWrite = (index) => { if (index === 1) setup.harness.setClock(EXPIRES_MS); };
    await assert.rejects(() => setup.next(role), isWindowExpired);
    await assertNothingAnchoredOrRequested(setup, role, 1);
  });

  test(`H-REQ-07: ${role} — the expiry reached after anchoring refuses the report and the evidence request`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS - 1);
    setup.ledger.afterAnchoring = () => { setup.harness.setClock(EXPIRES_MS); };
    await assert.rejects(() => setup.next(role), isWindowExpired);
    await assertNothingAnchoredOrRequested(setup, role, 3);
  });

  test(`H-REQ-07: ${role} — the expiry reached inside the state write that stores the evidence request refuses it`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS - 1);
    setup.ledger.afterAnchoring = () => {
      // The next state write after anchoring is the one that stores the evidence request.
      setup.harness.hooks.onStateUpdate = () => {
        delete setup.harness.hooks.onStateUpdate;
        setup.harness.setClock(EXPIRES_MS);
      };
    };
    await assert.rejects(() => setup.next(role), isWindowExpired);
    const record = await setup.harness.record(role);
    assert.notEqual(record.data.pending?.operation, "evidence", "no evidence request is stored");
    assert.notEqual(record.data.stage, "sign_evidence");
  });

  test(`H-REQ-07: ${role} — a clock read 1 ms earlier than the one before it while anchoring is refused with coordination_failed`, async () => {
    const setup = await descriptorPublished();
    const start = EXPIRES_MS - 10;
    setup.harness.setClock(start);
    setup.ledger.beforeWrite = (index) => { if (index === 1) setup.harness.setClock(start - 1); };
    await assert.rejects(() => setup.next(role), refusedWith("clock_backwards"));
    await assertNothingAnchoredOrRequested(setup, role, 1);
  });

  test(`H-REQ-07: ${role} — a non-integer clock read while anchoring is refused with coordination_failed`, async () => {
    const setup = await descriptorPublished();
    const start = EXPIRES_MS - 10;
    setup.harness.setClock(start);
    setup.ledger.beforeWrite = (index) => { if (index === 1) setup.harness.setClock(start + 0.5); };
    await assert.rejects(() => setup.next(role), refusedWith("clock_invalid"));
    await assertNothingAnchoredOrRequested(setup, role, 1);
  });

  test(`H-REQ-07: ${role} — evidence already uploaded still reaches the certificate after the expiry, with nothing anchored`, async () => {
    const setup = await descriptorPublished();
    setup.harness.setClock(EXPIRES_MS - 1);
    assert.equal((await setup.next(role)).stage, "sign_evidence");
    const policyDigest = F.parties[role].policyDigest;
    assert.equal((await setup.harness.coordinator.submit({ access: setup.harness.accesses[role], policyDigest, signatureHex: sig(4, role) })).stage, "evidence_submitted");
    const calls = setup.ledger.calls;

    setup.harness.setClock(EXPIRES_MS + 1_000);
    const response = await setup.next(role);
    // The harness relay has no host result yet: the certificate step waits for it.
    assert.equal(response.stage, "awaiting_certificate");
    assert.equal(setup.ledger.calls, calls, "nothing is anchored after the expiry");
  });
}

test("H-REQ-07: initiator — the expiry reached at the anchor report's post attempt sends nothing", async () => {
  const setup = await descriptorPublished({ productionRelayClient: true });
  setup.harness.setClock(EXPIRES_MS - 1);
  setup.ledger.afterAnchoring = () => {
    // The relay client's own sequence read, just before it posts the report.
    setup.harness.hooks.onRelayClientRead = () => {
      delete setup.harness.hooks.onRelayClientRead;
      setup.harness.setClock(EXPIRES_MS);
    };
  };
  await assert.rejects(() => setup.next("initiator"), isWindowExpired);
  await assertNothingAnchoredOrRequested(setup, "initiator", 3);
});

test("H-REQ-07: initiator — the expiry reached between attempts to post the anchor report stops the retry", async () => {
  const setup = await descriptorPublished({ productionRelayClient: true });
  setup.harness.setClock(EXPIRES_MS - 1);
  setup.ledger.afterAnchoring = () => {
    setup.harness.hooks.onRelayPost = (envelope) => {
      if (envelope.kind !== "agent_v2_anchor_report") return undefined;
      delete setup.harness.hooks.onRelayPost;
      setup.harness.setClock(EXPIRES_MS);
      return "conflict";
    };
  };
  await assert.rejects(() => setup.next("initiator"), isWindowExpired);
  assert.equal(setup.harness.sends.filter((send) => send.kind === "agent_v2_anchor_report").length, 1, "one attempt, answered with a conflict");
  assert.equal(setup.harness.posted("agent_v2_anchor_report").length, 0, "nothing is published");
  const record = await setup.harness.record("initiator");
  assert.notEqual(record.data.pending?.operation, "evidence", "no evidence request is stored");
});

// ---- the production anchoring (__advanceRuntimeV2) ------------------------

function descriptorFixture() {
  const proposal = F.proposalEnvelope.payload;
  return {
    agreementExpiresAtMs: proposal.expiresAtMs,
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: "f".repeat(64),
    identityPolicy: TERMS.identityPolicy,
    initiator: proposal.initiator,
    operatorPublicKey: HOST_SESSION_KEY_CERTIFICATE.certificate.sessionPublicKey,
    protocol: "clockchain.agent-handshake/v2",
    reference: TERMS.reference,
    repositorySha: REPOSITORY_SHA,
    responder: proposal.responder,
    schema: "clockchain.agent-handshake-descriptor/v2",
    sessionId: SESSION_ID,
    sessionOpenedAtMs: String(OPENED_MS),
    sessionOpenedBlock: "6999",
    statementDigest: proposal.statementDigest,
  };
}

// A Clockchain client stand-in: an in-memory ledger whose log() is the write.
function clockchainStandIn(events) {
  const entries = new Map();
  return {
    entries,
    searchAsset: async (reference) => [...entries.values()].filter((entry) => entry.assetReferenceId === reference),
    log: async ({ assetHash, assetReferenceId }) => {
      events.push("write");
      const ledgerId = randomUUID();
      entries.set(ledgerId, { assetHash, assetReferenceId, blockHeight: String(7000 + entries.size), ledgerId });
      return { ledgerId };
    },
    getLedgerEntry: async (ledgerId) => entries.get(ledgerId),
    getChainRecord: async (_blockHeight, ledgerId) => entries.get(ledgerId),
    getBlock: async () => ({ blockTime: "2026-08-09T17:00:00.000Z" }),
  };
}

test("H-REQ-07: the production anchoring runs the guard immediately before each ledger write", async () => {
  const events = [];
  const client = clockchainStandIn(events);
  const receipts = await __advanceRuntimeV2(client, {
    descriptor: descriptorFixture(), role: "initiator", existing: [], beforeAnchor: () => { events.push("guard"); },
  });
  // The initiator writes PROPOSED and ACKNOWLEDGED; ACCEPTED is the responder's,
  // so the initiator stops at it until the responder has written it.
  assert.deepEqual(events, ["guard", "write"]);
  assert.equal(receipts.length, 1);
});

test("H-REQ-07: the production anchoring makes no ledger write once the guard refuses", async () => {
  const events = [];
  const client = clockchainStandIn(events);
  const descriptor = descriptorFixture();
  // The responder's ACCEPTED must follow the initiator's PROPOSED: write PROPOSED first.
  await __advanceRuntimeV2(client, { descriptor, role: "initiator", existing: [] });
  assert.deepEqual(events, ["write"]);
  let guardCalls = 0;
  await assert.rejects(
    () => __advanceRuntimeV2(client, {
      descriptor, role: "responder", existing: [],
      beforeAnchor: () => { guardCalls += 1; throw Object.assign(new Error("window closed"), { name: "V2SigningWindowExpiredError" }); },
    }),
    isWindowExpired,
  );
  assert.equal(guardCalls, 1);
  assert.deepEqual(events, ["write"], "the refused write is not made");
  assert.equal(client.entries.size, 1);
});

test("H-REQ-07: the production anchoring does not run the guard for transitions already on the ledger", async () => {
  const events = [];
  const client = clockchainStandIn(events);
  const descriptor = descriptorFixture();
  await __advanceRuntimeV2(client, { descriptor, role: "initiator", existing: [] });
  await __advanceRuntimeV2(client, { descriptor, role: "responder", existing: [] });
  await __advanceRuntimeV2(client, { descriptor, role: "initiator", existing: [] });
  assert.equal(client.entries.size, 3);
  let guardCalls = 0;
  const receipts = await __advanceRuntimeV2(client, { descriptor, role: "initiator", existing: [], beforeAnchor: () => { guardCalls += 1; } });
  assert.equal(receipts.length, 3);
  assert.equal(guardCalls, 0, "reads only: nothing to refuse");
});
