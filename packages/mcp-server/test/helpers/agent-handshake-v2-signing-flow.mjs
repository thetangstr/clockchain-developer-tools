// Every signing response of one handshake on the fixture harness, in order:
// both identity claims, the initiator's proposal, the responder's acceptance
// and both evidence requests; then, on a second harness, the responder's
// acceptance of the canonical fixture proposal. `h` is a fixture-harness
// module, so the same steps run against any build of the coordinator.
export async function signingResponses(h, options = {}) {
  const responses = {};
  const harness = await h.createFixtureHarness(options);
  responses.identity_claim_initiator = await harness.join("initiator");
  await harness.submitIdentity("initiator");
  responses.identity_claim_responder = await harness.join("responder");
  await harness.submitIdentity("responder");
  for (const role of ["initiator", "responder"]) {
    harness.push("agent_v2_funding_record", "host", { role, address: h.ADDRESSES[role] });
    const outcome = await harness.coordinator.next({ access: harness.accesses[role] });
    if (outcome.stage !== "party_ready") throw new Error(`expected party_ready for ${role}, got ${outcome.stage}`);
  }

  responses.proposal = await harness.coordinator.next({ access: harness.accesses.initiator });
  const proposalPayload = JSON.parse(h.signedBytesOf(h.signingRequestOf(responses.proposal)).toString("utf8"));
  const proposalEnvelope = {
    payload: proposalPayload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: h.ADDRESSES.initiator, algorithm: "eip191", value: h.sig(2, "initiator") },
  };
  await harness.coordinator.submitCheckpoint({ access: harness.accesses.initiator, artifactSignatureHex: h.sig(2, "initiator"), checkpoint: h.proposalCheckpointFor(proposalEnvelope) });
  await harness.coordinator.submit({ access: harness.accesses.initiator, policyDigest: h.F.parties.initiator.policyDigest, signatureHex: h.sig(2, "initiator") });

  harness.setClock(harness.now() + 5_000);
  responses.acceptance = await harness.coordinator.next({ access: harness.accesses.responder });
  await harness.submitAcceptance(h.signingRequestOf(responses.acceptance));
  harness.publishDescriptor();
  responses.evidence_initiator = await harness.coordinator.next({ access: harness.accesses.initiator });
  responses.evidence_responder = await harness.coordinator.next({ access: harness.accesses.responder });

  const canonical = await h.createFixtureHarness(options);
  await canonical.ready();
  canonical.publishProposal(h.clone(h.F.proposalEnvelope));
  canonical.setClock(h.ACCEPT_AT_MS);
  responses.acceptance_of_fixture_proposal = await canonical.coordinator.next({ access: canonical.accesses.responder });
  return responses;
}
