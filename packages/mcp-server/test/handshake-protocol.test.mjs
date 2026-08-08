import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildEvidencePackage,
  buildProposal,
  canonicalBytes,
  digestHex,
  generateRelayKeyPair,
  partySignatureBytes,
  preparePayerMandate,
  preparePaymentRequest,
  sealPayerMandate,
  sealPaymentRequest,
  sessionKey,
  signRelayEnvelope,
  verifyDescriptorEnvelope,
  verifyRelayEnvelope,
  verifyResultEnvelope,
} from "../dist/handshake/protocol.js";

const EIP191_PAYER_SIGNATURE = `0x${"11".repeat(65)}`;
const EIP191_PAYEE_SIGNATURE = `0x${"22".repeat(65)}`;

const BASE = Object.freeze({
  amount: { currency: "USD", value: "25" },
  intakeDigest: "a".repeat(64),
  intakeRequestId: "123e4567-e89b-42d3-a456-426614174000",
  invoiceReferencePrefix: "INV-2026-",
  payee: {
    address: "0x2222222222222222222222222222222222222222",
    agentId: "202",
  },
  payer: {
    address: "0x1111111111111111111111111111111111111111",
    agentId: "101",
  },
  purpose: "Bilateral test payment",
  releaseId: "release-2026-08-08",
  repositorySha: "b".repeat(40),
  sessionId: "123e4567-e89b-42d3-a456-426614174001",
  subjectRun: "rehearsal",
});

const DESCRIPTOR = Object.freeze({
  amountOptions: [
    { currency: "USD", value: "25" },
    { currency: "USD", value: "30.5" },
  ],
  chainId: "11155111",
  expirySeconds: "600",
  mandateDigest: "f06609e446e56a74d89fefe41b29188a86045f0e984088e905a96eabb71e87cb",
  namespace: "cbv1",
  payee: {
    address: BASE.payee.address,
    agentId: BASE.payee.agentId,
    displayName: "Payee Agent",
    role: "payee",
  },
  payer: {
    address: BASE.payer.address,
    agentId: BASE.payer.agentId,
    displayName: "Payer Agent",
    role: "payer",
  },
  paymentMoved: false,
  promptSha256: "a94eb709fb27abb1097000cbd3a43d5ba95444dcc70a5c670f3a2a8c4808e58c",
  protocol: "clockchain.bilateral-authorization/v1",
  protocolVersion: "1",
  registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  repositorySha: BASE.repositorySha,
  requestDigest: "234184816d6bb015c0cce20d2a4690197801d7344f25dbffb5398a66a6a48c99",
  schema: "clockchain.bilateral-session-descriptor/v2",
  sessionId: "123e4567e89b42d3a456426614174001",
  settlement: "not-executed",
});

const DESCRIPTOR_ENVELOPE = Object.freeze({
  descriptor: DESCRIPTOR,
  operator: {
    algorithm: "ed25519",
    keyId: "fixture-key",
    publicKey: "KhUZ0ONeIdNgNRf8wzWxbXS+u1W/y1mMgVe2e1rkh24=",
    signature: "60qhJ9XuH9s9WpU2XeJ80XMq8JhVFjafb7tFHTuMYDD1L9DAhY9dGmTXsQKsj6L8kP4oL0GAT6pRE0VgEqaPCA==",
  },
});

const SESSION_DIGEST = "14f0b85c15f46b2adf12a1efb1ea7118e6ca9672d2bfe689e8fde1d64042204b";
const PROPOSAL_DIGEST = "9269f712940dd1143a9e886eb1526f22454cedbdd9d13d3ee65b830f5310fa05";
const ACCEPTANCE_DIGEST = "0785030ea1f238cd6e282657557c564dd6b46d4b1ca82e9acaf152cdc10bf729";
const ACK_DIGEST = "2b3702df885fd5a30f00e3e8909495571ab2a7309e17c5e5381c7ce55d7ca98c";
const RESULT_DISCLAIMER =
  "Single-validator testnet: anchored and independently re-verifiable; not mainnet, court-grade, consensus-secure, or trustless.";

function sha256(bytes) {
  return createHash("sha256").update(bytes, "utf8").digest("hex");
}

function resultKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKeyRaw: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
  };
}

function signedResultEnvelope({ key = resultKey(), resultOverrides = {} } = {}) {
  const result = {
    anchors: [
      {
        blockHeight: "100",
        blockTimeRaw: "2026-08-08T12:00:00.000Z",
        digest: PROPOSAL_DIGEST,
        kind: "proposal",
        ledgerId: "123e4567-e89b-42d3-a456-426614174010",
      },
      {
        blockHeight: "101",
        blockTimeRaw: "2026-08-08T12:00:10.000Z",
        digest: ACCEPTANCE_DIGEST,
        kind: "acceptance",
        ledgerId: "123e4567-e89b-42d3-a456-426614174011",
      },
      {
        blockHeight: "102",
        blockTimeRaw: "2026-08-08T12:00:20.000Z",
        digest: ACK_DIGEST,
        kind: "acknowledgment",
        ledgerId: "123e4567-e89b-42d3-a456-426614174012",
      },
    ],
    disclaimer: RESULT_DISCLAIMER,
    issuedAtMs: "1786190430000",
    outcome: "AUTHORIZED",
    parties: {
      payee: {
        address: BASE.payee.address,
        agentId: BASE.payee.agentId,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${BASE.payee.agentId}`,
      },
      payer: {
        address: BASE.payer.address,
        agentId: BASE.payer.agentId,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${BASE.payer.agentId}`,
      },
    },
    paymentMoved: false,
    schema: "clockchain.handshake-result/v1",
    sessionDigest: SESSION_DIGEST,
    sessionId: BASE.sessionId,
    subjectRun: "rehearsal",
    ...resultOverrides,
  };
  const signer = {
    algorithm: "ed25519",
    keyId: "fixture-key",
    publicKey: key.publicKeyRaw,
    signature: sign(null, canonicalBytes(result), createPrivateKey(key.privateKeyPem)).toString("base64"),
  };
  return { envelope: { result, signer }, key };
}

function protocolFixture({
  proposalBlockTimeMs = "1786190400000",
  proposalBlockTimeRaw = "2026-08-08T12:00:00.000Z",
  acceptanceBlockTimeMs = "1786190410000",
  acceptanceBlockTimeRaw = "2026-08-08T12:00:10.000Z",
  acceptanceUpperBoundMs = "1786190411100",
  acknowledgmentBlockTimeMs = "1786190420000",
  acknowledgmentBlockTimeRaw = "2026-08-08T12:00:20.000Z",
  acknowledgmentUpperBoundMs = "1786190421100",
  nodeParticipationPct = "100",
} = {}) {
  const proposal = buildProposal({
    amount: { currency: "USD", value: "25" },
    descriptor: DESCRIPTOR,
    sessionDigest: SESSION_DIGEST,
  });
  const proposalTriple = authoritativeTriple({
    anchoredHash: digestHex(proposal),
    blockHeight: "100",
    kind: "proposal",
    ledgerId: "123e4567-e89b-42d3-a456-426614174010",
  });
  const acceptance = buildAcceptance({ proposal, proposalTriple });
  const acceptanceTriple = authoritativeTriple({
    anchoredHash: digestHex(acceptance),
    blockHeight: "101",
    kind: "acceptance",
    ledgerId: "123e4567-e89b-42d3-a456-426614174011",
  });
  const acknowledgment = buildAcknowledgment({
    acceptance,
    acceptanceTriple,
    proposalTriple,
  });
  const transitions = [
    {
      blockTimeMs: proposalBlockTimeMs,
      blockTimeRaw: proposalBlockTimeRaw,
      digest: digestHex(proposal),
      message: proposal,
      onChain: {
        anchoredHash: digestHex(proposal),
        blockHeight: "100",
        ledgerId: "123e4567-e89b-42d3-a456-426614174010",
      },
      upperBoundMs: null,
    },
    {
      blockTimeMs: acceptanceBlockTimeMs,
      blockTimeRaw: acceptanceBlockTimeRaw,
      digest: digestHex(acceptance),
      message: acceptance,
      onChain: {
        anchoredHash: digestHex(acceptance),
        blockHeight: "101",
        ledgerId: "123e4567-e89b-42d3-a456-426614174011",
      },
      upperBoundMs: acceptanceUpperBoundMs,
    },
    {
      blockTimeMs: acknowledgmentBlockTimeMs,
      blockTimeRaw: acknowledgmentBlockTimeRaw,
      digest: digestHex(acknowledgment),
      message: acknowledgment,
      onChain: {
        anchoredHash: digestHex(acknowledgment),
        blockHeight: "102",
        ledgerId: "123e4567-e89b-42d3-a456-426614174012",
      },
      upperBoundMs: acknowledgmentUpperBoundMs,
    },
  ];
  return {
    transitions,
    result: {
      ackObserved: true,
      deadlineMs: String(Number(proposalBlockTimeMs) + 600000),
      localVerdict: "LOCAL_OK",
      paymentMoved: false,
      poolHealth: {
        degradedAtSubmission: false,
        nodeParticipationPct,
        totalNodes: "3",
      },
      promptSha256: DESCRIPTOR.promptSha256,
      protocolVersion: "1",
      rendezvous: {
        channel: "derived-reference-id",
        degradedAtSubmission: false,
        tenancy: "cross-client",
      },
      repositorySha: BASE.repositorySha,
      role: "payer",
      schema: "clockchain.bilateral-party-result/v1",
      sessionDigest: SESSION_DIGEST,
      signature: {
        address: BASE.payer.address,
        algorithm: "eip191",
        signature: EIP191_PAYER_SIGNATURE,
      },
      transitions,
    },
  };
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function normalizedInvalidTimeFixture(raw, normalizedMs) {
  const acceptanceMs = normalizedMs + 10000;
  const acknowledgmentMs = normalizedMs + 20000;
  return protocolFixture({
    proposalBlockTimeMs: String(normalizedMs),
    proposalBlockTimeRaw: raw,
    acceptanceBlockTimeMs: String(acceptanceMs),
    acceptanceBlockTimeRaw: iso(acceptanceMs),
    acceptanceUpperBoundMs: String(acceptanceMs + 1100),
    acknowledgmentBlockTimeMs: String(acknowledgmentMs),
    acknowledgmentBlockTimeRaw: iso(acknowledgmentMs),
    acknowledgmentUpperBoundMs: String(acknowledgmentMs + 1100),
  });
}

test("handshake protocol primitives match source-generated parity fixture", () => {
  assert.equal(
    canonicalBytes({ z: "last", a: ["first", false, null] }).toString("utf8"),
    "{\"a\":[\"first\",false,null],\"z\":\"last\"}",
  );
  assert.equal(
    digestHex({ z: "last", a: ["first", false, null] }),
    "8469848dd897c1163094bd63873950b5c7ef622967c76cacf1406ce191353642",
  );

  const mandate = preparePayerMandate({
    ...BASE,
    expiresAtMs: "1786191000000",
    issuedAtMs: "1786190400000",
  });
  const mandateEnvelope = sealPayerMandate(mandate, EIP191_PAYER_SIGNATURE);
  assert.equal(digestHex(mandateEnvelope.mandate), DESCRIPTOR.mandateDigest);
  assert.equal(mandateEnvelope.signature.address, BASE.payer.address);

  const request = preparePaymentRequest({
    ...BASE,
    createdAtMs: "1786190460000",
    expiresAtMs: "1786190900000",
    invoiceReference: "INV-2026-0001",
    mandateDigest: DESCRIPTOR.mandateDigest,
    requestId: "123e4567-e89b-42d3-a456-426614174002",
  });
  const requestEnvelope = sealPaymentRequest(request, EIP191_PAYEE_SIGNATURE);
  assert.equal(digestHex(requestEnvelope.request), DESCRIPTOR.requestDigest);
  assert.equal(requestEnvelope.signature.address, BASE.payee.address);

  assert.deepEqual(
    verifyDescriptorEnvelope(DESCRIPTOR_ENVELOPE, {
      repositoryPublicKey: DESCRIPTOR_ENVELOPE.operator.publicKey,
    }),
    { descriptor: DESCRIPTOR, sessionDigest: SESSION_DIGEST },
  );

  const proposal = buildProposal({
    amount: { currency: "USD", value: "25" },
    descriptor: DESCRIPTOR,
    sessionDigest: SESSION_DIGEST,
  });
  assert.equal(digestHex(proposal), PROPOSAL_DIGEST);
  assert.equal(
    sessionKey(SESSION_DIGEST, "proposal"),
    `cbv1:${SESSION_DIGEST}:proposal`,
  );

  const proposalTriple = authoritativeTriple({
    anchoredHash: PROPOSAL_DIGEST,
    blockHeight: "100",
    kind: "proposal",
    ledgerId: "123e4567-e89b-42d3-a456-426614174010",
  });
  const acceptance = buildAcceptance({ proposal, proposalTriple });
  assert.equal(digestHex(acceptance), ACCEPTANCE_DIGEST);

  const acceptanceTriple = authoritativeTriple({
    anchoredHash: ACCEPTANCE_DIGEST,
    blockHeight: "101",
    kind: "acceptance",
    ledgerId: "123e4567-e89b-42d3-a456-426614174011",
  });
  const acknowledgment = buildAcknowledgment({
    acceptance,
    acceptanceTriple,
    proposalTriple,
  });
  assert.equal(digestHex(acknowledgment), ACK_DIGEST);

  const transitions = [
    {
      blockTimeMs: "1786190400000",
      blockTimeRaw: "2026-08-08T12:00:00.000Z",
      digest: PROPOSAL_DIGEST,
      message: proposal,
      onChain: {
        anchoredHash: PROPOSAL_DIGEST,
        blockHeight: "100",
        ledgerId: "123e4567-e89b-42d3-a456-426614174010",
      },
      upperBoundMs: null,
    },
    {
      blockTimeMs: "1786190410000",
      blockTimeRaw: "2026-08-08T12:00:10.000Z",
      digest: ACCEPTANCE_DIGEST,
      message: acceptance,
      onChain: {
        anchoredHash: ACCEPTANCE_DIGEST,
        blockHeight: "101",
        ledgerId: "123e4567-e89b-42d3-a456-426614174011",
      },
      upperBoundMs: "1786190411100",
    },
    {
      blockTimeMs: "1786190420000",
      blockTimeRaw: "2026-08-08T12:00:20.000Z",
      digest: ACK_DIGEST,
      message: acknowledgment,
      onChain: {
        anchoredHash: ACK_DIGEST,
        blockHeight: "102",
        ledgerId: "123e4567-e89b-42d3-a456-426614174012",
      },
      upperBoundMs: "1786190421100",
    },
  ];

  assert.equal(
    partySignatureBytes({
      role: "payer",
      sessionDigest: SESSION_DIGEST,
      transitions,
    }).toString("utf8"),
    "{\"messages\":[{\"amount\":{\"currency\":\"USD\",\"moved\":false,\"value\":\"25\"},\"expirySeconds\":\"600\",\"kind\":\"proposal\",\"payee\":{\"address\":\"0x2222222222222222222222222222222222222222\",\"agentId\":\"202\"},\"payer\":{\"address\":\"0x1111111111111111111111111111111111111111\",\"agentId\":\"101\",\"reference\":\"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:101\"},\"predecessor\":null,\"protocol\":\"clockchain.bilateral-authorization/v1\",\"schema\":\"clockchain.bilateral-transition/v1\",\"sequence\":\"1\",\"sessionDigest\":\"14f0b85c15f46b2adf12a1efb1ea7118e6ca9672d2bfe689e8fde1d64042204b\"},{\"amount\":{\"currency\":\"USD\",\"moved\":false,\"value\":\"25\"},\"expirySeconds\":\"600\",\"kind\":\"acknowledgment\",\"outcome\":\"ACKNOWLEDGED\",\"payee\":{\"address\":\"0x2222222222222222222222222222222222222222\",\"agentId\":\"202\"},\"payer\":{\"address\":\"0x1111111111111111111111111111111111111111\",\"agentId\":\"101\",\"reference\":\"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:101\"},\"paymentMoved\":false,\"predecessor\":{\"anchoredHash\":\"0785030ea1f238cd6e282657557c564dd6b46d4b1ca82e9acaf152cdc10bf729\",\"blockHeight\":\"101\",\"kind\":\"acceptance\",\"ledgerId\":\"123e4567-e89b-42d3-a456-426614174011\"},\"proposal\":{\"anchoredHash\":\"9269f712940dd1143a9e886eb1526f22454cedbdd9d13d3ee65b830f5310fa05\",\"blockHeight\":\"100\",\"kind\":\"proposal\",\"ledgerId\":\"123e4567-e89b-42d3-a456-426614174010\"},\"protocol\":\"clockchain.bilateral-authorization/v1\",\"schema\":\"clockchain.bilateral-transition/v1\",\"sequence\":\"3\",\"sessionDigest\":\"14f0b85c15f46b2adf12a1efb1ea7118e6ca9672d2bfe689e8fde1d64042204b\"}],\"role\":\"payer\",\"schema\":\"clockchain.bilateral-party-signature/v1\",\"sessionDigest\":\"14f0b85c15f46b2adf12a1efb1ea7118e6ca9672d2bfe689e8fde1d64042204b\"}",
  );

  const resultFixture = {
    ackObserved: true,
    deadlineMs: "1786191000000",
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: {
      degradedAtSubmission: false,
      nodeParticipationPct: "100",
      totalNodes: "3",
    },
    promptSha256: DESCRIPTOR.promptSha256,
    protocolVersion: "1",
    rendezvous: {
      channel: "derived-reference-id",
      degradedAtSubmission: false,
      tenancy: "cross-client",
    },
    repositorySha: BASE.repositorySha,
    role: "payer",
    schema: "clockchain.bilateral-party-result/v1",
    sessionDigest: SESSION_DIGEST,
    signature: {
      address: BASE.payer.address,
      algorithm: "eip191",
      signature: EIP191_PAYER_SIGNATURE,
    },
    transitions,
  };
  const evidence = buildEvidencePackage(resultFixture);
  assert.equal(sha256(evidence.json), "2d4e25708dc49ccd28185296585047a8cb136bfb7aa01ebd9b63b8b64db78545");
  assert.equal(sha256(evidence.markdown), "117401a971de54274073eb6f67407ee24f5a9b083add10a57b754fc0ffc58cb3");
  assert.equal(
    evidence.marker,
    "{\"jsonSha256\":\"2d4e25708dc49ccd28185296585047a8cb136bfb7aa01ebd9b63b8b64db78545\",\"markdownSha256\":\"117401a971de54274073eb6f67407ee24f5a9b083add10a57b754fc0ffc58cb3\",\"schema\":\"clockchain.bilateral-party-result-completion/v1\"}\n",
  );

  const generatedRelayKeys = generateRelayKeyPair();
  assert.match(generatedRelayKeys.privateKeyPem, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.match(generatedRelayKeys.publicKeyPem, /^-----BEGIN PUBLIC KEY-----\n/);
  assert.match(generatedRelayKeys.senderKey, /^[A-Za-z0-9+/]{43}=$/);

  const relayEnvelope = signRelayEnvelope({
    body: proposal,
    kind: "proposal",
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHevky4ubEDTtlBZ+4B1nTe7K61KjFUg0DuVa3KmDpzs\n-----END PRIVATE KEY-----\n",
    role: "payer",
    senderKey: "Klg+xF8O3z+lLsQDXa7kWbnKNLJ/HYc0GWU/OBjjzIY=",
    seq: "1",
    sessionId: BASE.sessionId,
  });
  assert.equal(relayEnvelope.sig, "qC6hYB640Gg+5vuOrE3qKEtWEYXoNgtyfSlBQg0YtSKrgxL0CzVn8MdNBYcBonAblkVm7TpZGbw4f2k8noKYBA==");
  assert.equal(verifyRelayEnvelope(relayEnvelope), true);
});

test("descriptor and proposal validation fail closed on reviewed edge cases", () => {
  assert.throws(
    () => verifyDescriptorEnvelope(
      {
        descriptor: {
          ...DESCRIPTOR,
          amountOptions: [
            { currency: "USD", value: "30.5" },
            { currency: "USD", value: "25" },
          ],
        },
        operator: DESCRIPTOR_ENVELOPE.operator,
      },
      { repositoryPublicKey: DESCRIPTOR_ENVELOPE.operator.publicKey },
    ),
    /Handshake protocol validation failed/,
  );

  assert.throws(
    () => buildProposal({
      amount: { currency: "USD", value: "29.99" },
      descriptor: DESCRIPTOR,
      sessionDigest: SESSION_DIGEST,
    }),
    /Handshake protocol validation failed/,
  );
});

test("party signature and evidence validation enforce transition chain and role semantics", () => {
  const proposal = buildProposal({
    amount: { currency: "USD", value: "25" },
    descriptor: DESCRIPTOR,
    sessionDigest: SESSION_DIGEST,
  });
  const proposalTriple = authoritativeTriple({
    anchoredHash: digestHex(proposal),
    blockHeight: "100",
    kind: "proposal",
    ledgerId: "123e4567-e89b-42d3-a456-426614174010",
  });
  const acceptance = buildAcceptance({ proposal, proposalTriple });

  assert.throws(
    () => partySignatureBytes({
      role: "payer",
      sessionDigest: SESSION_DIGEST,
      transitions: [
        {
          blockTimeMs: "1786190400000",
          blockTimeRaw: "2026-08-08T12:00:00.000Z",
          digest: digestHex(proposal),
          message: proposal,
          onChain: {
            anchoredHash: digestHex(proposal),
            blockHeight: "100",
            ledgerId: "123e4567-e89b-42d3-a456-426614174010",
          },
          upperBoundMs: null,
        },
        {
          blockTimeMs: "1786190410000",
          blockTimeRaw: "2026-08-08T12:00:10.000Z",
          digest: digestHex(acceptance),
          message: acceptance,
          onChain: {
            anchoredHash: digestHex(acceptance),
            blockHeight: "101",
            ledgerId: "123e4567-e89b-42d3-a456-426614174011",
          },
          upperBoundMs: "1786190411100",
        },
      ],
    }),
    /Handshake protocol validation failed/,
  );

  assert.throws(
    () => buildEvidencePackage({
      ackObserved: false,
      deadlineMs: "1786191000000",
      localVerdict: "LOCAL_OK",
      paymentMoved: false,
      poolHealth: {
        degradedAtSubmission: false,
        nodeParticipationPct: "100",
        totalNodes: "3",
      },
      promptSha256: DESCRIPTOR.promptSha256,
      protocolVersion: "1",
      rendezvous: {
        channel: "derived-reference-id",
        degradedAtSubmission: false,
        tenancy: "cross-client",
      },
      repositorySha: BASE.repositorySha,
      role: "payer",
      schema: "clockchain.bilateral-party-result/v1",
      sessionDigest: SESSION_DIGEST,
      signature: {
        address: BASE.payee.address,
        algorithm: "eip191",
        signature: EIP191_PAYER_SIGNATURE,
      },
      transitions: [],
    }),
    /Handshake protocol validation failed/,
  );
});

test("non-proposal upper bounds after the proposal deadline fail closed", () => {
  const { result, transitions } = protocolFixture({
    acceptanceBlockTimeMs: "1786191001000",
    acceptanceBlockTimeRaw: "2026-08-08T12:10:01.000Z",
    acceptanceUpperBoundMs: "1786191002100",
    acknowledgmentBlockTimeMs: "1786191002000",
    acknowledgmentBlockTimeRaw: "2026-08-08T12:10:02.000Z",
    acknowledgmentUpperBoundMs: "1786191003100",
  });

  assert.throws(
    () => partySignatureBytes({
      role: "payer",
      sessionDigest: SESSION_DIGEST,
      transitions,
    }),
    /Handshake protocol validation failed/,
  );
  assert.throws(
    () => buildEvidencePackage(result),
    /Handshake protocol validation failed/,
  );
});

test("canonical block times reject Date.UTC calendar normalization in signatures and evidence", () => {
  const invalidCases = [
    ["2026-13-08T12:00:00.000Z", Date.UTC(2026, 12, 8, 12, 0, 0, 0)],
    ["2026-02-30T12:00:00.000Z", Date.UTC(2026, 1, 30, 12, 0, 0, 0)],
    ["2026-08-08T24:00:00.000Z", Date.UTC(2026, 7, 8, 24, 0, 0, 0)],
    ["2026-08-08T12:60:00.000Z", Date.UTC(2026, 7, 8, 12, 60, 0, 0)],
    ["2026-08-08T12:00:60.000Z", Date.UTC(2026, 7, 8, 12, 0, 60, 0)],
  ];
  for (const [raw, normalizedMs] of invalidCases) {
    const { result, transitions } = normalizedInvalidTimeFixture(raw, normalizedMs);
    assert.throws(
      () => partySignatureBytes({
        role: "payer",
        sessionDigest: SESSION_DIGEST,
        transitions,
      }),
      /Handshake protocol validation failed/,
      raw,
    );
    assert.throws(
      () => buildEvidencePackage(result),
      /Handshake protocol validation failed/,
      raw,
    );
  }
});

test("pool participation percentage is a canonical decimal quantity capped at 100", () => {
  assert.doesNotThrow(() => buildEvidencePackage(protocolFixture({ nodeParticipationPct: "100" }).result));
  assert.doesNotThrow(() => buildEvidencePackage(protocolFixture({ nodeParticipationPct: "100.0" }).result));
  assert.throws(
    () => buildEvidencePackage(protocolFixture({ nodeParticipationPct: "101" }).result),
    /Handshake protocol validation failed/,
  );
  assert.throws(
    () => buildEvidencePackage(protocolFixture({ nodeParticipationPct: "100.1" }).result),
    /Handshake protocol validation failed/,
  );
});

test("result envelope verification checks exact schema, signature, and expected operator key", () => {
  const { envelope, key } = signedResultEnvelope();
  assert.equal(
    verifyResultEnvelope(envelope, { expectedPublicKey: key.publicKeyRaw }).outcome,
    "AUTHORIZED",
  );

  assert.throws(
    () => verifyResultEnvelope({
      ...envelope,
      result: { ...envelope.result, outcome: "EXPIRED" },
    }, { expectedPublicKey: key.publicKeyRaw }),
    /Handshake protocol validation failed/,
  );

  const stranger = resultKey();
  assert.throws(
    () => verifyResultEnvelope(envelope, { expectedPublicKey: stranger.publicKeyRaw }),
    /Handshake protocol validation failed/,
  );
});
