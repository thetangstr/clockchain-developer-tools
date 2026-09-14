const IDENTITY_POLICY = { erc8004: "not_required", chainId: null, registryAddress: null };

export function validTerms(overrides = {}) {
  return {
    reference: "delivery-options-q3",
    purpose: "Discuss delivery options for Q3 orders",
    channelLimits: { durationSeconds: "3600", messageKinds: ["question", "proposal", "evidence"], maxMessageBytes: "16384" },
    identityPolicy: IDENTITY_POLICY,
    ...overrides,
  };
}

export function validReadiness(overrides = {}) {
  return {
    sessionKeyAddress: "0x" + "11".repeat(20),
    identity: null,
    authorityStatement: { accountableParty: "Acme Buying LLC", statement: "I am authorized to discuss delivery options for Acme." },
    authoritySignatureHex: "0x" + "11".repeat(64) + "1b",
    capabilityManifest: { dataHandlingClass: "confidential", purpose: "Discuss delivery options for Q3 orders" },
    ...overrides,
  };
}
