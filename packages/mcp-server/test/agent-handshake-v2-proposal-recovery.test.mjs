// H-REQ-02 with real EIP-191 recovery. The coordinator's production recovery
// (createRuntimeV2Coordinator -> recoverEip191Address in src/handshake/evm.ts)
// asks a JSON-RPC node for keccak256 of the EIP-191 message (web3_sha3) and
// for the ecrecover precompile at 0x…01 (eth_call). Here that production
// function runs unchanged with those two RPC answers computed locally (viem's
// keccak256 and secp256k1 recoverAddress), and separately the verifier runs
// with viem's recoverMessageAddress over the same canonical bytes.
import assert from "node:assert/strict";
import test from "node:test";

import { keccak256, recoverAddress, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { recoverEip191Address } from "../dist/handshake/evm.js";
import * as v2Protocol from "../dist/agent-handshake/v2/protocol.js";
import {
  ACCEPT_AT_MS,
  ADDRESSES,
  F,
  PROPOSAL_EXPIRES_MS,
  PROPOSAL_ISSUED_MS,
  REPOSITORY_SHA,
  SESSION_ID,
  TERMS,
  clone,
  createFixtureHarness,
  fixture,
} from "./helpers/agent-handshake-v2-fixture-harness.mjs";

// Public test keys of the reference fixture: the initiator is
// privateKeyToAccount(0x44…44); OTHER_KEY is any other key.
const INITIATOR = privateKeyToAccount(`0x${"4".repeat(64)}`);
const OTHER_KEY = privateKeyToAccount(`0x${"6".repeat(64)}`);
const ECRECOVER = "0x0000000000000000000000000000000000000001";
const proposalBytes = Buffer.from(fixture.canonical.proposal.bytesHex, "hex");

// The production function with its JSON-RPC node answered locally.
function productionRecovery() {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const { id, method, params } = JSON.parse(init.body);
    calls.push({ method, params });
    let result;
    if (method === "web3_sha3") {
      result = keccak256(params[0]);
    } else if (method === "eth_call" && params[0]?.to === ECRECOVER && params[1] === "latest") {
      const data = params[0].data.slice(2);
      const hash = `0x${data.slice(0, 64)}`;
      const v = Number.parseInt(data.slice(64, 128), 16);
      const signature = `0x${data.slice(128, 192)}${data.slice(192, 256)}${v.toString(16)}`;
      try {
        const address = await recoverAddress({ hash, signature });
        result = `0x${address.slice(2).toLowerCase().padStart(64, "0")}`;
      } catch {
        result = "0x"; // the precompile returns no output for an unrecoverable signature
      }
    } else {
      throw new Error(`unexpected JSON-RPC call ${method}`);
    }
    return { ok: true, status: 200, text: async () => JSON.stringify({ jsonrpc: "2.0", id, result }) };
  };
  return {
    calls,
    recover: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl: "http://rpc.test.invalid", fetchImpl }),
  };
}

const viemRecovery = () => ({
  calls: [],
  recover: async ({ bytes, signatureHex }) => recoverMessageAddress({ message: { raw: bytes }, signature: signatureHex }),
});

async function resignedBy(account, { claimAddress = account.address.toLowerCase(), payload = clone(F.proposalEnvelope.payload) } = {}) {
  const bytes = Buffer.from(v2Protocol.v2CanonicalRecord(payload).bytesHex, "hex");
  return {
    payload,
    schema: F.proposalEnvelope.schema,
    signature: { address: claimAddress, algorithm: "eip191", value: await account.signMessage({ message: { raw: bytes } }) },
  };
}

function withChangedBytes() {
  const envelope = clone(F.proposalEnvelope);
  envelope.payload.issuedAtMs = String(PROPOSAL_ISSUED_MS - 1_000);
  envelope.payload.expiresAtMs = String(PROPOSAL_EXPIRES_MS - 1_000);
  return envelope;
}

function verify(envelope, recover) {
  return v2Protocol.verifyV2ProposalEnvelope({
    envelope,
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedTerms: TERMS,
    nowMs: ACCEPT_AT_MS,
    recoverEip191Address: recover,
  });
}

const refused = (error) => error?.name === "AgentHandshakeV2ValidationError";

test("H-REQ-02: the fixture's proposal signature is the initiator test key's EIP-191 signature over its canonical bytes", async () => {
  assert.equal(INITIATOR.address.toLowerCase(), ADDRESSES.initiator);
  assert.equal(await INITIATOR.signMessage({ message: { raw: proposalBytes } }), F.proposalEnvelope.signature.value);
});

for (const [label, makeRecovery] of [["production recovery (evm.ts over local JSON-RPC)", productionRecovery], ["viem recoverMessageAddress", viemRecovery]]) {
  test(`H-REQ-02 (${label}): the fixture's proposal verifies`, async () => {
    const recovery = makeRecovery();
    const verified = await verify(clone(F.proposalEnvelope), recovery.recover);
    assert.deepEqual(verified.payload, F.proposalEnvelope.payload);
    if (makeRecovery === productionRecovery) {
      const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${proposalBytes.length}`, "utf8");
      assert.deepEqual(recovery.calls.map((call) => call.method), ["web3_sha3", "eth_call"]);
      assert.equal(recovery.calls[0].params[0], `0x${Buffer.concat([prefix, proposalBytes]).toString("hex")}`);
      assert.equal(recovery.calls[1].params[0].to, ECRECOVER);
    }
  });

  test(`H-REQ-02 (${label}): the exact proposal re-signed by a different key is refused`, async () => {
    const recovery = makeRecovery();
    const claimingInitiator = await resignedBy(OTHER_KEY, { claimAddress: ADDRESSES.initiator });
    const claimingItself = await resignedBy(OTHER_KEY);
    await assert.rejects(() => verify(claimingInitiator, recovery.recover), refused);
    await assert.rejects(() => verify(claimingItself, recovery.recover), refused);
  });

  test(`H-REQ-02 (${label}): a proposal whose bytes differ from those the initiator signed is refused`, async () => {
    const recovery = makeRecovery();
    await assert.rejects(() => verify(withChangedBytes(), recovery.recover), refused);
  });
}

test("H-REQ-02 (production recovery): the responder's coordinator accepts only the proposal signed by the initiator's key", async () => {
  const cases = [
    ["signed by the initiator's key", async () => clone(F.proposalEnvelope), true],
    ["re-signed by a different key", async () => resignedBy(OTHER_KEY, { claimAddress: ADDRESSES.initiator }), false],
    ["bytes differ from the signed bytes", async () => withChangedBytes(), false],
  ];
  for (const [name, envelope, accepted] of cases) {
    const harness = await createFixtureHarness({ realRecover: productionRecovery().recover });
    await harness.ready();
    harness.publishProposal(await envelope());
    harness.setClock(ACCEPT_AT_MS);
    if (accepted) {
      assert.equal((await harness.coordinator.next({ access: harness.accesses.responder })).stage, "sign_acceptance", name);
    } else {
      await assert.rejects(
        () => harness.coordinator.next({ access: harness.accesses.responder }),
        (error) => error?.name === "V2CoordinatorError" && error.detail === "proposal_unverified",
        name,
      );
      assert.ok(!(await harness.record("responder")).data.pending, name);
    }
  }
});
