import { test } from "node:test";
import assert from "node:assert/strict";
import {
  recoverEip191Address,
  resolveOwnedAgentId,
} from "../dist/handshake/evm.js";

const RPC_URL = "https://rpc.example.test";
const ADDRESS = "0x1111111111111111111111111111111111111111";
const REGISTRY = "0x2222222222222222222222222222222222222222";
const SEPOLIA_ERC8004_REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const DIGEST = "0x" + "aa".repeat(32);
const RECOVERED_WORD = "0x" + "00".repeat(12) + ADDRESS.slice(2);
const SIG =
  "0x" +
  "11".repeat(32) +
  "22".repeat(32) +
  "1b";

function rpcFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    assert.equal(url, RPC_URL);
    const body = JSON.parse(init.body);
    calls.push(body);
    const result = handler(body);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
    };
  };
  return { calls, fetchImpl };
}

test("recoverEip191Address hashes the EIP-191 message and recovers through ecrecover", async () => {
  const { calls, fetchImpl } = rpcFetch((body) => {
    if (body.method === "web3_sha3") return DIGEST;
    if (body.method === "eth_call") return RECOVERED_WORD;
    throw new Error(`unexpected ${body.method}`);
  });

  const recovered = await recoverEip191Address({
    rpcUrl: RPC_URL,
    bytes: "hello",
    signatureHex: SIG,
    fetchImpl,
  });

  assert.equal(recovered, ADDRESS);
  assert.deepEqual(calls.map((c) => c.method), ["web3_sha3", "eth_call"]);
  assert.equal(calls[0].params[0], "0x19457468657265756d205369676e6564204d6573736167653a0a3568656c6c6f");
  assert.equal(calls[1].params[0].to, "0x0000000000000000000000000000000000000001");
  assert.match(calls[1].params[0].data, /^0x(a{64})(0{62}1b)(1{64})(2{64})$/);
});

test("recoverEip191Address rejects non-65-byte hex signatures before RPC", async () => {
  let called = false;
  await assert.rejects(
    recoverEip191Address({
      rpcUrl: RPC_URL,
      bytes: "hello",
      signatureHex: "0x1234",
      fetchImpl: async () => {
        called = true;
      },
    }),
    /65-byte hex EIP-191 signature/,
  );
  assert.equal(called, false);
});

test("recoverEip191Address rejects malformed JSON-RPC envelopes", async () => {
  const malformed = [
    { jsonrpc: "1.0", id: 1, result: DIGEST },
    { jsonrpc: "2.0", id: 2, result: DIGEST },
    { jsonrpc: "2.0", id: 1, result: DIGEST, error: { code: -32000, message: "bad" } },
    { jsonrpc: "2.0", id: 1 },
    { jsonrpc: "2.0", id: 1, error: { code: "-32000", message: "bad" } },
    { jsonrpc: "2.0", id: 1, error: { code: -32000, message: 42 } },
    null,
  ];

  for (const envelope of malformed) {
    await assert.rejects(
      recoverEip191Address({
        rpcUrl: RPC_URL,
        bytes: "hello",
        signatureHex: SIG,
        fetchImpl: async () => ({
          ok: true,
          status: 200,
          text: async () => JSON.stringify(envelope),
        }),
      }),
      /invalid JSON-RPC response envelope/i,
    );
  }
});

test("resolveOwnedAgentId returns the newest acquired token still owned by the address", async () => {
  const oldToken = "0x" + "00".repeat(31) + "01";
  const newToken = "0x" + "00".repeat(31) + "02";
  const logs = [
    { address: REGISTRY, blockNumber: "0x10", logIndex: "0x1", topics: ["0xtransfer", "0xfrom", "0xto", oldToken] },
    { address: REGISTRY, blockNumber: "0x12", logIndex: "0x0", topics: ["0xtransfer", "0xfrom", "0xto", newToken] },
  ];
  const { calls, fetchImpl } = rpcFetch((body) => {
    if (body.method === "eth_blockNumber") return "0x20";
    if (body.method === "eth_getLogs") return logs;
    if (body.method === "eth_call") return body.params[0].data.endsWith(newToken.slice(2)) ? RECOVERED_WORD : "0x" + "00".repeat(32);
    throw new Error(`unexpected ${body.method}`);
  });

  const agentId = await resolveOwnedAgentId({
    rpcUrl: RPC_URL,
    registryAddress: REGISTRY,
    address: ADDRESS,
    fromBlock: "0x0",
    fetchImpl,
  });

  assert.equal(agentId, "2");
  const filter = calls.find((c) => c.method === "eth_getLogs").params[0];
  assert.equal(filter.address, REGISTRY);
  assert.equal(filter.fromBlock, "0x0");
  assert.equal(filter.toBlock, "0x20");
  assert.equal(filter.topics[2], "0x000000000000000000000000" + ADDRESS.slice(2));
});

test("resolveOwnedAgentId returns null when acquired tokens are no longer owned", async () => {
  const token = "0x" + "00".repeat(31) + "03";
  const { fetchImpl } = rpcFetch((body) => {
    if (body.method === "eth_blockNumber") return "0x1";
    if (body.method === "eth_getLogs") {
      return [{ address: REGISTRY, blockNumber: "0x1", logIndex: "0x0", topics: ["0xtransfer", "0xfrom", "0xto", token] }];
    }
    if (body.method === "eth_call") return "0x" + "00".repeat(32);
    throw new Error(`unexpected ${body.method}`);
  });

  assert.equal(
    await resolveOwnedAgentId({ rpcUrl: RPC_URL, registryAddress: REGISTRY, address: ADDRESS, fetchImpl }),
    null,
  );
});

test("resolveOwnedAgentId scans newest-first in provider-safe 50,000-block chunks", async () => {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    calls.push(body);
    let result;
    if (body.method === "eth_blockNumber") result = "0x1869f"; // 99,999
    else if (body.method === "eth_getLogs") result = [];
    else throw new Error(`unexpected ${body.method}`);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
    };
  };

  assert.equal(
    await resolveOwnedAgentId({
      rpcUrl: RPC_URL,
      registryAddress: REGISTRY,
      address: ADDRESS,
      fromBlock: "0x0",
      fetchImpl,
    }),
    null,
  );
  const ranges = calls
    .filter((call) => call.method === "eth_getLogs")
    .map((call) => call.params[0])
    .map(({ fromBlock, toBlock }) => [BigInt(fromBlock), BigInt(toBlock)]);
  assert.deepEqual(ranges, [
    [50_000n, 99_999n],
    [0n, 49_999n],
  ]);
});

test("resolveOwnedAgentId defaults the canonical Sepolia ERC-8004 registry to its creation block", async () => {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    calls.push(body);
    let result;
    if (body.method === "eth_blockNumber") result = "0x9878f0"; // 9,992,432
    else if (body.method === "eth_getLogs") result = [];
    else throw new Error(`unexpected ${body.method}`);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
    };
  };

  assert.equal(
    await resolveOwnedAgentId({
      rpcUrl: RPC_URL,
      registryAddress: SEPOLIA_ERC8004_REGISTRY,
      address: ADDRESS,
      fetchImpl,
    }),
    null,
  );

  const filter = calls.find((call) => call.method === "eth_getLogs").params[0];
  assert.equal(BigInt(filter.fromBlock), 9_989_393n);
});

test("resolveOwnedAgentId canonical Sepolia default works at current height and chunks newest-first", async () => {
  const latest = 11_444_194n;
  const creation = 9_989_393n;
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    calls.push(body);
    let result;
    if (body.method === "eth_blockNumber") result = `0x${latest.toString(16)}`;
    else if (body.method === "eth_getLogs") result = [];
    else throw new Error(`unexpected ${body.method}`);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
    };
  };

  assert.equal(
    await resolveOwnedAgentId({
      rpcUrl: RPC_URL,
      registryAddress: SEPOLIA_ERC8004_REGISTRY,
      address: ADDRESS,
      fetchImpl,
    }),
    null,
  );

  const ranges = calls
    .filter((call) => call.method === "eth_getLogs")
    .map((call) => call.params[0])
    .map(({ fromBlock, toBlock }) => [BigInt(fromBlock), BigInt(toBlock)]);
  assert.equal(ranges.length, Number((latest - creation) / 50_000n) + 1);
  assert.deepEqual(ranges[0], [latest - 49_999n, latest]);
  assert.equal(ranges.at(-1)[0], creation);
  for (let i = 0; i < ranges.length; i += 1) {
    const [from, to] = ranges[i];
    assert.ok(to - from + 1n <= 50_000n);
    if (i > 0) assert.equal(to, ranges[i - 1][0] - 1n);
  }
});

test("resolveOwnedAgentId honors explicit fromBlock over canonical registry default", async () => {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    calls.push(body);
    let result;
    if (body.method === "eth_blockNumber") result = "0x20";
    else if (body.method === "eth_getLogs") result = [];
    else throw new Error(`unexpected ${body.method}`);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
    };
  };

  await resolveOwnedAgentId({
    rpcUrl: RPC_URL,
    registryAddress: SEPOLIA_ERC8004_REGISTRY,
    address: ADDRESS,
    fromBlock: "0x10",
    fetchImpl,
  });

  const filter = calls.find((call) => call.method === "eth_getLogs").params[0];
  assert.equal(filter.fromBlock, "0x10");
});

test("resolveOwnedAgentId fails clearly when the reverse scan range exceeds the cap", async () => {
  const { fetchImpl } = rpcFetch((body) => {
    if (body.method === "eth_blockNumber") return "0x500001";
    throw new Error(`unexpected ${body.method}`);
  });

  await assert.rejects(
    resolveOwnedAgentId({
      rpcUrl: RPC_URL,
      registryAddress: REGISTRY,
      address: ADDRESS,
      fromBlock: "0x0",
      fetchImpl,
    }),
    /reverse ERC-721 Transfer scan range exceeds/i,
  );
});

test("resolveOwnedAgentId fails clearly when ownerOf candidate probes exceed the cap", async () => {
  const logs = Array.from({ length: 33 }, (_, index) => {
    const token = "0x" + BigInt(index + 1).toString(16).padStart(64, "0");
    return { address: REGISTRY, blockNumber: "0x20", logIndex: `0x${index.toString(16)}`, topics: ["0xtransfer", "0xfrom", "0xto", token] };
  });
  const { fetchImpl } = rpcFetch((body) => {
    if (body.method === "eth_blockNumber") return "0x20";
    if (body.method === "eth_getLogs") return logs;
    if (body.method === "eth_call") return "0x" + "00".repeat(32);
    throw new Error(`unexpected ${body.method}`);
  });

  await assert.rejects(
    resolveOwnedAgentId({
      rpcUrl: RPC_URL,
      registryAddress: REGISTRY,
      address: ADDRESS,
      fromBlock: "0x0",
      fetchImpl,
    }),
    /ownerOf candidate probe cap exceeded/i,
  );
});
