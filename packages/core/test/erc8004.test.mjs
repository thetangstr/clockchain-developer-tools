// Unit tests for ERC-8004 ABI decoding + resolveAgent guards (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeAbiString, decodeAbiAddress, resolveAgent } from "../dist/index.js";

test("decodeAbiString decodes a dynamic string (tokenURI shape)", () => {
  // ABI string: offset=0x20, len=0x28 (40), data = "ipfs://QmTest-ERC8004-v1-Deployment-Test"
  const hex =
    "0x" +
    "0000000000000000000000000000000000000000000000000000000000000020" +
    "0000000000000000000000000000000000000000000000000000000000000028" +
    "697066733a2f2f516d546573742d455243383030342d76312d4465706c6f796d656e742d54657374" +
    "0000000000000000000000000000000000000000000000000000000000000000";
  assert.equal(decodeAbiString(hex), "ipfs://QmTest-ERC8004-v1-Deployment-Test");
});

test("decodeAbiAddress takes the last 20 bytes", () => {
  assert.equal(
    decodeAbiAddress("0x0000000000000000000000009b4cef62a0ce1671ccfefa6a6d8cbfa165c49831"),
    "0x9b4cef62a0ce1671ccfefa6a6d8cbfa165c49831",
  );
});

test("resolveAgent returns unknown when not configured", async () => {
  const r = await resolveAgent({ apiKey: "k", clientId: "c", walletId: "w", endpoint: "x" }, "1");
  assert.equal(r.status, "unknown");
});

test("resolveAgent returns unknown for a non-numeric agentId (no network call)", async () => {
  const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "x", evmRpcUrl: "http://unused", erc8004RegistryAddress: "0xabc" };
  const r = await resolveAgent(cfg, "agent:treasury-bot");
  assert.equal(r.status, "unknown");
});
