// Regression: production's mcp container sets EVM_RPC_URL, not SEPOLIA_RPC_URL. The
// standalone coordinator must still find an RPC, or every authority/consent signature
// fails recovery and the readiness checklist reports AUTHORITY_INVALID.
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveStandaloneRpcUrl } from "../dist/standalone-handshake/coordinator.js";

test("standalone coordinator falls back to EVM_RPC_URL (what the mcp container gets)", () => {
  assert.equal(resolveStandaloneRpcUrl({ EVM_RPC_URL: "https://rpc.example" }), "https://rpc.example");
  assert.equal(resolveStandaloneRpcUrl({ SEPOLIA_RPC_URL: "https://sep.example", EVM_RPC_URL: "https://rpc.example" }), "https://sep.example");
  assert.equal(resolveStandaloneRpcUrl({ SEPOLIA_RPC_URL: "", EVM_RPC_URL: "https://rpc.example" }), "https://rpc.example");
  assert.equal(resolveStandaloneRpcUrl({}), "");
});
