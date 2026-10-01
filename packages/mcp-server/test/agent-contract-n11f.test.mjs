import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { loadContractConfig, missingDefaultHostRoots } from "../dist/agent-contract/config.js";
import { createContractService } from "../dist/agent-contract/service.js";
import {
  HOST_ROOTS, SIGNER, POLICY_DIGEST, uuid,
  boot, agreePair, makeApproval, keys, signedSubmit,
} from "./n4b9-harness.mjs";

// N11f (founder D21): CONTRACT_POLICY_DIGESTS accepts a SET of digests per
// role (`buyer:0xA|0xB,provider:0xC`) — the buyer digest rotates every run
// (the single-use mandate lives in the buyer policy), so pinning a batch
// ahead avoids an SSM write + restart per run. A single value per role
// keeps working. Hard cap 64 per role; exact lowercase-hex validation.
//
// Plus the N7C doc/parser hazards: CONTRACT_ERC8004_CHAIN_ID normalizes a
// decimal input to the certificate's `eip155:<n>` wire value, the registry
// address compares case-insensitively (certificates carry lowercase; the
// doc showed checksummed), and CONTRACT_HOST_ROOTS replaces the default
// root list (documented; missing root-2026-08 warns at startup in http.ts).

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder";
const D_A = `0x${"aa".repeat(32)}`;
const D_B = `0x${"bb".repeat(32)}`;
const D_C = `0x${"cc".repeat(32)}`;

function baseEnv(overrides = {}) {
  return {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: `buyer:${D_A},provider:${D_C}`,
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n11f-")),
    ...overrides,
  };
}

// ---- item 1: policy digest sets -------------------------------------------

test("single digest per role still parses (old format)", () => {
  const cfg = loadContractConfig(baseEnv());
  assert.equal(cfg.kind, "ready");
  cfg.service.close();
  assert.deepEqual([...cfg.policyDigests.buyer], [D_A]);
  assert.deepEqual([...cfg.policyDigests.provider], [D_C]);
});

test("set format: multiple digests per role via |", () => {
  const cfg = loadContractConfig(baseEnv({
    CONTRACT_POLICY_DIGESTS: `buyer:${D_A}|${D_B},provider:${D_C}`,
  }));
  assert.equal(cfg.kind, "ready");
  cfg.service.close();
  assert.deepEqual(new Set(cfg.policyDigests.buyer), new Set([D_A, D_B]));
  assert.deepEqual([...cfg.policyDigests.provider], [D_C]);
});

test("digest-set parsing refuses malformed/over-cap/unknown-role input", () => {
  const bad = [
    `buyer:${D_A}|,provider:${D_C}`,                        // empty segment
    `buyer:|${D_A},provider:${D_C}`,                        // leading empty
    `buyer:${D_A}||${D_B},provider:${D_C}`,                 // doubled pipe
    `buyer:${D_A.toUpperCase()},provider:${D_C}`,           // uppercase hex
    `buyer:${D_A},provider:${"0x" + "0".repeat(64)}`,       // zero digest
    `buyer:${D_A},provider:${D_C},admin:${D_B}`,            // unknown role
    `buyer:${D_A.slice(0, -1)},provider:${D_C}`,            // short digest
    `buyer:${D_A}|${D_A},provider:${D_C}`,                  // duplicate in set is fine
  ];
  // all but the last must misconfigure; the duplicate collapses to one pin
  for (const raw of bad.slice(0, -1)) {
    const cfg = loadContractConfig(baseEnv({ CONTRACT_POLICY_DIGESTS: raw }));
    assert.equal(cfg.kind, "misconfigured", raw);
  }
  const dup = loadContractConfig(baseEnv({ CONTRACT_POLICY_DIGESTS: bad.at(-1) }));
  assert.equal(dup.kind, "ready");
  dup.service.close();
  assert.equal(dup.policyDigests.buyer.size, 1);
});

test("the per-role cap is 64 digests", () => {
  // 65 distinct valid digests exceeds the per-role cap
  const many = Array.from({ length: 65 }, (_, i) => `0x${(i + 1).toString(16).padStart(64, "0")}`);
  const cfg = loadContractConfig(baseEnv({
    CONTRACT_POLICY_DIGESTS: `buyer:${many.join("|")},provider:${D_C}`,
  }));
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /64/);
  // exactly 64 is allowed
  const ok = loadContractConfig(baseEnv({
    CONTRACT_POLICY_DIGESTS: `buyer:${many.slice(0, 64).join("|")},provider:${D_C}`,
  }));
  assert.equal(ok.kind, "ready");
  ok.service.close();
});

test("service accepts string | array | Set per role and normalizes to sets", () => {
  const stateDir = () => mkdtempSync(path.join(tmpdir(), "n11f-svc-"));
  const svc1 = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: stateDir(),
    policyDigests: { buyer: POLICY_DIGEST, provider: [D_C, D_A] },
  });
  svc1.close();
  const svc2 = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: stateDir(),
    policyDigests: { buyer: new Set([POLICY_DIGEST]), provider: D_C },
  });
  svc2.close();
  assert.throws(() => createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: stateDir(),
    policyDigests: { buyer: [], provider: D_C },
  }), /policyDigests/);
  assert.throws(() => createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: stateDir(),
    policyDigests: { buyer: "not-a-digest", provider: D_C },
  }), /policyDigests/);
  const overCap = Array.from({ length: 65 }, (_, i) => `0x${(i + 1).toString(16).padStart(64, "0")}`);
  assert.throws(() => createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: stateDir(),
    policyDigests: { buyer: overCap, provider: D_C },
  }), /policyDigests/);
});

test("end to end: a digest inside the set approves, an unknown digest is refused", async () => {
  const OTHER = `0x${"ee".repeat(32)}`;
  const env = await boot({
    policyDigests: { buyer: [POLICY_DIGEST, OTHER], provider: [`0x${"dd".repeat(32)}`, POLICY_DIGEST] },
    allowLegacySealV2: true,
  });
  try {
    const sessionId = uuid(9101);
    const { agreementId } = await agreePair(env, sessionId, "tb1", "tp1");
    // An approval carrying a digest inside the role's set approves; one
    // outside it is refused.
    const prepared = await env.callTool("tp1", "booking_prepare", { agreementId });
    const bad = makeApproval({
      envelope: prepared.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
      policyDigest: `0x${"ff".repeat(32)}`, // NOT in the set
    });
    const refused = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared,
      submitTool: "booking_execute", extraArgs: { approval: bad },
    });
    assert.equal(refused.error, "APPROVAL_INVALID", JSON.stringify(refused));
    // The refused attempt consumed that nonce; prepare afresh for the good one.
    const prepared2 = await env.callTool("tp1", "booking_prepare", { agreementId });
    const good2 = makeApproval({
      envelope: prepared2.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
      policyDigest: POLICY_DIGEST,
    });
    const ok = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared: prepared2,
      submitTool: "booking_execute", extraArgs: { approval: good2 },
    });
    assert.equal(ok.error, undefined, JSON.stringify(ok));
  } finally {
    env.close();
  }
});

// ---- item 2: N7C parser/doc hazards ----------------------------------------

test("CONTRACT_ERC8004_CHAIN_ID accepts eip155:<n> or a bare decimal", () => {
  const eip = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "eip155:11155111", CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e" }));
  assert.equal(eip.kind, "ready");
  eip.service.close();
  assert.equal(eip.expectedErc8004.chainId, "eip155:11155111");

  const dec = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "11155111", CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e" }));
  assert.equal(dec.kind, "ready");
  dec.service.close();
  assert.equal(dec.expectedErc8004.chainId, "eip155:11155111", "decimal input normalizes to eip155:<n>");

  for (const bad of ["mainnet", "eip155:", "0x1", "eip155:abc", "155111.5", "0", "eip155:0", "011155111", "eip155:007", "1".repeat(21)]) {
    const cfg = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: bad, CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e" }));
    assert.equal(cfg.kind, "misconfigured", bad);
  }
});

test("CONTRACT_ERC8004_REGISTRY_ADDRESS normalizes case to lowercase", () => {
  const checksummed = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
  const cfg = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "eip155:11155111", CONTRACT_ERC8004_REGISTRY_ADDRESS: checksummed }));
  assert.equal(cfg.kind, "ready");
  cfg.service.close();
  assert.equal(cfg.expectedErc8004.registryAddress, checksummed.toLowerCase());
  const bad = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "eip155:11155111", CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x1234" }));
  assert.equal(bad.kind, "misconfigured");
});

test("bind honors a normalized pin: decimal chain + checksummed registry still verify", async () => {
  // The certificate carries chainId "eip155:11155111" and the lowercase
  // Sepolia registry (n4b9-harness). Provisioning the decimal chain id and
  // the checksummed address must NOT refuse the bind.
  const cfg = loadContractConfig(baseEnv({
    CONTRACT_ERC8004_CHAIN_ID: "11155111",
    CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    // the harness mints certs under "root-test" — pin it so verification
    // reaches the ERC-8004 compares instead of failing on the root.
    CONTRACT_HOST_ROOTS: `${HOST_ROOTS[0].kid}:${HOST_ROOTS[0].fingerprint}`,
  }));
  assert.equal(cfg.kind, "ready");
  const { createContractHttpHandler, tokenAuthenticator, parseContractTokens } =
    await import("../dist/agent-contract/http-handler.js");
  const { createServer } = await import("node:http");
  const handler = createContractHttpHandler({
    authenticate: tokenAuthenticator(parseContractTokens(TOKENS)),
    hostRoots: cfg.hostRoots,
    signer: cfg.signer,
    service: cfg.service,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const baseUrl = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
    const callTool = async (token, name, args = {}) => {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
      });
      const sid = init.headers.get("mcp-session-id");
      await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
      const res = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const text = await res.text();
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      const body = JSON.parse(data ? data.slice(5) : text);
      if (body.error !== undefined) return { rpcError: body.error };
      return body.result?.structuredContent ?? {};
    };
    const { mintCertificate, rootKey } = await import("./n4b9-harness.mjs");
    const { generateKeyPairSync } = await import("node:crypto");
    const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(9102) });
    const bound = await callTool("tb1", "contract_bind", {
      certificate: cert,
      signerKey: { keyId: keys.buyerSigner.keyId, publicKeyHex: keys.buyerSigner.publicKeyHex },
      approvalKey: { keyId: keys.buyerApproval.keyId, publicKeyHex: keys.buyerApproval.publicKeyHex },
    });
    assert.equal(bound.bound, true, JSON.stringify(bound));
  } finally {
    srv.close();
    cfg.service.close();
  }
});

test("missingDefaultHostRoots names the default root when CONTRACT_HOST_ROOTS drops it", () => {
  const dflt = loadContractConfig(baseEnv());
  assert.equal(dflt.kind, "ready");
  dflt.service.close();
  assert.deepEqual(missingDefaultHostRoots(dflt.hostRoots), []);

  const replaced = loadContractConfig(baseEnv({
    CONTRACT_HOST_ROOTS: `${HOST_ROOTS[0].kid}:${HOST_ROOTS[0].fingerprint}`,
  }));
  assert.equal(replaced.kind, "ready");
  replaced.service.close();
  assert.deepEqual(missingDefaultHostRoots(replaced.hostRoots), ["root-2026-08"]);

  const both = loadContractConfig(baseEnv({
    CONTRACT_HOST_ROOTS: `${HOST_ROOTS[0].kid}:${HOST_ROOTS[0].fingerprint},root-2026-08:da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8`,
  }));
  assert.equal(both.kind, "ready");
  both.service.close();
  assert.deepEqual(missingDefaultHostRoots(both.hostRoots), []);
});

// ---- review LOWs (L1-L4) ---------------------------------------------------

test("L1: a repeated role in CONTRACT_POLICY_DIGESTS is refused, not merged", () => {
  const cfg = loadContractConfig(baseEnv({
    CONTRACT_POLICY_DIGESTS: `buyer:${D_A},buyer:${D_B},provider:${D_C}`,
  }));
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /buyer/);
});

test("L2: chain id is a canonical positive decimal of at most 20 digits", () => {
  const ok = loadContractConfig(baseEnv({
    CONTRACT_ERC8004_CHAIN_ID: "1".repeat(20),
    CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
  }));
  assert.equal(ok.kind, "ready");
  ok.service.close();
  assert.equal(ok.expectedErc8004.chainId, `eip155:${"1".repeat(20)}`);
});

test("L3: the ERC-8004 pins are both set or both unset", () => {
  const onlyChain = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "11155111" }));
  assert.equal(onlyChain.kind, "misconfigured");
  assert.match(onlyChain.reason, /ERC8004/);
  const onlyReg = loadContractConfig(baseEnv({ CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e" }));
  assert.equal(onlyReg.kind, "misconfigured");
  assert.match(onlyReg.reason, /ERC8004/);
  const neither = loadContractConfig(baseEnv());
  assert.equal(neither.kind, "ready");
  neither.service.close();
  // compose-injected empty strings count as unset
  const empties = loadContractConfig(baseEnv({ CONTRACT_ERC8004_CHAIN_ID: "", CONTRACT_ERC8004_REGISTRY_ADDRESS: "" }));
  assert.equal(empties.kind, "ready");
  empties.service.close();
});

test("L4: the service refuses the zero digest in any pin form", () => {
  const zero = `0x${"0".repeat(64)}`;
  for (const pin of [zero, [D_A, zero], new Set([zero])]) {
    assert.throws(() => createContractService({
      hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: mkdtempSync(path.join(tmpdir(), "n11f-z-")),
      policyDigests: { buyer: pin, provider: D_C },
    }), /policyDigests/);
  }
});
