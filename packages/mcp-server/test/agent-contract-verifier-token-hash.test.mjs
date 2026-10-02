/**
 * CONTRACT_VERIFIER_TOKEN may be configured as `sha256:<64 lowercase hex>` —
 * the digest of the verifier's bearer — so whoever reads the SSM value (the
 * orchestrator) cannot present it. Plaintext config keeps today's behaviour.
 * A malformed `sha256:` value fails closed on every request and logs once.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { startContractEvidenceServer } from "../dist/agent-contract/evidence-routes.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";

const VERIFIER_BEARER = "verifier-bearer-9f3c1e";
const DIGEST = createHash("sha256").update(VERIFIER_BEARER, "utf8").digest("hex");

// The routes only call saltFor/receiptFeed/preBindFeed; a stub isolates auth.
const SALT = { scope: "run", id: "run-1", salt: "ab".repeat(32) };
const service = {
  saltFor: () => SALT,
  receiptFeed: () => ({ runId: "run-1", receipts: [], head: "h" }),
  preBindFeed: () => undefined,
};

async function status(url, token) {
  const headers = token === undefined ? {} : { authorization: `Bearer ${token}` };
  return (await fetch(url, { headers })).status;
}

async function withEvidence(options, fn) {
  const ev = await startContractEvidenceServer({ service, allowFeed: () => true, ...options });
  try {
    await fn(ev.url);
  } finally {
    await ev.close();
  }
}

test("hashed verifier config accepts the bearer whose sha256 matches", async () => {
  await withEvidence({ verifierToken: `sha256:${DIGEST}` }, async (url) => {
    const res = await fetch(`${url}/contract/run-salt?runId=run-1`, {
      headers: { authorization: `Bearer ${VERIFIER_BEARER}` },
    });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), SALT);
  });
});

test("hashed verifier config rejects a wrong bearer and a missing bearer", async () => {
  await withEvidence({ verifierToken: `sha256:${DIGEST}` }, async (url) => {
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, "wrong-bearer"), 401);
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`), 401);
  });
});

test("hashed verifier config rejects the digest itself presented as the bearer", async () => {
  await withEvidence({ verifierToken: `sha256:${DIGEST}` }, async (url) => {
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, `sha256:${DIGEST}`), 401);
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, DIGEST), 401);
  });
});

test("malformed sha256: verifier config fails closed on every request and logs a clear line", async () => {
  for (const bad of [
    "sha256:",
    `sha256:${DIGEST.slice(0, 63)}`,
    `sha256:${DIGEST}00`,
    `sha256:${DIGEST.toUpperCase()}`,
    `sha256:${"z".repeat(64)}`,
  ]) {
    const logged = [];
    const orig = console.error;
    console.error = (...args) => logged.push(args.join(" "));
    try {
      await withEvidence({ verifierToken: bad }, async (url) => {
        // Neither the real bearer, the literal config string, nor its tail opens it.
        assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, VERIFIER_BEARER), 401, bad);
        assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, bad), 401, bad);
        assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, bad.slice(7) || "x"), 401, bad);
      });
    } finally {
      console.error = orig;
    }
    assert.ok(
      logged.some((l) => /CONTRACT_VERIFIER_TOKEN/.test(l) && /sha256:/.test(l) && /fail/i.test(l)),
      `expected a fail-closed log line for ${JSON.stringify(bad)}, got ${JSON.stringify(logged)}`,
    );
  }
});

test("plaintext verifier config is unchanged", async () => {
  await withEvidence({ verifierToken: "ver-plain", observerToken: "obs-plain" }, async (url) => {
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, "ver-plain"), 200);
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, "wrong"), 401);
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, "obs-plain"), 401);
    const plainDigest = createHash("sha256").update("ver-plain").digest("hex");
    assert.equal(await status(`${url}/contract/run-salt?runId=run-1`, `sha256:${plainDigest}`), 401);
    assert.equal(await status(`${url}/contract/receipts?runId=run-1`, "obs-plain"), 200);
  });
});

test("config: a hashed verifier token that is the digest of the observer token is misconfigured", () => {
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tok:buyer:k1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"),
    CONTRACT_POLICY_DIGESTS: `buyer:0x${"1".repeat(64)},provider:0x${"2".repeat(64)}`,
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_OBSERVER_TOKEN: VERIFIER_BEARER,
    CONTRACT_VERIFIER_TOKEN: `sha256:${DIGEST}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-hash-same-")),
  };
  const cfg = loadContractConfig(env);
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /verifier|observer/i);

  const ok = loadContractConfig({
    ...env,
    CONTRACT_OBSERVER_TOKEN: "a-different-observer-token",
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-hash-ok-")),
  });
  assert.equal(ok.kind, "ready");
  assert.equal(ok.verifierToken, `sha256:${DIGEST}`);
});
