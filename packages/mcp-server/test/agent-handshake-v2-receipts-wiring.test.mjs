import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";

// Boots the REAL runHttp wiring: env -> loadHandshakeReceiptsConfig -> dispatch.

const KEYS = [
  "PORT", "MCP_PORT", "HANDSHAKE_V2_RECEIPTS", "HANDSHAKE_V2_RECEIPT_ED25519_SEED",
  "HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM", "HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN",
  "HANDSHAKE_V2_RECEIPTS_ALLOW_EPHEMERAL_KEY", "CONTRACT_OBSERVER_TOKEN", "HANDSHAKE_RELAY",
];

async function boot(env) {
  const saved = {};
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0" }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      await new Promise((r) => server.close(r));
      for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

const SESSION = "11111111-2222-4333-8444-555555555555";
const get = (url, path, headers = {}) => fetch(`${url}${path}`, { headers });

test("flag unset: the receipt routes are exactly as absent as any unknown path", async () => {
  const s = await boot({});
  try {
    const unknown = await get(s.url, "/handshake/no-such-route");
    for (const path of [`/handshake/receipts?sessionId=${SESSION}`, "/handshake/receipt-keys"]) {
      const r = await get(s.url, path, { authorization: "Bearer anything" });
      assert.equal(r.status, unknown.status);
      assert.equal(await r.text(), await unknown.clone().text());
    }
  } finally {
    await s.close();
  }
});

test("flag on but misconfigured (no seed): recording is off and the routes refuse closed with 503", async () => {
  const s = await boot({ HANDSHAKE_V2_RECEIPTS: "1" });
  try {
    for (const path of [`/handshake/receipts?sessionId=${SESSION}`, "/handshake/receipt-keys"]) {
      const r = await get(s.url, path);
      assert.equal(r.status, 503);
      assert.deepEqual(await r.json(), { error: "handshake_receipts_unavailable" });
    }
  } finally {
    await s.close();
  }
});
