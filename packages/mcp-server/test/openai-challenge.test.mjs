// OpenAI's domain check: the exact token as plain text at /.well-known/openai-apps-challenge. Off when unset.
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";

import { runHttp } from "../dist/http.js";

const PATH = "/.well-known/openai-apps-challenge";
const KEYS = ["PORT", "MCP_PORT", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "OPENAI_APPS_CHALLENGE_TOKEN"];

async function boot(token) {
  const saved = {};
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_REQUIRE_AUTH: "1", ...(token === undefined ? {} : { OPENAI_APPS_CHALLENGE_TOKEN: token }) });
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

test("with a token: the exact bytes, as plain text, with no sign-in", async () => {
  const token = "abc123_DEF-456.xyz";
  const s = await boot(` ${token}\n`);
  try {
    const res = await fetch(`${s.url}${PATH}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /^text\/plain/);
    assert.equal(await res.text(), token, "no newline or padding");
    const head = await fetch(`${s.url}${PATH}`, { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get("content-length"), String(token.length));
    assert.notEqual((await fetch(`${s.url}${PATH}`, { method: "POST" })).status, 200);
    assert.notEqual((await fetch(`${s.url}${PATH}/x`)).status, 200);
  } finally {
    await s.close();
  }
});

for (const [label, value] of [["unset", undefined], ["empty", ""], ["with a space in it", "two words"]]) {
  test(`${label}: the path answers just as any unknown one does`, async () => {
    const s = await boot(value);
    try {
      const res = await fetch(`${s.url}${PATH}`);
      const unknown = await fetch(`${s.url}/.well-known/some-other-file`);
      assert.equal(res.status, unknown.status);
      assert.notEqual(res.status, 200);
      assert.equal(await res.text(), await unknown.text());
    } finally {
      await s.close();
    }
  });
}
