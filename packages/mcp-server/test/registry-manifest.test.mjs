// server.json and its Shadow draft: within the registry schema's limits, and saying only what is true of this deployment.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const load = (name) => JSON.parse(readFileSync(fileURLToPath(new URL(`../../../${name}`, import.meta.url)), "utf8"));

for (const name of ["server.json", "server.shadow.draft.json"]) {
  test(`${name}: within the schema's limits, and no claim of a network we don't run`, () => {
    const m = load(name);
    assert.match(m.name, /^network\.clockchain\/[a-z]+$/);
    assert.ok(m.description.length >= 1 && m.description.length <= 100, `the schema allows 100 characters, not ${m.description.length}`);
    assert.ok(m.title.length <= 100);
    assert.match(m.description, /Testnet/);
    assert.doesNotMatch(JSON.stringify(m), /consensus|on-chain|decentrali[sz]ed|neutral|independent|complian|audited/i);
  });
}

test("the Shadow draft is its own server, on the listed path with OAuth, and can't be published by accident", () => {
  const m = load("server.shadow.draft.json");
  assert.deepEqual(m.remotes, [{ type: "streamable-http", url: "https://mcp.clockchain.network/shadow/mcp" }], "no x-api-key: Shadow refuses it");
  assert.match(m.___DRAFT_WARNING, /DO NOT feed this file to mcp-publisher/);
});

test("server.json stays on /mcp with its key, as that is what that endpoint takes", () => {
  const m = load("server.json");
  assert.deepEqual(m.remotes.map((r) => r.url), ["https://mcp.clockchain.network/mcp"]);
  assert.equal(m.remotes[0].headers[0].name, "x-api-key");
});
