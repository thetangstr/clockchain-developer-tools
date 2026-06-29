// Keeper MCP control-plane tools: keeper_schedule / keeper_list / keeper_cancel.
// Drives the handlers directly (same technique as mcp-server's coverage test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keeper, MemoryStore, registerKeeperTools } from "../dist/index.js";

const okAnchorer = {
  anchorFire: async () => ({ status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "1", receiptSchema: "clockchain.receipt/v1" }),
};

function makeKeeper() {
  return new Keeper({
    store: new MemoryStore(),
    anchorer: okAnchorer,
    nowMs: () => 1_000,
    fetchFn: async () => ({ status: 200 }),
    config: { agentId: "agent:test", webhookSecret: "s", ssrf: { allowLoopback: true } },
  });
}

function collect(keeper, opts) {
  const tools = {};
  registerKeeperTools({ registerTool: (name, _c, handler) => (tools[name] = handler) }, keeper, opts);
  return tools;
}

const payload = (res) => JSON.parse(res.content.map((c) => c.text).join("\n"));

test("registers exactly keeper_schedule / keeper_list / keeper_cancel", () => {
  const tools = collect(makeKeeper());
  assert.deepEqual(Object.keys(tools).sort(), ["keeper_cancel", "keeper_list", "keeper_schedule"]);
});

test("keeper_schedule registers a trigger and keeper_list returns it", async () => {
  const keeper = makeKeeper();
  const tools = collect(keeper);

  const sched = payload(await tools.keeper_schedule({ fire_at: 5_000, target_url: "https://127.0.0.1/h", payload: { a: 1 }, sub: "u1" }));
  assert.ok(sched.id);
  assert.equal(sched.status, "scheduled");
  assert.equal(sched.fireAtMs, 5_000);

  const list = payload(await tools.keeper_list({ sub: "u1" }));
  assert.equal(list.count, 1);
  assert.equal(list.triggers[0].id, sched.id);
});

test("keeper_schedule parses ISO-8601 fire_at", async () => {
  const tools = collect(makeKeeper());
  const sched = payload(await tools.keeper_schedule({ fire_at: "2030-01-01T00:00:00Z", target_url: "https://127.0.0.1/h", sub: "u1" }));
  assert.equal(sched.fireAtMs, Date.parse("2030-01-01T00:00:00Z"));
});

test("keeper_schedule reports an SSRF rejection as an MCP error", async () => {
  const keeper = new Keeper({
    store: new MemoryStore(),
    anchorer: okAnchorer,
    nowMs: () => 1_000,
    config: { agentId: "a", webhookSecret: "s", ssrf: {} }, // loopback NOT allowed
  });
  const tools = collect(keeper);
  const res = await tools.keeper_schedule({ fire_at: 1, target_url: "http://10.0.0.1/h", sub: "u1" });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /private\/loopback\/metadata/);
});

test("keeper_cancel cancels an owned trigger; missing returns cancelled:false", async () => {
  const keeper = makeKeeper();
  const tools = collect(keeper);
  const sched = payload(await tools.keeper_schedule({ fire_at: 5_000, target_url: "https://127.0.0.1/h", sub: "u1" }));

  const cancelled = payload(await tools.keeper_cancel({ id: sched.id, sub: "u1" }));
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.status, "cancelled");

  const missing = payload(await tools.keeper_cancel({ id: "nope", sub: "u1" }));
  assert.equal(missing.cancelled, false);
});

test("requestSub (BYO-key identity) overrides the sub argument and scopes tenancy", async () => {
  const keeper = makeKeeper();
  // Caller A's identity is fixed by the transport; their `sub` arg is ignored.
  const toolsA = collect(keeper, { requestSub: () => "byok:aaaa" });
  await toolsA.keeper_schedule({ fire_at: 1000, target_url: "https://127.0.0.1/h", sub: "spoofed" });

  const toolsB = collect(keeper, { requestSub: () => "byok:bbbb" });
  const listB = payload(await toolsB.keeper_list({}));
  assert.equal(listB.count, 0, "tenant B cannot see tenant A's triggers");

  const listA = payload(await toolsA.keeper_list({}));
  assert.equal(listA.count, 1);
});
