// Keeper MCP control-plane tools: keeper_schedule / keeper_list / keeper_cancel.
// Drives the handlers directly (same technique as mcp-server's coverage test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keeper, MemoryStore, registerKeeperTools } from "../dist/index.js";

const okAnchorer = {
  anchorFire: async () => ({ status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "1", receiptSchema: "clockchain.receipt/v1", receipt: {} }),
  pollAnchor: async () => ({ status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "1", receiptSchema: "clockchain.receipt/v1", receipt: {} }),
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

test("requireIdentity (HTTP/prod): identity-less list/cancel/schedule are REFUSED (no IDOR)", async () => {
  const keeper = makeKeeper();
  // A real tenant seeds a trigger.
  const owner = collect(keeper, { requestSub: () => "byok:owner", requireIdentity: true });
  await owner.keeper_schedule({ fire_at: 1000, target_url: "https://127.0.0.1/h" });

  // A caller with the shared bearer but NO x-clockchain-api-key -> no identity.
  const anon = collect(keeper, { requestSub: () => undefined, requireIdentity: true });

  // list must NOT fall through to "see everything".
  const listRes = await anon.keeper_list({ sub: "byok:owner" });
  assert.equal(listRes.isError, true);
  assert.match(listRes.content[0].text, /No caller identity/);

  // cancel must NOT skip ownership.
  const cancelRes = await anon.keeper_cancel({ id: "x", sub: "byok:owner" });
  assert.equal(cancelRes.isError, true);
  assert.match(cancelRes.content[0].text, /No caller identity/);

  // schedule must NOT accept a client-supplied owner.
  const schedRes = await anon.keeper_schedule({ fire_at: 1, target_url: "https://127.0.0.1/h", sub: "byok:owner" });
  assert.equal(schedRes.isError, true);
  assert.match(schedRes.content[0].text, /No caller identity/);

  // The owner's data is untouched and still visible only to them.
  const ownerList = payload(await owner.keeper_list({}));
  assert.equal(ownerList.count, 1);
});

test("requireIdentity ignores a client-supplied sub even when an identity IS present", async () => {
  const keeper = makeKeeper();
  const a = collect(keeper, { requestSub: () => "byok:a", requireIdentity: true });
  // Try to plant a trigger under another owner via the sub arg — must be ignored.
  const sched = payload(await a.keeper_schedule({ fire_at: 1000, target_url: "https://127.0.0.1/h", sub: "byok:victim" }));
  assert.ok(sched.id);
  // It belongs to byok:a, not byok:victim.
  const victim = collect(keeper, { requestSub: () => "byok:victim", requireIdentity: true });
  assert.equal(payload(await victim.keeper_list({})).count, 0);
  assert.equal(payload(await a.keeper_list({})).count, 1);
});
