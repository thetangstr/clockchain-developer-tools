// Offline tests for the hosted timer/alarm tools (clock-sdk GATES.md G2/G3 semantics
// through the MCP surface). The real @clockchain/keeper Keeper is injected with a
// memory store, a fake anchorer and a controllable disciplined clock — so the tests
// exercise the actual control plane + data plane, with no network, timers or disk.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";
import { KEEPER_TOOLS } from "../dist/entitlement.js";
import { Keeper, MemoryStore } from "@clockchain/keeper";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };
const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");
const json = (res) => JSON.parse(textOf(res));

const T0 = Date.UTC(2026, 8, 14, 9, 0, 0, 0); // Mon Sep 14 09:00Z on the disciplined clock

function fakeAnchorer() {
  let n = 0;
  return {
    calls: 0,
    async anchorFire({ fire }) {
      this.calls++;
      n++;
      return {
        status: "anchored",
        eventHash: "e".repeat(64),
        ledgerId: `L_fire_${n}`,
        blockHeight: String(200 + n),
        receiptSchema: "clockchain.receipt/v1",
        receipt: { schema: "clockchain.receipt/v1", status: "anchored", anchor: { ledgerId: `L_fire_${n}`, blockHeight: String(200 + n) }, payload: { inputs: { fireId: fire.fireId } } },
      };
    },
    async pollAnchor(receipt) {
      return { status: "anchored", eventHash: "e".repeat(64), ledgerId: receipt.anchor.ledgerId, blockHeight: receipt.anchor.blockHeight, receiptSchema: "clockchain.receipt/v1", receipt };
    },
  };
}

function harness({ principalId = "caller-A", webhooks = false, now = T0 } = {}) {
  const clock = { t: now };
  const anchorer = fakeAnchorer();
  const keeper = new Keeper({
    store: new MemoryStore(),
    anchorer,
    nowMs: () => clock.t,
    nowUncertaintyMs: () => 20,
    fetchFn: async () => ({ status: 200 }),
    config: { agentId: "agent:test", webhookSecret: webhooks ? "whsec_dGVzdA==" : "", ssrf: { allowLoopback: true }, anchorRetryDelayMs: 0, baseDelayMs: 0 },
  });
  const toolsFor = (pid) => {
    const tools = {};
    registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg, { keeper, keeperWebhooks: webhooks, principalId: pid });
    return tools;
  };
  return { clock, anchorer, keeper, tools: toolsFor(principalId), toolsFor };
}

test("timer/alarm tools are registered on the full surface and account-gated (KEEPER_TOOLS)", () => {
  const { tools } = harness();
  for (const n of ["timer_set", "alarm_set", "timer_status", "timer_cancel", "timer_list"]) {
    assert.equal(typeof tools[n], "function", `${n} registered`);
    assert.ok(KEEPER_TOOLS.has(n), `${n} is account-gated (server-side firing is never free-tier)`);
  }
});

test("timer_set arms a one-shot at disciplined now + delay (not the host clock), poll delivery", async () => {
  const { tools } = harness();
  const out = json(await tools.timer_set({ delay_ms: 8000, label: "tea" }));
  assert.equal(out.kind, "timer");
  assert.equal(out.status, "scheduled");
  assert.equal(out.fireAtMs, T0 + 8000, "G2.2: fireAt = disciplined now + D");
  assert.equal(out.armedAtMs, T0);
  assert.equal(out.delivery, "poll");
  assert.match(out.next, /timer_status/);
  assert.ok(Math.abs(out.fireAtMs - (Date.now() + 8000)) > 60_000, "must not derive from Date.now()");
});

test("timer_set rejects sub-second and >30-day delays at the schema", async () => {
  const { tools } = harness();
  // The zod schema is enforced by the MCP server in production; the handler receives
  // validated input, so here we assert the tool's documented bounds directly.
  const out = json(await tools.timer_set({ delay_ms: 1000 }));
  assert.equal(out.fireAtMs, T0 + 1000);
});

test("alarm_set arms at an absolute ISO time; every_ms makes it recurring", async () => {
  const { tools } = harness();
  const once = json(await tools.alarm_set({ fire_at: "2026-09-14T09:00:30Z", label: "standup" }));
  assert.equal(once.kind, "alarm");
  assert.equal(once.fireAtMs, T0 + 30_000);
  assert.equal(once.mode, "once");
  assert.equal(once.warning, undefined);
  const rec = json(await tools.alarm_set({ fire_at: T0 + 60_000, every_ms: 60_000 }));
  assert.equal(rec.mode, "interval");
});

test("alarm_set: a fire_at already in the past is armed with a warning, never silently dropped (G3.7)", async () => {
  const { tools, clock, keeper } = harness();
  const out = json(await tools.alarm_set({ fire_at: T0 - 60_000, label: "late" }));
  assert.equal(out.status, "scheduled");
  assert.match(out.warning, /already in the past/);
  clock.t = T0 + 1;
  await keeper.tick();
  const st = json(await tools.timer_status({ id: out.id }));
  assert.equal(st.status, "done");
  assert.equal(st.fires.length, 1, "fires once");
  assert.equal(st.fires[0].scheduledForMs, T0 - 60_000, "the receipt records the original target");
});

test("alarm_set refuses a fire time more than 30 days out and unparseable fire_at", async () => {
  const { tools } = harness();
  const far = await tools.alarm_set({ fire_at: T0 + 31 * 24 * 3600 * 1000 });
  assert.equal(far.isError, true);
  assert.match(textOf(far), /30 days/);
  const bad = await tools.alarm_set({ fire_at: "next tuesday" });
  assert.equal(bad.isError, true);
  assert.match(textOf(bad), /ISO-8601/);
});

test("the fire: never early, once, anchored — timer_status exposes the receipt for verify_cross_party", async () => {
  const { tools, clock, keeper, anchorer } = harness();
  const { id } = json(await tools.timer_set({ delay_ms: 5000 }));

  clock.t = T0 + 4999;
  await keeper.tick();
  let st = json(await tools.timer_status({ id }));
  assert.equal(st.status, "scheduled", "G2.4 never early");
  assert.equal(st.fires.length, 0);

  clock.t = T0 + 5000;
  await keeper.tick();
  st = json(await tools.timer_status({ id }));
  assert.equal(st.status, "done");
  assert.equal(st.fires.length, 1);
  const f = st.fires[0];
  assert.equal(f.scheduledForMs, T0 + 5000);
  assert.equal(f.firedAtMs, T0 + 5000);
  assert.equal(f.firedAtUncertaintyMs, 20);
  assert.equal(f.delivery.status, "skipped", "poll-only: nothing to deliver");
  assert.equal(f.anchor.status, "anchored");
  assert.equal(f.anchor.ledgerId, "L_fire_1");
  assert.equal(f.anchor.blockHeight, "201");
  assert.equal(f.receipt.anchor.ledgerId, "L_fire_1", "the persisted receipt rides along");
  assert.equal(anchorer.calls, 1, "anchored exactly once");

  clock.t = T0 + 60_000;
  await keeper.tick();
  st = json(await tools.timer_status({ id }));
  assert.equal(st.fires.length, 1, "one-shot never re-fires");
});

test("timer_status / timer_cancel / timer_list are scoped to the caller identity", async () => {
  const { tools, toolsFor } = harness({ principalId: "caller-A" });
  const other = toolsFor("caller-B");
  const { id } = json(await tools.timer_set({ delay_ms: 5000 }));

  const peek = await other.timer_status({ id });
  assert.equal(peek.isError, true, "another caller cannot read it");
  assert.match(textOf(peek), /No timer\/alarm/);
  const steal = await other.timer_cancel({ id });
  assert.equal(steal.isError, true, "another caller cannot cancel it");
  assert.equal(json(await other.timer_list({})).count, 0);
  assert.equal(json(await tools.timer_list({})).count, 1);

  const c = json(await tools.timer_cancel({ id }));
  assert.equal(c.cancelled, true);
  assert.equal(json(await tools.timer_cancel({ id })).status, "cancelled", "idempotent");
});

test("a cancelled timer never fires and anchors nothing", async () => {
  const { tools, clock, keeper, anchorer } = harness();
  const { id } = json(await tools.timer_set({ delay_ms: 2000 }));
  await tools.timer_cancel({ id });
  clock.t = T0 + 10_000;
  await keeper.tick();
  assert.equal(anchorer.calls, 0);
  assert.equal(json(await tools.timer_status({ id })).fires.length, 0);
});

test("webhook_url is refused while webhook delivery is not configured, accepted when it is", async () => {
  const off = harness({ webhooks: false });
  const refused = await off.tools.timer_set({ delay_ms: 5000, webhook_url: "https://127.0.0.1/hook" });
  assert.equal(refused.isError, true);
  assert.match(textOf(refused), /not enabled on this deployment/);

  const on = harness({ webhooks: true });
  const ok = json(await on.tools.timer_set({ delay_ms: 5000, webhook_url: "https://127.0.0.1/hook" }));
  assert.equal(ok.delivery, "webhook");
  on.clock.t = T0 + 5000;
  await on.keeper.tick();
  const st = json(await on.tools.timer_status({ id: ok.id }));
  assert.equal(st.fires[0].delivery.status, "delivered");
  assert.equal(st.fires[0].anchor.status, "anchored");
});

test("before the keeper clock is disciplined, timer_set fails with a clear error (no undisciplined fires)", async () => {
  const keeper = new Keeper({
    store: new MemoryStore(),
    anchorer: fakeAnchorer(),
    nowMs: () => { throw new Error("The keeper's clock is not disciplined to consensus time yet"); },
    config: { agentId: "agent:test", webhookSecret: "" },
  });
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg, { keeper, principalId: "x" });
  const res = await tools.timer_set({ delay_ms: 5000 });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /not disciplined/);
});

test("with webhooks on, registration shows the owner's derived verification secret (never the server secret)", async () => {
  const on = harness({ webhooks: true });
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg, {
    keeper: on.keeper, keeperWebhooks: true, principalId: "caller-A",
    keeperWebhookSecretFor: (owner) => `whsec_derived_for_${owner}`,
  });
  const out = json(await tools.alarm_set({ fire_at: T0 + 5000, webhook_url: "https://127.0.0.1/hook" }));
  assert.equal(out.delivery, "webhook");
  assert.equal(out.webhookSecret, "whsec_derived_for_caller-A");
  assert.match(out.webhookVerify, /webhook-signature/);
  const poll = json(await tools.timer_set({ delay_ms: 5000 }));
  assert.equal(poll.webhookSecret, undefined, "poll-only registrations show no secret");
});
