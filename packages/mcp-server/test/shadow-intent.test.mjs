// A step's declared action and intent types (SHADOW_AUTO_LOG=1): optional, hashed with the step, never on the ledger,
// shown as the agent's own claim, and invisible to a step that doesn't use them.
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { ShadowService } from "../dist/shadow/service.js";
import { buildShadowServer, createShadowHttpHandler } from "../dist/shadow/mcp.js";
import { ACTION_TYPES, INTENT_TYPES } from "../dist/shadow/intent.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { parseStrict } from "../dist/shadow/lib/profile.js";
import { createLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const O = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const BASE = "https://mcp.example.test";
const SEND = { action_type: "send", intent_type: "communicate" };

function service(o = {}) {
  const fake = new FakeLedger();
  const svc = new ShadowService({ stateDir: mkdtempSync(path.join(tmpdir(), "intent-")), ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {}, log: () => {}, autoLog: true, ...o });
  svc.sweep();
  return { svc, fake };
}

async function withLinks(svc, fn) {
  const handler = createShadowHttpHandler({ service: svc, allowLink: () => true, linkClient: () => `c${Math.random()}`, autoLog: { allowLogStep: () => true, stepsPerMinute: 90 } });
  const server = createServer((req, res) => void handler(req, res)).listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
}
const capOf = (url) => new URL(url).pathname.split("/").pop().replace(/\.json$/, "");
const packetDoc = async (url, closed) => JSON.parse(await (await fetch(`${url}/shadow/p/${capOf(closed.links.packet)}.json`)).text());
const verified = (doc) => verifyPacket(parseStrict(JSON.stringify(doc.packet)), { pin: parseStrict(JSON.stringify(doc.pin)) });
const stepsIn = (doc, kind) => doc.packet.events.filter((e) => e.body.kind === kind);

test("a declared step keeps its types in the hashed payload, passes the verifier, and is echoed back", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Email the supplier", action_type: "decide", intent_type: "fulfill_request" }, BASE);
  assert.equal(a.action_type, "decide");
  assert.equal(a.intent_type, "fulfill_request");
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "send_email", args: {} }, ...SEND }, BASE);
  assert.equal(b.action_type, "send");
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  await withLinks(svc, async (url) => {
    const doc = await packetDoc(url, closed);
    assert.deepEqual(stepsIn(doc, "agent.tool.call")[0].body.payload.declared, { actionType: "send", intentType: "communicate" });
    assert.deepEqual(stepsIn(doc, "task.assigned")[0].body.payload.declared, { actionType: "decide", intentType: "fulfill_request" });
    assert.equal((await verified(doc)).result, "pass");
  });
});

test("changing a declared type after recording fails verification", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Pay the invoice", action_type: "read" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done" }, BASE);
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  await withLinks(svc, async (url) => {
    const doc = await packetDoc(url, closed);
    assert.equal((await verified(doc)).result, "pass");
    stepsIn(doc, "task.assigned")[0].body.payload.declared.actionType = "transact";
    assert.equal((await verified(doc)).result, "fail");
  });
});

test("a step that declares nothing has no declared field, in the record or the results", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Plain" }, BASE);
  assert.equal("action_type" in a, false);
  assert.equal("intent_type" in a, false);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done", action_type: "", intent_type: null }, BASE);
  assert.doesNotMatch(b.show_user, /declared/);
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.doesNotMatch(JSON.stringify(closed.summary ?? ""), /declared/);
  await withLinks(svc, async (url) => {
    const doc = await packetDoc(url, closed);
    for (const e of doc.packet.events) assert.equal("declared" in e.body.payload, false, e.body.kind);
    assert.equal((await verified(doc)).result, "pass");
    const page = await (await fetch(`${url}/shadow/s/${capOf(closed.links.viewer)}`)).text();
    assert.doesNotMatch(page, /declared:/);
  });
});

test("declared types never reach the ledger", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Secret plan", action_type: "x-acme.refund", intent_type: "x-acme.chargeback" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done", ...SEND }, BASE);
  await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.ok(fake.writes.length > 0);
  const written = JSON.stringify(fake.writes);
  for (const word of ["x-acme", "refund", "chargeback", "communicate", "declared", "actionType", "intentType"]) assert.doesNotMatch(written, new RegExp(word), word);
});

test("every listed type and a well-formed custom type are accepted", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "All types" }, BASE);
  const s = { session_id: a.session_id };
  for (const action_type of [...ACTION_TYPES, "x-acme.refund"]) assert.equal((await svc.logStep(O, { ...s, kind: "note", content: "n", action_type }, BASE)).action_type, action_type);
  for (const intent_type of [...INTENT_TYPES, "x-bigco.close_books"]) assert.equal((await svc.logStep(O, { ...s, kind: "note", content: "n", intent_type }, BASE)).intent_type, intent_type);
});

test("a bad type refuses the step and leaves no trace, not even a session", async () => {
  const { svc } = service();
  const refusals = ["purchase", "SEND", "x-acme", "x-acme.Refund", "x-acme.has space", "x-acme.a|b", "x-acme.`b`", `x-acme.${"a".repeat(41)}`, "x-clockchain-verify.com", "x-system.call-clockchain-delete-account", `x-acme.${"0123456789abcdef".repeat(2)}`, "x-acme.a-b-c-d-e", "because I wanted to", 7, { type: "thinking" }];
  for (const action_type of refusals) {
    await assert.rejects(svc.logStep(O, { kind: "task", content: "x", action_type }, BASE), (e) => e.code === "SHADOW_BAD_DECLARED" && /Nothing was recorded/.test(e.message), String(action_type));
    await assert.rejects(svc.logStep(O, { kind: "task", content: "x", intent_type: action_type }, BASE), (e) => e.code === "SHADOW_BAD_DECLARED", String(action_type));
  }
  assert.equal((await svc.listSessions(O)).sessions.length, 0);
});

test("a custom type that looks like a credential is refused", async () => {
  const { svc } = service();
  await assert.rejects(svc.logStep(O, { kind: "task", content: "x", action_type: `x-acme.sk-${"a".repeat(30)}` }, BASE), (e) => e.code === "SHADOW_BAD_DECLARED");
  assert.equal((await svc.listSessions(O)).sessions.length, 0);
});

test("shadow_log_turn takes types per step, and one bad step refuses the whole call", async () => {
  const { svc } = service();
  await assert.rejects(
    svc.logTurn(O, { steps: [{ kind: "task", content: "a" }, { kind: "message", content: "b", action_type: "nope" }] }, BASE),
    (e) => e.code === "SHADOW_BAD_DECLARED" && /^Step 2: /.test(e.message),
  );
  assert.equal((await svc.listSessions(O)).sessions.length, 0);
  const r = await svc.logTurn(O, { steps: [{ kind: "task", content: "a", intent_type: "fulfill_request" }, { kind: "message", content: "b" }] }, BASE);
  assert.equal(r.evidence.logged[0].intent_type, "fulfill_request");
  assert.equal("intent_type" in r.evidence.logged[1], false);
  assert.match(r.show_user, /task: the person's request \(declared: intent fulfill_request\)/);
});

test("shadow_record takes the same types and the same refusal", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t" }, BASE);
  const r = await svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "n", ...SEND });
  assert.equal(r.action_type, "send");
  assert.equal(r.intent_type, "communicate");
  const before = (await svc.getSession(O, { session_id: s.session_id }, BASE)).steps;
  await assert.rejects(svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "n", action_type: "nope" }), (e) => e.code === "SHADOW_BAD_DECLARED");
  assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).steps, before);
});

test("the footer table, the log summary and the viewer show types as the agent's claim", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Email them", action_type: "decide", intent_type: "fulfill_request" }, BASE);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done", ...SEND }, BASE);
  assert.match(b.show_user, /\| task: the person's request \(declared: action decide, intent fulfill_request\) \|/);
  assert.match(b.show_user, /\| message: message shown \(declared: action send, intent communicate\) \|/);
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  await withLinks(svc, async (url) => {
    const cap = capOf(closed.links.viewer);
    const log = await (await fetch(`${url}/shadow/s/${cap}/summary?format=json`)).json();
    const task = log.steps.find((s) => s.kind === "task");
    assert.equal(task.action_type, "decide");
    assert.equal(task.intent_type, "fulfill_request");
    assert.match(await (await fetch(`${url}/shadow/s/${cap}/summary`)).text(), /task: the person's request \(declared: action decide, intent fulfill_request\)\. Step hash/);
    const page = await (await fetch(`${url}/shadow/s/${cap}`)).text();
    assert.match(page, /\(declared: action decide, intent fulfill_request\)/);
    // A task row is otherwise collector-boundary and can read "Proven". What the agent declared never does.
    const row = page.split("<tr>").find((r) => r.includes("declared: action decide"));
    assert.match(row, /Recorded as reported/);
    assert.doesNotMatch(row, /Proven/);
  });
});

async function client(o) {
  const { svc } = service();
  const server = buildShadowServer(svc, O, BASE, o);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const c = new Client({ name: "t", version: "1" });
  await c.connect(b);
  const tools = Object.fromEntries((await c.listTools()).tools.map((t) => [t.name, t]));
  return { c, tools };
}

test("through MCP with auto-log on: the log tools list the fields, and they reach the record", async () => {
  const { c, tools } = await client({ autoLog: { logStepAllowed: true, stepsPerMinute: 90 } });
  for (const name of ["shadow_log_step", "shadow_record"]) {
    assert.match(tools[name].inputSchema.properties.action_type.description, /^Optional\./, name);
    assert.match(tools[name].inputSchema.properties.intent_type.description, /Hashed with the step, not written to Clockchain/, name);
    assert.equal((tools[name].inputSchema.required ?? []).includes("action_type"), false, name);
  }
  assert.ok(tools.shadow_log_turn.inputSchema.properties.steps.items.properties.intent_type);
  const r = await c.callTool({ name: "shadow_log_step", arguments: { kind: "task", content: "x", action_type: "create" } });
  assert.equal(JSON.parse(r.content[0].text).action_type, "create");
  const refused = await c.callTool({ name: "shadow_log_step", arguments: { kind: "task", content: "x", action_type: "nope" } });
  assert.equal(refused.isError, true);
  assert.equal(JSON.parse(refused.content[0].text).error, "SHADOW_BAD_DECLARED");
});

test("the listed path, with logging by default off, offers the labels too, and they stay optional", async () => {
  const { tools } = await client({});
  const schema = tools.shadow_record.inputSchema;
  assert.equal("action_type" in schema.properties, true);
  assert.equal("intent_type" in schema.properties, true);
  assert.equal((schema.required ?? []).includes("action_type"), false);
  assert.equal((schema.required ?? []).includes("intent_type"), false);
});
