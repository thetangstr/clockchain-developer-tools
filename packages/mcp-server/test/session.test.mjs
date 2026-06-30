// CLO-48: ephemeral session lazy creation + channel ceiling resolution (LLD §5.1/§9.1/§14).
import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryStore } from "../dist/store.js";
import {
  getOrCreateSession,
  resolveCeiling,
  normalizeChannel,
  newEphemeralDid,
  checkCeiling,
  hashClaim,
} from "../dist/session.js";

test("normalizeChannel defaults unknown to mcp; passes known", () => {
  assert.equal(normalizeChannel(undefined), "mcp");
  assert.equal(normalizeChannel("bogus"), "mcp");
  assert.equal(normalizeChannel("web"), "web");
  assert.equal(normalizeChannel("chatbot"), "chatbot");
});

test("channel ceilings resolve from config, with safe defaults (LLD §9.1)", () => {
  assert.equal(resolveCeiling("mcp", {}), 10);
  assert.equal(resolveCeiling("chatbot", {}), 5);
  assert.equal(resolveCeiling("web", {}), 3);
  // env override
  assert.equal(resolveCeiling("mcp", { MCP_TRIAL_CEILING_MCP: "25" }), 25);
  // a bad override falls back to the default (never silently unlimited)
  assert.equal(resolveCeiling("web", { MCP_TRIAL_CEILING_WEB: "0" }), 3);
  assert.equal(resolveCeiling("web", { MCP_TRIAL_CEILING_WEB: "nope" }), 3);
});

test("session is lazily created on first call and is idempotent (LLD §6.4)", async () => {
  const store = new InMemoryStore();
  const eph = "did:clockchain:eph:lazy1";
  assert.equal(await store.getSession(eph), null, "no session before first call");

  const s1 = await getOrCreateSession(store, eph, "mcp", 1000, 3600, {});
  assert.equal(s1.sessionId, eph);
  assert.equal(s1.ephemeralDid, eph);
  assert.equal(s1.runsUsed, 0);
  assert.equal(s1.runsCeiling, 10);
  assert.equal(s1.status, "active");
  assert.equal(s1.expiresAt, 1000 + 3600);

  // simulate a completed run
  await store.putSession({ ...s1, runsUsed: 2 });

  // second call returns the SAME session and does NOT reset runsUsed
  const s2 = await getOrCreateSession(store, eph, "mcp", 9999, 3600, {});
  assert.equal(s2.runsUsed, 2, "lazy get must not reset an existing session");
  assert.equal(s2.createdAt, 1000, "createdAt unchanged on re-fetch");
});

test("checkCeiling: blocks at ceiling, unlimited when null", () => {
  const base = {
    sessionId: "x", ephemeralDid: "x", channel: "mcp",
    createdAt: 0, expiresAt: 0, claimTokenHash: null, promotedTo: null, status: "active",
  };
  assert.equal(checkCeiling({ ...base, runsUsed: 9, runsCeiling: 10 }), true);
  assert.equal(checkCeiling({ ...base, runsUsed: 10, runsCeiling: 10 }), false);
  assert.equal(checkCeiling({ ...base, runsUsed: 999, runsCeiling: null }), true);
});

test("newEphemeralDid + hashClaim are well-formed", () => {
  const did = newEphemeralDid();
  assert.match(did, /^did:clockchain:eph:[0-9a-f]+$/);
  assert.notEqual(newEphemeralDid(), newEphemeralDid());
  const h = hashClaim("cc_abc.def");
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, hashClaim("cc_abc.def")); // deterministic
});
