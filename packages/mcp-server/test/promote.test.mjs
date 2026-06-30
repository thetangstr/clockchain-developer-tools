// CLO-48: /promote binds + flips idempotently on claim (LLD §6.5/§11/§14).
import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryStore } from "../dist/store.js";
import { getOrCreateSession } from "../dist/session.js";
import { mintClaim } from "../dist/token.js";
import { runPromote } from "../dist/promote.js";

const SECRET = "promote-secret";

async function seedSession(store, eph, runsUsed) {
  const s = await getOrCreateSession(store, eph, "mcp", 1000, 3600, {});
  await store.putSession({ ...s, runsUsed });
}

test("promote requires claim + accountId", async () => {
  const store = new InMemoryStore();
  assert.equal((await runPromote(store, SECRET, {})).status, 400);
  assert.equal((await runPromote(store, SECRET, { claim: "x" })).status, 400);
});

test("an invalid/expired claim is 409 claim_invalid (LLD §11)", async () => {
  const store = new InMemoryStore();
  // forged claim
  const bad = await runPromote(store, SECRET, { claim: "cc_bogus.sig", accountId: "acct#1" });
  assert.equal(bad.status, 409);
  assert.equal(bad.body.error, "claim_invalid");
  // expired claim (exp in the past relative to nowSec)
  const { token } = mintClaim(SECRET, { eph: "did:clockchain:eph:e1", ch: "mcp" }, 100, 1000);
  const expired = await runPromote(store, SECRET, { claim: token, accountId: "acct#1" }, 2000);
  assert.equal(expired.status, 409);
  assert.equal(expired.body.error, "claim_invalid");
});

test("promote binds the session, flips the account, and carries receipts", async () => {
  const store = new InMemoryStore();
  const eph = "did:clockchain:eph:p1";
  await seedSession(store, eph, 3); // 3 completed trial runs
  const { token } = mintClaim(SECRET, { eph, ch: "mcp" }, 3600, 1000);

  const out = await runPromote(store, SECRET, { claim: token, accountId: "acct#42" }, 1500);
  assert.equal(out.status, 200);
  assert.equal(out.body.boundReceipts, 3, "prior trial receipts carry over");
  assert.equal(out.body.accountId, "acct#42");

  const session = await store.getSession(eph);
  assert.equal(session.status, "promoted");
  assert.equal(session.promotedTo, "acct#42");

  const acct = await store.getAccount("acct#42");
  assert.equal(acct.plan, "pro");
  assert.deepEqual(acct.promotedFrom, [eph]);
});

test("promote is idempotent on claim (LLD §6.5)", async () => {
  const store = new InMemoryStore();
  const eph = "did:clockchain:eph:p2";
  await seedSession(store, eph, 5);
  const { token } = mintClaim(SECRET, { eph, ch: "mcp" }, 3600, 1000);

  const first = await runPromote(store, SECRET, { claim: token, accountId: "acct#7" }, 1500);
  const second = await runPromote(store, SECRET, { claim: token, accountId: "acct#7" }, 1600);
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(second.body.idempotent, true);
  assert.equal(second.body.boundReceipts, first.body.boundReceipts);
  assert.equal(second.body.accountId, "acct#7");

  // re-sending the same claim with a DIFFERENT accountId still resolves to the
  // original binding (idempotent on claim, not on accountId).
  const replay = await runPromote(store, SECRET, { claim: token, accountId: "acct#999" }, 1700);
  assert.equal(replay.body.accountId, "acct#7");
});

test("a claim signed with a different secret is rejected (409)", async () => {
  const store = new InMemoryStore();
  const eph = "did:clockchain:eph:p3";
  await seedSession(store, eph, 1);
  const { token } = mintClaim("OTHER-secret", { eph, ch: "mcp" }, 3600, 1000);
  const out = await runPromote(store, SECRET, { claim: token, accountId: "acct#1" }, 1500);
  assert.equal(out.status, 409);
});
