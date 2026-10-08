import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  createContractEvidenceRoutes,
  createObserverFeedLimiter,
  parsePerMinute,
} from "../dist/agent-contract/evidence-routes.js";

/**
 * COUNTER window follow-up (2026-10-08): the observer/verifier feed limiter
 * gains an OPTIONAL per-subject (queried keyId/runId) bucket so concurrent
 * lanes stop starving each other on one global 30/min bucket. Unset = the old
 * single global bucket, byte for byte.
 */

const clock = () => {
  let t = 1_000_000;
  return { now: () => t, advance: (ms) => { t += ms; } };
};

test("parsePerMinute is strict: positive integers only, everything else is unset", () => {
  assert.equal(parsePerMinute("120"), 120);
  assert.equal(parsePerMinute(" 600 "), 600);
  for (const bad of [undefined, "", "0", "-1", "1.5", "abc", "1e3", "12345678", "07"]) {
    assert.equal(parsePerMinute(bad), undefined, String(bad));
  }
});

test("default (no per-subject bucket) is the old single global bucket per scope", () => {
  const c = clock();
  const allow = createObserverFeedLimiter({ globalPerMinute: 30, now: c.now });
  for (let i = 0; i < 30; i += 1) assert.equal(allow("observer", `r:run-${i}`), true);
  // distinct subjects do NOT get their own allowance without the option
  assert.equal(allow("observer", "r:fresh"), false);
  // scopes are separate buckets, exactly as before
  assert.equal(allow("verifier", "r:fresh"), true);
  c.advance(60_000);
  assert.equal(allow("observer", "r:fresh"), true);
});

test("per-subject bucket: one busy subject cannot starve another", () => {
  const c = clock();
  const allow = createObserverFeedLimiter({ globalPerMinute: 600, perSubjectPerMinute: 3, now: c.now });
  for (let i = 0; i < 3; i += 1) assert.equal(allow("observer", "k:family-travel-tc-1"), true);
  assert.equal(allow("observer", "k:family-travel-tc-1"), false);
  assert.equal(allow("observer", "k:family-travel-tc-2"), true);
  assert.equal(allow("observer", "r:run-a"), true);
  c.advance(60_000);
  assert.equal(allow("observer", "k:family-travel-tc-1"), true);
});

test("global bucket still caps the total; a per-subject refusal does not consume it", () => {
  const c = clock();
  const allow = createObserverFeedLimiter({ globalPerMinute: 5, perSubjectPerMinute: 2, now: c.now });
  assert.equal(allow("observer", "k:a"), true);
  assert.equal(allow("observer", "k:a"), true);
  for (let i = 0; i < 10; i += 1) assert.equal(allow("observer", "k:a"), false); // per-subject refusals
  assert.equal(allow("observer", "k:b"), true);
  assert.equal(allow("observer", "k:b"), true);
  assert.equal(allow("observer", "k:c"), true); // 5th global hit
  assert.equal(allow("observer", "k:d"), false); // global exhausted
  // no subject -> global only
  assert.equal(allow("observer", undefined), false);
});

test("the routes pass k:<keyId> / r:<runId> subjects to the limiter for both feeds", async () => {
  const seen = [];
  const service = { receiptFeed: () => undefined, preBindFeed: () => undefined, saltFor: () => undefined };
  const routes = createContractEvidenceRoutes({
    service, observerToken: "obs", verifierToken: "ver",
    allowFeed: (scope, subject) => { seen.push([scope, subject]); return subject !== "r:blocked"; },
  });
  const srv = createServer((req, res) => {
    if (!routes(req, res)) { res.writeHead(404); res.end(); }
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const get = (p, tok) => fetch(`${url}${p}`, { headers: { authorization: `Bearer ${tok}` } });
  try {
    assert.equal((await get("/contract/receipts?runId=r1", "obs")).status, 404);
    assert.equal((await get("/contract/receipts?keyId=family-travel-tc-2&mcpSessionId=s", "obs")).status, 404);
    assert.equal((await get("/contract/receipts?runId=blocked", "obs")).status, 429);
    assert.equal((await get("/contract/run-salt?runId=r2", "ver")).status, 404);
    assert.equal((await get("/contract/receipts", "obs")).status, 404);
    // bad bearer never reaches the limiter
    assert.equal((await get("/contract/receipts?runId=r1", "nope")).status, 401);
    assert.deepEqual(seen, [
      ["observer", "r:r1"],
      ["observer", "k:family-travel-tc-2"],
      ["observer", "r:blocked"],
      ["verifier", "r:r2"],
      ["observer", undefined],
    ]);
  } finally {
    await new Promise((r) => srv.close(r));
  }
});
