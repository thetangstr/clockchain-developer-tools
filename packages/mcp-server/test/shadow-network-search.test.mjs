// Shadow's search through the network's ledger search (GET /search/ledger), used when SHADOW_NETWORK_SEARCH_URL is set.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ClockchainClient, RateLimitError } from "@clockchain/core";
import {
  NETWORK_SEARCH_MAX_PASSES,
  NETWORK_SEARCH_MAX_PAGES,
  NETWORK_SEARCH_PAGE_SIZE,
  ShadowClockchainClient,
  __setShadowLedgerForTests,
  networkSearchUrl,
  prefetchOnline,
  runtimeShadowLedger,
  searchNetworkLedger,
  withNetworkWitness,
} from "../dist/shadow/ledger.js";

const BASE = "https://search.test";
const REF = "shadow:v1:aaafdef1-1aaa-4c8d-a9dd-054f0bacee9a";
const rec = (ledgerId, over = {}) => ({ ledgerId, clientId: "own", assetReferenceId: REF, assetHash: "h" + ledgerId, ...over });

/** A fake search host: pages[n] is page n's content; it records every URL asked for. */
function host(pages, { status = 200, body, total, headers = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(new URL(url));
    const page = Number(new URL(url).searchParams.get("page"));
    const json = body ?? { currentPage: page, totalPages: pages.length, size: NETWORK_SEARCH_PAGE_SIZE, totalElements: total ?? new Set(pages.flat().map((r) => r.ledgerId)).size, content: pages[page] ?? [] };
    return new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json", ...headers } });
  };
  return { calls, fetchImpl };
}
const search = (h, clientIds = ["own"]) => searchNetworkLedger({ baseUrl: BASE, referenceId: REF, clientIds, fetchImpl: h.fetchImpl });

test("asks for the exact reference, the largest page, from page 0", async () => {
  const h = host([[rec("1")]]);
  assert.deepEqual(await search(h), [rec("1")]);
  assert.equal(h.calls.length, 2, "two reads that agree");
  const u = h.calls[0];
  assert.equal(u.origin + u.pathname, `${BASE}/search/ledger`);
  assert.equal(u.searchParams.get("message"), REF);
  assert.equal(u.searchParams.get("size"), String(NETWORK_SEARCH_PAGE_SIZE));
  assert.equal(u.searchParams.get("page"), "0");
});

test("keeps only this exact reference, under Shadow's own clients, once each", async () => {
  const h = host([[
    rec("1"),
    rec("2", { clientId: "earlier" }),
    rec("3", { clientId: "someone-else" }),
    rec("4", { assetReferenceId: REF + "-other" }),
    rec("5", { assetReferenceId: "x" + REF }),
    rec("1"),
    { assetReferenceId: REF, clientId: "own" },
  ]], { total: 5 });
  assert.deepEqual((await search(h, ["own", "earlier", ""])).map((r) => r.ledgerId), ["1", "2"]);
});

test("reads every page, and stops at the last one", async () => {
  const h = host([[rec("1")], [rec("2", { clientId: "x" })], [rec("3")]]);
  assert.deepEqual((await search(h)).map((r) => r.ledgerId), ["1", "3"]);
  assert.deepEqual(h.calls.map((u) => u.searchParams.get("page")), ["0", "1", "2", "0", "1", "2"]);
});

test("none is a real empty answer", async () => {
  assert.deepEqual(await search(host([])), []);
  assert.deepEqual(await search(host([[rec("1", { clientId: "x" })]])), []);
});

test("a failed or odd answer fails the whole search, and a 404 is never read as none", async () => {
  await assert.rejects(search(host([[rec("1")]], { status: 503 })), (e) => e.status === 503);
  await assert.rejects(search(host([[rec("1")]], { status: 404 })), (e) => e.status === 502, "a wrong address, not none");
  await assert.rejects(search(host([], { body: [rec("1")] })), (e) => e.status === 502, "a bare list is not this route's form");
  await assert.rejects(search(host([], { body: { content: [] } })), (e) => e.status === 502);
  await assert.rejects(search(host([], { body: { content: [], totalPages: 0 } })), (e) => e.status === 502, "no totalElements");
  // Page 1 failing after page 0 answered: never a partial answer.
  let n = 0;
  const flaky = { fetchImpl: async (url) => (n++ === 0
    ? new Response(JSON.stringify({ totalPages: 2, totalElements: 2, content: [rec("1")] }), { status: 200 })
    : new Response("{}", { status: 500 })) };
  await assert.rejects(search(flaky), (e) => e.status === 500);
  await assert.rejects(search({ fetchImpl: async () => { throw new TypeError("fetch failed"); } }), TypeError);
});

test("gives up past the page cap rather than answer in part", async () => {
  const many = Array.from({ length: NETWORK_SEARCH_MAX_PAGES + 1 }, (_, i) => [rec(String(i))]);
  const h = host(many);
  await assert.rejects(search(h), (e) => e.status === 502);
  assert.equal(h.calls.length, 1, "it stops at the first page's count");
});

test("SHADOW_NETWORK_SEARCH_URL: https only, trailing slash dropped", () => {
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: " https://stagingapi.clockchain.network/ " }), "https://stagingapi.clockchain.network");
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: "http://stagingapi.clockchain.network" }), undefined);
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: "https://a.test?x=1" }), undefined);
  assert.equal(networkSearchUrl({}), undefined);
});

test("the order shifting between pages: one more read fills the gap, and a gap that stays fails", async () => {
  // Read 1 repeats record 1 on page 1 and never shows 3; read 2 shows 3. Together they hold all four.
  const reads = [[[rec("1"), rec("2")], [rec("1"), rec("4")]], [[rec("3"), rec("2")], [rec("4"), rec("1")]]];
  let call = 0;
  const shifting = { fetchImpl: async (url) => {
    const page = Number(new URL(url).searchParams.get("page"));
    const read = reads[Math.min(Math.floor(call++ / 2), reads.length - 1)];
    return new Response(JSON.stringify({ totalPages: 2, totalElements: 4, content: read[page] }), { status: 200 });
  } };
  assert.deepEqual((await search(shifting)).map((r) => r.ledgerId).sort(), ["1", "2", "3", "4"]);
  assert.equal(call, 6, "a gap-filling read, then one that agrees with it");
  // Always missing one: fails after the last read, never a short answer.
  const stuck = host([[rec("1"), rec("2")], [rec("1")]], { total: 3 });
  await assert.rejects(search(stuck), (e) => e.status === 502);
  assert.equal(stuck.calls.length, 2 * NETWORK_SEARCH_MAX_PASSES);
});

test("a count that changes mid-read, or an empty page before the last, doesn't count as a full read", async () => {
  let n = 0;
  const moving = { fetchImpl: async (url) => {
    const page = Number(new URL(url).searchParams.get("page"));
    const total = n++ % 2 === 0 ? 2 : 3;
    return new Response(JSON.stringify({ totalPages: 2, totalElements: total, content: [rec(String(page))] }), { status: 200 });
  } };
  await assert.rejects(search(moving), (e) => e.status === 502);
  const gap = host([[], [rec("1")]], { total: 1 });
  await assert.rejects(search(gap), (e) => e.status === 502, "an empty page before the last");
});

test("a 429 is a rate limit with its Retry-After, and the deadline stops further requests", async () => {
  await assert.rejects(search(host([[rec("1")]], { status: 429, headers: { "retry-after": "7" } })), (e) => e instanceof RateLimitError && e.retryAfter === 7);
  const h = host([[rec("1")]]);
  await assert.rejects(searchNetworkLedger({ baseUrl: BASE, referenceId: REF, clientIds: ["own"], fetchImpl: h.fetchImpl, deadline: Date.now() - 1 }), (e) => e.status === 502);
  assert.equal(h.calls.length, 0);
});

test("the server's ledger: the network search is only for the verifier; writes and retries keep the old search", () => {
  const env = { CLOCKCHAIN_API_KEY: "k", CLOCKCHAIN_CLIENT_ID: "c", CLOCKCHAIN_WALLET_ID: "w" };
  const own = { ...env, SHADOW_LEDGER_CLIENT_ID: "shadow", SHADOW_LEDGER_WALLET_ID: "shadow-wallet" };
  const url = { SHADOW_NETWORK_SEARCH_URL: "https://stagingapi.clockchain.network" };
  try {
    for (const [e, cls] of [[{ ...own, ...url }, ShadowClockchainClient], [{ ...env, ...url }, ClockchainClient], [own, ShadowClockchainClient], [env, ClockchainClient]]) {
      __setShadowLedgerForTests(undefined);
      const l = runtimeShadowLedger(e);
      assert.ok(l instanceof cls);
      assert.equal(typeof l.witnessSearch === "function", "SHADOW_NETWORK_SEARCH_URL" in e);
      assert.equal(l.searchAsset, cls.prototype.searchAsset, "retries search as before");
    }
  } finally {
    __setShadowLedgerForTests(undefined);
  }
});

/** A fake ledger for the verifier's prefetch. */
function fakeLedger(witness) {
  const entry = { ledgerId: "L1", assetHash: "h", blockHeight: "5", createdTimestamp: "1794015120193" };
  const l = {
    searchAsset: async () => { throw new Error("the old search must not be used for the verifier"); },
    getLedgerEntry: async () => entry,
    getBlock: async () => ({ blockTime: "2026-11-07T01:32:00Z" }),
    buildEvidencePackage: async () => ({}),
    verifyPackage: async () => ({ valid: true }),
  };
  return withNetworkWitness(l, { baseUrl: BASE, clientIds: ["own"], fetchImpl: witness.fetchImpl });
}

test("the verifier reads the network search; a none it can't vouch for is no answer", async () => {
  const h = host([[rec("L1", { assetHash: "h" }), rec("L2", { assetHash: "x" })]]);
  const online = await prefetchOnline(fakeLedger(h), { network: "staging", referenceId: REF, ledgerIds: ["L1"], timeoutMs: 5000 });
  assert.deepEqual((await online.search(REF)).map((r) => r.ledgerId), ["L1", "L2"]);
  assert.equal(online.searchUnanswered, false);
  const none = await prefetchOnline(fakeLedger(host([])), { network: "staging", referenceId: REF, ledgerIds: [], timeoutMs: 5000 });
  assert.equal(none.searchUnanswered, true, "with no receipts, it may not have caught up with a write");
  const behind = await prefetchOnline(fakeLedger(host([[rec("L2")]])), { network: "staging", referenceId: REF, ledgerIds: ["L1"], timeoutMs: 5000 });
  assert.equal(behind.searchUnanswered, false);
  await assert.rejects(behind.search(REF), /could not be reached/, "it doesn't list a receipt, so it hasn't caught up");
});

test("a first read that is complete but behind is not enough: the next read must agree", async () => {
  // Read 1 (a copy that is behind) shows 2 of 3; reads 2 and 3 show all 3. The answer is all 3.
  let call = 0;
  const lagging = { fetchImpl: async () => {
    const content = call++ === 0 ? [rec("1"), rec("2")] : [rec("1"), rec("2"), rec("3")];
    return new Response(JSON.stringify({ totalPages: 1, totalElements: content.length, content }), { status: 200 });
  } };
  assert.deepEqual((await search(lagging)).map((r) => r.ledgerId), ["1", "2", "3"]);
  assert.equal(call, 3);
  // Totals flipping between reads (370, 357, 370 seen live) never settle into an answer short of what was seen.
  let n = 0;
  const flipping = { fetchImpl: async () => {
    const content = n++ % 2 === 0 ? [rec("1"), rec("2"), rec("3")] : [rec("1"), rec("2")];
    return new Response(JSON.stringify({ totalPages: 1, totalElements: content.length, content }), { status: 200 });
  } };
  await assert.rejects(search(flipping), (e) => e.status === 502);
  // A record with no ledgerId can never complete a read.
  await assert.rejects(search(host([[rec("1"), { assetReferenceId: REF, clientId: "own" }]])), (e) => e.status === 502);
});

test("the verifier also searches under the client the ledger stored our receipts under", async () => {
  // The network stored our write under its own shared client, not the one Shadow names.
  const h = host([[rec("L1", { clientId: "network-shared", assetHash: "h" }), rec("L9", { clientId: "someone-else" })]]);
  const l = fakeLedger(h);
  l.getLedgerEntry = async () => ({ ledgerId: "L1", clientId: "network-shared", assetHash: "h", blockHeight: "5", createdTimestamp: "1794015120193" });
  const online = await prefetchOnline(l, { network: "staging", referenceId: REF, ledgerIds: ["L1"], timeoutMs: 5000 });
  assert.deepEqual((await online.search(REF)).map((r) => r.ledgerId), ["L1"]);
});

test("the verifier waits out the network's 429s on receipt and block reads instead of calling the receipts unreachable", async () => {
  const ids = Array.from({ length: 30 }, (_, i) => `L${i}`);
  const h = host([ids.map((id) => rec(id, { assetHash: "h" + id }))]);
  const l = fakeLedger(h);
  let limited = 0;
  const burst = () => { if (limited < 40 && Math.random() < 0.6) { limited++; throw new RateLimitError("Rate limit exceeded", 429, undefined, 0); } };
  l.getLedgerEntry = async (id) => { burst(); return { ledgerId: id, clientId: "own", assetHash: "h" + id, blockHeight: id.slice(1), createdTimestamp: "1794015120193" }; };
  l.getBlock = async () => { burst(); return { blockTime: "1794015120193" }; };
  const online = await prefetchOnline(l, { network: "staging", referenceId: REF, ledgerIds: ids, timeoutMs: 15000, concurrency: 8 });
  assert.ok(limited > 0, "the fake did rate-limit");
  assert.equal(online.receiptsChecked, 30, "every receipt read in the end");
  assert.equal((await online.search(REF)).length, 30);
});

test("a search or read that fails after the verifier's deadline doesn't become an unhandled rejection", async () => {
  const seen = [];
  const onUnhandled = (e) => seen.push(e);
  process.on("unhandledRejection", onUnhandled);
  try {
    const l = fakeLedger(host([]));
    l.witnessSearch = () => new Promise((_, reject) => setTimeout(() => reject(new Error("late search failure")), 300));
    l.getBlock = () => new Promise((_, reject) => setTimeout(() => reject(new Error("late block failure")), 300));
    const online = await prefetchOnline(l, { network: "staging", referenceId: REF, ledgerIds: ["L1"], timeoutMs: 100 });
    assert.equal(online.receiptsChecked, 0);
    await new Promise((r) => setTimeout(r, 600));
    assert.deepEqual(seen.map((e) => e.message), []);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("a used-up allowance is not waited for: the read fails at once", async () => {
  const l = fakeLedger(host([[rec("L1", { assetHash: "h" })]]));
  let blockCalls = 0;
  l.getBlock = async () => { blockCalls++; throw new RateLimitError("Rate limit exceeded", 429, { code: "FREE_QUOTA_EXHAUSTED" }); };
  const t = Date.now();
  const online = await prefetchOnline(l, { network: "staging", referenceId: REF, ledgerIds: ["L1"], timeoutMs: 10000 });
  assert.equal(online.receiptsChecked, 0);
  assert.equal(blockCalls, 1, "one try, no retries");
  assert.ok(Date.now() - t < 2000);
});
