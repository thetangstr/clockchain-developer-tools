// Shadow's search through the network's ledger search (GET /search/ledger), used when SHADOW_NETWORK_SEARCH_URL is set.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readConfigFromEnv } from "@clockchain/core";
import {
  NetworkSearchShadowClient,
  NETWORK_SEARCH_MAX_PAGES,
  NETWORK_SEARCH_PAGE_SIZE,
  ShadowClockchainClient,
  __setShadowLedgerForTests,
  networkSearchUrl,
  runtimeShadowLedger,
  searchNetworkLedger,
} from "../dist/shadow/ledger.js";

const BASE = "https://search.test";
const REF = "shadow:v1:aaafdef1-1aaa-4c8d-a9dd-054f0bacee9a";
const rec = (ledgerId, over = {}) => ({ ledgerId, clientId: "own", assetReferenceId: REF, assetHash: "h" + ledgerId, ...over });

/** A fake search host: pages[n] is page n's content; it records every URL asked for. */
function host(pages, { status = 200, body } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(new URL(url));
    const page = Number(new URL(url).searchParams.get("page"));
    const json = body ?? { currentPage: page, totalPages: pages.length, size: NETWORK_SEARCH_PAGE_SIZE, totalElements: pages.flat().length, content: pages[page] ?? [] };
    return new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json" } });
  };
  return { calls, fetchImpl };
}
const search = (h, clientIds = ["own"]) => searchNetworkLedger({ baseUrl: BASE, referenceId: REF, clientIds, fetchImpl: h.fetchImpl });

test("asks for the exact reference, the largest page, from page 0", async () => {
  const h = host([[rec("1")]]);
  assert.deepEqual(await search(h), [rec("1")]);
  assert.equal(h.calls.length, 1);
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
  ]]);
  assert.deepEqual((await search(h, ["own", "earlier", ""])).map((r) => r.ledgerId), ["1", "2"]);
});

test("reads every page, and stops at the last one", async () => {
  const h = host([[rec("1")], [rec("2", { clientId: "x" })], [rec("3")]]);
  assert.deepEqual((await search(h)).map((r) => r.ledgerId), ["1", "3"]);
  assert.deepEqual(h.calls.map((u) => u.searchParams.get("page")), ["0", "1", "2"]);
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
  // Page 1 failing after page 0 answered: never a partial answer.
  let n = 0;
  const flaky = { fetchImpl: async (url) => (n++ === 0
    ? new Response(JSON.stringify({ totalPages: 2, content: [rec("1")] }), { status: 200 })
    : new Response("{}", { status: 500 })) };
  await assert.rejects(search(flaky), (e) => e.status === 500);
  await assert.rejects(search({ fetchImpl: async () => { throw new TypeError("fetch failed"); } }), TypeError);
});

test("gives up past the page cap rather than answer in part", async () => {
  const many = Array.from({ length: NETWORK_SEARCH_MAX_PAGES + 1 }, (_, i) => [rec(String(i))]);
  const h = host(many);
  await assert.rejects(search(h), (e) => e.status === 502);
  assert.equal(h.calls.length, NETWORK_SEARCH_MAX_PAGES);
});

test("SHADOW_NETWORK_SEARCH_URL: https only, trailing slash dropped", () => {
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: " https://stagingapi.clockchain.network/ " }), "https://stagingapi.clockchain.network");
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: "http://stagingapi.clockchain.network" }), undefined);
  assert.equal(networkSearchUrl({ SHADOW_NETWORK_SEARCH_URL: "https://a.test?x=1" }), undefined);
  assert.equal(networkSearchUrl({}), undefined);
});

test("the server's client: network search when set (own and delegated clients), the old search otherwise", async () => {
  const env = { CLOCKCHAIN_API_KEY: "k", CLOCKCHAIN_CLIENT_ID: "c", CLOCKCHAIN_WALLET_ID: "w" };
  const own = { ...env, SHADOW_LEDGER_CLIENT_ID: "shadow", SHADOW_LEDGER_WALLET_ID: "shadow-wallet" };
  const url = { SHADOW_NETWORK_SEARCH_URL: "https://stagingapi.clockchain.network" };
  try {
    __setShadowLedgerForTests(undefined);
    assert.ok(runtimeShadowLedger({ ...own, ...url }) instanceof NetworkSearchShadowClient);
    __setShadowLedgerForTests(undefined);
    assert.ok(runtimeShadowLedger({ ...env, ...url }) instanceof NetworkSearchShadowClient);
    __setShadowLedgerForTests(undefined);
    assert.ok(runtimeShadowLedger(own) instanceof ShadowClockchainClient);
    __setShadowLedgerForTests(undefined);
    const plain = runtimeShadowLedger(env);
    assert.ok(!(plain instanceof NetworkSearchShadowClient) && !(plain instanceof ShadowClockchainClient));
  } finally {
    __setShadowLedgerForTests(undefined);
  }
  // Both of Shadow's clients are searched: its own and the delegated one earlier sessions were written under.
  const h = host([[rec("1", { clientId: "shadow" }), rec("2", { clientId: "c" }), rec("3", { clientId: "x" })]]);
  const client = new NetworkSearchShadowClient({ ...readConfigFromEnv(own), clientId: "shadow" }, { baseUrl: BASE, clientIds: ["shadow", "c"], fetchImpl: h.fetchImpl });
  assert.deepEqual((await client.searchAsset(REF)).map((r) => r.ledgerId), ["1", "2"]);
});
