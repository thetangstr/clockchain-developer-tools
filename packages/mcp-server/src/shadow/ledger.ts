// Anchoring for hosted Shadow, through the server's own in-process Clockchain client: the same write path log_action
// takes (pool-health guard, MCP_LOG_BUDGET check, client.log, budget.record, waitForConfirmation) with the delegated
// key, and the library's anchoring scheme (reference `shadow:v1:<sessionId>`, a 64-hex asset hash, fixed labels).
// Nothing but hashes, the reference id and a fixed label reaches Clockchain. Receipt times are read as the library's
// own client reads them (clockchain-shadow/ts/src/clockchain.ts receipt()): normalizeGatewayTime turns the gateway's
// DD-MM-YYYY form or an offset time into the one canonical UTC form (spec §2.6, v1.1 correction C11).
import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  parseRetryAfter,
  PoolDegradedError,
  RateLimitError,
  readConfigFromEnv,
  type BlockResponse,
  type ClockchainConfig,
  type EvidencePackage,
  type LedgerRecord,
  type LogResponse,
  type PackageVerification,
  type PoolHealth,
} from "@clockchain/core";
import { BudgetExceededError, type LogBudget } from "../budget.js";
import { ensurePoolHealthy } from "../tools.js";
import { normalizeGatewayTime } from "./lib/profile.js";
import type { OnlineClient } from "./lib/verify.js";
import type { WriteReceipt } from "./recorder.js";

/** The slice of @clockchain/core's ClockchainClient hosted Shadow uses (tests pass a fake). */
export interface ShadowLedger {
  getPoolHealth(): Promise<PoolHealth>;
  log(entry: { assetHash: string; assetReferenceId: string; hashType?: string; additionalInfo?: string }): Promise<LogResponse>;
  getLedgerEntry(ledgerId: string): Promise<LedgerRecord>;
  waitForConfirmation(ledgerId: string, timeoutMs?: number): Promise<LedgerRecord>;
  searchAsset(assetReferenceId: string): Promise<LedgerRecord[]>;
  /**
   * The verifier's completeness check, when set (SHADOW_NETWORK_SEARCH_URL): every record under a reference, from a search
   * that fails rather than answer in part. Only the verifier uses it. Retries keep searchAsset: this search is a separate
   * index that may lag a write, and a stale "none" there could pay for a write twice.
   */
  witnessSearch?(assetReferenceId: string, deadline?: number, alsoClientIds?: readonly string[]): Promise<LedgerRecord[]>;
  getBlock(height: string | number): Promise<BlockResponse>;
  buildEvidencePackage(ledgerId: string): Promise<EvidencePackage>;
  verifyPackage(pkg: EvidencePackage): Promise<PackageVerification>;
}

let testLedger: ShadowLedger | undefined;
let runtimeLedger: ShadowLedger | undefined;

/** Test-only: route hosted Shadow's anchoring to a fake ledger (undefined restores the real client, built afresh). */
const isNotFound = (e: unknown) => e instanceof ApiError && e.status === 404;

export function __setShadowLedgerForTests(ledger: ShadowLedger | undefined): void {
  testLedger = ledger;
  runtimeLedger = undefined;
}

/**
 * The client and wallet hosted Shadow anchors under (SHADOW_LEDGER_CLIENT_ID, SHADOW_LEDGER_WALLET_ID), or undefined when
 * they aren't set, and it anchors under the delegated CLOCKCHAIN_CLIENT_ID as before. loadShadowConfig checks them.
 */
export function shadowLedgerIdentity(env: NodeJS.ProcessEnv = process.env): { clientId: string; walletId: string } | undefined {
  const clientId = (env.SHADOW_LEDGER_CLIENT_ID ?? "").trim();
  const walletId = (env.SHADOW_LEDGER_WALLET_ID ?? "").trim();
  return clientId && walletId ? { clientId, walletId } : undefined;
}

/**
 * Writes under Shadow's own client. The ledger search is scoped to a client, so it also searches under the client that
 * earlier sessions were anchored under. Without that their online check would stop at indeterminate, and a retried anchor
 * could write again what the old client already wrote. A failed search under either is a failed search: never a partial
 * answer, which the verifier could read as "these records don't exist". A 404 is each client's way of saying it has none,
 * so it doesn't stand for the other's answer; but with nothing found at all the 404 goes on up, because a reader may need to
 * know that no client really answered.
 */
export class ShadowClockchainClient extends ClockchainClient {
  constructor(config: ClockchainConfig, private readonly earlier: ClockchainClient) {
    super(config);
  }
  override async searchAsset(assetReferenceId: string): Promise<LedgerRecord[]> {
    const read = (search: Promise<LedgerRecord[]>) => search.then((records) => ({ records, missed: null as unknown }), (e: unknown) => {
      if (isNotFound(e)) return { records: [] as LedgerRecord[], missed: e };
      throw e;
    });
    const [own, old] = await Promise.all([read(super.searchAsset(assetReferenceId)), read(this.earlier.searchAsset(assetReferenceId))]);
    const seen = new Set(own.records.map((r) => String(r.ledgerId)));
    const records = [...own.records, ...old.records.filter((r) => !seen.has(String(r.ledgerId)))];
    const missed = own.missed ?? old.missed;
    if (!records.length && missed) throw missed;
    return records;
  }
}

/** Largest page the network's ledger search serves; how many pages one read may need; how many full reads one search tries. */
export const NETWORK_SEARCH_PAGE_SIZE = 100;
export const NETWORK_SEARCH_MAX_PAGES = 20;
export const NETWORK_SEARCH_MAX_PASSES = 4;
const NETWORK_SEARCH_TIMEOUT_MS = 10_000;

/** SHADOW_NETWORK_SEARCH_URL, the network's search host (for example https://stagingapi.clockchain.network). Only https. */
export function networkSearchUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = (env.SHADOW_NETWORK_SEARCH_URL ?? "").trim().replace(/\/+$/, "");
  return /^https:\/\/[^\s/?#]+(\/[^\s?#]*)?$/.test(raw) ? raw : undefined;
}

const incomplete = (why: string, body?: unknown) => new ApiError(`Ledger search gave an incomplete answer (${why})`, 502, body);

/**
 * The network's own ledger search, GET <base>/search/ledger?message=&size=&page=. It needs no key, covers every client, and
 * matches any field by substring. Its order isn't stable from one request to the next, so paging can repeat one record and
 * skip another; and its count can differ between reads. So an answer counts only when every record the search says matches
 * has been seen: the distinct records across the pages read (before any filtering) must reach the reported total, with the
 * same total on every page of that read; and two reads in a row must agree, which catches a reader landing on a copy of the
 * index that is behind. It reads the whole result up to NETWORK_SEARCH_MAX_PASSES times, keeping what earlier reads saw,
 * and otherwise fails with a 502. Then only records whose reference is exactly this one, written under one of
 * Shadow's own clients, are kept. A 404 is passed on as a 502 and a 429 as a rate limit, so neither is read as an answer.
 */
export async function searchNetworkLedger(o: {
  baseUrl: string;
  referenceId: string;
  clientIds: readonly string[];
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Wall-clock time (ms) after which no further request starts. */
  deadline?: number;
}): Promise<LedgerRecord[]> {
  const fetchImpl = o.fetchImpl ?? fetch;
  const clients = new Set(o.clientIds.filter(Boolean));
  const seen = new Map<string, LedgerRecord>();
  const readPage = async (page: number) => {
    const left = o.deadline === undefined ? Infinity : o.deadline - Date.now();
    if (left <= 0) throw incomplete("out of time");
    const url = new URL(`${o.baseUrl}/search/ledger`);
    url.searchParams.set("message", o.referenceId);
    url.searchParams.set("size", String(NETWORK_SEARCH_PAGE_SIZE));
    url.searchParams.set("page", String(page));
    const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(Math.min(o.timeoutMs ?? NETWORK_SEARCH_TIMEOUT_MS, left)) });
    const body: unknown = await res.json().catch(() => undefined);
    if (res.status === 429) throw new RateLimitError("Ledger search rate limited", 429, body, parseRetryAfter(res.headers.get("retry-after")));
    if (!res.ok) throw new ApiError(`Ledger search failed (HTTP ${res.status})`, res.status === 404 ? 502 : res.status, body);
    const shape = body as { content?: unknown; totalPages?: unknown; totalElements?: unknown } | undefined;
    if (!shape || !Array.isArray(shape.content) || !Number.isSafeInteger(shape.totalPages) || !Number.isSafeInteger(shape.totalElements)) {
      throw incomplete("unexpected form", body);
    }
    return { content: shape.content as LedgerRecord[], totalPages: shape.totalPages as number, totalElements: shape.totalElements as number };
  };
  let agreed: number | undefined;
  for (let pass = 0; pass < NETWORK_SEARCH_MAX_PASSES; pass++) {
    let total: number | undefined;
    let pages = 1;
    let steady = true;
    for (let page = 0; page < pages; page++) {
      const r = await readPage(page);
      if (total === undefined) {
        total = r.totalElements;
        pages = r.totalPages;
        if (pages > NETWORK_SEARCH_MAX_PAGES) throw incomplete(`more than ${NETWORK_SEARCH_MAX_PAGES} pages`);
      } else if (r.totalElements !== total || r.totalPages !== pages) {
        steady = false;
      }
      if (r.content.length === 0 && page + 1 < pages) steady = false;
      for (const rec of r.content) {
        const id = String(rec?.ledgerId ?? "");
        if (id) seen.set(id, rec);
      }
    }
    const complete = steady && seen.size === total;
    if (complete && agreed === total) {
      return [...seen.values()].filter((r) => r.assetReferenceId === o.referenceId && clients.has(String(r.clientId)));
    }
    agreed = complete ? total : undefined;
  }
  throw incomplete("records shifted between pages");
}

/** Gives Shadow's ledger the network's search for the verifier's completeness check; writes and retries are unchanged. */
export function withNetworkWitness<T extends ShadowLedger>(ledger: T, o: { baseUrl: string; clientIds: readonly string[]; fetchImpl?: typeof fetch }): T {
  ledger.witnessSearch = (referenceId, deadline, alsoClientIds = []) =>
    searchNetworkLedger({ ...o, clientIds: [...o.clientIds, ...alsoClientIds], referenceId, deadline });
  return ledger;
}

/** The delegated in-process client (CLOCKCHAIN_API_KEY / _CLIENT_ID / _WALLET_ID), or Shadow's own identity on it, built on first use. */
export function runtimeShadowLedger(env: NodeJS.ProcessEnv = process.env): ShadowLedger {
  if (testLedger) return testLedger;
  if (!runtimeLedger) {
    const identity = shadowLedgerIdentity(env);
    runtimeLedger = identity
      ? new ShadowClockchainClient({ ...readConfigFromEnv(env), ...identity }, new ClockchainClient(readConfigFromEnv(env)))
      : new ClockchainClient(readConfigFromEnv(env));
    const searchUrl = networkSearchUrl(env);
    if (searchUrl) {
      const ids = [identity?.clientId, readConfigFromEnv(env).clientId].filter((v): v is string => !!v);
      withNetworkWitness(runtimeLedger, { baseUrl: searchUrl, clientIds: [...new Set(ids)] });
    }
  }
  return runtimeLedger;
}

/** The library's error kinds (clockchain-shadow/ts/src/clockchain.ts). */
export type ErrorKind = "Auth" | "Credits" | "RateLimited" | "PoolDegraded" | "Transient" | "Permanent";

/** The per-owner daily anchor limit, raised before a write is attempted. */
export class AnchorLimitError extends Error {
  constructor() {
    super("anchor limit reached");
    this.name = "AnchorLimitError";
  }
}

/**
 * The Starter allowance every new agent (ak: owner) shares is used up for today ("daily"), or the agent's address has used
 * its share of it ("source"); raised before a write is attempted.
 */
export class StarterLimitError extends Error {
  constructor(readonly reason: "daily" | "source" = "daily") {
    super(reason === "source" ? "starter allowance share reached" : "starter allowance reached");
    this.name = "StarterLimitError";
  }
}

class HashMismatchError extends Error {}

export type Failure = { kind: ErrorKind; code: string; retryAfterSeconds: number | null };

/** Maps a write failure to the library's error kinds, with a fixed content-free code (v1.1 correction C17). */
export function classifyFailure(e: unknown): Failure {
  const f = (kind: ErrorKind, code: string, retryAfterSeconds: number | null = null): Failure => ({ kind, code, retryAfterSeconds });
  if (e instanceof AnchorLimitError) return f("Credits", "anchor_limit");
  if (e instanceof StarterLimitError) return f("Credits", e.reason === "source" ? "starter_source_limit" : "starter_limit");
  if (e instanceof BudgetExceededError) return f("Credits", "log_budget");
  if (e instanceof HashMismatchError) return f("Permanent", "hash_mismatch");
  if (e instanceof AuthError) return f("Auth", "http_401");
  if (e instanceof InsufficientCreditsError) return f("Credits", "credits");
  if (e instanceof RateLimitError) return f("RateLimited", "http_429", e.retryAfter ?? null);
  if (e instanceof PoolDegradedError) return f("PoolDegraded", "pool_degraded");
  if (e instanceof ApiError) {
    if (e.name === "TimeoutError") return f("Transient", "timeout");
    if (e.name === "CircuitOpenError") return f("Transient", "circuit_open");
    if (e.status >= 500) return f("Transient", `http_${e.status}`);
    if (e.status >= 400) return f("Permanent", `http_${e.status}`);
    return f("Transient", "unavailable");
  }
  return f("Transient", "network");
}

const str = (v: unknown) => (v == null || v === "" ? null : String(v));

export type AnchorOutcome =
  | { kind: "anchored"; receipt: WriteReceipt }
  | { kind: "pending"; ledgerId: string; submittedAt: string | null }
  /** maybeWritten: a write was tried, now or on an earlier attempt, so this hash may be on the ledger. */
  | { kind: "failed"; failure: Failure; maybeWritten: boolean }
  /** This hash may be on the ledger and the ledger refused the search that would tell: nothing was paid, and paying blind could pay twice. */
  | { kind: "unconfirmed"; failure: Failure };

export type AnchorRequest = {
  ledger: ShadowLedger;
  referenceId: string;
  hash: string;
  label: string;
  /** A ledger id from an earlier attempt that was written but not yet in a block. */
  ledgerId: string | null;
  /** True when an earlier attempt may have written already: the reference is searched before paying again. */
  uncertain: boolean;
  budget: LogBudget;
  /** Takes one anchor from the owner's daily allowance (throws AnchorLimitError), and gives it back. */
  reserve: () => void;
  refund: () => void;
  waitMs: number;
  tries: number;
  backoffMs: readonly number[];
  sleep: (ms: number) => Promise<void>;
  /** Wall-clock time (ms) after which no further attempt starts: an agent's tool call must come back. */
  deadline: number;
};

async function settle(ledger: ShadowLedger, rec: LedgerRecord, hash: string): Promise<AnchorOutcome> {
  if (rec.assetHash && rec.assetHash !== hash) throw new HashMismatchError("Clockchain record does not carry the anchored hash");
  const ledgerId = String(rec.ledgerId);
  const submittedAt = normalizeGatewayTime(rec.createdTimestamp);
  const blockHeight = str(rec.blockHeight);
  if (!blockHeight) return { kind: "pending", ledgerId, submittedAt };
  let block: BlockResponse;
  try {
    block = await ledger.getBlock(blockHeight);
  } catch {
    // Written and in a block, but its block time is not readable yet: keep the ledger id, never write again.
    return { kind: "pending", ledgerId, submittedAt };
  }
  return { kind: "anchored", receipt: { ledgerId, blockHeight, blockTime: normalizeGatewayTime(block.blockTime), submittedAt } };
}

/** The records under a reference. The gateway answers "none" with a 404, as the core client reads it too; anything else is thrown. */
async function searchRecords(ledger: ShadowLedger, referenceId: string): Promise<LedgerRecord[]> {
  try {
    return await ledger.searchAsset(referenceId);
  } catch (e) {
    if (isNotFound(e)) return [];
    throw e;
  }
}

/**
 * One anchoring pass with a few in-call retries for transient failures. After any uncertain attempt the session
 * reference is searched first and a record that already carries the hash is adopted, so a retry never pays twice.
 * Auth, credit (including our own limits) and permanent failures stop at once.
 */
export async function anchorHash(o: AnchorRequest): Promise<AnchorOutcome> {
  let uncertain = o.uncertain;
  let last: Failure = { kind: "Transient", code: "network", retryAfterSeconds: null };
  for (let attempt = 0; attempt < o.tries; attempt++) {
    try {
      if (o.ledgerId) {
        return await settle(o.ledger, await o.ledger.waitForConfirmation(o.ledgerId, Math.min(o.waitMs, 3_000)), o.hash);
      }
      if (uncertain) {
        let records: LedgerRecord[];
        try {
          records = await searchRecords(o.ledger, o.referenceId);
        } catch (e) {
          // A refusal isn't an outage: trying again in this call won't change it, and it says nothing about this hash.
          const refused = classifyFailure(e);
          if (refused.kind === "Auth" || refused.kind === "Permanent") return { kind: "unconfirmed", failure: refused };
          throw e;
        }
        const found = records.find((r) => r.assetHash === o.hash);
        if (found) {
          const rec = found.blockHeight != null ? found : await o.ledger.waitForConfirmation(String(found.ledgerId), o.waitMs).catch(() => found);
          return await settle(o.ledger, rec, o.hash);
        }
      }
      // The log_action write path: refuse a write a degraded pool would not anchor, spend the budget only on success.
      await ensurePoolHealthy(o.ledger, false);
      o.budget.check();
      o.reserve();
      let written: LogResponse;
      try {
        uncertain = true;
        written = await o.ledger.log({ assetHash: o.hash, assetReferenceId: o.referenceId, hashType: "SHA-256", additionalInfo: o.label });
      } catch (e) {
        o.refund();
        throw e;
      }
      o.budget.record();
      const rec = written.blockHeight != null ? written : await o.ledger.waitForConfirmation(written.ledgerId, o.waitMs).catch(() => written);
      return await settle(o.ledger, rec, o.hash);
    } catch (e) {
      last = classifyFailure(e);
      const stop = last.kind === "Auth" || last.kind === "Credits" || last.kind === "Permanent" ||
        (last.kind === "RateLimited" && (last.retryAfterSeconds ?? 0) > 3);
      if (stop || attempt === o.tries - 1 || Date.now() >= o.deadline) break;
      await o.sleep(last.kind === "RateLimited" && last.retryAfterSeconds ? last.retryAfterSeconds * 1000 : o.backoffMs[Math.min(attempt, o.backoffMs.length - 1)]);
    }
  }
  return { kind: "failed", failure: last, maybeWritten: uncertain };
}

function withDeadline<T>(p: Promise<T>, deadline: number): Promise<T> {
  // When the deadline wins, p is abandoned; if it fails later nobody awaits it, and an unhandled rejection stops the
  // server. Its outcome no longer matters, so it is marked handled here.
  p.catch(() => undefined);
  const left = deadline - Date.now();
  if (left <= 0) return Promise.reject(new Error("deadline"));
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("deadline")), left);
      timer.unref();
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Reads, before the session's events are loaded, everything the verifier's online witness check asks for: each
 * receipt's ledger record and block time, Clockchain's evidence package for the last receipt, and the ledger search
 * under the session reference. Answers come from that snapshot; anything not fetched in time reads as unreachable,
 * which the verifier reports as indeterminate rather than failing.
 */
export async function prefetchOnline(
  ledger: ShadowLedger,
  o: { network: string; referenceId: string; ledgerIds: string[]; timeoutMs: number; concurrency?: number },
): Promise<OnlineClient & { receiptsChecked: number; searchUnanswered: boolean }> {
  const deadline = Date.now() + o.timeoutMs;
  const entries = new Map<string, { assetHash: string | null; blockHeight: string | null; blockTime: string | null; submittedAt: string | null }>();
  // A session with an anchor per step has hundreds of receipts: a few readers at once, one read per block.
  const blocks = new Map<string, Promise<{ blockTime?: unknown }>>();
  // The client each receipt was stored under, as the ledger reports it: the network may store a write under its own client
  // for our key rather than the one we name, and the witness search must look under the client that really wrote them.
  const writers = new Set<string>();
  let next = 0;
  // The network's API answers a burst of block reads with 429s: wait as it asks (or back off) and read again, within the
  // deadline, rather than count a rate-limited receipt as unreachable.
  const patient = async <T>(read: () => Promise<T>): Promise<T> => {
    for (let n = 0; ; n++) {
      try {
        return await withDeadline(read(), deadline);
      } catch (e) {
        // A used-up allowance (FREE_QUOTA_EXHAUSTED and the like) won't come back within this call: don't wait for it.
        const code = String((e as { body?: { code?: unknown } })?.body?.code ?? "");
        if (!(e instanceof RateLimitError) || /QUOTA_EXHAUSTED/i.test(code) || n >= 8) throw e;
        const wait = Math.min(e.retryAfter ? e.retryAfter * 1000 : 200 * 2 ** n, 4_000);
        if (Date.now() + wait >= deadline) throw e;
        await new Promise<void>((resolve) => setTimeout(resolve, wait).unref());
      }
    }
  };
  const reader = async () => {
    while (next < o.ledgerIds.length && Date.now() < deadline) {
      const id = o.ledgerIds[next++];
      try {
        const rec = await patient(() => ledger.getLedgerEntry(id));
        const blockHeight = str(rec.blockHeight);
        let blockTime: string | null = null;
        if (blockHeight) {
          let read = blocks.get(blockHeight);
          if (!read) {
            read = patient(() => ledger.getBlock(blockHeight));
            blocks.set(blockHeight, read);
          }
          blockTime = normalizeGatewayTime((await withDeadline(read, deadline)).blockTime as string);
        }
        entries.set(id, { assetHash: str(rec.assetHash), blockHeight, blockTime, submittedAt: normalizeGatewayTime(rec.createdTimestamp) });
        const writer = str((rec as { clientId?: unknown }).clientId);
        if (writer) writers.add(writer);
      } catch {
        // Unreachable for this receipt: the verifier reports witness as indeterminate.
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, o.concurrency ?? 1) }, reader));
  const last = o.ledgerIds.at(-1);
  let pkg: { valid: boolean } | undefined;
  if (last) {
    try {
      const built = await withDeadline(ledger.buildEvidencePackage(last), deadline);
      pkg = { valid: (await withDeadline(ledger.verifyPackage(built), deadline)).valid === true };
    } catch {
      pkg = undefined;
    }
  }
  let found: { ledgerId: string; assetHash: string | null }[] | undefined;
  let refused = false;
  const receipts = o.ledgerIds.length > 0;
  try {
    const search = ledger.witnessSearch ? ledger.witnessSearch(o.referenceId, deadline, [...writers]) : ledger.searchAsset(o.referenceId);
    found = (await withDeadline(search, deadline)).map((r) => ({ ledgerId: String(r.ledgerId), assetHash: str(r.assetHash) }));
    // That index may not have caught up with a write yet, so for a record with no receipts its "none" is no answer either.
    if (ledger.witnessSearch && !found.length && !receipts) {
      found = undefined;
      refused = true;
    }
    // A receipt it doesn't list shows it hasn't caught up: its answer can't vouch for what else the ledger holds.
    const listed = new Set(found?.map((r) => r.ledgerId));
    if (ledger.witnessSearch && found && o.ledgerIds.some((id) => !listed.has(id))) found = undefined;
  } catch (e) {
    // A 404 lands here too: it can mean none or a wrong route, so it is no answer, and can't vouch for what the ledger holds.
    found = undefined;
    const { kind } = classifyFailure(e);
    refused = kind === "Auth" || kind === "Permanent";
  }
  const unreachable = () => Promise.reject(new Error("Clockchain could not be reached"));
  // Refused isn't unreachable. With no search on the client the verifier says what really happened, and witness stays
  // indeterminate. Only with receipts: with none, it would go on to say the ledger holds no record for this session.
  const noSearch = refused && receipts;
  return {
    receiptsChecked: entries.size,
    /** Nothing in the record to check, and the ledger gave no answer: the record can't be read as having nothing to find. */
    searchUnanswered: refused && !receipts,
    network: o.network,
    logEntry: (id) => {
      const e = entries.get(id);
      return e ? Promise.resolve(e) : unreachable();
    },
    confirmPackage: (id) => (id === last && pkg ? Promise.resolve(pkg) : unreachable()),
    ...(noSearch ? {} : { search: (ref: string) => (ref === o.referenceId && found ? Promise.resolve(found) : unreachable()) }),
  };
}
