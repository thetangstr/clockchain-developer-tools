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
  PoolDegradedError,
  RateLimitError,
  readConfigFromEnv,
  type BlockResponse,
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
  getBlock(height: string | number): Promise<BlockResponse>;
  buildEvidencePackage(ledgerId: string): Promise<EvidencePackage>;
  verifyPackage(pkg: EvidencePackage): Promise<PackageVerification>;
}

let testLedger: ShadowLedger | undefined;
let runtimeLedger: ShadowLedger | undefined;

/** Test-only: route hosted Shadow's anchoring to a fake ledger (undefined restores the real client). */
export function __setShadowLedgerForTests(ledger: ShadowLedger | undefined): void {
  testLedger = ledger;
}

/** The delegated in-process client (CLOCKCHAIN_API_KEY / _CLIENT_ID / _WALLET_ID), built on first use. */
export function runtimeShadowLedger(env: NodeJS.ProcessEnv = process.env): ShadowLedger {
  if (testLedger) return testLedger;
  runtimeLedger ??= new ClockchainClient(readConfigFromEnv(env));
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

class HashMismatchError extends Error {}

export type Failure = { kind: ErrorKind; code: string; retryAfterSeconds: number | null };

/** Maps a write failure to the library's error kinds, with a fixed content-free code (v1.1 correction C17). */
export function classifyFailure(e: unknown): Failure {
  const f = (kind: ErrorKind, code: string, retryAfterSeconds: number | null = null): Failure => ({ kind, code, retryAfterSeconds });
  if (e instanceof AnchorLimitError) return f("Credits", "anchor_limit");
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
  | { kind: "failed"; failure: Failure };

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
        const found = (await o.ledger.searchAsset(o.referenceId)).find((r) => r.assetHash === o.hash);
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
  return { kind: "failed", failure: last };
}

function withDeadline<T>(p: Promise<T>, deadline: number): Promise<T> {
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
): Promise<OnlineClient & { receiptsChecked: number }> {
  const deadline = Date.now() + o.timeoutMs;
  const entries = new Map<string, { assetHash: string | null; blockHeight: string | null; blockTime: string | null; submittedAt: string | null }>();
  // A session with an anchor per step has hundreds of receipts: a few readers at once, one read per block.
  const blocks = new Map<string, Promise<{ blockTime?: unknown }>>();
  let next = 0;
  const reader = async () => {
    while (next < o.ledgerIds.length && Date.now() < deadline) {
      const id = o.ledgerIds[next++];
      try {
        const rec = await withDeadline(ledger.getLedgerEntry(id), deadline);
        const blockHeight = str(rec.blockHeight);
        let blockTime: string | null = null;
        if (blockHeight) {
          let read = blocks.get(blockHeight);
          if (!read) {
            read = ledger.getBlock(blockHeight);
            blocks.set(blockHeight, read);
          }
          blockTime = normalizeGatewayTime((await withDeadline(read, deadline)).blockTime as string);
        }
        entries.set(id, { assetHash: str(rec.assetHash), blockHeight, blockTime, submittedAt: normalizeGatewayTime(rec.createdTimestamp) });
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
  try {
    found = (await withDeadline(ledger.searchAsset(o.referenceId), deadline)).map((r) => ({ ledgerId: String(r.ledgerId), assetHash: str(r.assetHash) }));
  } catch {
    found = undefined;
  }
  const unreachable = () => Promise.reject(new Error("Clockchain could not be reached"));
  return {
    receiptsChecked: entries.size,
    network: o.network,
    logEntry: (id) => {
      const e = entries.get(id);
      return e ? Promise.resolve(e) : unreachable();
    },
    confirmPackage: (id) => (id === last && pkg ? Promise.resolve(pkg) : unreachable()),
    search: (ref) => (ref === o.referenceId && found ? Promise.resolve(found) : unreachable()),
  };
}
