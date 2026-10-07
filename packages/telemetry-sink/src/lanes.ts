import { randomBytes, verify, type KeyObject } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { canonicalDigest, canonicalJson } from "./canonical.js";
import type { EnrollmentRegistry } from "./enrollments.js";
import { sealTo, type SealedBox } from "./seal.js";
import type { ContractRole, TokenStore } from "./tokens.js";

/**
 * O-1 lanes (state/ledger/notes/mcp-coordination-design.md §O-1).
 *
 * A LANE is a pre-bind ingest stream for one (role, principal keyId,
 * mcpSessionId). Its id is `lane:<32 hex>`, allocated here; it is an
 * ordinary sink run (its own hash chain, its own ingest token) whose runId
 * happens to be the laneId.
 *
 *   POST /v1/lanes/open            (close listener) body = contract-signed ac-lane-open/v1
 *   POST /v1/runs/:runId/link      (close listener) body = contract-signed ac-run-link/v1
 *   POST /v1/lanes/release         (close listener) body = contract-signed ac-lane-release/v1
 *
 * CDT-SEC L5: every signed body names its audience — `aud`, this sink's
 * signing keyId — so a message signed for one sink is refused by another
 * that pins the same contract key. A release (the contract's MCP session
 * dropped before any run could capture the lane) stops the lane counting
 * toward LANE_LIMIT and bars it from any link; the session stays used.
 *
 * Authority (the reason this file exists):
 *   - The ingest token is minted HERE, by the sink — the only mint.
 *   - It is sealed ONLY to the x25519 key the sink admin enrolled for the
 *     named keyId (enrollments.json). The request names a keyId; it can never
 *     carry a public key — the lane-open field set is exact, and any extra
 *     field (publicKey, x25519, sealTo, ...) refuses REQUEST_INVALID.
 *   - The request is authorized by a contract-server ed25519 signature under
 *     a key pinned in `contractKeys` (the same pin as close). There is no
 *     bearer path and no public mint endpoint.
 *   - One lane per (keyId, role, mcpSessionId): a replayed or repeated
 *     open is LANE_REUSED. An unlinked lane is forgotten LANE_PRUNE_GRACE_MS
 *     after it leaves the window (L4); its signed open is stale by then. At most `maxOpenLanesPerKey` unlinked lanes per
 *     keyId inside `laneWindowMs` (LANE_LIMIT) so a contract key cannot
 *     exhaust sink state.
 *   - A link is write-once per contract runId; a lane belongs to at most one
 *     run. Linking marks the contract runId used so the verifier can mint a
 *     query token for it.
 *
 * lanes.json (state volume, server-written only) keeps lanes and links across
 * a restart, so a lane can never be re-opened for the same session and a
 * link survives; the lane CHAINS are in memory like every sink run — a
 * restart leaves an ingested lane RUN_LOST via runs.json, never reset.
 */

export const LANE_OPEN_SCHEMA = "ac-lane-open/v1" as const;
export const RUN_LINK_SCHEMA = "ac-run-link/v1" as const;
export const LANE_RELEASE_SCHEMA = "ac-lane-release/v1" as const;
export const LANES_FILE_SCHEMA = "ac-telemetry.lanes/v1" as const;
export const LANE_ID_RE = /^lane:[0-9a-f]{32}$/;
const MCP_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SIG_RE = /^0x[0-9a-f]{128}$/;
const MAX_LANES_PER_ROLE = 8;
const DEFAULT_MAX_OPEN_LANES_PER_KEY = 8;
const DEFAULT_LANE_WINDOW_MS = 6 * 60 * 60 * 1000;
const DEFAULT_CLOCK_SKEW_MS = 60_000;
/**
 * L4: an UNLINKED lane is forgotten this long after it leaves the window.
 * The grace covers clock skew plus a contract link that is still being
 * delivered (or resumed after a contract restart) for a lane it picked
 * inside the window. Linked lanes are never pruned: their records are run
 * evidence (run-set keyId / mcpSessionId / openDigest, query authority).
 */
export const LANE_PRUNE_GRACE_MS = 60 * 60 * 1000;

export const isLaneId = (id: string): boolean => id.startsWith("lane:");

export interface LaneRecord {
  laneId: string;
  keyId: string;
  role: ContractRole;
  mcpSessionId: string;
  openedAtMs: number;
  /** canonical digest of the accepted signed lane-open — the verifier's link from lane to session. */
  openDigest: string;
  /** contract runId once linked; null until then. */
  runId: string | null;
  /** L5: set when the contract released the lane (its session dropped unlinked). */
  releasedAtMs?: number;
}

export interface LinkedLanes {
  buyer: string[];
  provider: string[];
}

export interface RunLink {
  runId: string;
  lanes: LinkedLanes;
  /** canonicalDigest({schema: "ac-run-link/v1", runId, lanes}) — what ac-terminal-receipt/v2 carries. */
  linkDigest: string;
  tsMs: number;
  linkedAtMs: number;
}

export type LaneRefusalCode =
  | "REQUEST_INVALID"
  | "RECEIPT_INVALID"
  | "RECEIPT_STALE"
  | "NOT_ENROLLED"
  | "LANE_REUSED"
  | "LANE_LIMIT"
  | "LINK_INVALID"
  | "LINK_CONFLICT";

export interface LaneOpenResult {
  ok: true;
  laneId: string;
  role: ContractRole;
  keyId: string;
  mcpSessionId: string;
  /** the ingest token, sealed to the ENROLLED key, bound to (laneId, role). */
  sealedBox: SealedBox;
}

export interface LaneService {
  open(body: unknown): Promise<LaneOpenResult | { ok: false; code: LaneRefusalCode }>;
  link(runId: string, body: unknown): Promise<
    { ok: true; runId: string; linkDigest: string; created: boolean } | { ok: false; code: LaneRefusalCode }
  >;
  release(body: unknown): Promise<{ ok: true; laneId: string } | { ok: false; code: LaneRefusalCode }>;
  lane(laneId: string): LaneRecord | undefined;
  linkFor(runId: string): RunLink | undefined;
}

/** The digest both the contract service and the sink compute for a link. */
export function linkDigestOf(runId: string, lanes: LinkedLanes): string {
  return canonicalDigest({ schema: RUN_LINK_SCHEMA, runId, lanes });
}

/**
 * The signed message of an ac-lane-open/v1. The body's `keyId` names the
 * PRINCIPAL, so the signer's keyId rides nested under `signature` (with
 * `sig` omitted) rather than top-level as in the receipt convention — the
 * two keyIds can never collide.
 */
export function laneOpenMessage(
  fields: { aud: string; keyId: string; role: string; mcpSessionId: string; ts: string },
  signature: { alg: string; keyId: string },
): string {
  return canonicalJson({
    schema: LANE_OPEN_SCHEMA,
    aud: fields.aud,
    keyId: fields.keyId,
    role: fields.role,
    mcpSessionId: fields.mcpSessionId,
    ts: fields.ts,
    signature: { alg: signature.alg, keyId: signature.keyId },
  });
}

/** The signed message of an ac-run-link/v1 — the receipt convention {..., alg, keyId}. */
export function runLinkMessage(
  fields: { aud: string; runId: string; lanes: LinkedLanes; ts: string },
  signature: { alg: string; keyId: string },
): string {
  return canonicalJson({
    schema: RUN_LINK_SCHEMA,
    aud: fields.aud,
    runId: fields.runId,
    lanes: fields.lanes,
    ts: fields.ts,
    alg: signature.alg,
    keyId: signature.keyId,
  });
}

/** The signed message of an ac-lane-release/v1 — lane-open style (principal keyId top-level). */
export function laneReleaseMessage(
  fields: { aud: string; laneId: string; keyId: string; role: string; mcpSessionId: string; ts: string },
  signature: { alg: string; keyId: string },
): string {
  return canonicalJson({
    schema: LANE_RELEASE_SCHEMA,
    aud: fields.aud,
    laneId: fields.laneId,
    keyId: fields.keyId,
    role: fields.role,
    mcpSessionId: fields.mcpSessionId,
    ts: fields.ts,
    signature: { alg: signature.alg, keyId: signature.keyId },
  });
}

interface LanesDoc {
  schema: typeof LANES_FILE_SCHEMA;
  lanes: Record<string, Omit<LaneRecord, "laneId">>;
  links: Record<string, Omit<RunLink, "runId">>;
}

function readLanesFile(file: string): LanesDoc {
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (typeof raw !== "object" || raw === null || (raw as LanesDoc).schema !== LANES_FILE_SCHEMA) {
    throw new Error(`corrupt ${file}: not a ${LANES_FILE_SCHEMA} document`);
  }
  const doc = raw as LanesDoc;
  if (typeof doc.lanes !== "object" || doc.lanes === null || typeof doc.links !== "object" || doc.links === null) {
    throw new Error(`corrupt ${file}: bad shape`);
  }
  return {
    schema: LANES_FILE_SCHEMA,
    lanes: Object.assign(Object.create(null), doc.lanes),
    links: Object.assign(Object.create(null), doc.links),
  };
}

function writeLanesAtomic(file: string, doc: LanesDoc): void {
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify(doc));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  // The rename is durable only once the directory entry is (L4).
  const dirFd = openSync(path.dirname(file), "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

const exactKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(o, k));
};

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Parse the `signature` member: exactly {alg:"ed25519", keyId, sig:0x<128hex>}. */
function parseSignature(v: unknown): { alg: "ed25519"; keyId: string; sig: string } | null {
  if (!isPlainObject(v) || !exactKeys(v, ["alg", "keyId", "sig"])) return null;
  if (v.alg !== "ed25519" || typeof v.keyId !== "string" || typeof v.sig !== "string" || !SIG_RE.test(v.sig)) {
    return null;
  }
  return { alg: "ed25519", keyId: v.keyId, sig: v.sig };
}

export function createLaneService(options: {
  /** L5: this sink's audience id (its signing keyId); every signed body must name it. */
  audience: string;
  tokens: TokenStore;
  enrollments: EnrollmentRegistry;
  /** pinned contract-server ed25519 keys — the same pin as close. */
  contractKeys?: Record<string, KeyObject>;
  /** lanes.json on the state volume; absent → in-memory (tests). */
  file?: string;
  now?: () => number;
  clockSkewMs?: number;
  maxOpenLanesPerKey?: number;
  /** an unlinked lane older than this no longer counts toward the per-key cap. */
  laneWindowMs?: number;
}): LaneService {
  const now = options.now ?? Date.now;
  const clockSkewMs = options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const maxOpen = options.maxOpenLanesPerKey ?? DEFAULT_MAX_OPEN_LANES_PER_KEY;
  const laneWindowMs = options.laneWindowMs ?? DEFAULT_LANE_WINDOW_MS;
  // Fail closed on a corrupt file: construction throws, the sink refuses boot.
  const doc: LanesDoc = options.file !== undefined && existsSync(options.file)
    ? readLanesFile(options.file)
    : { schema: LANES_FILE_SCHEMA, lanes: Object.create(null), links: Object.create(null) };
  const sessionIndex = new Map<string, string>();
  const sessionKey = (keyId: string, role: string, mcpSessionId: string): string =>
    canonicalJson([keyId, role, mcpSessionId]);
  // L4: unlinked lanes per keyId, so the LANE_LIMIT count never scans every
  // lane the sink has ever opened.
  const unlinkedByKey = new Map<string, Set<string>>();
  const indexUnlinked = (keyId: string, laneId: string): void => {
    let set = unlinkedByKey.get(keyId);
    if (set === undefined) unlinkedByKey.set(keyId, (set = new Set()));
    set.add(laneId);
  };
  const unindexUnlinked = (keyId: string, laneId: string): void => {
    const set = unlinkedByKey.get(keyId);
    if (set === undefined) return;
    set.delete(laneId);
    if (set.size === 0) unlinkedByKey.delete(keyId);
  };
  for (const [laneId, l] of Object.entries(doc.lanes)) {
    sessionIndex.set(sessionKey(l.keyId, l.role, l.mcpSessionId), laneId);
    if (l.runId === null) indexUnlinked(l.keyId, laneId);
  }

  const persist = (): void => {
    if (options.file !== undefined) writeLanesAtomic(options.file, doc);
  };

  /**
   * L4: drop unlinked lanes past window + grace. Such a lane no longer counts
   * toward LANE_LIMIT and the contract never links it, and its signed open
   * is long past the skew, so forgetting its session cannot enable a replay.
   */
  const prune = (t: number): boolean => {
    let dropped = false;
    for (const [keyId, set] of [...unlinkedByKey]) {
      for (const laneId of [...set]) {
        const l = doc.lanes[laneId];
        if (l.openedAtMs + laneWindowMs + LANE_PRUNE_GRACE_MS > t) continue;
        delete doc.lanes[laneId];
        sessionIndex.delete(sessionKey(l.keyId, l.role, l.mcpSessionId));
        unindexUnlinked(keyId, laneId);
        dropped = true;
      }
    }
    return dropped;
  };
  if (prune(now())) {
    try { persist(); } catch { /* the pruned in-memory view is authoritative; the next write retries */ }
  }

  function verifyContractSig(message: string, sig: { keyId: string; sig: string }): boolean {
    const publicKey = options.contractKeys?.[sig.keyId];
    if (publicKey === undefined) return false;
    try {
      return verify(null, Buffer.from(message, "utf8"), publicKey, Buffer.from(sig.sig.slice(2), "hex"));
    } catch {
      return false;
    }
  }

  async function open(body: unknown): Promise<LaneOpenResult | { ok: false; code: LaneRefusalCode }> {
    // Exact field set — a public key (or anything else) in the request refuses.
    if (!isPlainObject(body) || !exactKeys(body, ["schema", "aud", "keyId", "role", "mcpSessionId", "ts", "signature"])) {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    const { schema, aud, keyId, role, mcpSessionId, ts } = body;
    if (schema !== LANE_OPEN_SCHEMA || typeof aud !== "string"
      || typeof keyId !== "string" || keyId.length === 0 || keyId.length > 128
      || (role !== "buyer" && role !== "provider")
      || typeof mcpSessionId !== "string" || !MCP_SESSION_RE.test(mcpSessionId)
      || typeof ts !== "string") {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    const tsMs = Date.parse(ts);
    if (Number.isNaN(tsMs)) return { ok: false, code: "REQUEST_INVALID" };
    const signature = parseSignature(body.signature);
    if (signature === null) return { ok: false, code: "RECEIPT_INVALID" };
    if (!verifyContractSig(laneOpenMessage({ aud, keyId, role, mcpSessionId, ts }, signature), signature)) {
      return { ok: false, code: "RECEIPT_INVALID" };
    }
    // L5: signed for another sink → not ours to honour.
    if (aud !== options.audience) return { ok: false, code: "RECEIPT_INVALID" };
    const t = now();
    if (Math.abs(tsMs - t) > clockSkewMs) return { ok: false, code: "RECEIPT_STALE" };
    const enrollment = options.enrollments.get(keyId);
    // Role mismatch reads the same as absence: the sink seals only to what
    // the admin enrolled for exactly this (keyId, role).
    if (enrollment === undefined || enrollment.role !== role) return { ok: false, code: "NOT_ENROLLED" };
    const sKey = sessionKey(keyId, role, mcpSessionId);
    if (sessionIndex.has(sKey)) return { ok: false, code: "LANE_REUSED" };
    prune(t); // persisted with the new lane below, or on the next write
    const openUnlinked = [...(unlinkedByKey.get(keyId) ?? [])].filter(
      (id) => doc.lanes[id].releasedAtMs === undefined && doc.lanes[id].openedAtMs + laneWindowMs > t,
    ).length;
    if (openUnlinked >= maxOpen) return { ok: false, code: "LANE_LIMIT" };

    const laneId = `lane:${randomBytes(16).toString("hex")}`;
    const record: Omit<LaneRecord, "laneId"> = {
      keyId,
      role,
      mcpSessionId,
      openedAtMs: t,
      openDigest: canonicalDigest(body),
      runId: null,
    };
    // Durable BEFORE minting: after a restart the session can never get a
    // second lane, and the lane is known to the link route.
    doc.lanes[laneId] = record;
    sessionIndex.set(sKey, laneId);
    indexUnlinked(keyId, laneId);
    try {
      persist();
    } catch (err) {
      delete doc.lanes[laneId];
      sessionIndex.delete(sKey);
      unindexUnlinked(keyId, laneId);
      throw err;
    }
    const minted = options.tokens.mintIngest({ runId: laneId, role });
    try {
      // Durable authority before it is handed out (same rule as mint-cli).
      await options.tokens.flush();
    } catch (err) {
      options.tokens.revoke(minted.record.tokenId);
      throw err;
    }
    // Sealed to the ENROLLED key only, bound to (laneId, role). The plaintext
    // never leaves this function.
    const sealedBox = sealTo(enrollment.x25519, minted.token, { runId: laneId, role });
    return { ok: true, laneId, role, keyId, mcpSessionId, sealedBox };
  }

  function parseLanes(v: unknown): LinkedLanes | null {
    if (!isPlainObject(v) || !exactKeys(v, ["buyer", "provider"])) return null;
    const seen = new Set<string>();
    for (const role of ["buyer", "provider"] as const) {
      const list = v[role];
      if (!Array.isArray(list) || list.length > MAX_LANES_PER_ROLE) return null;
      for (const id of list) {
        if (typeof id !== "string" || !LANE_ID_RE.test(id) || seen.has(id)) return null;
        seen.add(id);
      }
    }
    if (seen.size === 0) return null;
    return { buyer: [...(v.buyer as string[])], provider: [...(v.provider as string[])] };
  }

  async function link(
    runId: string,
    body: unknown,
  ): Promise<{ ok: true; runId: string; linkDigest: string; created: boolean } | { ok: false; code: LaneRefusalCode }> {
    if (!isPlainObject(body) || !exactKeys(body, ["schema", "aud", "runId", "lanes", "ts", "signature"])) {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    if (body.schema !== RUN_LINK_SCHEMA || typeof body.aud !== "string" || body.runId !== runId
      || !RUN_ID_RE.test(runId) || isLaneId(runId) || typeof body.ts !== "string") {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    const lanes = parseLanes(body.lanes);
    const tsMs = Date.parse(body.ts);
    if (lanes === null || Number.isNaN(tsMs)) return { ok: false, code: "REQUEST_INVALID" };
    const signature = parseSignature(body.signature);
    if (signature === null) return { ok: false, code: "RECEIPT_INVALID" };
    if (!verifyContractSig(runLinkMessage({ aud: body.aud, runId, lanes, ts: body.ts }, signature), signature)) {
      return { ok: false, code: "RECEIPT_INVALID" };
    }
    if (body.aud !== options.audience) return { ok: false, code: "RECEIPT_INVALID" };
    const t = now();
    if (tsMs > t + clockSkewMs) return { ok: false, code: "RECEIPT_STALE" };
    const linkDigest = linkDigestOf(runId, lanes);
    // Write-once: an identical re-link (a retried delivery) is idempotent;
    // anything else is a conflict.
    const existing = Object.hasOwn(doc.links, runId) ? doc.links[runId] : undefined;
    if (existing !== undefined) {
      return existing.linkDigest === linkDigest
        ? { ok: true, runId, linkDigest, created: false }
        : { ok: false, code: "LINK_CONFLICT" };
    }
    // A runId that already carries a direct (v1-era) sink run is never
    // re-purposed as a linked run.
    if (options.tokens.isRunUsed(runId)) return { ok: false, code: "LINK_CONFLICT" };
    for (const role of ["buyer", "provider"] as const) {
      for (const laneId of lanes[role]) {
        const lane = Object.hasOwn(doc.lanes, laneId) ? doc.lanes[laneId] : undefined;
        // L5: a released lane can never join a run.
        if (lane === undefined || lane.role !== role || lane.releasedAtMs !== undefined) {
          return { ok: false, code: "LINK_INVALID" };
        }
        // A lane belongs to at most one run.
        if (lane.runId !== null) return { ok: false, code: "LANE_REUSED" };
      }
    }
    doc.links[runId] = { lanes, linkDigest, tsMs, linkedAtMs: t };
    for (const laneId of [...lanes.buyer, ...lanes.provider]) {
      doc.lanes[laneId].runId = runId;
      unindexUnlinked(doc.lanes[laneId].keyId, laneId);
    }
    try {
      persist();
    } catch (err) {
      delete doc.links[runId];
      for (const laneId of [...lanes.buyer, ...lanes.provider]) {
        doc.lanes[laneId].runId = null;
        indexUnlinked(doc.lanes[laneId].keyId, laneId);
      }
      throw err;
    }
    // The contract runId becomes a real (query-mintable) run; it can never
    // gain direct ingest authority.
    options.tokens.markRunUsed(runId);
    await options.tokens.flush();
    return { ok: true, runId, linkDigest, created: true };
  }

  async function release(body: unknown): Promise<{ ok: true; laneId: string } | { ok: false; code: LaneRefusalCode }> {
    if (!isPlainObject(body)
      || !exactKeys(body, ["schema", "aud", "laneId", "keyId", "role", "mcpSessionId", "ts", "signature"])) {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    const { schema, aud, laneId, keyId, role, mcpSessionId, ts } = body;
    if (schema !== LANE_RELEASE_SCHEMA || typeof aud !== "string"
      || typeof laneId !== "string" || !LANE_ID_RE.test(laneId)
      || typeof keyId !== "string" || typeof role !== "string" || typeof mcpSessionId !== "string"
      || typeof ts !== "string") {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    const tsMs = Date.parse(ts);
    if (Number.isNaN(tsMs)) return { ok: false, code: "REQUEST_INVALID" };
    const signature = parseSignature(body.signature);
    if (signature === null) return { ok: false, code: "RECEIPT_INVALID" };
    if (!verifyContractSig(laneReleaseMessage({ aud, laneId, keyId, role, mcpSessionId, ts }, signature), signature)) {
      return { ok: false, code: "RECEIPT_INVALID" };
    }
    if (aud !== options.audience) return { ok: false, code: "RECEIPT_INVALID" };
    const t = now();
    if (Math.abs(tsMs - t) > clockSkewMs) return { ok: false, code: "RECEIPT_STALE" };
    const lane = Object.hasOwn(doc.lanes, laneId) ? doc.lanes[laneId] : undefined;
    // The release must name the lane exactly as it was opened.
    if (lane === undefined || lane.keyId !== keyId || lane.role !== role || lane.mcpSessionId !== mcpSessionId) {
      return { ok: false, code: "LINK_INVALID" };
    }
    if (lane.runId !== null) return { ok: false, code: "LANE_REUSED" };
    if (lane.releasedAtMs !== undefined) return { ok: true, laneId }; // idempotent retry
    lane.releasedAtMs = t;
    try {
      persist();
    } catch (err) {
      delete lane.releasedAtMs;
      throw err;
    }
    return { ok: true, laneId };
  }

  return {
    open,
    link,
    release,
    lane(laneId) {
      if (!Object.hasOwn(doc.lanes, laneId)) return undefined;
      return { laneId, ...doc.lanes[laneId] };
    },
    linkFor(runId) {
      if (!Object.hasOwn(doc.links, runId)) return undefined;
      const l = doc.links[runId];
      return { runId, ...l, lanes: { buyer: [...l.lanes.buyer], provider: [...l.lanes.provider] } };
    },
  };
}
