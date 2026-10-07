import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";

import { bodyDigest, canonicalDigest, canonicalJson } from "./canonical.js";
import { isLaneId, type LaneRecord, type LinkedLanes, type RunLink } from "./lanes.js";
import type { RunLedger } from "./run-ledger.js";
import type { ContractRole, TokenStore } from "./tokens.js";

/**
 * The telemetry sink core (N4c, LLD §9 / R13(d)). Append-only, hash-chained
 * span/log records per run, under a separate authority: the sink holds its own
 * ed25519 signing key, mints capability-separated tokens, and signs chain
 * heads.
 *
 * Post-review semantics (N4C-CHANGES-1):
 *  - Ingest validates OTLP/JSON shape and enforces per-run byte/record caps.
 *  - `verifyRecords` recomputes sha256(body) for EVERY record — a swapped
 *    body fails even when all metadata is kept.
 *  - The head signature covers keyId and alg (they are part of the signed
 *    message), and heads are cached per chain tip so identical state always
 *    yields identical signed bytes (no per-call signing oracle).
 *
 * Close authority (N4C-CHANGES-2/3 — the SINK, never the harness): there is
 * no admin credential. A run closes only when the sink sees a FRESH signed
 * terminal receipt from the contract server (ed25519 under a key pinned in
 * `contractKeys`; `ts` ≥ the run's first ingest and ≤ now + `clockSkewMs`)
 * or when the configured `runWindowMs` expires.
 *
 * Sealing (N4C-CHANGES-3):
 *  - `closedAt` = receipt.ts + `flushGraceMs` (or the window end) — a
 *    deterministic boundary, never the access time. Ingest keeps landing
 *    until the seal point; the run freezes there.
 *  - The final head is signed ONCE. The head anchor resolves BEFORE that
 *    single signing — the anchor write (or failure) rides inside the signed
 *    head as `anchor`, so the anchor id is part of the signed evidence.
 *    Post-close ingest refusals go into a separately signed monotonic
 *    `RefusalAnnex` {runId, finalHeadDigest, refusedAfterClose, updatedAt}
 *    — the head is never re-signed, so no stale head variants exist.
 *  - The anchor covers the canonicalDigest of the UNSIGNED head fields —
 *    everything except `anchor` and `signature` — recomputable by the
 *    verifier from the signed head itself.
 *  - A runId that has ever carried records can never be re-minted.
 */

export type SinkRecordKind = "traces" | "logs";

export interface SinkRecord {
  seq: number;
  runId: string;
  kind: SinkRecordKind;
  /** sha256 of the exact request body bytes received. */
  bodyDigest: string;
  bodyBytes: number;
  contentType: string;
  receivedAt: string;
  /** sha256 of the ingest token — binds role + runId, never the plaintext. */
  tokenId: string;
  role: ContractRole | null;
  prevHash: string;
  recordDigest: string;
}

export const RECORD_SCHEMA = "ac-telemetry.record/v1";
export const HEAD_SCHEMA = "ac-telemetry.chain-head/v1";
export const CHAIN_GENESIS = `0x${"0".repeat(64)}`;

export type CloseCause = "terminal_receipt" | "window_expired" | "run_lost";

export interface SignedHead {
  schema: typeof HEAD_SCHEMA;
  runId: string;
  /** seq of the last record chained under this head; -1 on a lost head. */
  seq: number;
  headDigest: string;
  /** number of records the head claims — the verifier requires an exact match. */
  recordCount: number;
  /** true only on the close head; only a final head completes evidence. */
  final: boolean;
  signedAt: string;
  /** present on final heads — receipt.ts + flushGrace, or the window end. Deterministic; never the access time. */
  closedAt?: string;
  /** present on final heads — why the sink closed the run. */
  closeCause?: CloseCause;
  /** present on final heads — sha256 of the canonical terminal receipt (null for window auto-close). */
  receiptDigest?: string | null;
  /**
   * N7a HIGH-1: present and true ONLY when the sink lost the run's chain to
   * a restart — the head is signed, final, and explicitly marks the evidence
   * incomplete so the verifier REJECTs instead of accepting a post-restart
   * tail as the whole run.
   */
  lost?: true;
  /**
   * N4b-8 (Part B): the head anchor, INSIDE the signed head. The anchor
   * covers canonicalDigest of the head fields (everything except `anchor`
   * and `signature`); the resolved write — or the failure — is folded in
   * before the single signing. A `failed` mark is still signed: the
   * verifier decides (verifyRecords rejects it).
   */
  anchor?: HeadAnchor;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

export interface AnchorLedger {
  ledgerId: string;
  blockHeight: string | null;
  time: string | null;
  status: string;
}

/** The normalized write a TsaAnchor resolves with — its id rides the signed head. */
export interface AnchorWrite {
  /** `tsa:<commitmentId>` — the on-chain anchor identity. */
  anchorId: string;
  eventHash?: string | null;
  ledger?: AnchorLedger | null;
}

export type HeadAnchor =
  | { status: "anchored"; anchorId: string; eventHash: string | null; ledger: AnchorLedger | null }
  | { status: "failed"; error: string };

export const ANNEX_SCHEMA = "ac-telemetry.refusal-annex/v1";

/**
 * Separately signed, monotonic post-close refusal ledger. The final head is
 * immutable — every refused post-close ingest re-signs ONLY this annex, so a
 * stale head can never masquerade and an old annex cannot hide later
 * refusals (the verifier always fetches the latest via `sink.annex` / the
 * head endpoint).
 */
export interface RefusalAnnex {
  schema: typeof ANNEX_SCHEMA;
  runId: string;
  /** canonicalDigest of the WHOLE signed final head this annex belongs to. */
  finalHeadDigest: string;
  refusedAfterClose: number;
  updatedAt: string;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

/** A signed terminal receipt minted by the contract server — the only close authority the harness can carry. */
export interface TerminalReceipt {
  schema: "ac-terminal-receipt/v1";
  runId: string;
  terminalState: TerminalState;
  ts: string;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

/**
 * O-1: the v2 receipt for a LINKED run. Every field is signed — the message
 * is canonicalJson({schema, runId, terminalState, ts, lanes, linkDigest, alg,
 * keyId}). The sink accepts it only when `lanes` equals the linked set and
 * `linkDigest` equals the link's digest, then freezes every member lane.
 */
export interface TerminalReceiptV2 {
  schema: "ac-terminal-receipt/v2";
  runId: string;
  terminalState: TerminalState;
  ts: string;
  lanes: LinkedLanes;
  linkDigest: string;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

export const RUN_SET_SCHEMA = "ac-telemetry.run-set/v1";

/** One member lane of a linked run, as the read listener serves it. */
export interface RunSetLane {
  laneId: string;
  /** open: still ingesting · pending: receipt accepted, sealing at closedAt · final: sealed under a final head · empty: sealed with no records · lost: a restart lost its chain */
  state: "open" | "pending" | "final" | "empty" | "lost";
  head: SignedHead | null;
  annex: RefusalAnnex | null;
  /** post-close ingest refusals (the annex count; for an empty lane the sink's own count). */
  refusedAfterClose: number;
  /** the lane's signed-open binding (role, keyId, mcpSessionId) — the verifier's R8 scope. */
  keyId: string;
  mcpSessionId: string;
  openDigest: string;
}

/**
 * The run as the ordered set of lane heads (design §O-1 step 2). Unsigned on
 * purpose: every component is already signed — each final lane head carries
 * receiptDigest = the v2 receipt's digest, and that receipt (contract-signed)
 * names the runId, the lane set, and the linkDigest.
 */
export interface RunSetHead {
  schema: typeof RUN_SET_SCHEMA;
  runId: string;
  linkDigest: string;
  lanes: { buyer: RunSetLane[]; provider: RunSetLane[] };
  /** digest of the accepted v2 receipt; null until one is accepted. */
  receiptDigest: string | null;
  /** true once a receipt was accepted AND every member lane is final, empty, or lost. */
  final: boolean;
  /**
   * CDT-GAPS gap 3 (opt-in, `signRunSet`): the signed combined head — null
   * until the set is final and the head is signed. Absent when the option is off.
   */
  signedHead?: SignedRunSetHead | null;
}

export const RUN_SET_HEAD_SCHEMA = "ac-telemetry.run-set-head/v1";

/** One lane's entry in the signed run-set head — the stable lane facts only. */
export interface RunSetHeadLane {
  laneId: string;
  state: "final" | "empty" | "lost";
  /** canonicalDigest of the lane's WHOLE signed final head (anchor + signature included); null for an empty lane. */
  headDigest: string | null;
  /** the lane head's recordCount; 0 for an empty lane. */
  recordCount: number;
  keyId: string;
  mcpSessionId: string;
  openDigest: string;
}

/**
 * CDT-GAPS gap 3: the SIGNED combined head of a linked run — one per runId,
 * signed once when the run set is final, with the same sink key and the same
 * scheme as a single-lane SignedHead: the anchor (when configured) covers
 * canonicalDigest of every field except `anchor` and `signature`, then the
 * signature covers canonicalJson({...fields, anchor?, alg, keyId}).
 * Opt-in: built only when the sink runs with `signRunSet` (TELEMETRY_RUN_SET_HEAD=1).
 */
export interface SignedRunSetHead {
  schema: typeof RUN_SET_HEAD_SCHEMA;
  runId: string;
  linkDigest: string;
  /** digest of the accepted v2 receipt — the same value every lane head carries. */
  receiptDigest: string;
  lanes: { buyer: RunSetHeadLane[]; provider: RunSetHeadLane[] };
  /** sum of the member lanes' recordCount. */
  recordCount: number;
  final: true;
  signedAt: string;
  /** the accepted receipt's ts + flushGrace — the lanes' common seal boundary. */
  closedAt: string;
  closeCause: "terminal_receipt";
  /** present and true when any member lane is lost — the run evidence is incomplete. */
  lost?: true;
  anchor?: HeadAnchor;
  signature: { alg: "ed25519"; keyId: string; sig: `0x${string}` };
}

export const TERMINAL_STATES = new Set([
  "settled",
  "no_agreement",
  "verification_failed",
  "blocked_by_policy",
  "budget_exhausted",
  "harness_error",
  // N4b-8 (Part B): the contract server's cancel path terminates with
  // "cancelled" — the close receipt must be accepted or a cancelled run can
  // never close on receipt authority.
  "cancelled",
  // Half-bound run release: the contract server ends a run that never got
  // both parties bound before its certificate expired with "expired_unbound".
  "expired_unbound",
  // CDT-GAPS gap 2: a fully bound run that reached its TTL non-terminal
  // (contract server CONTRACT_EXPIRE_AT_TTL=1) ends with "expired".
  "expired",
]);
export type TerminalState =
  | "settled"
  | "no_agreement"
  | "verification_failed"
  | "blocked_by_policy"
  | "budget_exhausted"
  | "harness_error"
  | "cancelled"
  | "expired_unbound"
  | "expired";

export type SinkRefusalCode =
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "REQUEST_INVALID"
  | "PAYLOAD_TOO_LARGE"
  | "RUN_FULL"
  | "RUN_CLOSED"
  | "ANCHOR_NOT_CONFIGURED"
  | "ANCHOR_FAILED"
  | "RECEIPT_INVALID"
  | "RECEIPT_STALE"
  | "RUN_EMPTY"
  /** N7a HIGH-1: the run was opened before a restart — its chain is gone. */
  | "RUN_LOST"
  /** O-1 lane-open / link refusals (lanes.ts). */
  | "NOT_ENROLLED"
  | "LANE_REUSED"
  | "LANE_LIMIT"
  | "LINK_INVALID"
  | "LINK_CONFLICT";

export interface SinkRefusal {
  ok: false;
  code: SinkRefusalCode;
}

export interface TsaAnchor {
  /**
   * Anchor `digestHex` (the canonical digest of the unsigned final-head
   * fields). Production wires `createMcpTsaAnchor` — tsa_issue over /mcp
   * with the sink's own Clockchain key; retries/backoff live inside the
   * client. The resolved AnchorWrite — or a thrown error — is folded into
   * the head before its single signing.
   */
  issue(digestHex: string): Promise<AnchorWrite>;
}

export interface SinkLimits {
  maxBodyBytes: number;
  maxRunBytes: number;
  maxRunRecords: number;
}

const DEFAULT_LIMITS: SinkLimits = {
  maxBodyBytes: 4 * 1024 * 1024,
  maxRunBytes: 64 * 1024 * 1024,
  maxRunRecords: 8192,
};

export type VerifyFailureCode =
  | "EMPTY_CHAIN"
  | "SEQ_GAP"
  | "CHAIN_LINK"
  | "BODY_MISSING"
  | "BODY_DIGEST"
  | "RECORD_DIGEST"
  | "RECORD_COUNT"
  | "HEAD_MISMATCH"
  | "HEAD_KEY_UNKNOWN"
  | "HEAD_SIGNATURE"
  | "HEAD_INVALID"
  | "ANNEX_MISSING"
  | "ANNEX_MISMATCH"
  | "ANNEX_KEY_UNKNOWN"
  | "ANNEX_SIGNATURE"
  /** N7a HIGH-1: the head marks the run lost to a restart — never complete. */
  | "RUN_LOST"
  /** N4b-8: the head is signed but its anchor block marks the tsa anchor failed. */
  | "ANCHOR_FAILED";

/**
 * ok === true            chain valid AND sealed under a final head (complete)
 * ok === "incomplete"    chain + signature valid but head is non-final — a
 *                        prefix can never masquerade as complete evidence
 * ok === false           integrity failure
 */
export type VerifyResult =
  | { ok: true; final: true; head: SignedHead }
  | { ok: "incomplete"; final: false; head: SignedHead }
  | { ok: false; code: VerifyFailureCode };

/** A record plus the exact body bytes the sink stored for it. */
export interface RecordEntry {
  record: SinkRecord;
  body: string | Uint8Array;
}

export interface TelemetrySink {
  ingest(input: {
    token: string | undefined;
    kind: SinkRecordKind;
    body: Uint8Array;
    contentType: string;
  }): { ok: true; record: SinkRecord } | SinkRefusal;
  /**
   * Close a run — sink authority only: a FRESH signed terminal receipt from
   * the contract server (ed25519, pinned in `contractKeys`; ts ≥ first ingest
   * and ≤ now+clockSkew) is required; window expiry auto-closes without one.
   * The run seals at `receipt.ts + flushGraceMs` (or the window end): ingest
   * keeps landing until then, the final head is signed ONCE at the seal
   * (anchor resolved first — the write or the failure rides inside it), and
   * post-close refusals go into the signed annex. Idempotent; a retry
   * returns the same signed head — anchor retries live inside the client.
   */
  closeRun(input: {
    runId: string;
    receipt?: unknown;
  }): Promise<
    | { ok: true; head: SignedHead | RunSetHead; anchorResult: unknown }
    | { ok: true; head: null; pendingClosedAt: string }
    | SinkRefusal
  >;
  isClosed(runId: string): boolean;
  /** O-1: the linked run as its ordered lane heads; null when `runId` is not linked. */
  runSet(runId: string): RunSetHead | null;
  /**
   * CDT-GAPS gap 3: the signed combined head of a linked run once its set is
   * final (anchor resolved first, signed once, cached). Null when the option
   * is off, the runId is not linked, or the set is not final yet.
   */
  runSetHead(runId: string): Promise<SignedRunSetHead | null>;
  /** The accepted terminal receipt body (v1 or v2) — the verifier fetches it from the sink, never the harness. */
  receipt(runId: string): unknown | null;
  /** Record metadata for a run (no bodies). */
  recordsFor(runId: string): SinkRecord[];
  /** Records WITH bodies — the extraction helper's and verifier's input. */
  exportRecords(runId: string): RecordEntry[];
  /** Signed chain head for a run — cached per tip; the final head once closed. */
  head(runId: string): SignedHead | null;
  /** Latest signed refusal annex for a closed run (null while open). */
  annex(runId: string): RefusalAnnex | null;
  verifyRun(runId: string, publicKeys?: Record<string, KeyObject>): VerifyResult;
  /** Optional anchor seam — calls the injected TsaAnchor with the head digest. */
  anchorHead(runId: string): Promise<{ ok: true; anchorResult: unknown } | SinkRefusal>;
}

const recordDigestOf = (r: Omit<SinkRecord, "recordDigest">): string =>
  canonicalDigest({ schema: RECORD_SCHEMA, ...r });

/**
 * Minimal OTLP/JSON shape validation: a JSON object whose signal field is an
 * array. Deliberately shallow — records are stored verbatim and the extractor
 * parses spans/logs structurally, so ingest only enforces the envelope.
 */
function isValidOtlpShape(kind: SinkRecordKind, body: Uint8Array): boolean {
  let doc: unknown;
  try {
    doc = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    return false;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return false;
  const key = kind === "traces" ? "resourceSpans" : "resourceLogs";
  return Array.isArray((doc as Record<string, unknown>)[key]);
}

function entryOf(raw: RecordEntry | (SinkRecord & { body?: string | Uint8Array })): RecordEntry | null {
  if (raw !== null && typeof raw === "object" && "record" in raw) {
    const e = raw as RecordEntry;
    if (e.record !== null && typeof e.record === "object") {
      return e.body === undefined ? null : { record: e.record, body: e.body };
    }
  }
  const r = raw as SinkRecord & { body?: string | Uint8Array };
  if (r.body === undefined) return null;
  return { record: r, body: r.body };
}

/**
 * Independent chain verification: recomputes sha256(body) per record,
 * recomputes every recordDigest, checks the prevHash linkage, enforces the
 * head's recordCount, and verifies the head signature (over a message that
 * includes keyId + alg). Only a final head yields ok === true.
 */
export function verifyRecords(
  records: readonly (RecordEntry | (SinkRecord & { body?: string | Uint8Array }))[],
  head: SignedHead | null | undefined,
  publicKeys: Record<string, KeyObject>,
): VerifyResult {
  if (head === null || head === undefined || head.schema !== HEAD_SCHEMA) {
    return { ok: false, code: "HEAD_INVALID" };
  }
  // A lost head is signed but can never stand as complete evidence.
  if (head.lost === true) return { ok: false, code: "RUN_LOST" };
  // N4b-8: a head whose signed anchor block marks failure — the anchor
  // write never landed, so the verifier rejects rather than silently
  // accepting un-anchored evidence. (No `anchor` field = anchor not
  // configured — not a failure.)
  if (head.anchor?.status === "failed") return { ok: false, code: "ANCHOR_FAILED" };
  if (records.length === 0) return { ok: false, code: "EMPTY_CHAIN" };

  let expectedPrev = CHAIN_GENESIS;
  for (let i = 0; i < records.length; i += 1) {
    const entry = entryOf(records[i]);
    if (entry === null) return { ok: false, code: "BODY_MISSING" };
    const record = entry.record;
    if (record.seq !== i) return { ok: false, code: "SEQ_GAP" };
    if (record.prevHash !== expectedPrev) return { ok: false, code: "CHAIN_LINK" };
    if (bodyDigest(
      typeof entry.body === "string" ? Buffer.from(entry.body, "utf8") : entry.body,
    ) !== record.bodyDigest) {
      return { ok: false, code: "BODY_DIGEST" };
    }
    const unsigned: Omit<SinkRecord, "recordDigest"> = {
      seq: record.seq,
      runId: record.runId,
      kind: record.kind,
      bodyDigest: record.bodyDigest,
      bodyBytes: record.bodyBytes,
      contentType: record.contentType,
      receivedAt: record.receivedAt,
      tokenId: record.tokenId,
      role: record.role,
      prevHash: record.prevHash,
    };
    if (recordDigestOf(unsigned) !== record.recordDigest) {
      return { ok: false, code: "RECORD_DIGEST" };
    }
    expectedPrev = record.recordDigest;
  }
  const last = records[records.length - 1];
  const lastRecord = entryOf(last)?.record;
  if (lastRecord === undefined) return { ok: false, code: "BODY_MISSING" };
  // Count first: a truncated tail against a final head reports the gap.
  if (head.recordCount !== records.length) return { ok: false, code: "RECORD_COUNT" };
  if (head.runId !== lastRecord.runId || head.seq !== lastRecord.seq || head.headDigest !== lastRecord.recordDigest) {
    return { ok: false, code: "HEAD_MISMATCH" };
  }

  // The signature covers every head field AND the claimed keyId/alg —
  // reconstruct the message from the head itself so a tampered closeCause,
  // receiptDigest, or refusedAfterClose fails verification.
  const { signature, ...headFields } = head;
  if (signature.alg !== "ed25519") return { ok: false, code: "HEAD_SIGNATURE" };
  const sigBytes = Buffer.from(signature.sig.slice(2), "hex");
  if (sigBytes.length !== 64) return { ok: false, code: "HEAD_SIGNATURE" };
  const publicKey = publicKeys[signature.keyId];
  if (publicKey === undefined) return { ok: false, code: "HEAD_KEY_UNKNOWN" };
  const messageFields = { ...headFields, alg: signature.alg, keyId: signature.keyId };
  if (!verify(null, Buffer.from(canonicalJson(messageFields), "utf8"), publicKey, sigBytes)) {
    return { ok: false, code: "HEAD_SIGNATURE" };
  }
  if (head.final !== true) return { ok: "incomplete", final: false, head };
  return { ok: true, final: true, head };
}

interface ClosedRun {
  /**
   * The signed final head — present once materialize() completes: the anchor
   * resolves first, then the head signs ONCE with the anchor block inside.
   * Until then `sink.head()` serves the last signed tip head (final:false).
   */
  head?: SignedHead;
  /** Resolves to the signed final head — never rejects (failure signs anchor:failed). */
  ready: Promise<SignedHead>;
  anchorResult: unknown;
}

interface PendingClose {
  receiptDigest: string;
  closedAtMs: number;
}

const DEFAULT_FLUSH_GRACE_MS = 30_000;
const DEFAULT_CLOCK_SKEW_MS = 60_000;

export function createTelemetrySink(options: {
  signer: { keyId: string; privateKey: KeyObject };
  tokens: TokenStore;
  now?: () => number;
  anchor?: TsaAnchor;
  limits?: Partial<SinkLimits>;
  /**
   * N7a HIGH-1: durable per-run markers. With a ledger, a restart never
   * silently restarts a chain — ingest for a previously-opened run without an
   * in-memory chain is refused RUN_LOST and marked permanently lost; a later
   * close signs a `lost: true` head the verifier must reject. WITHOUT a
   * ledger (pure in-memory mode) a restart can only produce a partial head —
   * deploys MUST always pass one.
   */
  runLedger?: RunLedger;
  /** pinned contract-server ed25519 keys — the only accepted close authority. */
  contractKeys?: Record<string, KeyObject>;
  /** maximum run window; expiry auto-closes the run at the window end. */
  runWindowMs?: number;
  /** flush grace after a receipt's ts before the run seals. */
  flushGraceMs?: number;
  /** bound on how far ahead of the sink clock a receipt ts may be. */
  clockSkewMs?: number;
  /**
   * O-1: the lane registry (lanes.ts). With it, a contract runId that has a
   * link closes ONLY by a matching ac-terminal-receipt/v2; v1 stays accepted
   * for every run with no link. Without it, behaviour is unchanged.
   */
  lanes?: { linkFor(runId: string): RunLink | undefined; lane(laneId: string): LaneRecord | undefined };
  /**
   * CDT-GAPS gap 3: sign one combined head per linked run once its set is
   * final (TELEMETRY_RUN_SET_HEAD=1). Off by default: the run set stays the
   * unsigned O-1 document and `head` stays null for a linked runId.
   */
  signRunSet?: boolean;
}): TelemetrySink {
  const now = options.now ?? Date.now;
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const flushGraceMs = options.flushGraceMs ?? DEFAULT_FLUSH_GRACE_MS;
  const clockSkewMs = options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const chains = new Map<string, SinkRecord[]>();
  /** Persistence-failure poisoning: a run whose durable markers could not be
   *  written is lost for the life of this process — it must never close as
   *  complete (HIGH-1). */
  const lostInMemory = new Set<string>();
  const bodies = new Map<string, Map<number, Buffer>>();
  const runBytes = new Map<string, number>();
  const runOpenedMs = new Map<string, number>();
  const pendingClose = new Map<string, PendingClose>();
  const closed = new Map<string, ClosedRun>();
  const annexes = new Map<string, RefusalAnnex>();
  // N4b-8: refusals accrue here while the anchor window is open — the count
  // mints into the annex the moment the final head is signed.
  const annexCounts = new Map<string, number>();
  const headCache = new Map<string, { tip: string; head: SignedHead }>();
  /** Accepted receipt bodies (v1 or v2), served to the verifier on the read listener. */
  const receipts = new Map<string, unknown>();
  /** O-1: linked runs whose v2 receipt was accepted. */
  const linkedClose = new Map<string, PendingClose>();
  /** O-1: lanes sealed with no records — no head exists; their ingest is revoked. */
  const emptySealed = new Map<string, number>();
  const emptyRefused = new Map<string, number>();
  /** CDT-GAPS gap 3: one signed combined head per linked runId — built once, never re-signed. */
  const runSetHeads = new Map<string, { head?: SignedRunSetHead; ready: Promise<SignedRunSetHead> }>();

  /** Sign a head message; every non-signature field lands top-level on the head. */
  function signHead(fields: Omit<SignedHead, "signature" | "anchor"> & { anchor?: HeadAnchor }): SignedHead {
    const message = { ...fields, alg: "ed25519" as const, keyId: options.signer.keyId };
    const sig = sign(null, Buffer.from(canonicalJson(message), "utf8"), options.signer.privateKey);
    return { ...fields, signature: { alg: "ed25519", keyId: options.signer.keyId, sig: `0x${sig.toString("hex")}` } };
  }

  function tipFields(runId: string, chain: SinkRecord[]): Omit<SignedHead, "signature"> {
    const last = chain[chain.length - 1];
    return {
      schema: HEAD_SCHEMA,
      runId,
      seq: last.seq,
      headDigest: last.recordDigest,
      recordCount: chain.length,
      final: false,
      signedAt: new Date(now()).toISOString(),
    };
  }

  function finalFields(runId: string, chain: SinkRecord[], cr: { closedAt: string; closeCause: CloseCause; receiptDigest: string | null }): Omit<SignedHead, "signature"> {
    return {
      ...tipFields(runId, chain),
      final: true,
      closedAt: cr.closedAt,
      closeCause: cr.closeCause,
      receiptDigest: cr.receiptDigest,
    };
  }

  /** Sign (or re-sign) the refusal annex — the ONLY mutable post-close doc. */
  function signAnnex(runId: string, head: SignedHead, refusedAfterClose: number): RefusalAnnex {
    const fields = {
      schema: ANNEX_SCHEMA as typeof ANNEX_SCHEMA,
      runId,
      finalHeadDigest: canonicalDigest(head),
      refusedAfterClose,
      updatedAt: new Date(now()).toISOString(),
      alg: "ed25519" as const,
      keyId: options.signer.keyId,
    };
    const sig = sign(null, Buffer.from(canonicalJson(fields), "utf8"), options.signer.privateKey);
    const { alg, keyId, ...rest } = fields;
    return { ...rest, signature: { alg, keyId, sig: `0x${sig.toString("hex")}` } };
  }

  /** Post-close ingest refusal: the head never moves — only the annex bumps. */
  function bumpRefused(runId: string): void {
    const cr = closed.get(runId);
    if (cr === undefined) return;
    const count = (annexCounts.get(runId) ?? 0) + 1;
    annexCounts.set(runId, count);
    // The annex mints once the final head exists — before that (the anchor
    // window) the count accrues and materialize() signs it in.
    if (annexes.has(runId) && cr.head !== undefined) {
      annexes.set(runId, signAnnex(runId, cr.head, count));
    }
  }

  /**
   * Seal the run at a deterministic boundary (receipt.ts+grace or window end).
   * Revokes ingest tokens, marks the runId used forever, then drives the
   * final head: the anchor covers the unsigned head fields, resolves, and
   * the head signs ONCE with the anchor block folded in. Retries live inside
   * the anchor client; an exhausted failure signs anchor:"failed" — still a
   * signed head, the verifier decides.
   */
  function freeze(runId: string, cause: CloseCause, receiptDigest: string | null, closedAtMs: number): ClosedRun | null {
    const chain = chains.get(runId);
    if (chain === undefined || chain.length === 0) return null;
    const fields = finalFields(runId, chain, {
      closedAt: new Date(closedAtMs).toISOString(),
      closeCause: cause,
      receiptDigest,
    });
    const cr: ClosedRun = {
      head: undefined,
      anchorResult: null,
      ready: Promise.resolve(undefined as unknown as SignedHead),
    };
    cr.ready = materialize(runId, cr, fields);
    closed.set(runId, cr);
    annexCounts.set(runId, 0);
    options.tokens.revokeRunIngests(runId);
    options.tokens.markRunUsed(runId);
    // Transition write: seal-time chain tip for post-mortem audit (MED — the
    // ledger only writes on open/close/lost, never per record).
    try {
      options.runLedger?.markClosed(runId, {
        lastSeq: chain.at(-1)!.seq,
        lastHash: chain.at(-1)!.recordDigest,
        closedAtMs,
      });
    } catch { /* a ledger write failure at seal does not invalidate the signed head */ }
    return cr;
  }

  /**
   * Anchor-then-sign, exactly once. The anchored subject is
   * canonicalDigest of the unsigned head fields — recomputable by a
   * verifier as the head minus `anchor` and `signature`. Never rejects:
   * a failed anchor signs head.anchor = {status:"failed"}.
   */
  async function materialize(
    runId: string,
    cr: ClosedRun,
    fields: Omit<SignedHead, "signature" | "anchor">,
  ): Promise<SignedHead> {
    if (options.anchor === undefined) {
      cr.head = signHead(fields);
    } else {
      try {
        const write = await options.anchor.issue(canonicalDigest(fields));
        cr.anchorResult = write;
        cr.head = signHead({
          ...fields,
          anchor: {
            status: "anchored",
            anchorId: write.anchorId,
            eventHash: write.eventHash ?? null,
            ledger: write.ledger ?? null,
          },
        });
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        cr.anchorResult = error;
        // N4b-8: the failure is folded into the signed head — never skipped,
        // never a silent un-anchored head.
        cr.head = signHead({ ...fields, anchor: { status: "failed", error } });
      }
    }
    annexes.set(runId, signAnnex(runId, cr.head, annexCounts.get(runId) ?? 0));
    return cr.head;
  }

  /**
   * Settle a run if a seal boundary has been reached — an accepted receipt's
   * closedAt, or the window end. ClosedAt is the boundary, never now().
   */
  function maybeSettle(runId: string): void {
    if (closed.has(runId) || emptySealed.has(runId)) return;
    const t = now();
    const pending = pendingClose.get(runId);
    if (pending !== undefined && t >= pending.closedAtMs) {
      pendingClose.delete(runId);
      const cr = freeze(runId, "terminal_receipt", pending.receiptDigest, pending.closedAtMs);
      if (cr !== null) {
        void cr.ready;
      } else {
        // O-1: a linked lane that never carried a record seals EMPTY — its
        // ingest authority ends exactly like a frozen run's (pendingClose is
        // only ever set for an empty chain on a lane).
        options.tokens.revokeRunIngests(runId);
        options.tokens.markRunUsed(runId);
        emptySealed.set(runId, pending.closedAtMs);
      }
      return;
    }
    const opened = runOpenedMs.get(runId);
    if (opened === undefined) return;
    const windowEndMs = options.runWindowMs === undefined ? undefined : opened + options.runWindowMs;
    if (windowEndMs !== undefined && t >= windowEndMs) {
      const cr = freeze(runId, "window_expired", null, windowEndMs);
      if (cr !== null) void cr.ready;
    }
  }

  /** Validate a contract-server terminal receipt; returns {digest, tsMs} or null. */
  function checkReceipt(receipt: unknown, runId: string): { digest: string; tsMs: number } | null {
    if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return null;
    const r = receipt as Record<string, unknown>;
    if (r.schema !== "ac-terminal-receipt/v1") return null;
    if (r.runId !== runId) return null;
    if (typeof r.terminalState !== "string" || !TERMINAL_STATES.has(r.terminalState as TerminalState)) return null;
    if (typeof r.ts !== "string") return null;
    const tsMs = Date.parse(r.ts);
    if (Number.isNaN(tsMs)) return null;
    const s = r.signature;
    if (typeof s !== "object" || s === null) return null;
    const sig = s as Record<string, unknown>;
    if (sig.alg !== "ed25519" || typeof sig.keyId !== "string") return null;
    if (typeof sig.sig !== "string" || !/^0x[0-9a-f]{128}$/.test(sig.sig)) return null;
    const publicKey = options.contractKeys?.[sig.keyId];
    if (publicKey === undefined) return null;
    const message = canonicalJson({
      schema: r.schema, runId: r.runId, terminalState: r.terminalState, ts: r.ts,
      alg: sig.alg, keyId: sig.keyId,
    });
    if (!verify(null, Buffer.from(message, "utf8"), publicKey, Buffer.from(sig.sig.slice(2), "hex"))) return null;
    return { digest: canonicalDigest({ schema: r.schema, runId: r.runId, terminalState: r.terminalState, ts: r.ts, signature: s }), tsMs };
  }

  /**
   * O-1: validate an ac-terminal-receipt/v2 against the run's link. Every
   * field is signed; `lanes` must equal the linked set and `linkDigest` the
   * link's digest. Returns {digest, tsMs} or null.
   */
  function checkReceiptV2(receipt: unknown, runId: string, link: RunLink): { digest: string; tsMs: number } | null {
    if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return null;
    const r = receipt as Record<string, unknown>;
    const keys = Object.keys(r);
    const want = ["schema", "runId", "terminalState", "ts", "lanes", "linkDigest", "signature"];
    if (keys.length !== want.length || !want.every((k) => Object.hasOwn(r, k))) return null;
    if (r.schema !== "ac-terminal-receipt/v2") return null;
    if (r.runId !== runId) return null;
    if (typeof r.terminalState !== "string" || !TERMINAL_STATES.has(r.terminalState as TerminalState)) return null;
    if (typeof r.ts !== "string") return null;
    const tsMs = Date.parse(r.ts);
    if (Number.isNaN(tsMs)) return null;
    if (typeof r.linkDigest !== "string" || r.linkDigest !== link.linkDigest) return null;
    let lanesJson: string;
    try { lanesJson = canonicalJson(r.lanes); } catch { return null; }
    if (lanesJson !== canonicalJson(link.lanes)) return null;
    const s = r.signature;
    if (typeof s !== "object" || s === null) return null;
    const sig = s as Record<string, unknown>;
    if (sig.alg !== "ed25519" || typeof sig.keyId !== "string") return null;
    if (typeof sig.sig !== "string" || !/^0x[0-9a-f]{128}$/.test(sig.sig)) return null;
    const publicKey = options.contractKeys?.[sig.keyId];
    if (publicKey === undefined) return null;
    const fields = {
      schema: r.schema, runId: r.runId, terminalState: r.terminalState, ts: r.ts,
      lanes: r.lanes, linkDigest: r.linkDigest,
    };
    const message = canonicalJson({ ...fields, alg: sig.alg, keyId: sig.keyId });
    if (!verify(null, Buffer.from(message, "utf8"), publicKey, Buffer.from(sig.sig.slice(2), "hex"))) return null;
    return { digest: canonicalDigest({ ...fields, signature: s }), tsMs };
  }

  /** Sign a `lost: true` final head for a run whose chain a restart lost (HIGH-1). */
  function closeLost(runId: string, receiptDigest: string): SignedHead {
    lostInMemory.add(runId);
    try { options.runLedger?.markLost(runId, now()); } catch { /* refuse regardless */ }
    const ts = new Date(now()).toISOString();
    const lostHead = signHead({
      schema: HEAD_SCHEMA,
      runId,
      seq: -1,
      headDigest: CHAIN_GENESIS,
      recordCount: 0,
      final: true,
      signedAt: ts,
      closedAt: ts,
      closeCause: "run_lost",
      receiptDigest,
      lost: true,
    });
    closed.set(runId, { head: lostHead, ready: Promise.resolve(lostHead), anchorResult: null });
    options.tokens.markRunUsed(runId);
    return lostHead;
  }

  const hasDurableTrace = (runId: string): boolean =>
    lostInMemory.has(runId)
    || options.runLedger?.isOpened(runId) === true
    || options.tokens.isRunUsed(runId);

  function runSetLane(laneId: string): RunSetLane {
    maybeSettle(laneId);
    const rec = options.lanes?.lane(laneId);
    const cr = closed.get(laneId);
    const signed = head(laneId);
    const annex = annexes.get(laneId) ?? null;
    let state: RunSetLane["state"];
    if (emptySealed.has(laneId)) state = "empty";
    else if (cr !== undefined && cr.head !== undefined) state = cr.head.lost === true ? "lost" : "final";
    else if (cr !== undefined || pendingClose.has(laneId)) state = "pending";
    else state = "open";
    return {
      laneId,
      state,
      head: signed,
      annex: annex === null ? null : { ...annex, signature: { ...annex.signature } },
      refusedAfterClose: emptySealed.has(laneId) ? (emptyRefused.get(laneId) ?? 0) : (annexCounts.get(laneId) ?? 0),
      keyId: rec?.keyId ?? "",
      mcpSessionId: rec?.mcpSessionId ?? "",
      openDigest: rec?.openDigest ?? "",
    };
  }

  function unsignedRunSet(runId: string): RunSetHead | null {
    const link = options.lanes?.linkFor(runId);
    if (link === undefined) return null;
    const lanes = { buyer: link.lanes.buyer.map(runSetLane), provider: link.lanes.provider.map(runSetLane) };
    const accepted = linkedClose.get(runId);
    const all = [...lanes.buyer, ...lanes.provider];
    return {
      schema: RUN_SET_SCHEMA,
      runId,
      linkDigest: link.linkDigest,
      lanes,
      receiptDigest: accepted?.receiptDigest ?? null,
      final: accepted !== undefined && all.every((l) => l.state === "final" || l.state === "empty" || l.state === "lost"),
    };
  }

  /**
   * CDT-GAPS gap 3: the combined head's unsigned fields, from a FINAL run set.
   * Every lane is reduced to its stable facts; the mutable per-lane refusal
   * count stays in that lane's own signed annex.
   */
  function runSetHeadFields(set: RunSetHead, accepted: PendingClose): Omit<SignedRunSetHead, "signature" | "anchor"> {
    const lane = (l: RunSetLane): RunSetHeadLane => ({
      laneId: l.laneId,
      state: l.state as RunSetHeadLane["state"],
      headDigest: l.head === null ? null : canonicalDigest(l.head),
      recordCount: l.head === null ? 0 : l.head.recordCount,
      keyId: l.keyId,
      mcpSessionId: l.mcpSessionId,
      openDigest: l.openDigest,
    });
    const lanes = { buyer: set.lanes.buyer.map(lane), provider: set.lanes.provider.map(lane) };
    const all = [...lanes.buyer, ...lanes.provider];
    return {
      schema: RUN_SET_HEAD_SCHEMA,
      runId: set.runId,
      linkDigest: set.linkDigest,
      receiptDigest: accepted.receiptDigest,
      lanes,
      recordCount: all.reduce((n, l) => n + l.recordCount, 0),
      final: true,
      signedAt: new Date(now()).toISOString(),
      closedAt: new Date(accepted.closedAtMs).toISOString(),
      closeCause: "terminal_receipt",
      ...(all.some((l) => l.state === "lost") ? { lost: true as const } : {}),
    };
  }

  /** Same key, same scheme as signHead: canonicalJson({...fields, alg, keyId}). */
  function signRunSetHead(fields: Omit<SignedRunSetHead, "signature">): SignedRunSetHead {
    const message = { ...fields, alg: "ed25519" as const, keyId: options.signer.keyId };
    const sig = sign(null, Buffer.from(canonicalJson(message), "utf8"), options.signer.privateKey);
    return { ...fields, signature: { alg: "ed25519", keyId: options.signer.keyId, sig: `0x${sig.toString("hex")}` } };
  }

  /** Start (once) the anchor-then-sign of a final linked run's combined head. */
  function ensureRunSetHead(set: RunSetHead): { head?: SignedRunSetHead; ready: Promise<SignedRunSetHead> } | null {
    if (options.signRunSet !== true || !set.final) return null;
    const existing = runSetHeads.get(set.runId);
    if (existing !== undefined) return existing;
    const accepted = linkedClose.get(set.runId);
    if (accepted === undefined) return null;
    const fields = runSetHeadFields(set, accepted);
    const entry: { head?: SignedRunSetHead; ready: Promise<SignedRunSetHead> } = {
      ready: Promise.resolve(undefined as unknown as SignedRunSetHead),
    };
    entry.ready = (async () => {
      if (options.anchor === undefined) {
        entry.head = signRunSetHead(fields);
      } else {
        try {
          const write = await options.anchor.issue(canonicalDigest(fields));
          entry.head = signRunSetHead({
            ...fields,
            anchor: { status: "anchored", anchorId: write.anchorId, eventHash: write.eventHash ?? null, ledger: write.ledger ?? null },
          });
        } catch (err) {
          // As materialize(): the failure is signed in, never skipped.
          entry.head = signRunSetHead({ ...fields, anchor: { status: "failed", error: err instanceof Error ? err.message : String(err) } });
        }
      }
      return entry.head;
    })();
    runSetHeads.set(set.runId, entry);
    return entry;
  }

  function runSet(runId: string): RunSetHead | null {
    const set = unsignedRunSet(runId);
    if (set === null || options.signRunSet !== true) return set;
    const entry = ensureRunSetHead(set);
    return { ...set, signedHead: entry?.head ?? null };
  }

  async function runSetHead(runId: string): Promise<SignedRunSetHead | null> {
    const set = unsignedRunSet(runId);
    if (set === null) return null;
    const entry = ensureRunSetHead(set);
    if (entry === null) return null;
    return entry.ready;
  }

  /**
   * O-1 close of a LINKED run: only a v2 receipt matching the link. Every
   * member lane seals at receipt.ts + flushGrace under that receipt's digest
   * (a lane already window-expired stays as it is — disclosed in the set);
   * a lane whose chain a restart lost signs `lost: true`; a lane that never
   * carried a record seals empty.
   */
  async function closeLinked(runId: string, receipt: unknown, link: RunLink): Promise<
    | { ok: true; head: RunSetHead; anchorResult: unknown }
    | { ok: true; head: null; pendingClosedAt: string }
    | SinkRefusal
  > {
    let accepted = linkedClose.get(runId);
    if (accepted === undefined) {
      const checked = checkReceiptV2(receipt, runId, link);
      if (checked === null) return { ok: false, code: "RECEIPT_INVALID" };
      if (checked.tsMs < link.tsMs - clockSkewMs || checked.tsMs > now() + clockSkewMs) {
        return { ok: false, code: "RECEIPT_STALE" };
      }
      accepted = { receiptDigest: checked.digest, closedAtMs: checked.tsMs + flushGraceMs };
      linkedClose.set(runId, accepted);
      receipts.set(runId, JSON.parse(JSON.stringify(receipt)));
      for (const laneId of [...link.lanes.buyer, ...link.lanes.provider]) {
        maybeSettle(laneId);
        if (closed.has(laneId) || emptySealed.has(laneId)) continue;
        const chain = chains.get(laneId);
        if ((chain === undefined || chain.length === 0) && hasDurableTrace(laneId)) {
          closeLost(laneId, checked.digest);
          continue;
        }
        pendingClose.set(laneId, { receiptDigest: accepted.receiptDigest, closedAtMs: accepted.closedAtMs });
      }
    }
    const members = [...link.lanes.buyer, ...link.lanes.provider];
    for (const laneId of members) maybeSettle(laneId);
    if (members.some((laneId) => pendingClose.has(laneId))) {
      return { ok: true, head: null, pendingClosedAt: new Date(accepted.closedAtMs).toISOString() };
    }
    await Promise.all(members.map((laneId) => closed.get(laneId)?.ready));
    // Gap 3 (opt-in): the combined head signs once the lanes are final — the
    // close answer carries it, so a close retry returns the same signed bytes.
    await runSetHead(runId);
    return { ok: true, head: runSet(runId) as RunSetHead, anchorResult: null };
  }

  function ingest(input: {
    token: string | undefined;
    kind: SinkRecordKind;
    body: Uint8Array;
    contentType: string;
  }): { ok: true; record: SinkRecord } | SinkRefusal {
    const peeked = input.token === undefined ? undefined : options.tokens.peek(input.token);
    if (peeked === undefined) return { ok: false, code: "UNAUTHORIZED" };
    // Kind first (no oracle): non-ingest holders never learn a run is closed.
    if (peeked.kind !== "ingest") return { ok: false, code: "FORBIDDEN" };
    maybeSettle(peeked.runId);
    if (emptySealed.has(peeked.runId)) {
      emptyRefused.set(peeked.runId, (emptyRefused.get(peeked.runId) ?? 0) + 1);
      return { ok: false, code: "RUN_CLOSED" };
    }
    // Then closed state: a post-close write is refused loudly AND counted in
    // the re-signed final head — the verifier requires refusedAfterClose === 0.
    if (closed.has(peeked.runId)) {
      bumpRefused(peeked.runId);
      return { ok: false, code: "RUN_CLOSED" };
    }
    const resolved = options.tokens.resolve(input.token ?? "");
    if (resolved === undefined) return { ok: false, code: "UNAUTHORIZED" };
    let chain = chains.get(resolved.runId);
    if (chain === undefined) {
      // HIGH-1: no in-memory chain + any durable trace of the run (ledger
      // marker, usedRunIds cross-check, or a persistence failure earlier in
      // this process) → the records died with a restart. Permanently lost;
      // it can never silently restart at seq 0.
      if (
        lostInMemory.has(resolved.runId)
        || options.runLedger?.isOpened(resolved.runId)
        || options.tokens.isRunUsed(resolved.runId)
      ) {
        try { options.runLedger?.markLost(resolved.runId, now()); } catch { /* already lost */ }
        return { ok: false, code: "RUN_LOST" };
      }
    }
    if (input.kind !== "traces" && input.kind !== "logs") {
      return { ok: false, code: "REQUEST_INVALID" };
    }
    if (input.body.byteLength > limits.maxBodyBytes) {
      return { ok: false, code: "PAYLOAD_TOO_LARGE" };
    }
    if (chain === undefined) {
      // HIGH-1 ordering: the durable run-opened markers are persisted BEFORE
      // any in-memory mutation — a persistence failure never leaves records
      // chained without a marker. On failure the run is poisoned in memory
      // (and pushed to usedRunIds best-effort) so it can never close as
      // complete, this process or the next.
      const openedAtMs = now();
      try {
        options.runLedger?.markOpened(resolved.runId, openedAtMs);
      } catch {
        lostInMemory.add(resolved.runId);
        try { options.tokens.markRunUsed(resolved.runId); } catch { /* poisoned either way */ }
        try { options.runLedger?.markLost(resolved.runId, openedAtMs); } catch { /* refuse regardless */ }
        return { ok: false, code: "RUN_LOST" };
      }
      try {
        options.tokens.markRunUsed(resolved.runId);
      } catch {
        lostInMemory.add(resolved.runId);
        try { options.runLedger?.markLost(resolved.runId, openedAtMs); } catch { /* ledger is already opened */ }
        return { ok: false, code: "RUN_LOST" };
      }
      chains.set(resolved.runId, []);
      chain = chains.get(resolved.runId)!;
      runOpenedMs.set(resolved.runId, openedAtMs);
      bodies.set(resolved.runId, new Map());
      runBytes.set(resolved.runId, 0);
    }
    if (chain.length >= limits.maxRunRecords) return { ok: false, code: "RUN_FULL" };
    const usedBytes = runBytes.get(resolved.runId) ?? 0;
    if (usedBytes + input.body.byteLength > limits.maxRunBytes) {
      return { ok: false, code: "RUN_FULL" };
    }
    if (!isValidOtlpShape(input.kind, input.body)) {
      return { ok: false, code: "REQUEST_INVALID" };
    }

    const unsigned: Omit<SinkRecord, "recordDigest"> = {
      seq: chain.length,
      runId: resolved.runId,
      kind: input.kind,
      bodyDigest: bodyDigest(input.body),
      bodyBytes: input.body.byteLength,
      contentType: input.contentType,
      receivedAt: new Date(now()).toISOString(),
      tokenId: resolved.tokenId,
      role: resolved.role,
      prevHash: chain.at(-1)?.recordDigest ?? CHAIN_GENESIS,
    };
    const record: SinkRecord = { ...unsigned, recordDigest: recordDigestOf(unsigned) };
    chain.push(record);
    runBytes.set(resolved.runId, usedBytes + input.body.byteLength);
    bodies.get(resolved.runId)!.set(record.seq, Buffer.from(input.body));
    return { ok: true, record: { ...record } };
  }

  async function closeRun(input: {
    runId: string;
    receipt?: unknown;
  }): Promise<
    | { ok: true; head: SignedHead | RunSetHead; anchorResult: unknown }
    | { ok: true; head: null; pendingClosedAt: string }
    | SinkRefusal
  > {
    // O-1: a linked contract runId closes only by its v2 receipt; a lane is
    // never closed directly by any receipt (it seals through its link or its
    // window). v1 is unchanged for every run with no link.
    const link = options.lanes?.linkFor(input.runId);
    if (link !== undefined) return closeLinked(input.runId, input.receipt, link);
    if (isLaneId(input.runId)) return { ok: false, code: "RECEIPT_INVALID" };
    maybeSettle(input.runId);
    const existing = closed.get(input.runId);
    if (existing !== undefined) {
      // The head materializes once the anchor resolves — await it. A failed
      // anchor signs anchor:"failed" into the head; retries live inside the
      // anchor client, so a retry here returns the same signed head.
      const head = await existing.ready;
      return { ok: true, head, anchorResult: existing.anchorResult };
    }
    const pending = pendingClose.get(input.runId);
    if (pending !== undefined) {
      // A receipt was already accepted; the run seals at its closedAt.
      return { ok: true, head: null, pendingClosedAt: new Date(pending.closedAtMs).toISOString() };
    }
    const checked = checkReceipt(input.receipt, input.runId);
    if (checked === null) return { ok: false, code: "RECEIPT_INVALID" };
    const chain = chains.get(input.runId);
    if (chain === undefined || chain.length === 0) {
      // HIGH-1: any durable trace of the run (ledger marker, usedRunIds
      // cross-check, or a persistence failure this boot) with no in-memory
      // chain — its records died with a restart. The receipt is still
      // verified authority; sign a `lost: true` head so the close is on
      // record and the verifier REJECTs rather than silently swallowing the
      // evidence gap. Permanently lost.
      if (hasDurableTrace(input.runId)) {
        receipts.set(input.runId, JSON.parse(JSON.stringify(input.receipt)));
        return { ok: true, head: closeLost(input.runId, checked.digest), anchorResult: null };
      }
      return { ok: false, code: "RUN_EMPTY" };
    }
    // Freshness: ts at-or-after the run's opening, and not beyond the skew.
    const opened = runOpenedMs.get(input.runId);
    if (opened === undefined || checked.tsMs < opened || checked.tsMs > now() + clockSkewMs) {
      return { ok: false, code: "RECEIPT_STALE" };
    }
    // Seal at receipt.ts + flushGrace — immediate if already due.
    const closedAtMs = checked.tsMs + flushGraceMs;
    pendingClose.set(input.runId, { receiptDigest: checked.digest, closedAtMs });
    receipts.set(input.runId, JSON.parse(JSON.stringify(input.receipt)));
    maybeSettle(input.runId);
    const sealed = closed.get(input.runId);
    if (sealed === undefined) {
      return { ok: true, head: null, pendingClosedAt: new Date(closedAtMs).toISOString() };
    }
    const head = await sealed.ready;
    return { ok: true, head, anchorResult: sealed.anchorResult };
  }

  function head(runId: string): SignedHead | null {
    maybeSettle(runId);
    const cr = closed.get(runId);
    // During the anchor window (head not yet signed) fall through to the
    // last signed tip head — final:false, honest interim state.
    if (cr !== undefined && cr.head !== undefined) return cr.head;
    const chain = chains.get(runId);
    if (chain === undefined || chain.length === 0) return null;
    const tip = chain[chain.length - 1].recordDigest;
    const cached = headCache.get(runId);
    if (cached !== undefined && cached.tip === tip) return cached.head;
    const signed = signHead({ ...tipFields(runId, chain) });
    headCache.set(runId, { tip, head: signed });
    return signed;
  }

  return {
    ingest,
    closeRun,
    isClosed: (runId) => { maybeSettle(runId); return closed.has(runId) || emptySealed.has(runId); },
    runSet,
    runSetHead,
    receipt(runId) {
      const r = receipts.get(runId);
      return r === undefined ? null : JSON.parse(JSON.stringify(r));
    },
    annex(runId) {
      maybeSettle(runId);
      const a = annexes.get(runId);
      return a === undefined ? null : { ...a, signature: { ...a.signature } };
    },
    recordsFor(runId) {
      maybeSettle(runId);
      return (chains.get(runId) ?? []).map((r) => ({ ...r }));
    },
    exportRecords(runId) {
      maybeSettle(runId);
      const runBodies = bodies.get(runId);
      return (chains.get(runId) ?? []).map((record) => ({
        record: { ...record },
        body: (runBodies?.get(record.seq) ?? Buffer.alloc(0)).toString("utf8"),
      }));
    },
    head,
    verifyRun(runId, publicKeys) {
      const entries = (chains.get(runId) ?? []).map((record) => ({
        record,
        body: bodies.get(runId)?.get(record.seq) ?? Buffer.alloc(0),
      }));
      const signedHead = head(runId);
      const keys = publicKeys ?? {
        [options.signer.keyId]: createPublicKey(options.signer.privateKey),
      };
      return verifyRecords(entries, signedHead, keys);
    },
    async anchorHead(runId) {
      const signedHead = head(runId);
      if (signedHead === null) return { ok: false, code: "RUN_EMPTY" };
      if (options.anchor === undefined) return { ok: false, code: "ANCHOR_NOT_CONFIGURED" };
      return { ok: true, anchorResult: await options.anchor.issue(signedHead.headDigest) };
    },
  };
}
