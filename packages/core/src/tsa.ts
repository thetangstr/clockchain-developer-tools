/**
 * TSA (Time-Stamped Agreement) commitment lifecycle.
 *
 * A 5-verb lifecycle layered on the anchor primitives:
 *   tsa_issue -> tsa_checkpoint -> tsa_attest (kept/broken) -> tsa_settle, plus
 *   tsa_status.
 *
 * Each write anchors a SHA-256 of a CANONICAL event payload under a shared
 * reference `tsa:<commitmentId>` via {@link ClockchainClient.log} and returns a
 * receipt the CALLER holds. The chain stores only the hash + reference + neutral
 * time — never the payload (additionalInfo is plain-text-only and is stripped of
 * structure server-side, so we anchor a hash and keep content client-side, in
 * line with Clockchain's "anchor a hash + neutral time, content never leaves"
 * model).
 *
 * MVP boundary: anchor the lifecycle and compute a kept/broken verdict from the
 * on-chain anchor time vs the caller-supplied deadline; the consequence is
 * RECORDED, not enforced.
 */
import { canonicalize } from "./receipt.js";
import { computeHash } from "./hash.js";
import { parseClockTime, deriveAnchorStatus } from "./client.js";
import type { ClockchainClient } from "./client.js";
import type { AnchorStatus, LogResponse } from "./types.js";

/** The on-chain anchor a TSA receipt carries (what the caller holds). */
export interface TsaAnchor {
  ledgerId: string;
  blockHeight: string | null;
  /** Clockchain consensus/record time for this anchor (createdTimestamp). */
  time: string | null;
  /**
   * Anchor status derived from blockHeight (AGE-193): "anchored" once a block
   * height is present, else "pending" — so a TSA write is never read as success
   * before it is on-chain.
   */
  status: AnchorStatus;
}

/** Input to {@link tsaIssue}. */
export interface TsaIssueInput {
  agentId: string;
  commitment: string;
  /** The deadline the verdict is judged against (gateway DD-MM-YYYY or ISO). */
  deadline: string;
  /** Optional recorded (not enforced) consequence of breaking the commitment. */
  consequence?: string;
}

/** Input to {@link tsaCheckpoint}. */
export interface TsaCheckpointInput {
  commitmentId: string;
  note: string;
  evidenceHash?: string;
}

/** Input to {@link tsaAttest}. */
export interface TsaAttestInput {
  commitmentId: string;
  /** The agent's self-reported outcome. The verdict reconciles it with time. */
  outcome: "kept" | "broken";
  /** The deadline to judge `onTime` against (gateway DD-MM-YYYY or ISO). */
  deadline: string;
  evidence?: string;
}

/** Input to {@link tsaSettle}. */
export interface TsaSettleInput {
  commitmentId: string;
  outcome: "kept" | "broken";
  consequence: string;
}

/** The reconciled verdict in a {@link TsaAttestReceipt}. */
export type TsaVerdict = "kept" | "broken-late" | "broken";

/** Receipt for a write verb (issue / checkpoint / settle). */
export interface TsaReceipt {
  commitmentId: string;
  event: Record<string, unknown>;
  anchor: TsaAnchor;
  eventHash: string;
}

/** Receipt for {@link tsaAttest} — carries the reconciled verdict. */
export interface TsaAttestReceipt {
  commitmentId: string;
  outcome: "kept" | "broken";
  onTime: boolean;
  verdict: TsaVerdict;
  attestedAt: string | null;
  deadline: string;
  anchor: TsaAnchor;
  eventHash: string;
}

/** The on-chain trail for a commitment (sequence, not content). */
export interface TsaStatus {
  commitmentId: string;
  assetReferenceId: string;
  count: number;
  events: Array<{
    ledgerId: string;
    blockHeight: string | null;
    time: string | null;
    assetHash: string;
  }>;
}

/**
 * Deterministic commitment id from the agent + commitment + deadline. Stable, so
 * the same agreement always resolves to the same `tsa:<id>` reference.
 */
export function computeCommitmentId(
  agentId: string,
  commitment: string,
  deadline: string,
): string {
  return computeHash(`tsa|${agentId}|${commitment}|${deadline}`).slice(0, 24);
}

/** The shared reference id every event for a commitment is anchored under. */
function referenceFor(commitmentId: string): string {
  return `tsa:${commitmentId}`;
}

/**
 * Anchor a canonical event payload under `tsa:<commitmentId>` and return the
 * pieces a TSA receipt is built from. The payload stays client-side; only its
 * SHA-256 hash + the reference + neutral time go on-chain.
 */
async function anchorEvent(
  client: ClockchainClient,
  commitmentId: string,
  event: Record<string, unknown>,
  label: string,
): Promise<{ log: LogResponse; eventHash: string }> {
  const eventHash = computeHash(canonicalize(event));
  const log = await client.log({
    assetHash: eventHash,
    assetReferenceId: referenceFor(commitmentId),
    // Plain-text label only — the gateway strips JSON/structure server-side.
    additionalInfo: label,
  });
  return { log, eventHash };
}

/** Build the {@link TsaAnchor} a caller holds from a log record. */
function anchorOf(log: LogResponse): TsaAnchor {
  return {
    ledgerId: log.ledgerId,
    blockHeight: log.blockHeight,
    time: log.createdTimestamp ?? null,
    // AGE-193: carry the honest anchor status through the whole TSA lifecycle.
    status: log.status ?? deriveAnchorStatus(log.blockHeight),
  };
}

/**
 * Issue a commitment: anchor the agreement and return its receipt. The
 * commitmentId is deterministic (agent + commitment + deadline).
 */
export async function tsaIssue(
  client: ClockchainClient,
  input: TsaIssueInput,
): Promise<TsaReceipt> {
  const commitmentId = computeCommitmentId(
    input.agentId,
    input.commitment,
    input.deadline,
  );
  const event: Record<string, unknown> = {
    kind: "issue",
    commitmentId,
    agentId: input.agentId,
    commitment: input.commitment,
    deadline: input.deadline,
    consequence: input.consequence ?? null,
  };
  const { log, eventHash } = await anchorEvent(
    client,
    commitmentId,
    event,
    "tsa:issue",
  );
  return { commitmentId, event, anchor: anchorOf(log), eventHash };
}

/** Checkpoint progress against a commitment (anchors a note + optional evidence hash). */
export async function tsaCheckpoint(
  client: ClockchainClient,
  input: TsaCheckpointInput,
): Promise<TsaReceipt> {
  const { commitmentId } = input;
  const event: Record<string, unknown> = {
    kind: "checkpoint",
    commitmentId,
    note: input.note,
    evidenceHash: input.evidenceHash ?? null,
  };
  const { log, eventHash } = await anchorEvent(
    client,
    commitmentId,
    event,
    "tsa:checkpoint",
  );
  return { commitmentId, event, anchor: anchorOf(log), eventHash };
}

/**
 * Attest a commitment as kept/broken and reconcile it with on-chain time. The
 * anchor time is the neutral, attested instant the verdict is judged against:
 * `onTime = attestTime <= deadlineTime` (both parsed with
 * {@link parseClockTime}, gateway DD-MM-YYYY FIRST). Verdict:
 *   - outcome "kept"  &&  onTime  -> "kept"
 *   - outcome "kept"  && !onTime  -> "broken-late"
 *   - outcome "broken"            -> "broken"
 */
export async function tsaAttest(
  client: ClockchainClient,
  input: TsaAttestInput,
): Promise<TsaAttestReceipt> {
  const { commitmentId, outcome, deadline } = input;
  const event: Record<string, unknown> = {
    kind: "attest",
    commitmentId,
    outcome,
    deadline,
    evidence: input.evidence ?? null,
  };
  const { log, eventHash } = await anchorEvent(
    client,
    commitmentId,
    event,
    "tsa:attest",
  );
  const anchor = anchorOf(log);

  const attestMs = parseClockTime(anchor.time);
  const deadlineMs = parseClockTime(deadline);
  // When either time is unparseable, fall back to NOT on time so a missing /
  // malformed deadline never silently grades a late commitment as kept.
  const onTime =
    !isNaN(attestMs) && !isNaN(deadlineMs) ? attestMs <= deadlineMs : false;

  let verdict: TsaVerdict;
  if (outcome === "broken") verdict = "broken";
  else verdict = onTime ? "kept" : "broken-late";

  return {
    commitmentId,
    outcome,
    onTime,
    verdict,
    attestedAt: anchor.time,
    deadline,
    anchor,
    eventHash,
  };
}

/**
 * Settle a commitment: RECORD (not enforce) the final outcome + consequence as a
 * terminal anchor in the trail.
 */
export async function tsaSettle(
  client: ClockchainClient,
  input: TsaSettleInput,
): Promise<TsaReceipt> {
  const { commitmentId } = input;
  const event: Record<string, unknown> = {
    kind: "settle",
    commitmentId,
    outcome: input.outcome,
    consequence: input.consequence,
  };
  const { log, eventHash } = await anchorEvent(
    client,
    commitmentId,
    event,
    "tsa:settle",
  );
  return { commitmentId, event, anchor: anchorOf(log), eventHash };
}

/**
 * Read the on-chain trail for a commitment via exact-match
 * `searchAsset("tsa:<commitmentId>")`. Reports the anchored SEQUENCE (count,
 * ledgerIds, block heights, times, hashes) — the payloads live in the caller's
 * receipts, never on-chain.
 */
export async function tsaStatus(
  client: ClockchainClient,
  commitmentId: string,
): Promise<TsaStatus> {
  const assetReferenceId = referenceFor(commitmentId);
  const records = await client.searchAsset(assetReferenceId);
  const events = records.map((r) => ({
    ledgerId: r.ledgerId,
    blockHeight: r.blockHeight,
    time: r.createdTimestamp ?? null,
    assetHash: r.assetHash,
  }));
  return {
    commitmentId,
    assetReferenceId,
    count: events.length,
    events,
  };
}
