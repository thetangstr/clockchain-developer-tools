/**
 * Stopwatch — a tamper-evident elapsed-time measurement anchored on-chain.
 *
 * `stopwatchStart()` anchors a "start" marker via `core.log`, waits for it to be
 * confirmed (block written), and returns a handle. `stopwatchStop(handle)`
 * anchors a "stop" marker the same way. `elapsed(measurement)` computes the
 * delta from the two CONFIRMED `createdTimestamp`s (parsed with
 * {@link parseGatewayTime}), so the measured interval is bracketed by two
 * independently-anchored consensus events rather than the caller's wall clock.
 *
 * Both ledgerIds + blockHeights are surfaced so a counterparty can re-verify
 * each marker keylessly via `core.verifyOnChain`.
 */
import type { LogResponse } from "@clockchain/core";
import { computeHash } from "@clockchain/core";
import { parseGatewayTime } from "./time.js";

/** The slice of {@link ClockchainClient} the stopwatch needs. */
export interface StopwatchClient {
  log(
    entry: { assetHash: string; assetReferenceId: string; additionalInfo?: string },
  ): Promise<LogResponse>;
  waitForConfirmation(ledgerId: string, timeoutMs?: number): Promise<LogResponse>;
}

/** One anchored stopwatch marker (start or stop). */
export interface StopwatchMarker {
  ledgerId: string;
  blockHeight: string | null;
  /** The gateway's createdTimestamp for the marker (DD-MM-YYYY ... UTC). */
  createdTimestamp: string;
  /** Parsed epoch ms (UTC) of createdTimestamp. */
  epochMs: number;
  /** The hash anchored for this marker. */
  assetHash: string;
  assetReferenceId: string;
}

/** Handle returned by {@link stopwatchStart}; pass it to {@link stopwatchStop}. */
export interface StopwatchHandle {
  label: string;
  start: StopwatchMarker;
}

/** A completed measurement: both anchored markers. */
export interface StopwatchMeasurement {
  label: string;
  start: StopwatchMarker;
  stop: StopwatchMarker;
}

function markerOf(log: LogResponse): StopwatchMarker {
  return {
    ledgerId: log.ledgerId,
    blockHeight: log.blockHeight,
    createdTimestamp: log.createdTimestamp,
    epochMs: parseGatewayTime(log.createdTimestamp),
    assetHash: log.assetHash,
    assetReferenceId: log.assetReferenceId,
  };
}

const ts = () => Date.now();

/**
 * Anchor a stopwatch "start" marker and wait for confirmation.
 *
 * @param client  a {@link ClockchainClient} (or compatible).
 * @param label   a human label; also the assetReferenceId base.
 * @param timeoutMs  confirmation timeout, ms (default 15000).
 */
export async function stopwatchStart(
  client: StopwatchClient,
  label: string,
  timeoutMs = 15000,
): Promise<StopwatchHandle> {
  const assetReferenceId = `stopwatch:${label}:start`;
  const assetHash = computeHash(`stopwatch-start:${label}:${ts()}`);
  const created = await client.log({
    assetHash,
    assetReferenceId,
    additionalInfo: "stopwatch start",
  });
  const confirmed = await client.waitForConfirmation(created.ledgerId, timeoutMs);
  return { label, start: markerOf(confirmed) };
}

/**
 * Anchor a stopwatch "stop" marker, wait for confirmation, and pair it with the
 * handle's start marker into a {@link StopwatchMeasurement}.
 */
export async function stopwatchStop(
  client: StopwatchClient,
  handle: StopwatchHandle,
  timeoutMs = 15000,
): Promise<StopwatchMeasurement> {
  const assetReferenceId = `stopwatch:${handle.label}:stop`;
  const assetHash = computeHash(`stopwatch-stop:${handle.label}:${ts()}`);
  const created = await client.log({
    assetHash,
    assetReferenceId,
    additionalInfo: "stopwatch stop",
  });
  const confirmed = await client.waitForConfirmation(created.ledgerId, timeoutMs);
  return { label: handle.label, start: handle.start, stop: markerOf(confirmed) };
}

/**
 * Elapsed milliseconds between the two CONFIRMED markers' consensus
 * createdTimestamps. NaN if either timestamp is unparseable.
 */
export function elapsed(measurement: StopwatchMeasurement): number {
  return measurement.stop.epochMs - measurement.start.epochMs;
}

/**
 * The ledgerIds + blockHeights of both markers — what a counterparty feeds to
 * `core.verifyOnChain(ledgerId, blockHeight)` to re-confirm each anchor keylessly.
 */
export function verificationRefs(measurement: StopwatchMeasurement): {
  start: { ledgerId: string; blockHeight: string | null };
  stop: { ledgerId: string; blockHeight: string | null };
} {
  return {
    start: {
      ledgerId: measurement.start.ledgerId,
      blockHeight: measurement.start.blockHeight,
    },
    stop: {
      ledgerId: measurement.stop.ledgerId,
      blockHeight: measurement.stop.blockHeight,
    },
  };
}
