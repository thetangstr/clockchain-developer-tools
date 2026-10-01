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

/**
 * Durable per-run markers (N7a-changes-1 HIGH-1). The record chains and the
 * refusal annexes are deliberately in-memory (N4c), but "a run was opened"
 * must SURVIVE a container restart: without this file, a post-restart ingest
 * would start the run over at seq 0 and the final head would verify over the
 * post-restart tail only — a valid-looking partial chain.
 *
 *   runs.json = {
 *     schema: "ac-telemetry.runs/v1",
 *     initializedAtMs,   // durable init marker — written at first boot (N4b-8 F8)
 *     runs: { "<runId>": { openedAtMs, lastSeq, lastHash, closedAtMs?, lostAtMs? } },
 *   }
 *
 * The versioned EMPTY document is persisted at construction, before any
 * token provisioning can write tokens.json. That makes "tokens.json exists
 * but runs.json does not" unambiguous: the initialized ledger was LOST
 * (deleted/rolled volume) and boot must refuse — a never-touched volume has
 * neither file.
 *
 * Writes happen only on TRANSITIONS — open, close, lost — never per record
 * (N7a-review MED: a full-file rewrite per ingest is unbounded). Terminal
 * entries (closedAtMs/lostAtMs) are pruned past retentionMs; pruned runIds
 * stay permanently refused via the usedRunIds cross-check in tokens.json,
 * which is never pruned.
 */

export const RUN_LEDGER_SCHEMA = "ac-telemetry.runs/v1" as const;
export const DEFAULT_LEDGER_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

export interface RunMarker {
  openedAtMs: number;
  /** Tip at the last transition — -1 while the run is merely open. */
  lastSeq: number;
  lastHash: string;
  closedAtMs?: number;
  lostAtMs?: number;
}

export interface RunLedger {
  isOpened(runId: string): boolean;
  isLost(runId: string): boolean;
  /** Write-once run-open marker — MUST be persisted before any in-memory chain mutation. */
  markOpened(runId: string, openedAtMs: number): void;
  /** Terminal seal transition — records the chain tip for post-mortem audit. */
  markClosed(runId: string, tip: { lastSeq: number; lastHash: string; closedAtMs: number }): void;
  /** Permanently lost: ingest refuses RUN_LOST; close signs lost:true. */
  markLost(runId: string, lostAtMs: number): void;
}

interface RunLedgerDoc {
  schema: typeof RUN_LEDGER_SCHEMA;
  /** First durable write — proves the ledger was initialized (N4b-8 F8). */
  initializedAtMs: number;
  runs: Record<string, RunMarker>;
}

function readLedger(file: string): RunLedgerDoc | null {
  if (!existsSync(file)) return null;
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (typeof raw !== "object" || raw === null || (raw as RunLedgerDoc).schema !== RUN_LEDGER_SCHEMA) {
    throw new Error(`corrupt ${file}: not a ${RUN_LEDGER_SCHEMA} document`);
  }
  const doc = raw as RunLedgerDoc;
  if (typeof doc.runs !== "object" || doc.runs === null) {
    throw new Error(`corrupt ${file}: bad shape`);
  }
  return {
    schema: RUN_LEDGER_SCHEMA,
    // Pre-marker ledgers count as initialized — the file existing IS proof.
    initializedAtMs: typeof doc.initializedAtMs === "number" ? doc.initializedAtMs : 0,
    // Null-prototype map: a runId like "__proto__" must never smuggle state.
    runs: Object.assign(Object.create(null), doc.runs),
  };
}

function writeLedgerAtomic(file: string, doc: RunLedgerDoc): void {
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
}

export function createRunLedger(options: {
  file: string;
  now?: () => number;
  /** Prune terminal (closed/lost) markers older than this — default 7d. */
  retentionMs?: number;
}): RunLedger {
  const file = options.file;
  const now = options.now ?? Date.now;
  const retentionMs = options.retentionMs ?? DEFAULT_LEDGER_RETENTION_MS;
  let doc = readLedger(file); // fail closed on corrupt state
  if (doc === null) {
    // N4b-8 F8: durably initialize the versioned empty ledger NOW — before
    // any token provisioning can write tokens.json. After this write,
    // "tokens.json exists but runs.json does not" can only mean a lost
    // initialized ledger, so main.ts's boot refusal stays fail-closed.
    doc = { schema: RUN_LEDGER_SCHEMA, initializedAtMs: now(), runs: Object.create(null) };
    writeLedgerAtomic(file, doc);
  }

  const persist = () => {
    const cutoff = now() - retentionMs;
    for (const [runId, m] of Object.entries(doc.runs)) {
      const terminalAt = m.closedAtMs ?? m.lostAtMs;
      if (terminalAt !== undefined && terminalAt < cutoff) delete doc.runs[runId];
    }
    writeLedgerAtomic(file, doc);
  };

  return {
    isOpened: (runId) => Object.hasOwn(doc.runs, runId),
    isLost: (runId) => Object.hasOwn(doc.runs, runId) && doc.runs[runId].lostAtMs !== undefined,
    markOpened(runId, openedAtMs) {
      const existing = Object.hasOwn(doc.runs, runId) ? doc.runs[runId] : undefined;
      if (existing !== undefined) {
        if (existing.openedAtMs !== openedAtMs) {
          throw new Error(`run ledger: openedAtMs mismatch for ${runId}`);
        }
        return;
      }
      doc.runs[runId] = { openedAtMs, lastSeq: -1, lastHash: "" };
      persist();
    },
    markClosed(runId, tip) {
      const marker = Object.hasOwn(doc.runs, runId) ? doc.runs[runId] : undefined;
      if (marker === undefined) {
        // A run closed without a ledger marker (e.g. ledger pruned or from a
        // pre-ledger build) — still record the terminal tip.
        doc.runs[runId] = { openedAtMs: tip.closedAtMs, lastSeq: tip.lastSeq, lastHash: tip.lastHash, closedAtMs: tip.closedAtMs };
      } else {
        marker.lastSeq = tip.lastSeq;
        marker.lastHash = tip.lastHash;
        marker.closedAtMs = tip.closedAtMs;
      }
      persist();
    },
    markLost(runId, lostAtMs) {
      const marker = Object.hasOwn(doc.runs, runId)
        ? doc.runs[runId]
        : (doc.runs[runId] = { openedAtMs: lostAtMs, lastSeq: -1, lastHash: "" });
      if (marker.lostAtMs === undefined) {
        marker.lostAtMs = lostAtMs;
        persist();
      }
    },
  };
}
