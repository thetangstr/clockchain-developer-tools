// Vendored from clockchain-shadow/ts/src/windows.ts (source sha256 c72031465c5ccd0caf4b8279206f884cde976bc12e3707bcd3ac2217c0eb504f) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Time windows (spec §7). Order comes from the hash chain; time comes only from Clockchain receipts in the chain, and
// only from receipts that pass the anchors check (v1.1 correction C8).
//
// Lower bound: a step chained after a receipt was recorded after Clockchain issued that receipt's ledger id, so it is
// no earlier than the receipt's submission time (Clockchain's createdTimestamp). The block time is later than that and
// is NOT a lower bound. Upper bound: a step inside a checkpoint anchored in block h existed by that block's time; the
// steps covered are the anchor's verified count, and only checkpoint anchors give upper bounds.
//
// Times are compared with the one strict grammar of parseTime (v1.1 correction C11); a receipt time that does not
// parse gives no bound. The sweep is O(n log n) (v1.1 correction C21).
import { compareTime, merklePrefixRoots, parseTime } from './profile.js';
import { checkReceipts, scopeOf, type ReceiptCheck } from './anchors.js';
import type { ShadowEvent } from './types.js';

export type Bound = { time: string; seq: number; ledgerId: string; blockHeight: string | null };
export type Window = { seq: number; lower: Bound | null; upper: Bound | null };

const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
type Candidate = { bound: Bound; key: [number, number]; pos: number };

// receipts: the record's checked receipts, as the verifier computed them against the packet's checkpoint scope. When
// omitted they are checked here against the scope of the first step.
export function windows(events: ShadowEvent[], o: { receipts?: ReceiptCheck[] } = {}): Window[] {
  const receipts = o.receipts ?? checkReceipts(events, scopeOf(events), merklePrefixRoots(events.map((e) => e.hash)));
  const n = events.length;
  const lowerAtPos: (Candidate | null)[] = new Array(n + 1).fill(null);
  const upperByCount: Candidate[][] = Array.from({ length: n + 1 }, () => []);
  for (const r of receipts) {
    if (!r.ok || !isStr(r.ledgerId)) continue;
    const blockHeight = isStr(r.blockHeight) ? r.blockHeight : null;
    const seq = r.seq as number;
    const sub = parseTime(r.submittedAt);
    if (sub && isStr(r.submittedAt)) lowerAtPos[r.pos] = { bound: { time: r.submittedAt, seq, ledgerId: r.ledgerId, blockHeight }, key: sub, pos: r.pos };
    const bt = parseTime(r.blockTime);
    if (r.marker === 'checkpoint' && r.count != null && bt && isStr(r.blockTime) && blockHeight)
      upperByCount[r.count].push({ bound: { time: r.blockTime, seq, ledgerId: r.ledgerId, blockHeight }, key: bt, pos: r.pos });
  }
  // lowerUpTo[p]: the latest-submitted receipt at a position <= p (the first one, on a tie).
  const lowerUpTo: (Candidate | null)[] = new Array(n + 1).fill(null);
  let best: Candidate | null = null;
  for (let p = 1; p <= n; p++) {
    const c = lowerAtPos[p];
    if (c && (!best || compareTime(c.key, best.key) > 0)) best = c;
    lowerUpTo[p] = best;
  }
  // upperFrom[s]: the earliest block time among anchors covering at least s steps (the first one, on a tie).
  const upperFrom: (Candidate | null)[] = new Array(n + 2).fill(null);
  let ub: Candidate | null = null;
  for (let s = n; s >= 1; s--) {
    for (const c of upperByCount[s]) {
      const d = ub ? compareTime(c.key, ub.key) : -1;
      if (!ub || d < 0 || (d === 0 && c.pos < ub.pos)) ub = c;
    }
    upperFrom[s] = ub;
  }
  const assigned = new Map<string, number>();
  events.forEach((e, i) => {
    const run = e.body.source?.agentRunId;
    if (e.body.kind === 'task.assigned' && run && !assigned.has(run)) assigned.set(run, i + 1);
  });
  return events.map((e, i) => {
    const pos = i + 1;
    const run = e.body.source?.agentRunId;
    const a = run && assigned.has(run) ? Math.min(assigned.get(run)!, pos) : pos;
    return { seq: e.body.seq, lower: lowerUpTo[a]?.bound ?? null, upper: upperFrom[pos]?.bound ?? null };
  });
}
