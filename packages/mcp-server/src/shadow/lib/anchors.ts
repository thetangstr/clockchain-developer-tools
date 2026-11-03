// Vendored from clockchain-shadow/ts/src/anchors.ts (source sha256 8905a48ef06d8332bf5f0652995f846ae35a39590995ef19409433570addaf02) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Clockchain receipts in a record (spec §5, §8 `anchors`), checked the same way for the verifier and for time windows.
// Only a receipt that passes these checks may bound time (v1.1 correction C8).
import { DOMAIN, hash, PROFILE } from './profile.js';
import type { ShadowEvent } from './types.js';

const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);

export type Scope = { operatorId: unknown; sessionId: unknown; network: unknown };

// One receipt. Field values are as found in the record; `ok` says whether it commits to what it claims, and `count`
// is the verified number of steps a checkpoint anchor covers.
export type ReceiptCheck = {
  seq: unknown;
  pos: number; // 1-based position in the record
  marker: 'start' | 'checkpoint';
  expected: unknown;
  ledgerId: unknown;
  blockHeight: unknown;
  blockTime: unknown;
  submittedAt: unknown;
  count: number | null;
  ok: boolean;
};

export const scopeOf = (events: ShadowEvent[]): Scope => {
  const b = events[0]?.body as any;
  return { operatorId: b?.operatorId, sessionId: b?.sessionId, network: b?.payload?.network };
};

const safeHash = (domain: string, v: unknown): string | null => {
  try {
    return hash(domain, v);
  } catch {
    return null;
  }
};

// Every receipt in the record: a non-null session.opened `receipt`, and every collector clockchain.anchored step.
// prefixRoot(n) is the Merkle root of the first n step hashes (merklePrefixRoots).
export function checkReceipts(events: ShadowEvent[], scope: Scope, prefixRoot: (n: number) => string): ReceiptCheck[] {
  const out: ReceiptCheck[] = [];
  const opened = (events[0]?.body as any)?.payload;
  const scoped = typeof scope.operatorId === 'string' && typeof scope.sessionId === 'string';
  const startHash = scoped && isObj(opened) && typeof opened.nonce === 'string'
    ? hash(DOMAIN.sessionStart, { operatorId: scope.operatorId, sessionId: scope.sessionId, nonce: opened.nonce }) : null;
  events.forEach((e, i) => {
    const body = e?.body as any;
    if (!isObj(body) || body.source?.boundary !== 'collector') return;
    const p = body.payload;
    let raw: unknown, marker: 'start' | 'checkpoint';
    let ok = true;
    if (body.kind === 'session.opened') {
      if (!isObj(p) || p.receipt === null || p.receipt === undefined) return;
      raw = p.receipt;
      marker = 'start';
      if (!isObj(raw)) ok = false;
    } else if (body.kind === 'clockchain.anchored') {
      raw = p;
      if (!isObj(p)) ok = false;
      // A start marker never carries a checkpoint, and no other marker exists.
      marker = isObj(p) && p.marker === 'start' ? 'start' : 'checkpoint';
      if (isObj(p) && (p.marker !== 'start' && p.marker !== 'checkpoint')) ok = false;
      if (isObj(p) && p.marker === 'start' && ('checkpoint' in p || 'checkpointHash' in p)) ok = false;
    } else return;
    const r = isObj(raw) ? raw : {};
    const expected = marker === 'start' ? (body.kind === 'session.opened' ? (p as any).startHash : r.startHash) : r.checkpointHash;
    const c: ReceiptCheck = {
      seq: body.seq, pos: i + 1, marker, expected, ledgerId: r.ledgerId ?? null, blockHeight: r.blockHeight ?? null,
      blockTime: r.blockTime ?? null, submittedAt: r.submittedAt ?? null, count: null, ok,
    };
    if (!(typeof c.ledgerId === 'string' && c.ledgerId && typeof expected === 'string' && HEX64.test(expected))) c.ok = false;
    else if (marker === 'start') {
      if (!startHash || expected !== startHash || opened.startHash !== expected) c.ok = false;
    } else {
      const cb = r.checkpoint, n = isObj(cb) ? cb.count : null;
      const good = c.ok && isObj(cb) && safeHash(DOMAIN.checkpoint, cb) === expected && Number.isSafeInteger(n) && n >= 1 && n < c.pos &&
        cb.operatorId === scope.operatorId && cb.sessionId === scope.sessionId && cb.network === scope.network &&
        cb.head === events[n - 1]?.hash && cb.merkleRoot === prefixRoot(n);
      if (good) c.count = n;
      else c.ok = false;
    }
    out.push(c);
  });
  return out;
}

// A checkpoint the recorder queued for Clockchain whose receipt is not in the record (spec §9 pendingCheckpoints): it
// must hash to its stated hash and commit to a prefix of the record, in the record's scope.
export function pendingCheckpointOk(p: unknown, events: ShadowEvent[], scope: Scope, prefixRoot: (n: number) => string): boolean {
  if (!isObj(p) || typeof p.hash !== 'string' || !HEX64.test(p.hash) || !isObj(p.body)) return false;
  const cb = p.body, n = cb.count;
  return safeHash(DOMAIN.checkpoint, cb) === p.hash && cb.profile === PROFILE && Number.isSafeInteger(n) && n >= 1 && n <= events.length &&
    cb.operatorId === scope.operatorId && cb.sessionId === scope.sessionId && cb.network === scope.network &&
    cb.head === events[n - 1]?.hash && cb.merkleRoot === prefixRoot(n);
}
