// Vendored from clockchain-shadow/ts/src/profile.ts (source sha256 23feb670070882a8672ae88e3f33bb58d85c91da8e126374538bb843f1104569) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Canonical profile shadow-json-safeint-v1 (spec/SPEC.md §2). Every hash in a Shadow record goes through here, and the
// Python library must produce byte-identical output on spec/vectors.
import { createHash } from 'node:crypto';

export const PROFILE = 'shadow-json-safeint-v1';
export const MAX_DEPTH = 48;
export const MAX_PACKET_BYTES = 16_000_000;

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

// Keys sort by UTF-16 code unit (JavaScript's default string order), which is what the 27 October prototype signed.
const byCodeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function canonical(value: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) throw new Error('Maximum canonical depth exceeded');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('Invalid Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('Only safe integers allowed');
    return String(value);
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) throw new Error('Sparse or extended array');
    return '[' + value.map((x) => canonical(x, depth + 1)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new Error('Unsupported canonical value');
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort(byCodeUnit).map((k) => canonical(k) + ':' + canonical(obj[k], depth + 1)).join(',') + '}';
  }
  throw new Error('Unsupported canonical value');
}

export const sha256 = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex');
export const hash = (domain: string, value: unknown) => sha256(domain + '\0' + canonical(value));

export const DOMAIN = {
  event: 'shadow:event:v1',
  checkpoint: 'shadow:checkpoint:v1',
  leaf: 'shadow:leaf:v1',
  node: 'shadow:node:v1',
  empty: 'shadow:empty:v1',
  publicKey: 'shadow:public-key:v1',
  identity: 'shadow:identity:v1',
  transcript: 'shadow:hermes-transcript:v1',
  sessionStart: 'shadow:session-start:v1',
} as const;

export type ProofStep = { side: 'left' | 'right'; hash: string };

// Binary Merkle tree over leaf hashes; an odd last node pairs with itself. Proof steps name the sibling's side.
export function merkle(hashes: string[]): { root: string; proofs: ProofStep[][] } {
  if (!hashes.length) return { root: hash(DOMAIN.empty, []), proofs: [] };
  let level = hashes.map((h) => hash(DOMAIN.leaf, h));
  const levels = [level];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash(DOMAIN.node, [level[i], level[i + 1] ?? level[i]]));
    levels.push(next);
    level = next;
  }
  const proofs = hashes.map((_, index) => {
    let j = index;
    const path: ProofStep[] = [];
    for (const l of levels.slice(0, -1)) {
      path.push({ side: j % 2 ? 'left' : 'right', hash: l[j ^ 1] ?? l[j] });
      j = Math.floor(j / 2);
    }
    return path;
  });
  return { root: level[0], proofs };
}

// Recomputes the root independently of merkle(), for the verifier.
export function merkleRoot(hashes: string[]): string {
  let level = hashes.map((h) => hash(DOMAIN.leaf, h));
  if (!level.length) return hash(DOMAIN.empty, []);
  while (level.length > 1) {
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(hash(DOMAIN.node, [level[j], level[j + 1] ?? level[j]]));
    level = next;
  }
  return level[0];
}

export function verifyProof(leafHash: string, index: number, count: number, proof: ProofStep[], root: string): boolean {
  let h = hash(DOMAIN.leaf, leafHash), i = index, width = count, step = 0;
  while (width > 1) {
    const p = proof[step++], side = i % 2 ? 'left' : 'right';
    if (!p || p.side !== side) return false;
    h = hash(DOMAIN.node, side === 'left' ? [p.hash, h] : [h, p.hash]);
    i = Math.floor(i / 2);
    width = Math.ceil(width / 2);
  }
  return step === proof.length && h === root;
}

// Strict parser for packets from other parties: rejects duplicate keys (which JSON.parse silently drops), non-integer
// numbers, ill-formed Unicode and excessive depth or size. Bytes are decoded as UTF-8 fatally, and a byte order mark is
// kept (and so rejected), exactly as the Python library does (v1.1 correction C12).
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LITERAL = /true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const isWs = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;

export function parseStrict(input: string | Uint8Array): Json {
  let text: string;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input) > MAX_PACKET_BYTES) throw new Error('Packet exceeds size limit');
    text = input;
  } else {
    if (input.byteLength > MAX_PACKET_BYTES) throw new Error('Packet exceeds size limit');
    try {
      text = UTF8.decode(input);
    } catch {
      throw new Error('Invalid UTF-8');
    }
  }
  let i = 0;
  const ws = () => { while (i < text.length && isWs(text.charCodeAt(i))) i++; };
  function val(depth = 0): Json {
    if (depth > MAX_DEPTH) throw new Error('JSON depth exceeded');
    ws();
    const c = text[i];
    if (c === '"') {
      const start = i++;
      while (i < text.length) {
        const ch = text.charCodeAt(i);
        if (ch === 0x5c) { i += 2; continue; }
        i++;
        if (ch === 0x22) {
          const s = JSON.parse(text.slice(start, i)) as string;
          if (!s.isWellFormed()) throw new Error('Invalid Unicode');
          return s;
        }
      }
      throw new Error('Unterminated string');
    }
    if (c === '{') {
      i++; ws();
      const o: Record<string, Json> = Object.create(null), keys = new Set<string>();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') throw new Error('Object key required');
        const k = val(depth + 1) as string;
        if (keys.has(k)) throw new Error('Duplicate JSON key');
        keys.add(k); ws();
        if (text[i++] !== ':') throw new Error('Colon required');
        o[k] = val(depth + 1); ws();
        const end = text[i++];
        if (end === '}') return o;
        if (end !== ',') throw new Error('Comma required');
      }
    }
    if (c === '[') {
      i++; ws();
      const a: Json[] = [];
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(val(depth + 1)); ws();
        const end = text[i++];
        if (end === ']') return a;
        if (end !== ',') throw new Error('Comma required');
      }
    }
    LITERAL.lastIndex = i;
    const m = LITERAL.exec(text);
    if (!m) throw new Error('Invalid JSON');
    if (/^-?\d/.test(m[0]) && /[.eE]/.test(m[0])) throw new Error('Only integer literals allowed');
    i += m[0].length;
    const v = JSON.parse(m[0]) as Json;
    canonical(v);
    return v;
  }
  const result = val();
  ws();
  if (i !== text.length) throw new Error('Trailing JSON');
  return result;
}

// Merkle roots of every prefix of a tree, in O(log n) each after O(n) set-up, so a verifier can check many checkpoint
// anchors without rebuilding a tree per anchor (v1.1 correction C16). prefix(n) equals merkleRoot(hashes.slice(0, n)).
// Nodes that cover 2^k real leaves are the same in every prefix that contains them; only the right edge differs.
export function merklePrefixRoots(hashes: readonly string[]): (n: number) => string {
  const levels: string[][] = [hashes.map((h) => hash(DOMAIN.leaf, h))];
  while (levels[levels.length - 1].length > 1) {
    const l = levels[levels.length - 1], next: string[] = [];
    for (let j = 0; j + 1 < l.length; j += 2) next.push(hash(DOMAIN.node, [l[j], l[j + 1]]));
    levels.push(next);
  }
  return (n: number) => {
    if (!Number.isSafeInteger(n) || n < 0 || n > hashes.length) throw new Error('Prefix out of range');
    if (n === 0) return hash(DOMAIN.empty, []);
    let r = levels[0][n - 1], w = n, k = 0;
    while (w > 1) {
      const idx = w - 1;
      r = idx % 2 ? hash(DOMAIN.node, [levels[k][idx - 1], r]) : hash(DOMAIN.node, [r, r]);
      w = Math.ceil(w / 2);
      k++;
    }
    return r;
  };
}

// One timestamp grammar for every time a verifier compares (v1.1 correction C11): RFC 3339 with upper-case T and Z,
// seconds required, up to nine fraction digits, and Z or a ±HH:MM offset. Anything else is not a time. Returns
// [seconds since 1970-01-01T00:00:00Z, nanoseconds], or null.
const TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;
function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400), yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}
export function parseTime(s: unknown): [number, number] | null {
  if (typeof s !== 'string') return null;
  const m = TIME.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (mo < 1 || mo > 12 || d < 1 || d > dim || h > 23 || mi > 59 || sec > 59) return null;
  let offset = 0;
  if (m[8]) {
    const oh = Number(m[9]), om = Number(m[10]);
    if (oh > 23 || om > 59) return null;
    offset = (m[8] === '+' ? 1 : -1) * (oh * 3600 + om * 60);
  }
  const nanos = m[7] ? Number(m[7].padEnd(9, '0')) : 0;
  return [daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset, nanos];
}
// Orders two parsed times: negative, zero or positive.
export const compareTime = (a: [number, number], b: [number, number]) => (a[0] - b[0]) || (a[1] - b[1]);

// Long text is stored clipped, with the digest and length of the full text (spec §3.4).
export const MAX_TEXT = 8000;
export type Clipped = { text: string; truncated: boolean; chars: number; digest: string };
// Lengths count UTF-16 code units; a cut never splits a surrogate pair, so the clipped text stays well-formed.
export function clip(value: unknown, max = MAX_TEXT): Clipped {
  const s = typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value);
  let text = s;
  if (s.length > max) {
    text = s.slice(0, max);
    if (/[\uD800-\uDBFF]$/.test(text)) text = text.slice(0, -1);
  }
  return { text: text.toWellFormed(), truncated: s.length > max, chars: s.length, digest: sha256(s) };
}
