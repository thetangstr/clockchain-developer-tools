import { canonicalDigest } from "./canonical.js";

/**
 * EIP-191 / secp256k1 role-signature recovery for `/contract/mcp` — pure
 * BigInt arithmetic, no dependencies, no network. This exists because the
 * only other EIP-191 recovery in the repo (`src/handshake/evm.ts`) shells out
 * to the ecrecover precompile via JSON-RPC, which is useless inside a
 * request handler and banned in this slice (no network calls).
 *
 * Scheme (LLD §13 rev 6.1, frozen by role-sig-vectors.v2.json):
 *   roleSigDigest = canonicalDigest({domain:"agent-contract.role-sig/v1",
 *                                  runId, role, tool, nonce, payloadDigest})
 *   signature     = EIP-191 signMessage({message:{raw: roleSigDigest}})
 *                   i.e. ecrecover over keccak256("\x19Ethereum Signed
 *                   Message:\n32" || digest)
 */

// --- keccak-256 -------------------------------------------------------------

const U64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl64(x: bigint, n: number): bigint {
  return n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & U64;
}

function keccakF1600(state: bigint[]): void {
  for (const rc of RC) {
    // θ
    const c = [0, 1, 2, 3, 4].map((x) => state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5]! ^ rotl64(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] = state[x + 5 * y]! ^ d;
    }
    // ρ + π
    const b = new Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y]!, ROT[x + 5 * y]!);
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = b[x + 5 * y]! ^ ((~b[((x + 1) % 5) + 5 * y]! & U64) & b[((x + 2) % 5) + 5 * y]!);
      }
    }
    // ι
    state[0] = state[0]! ^ rc;
  }
}

/** keccak-256 (Ethereum's variant — pad byte 0x01, NOT SHA-3's 0x06). */
export function keccak256(bytes: Uint8Array): Uint8Array {
  const rate = 136;
  const state = new Array<bigint>(25).fill(0n);
  let offset = 0;
  while (offset + rate <= bytes.length) {
    absorb(state, bytes.subarray(offset, offset + rate));
    keccakF1600(state);
    offset += rate;
  }
  const block = new Uint8Array(rate);
  block.set(bytes.subarray(offset));
  block[bytes.length - offset] = 0x01;
  block[rate - 1] |= 0x80;
  absorb(state, block);
  keccakF1600(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number((state[i >> 3]! >> BigInt((i & 7) * 8)) & 0xffn);
  }
  return out;
}

function absorb(state: bigint[], block: Uint8Array): void {
  for (let i = 0; i < block.length; i++) {
    state[i >> 3] = state[i >> 3]! ^ (BigInt(block[i]!) << BigInt((i & 7) * 8));
  }
}

// --- secp256k1 field / curve -------------------------------------------------

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

type Point = readonly [bigint, bigint]; // affine; use null for infinity

const G: Point = [GX, GY];

function mod(a: bigint, m = P): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInv(a: bigint, m: bigint): bigint {
  // Fermat inverse (m prime): a^(m-2)
  let base = mod(a, m);
  let exp = m - 2n;
  let acc = 1n;
  while (exp > 0n) {
    if (exp & 1n) acc = mod(acc * base, m);
    base = mod(base * base, m);
    exp >>= 1n;
  }
  return acc;
}

function pointAdd(a: Point | null, b: Point | null): Point | null {
  if (a === null) return b;
  if (b === null) return a;
  const [x1, y1] = a;
  const [x2, y2] = b;
  if (x1 === x2) {
    if (mod(y1 + y2) === 0n) return null;
    // doubling
    const lam = mod(3n * x1 * x1 * modInv(2n * y1, P));
    const x3 = mod(lam * lam - 2n * x1);
    return [x3, mod(lam * (x1 - x3) - y1)];
  }
  const lam = mod((y2 - y1) * modInv(x2 - x1, P));
  const x3 = mod(lam * lam - x1 - x2);
  return [x3, mod(lam * (x1 - x3) - y1)];
}

function pointMul(k: bigint, p: Point | null): Point | null {
  let acc: Point | null = null;
  let base = p;
  let kk = mod(k, N);
  while (kk > 0n) {
    if (kk & 1n) acc = pointAdd(acc, base);
    base = pointAdd(base, base);
    kk >>= 1n;
  }
  return acc;
}

function decompressPoint(x: bigint, odd: boolean): Point | null {
  if (x >= P) return null;
  const y2 = mod(x * x * x + 7n);
  const y = modPow4(y2);
  if (mod(y * y) !== y2) return null;
  return [x, (y & 1n) === BigInt(odd ? 1 : 0) ? y : P - y];
}

function modPow4(a: bigint): bigint {
  // p ≡ 3 (mod 4): sqrt = a^((p+1)/4)
  let base = a;
  let exp = (P + 1n) >> 2n;
  let acc = 1n;
  while (exp > 0n) {
    if (exp & 1n) acc = mod(acc * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return acc;
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

function bigIntTo32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return "0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** EIP-191 signMessage({message:{raw: digest32}}) → keccak hash actually signed. */
export function eip191Hash32(digestBytes: Uint8Array): Uint8Array {
  if (digestBytes.length !== 32) throw new Error("eip191Hash32 expects a 32-byte digest");
  const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
  return keccak256(new Uint8Array([...prefix, ...digestBytes]));
}

/**
 * Recover the uncompressed secp256k1 public key from an EIP-191 signature
 * over a 32-byte digest. Returns 65 bytes (0x04 || X || Y) or null.
 */
export function eip191RecoverPublicKey(digestBytes: Uint8Array, signatureHex: string): Uint8Array | null {
  try {
    const sig = hexToBytes(signatureHex);
    if (sig.length !== 65) return null;
    const r = bytesToBigInt(sig.subarray(0, 32));
    const s = bytesToBigInt(sig.subarray(32, 64));
    const vByte = sig[64]!;
    const recid = vByte >= 27 ? vByte - 27 : vByte;
    if (recid < 0 || recid > 3 || r === 0n || r >= N || s === 0n || s >= N) return null;
    const x = r + BigInt(recid >> 1) * N;
    const R = decompressPoint(x, (recid & 1) === 1);
    if (R === null) return null;
    const e = bytesToBigInt(eip191Hash32(digestBytes));
    const rInv = modInv(r, N);
    // Q = r⁻¹ (s·R − e·G)
    const sR = pointMul(s, R);
    const eG = pointMul(mod(-e, N), G);
    const Q = pointMul(rInv, pointAdd(sR, eG));
    if (Q === null) return null;
    return new Uint8Array([4, ...bigIntTo32(Q[0]), ...bigIntTo32(Q[1])]);
  } catch {
    return null;
  }
}

/** Ethereum address = last 20 bytes of keccak256(uncompressed pubkey sans 0x04). */
export function publicKeyToAddress(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new Error("need a 65-byte uncompressed key");
  return toHex(keccak256(uncompressed.subarray(1)).subarray(12));
}

/**
 * The contract-layer predicate: does `signatureHex` recover, under the
 * run-scoped role-sig domain, to `expectedPublicKeyHex` (the signer key bound
 * at contract_bind — compressed 33B or uncompressed 65B both accepted)?
 */
export function verifyRoleSignature(fields: {
  runId: string;
  role: "buyer" | "provider";
  tool: string;
  nonce: string;
  payloadDigest: string;
  signatureHex: string;
  expectedPublicKeyHex: string;
}): boolean {
  const roleSigDigest = canonicalDigest({
    domain: "agent-contract.role-sig/v1",
    runId: fields.runId,
    role: fields.role,
    tool: fields.tool,
    nonce: fields.nonce,
    payloadDigest: fields.payloadDigest,
  });
  const recovered = eip191RecoverPublicKey(hexToBytes(roleSigDigest), fields.signatureHex);
  if (recovered === null) return false;
  const expected = normalizePublicKeyHex(fields.expectedPublicKeyHex);
  return expected !== null && toHex(recovered) === expected;
}

/** Normalize a compressed (33B) or uncompressed (65B) hex key to uncompressed 65B lowercase 0x-hex. */
export function normalizePublicKeyHex(publicKeyHex: string): string | null {
  try {
    const b = hexToBytes(publicKeyHex);
    if (b.length === 65 && b[0] === 4) return toHex(b);
    if (b.length === 33 && (b[0] === 2 || b[0] === 3)) {
      const p = decompressPoint(bytesToBigInt(b.subarray(1)), b[0] === 3);
      if (p === null) return null;
      return toHex(new Uint8Array([4, ...bigIntTo32(p[0]), ...bigIntTo32(p[1])]));
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * TEST/TOOLING ONLY — deterministic (RFC-6979-free, k = hash-derived) EIP-191
 * signature for the frozen-vector tests and local driver keys. The server
 * never signs role signatures; roles sign in their own local signer (N5).
 */
export function eip191SignDigest32(digestBytes: Uint8Array, privateKeyHex: string): string {
  const d = bytesToBigInt(hexToBytes(privateKeyHex));
  if (d === 0n || d >= N) throw new Error("bad private key");
  const e = bytesToBigInt(eip191Hash32(digestBytes));
  // RFC-6979-lite: k = keccak256(d || e) mod N, retry on degenerate k/r/s.
  for (let tweak = 0n; ; tweak++) {
    const k = mod(bytesToBigInt(keccak256(new Uint8Array([...hexToBytes(privateKeyHex), ...bigIntTo32(e), ...bigIntTo32(tweak)]))), N);
    if (k === 0n) continue;
    const R = pointMul(k, G)!;
    const r = mod(R[0], N);
    if (r === 0n) continue;
    const s = mod(modInv(k, N) * (e + r * d), N);
    if (s === 0n) continue;
    // Ethereum enforces low-s; flip and flip the recovery bit to match.
    const sNorm = s > N >> 1n ? N - s : s;
    const recid = (Number(R[1] & 1n) ^ (s !== sNorm ? 1 : 0)) | (R[0] >= N ? 2 : 0);
    const sig = new Uint8Array(65);
    sig.set(bigIntTo32(r), 0);
    sig.set(bigIntTo32(sNorm), 32);
    sig[64] = 27 + recid;
    return toHex(sig);
  }
}
