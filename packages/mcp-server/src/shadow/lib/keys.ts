// Vendored from clockchain-shadow/ts/src/keys.ts (source sha256 d8dbb084384709ce0dd23b4ca9ada553786523af19939f721a9ac5aba07493c2) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Checkpoint signing keys (spec §4.3). A KeyProvider signs the 32 hash bytes of a checkpoint; KMS providers can
// implement the same interface later.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { DOMAIN, hash } from './profile.js';

export interface KeyProvider {
  publicKey(): string; // SPKI PEM
  sign(hashHex: string): string; // base64 Ed25519 signature over the hash bytes
}

export const fingerprint = (publicKeyPem: string) => hash(DOMAIN.publicKey, publicKeyPem);

// A public key is accepted only as the canonical PEM of an Ed25519 SubjectPublicKeyInfo, exactly as Node and Python's
// cryptography write it; a signature only as the canonical base64 of 64 bytes. Lenient decoders, other key types and
// private keys made the two libraries disagree (v1.1 correction C10).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PEM = /^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/]{59}=)\n-----END PUBLIC KEY-----\n$/;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function ed25519PublicKeyDer(publicKeyPem: unknown): Buffer | null {
  if (typeof publicKeyPem !== 'string') return null;
  const m = PEM.exec(publicKeyPem);
  if (!m) return null;
  const der = Buffer.from(m[1], 'base64');
  if (der.length !== 44 || der.toString('base64') !== m[1] || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) return null;
  return der;
}

export function verifySignature(publicKeyPem: unknown, hashHex: unknown, signature: unknown): boolean {
  try {
    const der = ed25519PublicKeyDer(publicKeyPem);
    if (!der || typeof hashHex !== 'string' || !HEX64.test(hashHex) || typeof signature !== 'string' || !SIGNATURE.test(signature)) return false;
    const sig = Buffer.from(signature, 'base64');
    if (sig.length !== 64 || sig.toString('base64') !== signature) return false;
    return verify(null, Buffer.from(hashHex, 'hex'), createPublicKey({ key: der, format: 'der', type: 'spki' }), sig);
  } catch {
    return false;
  }
}

function provider(privateKey: KeyObject): KeyProvider {
  const pem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  return {
    publicKey: () => pem,
    sign: (hashHex) => sign(null, Buffer.from(hashHex, 'hex'), privateKey).toString('base64'),
  };
}

export function memoryKeyProvider(): KeyProvider {
  return provider(generateKeyPairSync('ed25519').privateKey);
}

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

// Creates an Ed25519 key on first use and keeps it in <dir>/signing-key.pem, readable by the owner only. The file is
// created exclusively and opened without following symlinks; a key file that is a symlink, is not a regular file, is
// owned by someone else or is readable or writable by others is refused rather than repaired (v1.1 correction C20).
export function fileKeyProvider(dir: string): KeyProvider {
  const file = join(dir, 'signing-key.pem');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
    try {
      writeSync(fd, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
  }
  let fd: number;
  try {
    fd = openSync(file, constants.O_RDONLY | NOFOLLOW);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ELOOP') throw new Error(`${file} is a symbolic link; refusing to sign with it`);
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${file} is not a regular file; refusing to sign with it`);
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (uid != null && st.uid !== uid) throw new Error(`${file} is not owned by you; refusing to sign with it`);
    if (uid != null && st.mode & 0o077) throw new Error(`${file} is readable or writable by others (mode ${(st.mode & 0o777).toString(8)}); run chmod 600 on it`);
    const key = createPrivateKey(readFileSync(fd));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${file} is not an Ed25519 key`);
    return provider(key);
  } finally {
    closeSync(fd);
  }
}
