/**
 * Sealed boxes for ingest-token delivery (N4c). The sink seals a minted token
 * to the role's local-services X25519 public key; only the forwarder running
 * under that services uid can open it. The plaintext token is never logged or
 * returned unsealed.
 *
 * Construction: ephemeral x25519 → ECDH → HKDF-SHA256 → AES-256-GCM.
 *
 * Wire shape: {v: 3, epk, iv, ct, tag}, all 0x-hex.
 *  - epk: exactly 32 bytes (the ephemeral x25519 public key)
 *  - iv:  exactly 12 bytes
 *  - tag: exactly 16 bytes; GCM is opened with authTagLength 16, so a
 *    truncated tag can never verify
 *  - HKDF info and the GCM AAD are both the context
 *      "agent-contract seal ingest-token v3" ‖ epk ‖ recipientPub ‖ lp(runId) ‖ lp(role)
 *    where lp(x) is a one-byte length prefix followed by UTF-8 bytes.
 *
 * CHANGE vs N5 (reported to the orchestrator, N4c review M4): N5's seal emits
 * v:2 with context "agent-contract seal v1"‖epk‖recipientPub. N4c emits v:3
 * under the label "agent-contract seal ingest-token v3" with the context
 * extended by the length-prefixed runId and role, so a box is bound to the
 * exact (ephemeral, recipient, run, role) tuple — a sealed token cannot be
 * replayed under a different run or role. N5 code is untouched.
 */
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";

const HKDF_INFO_PREFIX = "agent-contract seal ingest-token v3";
const EPK_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

const evenHex = (bytes: number) => new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`);
const HEX_EVEN = /^0x(?:[0-9a-f]{2})+$/;

export interface SealedBox {
  v: 3;
  epk: `0x${string}`;
  iv: `0x${string}`;
  ct: `0x${string}`;
  tag: `0x${string}`;
}

/** The (runId, role) binding carried in the HKDF info and the GCM AAD. */
export interface SealBind {
  runId: string;
  role: string;
}

export class SealError extends Error {
  readonly code = "SEAL_OPEN_FAILED";
  constructor() {
    // Deliberately detail-free: "which byte was wrong" is attacker aid.
    super("sealed box could not be opened.");
    this.name = "SealError";
  }
}

const hexToBuf = (hex: string): Buffer => Buffer.from(hex.slice(2), "hex");

function isSealedBox(box: unknown): box is SealedBox {
  if (typeof box !== "object" || box === null) return false;
  const b = box as Record<string, unknown>;
  return (
    b.v === 3 &&
    typeof b.epk === "string" && evenHex(EPK_BYTES).test(b.epk) &&
    typeof b.iv === "string" && evenHex(IV_BYTES).test(b.iv) &&
    typeof b.ct === "string" && HEX_EVEN.test(b.ct) &&
    typeof b.tag === "string" && evenHex(TAG_BYTES).test(b.tag)
  );
}

function x25519PublicKeyFromRaw(rawHex: string): KeyObject {
  if (!evenHex(EPK_BYTES).test(rawHex)) throw new SealError();
  const raw = hexToBuf(rawHex);
  return createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** Raw 32-byte x25519 public key bytes from a KeyObject. */
function x25519PublicRaw(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  if (typeof jwk.x !== "string") throw new SealError();
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== EPK_BYTES) throw new SealError();
  return raw;
}

/** One-byte length prefix + UTF-8 bytes (unambiguous tuple encoding). */
function lp(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > 255) throw new SealError();
  return Buffer.concat([Buffer.from([bytes.byteLength]), bytes]);
}

/** "agent-contract seal ingest-token v3" ‖ epk ‖ recipientPub ‖ lp(runId) ‖ lp(role). */
function sealContext(epkRaw: Buffer, recipientRaw: Buffer, bind: SealBind): Buffer {
  return Buffer.concat([
    Buffer.from(HKDF_INFO_PREFIX, "utf8"),
    epkRaw,
    recipientRaw,
    lp(bind.runId),
    lp(bind.role),
  ]);
}

function deriveKey(sharedSecret: Buffer, context: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sharedSecret, Buffer.alloc(0), context, 32));
}

/** Seal `plaintext` to a counterparty's raw x25519 public key (0x-hex). */
export function sealTo(
  recipientX25519Pub: `0x${string}`,
  plaintext: string | Uint8Array,
  bind: SealBind,
): SealedBox {
  const ephemeral = generateKeyPairSync("x25519");
  try {
    const recipient = x25519PublicKeyFromRaw(recipientX25519Pub);
    const epkRaw = x25519PublicRaw(ephemeral.publicKey);
    const context = sealContext(epkRaw, hexToBuf(recipientX25519Pub), bind);
    const key = deriveKey(
      diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient }),
      context,
    );
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(context);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      v: 3,
      epk: `0x${epkRaw.toString("hex")}`,
      iv: `0x${iv.toString("hex")}`,
      ct: `0x${ct.toString("hex")}`,
      tag: `0x${cipher.getAuthTag().toString("hex")}`,
    };
  } catch (err) {
    if (err instanceof SealError) throw err;
    throw new SealError();
  }
}

/**
 * Open a box sealed to `recipientPrivateKey` (an x25519 private KeyObject).
 * The recipient public key — needed for the AAD context — is derived from the
 * private key, so the caller never has to supply it separately. `bind` must
 * equal the runId/role the box was sealed under.
 */
export function openSeal(recipientPrivateKey: KeyObject, box: unknown, bind: SealBind): string {
  if (!isSealedBox(box)) throw new SealError();
  try {
    const recipientRaw = x25519PublicRaw(createPublicKey(recipientPrivateKey));
    const epkRaw = hexToBuf(box.epk);
    const context = sealContext(epkRaw, recipientRaw, bind);
    const epk = x25519PublicKeyFromRaw(box.epk);
    const key = deriveKey(
      diffieHellman({ privateKey: recipientPrivateKey, publicKey: epk }),
      context,
    );
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      hexToBuf(box.iv),
      { authTagLength: TAG_BYTES },
    );
    decipher.setAAD(context);
    decipher.setAuthTag(hexToBuf(box.tag));
    return Buffer.concat([
      decipher.update(hexToBuf(box.ct)),
      decipher.final(),
    ]).toString("utf8");
  } catch (err) {
    if (err instanceof SealError) throw err;
    throw new SealError();
  }
}

/** Convenience: open a box when the private key is held as a JWK. */
export function openSealJwk(privateKeyJwk: JsonWebKey, box: unknown, bind: SealBind): string {
  try {
    return openSeal(createPrivateKey({ key: privateKeyJwk, format: "jwk" }), box, bind);
  } catch (err) {
    if (err instanceof SealError) throw err;
    throw new SealError();
  }
}
