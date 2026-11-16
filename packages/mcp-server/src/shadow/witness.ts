// Clockchain's single published witness key (SHADOW_WITNESS_KEY_FILE). Signed-in accounts' checkpoints are signed with
// it: Clockchain holds no key per account or per agent. The file is provisioned like any other secret and is only ever
// read, never created: a missing, unreadable or non-Ed25519 file is a configuration error, so Shadow does not start.
// Errors name the setting, never the file's contents.
import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import type { KeyProvider } from "./lib/keys.js";

const MAX_BYTES = 8 * 1024;

export class WitnessKeyError extends Error {
  constructor(message: string) {
    super(message);
    // http.ts reports a ShadowConfigError by its message, and keeps Shadow from starting.
    this.name = "ShadowConfigError";
  }
}

/** A KeyProvider over an Ed25519 private key: the same construction as the library's provider() in keys.ts (not exported there). */
export function keyProvider(privateKey: KeyObject): KeyProvider {
  const pem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
  return {
    publicKey: () => pem,
    sign: (hashHex) => sign(null, Buffer.from(hashHex, "hex"), privateKey).toString("base64"),
  };
}

/** The witness key from a PKCS8 Ed25519 private-key PEM file. Throws a WitnessKeyError when the file won't do. */
export function loadWitnessKey(file: string): KeyProvider {
  let pem: Buffer;
  try {
    pem = readFileSync(file);
  } catch (e) {
    throw new WitnessKeyError(`SHADOW_WITNESS_KEY_FILE can't be read (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }
  if (pem.length > MAX_BYTES) throw new WitnessKeyError("SHADOW_WITNESS_KEY_FILE is too large to be a private key");
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: pem, format: "pem" });
  } catch {
    throw new WitnessKeyError("SHADOW_WITNESS_KEY_FILE is not a PEM private key");
  } finally {
    pem.fill(0);
  }
  if (key.asymmetricKeyType !== "ed25519") throw new WitnessKeyError("SHADOW_WITNESS_KEY_FILE is not an Ed25519 key");
  return keyProvider(key);
}
