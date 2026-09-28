// Local EIP-191 signing for standalone handshake tests, the way a real agent would do it:
// a secp256k1 key held only by the test, bytes re-derived from the record before signing.
import { createHash, randomUUID } from "node:crypto";

import { recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

export function newSessionKey() {
  return privateKeyToAccount(generatePrivateKey());
}

// Canonical JSON as the playbook tells an agent to build it: keys sorted, no whitespace.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// Refuses to sign unless the server's bytes and digest are exactly what the record encodes.
export async function verifyAndSign(account, payload) {
  const bytes = canonicalJson(payload.record);
  if (bytes !== payload.bytes) throw new Error("server bytes do not match the record");
  if (sha256Hex(bytes) !== payload.bytesSha256) throw new Error("server digest does not match the bytes");
  return account.signMessage({ message: bytes });
}

// The coordinator's recoverEip191Address hook, done locally instead of over RPC.
export async function recoverLocally({ bytes, signatureHex }) {
  return recoverMessageAddress({ message: { raw: new Uint8Array(bytes) }, signature: signatureHex });
}

export function fakeLedger(blockTime = "2026-09-14T00:00:00.000Z") {
  const entries = new Map();
  let height = 100;
  return {
    entries,
    async searchAsset(reference) {
      return [...entries.values()].filter((entry) => entry.assetReferenceId === reference);
    },
    async log({ assetHash, assetReferenceId }) {
      const ledgerId = randomUUID();
      const record = { ledgerId, assetHash, assetReferenceId, blockHeight: String(++height) };
      entries.set(ledgerId, record);
      return { ...record };
    },
    async getLedgerEntry(ledgerId) {
      const record = entries.get(ledgerId);
      return record ? { ...record } : null;
    },
    async getChainRecord(blockHeight, ledgerId) {
      const record = entries.get(ledgerId);
      return record && record.blockHeight === String(blockHeight) ? { ...record } : null;
    },
    async getBlock(blockHeight) {
      return { blockHeight: String(blockHeight), blockTime };
    },
  };
}
