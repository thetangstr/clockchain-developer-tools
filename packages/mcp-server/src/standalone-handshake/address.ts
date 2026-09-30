// Handshake addresses (spec B4): `name#fingerprint`, bound to the listener's session key.
//
// The fingerprint is the first FINGERPRINT_HEX_LENGTH hex characters of
// keccak256(lowercase session-key address, as its 20 bytes). The server delivers to a
// mailbox only after its claimant proves, with an EIP-191 signature over a single-use
// challenge, the key whose fingerprint is in the address, and the listener must accept with
// that same key. So whoever controls an address controls a key with its fingerprint: the
// fingerprint length IS the cost of squatting a specific address.
//
// Length choice: 20 hex characters (80 bits). Vanity-address grinders reach ~1e9 keys/s on
// one GPU, so 32 bits falls in seconds; 80 bits is ~1e24 derivations per target, out of
// reach. The address is longer ("claude-code.alex#6dd06dce1a9f0b3c47e2") but it is copied,
// not memorized. An Initiator that knows the listener's full key can pin it (`toKey`).
import { keccak_256 } from "@noble/hashes/sha3";

import { canonicalBytes } from "../handshake/protocol.js";
import { standaloneSigningPayload, type StandaloneSigningPayload } from "./protocol.js";

export const FINGERPRINT_HEX_LENGTH = 20;
export const LISTEN_SCHEMA = "clockchain.handshake-listen/v1";

const NAME = /^[a-z0-9](?:[a-z0-9.-]{1,30})[a-z0-9]$/;
const ADDRESS = new RegExp(`^([a-z0-9.-]+)#([0-9a-f]{${FINGERPRINT_HEX_LENGTH}})$`);
const SESSION_KEY = /^0x[0-9a-fA-F]{40}$/;

// Names that could pass for the operator, a platform or a system role.
export const RESERVED_NAMES: ReadonlySet<string> = new Set([
  "admin", "administrator", "root", "system", "support", "help", "security", "abuse", "official",
  "clockchain", "handshake", "mcp", "api", "www", "server", "host", "operator", "relay", "staff",
  "anthropic", "claude", "openai", "meta", "google", "null", "undefined", "anonymous", "everyone",
]);

export class StandaloneAddressError extends Error {
  constructor(readonly reason: string) {
    super(`Handshake address refused: ${reason}`);
    this.name = "StandaloneAddressError";
  }
}

/** keccak256 fingerprint of a session-key address (checksummed or lowercase input). */
export function keyFingerprint(sessionKeyAddress: string): string {
  if (!SESSION_KEY.test(sessionKeyAddress)) throw new StandaloneAddressError("BAD_SESSION_KEY");
  const bytes = Buffer.from(sessionKeyAddress.slice(2).toLowerCase(), "hex");
  return Buffer.from(keccak_256(bytes)).toString("hex").slice(0, FINGERPRINT_HEX_LENGTH);
}

export function isValidName(name: string): boolean {
  return NAME.test(name) && !name.includes("..") && !RESERVED_NAMES.has(name.split(".")[0]) && !RESERVED_NAMES.has(name);
}

/** Parses `name#fingerprint`; throws StandaloneAddressError("BAD_ADDRESS") on any malformed input. */
export function parseAddress(value: unknown): { address: string; name: string; fingerprint: string } {
  if (typeof value !== "string") throw new StandaloneAddressError("BAD_ADDRESS");
  const match = ADDRESS.exec(value.trim().toLowerCase());
  if (!match || !isValidName(match[1])) throw new StandaloneAddressError("BAD_ADDRESS");
  return { address: `${match[1]}#${match[2]}`, name: match[1], fingerprint: match[2] };
}

/** The address a session key may claim under `name`. */
export function addressFor(name: string, sessionKeyAddress: string): string {
  if (!isValidName(name)) throw new StandaloneAddressError("BAD_ADDRESS");
  return `${name}#${keyFingerprint(sessionKeyAddress)}`;
}

/** The exact record (and its canonical bytes) a listener signs to claim an address. */
export function listenRecord(input: { address: string; endpoint: string; nonce: string; sessionKeyAddress: string }): StandaloneSigningPayload {
  if (!SESSION_KEY.test(input.sessionKeyAddress)) throw new StandaloneAddressError("BAD_SESSION_KEY");
  const record = Object.freeze({
    schema: LISTEN_SCHEMA,
    address: input.address,
    endpoint: input.endpoint,
    nonce: input.nonce,
    sessionKeyAddress: input.sessionKeyAddress.toLowerCase(),
  });
  canonicalBytes(record); // throws on anything non-canonical
  return standaloneSigningPayload(record);
}
