// Handshake addresses (spec B4): `name#fingerprint`, bound to the listener's session key.
//
// The fingerprint is the first FINGERPRINT_HEX_LENGTH hex characters of
// keccak256(lowercase session-key address, as its 20 bytes). It is not what secures the
// address: the server delivers to a mailbox only after its claimant proves, with an EIP-191
// signature over a single-use challenge, the key whose fingerprint is in the address, and the
// listener must accept with that same key. The fingerprint's job is to make a copied address
// self-checking (typos never reach a stranger) and to make squatting a specific address
// expensive: claiming `alex#<fp>` first needs a key with that fingerprint.
//
// Length choice: 8 hex characters (32 bits). With 4 (16 bits) a squatter grinds a matching
// key in well under a second; with 8 it takes about 4 billion key derivations for one
// target, and a claimed mailbox is first-come for as long as its owner keeps it alive. 8
// characters stays short enough for a person to read out or type ("claude-code.alex#3f9a1c07").
import { keccak_256 } from "@noble/hashes/sha3";

import { canonicalBytes } from "../handshake/protocol.js";
import { standaloneSigningPayload, type StandaloneSigningPayload } from "./protocol.js";

export const FINGERPRINT_HEX_LENGTH = 8;
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
