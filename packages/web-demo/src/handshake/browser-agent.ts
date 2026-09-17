// Browser-side agent for visitor-as-responder mode. Bundled to
// dist/handshake/browser-agent.js (esbuild IIFE) and served at /handshake/agent.js.
//
// The visitor's Sepolia keypair is generated in THIS tab and never leaves it:
// the page signs EIP-191 locally and only the signature crosses the wire —
// exactly the product's "local signing required" boundary, demonstrated live.

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const enc = new TextEncoder();

// Same canonicalization as packages/mcp-server/src/handshake/protocol.ts
// (sorted keys, JSON.stringify, UTF-8) — the consent/authority records are
// flat string maps, so this covers their full shape.
const canon = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(canon)
    : v !== null && typeof v === "object"
      ? Object.fromEntries(Object.keys(v as Record<string, unknown>).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])]))
      : v;

const canonicalJson = (record: Record<string, unknown>): string => JSON.stringify(canon(record));

const PROTOCOL = "clockchain.standalone-handshake/v1";

const authorityRecord = (sessionKeyAddress: string, accountableParty: string, statement: string) => ({
  schema: "clockchain.standalone-handshake-authority/v1",
  protocol: PROTOCOL,
  sessionKeyAddress,
  accountableParty,
  statement,
});

const consentRecord = (sessionId: string, role: string, termsDigest: string, checklistDigest: string) => ({
  schema: "clockchain.standalone-handshake-consent/v1",
  protocol: PROTOCOL,
  sessionId,
  role,
  termsDigest,
  checklistDigest,
});

async function sha256hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateKey() {
  const account = privateKeyToAccount(generatePrivateKey());
  return { address: account.address.toLowerCase(), account };
}

async function signRecord(account: { signMessage: (a: { message: { raw: Uint8Array } }) => Promise<string> }, record: Record<string, unknown>): Promise<string> {
  return account.signMessage({ message: { raw: enc.encode(canonicalJson(record)) } });
}

const termsDigestOf = (terms: Record<string, unknown>) => sha256hex(canonicalJson(terms));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).CCH = { generateKey, signRecord, authorityRecord, consentRecord, termsDigestOf, canonicalJson };
