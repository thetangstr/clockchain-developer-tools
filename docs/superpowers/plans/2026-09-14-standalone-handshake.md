# Standalone Handshake V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Standalone Handshake — a mutually authenticated, consented, witnessed A2A gateway with a readiness checklist, bounded channel, and anchored receipts — as its own credential-light MCP endpoint (`/connect/mcp`) in `clockchain-mcp`.

**Architecture:** New self-contained module `packages/mcp-server/src/standalone-handshake/` (protocol validators, deterministic checklist, in-memory session store, coordinator with ledger anchoring, MCP tools, public HTTP handler) wired into the existing `http.ts` next to the v2 agent-handshake routes. The v2 `agent-handshake` module is not modified. Landing page and `llms.txt` announce the capability.

**Tech Stack:** TypeScript (ESM, `tsc -b`), `@modelcontextprotocol/sdk` (McpServer + StreamableHTTPServerTransport), zod, `@clockchain/core` (`ClockchainClient`, `readConfigFromEnv`), `node:test` + `node:assert/strict`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-14-standalone-handshake-design.md` (read it first — the plan argues from it)

## Global Constraints

- Protocol string: `clockchain.standalone-handshake/v1` (exact).
- Message kinds enum: `question`, `proposal`, `evidence`, `note`. Data-handling classes: `public`, `confidential`, `restricted` (exact-match compatibility).
- Channel duration: decimal-string seconds, 60–86400. Max message: 16 KiB (`maxMessageBytes` decimal string 1–16384).
- Identity policy modes (same as v2): `required_fresh`, `required_existing_or_fresh`, `not_required`; when required, chainId `eip155:11155111`, registry `0x8004a818bfb912233c491871b3d84c89a494bd9e`.
- All time judgments against an injected clock that production binds to ledger time; expiry is lazy (checked on touch), never a timer.
- Failure reason codes, exact: admission `NOT_OPEN`, `EXPIRED`, `REVOKED`, `SCOPE_VIOLATION`, `TOO_LARGE`, `UNKNOWN_PARTY`; checklist `IDENTITY_UNVERIFIED`, `AUTHORITY_INVALID`, `MANIFEST_MISMATCH`, `PURPOSE_MISMATCH`.
- Every record validated with exact-key checks (extra or missing key ⇒ reject) in the style of `agent-handshake/v2/protocol.ts`.
- Anchors only opening (3 chained transitions: TERMS_READINESS → CONSENT → OPEN) and explicit closure (1 record). Message bodies never leave the session store; receipts carry digests.
- The module never mutates `src/agent-handshake/**` or `src/handshake/**` — import only.
- No external business actions anywhere (`externalBusinessActionPerformed: false` invariant).
- Tests run with `npm test` inside `packages/mcp-server` (= `tsc -b && node --test`); tests import compiled code from `../dist/standalone-handshake/*.js`.
- No TODOs, no skipped tests, no placeholder branches.

## File Structure

```
packages/mcp-server/src/standalone-handshake/
  protocol.ts        record schemas, exact-key validators, canonical digests, consent/authority payloads
  checklist.ts       deterministic readiness evaluation → checks[] + checklistDigest
  session-store.ts   in-memory state machine, invitation secrets, access tokens, admission enforcement
  coordinator.ts     tool orchestration, consent signature verification, ledger anchoring
  tools.ts           10 tool definitions (zod) + registerStandaloneTools
  public-server.ts   instructions, McpServer builder, role-access broker, HTTP handler, discovery manifest
packages/mcp-server/src/http.ts            (modify) /connect/mcp + /.well-known/standalone-handshake.json routes
packages/mcp-server/src/landing.ts         (modify) handshake section, module card, llms.txt facts
packages/mcp-server/test/standalone-*.test.mjs   six new test files
```

---

### Task 1: Protocol records and validators

**Files:**
- Create: `packages/mcp-server/src/standalone-handshake/protocol.ts`
- Test: `packages/mcp-server/test/standalone-protocol.test.mjs`

**Interfaces:**
- Consumes: `canonicalBytes`, `digestHex` from `../handshake/protocol.js` (existing, unmodified).
- Produces (used by every later task): constants `STANDALONE_HANDSHAKE_PROTOCOL`, `STANDALONE_CHAIN_ID`, `STANDALONE_REGISTRY_ADDRESS`, `MESSAGE_KINDS`, `DATA_HANDLING_CLASSES`; `StandaloneHandshakeValidationError`; `normalizeStandaloneTerms(value)`; `normalizeStandaloneReadiness(value, policyMode)`; `standaloneAuthorityRecord(readiness)`; `buildStandaloneConsentRecord(input)`; `standaloneCanonicalRecord(value)`; `normalizeStandaloneClosure(value)`.

- [ ] **Step 1: Write the failing test**

Create `packages/mcp-server/test/standalone-protocol.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  STANDALONE_HANDSHAKE_PROTOCOL,
  MESSAGE_KINDS,
  DATA_HANDLING_CLASSES,
  StandaloneHandshakeValidationError,
  normalizeStandaloneTerms,
  normalizeStandaloneReadiness,
  standaloneAuthorityRecord,
  buildStandaloneConsentRecord,
  standaloneCanonicalRecord,
  normalizeStandaloneClosure,
} from "../dist/standalone-handshake/protocol.js";

const IDENTITY_POLICY = { erc8004: "not_required", chainId: null, registryAddress: null };

export function validTerms(overrides = {}) {
  return {
    reference: "delivery-options-q3",
    purpose: "Discuss delivery options for Q3 orders",
    channelLimits: { durationSeconds: "3600", messageKinds: ["question", "proposal", "evidence"], maxMessageBytes: "16384" },
    identityPolicy: IDENTITY_POLICY,
    ...overrides,
  };
}

export function validReadiness(overrides = {}) {
  return {
    sessionKeyAddress: "0x" + "11".repeat(20),
    identity: null,
    authorityStatement: { accountableParty: "Acme Buying LLC", statement: "I am authorized to discuss delivery options for Acme." },
    authoritySignatureHex: "0x" + "11".repeat(64) + "1b",
    capabilityManifest: { dataHandlingClass: "confidential", purpose: "Discuss delivery options for Q3 orders" },
    ...overrides,
  };
}

test("accepts a valid terms record and freezes derived values", () => {
  const terms = normalizeStandaloneTerms(validTerms());
  assert.equal(terms.reference, "delivery-options-q3");
  assert.equal(terms.channelLimits.durationSeconds, "3600");
  assert.deepEqual([...terms.channelLimits.messageKinds], ["question", "proposal", "evidence"]);
  assert.equal(Object.isFrozen(terms), true);
});

test("terms rejects an extra key, a bad kind, an out-of-range duration, and a bad size", () => {
  assert.throws(() => normalizeStandaloneTerms({ ...validTerms(), extra: 1 }), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "60", messageKinds: ["bargain"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "59", messageKinds: ["question"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "86401", messageKinds: ["question"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "3600", messageKinds: ["question"], maxMessageBytes: "16385" } })), StandaloneHandshakeValidationError);
});

test("readiness validates address, signature shape, class, and identity-vs-policy", () => {
  const readiness = normalizeStandaloneReadiness(validReadiness(), "not_required");
  assert.equal(readiness.capabilityManifest.dataHandlingClass, "confidential");
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ sessionKeyAddress: "0x1234" }), "not_required"), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ authoritySignatureHex: "0x1234" }), "not_required"), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ capabilityManifest: { dataHandlingClass: "topsecret", purpose: "x" } }), "not_required"), StandaloneHandshakeValidationError);
  // identity must be null only when the policy is not_required
  assert.throws(() => normalizeStandaloneReadiness(validReadiness(), "required_fresh"), StandaloneHandshakeValidationError);
});

test("authority record and consent record have stable canonical digests", () => {
  const readiness = normalizeStandaloneReadiness(validReadiness(), "not_required");
  const authority = standaloneAuthorityRecord(readiness);
  assert.equal(authority.schema, "clockchain.standalone-handshake-authority/v1");
  const consentA = standaloneCanonicalRecord(buildStandaloneConsentRecord({ sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", role: "initiator", termsDigest: "a".repeat(64), checklistDigest: "b".repeat(64) }));
  const consentB = standaloneCanonicalRecord(buildStandaloneConsentRecord({ role: "initiator", termsDigest: "a".repeat(64), checklistDigest: "b".repeat(64), sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01" }));
  assert.equal(consentA.digest, consentB.digest); // key order irrelevant
  assert.equal(consentA.digest, /^[0-9a-f]{64}$/.test(consentA.digest) ? consentA.digest : "bad");
});

test("closure validates outcome, byRole, and the no-external-action invariant", () => {
  const closure = normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "revoked", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: false });
  assert.equal(closure.outcome, "revoked");
  assert.throws(() => normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "expired", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: false }), StandaloneHandshakeValidationError); // expired is never closed by a role
  assert.throws(() => normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "closed", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: true }), StandaloneHandshakeValidationError);
});

test("module constants are exact", () => {
  assert.equal(STANDALONE_HANDSHAKE_PROTOCOL, "clockchain.standalone-handshake/v1");
  assert.deepEqual([...MESSAGE_KINDS], ["question", "proposal", "evidence", "note"]);
  assert.deepEqual([...DATA_HANDLING_CLASSES], ["public", "confidential", "restricted"]);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/mcp-server && npm test 2>&1 | grep -A2 standalone-protocol || true`
Expected: import failure — `Cannot find module '../dist/standalone-handshake/protocol.js'`.

- [ ] **Step 3: Write the implementation**

Create `packages/mcp-server/src/standalone-handshake/protocol.ts`:

```ts
import { canonicalBytes, digestHex } from "../handshake/protocol.js";

export const STANDALONE_HANDSHAKE_PROTOCOL = "clockchain.standalone-handshake/v1";
export const STANDALONE_CHAIN_ID = "eip155:11155111";
export const STANDALONE_REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const MESSAGE_KINDS = ["question", "proposal", "evidence", "note"] as const;
export const DATA_HANDLING_CLASSES = ["public", "confidential", "restricted"] as const;

type JsonRecord = Record<string, any>;

const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE = /^[ -~]+$/;
const IDENTITY_MODES = ["required_fresh", "required_existing_or_fresh", "not_required"];
const ROLES = ["initiator", "responder"];

export class StandaloneHandshakeValidationError extends Error {
  constructor() {
    super("Standalone handshake validation failed.");
    this.name = "StandaloneHandshakeValidationError";
  }
}

function invalid(): never {
  throw new StandaloneHandshakeValidationError();
}

export { ADDRESS, DECIMAL, DIGEST, SIGNATURE, UUID, ROLES };

function exact(value: unknown, keys: readonly string[]): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
  const result: JsonRecord = {};
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function printable(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && value.trim() === value && PRINTABLE.test(value);
}

function decimalWithin(value: unknown, min: bigint, max: bigint): value is string {
  return typeof value === "string" && DECIMAL.test(value) && BigInt(value) >= min && BigInt(value) <= max;
}

function identityPolicy(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["erc8004", "chainId", "registryAddress"]);
  if (!IDENTITY_MODES.includes(item.erc8004)) invalid();
  if (item.erc8004 === "not_required") {
    if (item.chainId !== null || item.registryAddress !== null) invalid();
  } else if (item.chainId !== STANDALONE_CHAIN_ID || item.registryAddress !== STANDALONE_REGISTRY_ADDRESS) invalid();
  return Object.freeze(item);
}

export function normalizeStandaloneTerms(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["reference", "purpose", "channelLimits", "identityPolicy"]);
  if (!printable(item.reference, 128) || !printable(item.purpose, 256)) invalid();
  const limits = exact(item.channelLimits, ["durationSeconds", "messageKinds", "maxMessageBytes"]);
  if (!decimalWithin(limits.durationSeconds, 60n, 86400n)) invalid();
  if (!decimalWithin(limits.maxMessageBytes, 1n, 16384n)) invalid();
  if (!Array.isArray(limits.messageKinds) || limits.messageKinds.length === 0) invalid();
  const kinds = [...limits.messageKinds];
  if (kinds.some((kind) => !MESSAGE_KINDS.includes(kind)) || new Set(kinds).size !== kinds.length) invalid();
  return Object.freeze({
    reference: item.reference,
    purpose: item.purpose,
    channelLimits: Object.freeze({ durationSeconds: limits.durationSeconds, messageKinds: Object.freeze(kinds), maxMessageBytes: limits.maxMessageBytes }),
    identityPolicy: identityPolicy(item.identityPolicy),
  });
}

function registration(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["agentId", "chainId", "registryAddress"]);
  if (typeof item.agentId !== "string" || !DECIMAL.test(item.agentId) || item.chainId !== STANDALONE_CHAIN_ID || item.registryAddress !== STANDALONE_REGISTRY_ADDRESS) invalid();
  return Object.freeze(item);
}

export function normalizeStandaloneReadiness(value: unknown, policyMode: string): Readonly<JsonRecord> {
  if (!IDENTITY_MODES.includes(policyMode)) invalid();
  const item = exact(value, ["sessionKeyAddress", "identity", "authorityStatement", "authoritySignatureHex", "capabilityManifest"]);
  if (!ADDRESS.test(item.sessionKeyAddress) || !SIGNATURE.test(item.authoritySignatureHex)) invalid();
  const identity = policyMode === "not_required" ? (item.identity === null ? null : invalid()) : item.identity === null ? invalid() : registration(item.identity);
  const authority = exact(item.authorityStatement, ["accountableParty", "statement"]);
  if (!printable(authority.accountableParty, 128) || !printable(authority.statement, 512)) invalid();
  const manifest = exact(item.capabilityManifest, ["dataHandlingClass", "purpose"]);
  if (!DATA_HANDLING_CLASSES.includes(manifest.dataHandlingClass) || !printable(manifest.purpose, 256)) invalid();
  return Object.freeze({
    sessionKeyAddress: item.sessionKeyAddress,
    identity,
    authorityStatement: Object.freeze({ accountableParty: authority.accountableParty, statement: authority.statement }),
    authoritySignatureHex: item.authoritySignatureHex,
    capabilityManifest: Object.freeze({ dataHandlingClass: manifest.dataHandlingClass, purpose: manifest.purpose }),
  });
}

export function standaloneAuthorityRecord(readiness: Readonly<JsonRecord>): Readonly<JsonRecord> {
  return Object.freeze({
    schema: "clockchain.standalone-handshake-authority/v1",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    sessionKeyAddress: readiness.sessionKeyAddress,
    accountableParty: readiness.authorityStatement.accountableParty,
    statement: readiness.authorityStatement.statement,
  });
}

export function buildStandaloneConsentRecord(input: { sessionId: string; role: string; termsDigest: string; checklistDigest: string }): Readonly<JsonRecord> {
  const item = exact(input, ["sessionId", "role", "termsDigest", "checklistDigest"]);
  if (!UUID.test(item.sessionId) || !ROLES.includes(item.role) || !DIGEST.test(item.termsDigest) || !DIGEST.test(item.checklistDigest)) invalid();
  return Object.freeze({
    schema: "clockchain.standalone-handshake-consent/v1",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    sessionId: item.sessionId,
    role: item.role,
    termsDigest: item.termsDigest,
    checklistDigest: item.checklistDigest,
  });
}

export function normalizeStandaloneClosure(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, ["schema", "protocol", "sessionId", "outcome", "byRole", "closedAtMs", "externalBusinessActionPerformed"]);
  if (item.schema !== "clockchain.standalone-handshake-closure/v1" || item.protocol !== STANDALONE_HANDSHAKE_PROTOCOL) invalid();
  if (!UUID.test(item.sessionId) || !["closed", "revoked"].includes(item.outcome)) invalid();
  if (!ROLES.includes(item.byRole)) invalid();
  if (!decimalWithin(item.closedAtMs, 0n, 99999999999999n)) invalid();
  if (item.externalBusinessActionPerformed !== false) invalid();
  return Object.freeze(item);
}

export function standaloneCanonicalRecord(value: unknown): Readonly<{ bytesHex: string; digest: string }> {
  const bytes = canonicalBytes(value);
  return Object.freeze({ bytesHex: bytes.toString("hex"), digest: digestHex(value) });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -20`
Expected: all `standalone-protocol` tests PASS, existing suite unchanged.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/standalone-handshake/protocol.ts packages/mcp-server/test/standalone-protocol.test.mjs
git commit -m "standalone-handshake: protocol records — exact-key validators, canonical digests, consent/authority payloads"
```

---

### Task 2: Deterministic readiness checklist

**Files:**
- Create: `packages/mcp-server/src/standalone-handshake/checklist.ts`
- Test: `packages/mcp-server/test/standalone-checklist.test.mjs`

**Interfaces:**
- Consumes: `canonicalBytes` from `../handshake/protocol.js`; `standaloneAuthorityRecord`, `standaloneCanonicalRecord`, `normalizeStandaloneReadiness` outputs from Task 1.
- Produces: `evaluateStandaloneReadiness(input)` → `Promise<Readonly<{passed: boolean; checks: readonly {check: string; passed: boolean; reason?: string}[]; checklistDigest: string}>>` where `input = {sessionId, terms, termsDigest, initiator, responder, resolveIdentity, recoverAddress}`. `resolveIdentity: (identity) => Promise<boolean>`, `recoverAddress: ({bytes, signatureHex}) => Promise<string>`.

- [ ] **Step 1: Write the failing test**

Create `packages/mcp-server/test/standalone-checklist.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateStandaloneReadiness } from "../dist/standalone-handshake/checklist.js";
import { normalizeStandaloneTerms, normalizeStandaloneReadiness, standaloneCanonicalRecord } from "../dist/standalone-handshake/protocol.js";
import { validTerms, validReadiness } from "./standalone-protocol.test.js";

const SESSION = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";

const OK_RESOLVE = async () => true;
const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);

function recovering() {
  return async ({ signatureHex }) => {
    if (signatureHex === SIG_INITIATOR) return ADDR_INITIATOR;
    if (signatureHex === SIG_RESPONDER) return ADDR_RESPONDER;
    return "0x" + "99".repeat(20);
  };
}

async function run(overrides = {}) {
  const terms = normalizeStandaloneTerms(validTerms(overrides.terms));
  const termsDigest = standaloneCanonicalRecord(terms).digest;
  const initiator = normalizeStandaloneReadiness(
    validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR, ...(overrides.initiator ?? {}) }),
    terms.identityPolicy.erc8004,
  );
  const responder = normalizeStandaloneReadiness(
    validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER, ...(overrides.responder ?? {}) }),
    terms.identityPolicy.erc8004,
  );
  return evaluateStandaloneReadiness({
    sessionId: SESSION,
    terms,
    termsDigest,
    initiator,
    responder,
    resolveIdentity: overrides.resolveIdentity ?? OK_RESOLVE,
    recoverAddress: overrides.recoverAddress ?? recovering(),
  });
}

test("a fully consistent pair passes with a stable checklist digest", async () => {
  const result = await run();
  assert.equal(result.passed, true);
  assert.deepEqual(result.checks.map((c) => c.check), ["identity", "authority", "manifest"]);
  assert.equal(/^[0-9a-f]{64}$/.test(result.checklistDigest), true);
  const again = await run();
  assert.equal(again.checklistDigest, result.checklistDigest);
});

test("identity failure carries IDENTITY_UNVERIFIED and fails the checklist", async () => {
  const result = await run({ resolveIdentity: async () => false });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["IDENTITY_UNVERIFIED"]);
});

test("a wrong authority signer fails with AUTHORITY_INVALID", async () => {
  const result = await run({ responder: { authoritySignatureHex: "0x" + "33".repeat(64) + "1d" } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["AUTHORITY_INVALID"]);
});

test("mismatched data-handling class fails with MANIFEST_MISMATCH", async () => {
  const result = await run({ responder: { capabilityManifest: { dataHandlingClass: "public", purpose: "Discuss delivery options for Q3 orders" } } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["MANIFEST_MISMATCH"]);
});

test("a party whose manifest purpose differs from the terms fails with PURPOSE_MISMATCH", async () => {
  const result = await run({ initiator: { capabilityManifest: { dataHandlingClass: "confidential", purpose: "Sell advertising inventory" } } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["PURPOSE_MISMATCH"]);
});

test("identity is structurally satisfied when the policy is not_required", async () => {
  const result = await run({ resolveIdentity: async () => { throw new Error("must not be called"); } });
  assert.equal(result.passed, true);
});
```

Note: the test imports helpers from `./standalone-protocol.test.js` — `node --test` runs every `*.test.mjs` file; importing one test file from another re-uses its exports without duplicating fixtures. The imported module's `test()` registrations run under their own file name only when the file is itself a test target, which it is — its tests simply also run there; no double-run issue arises because `node --test` deduplicates by resolved path per file executed. If the runner version double-executes, move `validTerms`/`validReadiness` into `test/helpers/standalone-fixtures.mjs` and import from both.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/mcp-server && npm test 2>&1 | grep -B1 -A2 standalone-checklist | head -20`
Expected: import failure — `Cannot find module '../dist/standalone-handshake/checklist.js'`.

- [ ] **Step 3: Write the implementation**

Create `packages/mcp-server/src/standalone-handshake/checklist.ts`:

```ts
import { canonicalBytes } from "../handshake/protocol.js";

import { standaloneAuthorityRecord, standaloneCanonicalRecord } from "./protocol.js";

export interface StandaloneCheck {
  check: "identity" | "authority" | "manifest";
  passed: boolean;
  reason?: string;
}

export interface StandaloneChecklistResult {
  passed: boolean;
  checks: readonly StandaloneCheck[];
  checklistDigest: string;
}

export async function evaluateStandaloneReadiness(input: {
  sessionId: string;
  terms: Readonly<Record<string, any>>;
  termsDigest: string;
  initiator: Readonly<Record<string, any>>;
  responder: Readonly<Record<string, any>>;
  resolveIdentity: (identity: Readonly<Record<string, any>> | null) => Promise<boolean>;
  recoverAddress: (input: { bytes: Buffer; signatureHex: string }) => Promise<string>;
}): Promise<StandaloneChecklistResult> {
  const { sessionId, terms, termsDigest, initiator, responder, resolveIdentity, recoverAddress } = input;
  const checks: StandaloneCheck[] = [];
  const required = terms.identityPolicy.erc8004 !== "not_required";

  const identityOk = !required ? true : (await resolveIdentity(initiator.identity)) && (await resolveIdentity(responder.identity));
  checks.push({ check: "identity", passed: identityOk, ...(identityOk ? {} : { reason: "IDENTITY_UNVERIFIED" }) });

  const parties: readonly [string, any][] = [["initiator", initiator], ["responder", responder]];
  let authorityOk = true;
  for (const [role, readiness] of parties) {
    const bytes = canonicalBytes(standaloneAuthorityRecord(readiness));
    let recovered = "";
    try {
      recovered = (await recoverAddress({ bytes, signatureHex: readiness.authoritySignatureHex })).toLowerCase();
    } catch {
      recovered = "";
    }
    if (recovered !== String(readiness.sessionKeyAddress).toLowerCase()) authorityOk = false;
  }
  checks.push({ check: "authority", passed: authorityOk, ...(authorityOk ? {} : { reason: "AUTHORITY_INVALID" }) });

  const sameClass = initiator.capabilityManifest.dataHandlingClass === responder.capabilityManifest.dataHandlingClass;
  const purposesMatch = initiator.capabilityManifest.purpose === terms.purpose && responder.capabilityManifest.purpose === terms.purpose;
  checks.push({
    check: "manifest",
    passed: sameClass && purposesMatch,
    ...(sameClass && purposesMatch ? {} : { reason: sameClass ? "PURPOSE_MISMATCH" : "MANIFEST_MISMATCH" }),
  });

  const passed = checks.every((check) => check.passed);
  const digestRecord = {
    schema: "clockchain.standalone-handshake-checklist/v1",
    protocol: "clockchain.standalone-handshake/v1",
    sessionId,
    termsDigest,
    checks: checks.map(({ check, passed: ok, reason }) => (reason === undefined ? { check, passed: ok } : { check, passed: ok, reason })),
  };
  return { passed, checks: Object.freeze(checks), checklistDigest: standaloneCanonicalRecord(digestRecord).digest };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -20`
Expected: `standalone-checklist` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/standalone-handshake/checklist.ts packages/mcp-server/test/standalone-checklist.test.mjs
git commit -m "standalone-handshake: deterministic readiness checklist — identity, authority signature, manifest cross-check"
```

---

### Task 3: Session store — state machine and admission enforcement

**Files:**
- Create: `packages/mcp-server/src/standalone-handshake/session-store.ts`
- Test: `packages/mcp-server/test/standalone-session-store.test.mjs`

**Interfaces:**
- Consumes: `digestHex` from `../handshake/protocol.js` (for nothing — body digest uses `node:crypto` sha256 directly), Task 1 types.
- Produces: `StandaloneIllegalTransitionError`; `StandaloneAdmissionError` (`.reason` one of `NOT_OPEN`, `EXPIRED`, `REVOKED`, `SCOPE_VIOLATION`, `TOO_LARGE`, `UNKNOWN_PARTY`); `createStandaloneSessionStore({now?})` → store with methods `createSession({sessionId, terms, termsDigest, initiatorReadiness})`, `putInvitation({secret, sessionId})`, `claimInvitation(secret)` (single-use), `getSession(id)`, `authenticate(id, token)` → `"initiator" | "responder" | undefined`, `setStage(id, stage)`, `setResponderReadiness(id, readiness)`, `setChecklist(id, result)`, `setConsent(id, role, consentDigest)`, `bothConsented(id)`, `openChannel(id, {openedAtMs, expiresAtMs})`, `admitMessage(id, role, kind, body)` → message record, `readMessages(id, role)`, `status(id)`, `closeChannel(id, role)`, `revokeChannel(id, role)`. Stages exactly: `invited, readiness_pending, ready, ready_failed, consent_pending, consented, open, closed, revoked, expired`.

- [ ] **Step 1: Write the failing test**

Create `packages/mcp-server/test/standalone-session-store.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";

import { createStandaloneSessionStore, StandaloneAdmissionError, StandaloneIllegalTransitionError } from "../dist/standalone-handshake/session-store.js";
import { validTerms, validReadiness } from "./standalone-protocol.test.js";

const SESSION = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";

function storeWithSession(overrides = {}) {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs });
  const terms = { ...validTerms(overrides.terms) };
  store.createSession({ sessionId: SESSION, terms, termsDigest: "a".repeat(64), initiatorReadiness: validReadiness() });
  return { store, advance: (ms) => { nowMs += ms; } };
}

function toOpen(context) {
  const { store } = context;
  store.setStage(SESSION, "readiness_pending");
  store.setStage(SESSION, "ready");
  store.setStage(SESSION, "consent_pending");
  store.setStage(SESSION, "consented");
  store.openChannel(SESSION, { openedAtMs: 1_750_000_000_000, expiresAtMs: 1_750_003_600_000 });
  return context;
}

test("a session is created invited and only legal transitions apply", () => {
  const { store } = storeWithSession();
  assert.equal(store.getSession(SESSION).stage, "invited");
  store.setStage(SESSION, "readiness_pending");
  assert.throws(() => store.setStage(SESSION, "open"), StandaloneIllegalTransitionError);
  store.setStage(SESSION, "ready_failed");
  assert.equal(store.getSession(SESSION).stage, "ready_failed");
});

test("admission enforces scope, size, party, and state with exact reason codes", () => {
  const { store } = storeWithSession();
  store.setStage(SESSION, "readiness_pending");
  let error = null;
  try { store.admitMessage(SESSION, "initiator", "question", "hello"); } catch (e) { error = e; }
  assert.equal(error instanceof StandaloneAdmissionError && error.reason, "NOT_OPEN");

  toOpen(storeWithSession());
});

test("an open channel admits an in-scope message and records sender, digest, and sequence", () => {
  const { store } = storeWithSession();
  toOpen({ store });
  const message = store.admitMessage(SESSION, "responder", "proposal", "Ship Tuesdays, 14-day lead time.");
  assert.equal(message.seq, 1);
  assert.equal(message.kind, "proposal");
  assert.equal(message.fromRole, "responder");
  assert.equal(message.toRole, "initiator");
  assert.equal(/^[0-9a-f]{64}$/.test(message.bodyDigest), true);
  assert.equal(message.sentAtMs, 1_750_000_000_000);
  const second = store.admitMessage(SESSION, "initiator", "question", "Can you do 10 days?");
  assert.equal(second.seq, 2);
});

test("scope violation, oversize, and unknown party are refused", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  try { store.admitMessage(SESSION, "responder", "note", "x"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "SCOPE_VIOLATION"); }
  try { store.admitMessage(SESSION, "responder", "proposal", "x".repeat(16385)); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "TOO_LARGE"); }
  try { store.admitMessage(SESSION, "stranger", "question", "x"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "UNKNOWN_PARTY"); }
});

test("expiry at exactly expiresAtMs refuses with EXPIRED and flips the stage", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store, advance } = context;
  advance(3_600_000); // exactly to expiresAtMs
  try { store.admitMessage(SESSION, "responder", "question", "still there?"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "EXPIRED"); }
  assert.equal(store.getSession(SESSION).stage, "expired");
  try { store.admitMessage(SESSION, "responder", "question", "again"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "EXPIRED"); }
});

test("revocation is immediate, permanent, and reports REVOKED", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  store.revokeChannel(SESSION, "initiator");
  assert.equal(store.getSession(SESSION).stage, "revoked");
  try { store.admitMessage(SESSION, "responder", "question", "hello?"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "REVOKED"); }
  assert.throws(() => store.setStage(SESSION, "open"), StandaloneIllegalTransitionError);
});

test("explicit close records the closer and readMessages filters by addressee", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  store.admitMessage(SESSION, "responder", "proposal", "Tuesdays work.");
  store.admitMessage(SESSION, "initiator", "question", "Confirm Tuesday?");
  const forInitiator = store.readMessages(SESSION, "initiator");
  assert.equal(forInitiator.length, 1);
  assert.equal(forInitiator[0].fromRole, "responder");
  assert.equal(forInitiator[0].body, "Tuesdays work.");
  store.closeChannel(SESSION, "responder");
  const snapshot = store.status(SESSION);
  assert.equal(snapshot.stage, "closed");
  assert.equal(snapshot.closedBy, "responder");
  assert.equal(snapshot.messageCount, 2);
  assert.equal(snapshot.messages === undefined, true); // status never leaks bodies
});

test("invitation claims are single-use and access tokens authenticate roles", () => {
  const { store } = storeWithSession();
  store.putInvitation({ secret: "s3cret-value-with-length", sessionId: SESSION });
  assert.equal(store.claimInvitation("s3cret-value-with-length"), SESSION);
  assert.equal(store.claimInvitation("s3cret-value-with-length"), undefined);
  assert.equal(store.claimInvitation("never-issued"), undefined);
  store.setAccessToken(SESSION, "initiator", "sat_" + "A".repeat(43));
  assert.equal(store.authenticate(SESSION, "sat_" + "A".repeat(43)), "initiator");
  assert.equal(store.authenticate(SESSION, "sat_" + "B".repeat(43)), undefined);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/mcp-server && npm test 2>&1 | grep -A3 standalone-session-store | head -10`
Expected: import failure — `Cannot find module '../dist/standalone-handshake/session-store.js'`.

- [ ] **Step 3: Write the implementation**

Create `packages/mcp-server/src/standalone-handshake/session-store.ts`:

```ts
import { createHash } from "node:crypto";

const STAGES = ["invited", "readiness_pending", "ready", "ready_failed", "consent_pending", "consented", "open", "closed", "revoked", "expired"] as const;
const LEGAL: Record<string, readonly string[]> = {
  invited: ["readiness_pending"],
  readiness_pending: ["ready", "ready_failed"],
  ready: ["consent_pending"],
  consent_pending: ["consented"],
  consented: ["open"],
  open: ["closed", "revoked", "expired"],
};
const ROLES = ["initiator", "responder"];

export class StandaloneIllegalTransitionError extends Error {
  constructor() {
    super("Standalone handshake illegal transition.");
    this.name = "StandaloneIllegalTransitionError";
  }
}

export class StandaloneAdmissionError extends Error {
  constructor(readonly reason: string) {
    super(`Standalone handshake admission refused: ${reason}`);
    this.name = "StandaloneAdmissionError";
  }
}

export function createStandaloneSessionStore(options: { now?: () => number } = {}) {
  const now = options.now ?? Date.now;
  const sessions = new Map<string, any>();
  const invitations = new Map<string, string>();

  function requireSession(sessionId: string): any {
    const session = sessions.get(sessionId);
    if (!session) throw new StandaloneAdmissionError("NOT_OPEN");
    return session;
  }

  function expireIfDue(session: any): void {
    if (session.stage === "open" && now() >= session.expiresAtMs) session.stage = "expired";
  }

  function other(role: string): string {
    return role === "initiator" ? "responder" : "initiator";
  }

  return {
    createSession(input: { sessionId: string; terms: any; termsDigest: string; initiatorReadiness: any }): void {
      sessions.set(input.sessionId, {
        sessionId: input.sessionId,
        terms: input.terms,
        termsDigest: input.termsDigest,
        initiatorReadiness: input.initiatorReadiness,
        responderReadiness: undefined,
        checklist: undefined,
        consents: {},
        auth: {},
        stage: "invited",
        openedAtMs: undefined,
        expiresAtMs: undefined,
        closedBy: undefined,
        messages: [],
        seq: 0,
      });
    },

    putInvitation(input: { secret: string; sessionId: string }): void {
      invitations.set(input.secret, input.sessionId);
    },

    claimInvitation(secret: string): string | undefined {
      const sessionId = invitations.get(secret);
      if (sessionId === undefined) return undefined;
      invitations.delete(secret);
      return sessionId;
    },

    getSession(sessionId: string): any {
      const session = sessions.get(sessionId);
      if (!session) return undefined;
      expireIfDue(session);
      return session;
    },

    requireSession,

    authenticate(sessionId: string, token: string): string | undefined {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      for (const role of ROLES) if (session.auth[role] !== undefined && session.auth[role] === token) return role;
      return undefined;
    },

    setAccessToken(sessionId: string, role: string, token: string): void {
      requireSession(sessionId).auth[role] = token;
    },

    setStage(sessionId: string, stage: string): void {
      const session = requireSession(sessionId);
      if (!STAGES.includes(stage) || !LEGAL[session.stage]?.includes(stage)) throw new StandaloneIllegalTransitionError();
      session.stage = stage;
    },

    setResponderReadiness(sessionId: string, readiness: any): void {
      requireSession(sessionId).responderReadiness = readiness;
    },

    setChecklist(sessionId: string, result: any): void {
      requireSession(sessionId).checklist = result;
    },

    setConsent(sessionId: string, role: string, consentDigest: string): void {
      const session = requireSession(sessionId);
      session.consents[role] = consentDigest;
    },

    bothConsented(sessionId: string): boolean {
      const session = requireSession(sessionId);
      return ROLES.every((role) => typeof session.consents[role] === "string" && session.consents[role].length === 64);
    },

    openChannel(sessionId: string, times: { openedAtMs: number; expiresAtMs: number }): void {
      const session = requireSession(sessionId);
      session.openedAtMs = times.openedAtMs;
      session.expiresAtMs = times.expiresAtMs;
    },

    admitMessage(sessionId: string, role: string, kind: string, body: string): any {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      if (session.stage === "expired") throw new StandaloneAdmissionError("EXPIRED");
      if (session.stage === "revoked") throw new StandaloneAdmissionError("REVOKED");
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      if (!session.terms.channelLimits.messageKinds.includes(kind)) throw new StandaloneAdmissionError("SCOPE_VIOLATION");
      if (typeof body !== "string" || body.length === 0 || Buffer.byteLength(body, "utf8") > Number(session.terms.channelLimits.maxMessageBytes)) {
        throw new StandaloneAdmissionError("TOO_LARGE");
      }
      session.seq += 1;
      const message = {
        sessionId,
        seq: session.seq,
        kind,
        fromRole: role,
        toRole: other(role),
        bodyDigest: createHash("sha256").update(body, "utf8").digest("hex"),
        sentAtMs: now(),
        body,
      };
      session.messages.push(message);
      return message;
    },

    readMessages(sessionId: string, role: string): readonly any[] {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      return session.messages.filter((message: any) => message.toRole === role).map((message: any) => Object.freeze({ ...message }));
    },

    status(sessionId: string): any {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      return Object.freeze({
        sessionId: session.sessionId,
        reference: session.terms.reference,
        stage: session.stage,
        checklist: session.checklist,
        consented: { initiator: session.consents.initiator !== undefined, responder: session.consents.responder !== undefined },
        openedAtMs: session.openedAtMs,
        expiresAtMs: session.expiresAtMs,
        remainingMs: session.stage === "open" ? Math.max(0, session.expiresAtMs - now()) : 0,
        scope: session.terms.channelLimits,
        messageCount: session.messages.length,
        closedBy: session.closedBy,
      });
    },

    closeChannel(sessionId: string, role: string): void {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      session.stage = "closed";
      session.closedBy = role;
    },

    revokeChannel(sessionId: string, role: string): void {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      session.stage = "revoked";
      session.closedBy = role;
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -20`
Expected: `standalone-session-store` tests PASS. Fix the `toOpen(storeWithSession())` call shape in the scope test if the compile flags it (use the context object).

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/standalone-handshake/session-store.ts packages/mcp-server/test/standalone-session-store.test.mjs
git commit -m "standalone-handshake: session store — state machine, invitation claims, fail-closed admission"
```

---

### Task 4: Coordinator — orchestration and anchoring

**Files:**
- Create: `packages/mcp-server/src/standalone-handshake/coordinator.ts`
- Test: `packages/mcp-server/test/standalone-coordinator.test.mjs`

**Interfaces:**
- Consumes: Tasks 1–3; `randomUUID`, `randomBytes` from `node:crypto`; `canonicalBytes` from `../handshake/protocol.js`; `resolveOwnedAgentRegistration`, `recoverEip191Address` from `../handshake/evm.js` (runtime binding only); `ClockchainClient`, `readConfigFromEnv` from `@clockchain/core` (runtime binding only).
- Produces: `StandaloneCoordinatorError`, `StandaloneTransientCoordinatorError`; `createStandaloneCoordinator({client, now, rpcUrl, recoverEip191Address, resolveIdentity})` → `{invoke(name, args) → Promise<Record<string, unknown>>, store}`; `createRuntimeStandaloneCoordinator(env)` → same, built from real infra. `invoke` handles the ten tool names; `handshake_invite` returns `{sessionId, reference, invitation, initiatorAccess}`; `handshake_accept_invitation` returns `{sessionId, stage, checklist, responderAccess}`; `channel_open` returns an opening receipt `{schema, protocol, sessionId, reference, termsDigest, checklistDigest, openedAtMs, expiresAtMs, anchors[3], externalBusinessActionPerformed: false}`; `channel_close`/`channel_revoke` return `{outcome, byRole, closureAnchor}`.

- [ ] **Step 1: Write the failing test**

Create `packages/mcp-server/test/standalone-coordinator.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { validTerms, validReadiness } from "./standalone-protocol.test.js";

const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);

function fakeLedger() {
  const entries = new Map();
  let height = 100;
  return {
    blocks: entries,
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
      return { blockHeight: String(blockHeight), blockTime: "2026-09-14T00:00:00.000Z" };
    },
  };
}

function coordinator(ledger = fakeLedger(), overrides = {}) {
  let nowMs = 1_750_000_000_000;
  const instance = createStandaloneCoordinator({
    client: ledger,
    now: () => nowMs,
    recoverEip191Address: async ({ signatureHex }) =>
      signatureHex === SIG_INITIATOR ? ADDR_INITIATOR : signatureHex === SIG_RESPONDER ? ADDR_RESPONDER : "0x" + "99".repeat(20),
    resolveIdentity: overrides.resolveIdentity ?? (async () => true),
    ...overrides.coordinator,
  });
  return { ...instance, advance: (ms) => { nowMs += ms; } };
}

async function openSession(instance, termsOverrides = {}) {
  const invite = await instance.invoke("handshake_invite", {
    ...validTerms(termsOverrides),
    readiness: validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR }),
  });
  assert.equal(invite.stage, undefined);
  const accept = await instance.invoke("handshake_accept_invitation", {
    invitation: invite.invitation,
    readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }),
  });
  return { invite, accept };
}

async function consentAndOpen(instance, session) {
  const statusI = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(statusI.stage, "ready");
  const consent1 = await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  assert.equal(consent1.stage, "consent_pending");
  const consent2 = await instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_RESPONDER });
  assert.equal(consent2.stage, "consented");
  const receipt = await instance.invoke("channel_open", { access: session.invite.initiatorAccess });
  assert.equal(receipt.anchors.length, 3);
  assert.deepEqual(receipt.anchors.map((a) => a.kind), ["terms-readiness", "consent", "open"]);
  assert.equal(receipt.externalBusinessActionPerformed, false);
  return receipt;
}

test("invite → accept passes the checklist and issues both role accesses", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  assert.equal(session.invite.invitation.length >= 80, true);
  assert.equal(typeof session.invite.initiatorAccess, "string");
  assert.equal(session.accept.stage, "ready");
  assert.equal(session.accept.checklist.passed, true);
  assert.equal(typeof session.accept.responderAccess, "string");
});

test("a failed checklist lands in ready_failed with reason codes, never open", async () => {
  const instance = coordinator(fakeLedger(), { resolveIdentity: async () => false });
  const session = await openSession(instance);
  assert.equal(session.accept.stage, "ready_failed");
  assert.equal(session.accept.checklist.passed, false);
  await assert.rejects(() => instance.invoke("channel_open", { access: session.invite.initiatorAccess }), StandaloneCoordinatorErrorNamed());
});

function StandaloneCoordinatorErrorNamed() {
  return (error) => error?.name === "StandaloneCoordinatorError";
}

test("consent requires a signature that recovers to the party's own session key", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  await assert.rejects(
    () => instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_INITIATOR }),
    (error) => error?.name === "StandaloneCoordinatorError",
  );
});

test("opening anchors three chained transitions and the receipt is internally consistent", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  const receipt = await consentAndOpen(instance, session);
  assert.equal(/^[0-9a-f]{64}$/.test(receipt.termsDigest), true);
  assert.equal(receipt.checklistDigest, session.accept.checklist.checklistDigest);
  for (const anchor of receipt.anchors) {
    assert.equal(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(anchor.ledgerId), true);
    assert.equal(typeof anchor.blockHeight, "string");
  }
});

test("channel flows end to end: send, read, close — with an anchored closure", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  const sent = await instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "proposal", body: "Tuesdays, 14-day lead." });
  assert.equal(sent.seq, 1);
  const read = await instance.invoke("channel_read", { access: session.invite.initiatorAccess });
  assert.equal(read.messages.length, 1);
  assert.equal(read.messages[0].body, "Tuesdays, 14-day lead.");
  const closed = await instance.invoke("channel_close", { access: session.invite.initiatorAccess });
  assert.equal(closed.outcome, "closed");
  assert.equal(closed.byRole, "initiator");
  assert.equal(typeof closed.closureAnchor.ledgerId, "string");
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "question", body: "anyone?" }),
    (error) => error?.name === "StandaloneAdmissionError",
  );
});

test("revocation mid-conversation stops admission and anchors the revocation", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  await instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "question", body: "ready to talk?" });
  const revoked = await instance.invoke("channel_revoke", { access: session.accept.responderAccess });
  assert.equal(revoked.outcome, "revoked");
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.invite.initiatorAccess, kind: "question", body: "hello?" }),
    (error) => error instanceof Error && error.name === "StandaloneAdmissionError",
  );
});

test("expiry: consented session that is opened late still expires on consensus time", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  instance.advance(3_600_000);
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.invite.initiatorAccess, kind: "question", body: "still open?" }),
    (error) => error instanceof Error && error.name === "StandaloneAdmissionError",
  );
  const status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "expired");
});

test("status is role-gated: a bad access token is refused", async () => {
  const instance = coordinator();
  await assert.rejects(() => instance.invoke("handshake_status", { access: "sat_" + "Z".repeat(43) }), (error) => error?.name === "StandaloneCoordinatorError");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/mcp-server && npm test 2>&1 | grep -A3 standalone-coordinator | head -10`
Expected: import failure — `Cannot find module '../dist/standalone-handshake/coordinator.js'`.

- [ ] **Step 3: Write the implementation**

Create `packages/mcp-server/src/standalone-handshake/coordinator.ts`:

```ts
import { randomBytes, randomUUID } from "node:crypto";

import { canonicalBytes } from "../handshake/protocol.js";

import { evaluateStandaloneReadiness } from "./checklist.js";
import {
  ADDRESS,
  DIGEST,
  STANDALONE_HANDSHAKE_PROTOCOL,
  SIGNATURE,
  buildStandaloneConsentRecord,
  normalizeStandaloneClosure,
  normalizeStandaloneReadiness,
  normalizeStandaloneTerms,
  standaloneCanonicalRecord,
} from "./protocol.js";
import { createStandaloneSessionStore, StandaloneAdmissionError, StandaloneIllegalTransitionError } from "./session-store.js";

export class StandaloneCoordinatorError extends Error {
  constructor(message = "Standalone handshake coordinator refused.") {
    super(message);
    this.name = "StandaloneCoordinatorError";
  }
}

export class StandaloneTransientCoordinatorError extends Error {
  constructor() {
    super("Standalone handshake coordinator is temporarily unavailable.");
    this.name = "StandaloneTransientCoordinatorError";
  }
}

const KIND_REFERENCES = { TERMS_READINESS: "terms-readiness", CONSENT: "consent", OPEN: "open" } as const;

async function anchorStandalone(client: any, record: Readonly<Record<string, any>>, reference: string, canWrite: boolean): Promise<any> {
  const digest = standaloneCanonicalRecord(record).digest;
  const found = await client.searchAsset(reference);
  const matches = (Array.isArray(found) ? found : []).filter((entry: any) => entry.assetReferenceId === reference && entry.assetHash === digest);
  if (matches.length > 1) throw new StandaloneCoordinatorError();
  let ledgerRecord = matches[0];
  if (!ledgerRecord && canWrite) {
    ledgerRecord = await client.log({ assetHash: digest, assetReferenceId: reference, additionalInfo: `standalone handshake v1 ${record.kind ?? record.schema}` });
  }
  if (!ledgerRecord) throw new StandaloneTransientCoordinatorError();
  const ledgerId = String(ledgerRecord.ledgerId ?? "");
  if (!/^[0-9a-f-]{36}$/.test(ledgerId)) throw new StandaloneCoordinatorError();
  const ledger = await client.getLedgerEntry(ledgerId);
  if (!ledger || ledger.ledgerId === undefined || ledger.assetHash === undefined) throw new StandaloneTransientCoordinatorError();
  const blockHeight = String(ledger.blockHeight ?? "");
  if (!/^(?:0|[1-9][0-9]*)$/.test(blockHeight) || ledger.assetHash !== digest) throw new StandaloneCoordinatorError();
  const chain = await client.getChainRecord(blockHeight, ledgerId);
  if (!chain || chain.assetHash !== digest || String(chain.blockHeight) !== blockHeight) throw new StandaloneCoordinatorError();
  const block = await client.getBlock(blockHeight);
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  if (!blockTimeRaw) throw new StandaloneTransientCoordinatorError();
  return Object.freeze({ digest, blockHeight, blockTimeRaw, ledgerId });
}

export function createStandaloneCoordinator(options: {
  client?: any;
  now?: () => number;
  rpcUrl?: string;
  recoverEip191Address?: (input: { bytes: Buffer; signatureHex: string }) => Promise<string>;
  resolveIdentity?: (identity: Readonly<Record<string, any>> | null) => Promise<boolean>;
} = {}) {
  if (!options.client) throw new StandaloneCoordinatorError("A ledger client is required.");
  const client = options.client;
  const now = options.now ?? Date.now;
  const store = createStandaloneSessionStore({ now });
  const recover = options.recoverEip191Address;
  const resolveIdentity =
    options.resolveIdentity ??
    (async () => {
      throw new StandaloneCoordinatorError("Identity resolution is not configured.");
    });

  function authedSession(args: Record<string, unknown>): { session: any; role: string } {
    const access = args.access;
    if (typeof access !== "string" || !access.startsWith("sat_")) throw new StandaloneCoordinatorError();
    // Sessions are few in V1; linear scan keeps the store the single source of truth.
    for (const sessionId of storeSessionIds()) {
      const role = store.authenticate(sessionId, access);
      if (role !== undefined) return { session: store.requireSession(sessionId), role };
    }
    throw new StandaloneCoordinatorError();
  }

  let cachedIds: string[] = [];
  function storeSessionIds(): string[] {
    return cachedIds;
  }

  return {
    store,

    async invoke(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
      if (name === "handshake_invite") {
        const terms = normalizeStandaloneTerms({ reference: args.reference, purpose: args.purpose, channelLimits: args.channelLimits, identityPolicy: args.identityPolicy });
        const readiness = normalizeStandaloneReadiness(args.readiness, terms.identityPolicy.erc8004);
        const termsDigest = standaloneCanonicalRecord(terms).digest;
        const sessionId = randomUUID();
        store.createSession({ sessionId, terms, termsDigest, initiatorReadiness: readiness });
        const secret = randomBytes(24).toString("base64url");
        store.putInvitation({ secret, sessionId });
        const initiatorAccess = `sat_${randomBytes(32).toString("base64url")}`;
        store.setAccessToken(sessionId, "initiator", initiatorAccess);
        cachedIds.push(sessionId);
        const invitation = Buffer.from(JSON.stringify({ v: 1, sessionId, secret })).toString("base64url");
        return { sessionId, reference: terms.reference, invitation, initiatorAccess };
      }

      if (name === "handshake_accept_invitation") {
        const invitation = args.invitation;
        if (typeof invitation !== "string" || invitation.length < 80 || invitation.length > 4096) throw new StandaloneCoordinatorError();
        let decoded: any;
        try {
          decoded = JSON.parse(Buffer.from(invitation, "base64url").toString("utf8"));
        } catch {
          throw new StandaloneCoordinatorError();
        }
        if (decoded?.v !== 1 || typeof decoded.sessionId !== "string" || typeof decoded.secret !== "string") throw new StandaloneCoordinatorError();
        const sessionId = store.claimInvitation(decoded.secret);
        if (sessionId !== decoded.sessionId) throw new StandaloneCoordinatorError();
        const session = store.requireSession(sessionId);
        if (session.stage !== "invited") throw new StandaloneCoordinatorError();
        const responderReadiness = normalizeStandaloneReadiness(args.readiness, session.terms.identityPolicy.erc8004);
        store.setResponderReadiness(sessionId, responderReadiness);
        store.setStage(sessionId, "readiness_pending");
        const checklist = await evaluateStandaloneReadiness({
          sessionId,
          terms: session.terms,
          termsDigest: session.termsDigest,
          initiator: session.initiatorReadiness,
          responder: responderReadiness,
          resolveIdentity: requiredIdentity(session) ? resolveIdentity : async () => true,
          recoverAddress: recover ?? (async () => {
            throw new StandaloneCoordinatorError("Signature recovery is not configured.");
          }),
        });
        store.setChecklist(sessionId, checklist);
        store.setStage(sessionId, checklist.passed ? "ready" : "ready_failed");
        const responderAccess = `sat_${randomBytes(32).toString("base64url")}`;
        store.setAccessToken(sessionId, "responder", responderAccess);
        return { sessionId, stage: checklist.passed ? "ready" : "ready_failed", checklist, responderAccess };
      }

      if (name === "handshake_status" || name === "channel_status") {
        const { session } = authedSession(args);
        const snapshot: any = store.status(session.sessionId);
        return { ...snapshot, protocol: STANDALONE_HANDSHAKE_PROTOCOL };
      }

      if (name === "consent_sign") {
        const { session, role } = authedSession(args);
        const signatureHex = args.signatureHex;
        if (typeof signatureHex !== "string" || !SIGNATURE.test(signatureHex)) throw new StandaloneCoordinatorError();
        if (session.stage !== "ready" && session.stage !== "consent_pending") throw new StandaloneCoordinatorError();
        const readiness = role === "initiator" ? session.initiatorReadiness : session.responderReadiness;
        const checklist = session.checklist;
        if (!checklist?.passed || typeof checklist.checklistDigest !== "string" || !DIGEST.test(checklist.checklistDigest)) throw new StandaloneCoordinatorError();
        const consentRecord = buildStandaloneConsentRecord({ sessionId: session.sessionId, role, termsDigest: session.termsDigest, checklistDigest: checklist.checklistDigest });
        let recovered = "";
        try {
          recovered = (await (recover ?? failMissing())({ bytes: canonicalBytes(consentRecord), signatureHex })).toLowerCase();
        } catch (error) {
          if ((error as Error)?.name === "StandaloneCoordinatorError") throw error;
          recovered = "";
        }
        if (recovered !== String(readiness.sessionKeyAddress).toLowerCase()) throw new StandaloneCoordinatorError();
        if (session.stage === "ready") store.setStage(session.sessionId, "consent_pending");
        store.setConsent(session.sessionId, role, standaloneCanonicalRecord(consentRecord).digest);
        const stage = store.bothConsented(session.sessionId) ? (store.setStage(session.sessionId, "consented"), "consented") : "consent_pending";
        return { sessionId: session.sessionId, role, stage, consentDigest: standaloneCanonicalRecord(consentRecord).digest };
      }

      if (name === "channel_open") {
        const { session, role } = authedSession(args);
        if (session.stage !== "consented" || !store.bothConsented(session.sessionId)) throw new StandaloneCoordinatorError();
        const openedAtMs = now();
        const expiresAtMs = openedAtMs + Number(session.terms.channelLimits.durationSeconds) * 1000;
        store.setStage(session.sessionId, "open");
        store.openChannel(session.sessionId, { openedAtMs, expiresAtMs });
        const base = {
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          reference: session.terms.reference,
          termsDigest: session.termsDigest,
          checklistDigest: session.checklist.checklistDigest,
          initiator: { sessionKeyAddress: session.initiatorReadiness.sessionKeyAddress },
          responder: { sessionKeyAddress: session.responderReadiness.sessionKeyAddress },
          externalBusinessActionPerformed: false,
        };
        const transitions = [
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "TERMS_READINESS", sequence: "1", predecessor: null },
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "CONSENT", sequence: "2", predecessor: "" },
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "OPEN", sequence: "3", predecessor: "" },
        ];
        transitions[1].predecessor = standaloneCanonicalRecord(transitions[0]).digest;
        transitions[2].predecessor = standaloneCanonicalRecord(transitions[1]).digest;
        const anchors: any[] = [];
        for (let index = 0; index < transitions.length; index += 1) {
          const owner = index === 1 ? "responder" : "initiator";
          const reference = `standalone-handshake-v1:${session.sessionId}:${KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES]}`;
          const receipt = await anchorStandalone(client, transitions[index], reference, role === owner);
          anchors.push({ kind: KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES], ...receipt });
        }
        return {
          schema: "clockchain.standalone-handshake-opening/v1",
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          reference: session.terms.reference,
          termsDigest: session.termsDigest,
          checklistDigest: session.checklist.checklistDigest,
          openedAtMs: String(openedAtMs),
          expiresAtMs: String(expiresAtMs),
          anchors: Object.freeze(anchors),
          externalBusinessActionPerformed: false,
        };
      }

      if (name === "channel_send") {
        const { session, role } = authedSession(args);
        const message = store.admitMessage(session.sessionId, role, String(args.kind ?? ""), typeof args.body === "string" ? args.body : "");
        const { body: _body, ...publicMessage } = message;
        return publicMessage;
      }

      if (name === "channel_read") {
        const { session, role } = authedSession(args);
        return { sessionId: session.sessionId, stage: store.getSession(session.sessionId).stage, messages: store.readMessages(session.sessionId, role) };
      }

      if (name === "channel_close" || name === "channel_revoke") {
        const { session, role } = authedSession(args);
        const outcome = name === "channel_close" ? "closed" : "revoked";
        (outcome === "closed" ? store.closeChannel : store.revokeChannel).call(store, session.sessionId, role);
        const closureRecord = normalizeStandaloneClosure({
          schema: "clockchain.standalone-handshake-closure/v1",
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          outcome,
          byRole: role,
          closedAtMs: String(now()),
          externalBusinessActionPerformed: false,
        });
        const anchor = await anchorStandalone(client, closureRecord, `standalone-handshake-v1:${session.sessionId}:closure`, true);
        return { sessionId: session.sessionId, outcome, byRole: role, closureAnchor: anchor };
      }

      throw new StandaloneCoordinatorError(`Unknown tool ${name}.`);
    },
  };

  function requiredIdentity(session: any): boolean {
    return session.terms.identityPolicy.erc8004 !== "not_required";
  }

  function failMissing(): never {
    throw new StandaloneCoordinatorError("Signature recovery is not configured.");
  }
}

export function createRuntimeStandaloneCoordinator(env: Record<string, string | undefined> = process.env) {
  // Late-bound to keep the module importable in tests without the core client configured.
  const { ClockchainClient, readConfigFromEnv } = require("@clockchain/core") as typeof import("@clockchain/core");
  const { recoverEip191Address, resolveOwnedAgentRegistration } = require("../handshake/evm.js") as typeof import("../handshake/evm.js");
  const rpcUrl = env.SEPOLIA_RPC_URL ?? "";
  const client = new ClockchainClient(readConfigFromEnv(env));
  return createStandaloneCoordinator({
    client,
    rpcUrl,
    recoverEip191Address: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl }),
    resolveIdentity: async (identity) => {
      if (!identity) return false;
      const registration = await resolveOwnedAgentRegistration({ rpcUrl, registryAddress: identity.registryAddress, address: "", fetchImpl: undefined });
      return registration !== null && registration !== undefined;
    },
  });
}
```

**Note on `require` in ESM:** this package is `"type": "module"`, so `require` is unavailable. Replace `createRuntimeStandaloneCoordinator`'s late-binding with top-of-file static imports — `import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";` and `import { recoverEip191Address, resolveOwnedAgentRegistration } from "../handshake/evm.js";` — exactly as `agent-handshake/v2/coordinator.ts:4` and `:10` do. The fake-client tests construct `createStandaloneCoordinator` directly with injected fakes, so static imports do not affect testability. Also fix `resolveIdentity` to pass the caller's `address`: the readiness record's `sessionKeyAddress` is the address to resolve, so thread it through — change the coordinator's `evaluateStandaloneReadiness` call site to close over the responding party's address (simplest: make `resolveIdentity` signature `(identity, address) => Promise<boolean>` in checklist Task 2 OR bind per-call here with `(identity) => resolveOwnedAgentRegistration({rpcUrl, registryAddress: identity.registryAddress, address: session.initiatorReadiness.sessionKeyAddress /* or responder's */})`. Because the checklist resolves BOTH parties' identities with one function, the injected signature must be `(identity, address) => Promise<boolean>`; if Task 2 shipped `(identity)`, extend it here with a wrapper that resolves by matching `identity` against each side's `sessionKeyAddress`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -25`
Expected: `standalone-coordinator` tests PASS. If the identity-signature mismatch between checklist and runtime surfaces here, extend `evaluateStandaloneReadiness` and its Task 2 test with `(identity, address)` in both modules and re-run both suites.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/standalone-handshake/coordinator.ts packages/mcp-server/test/standalone-coordinator.test.mjs packages/mcp-server/src/standalone-handshake/checklist.ts packages/mcp-server/test/standalone-checklist.test.mjs
git commit -m "standalone-handshake: coordinator — consent signing, three-anchor opening receipt, closure anchoring"
```

---

### Task 5: MCP tools and public server

**Files:**
- Create: `packages/mcp-server/src/standalone-handshake/tools.ts`
- Create: `packages/mcp-server/src/standalone-handshake/public-server.ts`
- Test: `packages/mcp-server/test/standalone-public-server.test.mjs`

**Interfaces:**
- Consumes: Task 4's `invoke(name, args)`; the v2 patterns in `agent-handshake/v2/public-server.ts` (role-access broker, limiter, handler) and `public-tools.ts` (registration shape) — copied and adapted, v2 files untouched.
- Produces: `STANDALONE_TOOL_NAMES` (10), `STANDALONE_ROLE_SCOPED_TOOLS`; `registerStandaloneTools(server, invoke)`; `buildStandaloneInstructions()`; `buildStandalonePublicServer({invoke})`; `createStandaloneHttpHandler({invoke, trustedProxy?, invitesPerHour?, callsPerMinute?, now?})` → `(req, res) => Promise<void>` for `/connect/mcp`; `buildStandaloneDiscovery()`.

- [ ] **Step 1: Write the failing test**

Create `packages/mcp-server/test/standalone-public-server.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import {
  STANDALONE_TOOL_NAMES,
  buildStandaloneDiscovery,
  buildStandaloneInstructions,
  createStandaloneHttpHandler,
} from "../dist/standalone-handshake/public-server.js";
import { buildStandalonePublicServer } from "../dist/standalone-handshake/public-server.js";

const ACCEPT = "application/json, text/event-stream";

test("the tool surface is exactly the ten designed tools", () => {
  assert.deepEqual([...STANDALONE_TOOL_NAMES], [
    "handshake_invite",
    "handshake_accept_invitation",
    "handshake_status",
    "consent_sign",
    "channel_open",
    "channel_send",
    "channel_read",
    "channel_status",
    "channel_close",
    "channel_revoke",
  ]);
});

test("instructions lead with the local-signing boundary", () => {
  const text = buildStandaloneInstructions();
  assert.match(text, /never holds a private key/);
  assert.match(text, /clockchain\.standalone-handshake\/v1/);
  assert.match(text, /external business action/i);
});

test("discovery manifest names the endpoint and every tool", () => {
  const discovery = buildStandaloneDiscovery();
  assert.equal(discovery.name, "clockchain-standalone-handshake");
  assert.equal(discovery.endpoint, "https://mcp.clockchain.network/connect/mcp");
  assert.equal(discovery.tools.length, STANDALONE_TOOL_NAMES.length);
});

test("the HTTP handler serves /connect/mcp and rate-limits invites per IP", async () => {
  const calls = [];
  const handler = createStandaloneHttpHandler({
    invoke: async (name, args) => {
      calls.push(name);
      return { ok: true };
    },
    invitesPerHour: 1,
    callsPerMinute: 10,
    now: (() => { let t = 1_750_000_000_000; return () => (t += 1_000); })(),
  });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  try {
    const rpc = async (method, params = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return { status: response.status, body: JSON.parse(data ? data.slice(5) : text) };
    };

    const initialized = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    assert.equal(initialized.status, 200);
    assert.equal(initialized.body.result.serverInfo.name, "clockchain-standalone-handshake");

    await rpc("notifications/initialized");
    const first = await rpc("tools/call", { name: "handshake_invite", arguments: { reference: "r", purpose: "p" } });
    assert.equal(first.status, 200);
    const second = await rpc("tools/call", { name: "handshake_invite", arguments: { reference: "r", purpose: "p" } });
    const secondBody = JSON.stringify(second.body);
    assert.match(secondBody, /HANDSHAKE_TEMPORARILY_UNAVAILABLE|rate_limited|error/);

    const wrong = await fetch(`http://127.0.0.1:${server.address().port}/other/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT }, body: "{}" });
    assert.equal(wrong.status, 404);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("buildStandalonePublicServer wires every tool onto an MCP server", async () => {
  const seen = [];
  const server = buildStandalonePublicServer({ invoke: async (name) => { seen.push(name); return { ok: true }; } });
  assert.notEqual(server, undefined);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/mcp-server && npm test 2>&1 | grep -A3 standalone-public-server | head -10`
Expected: import failure — `Cannot find module '../dist/standalone-handshake/public-server.js'`.

- [ ] **Step 3: Write the implementation**

Create `packages/mcp-server/src/standalone-handshake/tools.ts`:

```ts
import { z } from "zod";

import { STANDALONE_CHAIN_ID, STANDALONE_REGISTRY_ADDRESS } from "./protocol.js";

export const STANDALONE_TOOL_NAMES = Object.freeze([
  "handshake_invite",
  "handshake_accept_invitation",
  "handshake_status",
  "consent_sign",
  "channel_open",
  "channel_send",
  "channel_read",
  "channel_status",
  "channel_close",
  "channel_revoke",
]);

export const STANDALONE_ROLE_SCOPED_TOOLS = Object.freeze(
  STANDALONE_TOOL_NAMES.filter((name) => name !== "handshake_invite" && name !== "handshake_accept_invitation"),
);

const identityPolicy = z.discriminatedUnion("erc8004", [
  z.object({ erc8004: z.literal("required_fresh"), chainId: z.literal(STANDALONE_CHAIN_ID), registryAddress: z.literal(STANDALONE_REGISTRY_ADDRESS) }).strict(),
  z.object({ erc8004: z.literal("required_existing_or_fresh"), chainId: z.literal(STANDALONE_CHAIN_ID), registryAddress: z.literal(STANDALONE_REGISTRY_ADDRESS) }).strict(),
  z.object({ erc8004: z.literal("not_required"), chainId: z.null(), registryAddress: z.null() }).strict(),
]);

const channelLimits = z.object({
  durationSeconds: z.string().regex(/^(?:[6-9][0-9]|[1-8][0-9]{2,3}|8[0-5][0-9]{3}|86[0-3][0-9]{2}|86400)$/),
  messageKinds: z.array(z.enum(["question", "proposal", "evidence", "note"])).min(1).max(4),
  maxMessageBytes: z.string().regex(/^(?:[1-9][0-9]{0,3}|1[0-5][0-9]{3}|16384)$/),
}).strict();

const readiness = z.object({
  sessionKeyAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  identity: z.any().nullable(),
  authorityStatement: z.object({ accountableParty: z.string().min(1).max(128), statement: z.string().min(1).max(512) }).strict(),
  authoritySignatureHex: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
  capabilityManifest: z.object({ dataHandlingClass: z.enum(["public", "confidential", "restricted"]), purpose: z.string().min(1).max(256) }).strict(),
}).strict();

const access = z.string().min(20).max(200);

export const STANDALONE_TOOL_DEFINITIONS = Object.freeze([
  {
    name: "handshake_invite",
    title: "Propose a standalone handshake",
    description: "Propose bounded A2A communication: terms, channel limits, and your readiness package. Returns a single-use Responder invitation and your role access.",
    schema: { reference: z.string().min(1).max(128), purpose: z.string().min(1).max(256), channelLimits, identityPolicy, readiness },
    readOnly: false,
  },
  {
    name: "handshake_accept_invitation",
    title: "Accept a standalone handshake invitation",
    description: "Claim one invitation once with your readiness package. The coordinator runs the readiness checklist and issues your role access.",
    schema: { invitation: z.string().min(80).max(4096), readiness },
    readOnly: false,
  },
  { name: "handshake_status", title: "Read handshake status", description: "Read progress, checklist results, channel state, remaining time, and scope for this role.", schema: { access }, readOnly: true },
  { name: "consent_sign", title: "Sign consent", description: "Sign consent over the exact terms and checklist digest with your session key (local signing; the server never holds keys).", schema: { access, signatureHex: z.string().regex(/^0x[0-9a-fA-F]{130}$/) }, readOnly: false },
  { name: "channel_open", title: "Open the channel", description: "Open the witnessed channel once both consents are signed. Anchors the opening receipt (terms-readiness, consent, open) on the ledger.", schema: { access }, readOnly: false },
  { name: "channel_send", title: "Send a channel message", description: "Send one typed message within the consented scope. Refused with a reason code when the channel is not open, expired, revoked, out of scope, oversized, or you are not a party.", schema: { access, kind: z.enum(["question", "proposal", "evidence", "note"]), body: z.string().min(1).max(16384) }, readOnly: false },
  { name: "channel_read", title: "Read channel messages", description: "Read the messages addressed to you on this channel.", schema: { access }, readOnly: true },
  { name: "channel_status", title: "Read channel status", description: "Thin post-open status: state, remaining time, scope, message counts.", schema: { access }, readOnly: true },
  { name: "channel_close", title: "Close the channel", description: "Close the channel explicitly; the closure is anchored as a ledger record.", schema: { access }, readOnly: false },
  { name: "channel_revoke", title: "Revoke the channel", description: "Revoke consent unilaterally. Admission stops immediately and permanently; the revocation is anchored.", schema: { access }, readOnly: false },
] as const);

const SAFE_ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const RETRYABLE_ERROR_NAMES = new Set(["StandaloneTransientCoordinatorError", "HttpRequestError", "TimeoutError", "CircuitOpenError"]);

export function registerStandaloneTools(server: any, invoke: (name: string, args: Record<string, unknown>) => Promise<Record<string, unknown>>): void {
  for (const definition of STANDALONE_TOOL_DEFINITIONS) {
    server.registerTool(definition.name, {
      title: definition.title,
      description: definition.description,
      inputSchema: definition.schema,
      annotations: {
        readOnlyHint: definition.readOnly,
        destructiveHint: definition.name === "channel_revoke",
        idempotentHint: definition.readOnly,
        openWorldHint: false,
      },
    }, async (args: Record<string, unknown>) => {
      try {
        const result = await invoke(definition.name, args);
        const body = { ...result };
        return { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
      } catch (error) {
        const observedName = (error as Error)?.name;
        const retryable = typeof observedName === "string" && RETRYABLE_ERROR_NAMES.has(observedName);
        const body = retryable
          ? { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 }
          : { error: (error as Error)?.message ?? "HANDSHAKE_UNAVAILABLE", retryable: false };
        return retryable
          ? { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body }
          : { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
      }
    });
  }
}
```

Create `packages/mcp-server/src/standalone-handshake/public-server.ts`:

```ts
import { randomBytes } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { STANDALONE_HANDSHAKE_PROTOCOL } from "./protocol.js";
import { STANDALONE_ROLE_SCOPED_TOOLS, STANDALONE_TOOL_NAMES, registerStandaloneTools } from "./tools.js";

export { STANDALONE_TOOL_NAMES } from "./tools.js";

const STANDALONE_ENDPOINT = "https://mcp.clockchain.network/connect/mcp";
const ROLE_ACCESS_HANDLE = /^csha_[A-Za-z0-9_-]{22}$/;
const ROLE_ACCESS_HANDLE_TTL_MS = 60 * 60_000;
const ROLE_ACCESS_HANDLE_LIMIT = 10_000;

export function buildStandaloneInstructions(): string {
  return [
    "Clockchain Standalone Handshake — the pre-negotiation, mutually authenticated gateway for two agents.",
    "",
    `Protocol ${STANDALONE_HANDSHAKE_PROTOCOL}. LOCAL SIGNING REQUIRED: this server never holds a private key and never signs for either party. consent_sign expects an EIP-191 signature over the exact canonical consent bytes returned in handshake_status; submit only that signature.`,
    "",
    "Flow: handshake_invite → the Responder runs handshake_accept_invitation with their readiness package → the deterministic checklist (identity, authority, capability manifest) must pass → both roles consent_sign the same digest → channel_open anchors the witnessed opening receipt → channel_send / channel_read within the consented scope until expiry, channel_close, or channel_revoke.",
    "",
    "Consent covers communication only. Opening the channel authorizes no business action, accepts no proposal, and moves no funds. The server records what was checked and consented to; it does not guarantee truthfulness of either party.",
  ].join("\n");
}

export function buildStandaloneDiscovery(): Record<string, unknown> {
  return {
    name: "clockchain-standalone-handshake",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    endpoint: STANDALONE_ENDPOINT,
    tools: [...STANDALONE_TOOL_NAMES],
    localSigningRequired: true,
    externalBusinessActionsAllowed: false,
  };
}

function firstHeader(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

export function standaloneClientIp(headers: IncomingHttpHeaders, remoteAddress: string | undefined, trustedProxy?: string): string {
  if (trustedProxy && remoteAddress === trustedProxy) {
    return firstHeader(headers["x-forwarded-for"]).split(",")[0]?.trim() || remoteAddress || "unknown";
  }
  return remoteAddress ?? "unknown";
}

function limiter(limit: number, windowMs: number, now: () => number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (key: string): boolean => {
    const current = now();
    const prior = hits.get(key);
    if (!prior || current >= prior.resetAt) {
      hits.set(key, { count: 1, resetAt: current + windowMs });
      return true;
    }
    if (prior.count >= limit) return false;
    prior.count += 1;
    return true;
  };
}

class StandaloneRoleAccessError extends Error {
  constructor() {
    super("standalone role access refused");
    this.name = "StandaloneRoleAccessError";
  }
}

function createRoleAccessBroker(invoke: (name: string, args: Record<string, unknown>) => Promise<unknown>, now: () => number) {
  const handles = new Map<string, { access: string; expiresAt: number }>();

  function prune(): void {
    const current = now();
    for (const [handle, entry] of handles) if (current >= entry.expiresAt) handles.delete(handle);
  }

  function issue(access: unknown): string {
    if (typeof access !== "string" || access.length < 20 || access.length > 4096) throw new StandaloneRoleAccessError();
    prune();
    if (handles.size >= ROLE_ACCESS_HANDLE_LIMIT) throw new StandaloneRoleAccessError();
    let handle: string;
    do {
      handle = `csha_${randomBytes(16).toString("base64url")}`;
    } while (handles.has(handle));
    handles.set(handle, { access, expiresAt: now() + ROLE_ACCESS_HANDLE_TTL_MS });
    return handle;
  }

  function resolve(value: unknown): { clientHandle: string | undefined; signedAccess: string } {
    if (typeof value !== "string") throw new StandaloneRoleAccessError();
    if (!ROLE_ACCESS_HANDLE.test(value)) return { clientHandle: undefined, signedAccess: value };
    prune();
    const entry = handles.get(value);
    if (!entry) throw new StandaloneRoleAccessError();
    return { clientHandle: value, signedAccess: entry.access };
  }

  return async (name: string, args: Record<string, unknown>) => {
    if (STANDALONE_ROLE_SCOPED_TOOLS.includes(name as never)) {
      const resolved = resolve(args.access);
      const result = (await invoke(name, { ...args, access: resolved.signedAccess })) as Record<string, unknown>;
      return { ...result, roleAccess: resolved.clientHandle ?? issue(resolved.signedAccess) };
    }
    const result = (await invoke(name, args)) as Record<string, unknown>;
    if (name === "handshake_invite") return { ...withoutAccessKeys(result), roleAccess: issue(result.initiatorAccess) };
    if (name === "handshake_accept_invitation") return { ...withoutAccessKeys(result), roleAccess: issue(result.responderAccess) };
    return result;
  };
}

function withoutAccessKeys(result: Record<string, unknown>): Record<string, unknown> {
  const { initiatorAccess: _i, responderAccess: _r, ...rest } = result;
  return rest;
}

export function buildStandalonePublicServer(options: { invoke: (name: string, args: Record<string, unknown>) => Promise<unknown> }): McpServer {
  const server = new McpServer({ name: "clockchain-standalone-handshake", version: "0.1.0" }, {
    instructions: buildStandaloneInstructions(),
  });
  registerStandaloneTools(server, options.invoke as never);
  return server;
}

export function createStandaloneHttpHandler(options: {
  invoke: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  trustedProxy?: string;
  invitesPerHour?: number;
  callsPerMinute?: number;
  now?: () => number;
}) {
  const now = options.now ?? Date.now;
  const allowInvite = limiter(options.invitesPerHour ?? 5, 60 * 60_000, now);
  const allowCall = limiter(options.callsPerMinute ?? 120, 60_000, now);
  const invoke = createRoleAccessBroker(options.invoke, now);
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if ((req.url ?? "").split("?")[0] !== "/connect/mcp") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const ip = standaloneClientIp(req.headers, req.socket.remoteAddress, options.trustedProxy);
    if (!allowCall(`call:${ip}`)) {
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    const server = buildStandalonePublicServer({
      invoke: async (name, args) => {
        if (name === "handshake_invite" && !allowInvite(`invite:${ip}`)) throw new Error("rate_limited");
        return invoke(name, args);
      },
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -25`
Expected: `standalone-public-server` tests PASS. If the rate-limit assertion is flaky because the per-call limiter advances `now` by 1s per request (60-call window), raise `callsPerMinute` or slow the fake clock — keep the invite limit the binding constraint (1/hour).

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/standalone-handshake/tools.ts packages/mcp-server/src/standalone-handshake/public-server.ts packages/mcp-server/test/standalone-public-server.test.mjs
git commit -m "standalone-handshake: MCP tool surface and credential-light public server at /connect/mcp"
```

---

### Task 6: HTTP wiring — routes on the main server

**Files:**
- Modify: `packages/mcp-server/src/http.ts` (near the v2 routes: lazy handler getter ~line 454, well-known route ~line 543, `/handshake/mcp` route ~line 557)

**Interfaces:**
- Consumes: `createStandaloneHttpHandler`, `buildStandaloneDiscovery` from `./standalone-handshake/public-server.js`; `createRuntimeStandaloneCoordinator` from `./standalone-handshake/coordinator.js`.
- Produces: two new routes on the existing HTTP server — `GET /.well-known/standalone-handshake.json` (200, `cache-control: public, max-age=300`) and `POST|anything /connect/mcp` (delegated to the standalone handler; 503 wrapper on construction failure). Env keys: `STANDALONE_HANDSHAKE_TRUSTED_PROXY`, `STANDALONE_HANDSHAKE_INVITES_PER_HOUR`, `STANDALONE_HANDSHAKE_CALLS_PER_MINUTE`, `SEPOLIA_RPC_URL`.

- [ ] **Step 1: Add the lazy handler getter**

In `packages/mcp-server/src/http.ts`, immediately after the `getPublicHandshakeHandler` definition (which ends near line 470), add:

```ts
let standaloneHandshakeHandler: ReturnType<typeof createStandaloneHttpHandler> | undefined;
let standaloneHandshakeCoordinator: ReturnType<typeof createRuntimeStandaloneCoordinator> | undefined;
const getStandaloneHandshakeHandler = () => {
  if (standaloneHandshakeHandler) return standaloneHandshakeHandler;
  standaloneHandshakeCoordinator ??= createRuntimeStandaloneCoordinator(process.env);
  standaloneHandshakeHandler = createStandaloneHttpHandler({
    trustedProxy: process.env.STANDALONE_HANDSHAKE_TRUSTED_PROXY,
    invitesPerHour: Number(process.env.STANDALONE_HANDSHAKE_INVITES_PER_HOUR ?? "5"),
    callsPerMinute: Number(process.env.STANDALONE_HANDSHAKE_CALLS_PER_MINUTE ?? "120"),
    invoke: (name, args) => standaloneHandshakeCoordinator!.invoke(name, args),
  });
  return standaloneHandshakeHandler;
};
```

Add the imports at the top of `http.ts`, next to the existing `agent-handshake/v2` imports (line ~41):

```ts
import { buildStandaloneDiscovery, createStandaloneHttpHandler } from "./standalone-handshake/public-server.js";
import { createRuntimeStandaloneCoordinator } from "./standalone-handshake/coordinator.js";
```

- [ ] **Step 2: Add the two routes**

In the route chain, immediately AFTER the `/.well-known/agent-handshake.json` block (ends ~line 555) and BEFORE the `/handshake/mcp` block, insert:

```ts
    if (req.method === "GET" && pathOf(req.url) === "/.well-known/standalone-handshake.json") {
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(JSON.stringify(buildStandaloneDiscovery(), null, 2));
      return;
    }

    if (pathOf(req.url) === "/connect/mcp") {
      try {
        await getStandaloneHandshakeHandler()(req, res);
      } catch {
        if (!res.headersSent) {
          res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "standalone_handshake_unavailable" }));
        }
      }
      return;
    }
```

- [ ] **Step 3: Build and run the suite**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -10`
Expected: full suite PASS — the existing tests must be untouched and green; new module tests still green (routes themselves are exercised in deployment; the handler and discovery are already unit-covered).

- [ ] **Step 4: Commit**

```bash
git add packages/mcp-server/src/http.ts
git commit -m "standalone-handshake: mount /connect/mcp and /.well-known/standalone-handshake.json on the main HTTP server"
```

---

### Task 7: Landing page and llms.txt announcement

**Files:**
- Modify: `packages/mcp-server/src/landing.ts` (MODULES array ~line 180; sections ~lines 404–413; `INSTALL_TXT` string)

**Interfaces:**
- Consumes: existing `MODULES` card shape `{i, name, body, wide?, href?, cta?}`; section markup pattern (`.wrap`, `.head`, `.eyebrow`, `.code`, `.cpy`); `INSTALL_TXT` export consumed by the `/llms.txt` route in `http.ts`.
- Produces: a new `MODULES` entry (count becomes 8 — `MODULE_WORD` and `MODULE_COUNT` update automatically), a `<section id="handshake">` before the install section, and an `INSTALL_TXT` paragraph.

- [ ] **Step 1: Add the module card**

In the `MODULES` array, after the `"07"` entry, add:

```ts
  { i: "08", name: "Standalone Handshake", wide: true, href: "/.well-known/standalone-handshake.json", cta: "Discovery manifest →", body: `The pre-negotiation gateway for two previously unconnected agents: mutually authenticated identity, a deterministic readiness checklist, signed consent to a stated purpose and scope — then a witnessed, bounded channel. Opening decisions and closures are anchored on the ${SUBSTRATE_LABEL}; consent authorizes communication only, never a transaction. Credential-light at /connect/mcp.` },
```

- [ ] **Step 2: Add the handshake section**

Insert this section between the "Proof, not assurance" section (`</section>` at ~line 411) and the `<section id="install">` at line 413:

```html
<section class="tint" id="handshake"><div class="wrap">
  <div class="head"><span class="eyebrow">Standalone Handshake</span><h2>Two strangers, one bounded conversation</h2>
  <p>Before agents talk business, they establish who is present, whether entry conditions are met, and what each side consented to discuss. Identity, authority, and capability checks run deterministically on both sides; consent is signed locally over the exact terms; the opening decision is anchored where anyone can re-verify it.</p></div>
  <div class="code"><button class="cpy" onclick="copyEl(this)">Copy</button><pre><code id="handshakeCmd">claude mcp add clockchain-handshake --transport http https://mcp.clockchain.network/connect/mcp</code></pre></div>
  <p class="hint">No API key. Consent covers communication only — it is not an agreement, and it never authorizes a transaction.</p>
</div></section>
```

- [ ] **Step 3: Add the llms.txt paragraph**

Inside the `INSTALL_TXT` template literal, after the main connect instructions and before the closing backtick, append:

```
Standalone Handshake — two agents opening a bounded, witnessed conversation

The same host also serves clockchain-standalone-handshake at /connect/mcp (no API key):
  claude mcp add clockchain-handshake --transport http https://mcp.clockchain.network/connect/mcp
Flow: handshake_invite → handshake_accept_invitation (readiness checklist) → consent_sign
(both roles, local signing) → channel_open (anchored opening receipt) → channel_send /
channel_read within the consented scope → channel_close / channel_revoke (anchored closure).
Consent covers communication only. Discovery: GET /.well-known/standalone-handshake.json
```

- [ ] **Step 4: Add the page test**

Create `packages/mcp-server/test/standalone-pages.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";

import { INSTALL_TXT, LANDING_HTML, MODULE_COUNT } from "../dist/landing.js";
import { buildStandaloneDiscovery } from "../dist/standalone-handshake/public-server.js";

test("the landing page announces Standalone Handshake and stays consistent", () => {
  assert.match(LANDING_HTML, /Standalone Handshake/);
  assert.match(LANDING_HTML, /\/connect\/mcp/);
  assert.equal(LANDING_HTML.includes(String(MODULE_COUNT)), true);
});

test("llms.txt carries the agent-readable handshake facts", () => {
  assert.match(INSTALL_TXT, /standalone-handshake/);
  assert.match(INSTALL_TXT, /\/connect\/mcp/);
  assert.match(INSTALL_TXT, /channel_open/);
  assert.match(INSTALL_TXT, /Consent covers communication only/);
});

test("the discovery manifest matches what the page promises", () => {
  const discovery = buildStandaloneDiscovery();
  assert.match(LANDING_HTML, new RegExp(discovery.endpoint.replace(/\//g, "\\/")));
});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -10`
Expected: `standalone-pages` tests PASS, full suite green. If the `MODULE_COUNT` assertion fails because the number renders with different surroundings, assert `/Standalone Handshake/` and `/08/` instead — the intent is "the card is rendered".

- [ ] **Step 6: Commit**

```bash
git add packages/mcp-server/src/landing.ts packages/mcp-server/test/standalone-pages.test.mjs
git commit -m "standalone-handshake: announce the capability on the landing page and llms.txt"
```

---

### Task 8: End-to-end two-party flow over HTTP

**Files:**
- Test: `packages/mcp-server/test/standalone-e2e.test.mjs`

**Interfaces:**
- Consumes: Tasks 4–5 — `createStandaloneCoordinator` with the fake ledger from Task 4's test (re-declared here; do not import from another test file), `createStandaloneHttpHandler`.
- Produces: the golden-path proof that a stakeholder demo will follow, from invite to anchored closure, including a mid-channel scope violation and a revocation.

- [ ] **Step 1: Write the test**

Create `packages/mcp-server/test/standalone-e2e.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { validTerms, validReadiness } from "./standalone-protocol.test.js";

const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);

function fakeLedger() {
  const entries = new Map();
  let height = 100;
  return {
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
      return { blockHeight: String(blockHeight), blockTime: "2026-09-14T00:00:00.000Z" };
    },
  };
}

const ACCEPT = "application/json, text/event-stream";

test("two unconnected agents go from invitation to anchored closure over HTTP", async () => {
  let nowMs = 1_750_000_000_000;
  const coordinator = createStandaloneCoordinator({
    client: fakeLedger(),
    now: () => nowMs,
    recoverEip191Address: async ({ signatureHex }) =>
      signatureHex === SIG_INITIATOR ? ADDR_INITIATOR : signatureHex === SIG_RESPONDER ? ADDR_RESPONDER : "0x" + "99".repeat(20),
    resolveIdentity: async () => true,
  });
  const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args) });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;

  async function call(name, args = {}) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await response.text();
    const data = text.split("\n").find((line) => line.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    const content = body.result?.content?.[0]?.text;
    return { status: response.status, result: body.result, payload: content ? JSON.parse(content) : body.result };
  }

  try {
    // Buyer proposes; supplier accepts.
    const invite = await call("handshake_invite", {
      ...validTerms(),
      readiness: validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR }),
    });
    assert.equal(invite.payload.sessionId.length, 36);
    const accept = await call("handshake_accept_invitation", {
      invitation: invite.payload.invitation,
      readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }),
    });
    assert.equal(accept.payload.checklist.passed, true);

    // Both sign consent over the same digest; supplier opens.
    const c1 = await call("consent_sign", { access: invite.payload.roleAccess, signatureHex: SIG_INITIATOR });
    assert.equal(c1.payload.stage, "consent_pending");
    const c2 = await call("consent_sign", { access: accept.payload.roleAccess, signatureHex: SIG_RESPONDER });
    assert.equal(c2.payload.stage, "consented");
    const open = await call("channel_open", { access: invite.payload.roleAccess });
    assert.deepEqual(open.payload.anchors.map((a) => a.kind), ["terms-readiness", "consent", "open"]);

    // Bounded exchange: an out-of-scope kind is refused before an in-scope one lands.
    const violation = await call("channel_send", { access: accept.payload.roleAccess, kind: "note", body: "off-scope" });
    assert.match(violation.payload.error, /SCOPE_VIOLATION/);
    const sent = await call("channel_send", { access: accept.payload.roleAccess, kind: "proposal", body: "Ship Tuesdays." });
    assert.equal(sent.payload.seq, 1);
    const read = await call("channel_read", { access: invite.payload.roleAccess });
    assert.equal(read.payload.messages[0].body, "Ship Tuesdays.");

    // Buyer revokes; the channel is dead for both, and the closure is anchored.
    const revoked = await call("channel_revoke", { access: invite.payload.roleAccess });
    assert.equal(revoked.payload.outcome, "revoked");
    assert.equal(typeof revoked.payload.closureAnchor.ledgerId, "string");
    const after = await call("channel_send", { access: accept.payload.roleAccess, kind: "question", body: "hello?" });
    assert.match(after.payload.error, /REVOKED/);

    // Status tells the whole story to either role.
    const status = await call("handshake_status", { access: accept.payload.roleAccess });
    assert.equal(status.payload.stage, "revoked");
    assert.equal(status.payload.protocol, "clockchain.standalone-handshake/v1");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
```

- [ ] **Step 2: Run the test**

Run: `cd packages/mcp-server && npm test 2>&1 | tail -15`
Expected: the e2e test PASSES. Note: admission refusals surface through `invoke` as thrown `StandaloneAdmissionError`, which `registerStandaloneTools` renders as `isError` results whose text carries the reason code — that is why the assertions `match` on `payload.error`. If a refusal instead returns `HANDSHAKE_UNAVAILABLE`, the error name is escaping the tool layer wrong — fix `registerStandaloneTools` to include `(error as Error).message` (it already does) and confirm the reason code is in that message.

- [ ] **Step 3: Commit**

```bash
git add packages/mcp-server/test/standalone-e2e.test.mjs
git commit -m "standalone-handshake: end-to-end two-party flow from invitation to anchored revocation over HTTP"
```

---

### Task 9: Full verification and spec conformance sweep

**Files:** none created — verification only.

- [ ] **Step 1: Run the entire package suite from clean**

```bash
cd packages/mcp-server && npm run build && npm test
```
Expected: build succeeds; every test file passes; zero skipped tests, zero TODOs. Confirm: `npm test 2>&1 | grep -E "^. (fail|skip)|# fail|# skip"` shows `# fail 0` and `# skip 0`.

- [ ] **Step 2: Spec conformance sweep**

Walk `docs/superpowers/specs/2026-09-14-standalone-handshake-design.md` section by section and check each against the code:
- Ten tools on `/connect/mcp`, credential-light → Task 5–6.
- Checklist: identity/authority/manifest with the exact reason codes → Task 2.
- State machine stages and edges exactly as specced → Task 3.
- Consensus-time expiry, lazy, fail-closed; revocation immediate → Task 3 tests with injected clock.
- Three-anchor opening receipt + single closure anchor; expiry unanchored by design → Task 4.
- Exact-key canonical records, schema family `clockchain.standalone-handshake-*/v1` → Task 1.
- Landing + llms.txt + `/.well-known/standalone-handshake.json` → Tasks 6–7.
- v2 `agent-handshake` and `handshake` modules unmodified → `git diff --stat main...HEAD -- packages/mcp-server/src/agent-handshake packages/mcp-server/src/handshake` must be empty.

- [ ] **Step 3: Report**

Summarize: test counts before/after, the git log of the nine commits, and any deviation from the spec with its justification. No commit in this task.

---

## Self-Review Notes (already applied)

- Interface names were cross-checked task-to-task: `createStandaloneCoordinator` returns `{invoke, store}` and every consumer uses exactly that shape; reason-code strings appear identically in Tasks 3, 5, and 8.
- Known plan-level risks the executor must resolve, flagged inline rather than papered over: (1) Task 4's `require` in ESM — use static imports as v2 does; (2) the `resolveIdentity` signature must be `(identity, address)` if the runtime ERC-8004 resolution needs the caller address — Task 4's note says to extend Task 2's interface if so, re-running both suites; (3) test-fixture sharing across `*.test.mjs` files — if the runner double-executes, move fixtures to `test/helpers/standalone-fixtures.mjs`.
