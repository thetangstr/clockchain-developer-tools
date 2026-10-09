import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { gzipSync } from "node:zlib";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";

import { generateRelayKeyPair, canonicalBytes, digestHex, signRelayEnvelope, verifyRelayEnvelope } from "../../handshake/protocol.js";
import type { HandshakeKey, HandshakeRecord, HandshakeStateStore } from "../../handshake/state.js";
import { createHandshakeStateStore, createIsolatedHandshakeStateStore } from "../../handshake/state.js";
import { createHandshakeRelayClient, normalizeRelayBaseUrl } from "../../handshake/relay.js";
import { readEvmBalance, recoverEip191Address, resolveOwnedAgentRegistration } from "../../handshake/evm.js";
import { authorizeV2RoleAccess, readV2RoleAccessPayload, V2RoleAccessError, verifyV2RoleAccess, type V2AccessKey, type V2Role } from "./access.js";
import type { ClaimPhase, V2AcceptanceHmacKey, V2InvitationClaim, V2InvitationMetadata } from "./invitation-store.js";
import { createV2InvitationService, createV2InvitationStore, V2InvitationWindowUnavailableError } from "./invitation-store.js";
import { V2_HELPER_VERSION, V2_PUBLIC_ENDPOINT, readV2ReleasePin, verifiedV2HelperPrefix } from "./instructions.js";
import {
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  normalizeV2CommitmentCheckpoint,
} from "./commitment-checkpoint.js";
import {
  AGENT_HANDSHAKE_V2_MCP_ORIGIN,
  normalizeV2Acceptance,
  normalizeV2Descriptor,
  normalizeV2EvidenceResult,
  normalizeV2IdentityClaim,
  normalizeV2Party,
  normalizeV2Policy,
  normalizeV2Proposal,
  normalizeV2Result,
  normalizeV2Terms,
  v2CanonicalRecord,
} from "./protocol.js";

type JsonObject = Record<string, any>;
type InvitationService = Readonly<{
  create(input: { sessionId: string; statementDigest: string; nbfMs: string | number; expMs: string | number; invitationExpMs?: string | number; metadata?: V2InvitationMetadata; commitGuard?: () => boolean }): Promise<{ initiatorAccess: string; responderInvitation: string }>;
  accept(input: { invitation: string; acceptanceIdempotencyKey?: string }): Promise<{ claimedAtMs: string | null; responderAccess: string; metadata: V2InvitationMetadata | null; claim: V2InvitationClaim | null }>;
  advanceClaim(input: { claim: V2InvitationClaim; phase: ClaimPhase; completedAtMs?: string }): Promise<{ claim: V2InvitationClaim | null }>;
}>;
export type RelaySessionListing = Readonly<{ sessionId: string; startedAtMs: number; stage: string | null }>;
export type Relay = Readonly<{
  fetchDiscovery(sessionId?: string): Promise<unknown>;
  // Optional (multi-session hosting): every session the relay holds, newest first
  // (relay GET /v1/runs). Absent => invite() uses only the relay's "current" session.
  listSessions?(): Promise<readonly RelaySessionListing[]>;
  getMessages(input: { sessionId: string; after?: string; waitMs?: number }): Promise<{ highestSeq?: string; messages: readonly JsonObject[] }>;
  postMessage(input: { body: unknown; kind: string; privateKeyPem: string; role: V2Role; senderKey: string; sessionId: string }): Promise<unknown>;
  getResult(input: { sessionId: string }): Promise<unknown>;
}>;
type CoordinatorData = JsonObject & {
  discovery: JsonObject;
  terms: JsonObject;
  policyDigest?: string;
  sessionKeyAddress?: string;
  party?: JsonObject;
  counterpart?: JsonObject;
  pending?: { operation: "identity_claim" | "proposal" | "acceptance" | "evidence"; payload: JsonObject } | null;
  proposalEnvelope?: JsonObject;
  acceptanceEnvelope?: JsonObject;
  proposalCheckpoint?: JsonObject;
  acceptanceCheckpoint?: JsonObject;
  descriptorEnvelope?: JsonObject;
  sessionDigest?: string;
  transitions?: JsonObject[];
  evidenceUploaded?: boolean;
  certificateAvailable?: boolean;
  relay?: { senderKey: string };
  stage?: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const RETRY_AFTER_MS = 3000;
const MIN_REGISTRATION_BALANCE_WEI = 5_000_000_000_000_000n;
// Minimum remaining invitation-window runway required to mint responder role state. The session's
// invitationExpiresAtMs is the MINT cutoff — past it the host may rotate before the mint's
// agent_v2_invitation_created lands on the relay log — so a mint must commit early enough for that
// message to be observed. The claim runway itself is mint-relative (below), not bound to the cutoff.
const INVITATION_MIN_RUNWAY_MS = 30_000;
// The responder's claim window is mint-relative so an invitation minted late
// in the session's invitation window still gets a full runway for real
// LLM-agent turn latency (~10-90s to read the drop, build the token argument,
// and issue accept). The host learns this expiry from the
// agent_v2_invitation_created message and extends its claim-observation bound
// to match, so a claim still can never outlive host observation.
const INVITATION_CLAIM_RUNWAY_MS = 180_000;
// The claim window must end strictly inside the session deadline, with a
// small landing margin so a claim accepted at the edge still reaches the host
// while it is observing — an accept that lands after rotation succeeds on the
// coordinator but orphans the session (claims post, nobody funds, the session
// stalls at awaiting_funding until deadline).
const INVITATION_CLAIM_LANDING_MARGIN_MS = 5_000;
// Multi-session hosting: N host containers each open their own ~120 s session on
// the shared relay, staggered. invite() considers the newest few sessions the
// relay lists (not only "current") and mints into a FREE one: valid discovery,
// same host build as "current", >= INVITATION_MIN_RUNWAY_MS of invitation window
// left, no initiator invitation on its relay log, and not reserved by a
// concurrent invite in this process. One invitation per session is unchanged.
const MULTI_SESSION_MAX_CANDIDATES = 8;
// A listed session older than this cannot still be in its invitation window.
const MULTI_SESSION_MAX_AGE_MS = 10 * 60_000;
const NEXT_ACTION = "call_agent_handshake_next_with_unchanged_role_access";
// agent_handshake_next bridges ordinary dependency waits server-side: one tool
// call may hold up to a bounded waitMs so a public client gets the next
// actionable response without relying on the model to repoll between waits.
const DEFAULT_NEXT_WAIT_MS = 12_000;
const MAX_NEXT_WAIT_MS = 15_000;
const NEXT_WAIT_POLL_MS = 2_000;
const MAX_NEXT_WAIT_POLLS = 64;

function boundedNextWaitMs(value: unknown): number {
  if (value === undefined || value === null) return DEFAULT_NEXT_WAIT_MS;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) fail();
  return Math.min(value, MAX_NEXT_WAIT_MS);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function joinRequired(role: V2Role, sessionId: string): JsonObject {
  return Object.freeze({
    externalBusinessActionPerformed: false,
    needed: "agent_handshake_join",
    nextAction: "call_agent_handshake_join_now_with_access_and_exact_init_policy_inspect_outputs",
    requiredInputs: Object.freeze(["access", "helperVersion", "sessionKeyAddress", "policyDigest"]),
    role,
    sessionId,
    stage: "invited",
    stageMeaning: "this_role_has_not_joined",
  });
}

export class V2CoordinatorError extends Error {
  // A short machine-stable tag naming which coordination guard fired. It is
  // emitted only in the server-side agent_handshake_tool_failure log — the
  // public response stays "coordination_failed".
  readonly detail?: string;
  constructor(detail?: string) {
    super("Agent handshake coordination failed safely.");
    this.name = "V2CoordinatorError";
    this.detail = detail;
  }
}
// The published session terms are not secret — the host publishes them in
// discovery — so a mismatch error may carry them verbatim to let the caller
// resubmit with the exact published terms inside the same session window.
export class V2TermsMismatchError extends V2CoordinatorError {
  readonly publishedTerms: JsonObject;
  constructor(publishedTerms: JsonObject) {
    super();
    this.name = "V2TermsMismatchError";
    this.publishedTerms = publishedTerms;
  }
}
// A pending proposal/acceptance carries a fixed issuedAtMs/expiresAtMs window.
// Once it lapses the payload can never be signed again: proposal windows are
// renewed on re-poll (the payload is not anchored until submit), but an
// acceptance window is bound to the anchored proposal's expiresAtMs and a
// session past its deadline cannot sign at all — both are terminal.
export class V2SigningWindowExpiredError extends V2CoordinatorError {
  constructor() { super(); this.name = "V2SigningWindowExpiredError"; }
}
// The session deadline passed while the role was joined but still waiting on
// the host's funding record — a distinct terminal state from an invalid or
// forged role access so a caller can tell a stalled host funder from a bad
// token.
export class V2FundingTimeoutError extends V2CoordinatorError {
  constructor() { super(); this.name = "V2FundingTimeoutError"; }
}
// The generic host ended this session and said so on the relay log
// (agent_v2_session_failed, signed by its certified per-session key): a snapshot
// the relay refused, an invitation that expired unclaimed or was claimed too
// late, a failed identity preparation or verdict. Terminal for both roles, so
// agent_handshake_next stops at once instead of waiting out the deadline.
export class V2SessionFailedError extends V2CoordinatorError {
  readonly reasonCode: string;
  constructor(reasonCode: string) {
    super(`host.${reasonCode.toLowerCase()}`.slice(0, 64));
    this.name = "V2SessionFailedError";
    this.reasonCode = reasonCode;
  }
}
export class V2SessionInvitationExpiredError extends V2SessionFailedError {
  constructor(reasonCode: string) {
    super(reasonCode);
    this.name = "V2SessionInvitationExpiredError";
  }
}
export class V2TransientCoordinatorError extends Error {
  readonly retryAfterMs?: number;
  constructor(retryAfterMs?: number) {
    super("Agent handshake coordination is waiting for durable infrastructure state.");
    this.name = "V2TransientCoordinatorError";
    this.retryAfterMs = retryAfterMs;
  }
}
// Transport/JSON-RPC failures from the EVM node (handshake/evm.ts EvmRpcError,
// plus viem-style names) are environmental, not protocol rejections.
const TRANSIENT_RPC_ERROR_NAMES = new Set(["EvmRpcError", "HttpRequestError", "RpcRequestError", "TimeoutError"]);
const SAFE_RPC_TAG = /^[a-z][a-z0-9_]{0,31}$/;
function isTransientRpcError(error: unknown): boolean {
  return TRANSIENT_RPC_ERROR_NAMES.has((error as Error)?.name);
}
function transientRpcTag(error: unknown): string {
  const tag = (error as { tag?: unknown })?.tag;
  if (typeof tag === "string" && SAFE_RPC_TAG.test(tag)) return tag;
  const name = (error as Error)?.name;
  return name === "TimeoutError" ? "timeout" : name === "HttpRequestError" ? "http_error" : "rpc_error";
}
function fail(detail?: string): never { throw new V2CoordinatorError(detail); }
function transient(retryAfterMs?: number): never { throw new V2TransientCoordinatorError(retryAfterMs); }
function windowExpired(): never { throw new V2SigningWindowExpiredError(); }

// Agents mint checkpoint issuedAtMs on their own machines, so it is checked
// against the host clock. NTP skew between independent hosts routinely exceeds
// one second, and a tight bound rejected every checkpoint from a slightly
// fast agent clock — deterministic coordination_failed at sign_proposal. Two
// minutes tolerates real-world skew; expiresAtMs remains the strict bound.
const CHECKPOINT_ISSUED_FUTURE_SKEW_MS = 120_000;

// The helper requires proposal windows to be exactly validForSeconds wide and
// to end at or before the session deadline. Near the deadline issuedAtMs
// slides back to keep the width exact; issuedAtMs only needs to be <= now.
// Returns null when no valid window fits before the deadline.
function agreementWindow(validForSeconds: string, sessionDeadlineMs: string, nowMs: number): { issuedAtMs: string; expiresAtMs: string } | null {
  const width = BigInt(validForSeconds) * 1000n;
  const deadline = BigInt(sessionDeadlineMs);
  const nowBig = BigInt(nowMs);
  const issued = nowBig + width <= deadline ? nowBig : deadline - width;
  const expires = issued + width;
  if (issued < 1n || nowBig >= expires) return null;
  return { issuedAtMs: String(issued), expiresAtMs: String(expires) };
}

function exact(value: unknown, keys: readonly string[]): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const item = value as JsonObject;
  if (Object.keys(item).sort().join(",") !== [...keys].sort().join(",")) fail();
  return item;
}

function discovery(value: unknown): JsonObject {
  const probe = value !== null && typeof value === "object" && !Array.isArray(value) ? Object.keys(value) : [];
  const hasTerms = probe.includes("terms");
  const item = exact(value, [
    "schema", "protocol", "sessionId", "repositorySha", "kitRepoUrl", "relayUrl",
    "createdAtMs", "invitationExpiresAtMs", "sessionDeadlineMs", "hostSessionKeyCertificate",
    "sessionOpenedBlock", ...(hasTerms ? ["terms"] : []), "externalBusinessActionPerformed",
  ]);
  if (
    item.schema !== "clockchain.agent-handshake-discovery/v2" ||
    item.protocol !== "clockchain.agent-handshake/v2" || !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) || typeof item.kitRepoUrl !== "string" ||
    typeof item.relayUrl !== "string" || !DECIMAL.test(item.createdAtMs) ||
    !DECIMAL.test(item.invitationExpiresAtMs) || !DECIMAL.test(item.sessionDeadlineMs) ||
    !DECIMAL.test(item.sessionOpenedBlock) ||
    BigInt(item.createdAtMs) >= BigInt(item.invitationExpiresAtMs) ||
    BigInt(item.invitationExpiresAtMs) > BigInt(item.sessionDeadlineMs) ||
    item.hostSessionKeyCertificate === null || typeof item.hostSessionKeyCertificate !== "object" ||
    item.externalBusinessActionPerformed !== false
  ) fail();
  if (!hasTerms) return Object.freeze(JSON.parse(JSON.stringify(item)));
  let terms: unknown;
  try { terms = normalizeV2Terms(item.terms); } catch { fail(); }
  return Object.freeze(JSON.parse(JSON.stringify({ ...item, terms })));
}

function key(principal: string, session: string, role: V2Role): HandshakeKey { return { principal, session, role }; }
function data(record: HandshakeRecord | null): CoordinatorData { return (record?.data ?? {}) as CoordinatorData; }
function merge(current: HandshakeRecord | null, keyValue: HandshakeKey, patch: Partial<CoordinatorData>): HandshakeRecord {
  return {
    ...(current ?? { ...keyValue, status: "active" }),
    data: { ...data(current), ...patch },
    status: "active",
  };
}

function localPolicy(terms: JsonObject, role: V2Role): JsonObject {
  return normalizeV2Policy({
    schema: "clockchain.agent-handshake-policy/v1",
    protocol: "clockchain.agent-handshake/v2",
    role,
    mcpOrigin: "https://mcp.clockchain.network",
    reference: terms.reference,
    statementDigest: v2CanonicalRecord(terms).digest,
    maxValidForSeconds: terms.validForSeconds,
    identityPolicy: terms.identityPolicy,
    externalBusinessActionsAllowed: false,
  }) as JsonObject;
}

function metadataFrom(discoveryValue: JsonObject, terms: JsonObject): V2InvitationMetadata {
  return Object.freeze({
    terms,
    repositorySha: discoveryValue.repositorySha,
    hostSessionKeyCertificate: discoveryValue.hostSessionKeyCertificate,
    invitationExpiresAtMs: discoveryValue.invitationExpiresAtMs,
    sessionDeadlineMs: discoveryValue.sessionDeadlineMs,
    createdAtMs: discoveryValue.createdAtMs,
    sessionOpenedBlock: discoveryValue.sessionOpenedBlock,
  });
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return digestHex(left) === digestHex(right);
  } catch {
    fail();
  }
}

function warnCompatibility(event: string, sessionId: string): void {
  console.warn(JSON.stringify({ event, sessionId }));
}

function sameDiscoveryStableFields(current: JsonObject, found: JsonObject): boolean {
  const stableKeys = [
    "schema", "protocol", "sessionId", "repositorySha", "kitRepoUrl", "relayUrl",
    "createdAtMs", "invitationExpiresAtMs", "sessionDeadlineMs", "sessionOpenedBlock",
    "externalBusinessActionPerformed",
  ];
  return stableKeys.every((field) => current[field] === found[field]) &&
    sameCanonical(current.hostSessionKeyCertificate, found.hostSessionKeyCertificate);
}

function discoveryTermsCompatible(current: JsonObject, found: JsonObject, terms: JsonObject): boolean {
  const expected = v2CanonicalRecord(terms).digest;
  const currentTerms = current.terms as JsonObject | undefined;
  const foundTerms = found.terms as JsonObject | undefined;
  if (currentTerms !== undefined && v2CanonicalRecord(currentTerms).digest !== expected) return false;
  if (foundTerms !== undefined && v2CanonicalRecord(foundTerms).digest !== expected) return false;
  return true;
}

function relayPrivateKeyMatchesSender(input: { privateKeyPem: string; senderKey: string; sessionId: string; role: V2Role }): boolean {
  try {
    const envelope = signRelayEnvelope({
      body: Object.freeze({ externalBusinessActionPerformed: false }),
      kind: "agent_v2_relay_key_check",
      privateKeyPem: input.privateKeyPem,
      role: input.role,
      senderKey: input.senderKey,
      seq: "0",
      sessionId: input.sessionId,
    });
    return verifyRelayEnvelope(envelope as JsonObject) === true;
  } catch {
    return false;
  }
}

function signRequest(current: CoordinatorData, role: V2Role, operation: string, payload: JsonObject): JsonObject {
  const bytes = canonicalBytes(payload);
  const descriptorEnvelope = operation === "evidence"
    ? current.descriptorEnvelope
    : null;
  if (operation === "evidence" && !descriptorEnvelope) fail();
  // The helper's sign step emits the commitment checkpoint alongside the
  // artifact signature so portable clients can satisfy submit_checkpoint
  // without a local adapter. Acceptance checkpoints link to the proposal
  // checkpoint, which must already exist by the time an acceptance is minted.
  const previousCheckpointDigest = operation === "acceptance"
    ? (current.proposalCheckpoint ? commitmentCheckpointDigest(current.proposalCheckpoint) : fail())
    : null;
  return Object.freeze({
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: V2_HELPER_VERSION,
    operation,
    role,
    sessionId: current.discovery.sessionId,
    repositorySha: current.discovery.repositorySha,
    sessionDeadlineMs: current.discovery.sessionDeadlineMs,
    hostSessionKeyCertificate: current.discovery.hostSessionKeyCertificate,
    terms: current.terms,
    policyDigest: current.policyDigest,
    previousCheckpointDigest,
    descriptorEnvelope,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
    externalBusinessActionPerformed: false,
  });
}

function signatureEnvelope(kind: "proposal" | "acceptance", payload: JsonObject, address: string, signatureHex: string): JsonObject {
  return Object.freeze({
    payload,
    schema: `clockchain.agent-handshake-${kind}-envelope/v2`,
    signature: Object.freeze({ address, algorithm: "eip191", value: signatureHex }),
  });
}

function evidenceEnvelope(result: JsonObject, address: string, signatureHex: string): JsonObject {
  return Object.freeze({
    result,
    schema: "clockchain.agent-handshake-evidence/v2",
    signature: Object.freeze({ address, algorithm: "eip191", value: signatureHex }),
  });
}

function localStateDir(sessionId: string, role: V2Role): string {
  if (!UUID.test(sessionId)) fail();
  return `$TMPDIR/.clockchain/handshakes/${sessionId}/${role}`;
}

// macOS exports $TMPDIR with a trailing slash, so verbatim shell expansion of
// "$TMPDIR/.clockchain/..." yields ".../T//.clockchain/..." and the helper's
// private-path guard (resolve(p) === p) rejects the redundant separator. The
// shell rendering uses ${TMPDIR%/} to strip it; argvAfterVerifiedPrefix keeps
// the literal "$TMPDIR/" prefix because the harness adapter contractually
// recognizes that exact prefix and resolves it to a canonical path itself.
function localStateDirShell(sessionId: string, role: V2Role): string {
  if (!UUID.test(sessionId)) fail();
  return "${TMPDIR%/}/.clockchain/handshakes/" + sessionId + "/" + role;
}

function helperStep(verifiedHelperPrefix: string, operation: string, sessionId: string, role: V2Role, payload?: JsonObject): JsonObject {
  const stateDir = localStateDir(sessionId, role);
  const argvAfterVerifiedPrefix = [operation, "--state-dir", stateDir];
  const shellArgv = [operation, "--state-dir", localStateDirShell(sessionId, role)];
  if (payload !== undefined) {
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    argvAfterVerifiedPrefix.push("--payload-base64url", encoded);
    shellArgv.push("--payload-base64url", encoded);
  }
  const shellCommandSuffix = shellArgv
    .map((value, index) => index === 2 ? `"${value}"` : value)
    .join(" ");
  return Object.freeze({
    operation,
    argvAfterVerifiedPrefix: Object.freeze(argvAfterVerifiedPrefix),
    shellCommand: `${verifiedHelperPrefix} ${shellCommandSuffix}`,
    shellCommandSuffix,
  });
}

// Digest-addressed verbatim commands: a shellCommand is multi-KB and must be
// transcribed byte-exact by adapter-less agents, which is slow and corruptible
// through a chat/shell round-trip. Each step therefore also carries
// shellCommandFetch — a short digest-bound command that downloads the exact
// shellCommand bytes by commandSha256 and verifies them before executing.
// Registered commands live only slightly longer than a session; the digest is
// the capability (256-bit, unguessable) and the bytes served are the same
// already-issued command the caller holds.
const LOCAL_ACTION_COMMAND_TTL_MS = 20 * 60_000;
type LocalActionCommandRegistrar = (commandSha256: string, shellCommand: string, sessionId: string, role: V2Role) => string;

function compactHelperStep(step: JsonObject, role: V2Role, sessionId: string, registerCommand?: LocalActionCommandRegistrar): JsonObject {
  const shellCommand = step.shellCommand as string;
  const commandSha256 = createHash("sha256").update(shellCommand, "utf8").digest("hex");
  return Object.freeze({
    operation: step.operation,
    role,
    sessionId,
    approvalTool: "mcp__clockchain-local-adapter__authorize_local_action",
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256,
    ...(registerCommand ? { shellCommandFetch: registerCommand(commandSha256, shellCommand, sessionId, role) } : {}),
    shellCommand,
  });
}

function signingSummary(signingRequest: JsonObject): JsonObject {
  return Object.freeze({
    schema: "clockchain.agent-handshake-signing-summary/v1",
    operation: signingRequest.operation,
    role: signingRequest.role,
    sessionId: signingRequest.sessionId,
    bytesSha256: signingRequest.bytesSha256,
  });
}

function setupLocalAction(verifiedHelperPrefix: string, policy: JsonObject, sessionId: string, role: V2Role, registerCommand?: LocalActionCommandRegistrar): JsonObject {
  return Object.freeze({
    executor: "pinned_helper",
    operations: Object.freeze(["init", "policy", "inspect"]),
    payloadEncoding: "base64url_utf8_json",
    stateDirectoryCommand: `mkdir -p -m 700 "${localStateDirShell(sessionId, role)}"`,
    helperSteps: Object.freeze([
      compactHelperStep(helperStep(verifiedHelperPrefix, "init", sessionId, role), role, sessionId, registerCommand),
      compactHelperStep(helperStep(verifiedHelperPrefix, "policy", sessionId, role, policy), role, sessionId, registerCommand),
      compactHelperStep(helperStep(verifiedHelperPrefix, "inspect", sessionId, role), role, sessionId, registerCommand),
    ]),
    stateDir: "new_private_absolute_state_dir",
    registrationGate: "do_not_register_until_agent_handshake_next_returns_erc8004_registration_after_join_and_funding",
    afterSuccess: "call_agent_handshake_join_with_helper_output",
  });
}

function signingLocalAction(verifiedHelperPrefix: string, signingRequest: JsonObject, registerCommand?: LocalActionCommandRegistrar): JsonObject {
  const role = signingRequest.role as V2Role;
  const sessionId = signingRequest.sessionId as string;
  const step = helperStep(verifiedHelperPrefix, "sign", sessionId, role, signingRequest);
  return Object.freeze({
    executor: "pinned_helper",
    operation: "sign",
    helperStep: compactHelperStep(step, role, sessionId, registerCommand),
    stateDir: "reuse_exact_absolute_state_dir",
    afterSuccess: signingRequest.operation === "proposal" || signingRequest.operation === "acceptance"
      ? "call_agent_handshake_submit_checkpoint_with_helper_output_checkpoint_then_agent_handshake_submit_with_signatureHex_and_unchanged_policy_digest"
      : "call_agent_handshake_submit_with_helper_output_and_unchanged_policy_digest",
  });
}

function certificateLocalAction(verifiedHelperPrefix: string, input: {
  certificate: JsonObject;
  discovery: JsonObject;
  role: V2Role;
  sessionId: string;
}, registerCommand?: LocalActionCommandRegistrar): JsonObject {
  const payload = Object.freeze({
    schema: "clockchain.agent-handshake-certificate-verification/v1",
    helperVersion: V2_HELPER_VERSION,
    role: input.role,
    sessionId: input.sessionId,
    repositorySha: input.discovery.repositorySha,
    sessionDeadlineMs: input.discovery.sessionDeadlineMs,
    certificate: input.certificate,
    externalBusinessActionPerformed: false,
  });
  const step = helperStep(verifiedHelperPrefix, "verify-certificate", input.sessionId, input.role, payload);
  return Object.freeze({
    executor: "pinned_helper",
    operation: "verify-certificate",
    helperStep: compactHelperStep(step, input.role, input.sessionId, registerCommand),
    stateDir: "reuse_exact_absolute_state_dir",
    terminalProof: "use_verified_helper_output_only",
  });
}

function find(entries: readonly JsonObject[], kind: string, role?: string): JsonObject | undefined {
  return [...entries].reverse().find((entry) => entry?.kind === kind && (role === undefined || entry?.role === role));
}

const SESSION_FAILED_KIND = "agent_v2_session_failed";
const SESSION_FAILED_DOMAIN = "clockchain.agent-handshake-session-failed/v1";
const HOST_REASON_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;

// The relay is an unauthenticated mailbox, so a host failure notice counts only
// when its Ed25519 signature verifies under the host's certified per-session
// key (discovery.hostSessionKeyCertificate.certificate.sessionPublicKey) over
// the domain-separated session id and reason code. Anything else is ignored.
export function verifiedHostSessionFailure(
  entries: readonly JsonObject[],
  sessionId: string,
  hostSessionKeyCertificate: unknown,
): string | null {
  const sessionPublicKey = (hostSessionKeyCertificate as { certificate?: { sessionPublicKey?: unknown } } | null)
    ?.certificate?.sessionPublicKey;
  if (typeof sessionPublicKey !== "string") return null;
  const raw = Buffer.from(sessionPublicKey, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== sessionPublicKey) return null;
  let publicKey;
  try {
    publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (entry?.kind !== SESSION_FAILED_KIND || entry?.role !== "host") continue;
    const body = entry.body as JsonObject | undefined;
    const reasonCode = body?.reasonCode;
    const signature = body?.sessionSignature;
    if (
      typeof reasonCode !== "string" || !HOST_REASON_CODE.test(reasonCode) ||
      typeof signature !== "string" || !BASE64_SIGNATURE.test(signature)
    ) continue;
    const bytes = Buffer.from(`${SESSION_FAILED_DOMAIN}\n${sessionId}\n${reasonCode}`, "utf8");
    let valid = false;
    try { valid = verifySignature(null, bytes, publicKey, Buffer.from(signature, "base64")); } catch { valid = false; }
    if (valid) return reasonCode;
  }
  return null;
}

function hostSessionFailed(reasonCode: string): never {
  if (reasonCode === "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED") throw new V2SessionInvitationExpiredError(reasonCode);
  throw new V2SessionFailedError(reasonCode);
}

function funded(entries: readonly JsonObject[], role: V2Role, address: string): boolean {
  return entries.some((entry) => entry?.kind === "agent_v2_funding_record" && entry?.role === "host" && entry?.body?.role === role && entry?.body?.address === address);
}

export function createV2Coordinator(options: {
  accessKeys: readonly V2AccessKey[];
  activeAccessKey: V2AccessKey;
  invitationService: InvitationService;
  relay: Relay;
  stateStore?: HandshakeStateStore;
  now?: () => number;
  recoverEip191Address(input: { bytes: Buffer; signatureHex: string }): Promise<string>;
  registrationFundingReady(input: { address: string }): Promise<boolean>;
  resolveRegistration(input: { address: string; fromBlock: string }): Promise<JsonObject | null>;
  advanceTransitions(input: { descriptor: JsonObject; role: V2Role; existing: readonly JsonObject[] }): Promise<JsonObject[]>;
  nextWaitDefaultMs?: number;
  verifiedHelperPrefix: string;
}) {
  const store = options.stateStore ?? createHandshakeStateStore();
  const now = options.now ?? Date.now;
  const acceptSerializers = new Map<string, Promise<void>>();
  const localActionCommands = new Map<string, { command: string; expiresAtMs: number }>();
  const registerLocalActionCommand: LocalActionCommandRegistrar = (commandSha256, shellCommand, sessionId, role) => {
    for (const [digest, entry] of localActionCommands) if (entry.expiresAtMs <= now()) localActionCommands.delete(digest);
    localActionCommands.set(commandSha256, { command: shellCommand, expiresAtMs: now() + LOCAL_ACTION_COMMAND_TTL_MS });
    const file = `${localStateDirShell(sessionId, role)}/cmd-${commandSha256.slice(0, 16)}.sh`;
    // Node is guaranteed present (the helper requires it), so the digest check
    // uses node rather than shasum/sha256sum, which differ across platforms.
    return `curl -fsS "${AGENT_HANDSHAKE_V2_MCP_ORIGIN}/handshake/local-action/${commandSha256}" -o "${file}" && node -e 'const c=require("node:crypto"),f=require("node:fs");process.exit(c.createHash("sha256").update(f.readFileSync(process.argv[1])).digest("hex")==="${commandSha256}"?0:1)' "${file}" && bash "${file}"`;
  };

  // A role access can fail verification either because it is malformed/forged
  // or simply because its expiry — the session deadline — passed. When the
  // signature and bindings verify under a synthetic in-window clock and the
  // stored record shows the role joined but never reached party_ready on an
  // erc8004-required session with no host funding record on the relay, the
  // honest terminal reason is a stalled host funder, not a bad token.
  async function classifyAccessFailure(access: string, tool: string, original: Error): Promise<Error> {
    try {
      const untrusted = readV2RoleAccessPayload(access);
      const verified = verifyV2RoleAccess(access, {
        keys: options.accessKeys,
        nowMs: Number(untrusted.nbfMs),
        expectedSessionId: untrusted.sessionId,
        expectedRole: untrusted.role,
        expectedStatementDigest: untrusted.statementDigest,
        expectedExpMs: untrusted.expMs,
        requiredTool: tool,
      });
      if (now() < Number(untrusted.expMs)) return original;
      const record = await store.get(key(verified.principal, untrusted.sessionId, untrusted.role));
      if (!record) return original;
      const current = data(record);
      const erc8004 = (current.terms as { identityPolicy?: { erc8004?: unknown } } | undefined)?.identityPolicy?.erc8004;
      if (
        typeof current.sessionKeyAddress !== "string" || current.party !== undefined ||
        (erc8004 !== "required_fresh" && erc8004 !== "required_existing_or_fresh")
      ) return original;
      const entries = (await options.relay.getMessages({ sessionId: untrusted.sessionId })).messages;
      return funded(entries, untrusted.role, current.sessionKeyAddress) ? original : new V2FundingTimeoutError();
    } catch {
      return original;
    }
  }

  async function authorize(access: string, tool: string) {
    let verified: ReturnType<typeof authorizeV2RoleAccess>;
    try {
      verified = authorizeV2RoleAccess(access, { keys: options.accessKeys, nowMs: now(), requiredTool: tool });
    } catch (error) {
      if (!(error instanceof V2RoleAccessError)) throw error;
      throw await classifyAccessFailure(access, tool, error);
    }
    const keyValue = key(verified.principal, verified.payload.sessionId, verified.payload.role);
    const record = await store.get(keyValue);
    if (!record) fail();
    const current = data(record);
    if (v2CanonicalRecord(current.terms).digest !== verified.payload.statementDigest || current.discovery.sessionDeadlineMs !== verified.payload.expMs) fail();
    return { verified, keyValue, record, current };
  }

  async function post(keyValue: HandshakeKey, kind: string, body: unknown): Promise<void> {
    const record = await store.get(keyValue);
    const current = data(record);
    if (!record?.relayEd25519Pem || !current.relay?.senderKey) fail();
    const existing = (await options.relay.getMessages({ sessionId: keyValue.session })).messages
      .filter((entry) => entry?.kind === kind && entry?.role === keyValue.role);
    if (existing.length > 0) {
      for (const entry of existing) {
        if (entry.senderKey !== current.relay.senderKey || !sameCanonical(entry.body, body)) fail();
      }
      return;
    }
    await options.relay.postMessage({
      body, kind, privateKeyPem: record.relayEd25519Pem, role: keyValue.role as V2Role,
      senderKey: current.relay.senderKey, sessionId: keyValue.session,
    });
  }

  async function refresh(keyValue: HandshakeKey, observed?: { entries?: readonly JsonObject[] }): Promise<CoordinatorData> {
    const record = await store.get(keyValue);
    if (!record) fail();
    const current = data(record);
    const entries = (await options.relay.getMessages({ sessionId: keyValue.session })).messages;
    if (observed) observed.entries = entries;
    const other = keyValue.role === "initiator" ? "responder" : "initiator";
    const ready = find(entries, "agent_v2_party_ready", other);
    const patch: Partial<CoordinatorData> = {};
    if (ready?.body) patch.counterpart = normalizeV2Party(ready.body, current.terms.identityPolicy) as JsonObject;
    const proposal = find(entries, "agent_v2_proposal", "initiator");
    if (proposal?.body?.proposalEnvelope) patch.proposalEnvelope = proposal.body.proposalEnvelope;
    const proposalCheckpoint = find(entries, "agent_v2_commitment_checkpoint", "initiator");
    if (proposalCheckpoint?.body?.checkpoint) patch.proposalCheckpoint = normalizeV2CommitmentCheckpoint(proposalCheckpoint.body.checkpoint) as JsonObject;
    const acceptance = find(entries, "agent_v2_acceptance", "responder");
    if (acceptance?.body?.acceptanceEnvelope) patch.acceptanceEnvelope = acceptance.body.acceptanceEnvelope;
    const acceptanceCheckpoint = find(entries, "agent_v2_commitment_checkpoint", "responder");
    if (acceptanceCheckpoint?.body?.checkpoint) patch.acceptanceCheckpoint = normalizeV2CommitmentCheckpoint(acceptanceCheckpoint.body.checkpoint) as JsonObject;
    const descriptorMessage = find(entries, "agent_v2_handshake_required", "host");
    if (descriptorMessage?.body?.descriptorEnvelope?.descriptor) {
      const descriptor = normalizeV2Descriptor(descriptorMessage.body.descriptorEnvelope.descriptor);
      const sessionDigest = v2CanonicalRecord(descriptor).digest;
      if (descriptorMessage.body.sessionDigest !== sessionDigest || descriptor.sessionId !== keyValue.session) fail();
      patch.descriptorEnvelope = descriptorMessage.body.descriptorEnvelope;
      patch.sessionDigest = sessionDigest;
    }
    const updated = await store.update(keyValue, (value) => merge(value, keyValue, patch));
    return data(updated);
  }

  async function storeInitial(access: string, metadata: V2InvitationMetadata, role: V2Role, missingTermsEvent?: string): Promise<HandshakeKey> {
    const certificate = metadata.hostSessionKeyCertificate as JsonObject;
    const verified = verifyV2RoleAccess(access, {
      keys: options.accessKeys, nowMs: now(), expectedSessionId: certificate.certificate?.sessionId,
      expectedRole: role, expectedStatementDigest: v2CanonicalRecord(metadata.terms).digest,
      expectedExpMs: metadata.sessionDeadlineMs, requiredTool: "agent_handshake_join",
    });
    const found = discovery(await options.relay.fetchDiscovery(verified.payload.sessionId));
    const foundTerms = found.terms as JsonObject | undefined;
    if (foundTerms === undefined) {
      if (missingTermsEvent) warnCompatibility(missingTermsEvent, found.sessionId as string);
    } else if (v2CanonicalRecord(foundTerms).digest !== v2CanonicalRecord(metadata.terms).digest) fail();
    if (
      found.repositorySha !== metadata.repositorySha || found.sessionDeadlineMs !== metadata.sessionDeadlineMs ||
      found.createdAtMs !== metadata.createdAtMs || found.invitationExpiresAtMs !== metadata.invitationExpiresAtMs ||
      found.sessionOpenedBlock !== metadata.sessionOpenedBlock ||
      !sameCanonical(found.hostSessionKeyCertificate, metadata.hostSessionKeyCertificate)
    ) fail();
    const keyValue = key(verified.principal, verified.payload.sessionId, role);
    await store.update(keyValue, (current) => {
      if (current) {
        const currentData = data(current);
        if (
          current.principal !== keyValue.principal || current.session !== keyValue.session ||
          current.role !== keyValue.role || !current.relayEd25519Pem ||
          !currentData.relay?.senderKey || !currentData.discovery || !currentData.terms ||
          !sameDiscoveryStableFields(currentData.discovery, found) ||
          !discoveryTermsCompatible(currentData.discovery, found, metadata.terms as JsonObject) ||
          v2CanonicalRecord(currentData.terms).digest !== v2CanonicalRecord(metadata.terms).digest ||
          !sameCanonical(currentData.discovery.hostSessionKeyCertificate, metadata.hostSessionKeyCertificate) ||
          !relayPrivateKeyMatchesSender({
            privateKeyPem: current.relayEd25519Pem,
            senderKey: currentData.relay.senderKey,
            sessionId: keyValue.session,
            role,
          })
        ) fail();
        return {
          ...merge(current, keyValue, {
            discovery: found,
            terms: currentData.terms,
            relay: { senderKey: currentData.relay.senderKey },
            stage: currentData.stage ?? "invited",
          }),
          relayEd25519Pem: current.relayEd25519Pem,
        };
      }
      const relayKey = generateRelayKeyPair();
      return {
        ...merge(current, keyValue, { discovery: found, terms: metadata.terms, relay: { senderKey: relayKey.senderKey }, stage: "invited" }),
        relayEd25519Pem: relayKey.privateKeyPem,
      };
    });
    return keyValue;
  }

  async function withClaimSerializer<T>(claim: V2InvitationClaim, work: () => Promise<T>): Promise<T> {
    const lockKey = `${claim.jti}:${claim.acceptanceKey.kid}:${claim.acceptanceKey.digest}`;
    const previous = acceptSerializers.get(lockKey) ?? Promise.resolve();
    const current = previous.then(work, work);
    const cleanup = current.then(() => undefined, () => undefined);
    acceptSerializers.set(lockKey, cleanup);
    try {
      return await current;
    } finally {
      if (acceptSerializers.get(lockKey) === cleanup) acceptSerializers.delete(lockKey);
    }
  }

  async function certificateResponse(
    keyValue: HandshakeKey,
    current: CoordinatorData,
    role: V2Role,
  ): Promise<JsonObject> {
    let certificate;
    try { certificate = await options.relay.getResult({ sessionId: keyValue.session }); }
    catch { return Object.freeze({ needed: "certificate", nextAction: NEXT_ACTION, retryAfterMs: 5000, sessionId: keyValue.session, stage: "awaiting_certificate" }); }
    const envelope = exact(certificate, ["hostSessionKeyCertificate", "result", "signer"]);
    const result = normalizeV2Result(envelope.result);
    if (
      result.sessionId !== keyValue.session || result.outcome !== "VERIFIED" ||
      result.externalBusinessActionPerformed !== false ||
      result.policyDigests[role] !== current.policyDigest ||
      result.parties[role].sessionKeyAddress !== current.sessionKeyAddress
    ) fail();
    await store.update(keyValue, (value) => merge(value, keyValue, { certificateAvailable: true, stage: "certificate_available" }));
    return Object.freeze({
      role,
      sessionId: keyValue.session,
      certificateSummary: Object.freeze({
        schema: "clockchain.agent-handshake-certificate-summary/v1",
        outcome: result.outcome,
        resultDigest: v2CanonicalRecord(result).digest,
        role,
        sessionId: keyValue.session,
      }),
      localAction: certificateLocalAction(options.verifiedHelperPrefix, {
        certificate: envelope,
        discovery: current.discovery,
        role,
        sessionId: keyValue.session,
      }, registerLocalActionCommand),
    });
  }

  async function evaluateNext(auth: Awaited<ReturnType<typeof authorize>>, role: V2Role): Promise<JsonObject> {
    const observed: { entries?: readonly JsonObject[] } = {};
    let current = await refresh(auth.keyValue, observed);
    // A signed host failure notice ends the session for both roles before any
    // other step: there is nothing left to sign, fund or wait for.
    const hostFailure = verifiedHostSessionFailure(
      observed.entries ?? [],
      auth.keyValue.session,
      current.discovery?.hostSessionKeyCertificate,
    );
    if (hostFailure !== null) hostSessionFailed(hostFailure);
    if (!current.policyDigest || !current.sessionKeyAddress) {
      return joinRequired(role, auth.keyValue.session);
    }
    if (current.pending) {
      if (BigInt(now()) >= BigInt(current.discovery.sessionDeadlineMs)) windowExpired();
      const pending = current.pending;
      const expiresAtMs = pending.payload.expiresAtMs;
      if (typeof expiresAtMs === "string" && BigInt(expiresAtMs) <= BigInt(now())) {
        // An expired acceptance window is anchored to the submitted proposal's
        // expiresAtMs and cannot be extended; an expired proposal is not yet
        // anchored, so re-issue its window and re-store the pending payload.
        if (pending.operation !== "proposal") windowExpired();
        const window = agreementWindow(current.terms.validForSeconds, current.discovery.sessionDeadlineMs, now());
        if (!window) windowExpired();
        const renewed = normalizeV2Proposal({ ...pending.payload, ...window }) as JsonObject;
        // A concurrent next() may have renewed the window first — keep the
        // winner so the served request always matches the stored payload.
        const updated = await store.update(auth.keyValue, (value) => {
          const stored = data(value).pending;
          if (
            stored?.operation === "proposal" && typeof stored.payload.expiresAtMs === "string" &&
            BigInt(stored.payload.expiresAtMs) > BigInt(now())
          ) return value;
          return merge(value, auth.keyValue, { pending: { operation: "proposal", payload: renewed } });
        });
        current = data(updated);
        if (!current.pending) fail();
      }
      const signingRequest = signRequest(current, role, current.pending.operation, current.pending.payload);
      return Object.freeze({ stage: current.stage, signingSummary: signingSummary(signingRequest), localAction: signingLocalAction(options.verifiedHelperPrefix, signingRequest, registerLocalActionCommand) });
    }
    const entries = (await options.relay.getMessages({ sessionId: auth.keyValue.session })).messages;
    if (!current.party) {
      if (current.terms.identityPolicy.erc8004 !== "not_required" && !funded(entries, role, current.sessionKeyAddress)) {
        return Object.freeze({
          needed: "funding_record",
          nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access",
          retryAfterMs: RETRY_AFTER_MS,
          role,
          selfFundingRequired: false,
          sessionId: auth.keyValue.session,
          stage: "awaiting_funding",
          waitingOn: "clockchain_host",
        });
      }
      let registration = null;
      if (current.terms.identityPolicy.erc8004 !== "not_required") {
        const awaitingFundingVisibility = () => Object.freeze({
          needed: "funding_visibility",
          nextAction: "wait_for_clockchain_host_funding_visibility_then_call_agent_handshake_next_with_unchanged_role_access",
          retryAfterMs: RETRY_AFTER_MS,
          role,
          selfFundingRequired: false,
          sessionId: auth.keyValue.session,
          stage: "awaiting_funding_visibility",
          waitingOn: "clockchain_host",
        });
        try {
          registration = await options.resolveRegistration({ address: current.sessionKeyAddress, fromBlock: current.discovery.sessionOpenedBlock ?? "0" });
        } catch (error) {
          // QA F-10: a transient Sepolia RPC failure (provider 429/5xx, network
          // blip, malformed envelope) is not a protocol rejection. Treat it like
          // the chain not yet showing the registration: a bounded, retryable
          // dependency wait. Deterministic resolver failures stay fatal.
          if (!isTransientRpcError(error)) throw error;
          console.warn(JSON.stringify({
            event: "agent_handshake_v2_rpc_transient",
            op: "resolve_registration",
            tag: transientRpcTag(error),
            sessionId: auth.keyValue.session,
          }));
          return awaitingFundingVisibility();
        }
        if (!registration) {
          if (!await options.registrationFundingReady({ address: current.sessionKeyAddress })) {
            return awaitingFundingVisibility();
          }
          return Object.freeze({
            needed: "erc8004_registration",
            role,
            sessionId: auth.keyValue.session,
            stage: "awaiting_identity_registration",
            identityPolicy: current.terms.identityPolicy,
            localAction: Object.freeze({
              executor: "pinned_helper",
              operation: "register",
              stateDir: "reuse_exact_absolute_state_dir",
              helperStep: compactHelperStep(
                helperStep(options.verifiedHelperPrefix, "register", auth.keyValue.session, role),
                role,
                auth.keyValue.session,
                registerLocalActionCommand,
              ),
              afterSuccess: NEXT_ACTION,
            }),
          });
        }
        if (current.terms.identityPolicy.erc8004 === "required_fresh" && BigInt(registration.registrationBlock) <= BigInt(current.discovery.sessionOpenedBlock ?? "0")) fail();
      }
      const party = normalizeV2Party({ sessionKeyAddress: current.sessionKeyAddress, policyDigest: current.policyDigest, erc8004: registration }, current.terms.identityPolicy) as JsonObject;
      await post(auth.keyValue, "agent_v2_party_ready", party);
      const updated = await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { party, stage: "party_ready" }));
      return Object.freeze({ needed: null, role, sessionId: auth.keyValue.session, stage: "party_ready", identity: party, nextAction: NEXT_ACTION });
    }
    current = await refresh(auth.keyValue);
    if (!current.counterpart) return Object.freeze({ needed: "counterpart_identity", nextAction: NEXT_ACTION, retryAfterMs: RETRY_AFTER_MS, role, sessionId: auth.keyValue.session, stage: "awaiting_counterpart" });
    const parties = role === "initiator" ? { initiator: current.party, responder: current.counterpart } : { initiator: current.counterpart, responder: current.party };
    if (role === "initiator" && !current.proposalEnvelope) {
      const window = agreementWindow(current.terms.validForSeconds, current.discovery.sessionDeadlineMs, now());
      if (!window) windowExpired();
      const proposal = normalizeV2Proposal({
        schema: "clockchain.agent-handshake-proposal/v2", protocol: "clockchain.agent-handshake/v2",
        sessionId: auth.keyValue.session, repositorySha: current.discovery.repositorySha,
        reference: current.terms.reference, statementDigest: v2CanonicalRecord(current.terms).digest,
        identityPolicy: current.terms.identityPolicy, initiator: parties.initiator, responder: parties.responder,
        issuedAtMs: window.issuedAtMs, expiresAtMs: window.expiresAtMs,
        externalBusinessActionPerformed: false,
      }) as JsonObject;
      // Two concurrent next() calls can both observe no pending and mint; the
      // serialized update keeps the first payload and the response is built
      // from whatever landed, so a lost race can never strand a signature made
      // over bytes the coordinator no longer holds.
      const updated = await store.update(auth.keyValue, (value) =>
        data(value).pending ? value : merge(value, auth.keyValue, { pending: { operation: "proposal", payload: proposal }, stage: "sign_proposal" }));
      const storedProposal = data(updated).pending;
      if (storedProposal?.operation !== "proposal") fail("proposal_pending");
      const signingRequest = signRequest(data(updated), role, "proposal", storedProposal.payload);
      return Object.freeze({ stage: "sign_proposal", signingSummary: signingSummary(signingRequest), localAction: signingLocalAction(options.verifiedHelperPrefix, signingRequest, registerLocalActionCommand) });
    }
    if (role === "responder" && !current.acceptanceEnvelope) {
      if (!current.proposalEnvelope?.payload) return Object.freeze({ needed: "proposal", nextAction: NEXT_ACTION, retryAfterMs: RETRY_AFTER_MS, role, sessionId: auth.keyValue.session, stage: "awaiting_proposal" });
      const proposal = normalizeV2Proposal(current.proposalEnvelope.payload) as JsonObject;
      if (BigInt(proposal.expiresAtMs) <= BigInt(now())) windowExpired();
      const acceptance = normalizeV2Acceptance({
        schema: "clockchain.agent-handshake-acceptance/v2", protocol: "clockchain.agent-handshake/v2",
        sessionId: proposal.sessionId, repositorySha: proposal.repositorySha, reference: proposal.reference,
        statementDigest: proposal.statementDigest, identityPolicy: proposal.identityPolicy,
        initiator: proposal.initiator, responder: proposal.responder, proposalDigest: digestHex(proposal),
        decision: "ACCEPTED", issuedAtMs: String(now()), expiresAtMs: proposal.expiresAtMs,
        externalBusinessActionPerformed: false,
      }) as JsonObject;
      // Same concurrent-mint guard as the proposal branch: keep the first
      // stored pending and serve its request, never a discarded mint's.
      const updated = await store.update(auth.keyValue, (value) =>
        data(value).pending ? value : merge(value, auth.keyValue, { pending: { operation: "acceptance", payload: acceptance }, stage: "sign_acceptance" }));
      const storedAcceptance = data(updated).pending;
      if (storedAcceptance?.operation !== "acceptance") fail("acceptance_pending");
      const signingRequest = signRequest(data(updated), role, "acceptance", storedAcceptance.payload);
      return Object.freeze({
        stage: "sign_acceptance",
        signingSummary: signingSummary(signingRequest),
        localAction: signingLocalAction(options.verifiedHelperPrefix, signingRequest, registerLocalActionCommand),
        previousCheckpoint: current.proposalCheckpoint,
      });
    }
    current = await refresh(auth.keyValue);
    if (!current.descriptorEnvelope?.descriptor || !current.sessionDigest) return Object.freeze({ needed: "descriptor", nextAction: NEXT_ACTION, retryAfterMs: RETRY_AFTER_MS, role, sessionId: auth.keyValue.session, stage: "awaiting_descriptor" });
    const descriptor = normalizeV2Descriptor(current.descriptorEnvelope.descriptor) as JsonObject;
    const transitions = await options.advanceTransitions({ descriptor, role, existing: current.transitions ?? [] });
    if (transitions.length !== 3) {
      await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { transitions, stage: "awaiting_anchors" }));
      return Object.freeze({ needed: "counterpart_transition", nextAction: NEXT_ACTION, retryAfterMs: RETRY_AFTER_MS, role, sessionId: auth.keyValue.session, stage: "awaiting_anchors" });
    }
    if (role === "initiator") await post(auth.keyValue, "agent_v2_anchor_report", { transitions });
    if (current.evidenceUploaded) return certificateResponse(auth.keyValue, current, role);
    const evidence = normalizeV2EvidenceResult({
      externalBusinessActionPerformed: false, party: current.party, policyDigest: current.policyDigest,
      reference: current.terms.reference, repositorySha: current.discovery.repositorySha, role,
      schema: "clockchain.agent-handshake-party-result/v2", sessionDigest: current.sessionDigest,
      statementDigest: v2CanonicalRecord(current.terms).digest,
      transitionDigests: transitions.map((entry) => entry.digest),
    }, current.terms.identityPolicy) as JsonObject;
    // Concurrent-mint guard: keep the first stored pending (transitions are
    // recomputed on every poll, so refreshing them here stays safe).
    const updated = await store.update(auth.keyValue, (value) =>
      data(value).pending
        ? merge(value, auth.keyValue, { transitions })
        : merge(value, auth.keyValue, { transitions, pending: { operation: "evidence", payload: evidence }, stage: "sign_evidence" }));
    const storedEvidence = data(updated).pending;
    if (storedEvidence?.operation !== "evidence") fail("evidence_pending");
    const signingRequest = signRequest(data(updated), role, "evidence", storedEvidence.payload);
    return Object.freeze({ stage: "sign_evidence", signingSummary: signingSummary(signingRequest), localAction: signingLocalAction(options.verifiedHelperPrefix, signingRequest, registerLocalActionCommand) });
  }

  // ---- Multi-session invite selection ------------------------------------
  const inviteReservations = new Map<string, number>();

  function inviteRetryHints(found: JsonObject, inviteNow: number): { rotationRetryMs: number; windowRetryMs: number } {
    // Retry hints name the moment the NEXT usable session is live — window end
    // (or claim-window end) plus a rotation margin — never a cycle-length value:
    // a ~120s hint against a ~121s rotation phase-locks an obedient caller into
    // the same dead phase on every retry.
    const rotationRetryMs = Math.min(Math.max(Number(found.sessionDeadlineMs) - inviteNow + 2_000, 5_000), 120_000);
    const windowRetryMs = Number.isSafeInteger(Number(found.invitationExpiresAtMs))
      ? Math.min(Math.max(Number(found.invitationExpiresAtMs) - inviteNow + 2_500, 5_000), 120_000)
      : rotationRetryMs;
    return { rotationRetryMs, windowRetryMs };
  }

  // null => free (as far as the relay log shows); a number => busy, retry hint in ms.
  async function sessionBusyRetryMs(found: JsonObject, inviteNow: number): Promise<number | null> {
    const { rotationRetryMs, windowRetryMs } = inviteRetryHints(found, inviteNow);
    // Reject before minting any state unless the window retains enough runway for the Responder's claim
    // to land; an already-expired or near-expiry session rolls over underneath the invite, so the
    // caller must retry into a fresh session rather than hold an invitation nobody will observe.
    if (inviteNow + INVITATION_MIN_RUNWAY_MS >= Number(found.invitationExpiresAtMs)) return windowRetryMs;
    // One invitation per session: the first invite anchors an
    // agent_v2_invitation_created message on the session's relay log, and a
    // second invite would fail closed inside post() on the sender-key check.
    // The condition self-heals at session rotation, so surface it as
    // transient instead of a terminal coordination failure.
    const takenInvitation = (await options.relay.getMessages({ sessionId: found.sessionId as string })).messages
      .find((entry) => entry?.kind === "agent_v2_invitation_created" && entry?.role === "initiator");
    if (takenInvitation) {
      // An unclaimed mint lapses at its claimExpiresAtMs and the host rotates
      // ~1-2s later; a claimed one holds the session to its deadline. Hint the
      // earlier horizon, floored so a legitimately-busy session is not hot-polled.
      const claimExpMs = Number((takenInvitation.body as JsonObject | undefined)?.claimExpiresAtMs);
      return Number.isSafeInteger(claimExpMs)
        ? Math.min(Math.max(claimExpMs - inviteNow + 2_500, 15_000), 120_000)
        : rotationRetryMs;
    }
    return null;
  }

  function reserveInviteSession(found: JsonObject, inviteNow: number): boolean {
    for (const [id, until] of inviteReservations) if (until <= inviteNow) inviteReservations.delete(id);
    const id = found.sessionId as string;
    if (inviteReservations.has(id)) return false;
    inviteReservations.set(id, Number(found.invitationExpiresAtMs));
    return true;
  }

  // A listed session is only a candidate when it is the same host build as the
  // relay's "current" session (the one the single-session path trusts) and its
  // windows are no wider than current's: the relay is an open mailbox, so a
  // foreign session must not attract invites by advertising a longer window.
  function compatibleWithCurrent(current: JsonObject, candidate: JsonObject): boolean {
    if (candidate.sessionId === current.sessionId) return true;
    if (
      candidate.repositorySha !== current.repositorySha ||
      candidate.kitRepoUrl !== current.kitRepoUrl ||
      candidate.relayUrl !== current.relayUrl ||
      candidate.hostSessionKeyCertificate?.certificate?.rootKid !== current.hostSessionKeyCertificate?.certificate?.rootKid ||
      candidate.hostSessionKeyCertificate?.certificate?.sessionId !== candidate.sessionId ||
      candidate.hostSessionKeyCertificate?.certificate?.repositorySha !== candidate.repositorySha
    ) return false;
    const width = (item: JsonObject, field: string) => BigInt(item[field]) - BigInt(item.createdAtMs);
    if (width(candidate, "invitationExpiresAtMs") > width(current, "invitationExpiresAtMs")) return false;
    if (width(candidate, "sessionDeadlineMs") > width(current, "sessionDeadlineMs")) return false;
    const currentTerms = current.terms as JsonObject | undefined;
    const candidateTerms = candidate.terms as JsonObject | undefined;
    if ((currentTerms === undefined) !== (candidateTerms === undefined)) return false;
    if (currentTerms !== undefined && v2CanonicalRecord(currentTerms).digest !== v2CanonicalRecord(candidateTerms as JsonObject).digest) return false;
    return true;
  }

  async function listedCandidates(current: JsonObject, inviteNow: number): Promise<JsonObject[] | null> {
    if (typeof options.relay.listSessions !== "function") return null;
    let listing: readonly RelaySessionListing[];
    try {
      listing = await options.relay.listSessions();
      if (!Array.isArray(listing)) return null;
    } catch {
      console.warn(JSON.stringify({ event: "agent_handshake_v2_session_list_unavailable" }));
      return null;
    }
    const ids: string[] = [];
    for (const entry of listing) {
      if (ids.length >= MULTI_SESSION_MAX_CANDIDATES) break;
      if (entry === null || typeof entry !== "object" || typeof entry.sessionId !== "string" || !UUID.test(entry.sessionId)) continue;
      if (entry.stage !== null && entry.stage !== undefined) continue;
      if (!Number.isFinite(entry.startedAtMs) || inviteNow - entry.startedAtMs > MULTI_SESSION_MAX_AGE_MS) continue;
      if (!ids.includes(entry.sessionId)) ids.push(entry.sessionId);
    }
    const others = ids.filter((id) => id !== current.sessionId);
    const fetched = await Promise.all(others.map(async (id) => {
      try {
        const candidate = discovery(await options.relay.fetchDiscovery(id));
        return candidate.sessionId === id && compatibleWithCurrent(current, candidate) ? candidate : null;
      } catch {
        return null;
      }
    }));
    const candidates = [current, ...fetched.filter((item): item is JsonObject => item !== null)];
    // Oldest free window first: keeps the freshest sessions for the next caller.
    candidates.sort((a, b) => {
      const left = BigInt(a.invitationExpiresAtMs);
      const right = BigInt(b.invitationExpiresAtMs);
      return left < right ? -1 : left > right ? 1 : 0;
    });
    return candidates;
  }

  async function selectInviteSession(current: JsonObject, inviteNow: number): Promise<JsonObject> {
    const candidates = (await listedCandidates(current, inviteNow)) ?? [current];
    let bestRetryMs: number | null = null;
    for (const candidate of candidates) {
      const busyRetryMs = await sessionBusyRetryMs(candidate, inviteNow);
      if (busyRetryMs === null) {
        if (reserveInviteSession(candidate, inviteNow)) return candidate;
        // Another invite in this process is minting into it right now.
        const reservedRetryMs = Math.max(inviteRetryHints(candidate, inviteNow).windowRetryMs, 15_000);
        bestRetryMs = bestRetryMs === null ? reservedRetryMs : Math.min(bestRetryMs, reservedRetryMs);
        continue;
      }
      bestRetryMs = bestRetryMs === null ? busyRetryMs : Math.min(bestRetryMs, busyRetryMs);
    }
    transient(bestRetryMs ?? inviteRetryHints(current, inviteNow).rotationRetryMs);
  }

  async function mintInvitation(found: JsonObject, terms: JsonObject, inviteNow: number): Promise<JsonObject> {
    const activeTerms = (found.terms as JsonObject | undefined) ?? terms;
    const { windowRetryMs } = inviteRetryHints(found, inviteNow);
    // The minted claim window is mint-relative at INVITATION_CLAIM_RUNWAY_MS,
    // capped only by the session deadline minus the landing margin. The host
    // observes agent_v2_invitation_created (posted below with the minted
    // expiry as claimExpiresAtMs) and extends its claim-observation bound to
    // match, so the window never outlives observation — the #141 orphan guard
    // — while a late-window mint still gets the full runway. A Responder too
    // slow to claim gets invitation_expired and the Initiator re-invites into
    // the next session rather than both sides stalling in an orphaned one.
    const invitationExpMs = String(Math.min(
      inviteNow + INVITATION_CLAIM_RUNWAY_MS,
      Number(found.sessionDeadlineMs) - INVITATION_CLAIM_LANDING_MARGIN_MS,
    ));
    const metadata = metadataFrom(found, activeTerms);
    let created;
    try {
      created = await options.invitationService.create({
        sessionId: found.sessionId,
        statementDigest: v2CanonicalRecord(activeTerms).digest,
        nbfMs: found.createdAtMs,
        expMs: found.sessionDeadlineMs,
        invitationExpMs,
        metadata,
        // Evaluated inside the store's serialized write: if the remaining window drops below the minimum
        // runway during create, the commit is refused atomically so no unclaimed invitation record is
        // left behind. Same invariant as the precheck above — a late commit must not shrink the runway.
        commitGuard: () => now() + INVITATION_MIN_RUNWAY_MS < Number(found.invitationExpiresAtMs),
      });
    } catch (error) {
      if (error instanceof V2InvitationWindowUnavailableError) transient(windowRetryMs);
      throw error;
    }
    const createdAtMs = now();
    const keyValue = await storeInitial(created.initiatorAccess, metadata, "initiator");
    await post(keyValue, "agent_v2_invitation_created", {
      claimExpiresAtMs: invitationExpMs,
      createdAtMs: String(createdAtMs),
      externalBusinessActionPerformed: false,
      statementDigest: v2CanonicalRecord(activeTerms).digest,
      terms: activeTerms,
    });
    const policy = localPolicy(activeTerms, "initiator") as JsonObject;
    return Object.freeze({ ...created, endpoint: V2_PUBLIC_ENDPOINT, sessionId: found.sessionId, invitationExpiresAtMs: invitationExpMs, sessionDeadlineMs: found.sessionDeadlineMs, terms: activeTerms, localPolicy: policy, localAction: setupLocalAction(options.verifiedHelperPrefix, policy, found.sessionId, "initiator", registerLocalActionCommand) });
  }

  return Object.freeze({
    async invite(value: unknown): Promise<JsonObject> {
      const terms = normalizeV2Terms(value) as JsonObject;
      const current = discovery(await options.relay.fetchDiscovery());
      const hostTerms = current.terms as JsonObject | undefined;
      if (hostTerms === undefined) {
        console.warn(JSON.stringify({ event: "agent_handshake_v2_invite_without_host_terms", sessionId: current.sessionId }));
      } else if (v2CanonicalRecord(terms).digest !== v2CanonicalRecord(hostTerms).digest) {
        throw new V2TermsMismatchError(hostTerms);
      }
      const inviteNow = now();
      // Picks a free session and reserves it (synchronously, after its last
      // await) so a concurrent invite in this process moves on to another one.
      const found = await selectInviteSession(current, inviteNow);
      try {
        return await mintInvitation(found, terms, inviteNow);
      } catch (error) {
        inviteReservations.delete(found.sessionId as string);
        throw error;
      }
    },

    async acceptInvitation(invitation: string, acceptanceIdempotencyKey?: string): Promise<JsonObject> {
      const accepted = await options.invitationService.accept({ invitation, acceptanceIdempotencyKey });
      if (!accepted.metadata || !accepted.claimedAtMs) fail();
      const build = async () => {
        const keyValue = await storeInitial(accepted.responderAccess, accepted.metadata!, "responder", "agent_handshake_v2_accept_without_host_terms");
        if (accepted.claim) await options.invitationService.advanceClaim({ claim: accepted.claim, phase: "initialized" });
        await post(keyValue, "agent_v2_invitation_claimed", {
          claimedAtMs: accepted.claimedAtMs,
          externalBusinessActionPerformed: false,
        });
        if (accepted.claim) await options.invitationService.advanceClaim({ claim: accepted.claim, phase: "posted" });
        const policy = localPolicy(accepted.metadata!.terms as JsonObject, "responder") as JsonObject;
        const sessionId = (accepted.metadata!.hostSessionKeyCertificate as JsonObject).certificate?.sessionId as string;
        const response = Object.freeze({ responderAccess: accepted.responderAccess, sessionId, terms: accepted.metadata!.terms, sessionDeadlineMs: accepted.metadata!.sessionDeadlineMs, localPolicy: policy, localAction: setupLocalAction(options.verifiedHelperPrefix, policy, sessionId, "responder", registerLocalActionCommand) });
        if (accepted.claim) await options.invitationService.advanceClaim({ claim: accepted.claim, phase: "completed", completedAtMs: String(now()) });
        return response;
      };
      return accepted.claim ? withClaimSerializer(accepted.claim, build) : build();
    },

    async join(input: { access: string; helperVersion: string; sessionKeyAddress: string; policyDigest: string }): Promise<JsonObject> {
      if (input.helperVersion !== V2_HELPER_VERSION || !ADDRESS.test(input.sessionKeyAddress) || !DIGEST.test(input.policyDigest)) fail();
      const sessionKeyAddress = input.sessionKeyAddress.toLowerCase();
      const auth = await authorize(input.access, "agent_handshake_join");
      const expectedPolicy = localPolicy(auth.current.terms, auth.verified.payload.role);
      if (v2CanonicalRecord(expectedPolicy).digest !== input.policyDigest) fail();
      if (auth.current.policyDigest && (auth.current.policyDigest !== input.policyDigest || auth.current.sessionKeyAddress !== sessionKeyAddress)) fail();
      const claim = normalizeV2IdentityClaim({
        schema: "clockchain.agent-handshake-identity-claim/v2", protocol: "clockchain.agent-handshake/v2",
        sessionId: auth.keyValue.session, repositorySha: auth.current.discovery.repositorySha,
        role: auth.verified.payload.role, sessionKeyAddress,
        policyDigest: input.policyDigest, statementDigest: v2CanonicalRecord(auth.current.terms).digest,
        externalBusinessActionPerformed: false,
      }) as JsonObject;
      const updated = await store.update(auth.keyValue, (current) => merge(current, auth.keyValue, {
        policyDigest: input.policyDigest, sessionKeyAddress,
        pending: { operation: "identity_claim", payload: claim }, stage: "sign_identity",
      }));
      const signingRequest = signRequest(data(updated), auth.verified.payload.role, "identity_claim", claim);
      return Object.freeze({
        role: auth.verified.payload.role, sessionId: auth.keyValue.session,
        repositorySha: auth.current.discovery.repositorySha, sessionDeadlineMs: auth.current.discovery.sessionDeadlineMs,
        signingSummary: signingSummary(signingRequest),
        localAction: signingLocalAction(options.verifiedHelperPrefix, signingRequest, registerLocalActionCommand),
      });
    },

    async status(input: { access: string }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_status");
      if (!auth.current.policyDigest || !auth.current.sessionKeyAddress) {
        return joinRequired(auth.verified.payload.role, auth.keyValue.session);
      }
      return Object.freeze({ role: auth.verified.payload.role, sessionId: auth.keyValue.session, stage: auth.current.stage ?? "invited", externalBusinessActionPerformed: false });
    },

    async next(input: { access: string; waitMs?: number }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_next");
      const role = auth.verified.payload.role;
      const waitMs = boundedNextWaitMs(input.waitMs ?? options.nextWaitDefaultMs);
      const startedMs = now();
      const sessionDeadlineMs = Number(auth.current.discovery.sessionDeadlineMs);
      // Long-poll only for messages after the highest seq already observed;
      // replaying the backlog with after=0 would return instantly and spin.
      let cursor: string | undefined;
      for (let polls = 0; ; polls += 1) {
        const result = await evaluateNext(auth, role);
        // retryAfterMs marks a dependency wait; signing requests, localActions,
        // join instructions, and terminal results never carry it.
        if (typeof result.retryAfterMs !== "number" || polls >= MAX_NEXT_WAIT_POLLS) return result;
        let budgetMs = waitMs - (now() - startedMs);
        if (Number.isSafeInteger(sessionDeadlineMs)) budgetMs = Math.min(budgetMs, sessionDeadlineMs - now());
        if (budgetMs <= 0) return result;
        const sliceMs = Math.min(NEXT_WAIT_POLL_MS, budgetMs);
        try {
          if (cursor === undefined) {
            const seeded = await options.relay.getMessages({ sessionId: auth.keyValue.session });
            cursor = seeded.highestSeq ?? "0";
          }
          const page = await options.relay.getMessages({ after: cursor, sessionId: auth.keyValue.session, waitMs: sliceMs });
          if (page.highestSeq !== undefined) cursor = page.highestSeq;
        } catch {
          await sleep(sliceMs);
        }
      }
    },

    async submitCheckpoint(input: { access: string; artifactSignatureHex: string; checkpoint: unknown }): Promise<JsonObject> {
      if (!SIGNATURE.test(input.artifactSignatureHex)) fail("signature_hex");
      const auth = await authorize(input.access, "agent_handshake_submit_checkpoint");
      const current = await refresh(auth.keyValue);
      const operation = current.pending?.operation;
      if (!current.sessionKeyAddress || (operation !== "proposal" && operation !== "acceptance")) fail("no_pending_signing_op");
      const pending = current.pending;
      if (!pending) fail("no_pending");
      const checkpoint = normalizeV2CommitmentCheckpoint(input.checkpoint) as JsonObject;
      const expectedRole = auth.verified.payload.role;
      const expectedSequence = operation === "proposal" ? "1" : "2";
      const expectedPrevious = operation === "proposal"
        ? null
        : current.proposalCheckpoint ? commitmentCheckpointDigest(current.proposalCheckpoint) : fail("missing_prior_proposal_checkpoint");
      const signature = checkpoint.signature as JsonObject;
      const mismatch =
        checkpoint.sessionId !== auth.keyValue.session ? "sessionId" :
        checkpoint.role !== expectedRole ? "role" :
        checkpoint.artifactType !== operation ? "artifactType" :
        checkpoint.sequence !== expectedSequence ? "sequence" :
        checkpoint.previousCheckpointDigest !== expectedPrevious ? "previousCheckpointDigest" :
        checkpoint.signerAddress !== current.sessionKeyAddress ? "signerAddress" :
        Number(checkpoint.issuedAtMs) > now() + CHECKPOINT_ISSUED_FUTURE_SKEW_MS ? "issuedAtMs_future" :
        Number(checkpoint.expiresAtMs) <= now() ? "expiresAtMs" : null;
      if (mismatch) fail(`checkpoint.${mismatch}`);
      const artifactBytes = canonicalBytes(pending.payload);
      const artifactSigner = (await options.recoverEip191Address({
        bytes: artifactBytes,
        signatureHex: input.artifactSignatureHex,
      })).toLowerCase();
      // The recovered signer and the stored payload's bytes hash are
      // session-scoped public data (the key is already published in
      // party_ready); carrying them in the log tag separates "signed by a
      // different key" from "signed over different bytes" in one line.
      if (artifactSigner !== current.sessionKeyAddress) {
        fail(`artifact_signer.${artifactSigner.slice(0, 12)}.${createHash("sha256").update(artifactBytes).digest("hex").slice(0, 8)}`);
      }
      const envelope = signatureEnvelope(operation, pending.payload, artifactSigner, input.artifactSignatureHex);
      const expectedArtifactDigest = v2CanonicalRecord(envelope).digest;
      if (checkpoint.artifactDigest !== expectedArtifactDigest) fail(`artifact_digest.${expectedArtifactDigest.slice(0, 8)}`);
      const recovered = (await options.recoverEip191Address({
        bytes: commitmentCheckpointSigningBytes(checkpoint),
        signatureHex: signature.value,
      })).toLowerCase();
      if (recovered !== current.sessionKeyAddress) fail(`checkpoint_signer.${recovered.slice(0, 12)}`);
      const field = operation === "proposal" ? "proposalCheckpoint" : "acceptanceCheckpoint";
      const prior = operation === "proposal" ? current.proposalCheckpoint : current.acceptanceCheckpoint;
      if (prior && commitmentCheckpointDigest(prior) !== commitmentCheckpointDigest(checkpoint)) fail("prior_checkpoint_mismatch");
      await post(auth.keyValue, "agent_v2_commitment_checkpoint", { checkpoint });
      await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { [field]: checkpoint }));
      return Object.freeze({
        role: expectedRole,
        sessionId: auth.keyValue.session,
        stage: `${operation}_checkpoint_submitted`,
        checkpointDigest: commitmentCheckpointDigest(checkpoint),
      });
    },

    async submit(input: { access: string; policyDigest: string; signatureHex: string }): Promise<JsonObject> {
      if (!DIGEST.test(input.policyDigest) || !SIGNATURE.test(input.signatureHex)) fail();
      const auth = await authorize(input.access, "agent_handshake_submit");
      const current = auth.current;
      if (!current.pending || current.policyDigest !== input.policyDigest || !current.sessionKeyAddress) fail();
      const bytes = canonicalBytes(current.pending.payload);
      const recovered = (await options.recoverEip191Address({ bytes, signatureHex: input.signatureHex })).toLowerCase();
      if (recovered !== current.sessionKeyAddress) fail();
      if (current.pending.operation === "identity_claim") {
        await post(auth.keyValue, "agent_v2_identity_claim", {
          claim: current.pending.payload,
          signature: { address: recovered, algorithm: "eip191", value: input.signatureHex },
        });
      } else if (current.pending.operation === "proposal") {
        const proposalEnvelope = signatureEnvelope("proposal", current.pending.payload, recovered, input.signatureHex);
        if (!current.proposalCheckpoint || current.proposalCheckpoint.artifactDigest !== v2CanonicalRecord(proposalEnvelope).digest) fail();
        await post(auth.keyValue, "agent_v2_proposal", { proposalEnvelope });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { proposalEnvelope }));
      } else if (current.pending.operation === "acceptance") {
        const acceptanceEnvelope = signatureEnvelope("acceptance", current.pending.payload, recovered, input.signatureHex);
        if (!current.acceptanceCheckpoint || current.acceptanceCheckpoint.artifactDigest !== v2CanonicalRecord(acceptanceEnvelope).digest) fail();
        await post(auth.keyValue, "agent_v2_acceptance", { acceptanceEnvelope });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { acceptanceEnvelope }));
      } else {
        await post(auth.keyValue, "agent_v2_evidence", { evidenceEnvelope: evidenceEnvelope(current.pending.payload, recovered, input.signatureHex) });
        await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { evidenceUploaded: true }));
      }
      const stage = current.pending.operation === "identity_claim" ? "identity_claimed" : `${current.pending.operation}_submitted`;
      await store.update(auth.keyValue, (value) => merge(value, auth.keyValue, { pending: null, stage }));
      return Object.freeze({ role: auth.verified.payload.role, sessionId: auth.keyValue.session, stage });
    },

    async getCertificate(input: { access: string }): Promise<JsonObject> {
      const auth = await authorize(input.access, "agent_handshake_get_certificate");
      if (!auth.current.evidenceUploaded) fail();
      return certificateResponse(auth.keyValue, auth.current, auth.verified.payload.role);
    },

    localActionCommand(commandSha256: string): string | null {
      if (!/^[0-9a-f]{64}$/.test(commandSha256)) return null;
      const entry = localActionCommands.get(commandSha256);
      if (!entry || entry.expiresAtMs <= now()) {
        localActionCommands.delete(commandSha256);
        return null;
      }
      return entry.command;
    },

    async invoke(name: string, args: JsonObject): Promise<unknown> {
      if (name === "agent_handshake_invite") return this.invite(args);
      if (name === "agent_handshake_accept_invitation") return this.acceptInvitation(args.invitation, typeof args.acceptanceIdempotencyKey === "string" ? args.acceptanceIdempotencyKey : undefined);
      if (name === "agent_handshake_join") return this.join(args as any);
      if (name === "agent_handshake_status") return this.status(args as any);
      if (name === "agent_handshake_next") return this.next(args as any);
      if (name === "agent_handshake_submit_checkpoint") return this.submitCheckpoint(args as any);
      if (name === "agent_handshake_submit") return this.submit(args as any);
      if (name === "agent_handshake_get_certificate") return this.getCertificate(args as any);
      fail();
    },
  });
}

const RUNTIME_KEY_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

function runtimeKeyFromEnvironment(raw: string | undefined): V2AccessKey {
  if (!raw) fail();
  try {
    const parsed = JSON.parse(raw) as { kid?: unknown; secretBase64?: unknown };
    if (
      parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "kid,secretBase64" ||
      typeof parsed.kid !== "string" || !RUNTIME_KEY_ID.test(parsed.kid) ||
      typeof parsed.secretBase64 !== "string"
    ) fail();
    const secret = Buffer.from(parsed.secretBase64, "base64");
    if (secret.length < 32 || secret.toString("base64") !== parsed.secretBase64) fail();
    return Object.freeze({ kid: parsed.kid, secret });
  } catch { fail(); }
}

function optionalRuntimeKeyFromEnvironment(raw: string | undefined): V2AccessKey | null {
  return raw ? runtimeKeyFromEnvironment(raw) : null;
}

function assertDistinctRuntimeKeys(groups: readonly (readonly V2AccessKey[])[]): void {
  const seenKids = new Set<string>();
  const seenSecrets = new Set<string>();
  for (const group of groups) {
    for (const keyValue of group) {
      const secret = keyValue.secret.toString("base64");
      if (seenKids.has(keyValue.kid) || seenSecrets.has(secret)) fail();
      seenKids.add(keyValue.kid);
      seenSecrets.add(secret);
    }
  }
}

export function __runtimeV2KeyConfig(env: Record<string, string | undefined>): {
  activeAccessKey: V2AccessKey;
  accessKeys: readonly V2AccessKey[];
  acceptanceHmacKeys: readonly V2AcceptanceHmacKey[];
} {
  const activeAccessKey = runtimeKeyFromEnvironment(env.AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE);
  const accessKeys = [activeAccessKey];
  const previousAccessKey = optionalRuntimeKeyFromEnvironment(env.AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS);
  if (previousAccessKey) accessKeys.push(previousAccessKey);
  const activeAcceptanceHmacKey = runtimeKeyFromEnvironment(env.AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE);
  const acceptanceHmacKeys = [activeAcceptanceHmacKey];
  const previousAcceptanceHmacKey = optionalRuntimeKeyFromEnvironment(env.AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS);
  if (previousAcceptanceHmacKey) acceptanceHmacKeys.push(previousAcceptanceHmacKey);
  assertDistinctRuntimeKeys([accessKeys, acceptanceHmacKeys]);
  return Object.freeze({
    activeAccessKey,
    accessKeys: Object.freeze(accessKeys),
    acceptanceHmacKeys: Object.freeze(acceptanceHmacKeys),
  });
}

async function fetchV2Discovery(relayUrl: string, sessionId?: string): Promise<unknown> {
  const path = sessionId ? `/v1/discovery/${encodeURIComponent(sessionId)}` : "/v1/discovery/current";
  const response = await fetch(`${relayUrl}${path}`, { headers: { accept: "application/json" } });
  if (!response.ok) fail();
  return response.json();
}

// GET /v1/runs: every session the relay holds, newest first (relay caps it at 50).
// Only the listing fields invite() needs are kept; anything malformed is dropped.
async function listV2Sessions(relayUrl: string): Promise<readonly RelaySessionListing[]> {
  const response = await fetch(`${relayUrl}/v1/runs`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(5_000) });
  if (!response.ok) fail();
  const body = await response.json() as unknown;
  const runs = (body !== null && typeof body === "object" && Array.isArray((body as JsonObject).runs)) ? (body as JsonObject).runs as unknown[] : null;
  if (runs === null) fail();
  const out: RelaySessionListing[] = [];
  for (const run of runs) {
    if (run === null || typeof run !== "object") continue;
    const item = run as JsonObject;
    if (typeof item.sessionId !== "string" || typeof item.startedAtMs !== "number") continue;
    out.push(Object.freeze({ sessionId: item.sessionId, startedAtMs: item.startedAtMs, stage: typeof item.stage === "string" ? item.stage : null }));
  }
  return Object.freeze(out);
}

export function runtimeRelay(relayUrl: string): Relay {
  const base = createHandshakeRelayClient({ relayUrl }) as unknown as Relay;
  return Object.freeze({
    ...base,
    fetchDiscovery: (sessionId?: string) => fetchV2Discovery(relayUrl, sessionId),
    listSessions: () => listV2Sessions(relayUrl),
  });
}

async function anchorV2(client: any, transition: JsonObject, canWrite: boolean): Promise<JsonObject | null> {
  const digest = v2CanonicalRecord(transition).digest;
  const reference = `agent-handshake-v2:${transition.sessionDigest}:${transition.kind.toLowerCase()}`;
  const found = (await client.searchAsset(reference)).filter((entry: JsonObject) => entry.assetReferenceId === reference && entry.assetHash === digest);
  if (found.length > 1) fail();
  let record = found[0];
  if (!record && canWrite) record = await client.log({ assetHash: digest, assetReferenceId: reference, additionalInfo: `agent handshake v2 ${transition.kind}` });
  if (!record) return null;
  const ledgerId = String(record.ledgerId ?? "");
  if (!UUID.test(ledgerId)) fail();
  const ledger = await client.getLedgerEntry(ledgerId);
  if (
    !ledger || typeof ledger !== "object" || ledger.blockHeight === undefined || ledger.blockHeight === null ||
    ledger.ledgerId === undefined || ledger.ledgerId === null || ledger.assetHash === undefined ||
    ledger.assetHash === null || ledger.assetReferenceId === undefined || ledger.assetReferenceId === null
  ) transient();
  const blockHeight = String(ledger.blockHeight ?? "");
  if (!DECIMAL.test(blockHeight) || ledger.ledgerId !== ledgerId || ledger.assetHash !== digest || ledger.assetReferenceId !== reference) fail();
  const chain = await client.getChainRecord(blockHeight, ledgerId);
  if (
    !chain || typeof chain !== "object" || chain.blockHeight === undefined || chain.blockHeight === null ||
    chain.assetHash === undefined || chain.assetHash === null ||
    chain.assetReferenceId === undefined || chain.assetReferenceId === null
  ) transient();
  if (!chain || chain.assetHash !== digest || chain.assetReferenceId !== reference || String(chain.blockHeight) !== blockHeight) fail();
  const block = await client.getBlock(blockHeight);
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  if (!blockTimeRaw) transient();
  return Object.freeze({ blockTimeRaw, digest, message: transition, onChain: Object.freeze({ blockHeight, ledgerId }) });
}

export async function __advanceRuntimeV2(client: any, input: { descriptor: JsonObject; role: V2Role; existing: readonly JsonObject[] }): Promise<JsonObject[]> {
  const descriptor = input.descriptor;
  const sessionDigest = v2CanonicalRecord(descriptor).digest;
  const base = {
    expiresAtMs: descriptor.agreementExpiresAtMs,
    externalBusinessActionPerformed: false,
    initiator: descriptor.initiator,
    protocol: "clockchain.agent-handshake/v2",
    reference: descriptor.reference,
    responder: descriptor.responder,
    schema: "clockchain.agent-handshake-transition/v2",
    sessionDigest,
    statementDigest: descriptor.statementDigest,
  };
  const transitions = [
    { ...base, kind: "PROPOSED", predecessor: null, sequence: "1" },
    { ...base, kind: "ACCEPTED", predecessor: "", sequence: "2" },
    { ...base, kind: "ACKNOWLEDGED", predecessor: "", sequence: "3" },
  ];
  transitions[1].predecessor = v2CanonicalRecord(transitions[0]).digest;
  transitions[2].predecessor = v2CanonicalRecord(transitions[1]).digest;
  const receipts: JsonObject[] = [];
  for (let index = 0; index < transitions.length; index += 1) {
    const owner = index === 1 ? "responder" : "initiator";
    const anchored = await anchorV2(client, transitions[index], input.role === owner);
    if (!anchored) return receipts;
    receipts.push(anchored);
  }
  return receipts;
}

export function createRuntimeV2Coordinator(env: Record<string, string | undefined> = process.env) {
  const releasePin = readV2ReleasePin(env);
  const { activeAccessKey, accessKeys, acceptanceHmacKeys } = __runtimeV2KeyConfig(env);
  const relayUrl = normalizeRelayBaseUrl(env.HANDSHAKE_RELAY ?? "");
  const relay = runtimeRelay(relayUrl);
  const invitationStore = createV2InvitationStore({ path: env.AGENT_HANDSHAKE_V2_INVITATION_FILE });
  const invitationService = createV2InvitationService({ activeKey: activeAccessKey, verificationKeys: accessKeys, acceptanceHmacKeys, store: invitationStore });
  const clockchain = new ClockchainClient(readConfigFromEnv(env));
  const rpcUrl = env.EVM_RPC_URL ?? env.SEPOLIA_RPC_URL;
  if (!rpcUrl) fail();
  return createV2Coordinator({
    accessKeys,
    activeAccessKey,
    invitationService,
    relay,
    stateStore: createIsolatedHandshakeStateStore(env.AGENT_HANDSHAKE_V2_STATE_FILE),
    recoverEip191Address: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl }),
    registrationFundingReady: async ({ address }) => {
      try {
        return await readEvmBalance({ address, rpcUrl }) >= MIN_REGISTRATION_BALANCE_WEI;
      } catch {
        return false;
      }
    },
    resolveRegistration: async ({ address, fromBlock }) => {
      const found = await resolveOwnedAgentRegistration({
        address, fromBlock, registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e", rpcUrl,
      });
      return found ? Object.freeze({
        agentId: found.agentId,
        chainId: "eip155:11155111",
        registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${found.agentId}`,
        registrationTx: found.registrationTx,
        registrationBlock: found.registrationBlock,
      }) : null;
    },
    advanceTransitions: (input) => __advanceRuntimeV2(clockchain, input),
    verifiedHelperPrefix: verifiedV2HelperPrefix(releasePin),
  });
}
