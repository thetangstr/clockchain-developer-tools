import { createHash, createHmac, randomUUID as systemRandomUUID, timingSafeEqual } from "node:crypto";
import {
  chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync,
  renameSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import {
  AGENT_HANDSHAKE_INVITATION_TOOLS,
  AGENT_HANDSHAKE_ROLE_TOOLS,
  mintV2RoleAccess,
  readV2RoleAccessPayload,
  verifyV2RoleAccess,
  type V2AccessKey,
} from "./access.js";
import { normalizeV2Terms, v2CanonicalRecord } from "./protocol.js";

const STORE_SCHEMA_V1 = "clockchain.agent-handshake-v2-invitations/v1";
const STORE_SCHEMA = "clockchain.agent-handshake-v2-invitations/v2";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CLAIM_PHASES = ["claimed", "initialized", "posted", "completed"] as const;

type ClaimPhase = typeof CLAIM_PHASES[number];
type StoredClaim = Readonly<{
  phase: ClaimPhase;
  claimedAtMs: string;
  acceptanceKeyKid: string;
  acceptanceKeyDigest: string;
  responderAccessKid: string;
  responderAccessJti: string;
  responderAccessNbfMs: string;
  responderAccessExpMs: string;
  completedAtMs: string | null;
}> | Readonly<{
  phase: "legacy_terminal";
  claimedAtMs: string;
}>;

type StoredInvitation = Readonly<{
  invitationDigest: string;
  jti: string;
  sessionId: string;
  statementDigest: string;
  expMs: string;
  claim: StoredClaim | null;
  metadata: V2InvitationMetadata | null;
}>;

export type V2InvitationMetadata = Readonly<{
  terms: Readonly<Record<string, unknown>>;
  repositorySha: string;
  hostSessionKeyCertificate: Readonly<Record<string, unknown>>;
  invitationExpiresAtMs: string;
  sessionDeadlineMs: string;
  createdAtMs: string;
  sessionOpenedBlock: string;
}>;

export class V2InvitationError extends Error {
  constructor() {
    super("Agent handshake invitation is unavailable.");
    this.name = "V2InvitationError";
  }
}

function unavailable(): never { throw new V2InvitationError(); }
function digest(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function hmacDigest(secret: Buffer, value: string): string { return createHmac("sha256", secret).update(value, "utf8").digest("hex"); }

function sameDigest(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function validIdempotencyKey(value: string): boolean {
  if (UUID_V4.test(value)) return true;
  if (!BASE64URL.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length >= 16 && decoded.toString("base64url") === value;
}

function hmacKey(value: V2AcceptanceHmacKey): V2AcceptanceHmacKey {
  if (!KID.test(value?.kid) || !Buffer.isBuffer(value?.secret) || value.secret.length < 32) unavailable();
  return Object.freeze({ kid: value.kid, secret: Buffer.from(value.secret) });
}

function metadata(value: unknown, expectedStatementDigest: string): V2InvitationMetadata | null {
  if (value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) unavailable();
  const item = value as Record<string, unknown>;
  const keys = ["terms", "repositorySha", "hostSessionKeyCertificate", "invitationExpiresAtMs", "sessionDeadlineMs", "createdAtMs", "sessionOpenedBlock"].sort();
  if (Object.keys(item).sort().join(",") !== keys.join(",")) unavailable();
  let terms;
  try { terms = normalizeV2Terms(item.terms); } catch { unavailable(); }
  if (
    v2CanonicalRecord(terms).digest !== expectedStatementDigest ||
    typeof item.repositorySha !== "string" || !/^[0-9a-f]{40}$/.test(item.repositorySha) ||
    item.hostSessionKeyCertificate === null || typeof item.hostSessionKeyCertificate !== "object" || Array.isArray(item.hostSessionKeyCertificate) ||
    typeof item.invitationExpiresAtMs !== "string" || !DECIMAL.test(item.invitationExpiresAtMs) ||
    typeof item.sessionDeadlineMs !== "string" || !DECIMAL.test(item.sessionDeadlineMs) ||
    typeof item.createdAtMs !== "string" || !DECIMAL.test(item.createdAtMs) ||
    typeof item.sessionOpenedBlock !== "string" || !DECIMAL.test(item.sessionOpenedBlock) ||
    BigInt(item.createdAtMs) >= BigInt(item.invitationExpiresAtMs) ||
    BigInt(item.invitationExpiresAtMs) > BigInt(item.sessionDeadlineMs)
  ) unavailable();
  return Object.freeze({
    terms,
    repositorySha: item.repositorySha,
    hostSessionKeyCertificate: Object.freeze(JSON.parse(JSON.stringify(item.hostSessionKeyCertificate))),
    invitationExpiresAtMs: item.invitationExpiresAtMs,
    sessionDeadlineMs: item.sessionDeadlineMs,
    createdAtMs: item.createdAtMs,
    sessionOpenedBlock: item.sessionOpenedBlock,
  });
}

function claim(value: unknown): StoredClaim | null {
  if (value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) unavailable();
  const item = value as Record<string, unknown>;
  if (item.phase === "legacy_terminal") {
    const expected = ["phase", "claimedAtMs"].sort();
    const keys = Object.keys(item).sort();
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
    if (typeof item.claimedAtMs !== "string" || !DECIMAL.test(item.claimedAtMs)) unavailable();
    return Object.freeze({ phase: "legacy_terminal", claimedAtMs: item.claimedAtMs });
  }
  const expected = [
    "phase", "claimedAtMs", "acceptanceKeyKid", "acceptanceKeyDigest", "responderAccessKid",
    "responderAccessJti", "responderAccessNbfMs", "responderAccessExpMs", "completedAtMs",
  ].sort();
  const keys = Object.keys(item).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
  if (
    typeof item.phase !== "string" || !CLAIM_PHASES.includes(item.phase as ClaimPhase) ||
    typeof item.claimedAtMs !== "string" || !DECIMAL.test(item.claimedAtMs) ||
    typeof item.acceptanceKeyKid !== "string" || !KID.test(item.acceptanceKeyKid) ||
    typeof item.acceptanceKeyDigest !== "string" || !DIGEST.test(item.acceptanceKeyDigest) ||
    typeof item.responderAccessKid !== "string" || !KID.test(item.responderAccessKid) ||
    typeof item.responderAccessJti !== "string" || !UUID.test(item.responderAccessJti) ||
    typeof item.responderAccessNbfMs !== "string" || !DECIMAL.test(item.responderAccessNbfMs) ||
    typeof item.responderAccessExpMs !== "string" || !DECIMAL.test(item.responderAccessExpMs) ||
    item.completedAtMs !== null && (typeof item.completedAtMs !== "string" || !DECIMAL.test(item.completedAtMs))
  ) unavailable();
  if (BigInt(item.responderAccessNbfMs) >= BigInt(item.responderAccessExpMs)) unavailable();
  return Object.freeze({
    phase: item.phase as ClaimPhase,
    claimedAtMs: item.claimedAtMs,
    acceptanceKeyKid: item.acceptanceKeyKid,
    acceptanceKeyDigest: item.acceptanceKeyDigest,
    responderAccessKid: item.responderAccessKid,
    responderAccessJti: item.responderAccessJti,
    responderAccessNbfMs: item.responderAccessNbfMs,
    responderAccessExpMs: item.responderAccessExpMs,
    completedAtMs: item.completedAtMs,
  });
}

function v2Record(value: unknown): StoredInvitation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) unavailable();
  const item = value as Record<string, unknown>;
  const keys = Object.keys(item).sort();
  const expected = ["invitationDigest", "jti", "sessionId", "statementDigest", "expMs", "claim", "metadata"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
  if (
    typeof item.invitationDigest !== "string" || !DIGEST.test(item.invitationDigest) ||
    typeof item.jti !== "string" || !UUID.test(item.jti) ||
    typeof item.sessionId !== "string" || !UUID.test(item.sessionId) ||
    typeof item.statementDigest !== "string" || !DIGEST.test(item.statementDigest) ||
    typeof item.expMs !== "string" || !DECIMAL.test(item.expMs)
  ) unavailable();
  return Object.freeze({
    invitationDigest: item.invitationDigest,
    jti: item.jti,
    sessionId: item.sessionId,
    statementDigest: item.statementDigest,
    expMs: item.expMs,
    claim: claim(item.claim),
    metadata: metadata(item.metadata, item.statementDigest as string),
  });
}

function v1Record(value: unknown): StoredInvitation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) unavailable();
  const item = value as Record<string, unknown>;
  const keys = Object.keys(item).sort();
  const expected = ["invitationDigest", "jti", "sessionId", "statementDigest", "expMs", "claimedAtMs", "metadata"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
  if (
    typeof item.invitationDigest !== "string" || !DIGEST.test(item.invitationDigest) ||
    typeof item.jti !== "string" || !UUID.test(item.jti) ||
    typeof item.sessionId !== "string" || !UUID.test(item.sessionId) ||
    typeof item.statementDigest !== "string" || !DIGEST.test(item.statementDigest) ||
    typeof item.expMs !== "string" || !DECIMAL.test(item.expMs) ||
    item.claimedAtMs !== null && (typeof item.claimedAtMs !== "string" || !DECIMAL.test(item.claimedAtMs))
  ) unavailable();
  return Object.freeze({
    invitationDigest: item.invitationDigest,
    jti: item.jti,
    sessionId: item.sessionId,
    statementDigest: item.statementDigest,
    expMs: item.expMs,
    claim: item.claimedAtMs === null ? null : Object.freeze({ phase: "legacy_terminal", claimedAtMs: item.claimedAtMs }),
    metadata: metadata(item.metadata, item.statementDigest),
  });
}

function read(path: string): Map<string, StoredInvitation> {
  try {
    const link = lstatSync(path);
    const stat = statSync(path);
    if (!link.isFile() || link.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) unavailable();
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    if (
      Object.keys(parsed).sort().join(",") !== "records,schema" ||
      ![STORE_SCHEMA, STORE_SCHEMA_V1].includes(parsed.schema as string) ||
      parsed.records === null || typeof parsed.records !== "object" || Array.isArray(parsed.records)
    ) unavailable();
    const records = new Map<string, StoredInvitation>();
    for (const [jti, value] of Object.entries(parsed.records as Record<string, unknown>)) {
      const verified = parsed.schema === STORE_SCHEMA ? v2Record(value) : v1Record(value);
      if (jti !== verified.jti || records.has(jti)) unavailable();
      records.set(jti, verified);
    }
    return records;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    if (error instanceof V2InvitationError) throw error;
    unavailable();
  }
}

function persist(path: string, records: Map<string, StoredInvitation>): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  chmodSync(parent, 0o700);
  const parentStat = statSync(parent);
  if (!parentStat.isDirectory() || (parentStat.mode & 0o077) !== 0) unavailable();
  const temporary = `${path}.${process.pid}.${systemRandomUUID()}.tmp`;
  const body = JSON.stringify({
    schema: STORE_SCHEMA,
    records: Object.fromEntries([...records.entries()].sort(([left], [right]) => left.localeCompare(right))),
  }) + "\n";
  try {
    writeFileSync(temporary, body, { flag: "wx", mode: 0o600 });
    const file = openSync(temporary, "r");
    try { fsyncSync(file); } finally { closeSync(file); }
    renameSync(temporary, path);
    const directory = openSync(parent, "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* retain the original error */ }
    throw error;
  }
}

export interface V2InvitationStore {
  put(value: StoredInvitation): Promise<void>;
  get(jti: string): Promise<StoredInvitation | null>;
  claim(input: { invitationDigest: string; jti: string; nowMs: string }): Promise<StoredInvitation>;
  beginClaim(input: {
    invitationDigest: string;
    jti: string;
    nowMs: string;
    acceptanceKey?: { kid: string; digest: string };
    responderAccess?: { kid: string; jti: string; nbfMs: string; expMs: string };
  }): Promise<StoredInvitation>;
  advanceClaim(input: {
    invitationDigest: string;
    jti: string;
    acceptanceKey: { kid: string; digest: string };
    phase: ClaimPhase;
    completedAtMs?: string;
  }): Promise<StoredInvitation>;
}

export function createV2InvitationStore(options: { path?: string } = {}): V2InvitationStore {
  let records = options.path ? read(options.path) : new Map<string, StoredInvitation>();
  let queue = Promise.resolve();
  function exclusively<T>(operation: () => T): Promise<T> {
    const result = queue.then(operation, operation);
    queue = result.then(() => undefined, () => undefined);
    return result;
  }
  function save(): void { if (options.path) persist(options.path, records); }
  return Object.freeze({
    get(jti: string): Promise<StoredInvitation | null> {
      const current = records.get(jti);
      return Promise.resolve(current ? v2Record(current) : null);
    },
    put(value: StoredInvitation): Promise<void> {
      return exclusively(() => {
        const verified = v2Record(value);
        if (records.has(verified.jti)) unavailable();
        records = new Map(records).set(verified.jti, verified);
        save();
      });
    },
    claim(input: { invitationDigest: string; jti: string; nowMs: string }): Promise<StoredInvitation> {
      return this.beginClaim(input);
    },
    beginClaim(input: {
      invitationDigest: string;
      jti: string;
      nowMs: string;
      acceptanceKey?: { kid: string; digest: string };
      responderAccess?: { kid: string; jti: string; nbfMs: string; expMs: string };
    }): Promise<StoredInvitation> {
      return exclusively(() => {
        const current = records.get(input.jti);
        if (
          !current || current.invitationDigest !== input.invitationDigest || !DECIMAL.test(input.nowMs)
        ) unavailable();
        if (current.claim !== null) {
          if (
            current.claim.phase === "legacy_terminal" || !input.acceptanceKey ||
            current.claim.acceptanceKeyKid !== input.acceptanceKey.kid ||
            !sameDigest(current.claim.acceptanceKeyDigest, input.acceptanceKey.digest) ||
            BigInt(input.nowMs) >= BigInt(current.claim.responderAccessExpMs)
          ) unavailable();
          return current;
        }
        if (BigInt(input.nowMs) >= BigInt(current.expMs)) unavailable();
        let nextClaim: StoredClaim;
        if (!input.acceptanceKey) {
          nextClaim = Object.freeze({ phase: "legacy_terminal", claimedAtMs: input.nowMs });
        } else {
          if (
            !input.responderAccess ||
            !KID.test(input.acceptanceKey.kid) || !DIGEST.test(input.acceptanceKey.digest) ||
            !KID.test(input.responderAccess.kid) || !UUID.test(input.responderAccess.jti) ||
            !DECIMAL.test(input.responderAccess.nbfMs) || !DECIMAL.test(input.responderAccess.expMs) ||
            BigInt(input.responderAccess.nbfMs) >= BigInt(input.responderAccess.expMs)
          ) unavailable();
          nextClaim = Object.freeze({
            phase: "claimed",
            claimedAtMs: input.nowMs,
            acceptanceKeyKid: input.acceptanceKey.kid,
            acceptanceKeyDigest: input.acceptanceKey.digest,
            responderAccessKid: input.responderAccess.kid,
            responderAccessJti: input.responderAccess.jti,
            responderAccessNbfMs: input.responderAccess.nbfMs,
            responderAccessExpMs: input.responderAccess.expMs,
            completedAtMs: null,
          });
        }
        const claimed = Object.freeze({ ...current, claim: nextClaim });
        records = new Map(records).set(current.jti, claimed);
        save();
        return claimed;
      });
    },
    advanceClaim(input: {
      invitationDigest: string;
      jti: string;
      acceptanceKey: { kid: string; digest: string };
      phase: ClaimPhase;
      completedAtMs?: string;
    }): Promise<StoredInvitation> {
      return exclusively(() => {
        const current = records.get(input.jti);
        if (
          !current || current.invitationDigest !== input.invitationDigest ||
          current.claim === null || current.claim.phase === "legacy_terminal" ||
          !input.acceptanceKey || current.claim.acceptanceKeyKid !== input.acceptanceKey.kid ||
          !sameDigest(current.claim.acceptanceKeyDigest, input.acceptanceKey.digest)
        ) unavailable();
        const currentIndex = CLAIM_PHASES.indexOf(current.claim.phase);
        const nextIndex = CLAIM_PHASES.indexOf(input.phase);
        if (nextIndex === -1) unavailable();
        if (nextIndex <= currentIndex) return current;
        if (input.phase === "completed" && (input.completedAtMs === undefined || !DECIMAL.test(input.completedAtMs))) unavailable();
        const nextClaim = Object.freeze({
          ...current.claim,
          phase: input.phase,
          completedAtMs: input.phase === "completed" ? input.completedAtMs! : current.claim.completedAtMs,
        });
        const advanced = Object.freeze({ ...current, claim: nextClaim });
        records = new Map(records).set(current.jti, advanced);
        save();
        return advanced;
      });
    },
  });
}

export type V2AcceptanceHmacKey = Readonly<{ kid: string; secret: Buffer }>;

export function createV2InvitationService(options: {
  activeKey: V2AccessKey;
  verificationKeys: readonly V2AccessKey[];
  acceptanceHmacKeys?: readonly V2AcceptanceHmacKey[];
  store: V2InvitationStore;
  nowMs?: () => number;
  randomUUID?: () => string;
}) {
  const nowMs = options.nowMs ?? Date.now;
  const nextId = options.randomUUID ?? systemRandomUUID;
  const acceptanceHmacKeys = (options.acceptanceHmacKeys ?? []).map(hmacKey);
  if (new Set(acceptanceHmacKeys.map((entry) => entry.kid)).size !== acceptanceHmacKeys.length) unavailable();
  const signingKeys = [options.activeKey, ...options.verificationKeys.filter((entry) => entry.kid !== options.activeKey.kid)];
  function acceptanceKey(value: string, storedKid?: string): { kid: string; digest: string } {
    if (!validIdempotencyKey(value)) unavailable();
    const key = storedKid === undefined ? acceptanceHmacKeys[0] : acceptanceHmacKeys.find((entry) => entry.kid === storedKid);
    if (!key) unavailable();
    return Object.freeze({ kid: key.kid, digest: hmacDigest(key.secret, value) });
  }
  function signingKey(kid: string): V2AccessKey {
    const found = signingKeys.find((entry) => entry.kid === kid);
    if (!found) unavailable();
    return found;
  }
  function responderAccess(stored: StoredInvitation, storedClaim: StoredClaim): string {
    if (storedClaim.phase === "legacy_terminal") unavailable();
    return mintV2RoleAccess({
      key: signingKey(storedClaim.responderAccessKid),
      jti: storedClaim.responderAccessJti,
      sessionId: stored.sessionId,
      role: "responder",
      statementDigest: stored.statementDigest,
      allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
      nbfMs: storedClaim.responderAccessNbfMs,
      expMs: storedClaim.responderAccessExpMs,
    });
  }
  return Object.freeze({
    async create(input: { sessionId: string; statementDigest: string; nbfMs: string | number; expMs: string | number; invitationExpMs?: string | number; metadata?: V2InvitationMetadata }) {
      const invitationExpMs = input.invitationExpMs ?? input.expMs;
      const initiatorAccess = mintV2RoleAccess({
        key: options.activeKey, jti: nextId(), sessionId: input.sessionId, role: "initiator",
        statementDigest: input.statementDigest, allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
        nbfMs: input.nbfMs, expMs: input.expMs,
      });
      const invitationJti = nextId();
      const responderInvitation = mintV2RoleAccess({
        key: options.activeKey, jti: invitationJti, sessionId: input.sessionId, role: "responder",
        statementDigest: input.statementDigest, allowedTools: AGENT_HANDSHAKE_INVITATION_TOOLS,
        nbfMs: input.nbfMs, expMs: invitationExpMs,
      });
      await options.store.put({
        invitationDigest: digest(responderInvitation), jti: invitationJti,
        sessionId: input.sessionId, statementDigest: input.statementDigest,
        expMs: String(invitationExpMs), claim: null, metadata: input.metadata ?? null,
      });
      return Object.freeze({ initiatorAccess, responderInvitation });
    },
    async accept(input: { invitation: string; sessionId?: string; statementDigest?: string; expMs?: string | number; acceptanceIdempotencyKey?: string }) {
      const untrusted = readV2RoleAccessPayload(input.invitation);
      const stored = await options.store.get(untrusted.jti);
      if (!stored) unavailable();
      if (input.sessionId !== undefined && input.sessionId !== stored.sessionId) unavailable();
      if (input.statementDigest !== undefined && input.statementDigest !== stored.statementDigest) unavailable();
      if (input.expMs !== undefined && String(input.expMs) !== stored.expMs) unavailable();
      const now = nowMs();
      const existingClaim = stored.claim?.phase === "legacy_terminal" ? stored.claim : stored.claim;
      const verificationNow = existingClaim && existingClaim.phase !== "legacy_terminal" && now >= Number(stored.expMs)
        ? Number(stored.expMs) - 1
        : now;
      const verified = verifyV2RoleAccess(input.invitation, {
        keys: options.verificationKeys, nowMs: verificationNow, expectedSessionId: stored.sessionId,
        expectedRole: "responder", expectedStatementDigest: stored.statementDigest,
        expectedExpMs: stored.expMs, requiredTool: "agent_handshake_accept_invitation",
      });
      const keyedAcceptance = input.acceptanceIdempotencyKey === undefined ? undefined : acceptanceKey(
        input.acceptanceIdempotencyKey,
        existingClaim && existingClaim.phase !== "legacy_terminal" ? existingClaim.acceptanceKeyKid : undefined,
      );
      const responderAccessJti = existingClaim && existingClaim.phase !== "legacy_terminal" ? existingClaim.responderAccessJti : nextId();
      const responderAccessNbfMs = existingClaim && existingClaim.phase !== "legacy_terminal" ? existingClaim.responderAccessNbfMs : verified.payload.nbfMs;
      const responderAccessExpMs = existingClaim && existingClaim.phase !== "legacy_terminal" ? existingClaim.responderAccessExpMs : stored.metadata?.sessionDeadlineMs ?? stored.expMs;
      const responderAccessKid = existingClaim && existingClaim.phase !== "legacy_terminal" ? existingClaim.responderAccessKid : options.activeKey.kid;
      const claimed = await options.store.beginClaim({
        invitationDigest: digest(input.invitation), jti: verified.payload.jti, nowMs: String(now),
        acceptanceKey: keyedAcceptance,
        responderAccess: keyedAcceptance ? {
          kid: responderAccessKid,
          jti: responderAccessJti,
          nbfMs: responderAccessNbfMs,
          expMs: responderAccessExpMs,
        } : undefined,
      });
      const currentClaim = claimed.claim;
      let access: string;
      if (currentClaim && currentClaim.phase !== "legacy_terminal") {
        access = responderAccess(claimed, currentClaim);
      } else {
        access = mintV2RoleAccess({
          key: options.activeKey, jti: nextId(), sessionId: stored.sessionId, role: "responder",
          statementDigest: stored.statementDigest, allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
          nbfMs: verified.payload.nbfMs, expMs: stored.metadata?.sessionDeadlineMs ?? stored.expMs,
        });
      }
      return Object.freeze({
        claimedAtMs: currentClaim?.claimedAtMs ?? null,
        responderAccess: access,
        metadata: stored.metadata,
        claim: currentClaim && currentClaim.phase !== "legacy_terminal" ? Object.freeze({
          invitationDigest: claimed.invitationDigest,
          jti: claimed.jti,
          acceptanceKey: Object.freeze({
            kid: currentClaim.acceptanceKeyKid,
            digest: currentClaim.acceptanceKeyDigest,
          }),
          phase: currentClaim.phase,
          claimedAtMs: currentClaim.claimedAtMs,
        }) : null,
      });
    },
  });
}
