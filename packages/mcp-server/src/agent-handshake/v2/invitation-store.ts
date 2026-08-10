import { createHash, randomUUID as systemRandomUUID } from "node:crypto";
import {
  chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync,
  renameSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import {
  AGENT_HANDSHAKE_INVITATION_TOOLS,
  AGENT_HANDSHAKE_ROLE_TOOLS,
  mintV2RoleAccess,
  verifyV2RoleAccess,
  type V2AccessKey,
} from "./access.js";

const STORE_SCHEMA = "clockchain.agent-handshake-v2-invitations/v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

type StoredInvitation = Readonly<{
  invitationDigest: string;
  jti: string;
  sessionId: string;
  statementDigest: string;
  expMs: string;
  claimedAtMs: string | null;
}>;

export class V2InvitationError extends Error {
  constructor() {
    super("Agent handshake invitation is unavailable.");
    this.name = "V2InvitationError";
  }
}

function unavailable(): never { throw new V2InvitationError(); }
function digest(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }

function record(value: unknown): StoredInvitation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) unavailable();
  const item = value as Record<string, unknown>;
  const keys = Object.keys(item).sort();
  const expected = ["invitationDigest", "jti", "sessionId", "statementDigest", "expMs", "claimedAtMs"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
  if (
    typeof item.invitationDigest !== "string" || !DIGEST.test(item.invitationDigest) ||
    typeof item.jti !== "string" || !UUID.test(item.jti) ||
    typeof item.sessionId !== "string" || !UUID.test(item.sessionId) ||
    typeof item.statementDigest !== "string" || !DIGEST.test(item.statementDigest) ||
    typeof item.expMs !== "string" || !DECIMAL.test(item.expMs) ||
    item.claimedAtMs !== null && (typeof item.claimedAtMs !== "string" || !DECIMAL.test(item.claimedAtMs))
  ) unavailable();
  return Object.freeze(item as StoredInvitation);
}

function read(path: string): Map<string, StoredInvitation> {
  try {
    const link = lstatSync(path);
    const stat = statSync(path);
    if (!link.isFile() || link.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) unavailable();
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    if (Object.keys(parsed).sort().join(",") !== "records,schema" || parsed.schema !== STORE_SCHEMA || parsed.records === null || typeof parsed.records !== "object" || Array.isArray(parsed.records)) unavailable();
    const records = new Map<string, StoredInvitation>();
    for (const [jti, value] of Object.entries(parsed.records as Record<string, unknown>)) {
      const verified = record(value);
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
  claim(input: { invitationDigest: string; jti: string; nowMs: string }): Promise<StoredInvitation>;
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
    put(value: StoredInvitation): Promise<void> {
      return exclusively(() => {
        const verified = record(value);
        if (records.has(verified.jti)) unavailable();
        records = new Map(records).set(verified.jti, verified);
        save();
      });
    },
    claim(input: { invitationDigest: string; jti: string; nowMs: string }): Promise<StoredInvitation> {
      return exclusively(() => {
        const current = records.get(input.jti);
        if (
          !current || current.invitationDigest !== input.invitationDigest ||
          current.claimedAtMs !== null || !DECIMAL.test(input.nowMs) ||
          BigInt(input.nowMs) >= BigInt(current.expMs)
        ) unavailable();
        const claimed = Object.freeze({ ...current, claimedAtMs: input.nowMs });
        records = new Map(records).set(current.jti, claimed);
        save();
        return claimed;
      });
    },
  });
}

export function createV2InvitationService(options: {
  activeKey: V2AccessKey;
  verificationKeys: readonly V2AccessKey[];
  store: V2InvitationStore;
  nowMs?: () => number;
  randomUUID?: () => string;
}) {
  const nowMs = options.nowMs ?? Date.now;
  const nextId = options.randomUUID ?? systemRandomUUID;
  return Object.freeze({
    async create(input: { sessionId: string; statementDigest: string; nbfMs: string | number; expMs: string | number }) {
      const initiatorAccess = mintV2RoleAccess({
        key: options.activeKey, jti: nextId(), sessionId: input.sessionId, role: "initiator",
        statementDigest: input.statementDigest, allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
        nbfMs: input.nbfMs, expMs: input.expMs,
      });
      const invitationJti = nextId();
      const responderInvitation = mintV2RoleAccess({
        key: options.activeKey, jti: invitationJti, sessionId: input.sessionId, role: "responder",
        statementDigest: input.statementDigest, allowedTools: AGENT_HANDSHAKE_INVITATION_TOOLS,
        nbfMs: input.nbfMs, expMs: input.expMs,
      });
      await options.store.put({
        invitationDigest: digest(responderInvitation), jti: invitationJti,
        sessionId: input.sessionId, statementDigest: input.statementDigest,
        expMs: String(input.expMs), claimedAtMs: null,
      });
      return Object.freeze({ initiatorAccess, responderInvitation });
    },
    async accept(input: { invitation: string; sessionId: string; statementDigest: string; expMs: string | number }) {
      const verified = verifyV2RoleAccess(input.invitation, {
        keys: options.verificationKeys, nowMs: nowMs(), expectedSessionId: input.sessionId,
        expectedRole: "responder", expectedStatementDigest: input.statementDigest,
        expectedExpMs: input.expMs, requiredTool: "agent_handshake_accept_invitation",
      });
      await options.store.claim({
        invitationDigest: digest(input.invitation), jti: verified.payload.jti, nowMs: String(nowMs()),
      });
      const responderAccess = mintV2RoleAccess({
        key: options.activeKey, jti: nextId(), sessionId: input.sessionId, role: "responder",
        statementDigest: input.statementDigest, allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
        nbfMs: verified.payload.nbfMs, expMs: input.expMs,
      });
      return Object.freeze({ responderAccess });
    },
  });
}

