import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  chmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import {
  agentHandshakeStatementDigest,
  normalizeAgentHandshakeTerms,
  type AgentHandshakeTerms,
} from "./protocol.js";
import {
  mintHandshakeInvitation,
  mintHandshakeSessionToken,
  verifyHandshakeInvitation,
} from "../token.js";
import { createHandshakeRelayClient } from "../handshake/relay.js";

const STORE_SCHEMA = "clockchain.agent-handshake-invitations/v1";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

type StoredInvitation = Readonly<{
  capabilityHash: string;
  consumedAt: number | null;
  exp: number;
  invitationId: string;
  jti: string;
  role: "responder";
  statementDigest: string;
}>;

type InvitationFile = Readonly<{
  records: Record<string, StoredInvitation>;
  schema: typeof STORE_SCHEMA;
}>;

export class AgentHandshakeInvitationError extends Error {
  readonly code = "INVITATION_UNAVAILABLE";

  constructor() {
    super("INVITATION_UNAVAILABLE");
    this.name = "AgentHandshakeInvitationError";
  }
}

function unavailable(): never {
  throw new AgentHandshakeInvitationError();
}

function capabilityHash(capability: string): string {
  return createHash("sha256").update(capability, "utf8").digest("hex");
}

function validateRecord(value: unknown): StoredInvitation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) unavailable();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expected = ["capabilityHash", "consumedAt", "exp", "invitationId", "jti", "role", "statementDigest"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) unavailable();
  if (
    typeof record.capabilityHash !== "string" || !DIGEST_PATTERN.test(record.capabilityHash) ||
    (record.consumedAt !== null && !Number.isSafeInteger(record.consumedAt)) ||
    !Number.isSafeInteger(record.exp) ||
    typeof record.invitationId !== "string" || !UUID_PATTERN.test(record.invitationId) ||
    typeof record.jti !== "string" || !UUID_PATTERN.test(record.jti) ||
    record.role !== "responder" ||
    typeof record.statementDigest !== "string" || !DIGEST_PATTERN.test(record.statementDigest)
  ) unavailable();
  return Object.freeze(record as StoredInvitation);
}

function readStore(path: string): Map<string, StoredInvitation> {
  try {
    const link = lstatSync(path);
    const stat = statSync(path);
    if (!link.isFile() || link.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) unavailable();
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) unavailable();
    const file = parsed as Record<string, unknown>;
    if (Object.keys(file).sort().join(",") !== "records,schema" || file.schema !== STORE_SCHEMA) unavailable();
    if (file.records === null || typeof file.records !== "object" || Array.isArray(file.records)) unavailable();
    const records = new Map<string, StoredInvitation>();
    for (const [jti, value] of Object.entries(file.records as Record<string, unknown>)) {
      const record = validateRecord(value);
      if (jti !== record.jti || records.has(jti)) unavailable();
      records.set(jti, record);
    }
    return records;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    if (error instanceof AgentHandshakeInvitationError) throw error;
    unavailable();
  }
}

function fsyncDirectory(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeStore(path: string, records: Map<string, StoredInvitation>): void {
  const parent = dirname(path);
  mkdirSync(parent, { mode: 0o700, recursive: true });
  chmodSync(parent, 0o700);
  const existingParent = statSync(parent);
  if (!existingParent.isDirectory() || (existingParent.mode & 0o077) !== 0) unavailable();
  const file: InvitationFile = {
    records: Object.fromEntries([...records.entries()].sort(([a], [b]) => a.localeCompare(b))),
    schema: STORE_SCHEMA,
  };
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(file)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    const fd = openSync(temporary, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, path);
    fsyncDirectory(parent);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* Preserve the write failure. */ }
    throw error;
  }
}

export interface AgentHandshakeInvitationStore {
  put(record: StoredInvitation): Promise<void>;
  consume(input: StoredInvitation, nowSec: number): Promise<StoredInvitation>;
}

export function createAgentHandshakeInvitationStore(options: { path?: string } = {}): AgentHandshakeInvitationStore {
  let records = options.path ? readStore(options.path) : new Map<string, StoredInvitation>();
  let queue = Promise.resolve();

  function exclusively<T>(operation: () => T): Promise<T> {
    const result = queue.then(operation, operation);
    queue = result.then(() => undefined, () => undefined);
    return result;
  }

  function persist(): void {
    if (options.path) writeStore(options.path, records);
  }

  return Object.freeze({
    put(record: StoredInvitation): Promise<void> {
      return exclusively(() => {
        const verified = validateRecord(record);
        if (records.has(verified.jti)) unavailable();
        records = new Map(records).set(verified.jti, verified);
        persist();
      });
    },
    consume(input: StoredInvitation, nowSec: number): Promise<StoredInvitation> {
      return exclusively(() => {
        const expected = validateRecord(input);
        const current = records.get(expected.jti);
        if (
          !current || current.capabilityHash !== expected.capabilityHash ||
          current.invitationId !== expected.invitationId || current.role !== expected.role ||
          current.statementDigest !== expected.statementDigest || current.exp !== expected.exp ||
          current.consumedAt !== null || nowSec >= current.exp
        ) unavailable();
        const consumed = Object.freeze({ ...current, consumedAt: nowSec });
        records = new Map(records).set(current.jti, consumed);
        persist();
        return consumed;
      });
    },
  });
}

type Discovery = Readonly<{ expiresAtMs: string; sessionId: string }>;

export function createAgentHandshakeInvitationService(options: {
  fetchDiscovery: () => Promise<Discovery>;
  joinBaseUrl: string;
  nowSec?: () => number;
  secret: string;
  store: AgentHandshakeInvitationStore;
}) {
  const nowSec = options.nowSec ?? (() => Math.floor(Date.now() / 1000));

  return Object.freeze({
    async invite(value: unknown): Promise<Readonly<{
      expiresAt: number;
      invitationId: string;
      joinUrl: string;
      statementDigest: string;
      terms: AgentHandshakeTerms;
    }>> {
      if (!options.secret) unavailable();
      const terms = normalizeAgentHandshakeTerms(value);
      const discovery = await options.fetchDiscovery();
      if (!UUID_PATTERN.test(discovery.sessionId) || !/^(?:0|[1-9][0-9]*)$/.test(discovery.expiresAtMs)) unavailable();
      const issuedAt = nowSec();
      const expiresAt = Math.min(Math.floor(Number(discovery.expiresAtMs) / 1000), issuedAt + 60 * 60);
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) unavailable();
      const jti = randomUUID();
      const statementDigest = agentHandshakeStatementDigest(terms);
      const minted = mintHandshakeInvitation(options.secret, {
        exp: expiresAt,
        iat: issuedAt,
        invitationId: discovery.sessionId,
        jti,
        statementDigest,
      });
      await options.store.put({
        capabilityHash: capabilityHash(minted.token),
        consumedAt: null,
        exp: expiresAt,
        invitationId: discovery.sessionId,
        jti,
        role: "responder",
        statementDigest,
      });
      const joinUrl = new URL(options.joinBaseUrl);
      joinUrl.hash = `capability=${minted.token}`;
      return Object.freeze({
        expiresAt,
        invitationId: discovery.sessionId,
        joinUrl: joinUrl.toString(),
        statementDigest,
        terms,
      });
    },

    async exchange(capability: string): Promise<Readonly<{
      endpoint: string;
      expiresAt: number;
      invitationId: string;
      role: "responder";
      statementDigest: string;
      token: string;
      tools: readonly string[];
    }>> {
      try {
        const issuedAt = nowSec();
        const verified = verifyHandshakeInvitation(options.secret, capability, issuedAt);
        if (!verified.valid) unavailable();
        const discovery = await options.fetchDiscovery();
        if (discovery.sessionId !== verified.payload.invitationId) unavailable();
        await options.store.consume({
          capabilityHash: capabilityHash(capability),
          consumedAt: null,
          exp: verified.payload.exp,
          invitationId: verified.payload.invitationId,
          jti: verified.payload.jti,
          role: "responder",
          statementDigest: verified.payload.statementDigest,
        }, issuedAt);
        const minted = mintHandshakeSessionToken(options.secret, {
          exp: verified.payload.exp,
          iat: issuedAt,
          invitationId: verified.payload.invitationId,
          jti: randomUUID(),
          statementDigest: verified.payload.statementDigest,
        });
        return Object.freeze({
          endpoint: "https://mcp.clockchain.network/mcp",
          expiresAt: minted.payload.exp,
          invitationId: minted.payload.invitationId,
          role: minted.payload.role,
          statementDigest: minted.payload.statementDigest,
          token: minted.token,
          tools: minted.payload.tools,
        });
      } catch {
        unavailable();
      }
    },
  });
}

let runtimeService: ReturnType<typeof createAgentHandshakeInvitationService> | undefined;

/** One process-wide service so invite creation and HTTP exchange share atomic state. */
export function getRuntimeAgentHandshakeInvitationService(
  env: Record<string, string | undefined> = process.env,
): ReturnType<typeof createAgentHandshakeInvitationService> {
  if (runtimeService) return runtimeService;
  const secret = env.MCP_TOKEN_SIGNING_SECRET ?? "";
  if (!secret) unavailable();
  const relay = createHandshakeRelayClient({ relayUrl: env.HANDSHAKE_RELAY });
  runtimeService = createAgentHandshakeInvitationService({
    fetchDiscovery: () => relay.fetchDiscovery(),
    joinBaseUrl: env.AGENT_HANDSHAKE_JOIN_URL ?? "https://clockchain-research.vercel.app/handshake/join",
    secret,
    store: createAgentHandshakeInvitationStore({ path: env.MCP_HANDSHAKE_INVITATION_FILE }),
  });
  return runtimeService;
}
