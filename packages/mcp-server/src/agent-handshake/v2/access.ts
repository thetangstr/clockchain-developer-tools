import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const AGENT_HANDSHAKE_ROLE_TOOLS = Object.freeze([
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
export const AGENT_HANDSHAKE_INVITATION_TOOLS = Object.freeze([
  "agent_handshake_accept_invitation",
]);

export type V2Role = "initiator" | "responder";
export type V2AccessKey = Readonly<{ kid: string; secret: Buffer }>;
export type V2RoleAccessPayload = Readonly<{
  v: 1;
  alg: "HS256";
  typ: "clockchain-agent-handshake-role-access";
  iss: "https://mcp.clockchain.network";
  aud: "clockchain-agent-handshake";
  kid: string;
  jti: string;
  sessionId: string;
  role: V2Role;
  statementDigest: string;
  allowedTools: readonly string[];
  nbfMs: string;
  expMs: string;
}>;

const PAYLOAD_KEYS = [
  "v", "alg", "typ", "iss", "aud", "kid", "jti", "sessionId", "role",
  "statementDigest", "allowedTools", "nbfMs", "expMs",
] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CLOCK_SKEW_MS = 1_000;

export class V2RoleAccessError extends Error {
  constructor() {
    super("Agent handshake access is unavailable.");
    this.name = "V2RoleAccessError";
  }
}

function invalid(): never { throw new V2RoleAccessError(); }

function encode(value: Buffer): string {
  return value.toString("base64url");
}

function accessBytes(value: V2RoleAccessPayload): Buffer {
  return Buffer.from(JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  )), "utf8");
}

function exactPayload(value: unknown): Record<string, any> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== PAYLOAD_KEYS.length || actual.some((key) => typeof key !== "string" || !PAYLOAD_KEYS.includes(key as any))) invalid();
  const result: Record<string, any> = {};
  for (const key of PAYLOAD_KEYS) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function key(value: V2AccessKey): V2AccessKey {
  if (!KID.test(value?.kid) || !Buffer.isBuffer(value?.secret) || value.secret.length < 32) invalid();
  return Object.freeze({ kid: value.kid, secret: Buffer.from(value.secret) });
}

function tools(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || new Set(value).size !== value.length) invalid();
  const allowed = [...AGENT_HANDSHAKE_ROLE_TOOLS, ...AGENT_HANDSHAKE_INVITATION_TOOLS];
  if (value.some((entry) => typeof entry !== "string" || !allowed.includes(entry))) invalid();
  const roleSet = AGENT_HANDSHAKE_ROLE_TOOLS;
  const invitationSet = AGENT_HANDSHAKE_INVITATION_TOOLS;
  if (
    value.length !== roleSet.length && value.length !== invitationSet.length ||
    !(value.every((entry, index) => entry === roleSet[index]) || value.every((entry, index) => entry === invitationSet[index]))
  ) invalid();
  return Object.freeze([...value]);
}

function payload(value: unknown): V2RoleAccessPayload {
  const item = exactPayload(value);
  const allowedTools = tools(item.allowedTools);
  if (
    item.v !== 1 || item.alg !== "HS256" ||
    item.typ !== "clockchain-agent-handshake-role-access" ||
    item.iss !== "https://mcp.clockchain.network" ||
    item.aud !== "clockchain-agent-handshake" || !KID.test(item.kid) ||
    !UUID.test(item.jti) || !UUID.test(item.sessionId) ||
    !["initiator", "responder"].includes(item.role) || !DIGEST.test(item.statementDigest) ||
    typeof item.nbfMs !== "string" || !DECIMAL.test(item.nbfMs) ||
    typeof item.expMs !== "string" || !DECIMAL.test(item.expMs) ||
    BigInt(item.nbfMs) >= BigInt(item.expMs)
  ) invalid();
  return Object.freeze({ ...item, allowedTools }) as V2RoleAccessPayload;
}

function signature(segment: string, secret: Buffer): Buffer {
  return createHmac("sha256", secret).update(segment, "ascii").digest();
}

export function mintV2RoleAccess(input: {
  key: V2AccessKey;
  jti: string;
  sessionId: string;
  role: V2Role;
  statementDigest: string;
  allowedTools: readonly string[];
  nbfMs: string | number;
  expMs: string | number;
}): string {
  const signingKey = key(input.key);
  const verified = payload({
    v: 1,
    alg: "HS256",
    typ: "clockchain-agent-handshake-role-access",
    iss: "https://mcp.clockchain.network",
    aud: "clockchain-agent-handshake",
    kid: signingKey.kid,
    jti: input.jti,
    sessionId: input.sessionId,
    role: input.role,
    statementDigest: input.statementDigest,
    allowedTools: input.allowedTools,
    nbfMs: String(input.nbfMs),
    expMs: String(input.expMs),
  });
  const segment = encode(accessBytes(verified));
  return `${segment}.${encode(signature(segment, signingKey.secret))}`;
}

export function verifyV2RoleAccess(access: string, options: {
  keys: readonly V2AccessKey[];
  nowMs: number;
  expectedSessionId: string;
  expectedRole?: V2Role;
  expectedStatementDigest: string;
  expectedExpMs: string | number;
  requiredTool: string;
}): Readonly<{ payload: V2RoleAccessPayload; principal: string }> {
  try {
    if (typeof access !== "string" || access.includes("=") || access.split(".").length !== 2) invalid();
    const [segment, signatureSegment] = access.split(".");
    if (!BASE64URL.test(segment) || !BASE64URL.test(signatureSegment)) invalid();
    const decoded = Buffer.from(segment, "base64url");
    if (encode(decoded) !== segment) invalid();
    const parsed = payload(JSON.parse(decoded.toString("utf8")));
    if (encode(accessBytes(parsed)) !== segment) invalid();
    if (!Array.isArray(options.keys) || options.keys.length < 1 || options.keys.length > 2) invalid();
    const keys = options.keys.map(key);
    if (new Set(keys.map((entry) => entry.kid)).size !== keys.length) invalid();
    const matched = keys.find((entry) => entry.kid === parsed.kid);
    if (!matched) invalid();
    const supplied = Buffer.from(signatureSegment, "base64url");
    const expected = signature(segment, matched.secret);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) invalid();
    if (
      !Number.isSafeInteger(options.nowMs) ||
      options.nowMs < Number(parsed.nbfMs) - CLOCK_SKEW_MS || options.nowMs >= Number(parsed.expMs) ||
      parsed.sessionId !== options.expectedSessionId ||
      options.expectedRole !== undefined && parsed.role !== options.expectedRole ||
      parsed.statementDigest !== options.expectedStatementDigest ||
      parsed.expMs !== String(options.expectedExpMs) ||
      !parsed.allowedTools.includes(options.requiredTool)
    ) invalid();
    return Object.freeze({
      payload: parsed,
      principal: createHash("sha256").update(access, "utf8").digest("hex"),
    });
  } catch (error) {
    if (error instanceof V2RoleAccessError) throw error;
    invalid();
  }
}

export function readV2RoleAccessPayload(access: string): V2RoleAccessPayload {
  try {
    if (typeof access !== "string" || access.includes("=") || access.split(".").length !== 2) invalid();
    const [segment, signatureSegment] = access.split(".");
    if (!BASE64URL.test(segment) || !BASE64URL.test(signatureSegment)) invalid();
    const decoded = Buffer.from(segment, "base64url");
    if (encode(decoded) !== segment) invalid();
    const parsed = payload(JSON.parse(decoded.toString("utf8")));
    if (encode(accessBytes(parsed)) !== segment) invalid();
    return parsed;
  } catch (error) {
    if (error instanceof V2RoleAccessError) throw error;
    invalid();
  }
}

export function authorizeV2RoleAccess(access: string, options: {
  keys: readonly V2AccessKey[];
  nowMs: number;
  requiredTool: string;
}): Readonly<{ payload: V2RoleAccessPayload; principal: string }> {
  const untrusted = readV2RoleAccessPayload(access);
  return verifyV2RoleAccess(access, {
    keys: options.keys,
    nowMs: options.nowMs,
    expectedSessionId: untrusted.sessionId,
    expectedRole: untrusted.role,
    expectedStatementDigest: untrusted.statementDigest,
    expectedExpMs: untrusted.expMs,
    requiredTool: options.requiredTool,
  });
}
