import { createHash } from "node:crypto";

type JsonRecord = Record<string, any>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ROLES = new Set(["initiator", "responder"]);
const ARTIFACT_TYPES = new Set(["proposal", "counterproposal", "acceptance"]);

const CHECKPOINT_KEYS = [
  "schema", "version", "protocol", "sessionId", "role", "artifactType",
  "artifactDigest", "sequence", "previousCheckpointDigest", "issuedAtMs",
  "expiresAtMs", "signerAddress", "signature",
] as const;
const SIGNATURE_KEYS = ["address", "algorithm", "value"] as const;

export class V2CommitmentCheckpointError extends Error {
  constructor() {
    super("Agent handshake commitment checkpoint validation failed.");
    this.name = "V2CommitmentCheckpointError";
  }
}

function invalid(): never { throw new V2CommitmentCheckpointError(); }

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

export function normalizeV2CommitmentCheckpoint(value: unknown): Readonly<JsonRecord> {
  const item = exact(value, CHECKPOINT_KEYS);
  const signature = exact(item.signature, SIGNATURE_KEYS);
  if (
    item.schema !== "clockchain.agent-handshake-commitment-checkpoint/v1" ||
    item.version !== "1" || item.protocol !== "clockchain.agent-handshake/v2" ||
    !UUID.test(item.sessionId) || !ROLES.has(item.role) ||
    !ARTIFACT_TYPES.has(item.artifactType) || !DIGEST.test(item.artifactDigest) ||
    typeof item.sequence !== "string" || !DECIMAL.test(item.sequence) || BigInt(item.sequence) < 1n ||
    !(item.previousCheckpointDigest === null || typeof item.previousCheckpointDigest === "string" && DIGEST.test(item.previousCheckpointDigest)) ||
    typeof item.issuedAtMs !== "string" || !DECIMAL.test(item.issuedAtMs) ||
    typeof item.expiresAtMs !== "string" || !DECIMAL.test(item.expiresAtMs) ||
    BigInt(item.issuedAtMs) >= BigInt(item.expiresAtMs) ||
    !ADDRESS.test(item.signerAddress) || signature.address !== item.signerAddress ||
    signature.algorithm !== "eip191" || !SIGNATURE.test(signature.value)
  ) invalid();
  if (
    item.artifactType === "proposal" && (item.sequence !== "1" || item.previousCheckpointDigest !== null) ||
    item.artifactType !== "proposal" && (BigInt(item.sequence) < 2n || item.previousCheckpointDigest === null)
  ) invalid();
  return Object.freeze({ ...item, signature: Object.freeze(signature) });
}

export function commitmentCheckpointSigningBytes(value: unknown): Buffer {
  const checkpoint = normalizeV2CommitmentCheckpoint(value);
  const { signature: _signature, ...unsigned } = checkpoint;
  return checkpointBytes(unsigned);
}

export function commitmentCheckpointDigest(value: unknown): string {
  return createHash("sha256").update(checkpointBytes(normalizeV2CommitmentCheckpoint(value))).digest("hex");
}

function checkpointBytes(value: unknown, ancestors = new Set<object>(), depth = 0): Buffer {
  function canonicalize(item: unknown, level: number): unknown {
    if (level > 24) invalid();
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "string") {
      if (item.length === 0 || item.length > 512 || item.trim() !== item || !/^[ -~]+$/.test(item)) invalid();
      return item;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) invalid();
      return item;
    }
    if (typeof item !== "object" || Array.isArray(item) || ancestors.has(item)) invalid();
    if (![Object.prototype, null].includes(Object.getPrototypeOf(item))) invalid();
    ancestors.add(item);
    try {
      const result: JsonRecord = {};
      const keys = Reflect.ownKeys(item);
      if (keys.length > 32 || keys.some((key) => typeof key !== "string")) invalid();
      for (const key of (keys as string[]).sort()) {
        const property = Object.getOwnPropertyDescriptor(item, key);
        if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
        result[key] = canonicalize(property.value, level + 1);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  }
  return Buffer.from(JSON.stringify(canonicalize(value, depth)), "utf8");
}
