import {
  signRelayEnvelope,
  verifyRelayEnvelope,
} from "./protocol.js";

type JsonObject = Record<string, unknown>;
type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;
type MessageRole = "initiator" | "payer" | "requestor" | "responder";
type EvidenceRole = "payer" | "payee";

const DISCOVERY_SCHEMA = "handshake-discovery/v2";
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024;
const MIN_DISCOVERY_LIFETIME_MS = 30 * 60 * 1000;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const INVITATION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;

export type HandshakeRelayDiscovery = Readonly<{
  schema: typeof DISCOVERY_SCHEMA;
  expiresAtMs: string;
  issuedAtMs: string;
  kitRepoUrl: string;
  operatorPublicKey: string;
  paymentMoved: false;
  relayUrl: string;
  repositorySha: string;
  sessionId: string;
}>;

export type HandshakeRelayMessages = Readonly<{
  highestSeq?: string;
  messages: readonly JsonObject[];
}>;

export type HandshakeRelayPostResult = Readonly<{
  ok: true;
  seq: string;
}>;

export class HandshakeRelayError extends Error {
  constructor(
    message: string,
    readonly code = "RELAY_ERROR",
    readonly status?: number,
  ) {
    super(`${code}: ${message}`);
    this.name = new.target.name;
  }
}

export class HandshakeRelayResultPendingError extends HandshakeRelayError {
  constructor() {
    super("Handshake relay result is pending.", "RESULT_NOT_SET", 404);
  }
}

export function normalizeRelayBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new HandshakeRelayError("Handshake relay URL is invalid.", "RELAY_URL_INVALID");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    (url.pathname !== "" && !/^\/+$/.test(url.pathname)) ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new HandshakeRelayError("Handshake relay URL is invalid.", "RELAY_URL_INVALID");
  }
  return `${url.protocol}//${url.host}`;
}

export function verifyRelayMessageEnvelope(envelope: JsonObject): boolean {
  return verifyRelayEnvelope(envelope);
}

export function createHandshakeRelayClient(options: {
  fetch?: FetchLike;
  maxJsonBytes?: number;
  now?: () => number;
  relayUrl?: string;
  timeoutMs?: number;
}) {
  const relayBase = normalizeRelayBaseUrl(options.relayUrl ?? process.env.HANDSHAKE_RELAY ?? "");
  const fetcher = options.fetch ?? globalThis.fetch;
  if (typeof fetcher !== "function") {
    throw new HandshakeRelayError("Handshake relay fetch is unavailable.", "RELAY_FETCH_UNAVAILABLE");
  }
  const maxJsonBytes = options.maxJsonBytes ?? DEFAULT_MAX_JSON_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = options.now ?? (() => Date.now());

  async function requestJson(path: string, init: RequestInit = {}, extra?: { resultPending?: boolean }): Promise<unknown> {
    const { json, response } = await request(path, init);
    if (response.ok) return json;
    const relayCode = isPlainObject(json) && typeof json.error === "string" ? json.error : "RELAY_HTTP_ERROR";
    if (
      extra?.resultPending === true &&
      response.status === 404 &&
      relayCode === "RESULT_NOT_SET"
    ) {
      throw new HandshakeRelayResultPendingError();
    }
    throw new HandshakeRelayError("Handshake relay returned a non-success status.", relayCode, response.status);
  }

  async function request(path: string, init: RequestInit = {}): Promise<{ json: unknown; response: Response }> {
    const controller = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const response = await fetcher(`${relayBase}${path}`, {
        ...init,
        signal: controller.signal,
      });
      return { json: await readJson(response, maxJsonBytes, controller.signal), response };
    } catch (error) {
      if (error instanceof HandshakeRelayError) throw error;
      const code = timedOut || isAbortError(error) ? "RELAY_TIMEOUT" : "RELAY_NETWORK";
      throw new HandshakeRelayError(code === "RELAY_TIMEOUT" ? "Handshake relay request timed out." : "Handshake relay request failed.", code);
    } finally {
      clearTimeout(timeout);
    }
  }

  return Object.freeze({
    fetchDiscovery: async (sessionId?: string): Promise<HandshakeRelayDiscovery> => {
      if (sessionId !== undefined && !INVITATION_ID_PATTERN.test(sessionId)) {
        invalid("SESSION_ID_INVALID");
      }
      const path = sessionId === undefined
        ? "/v1/discovery/current"
        : `/v1/discovery/${encodeURIComponent(sessionId)}`;
      const result = validateDiscovery(await requestJson(path), relayBase, now());
      if (sessionId !== undefined && result.sessionId !== sessionId) {
        invalid("DISCOVERY_SESSION_MISMATCH");
      }
      return result;
    },

    getMessages: async ({ after = "0", sessionId }: { after?: string; sessionId: string }): Promise<HandshakeRelayMessages> => {
      validateSessionId(sessionId);
      validateDecimal(after, "MESSAGE_AFTER_INVALID");
      const json = await requestJson(`/v1/sessions/${encodeURIComponent(sessionId)}/messages?after=${after}&waitMs=0`);
      return validateMessages(json, sessionId, after);
    },

    postMessage: async (input: {
      body: unknown;
      kind: string;
      privateKeyPem: string;
      role: MessageRole;
      senderKey: string;
      sessionId: string;
    }): Promise<HandshakeRelayPostResult> => {
      validateSessionId(input.sessionId);
      validateMessageRole(input.role);
      const initial = await validateMessages(
        await requestJson(`/v1/sessions/${encodeURIComponent(input.sessionId)}/messages?after=0&waitMs=0`),
        input.sessionId,
        "0",
      );
      let seq = BigInt(initial.highestSeq ?? "0") + 1n;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const envelope = signRelayEnvelope({
          body: input.body,
          kind: input.kind,
          privateKeyPem: input.privateKeyPem,
          role: input.role,
          senderKey: input.senderKey,
          seq: String(seq),
          sessionId: input.sessionId,
        });
        const { json, response } = await request(`/v1/sessions/${encodeURIComponent(input.sessionId)}/messages`, {
          body: JSON.stringify(envelope),
          headers: { "content-type": "application/json" },
          method: "POST",
        });
        if (response.ok) return validatePostResult(json);
        if (
          response.status === 409 &&
          isPlainObject(json) &&
          json.error === "SEQ_CONFLICT" &&
          isPlainObject(json.detail) &&
          typeof json.detail.expectedSeq === "string" &&
          DECIMAL_INTEGER_PATTERN.test(json.detail.expectedSeq)
        ) {
          seq = BigInt(json.detail.expectedSeq);
          continue;
        }
        const code = isPlainObject(json) && typeof json.error === "string" ? json.error : "RELAY_HTTP_ERROR";
        throw new HandshakeRelayError("Handshake relay returned a non-success status.", code, response.status);
      }
      throw new HandshakeRelayError("Handshake relay sequence conflict retry limit exceeded.", "SEQ_CONFLICT");
    },

    putEvidence: async ({
      json,
      markdown,
      marker,
      role,
      sessionId,
    }: {
      json: Uint8Array | string;
      markdown: Uint8Array | string;
      marker: Uint8Array | string;
      role: EvidenceRole;
      sessionId: string;
    }): Promise<unknown> => {
      validateSessionId(sessionId);
      validateEvidenceRole(role);
      return requestJson(`/v1/sessions/${encodeURIComponent(sessionId)}/evidence/${role}`, {
        body: JSON.stringify({
          json: evidencePartBase64(json),
          markdown: evidencePartBase64(markdown),
          marker: evidencePartBase64(marker),
        }),
        headers: { "content-type": "application/json" },
        method: "PUT",
      });
    },

    getResult: async ({ sessionId }: { sessionId: string }): Promise<unknown> => {
      validateSessionId(sessionId);
      return requestJson(`/v1/sessions/${encodeURIComponent(sessionId)}/result`, {}, { resultPending: true });
    },
  });
}

function validateDiscovery(value: unknown, relayBase: string, nowMs: number): HandshakeRelayDiscovery {
  if (!isPlainObject(value)) invalid("DISCOVERY_INVALID");
  if (
    value.schema !== DISCOVERY_SCHEMA ||
    value.paymentMoved !== false ||
    typeof value.sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(value.sessionId) ||
    typeof value.repositorySha !== "string" ||
    !SHA_PATTERN.test(value.repositorySha) ||
    typeof value.kitRepoUrl !== "string" ||
    normalizeHttpUrl(value.kitRepoUrl) === null ||
    typeof value.operatorPublicKey !== "string" ||
    !isCanonicalRawEd25519PublicKey(value.operatorPublicKey) ||
    typeof value.issuedAtMs !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.issuedAtMs) ||
    typeof value.expiresAtMs !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.expiresAtMs) ||
    typeof value.relayUrl !== "string"
  ) {
    invalid("DISCOVERY_INVALID");
  }
  const issued = BigInt(value.issuedAtMs);
  const expires = BigInt(value.expiresAtMs);
  if (expires <= BigInt(Math.trunc(nowMs))) invalid("DISCOVERY_EXPIRED");
  if (expires - issued < BigInt(MIN_DISCOVERY_LIFETIME_MS)) invalid("DISCOVERY_LIFETIME_INVALID");
  if (normalizeRelayBaseUrl(value.relayUrl) !== relayBase) invalid("DISCOVERY_RELAY_MISMATCH");
  return Object.freeze({
    schema: value.schema,
    expiresAtMs: value.expiresAtMs,
    issuedAtMs: value.issuedAtMs,
    kitRepoUrl: normalizeHttpUrl(value.kitRepoUrl) ?? value.kitRepoUrl,
    operatorPublicKey: value.operatorPublicKey,
    paymentMoved: false,
    relayUrl: normalizeRelayBaseUrl(value.relayUrl),
    repositorySha: value.repositorySha,
    sessionId: value.sessionId,
  });
}

function validateMessages(value: unknown, expectedSessionId: string, after: string): HandshakeRelayMessages {
  if (!isPlainObject(value) || value.ok !== true || !Array.isArray(value.messages)) {
    invalid("MESSAGES_INVALID");
  }
  const afterSeq = BigInt(after);
  let highestSeq: bigint | null = null;
  let previousSeq: bigint | null = null;
  for (const message of value.messages) {
    if (!isPlainObject(message)) invalid("MESSAGES_INVALID");
    verifyRelayEnvelope(message);
    if (message.sessionId !== expectedSessionId) invalid("MESSAGE_SESSION_MISMATCH");
    const seq = BigInt(String(message.seq));
    if (seq <= afterSeq) invalid("MESSAGE_SEQ_REPLAY");
    if (previousSeq !== null && seq <= previousSeq) invalid("MESSAGE_SEQ_ORDER_INVALID");
    previousSeq = seq;
    if (highestSeq === null || seq > highestSeq) highestSeq = seq;
  }
  const result: { highestSeq?: string; messages: readonly JsonObject[] } = {
    messages: Object.freeze([...value.messages]) as readonly JsonObject[],
  };
  if (highestSeq !== null) result.highestSeq = String(highestSeq);
  return Object.freeze(result);
}

function validatePostResult(value: unknown): HandshakeRelayPostResult {
  if (!isPlainObject(value) || value.ok !== true || typeof value.seq !== "string" || !DECIMAL_INTEGER_PATTERN.test(value.seq)) {
    invalid("POST_RESULT_INVALID");
  }
  return Object.freeze({ ok: true, seq: value.seq });
}

async function readJson(response: Response, maxBytes: number, signal: AbortSignal): Promise<unknown> {
  const bytes = await readBoundedText(response, maxBytes, signal);
  try {
    return JSON.parse(bytes) as unknown;
  } catch {
    throw new HandshakeRelayError("Handshake relay JSON response is malformed.", "RELAY_JSON_INVALID", response.status);
  }
}

function validateSessionId(sessionId: string): void {
  if (!SESSION_ID_PATTERN.test(sessionId)) invalid("SESSION_ID_INVALID");
}

function validateDecimal(value: string, code: string): void {
  if (!DECIMAL_INTEGER_PATTERN.test(value)) invalid(code);
}

function validateMessageRole(role: string): asserts role is MessageRole {
  if (!["initiator", "payer", "requestor", "responder"].includes(role)) invalid("ROLE_INVALID");
}

function validateEvidenceRole(role: string): asserts role is EvidenceRole {
  if (role !== "payer" && role !== "payee") invalid("EVIDENCE_ROLE_INVALID");
}

function isCanonicalRawEd25519PublicKey(value: string): boolean {
  const bytes = Buffer.from(value, "base64");
  return bytes.length === 32 && bytes.toString("base64") === value;
}

function isPlainObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalid(code: string): never {
  throw new HandshakeRelayError("Handshake relay validation failed.", code);
}

function evidencePartBase64(value: Uint8Array | string): string {
  if (typeof value === "string") return Buffer.from(value, "utf8").toString("base64");
  if (value instanceof Uint8Array) return Buffer.from(value).toString("base64");
  invalid("MALFORMED_EVIDENCE");
}

function normalizeHttpUrl(value: string): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    return null;
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

async function readBoundedText(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const entry = await readWithAbort(reader, signal);
      if (entry.done) break;
      if (entry.value !== undefined) {
        total += entry.value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new HandshakeRelayError("Handshake relay JSON response is too large.", "RELAY_JSON_OVERSIZED", response.status);
        }
        chunks.push(entry.value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total).toString("utf8");
}

function readWithAbort(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<{ done: boolean; value?: Uint8Array }> {
  if (signal.aborted) {
    return Promise.reject(new DOMException("The operation was aborted.", "AbortError"));
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new DOMException("The operation was aborted.", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    reader.read().then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function isAbortError(error: unknown): boolean {
  return (
    (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError") ||
    (isPlainObject(error) && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}
