import {
  createHandshakeRelayClient,
  HandshakeRelayError,
  HandshakeRelayResultPendingError,
} from "../handshake/relay.js";

/**
 * `contract_bind` by reference: resolve a handshake session's closing
 * certificate server-side, so an agent presents only the sessionId and never
 * carries (or hand-reconstructs) the signed certificate object.
 *
 * Source of truth: the handshake relay's `/v1/sessions/{id}/result` — the
 * SAME record the v2 coordinator reads in `agent_handshake_get_certificate`
 * (coordinator.certificateResponse → relay.getResult). The coordinator's own
 * state store holds only per-role progress records keyed by access principal,
 * never the envelope, so the relay is the one store both surfaces share; it
 * lives outside the mcp container and survives any container restart.
 *
 * The resolved envelope is UNTRUSTED input: `contract_bind` runs it through
 * the unchanged `verifyCertificateEnvelope` (pinned host root, session-key
 * signature, parties, ERC-8004 pins) and requires its sessionId to equal the
 * one presented.
 */

export type CertificateResolution =
  | { ok: true; certificate: unknown }
  | {
      ok: false;
      code: "CERTIFICATE_NOT_READY" | "HANDSHAKE_SESSION_UNKNOWN" | "CONTRACT_UNAVAILABLE";
      retryable: boolean;
      retryAfterMs?: number;
    };

export type CertificateResolver = (sessionId: string) => Promise<CertificateResolution>;

export const HANDSHAKE_SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const RETRY_AFTER_MS = 5_000;

export function createRelayCertificateResolver(options: {
  relayUrl: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}): CertificateResolver {
  const relay = createHandshakeRelayClient({
    relayUrl: options.relayUrl,
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
  });
  return async (sessionId) => {
    if (typeof sessionId !== "string" || !HANDSHAKE_SESSION_ID.test(sessionId)) {
      return { ok: false, code: "HANDSHAKE_SESSION_UNKNOWN", retryable: false };
    }
    try {
      return { ok: true, certificate: await relay.getResult({ sessionId }) };
    } catch (error) {
      if (error instanceof HandshakeRelayResultPendingError) {
        return { ok: false, code: "CERTIFICATE_NOT_READY", retryable: true, retryAfterMs: RETRY_AFTER_MS };
      }
      if (error instanceof HandshakeRelayError && (error.status === 404 || error.status === 400)) {
        return { ok: false, code: "HANDSHAKE_SESSION_UNKNOWN", retryable: false };
      }
      return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: true, retryAfterMs: RETRY_AFTER_MS };
    }
  };
}
