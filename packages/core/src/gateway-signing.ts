/**
 * Payload-bound request signing for the owned Clockchain anchoring gateway.
 *
 * The MCP coordinator (this package's {@link ClockchainClient}) signs every gateway request; the gateway
 * (anchoring-gateway/gateway.mjs `verifySignature`) verifies before doing any work. This authenticates the
 * caller, binds the signature to the exact payload (method + path + body), and — with the gateway's timestamp
 * window + single-use nonce — gives replay and tamper protection.
 *
 * The scheme here MUST match gateway.mjs byte-for-byte (there is a shared test vector in
 * test/gateway-signing.test.mjs and the gateway self-test selftest.mjs):
 *   canonical = METHOD "\n" PATH+QUERY "\n" TIMESTAMP "\n" NONCE "\n" sha256hex(body)
 *   signature = base64( HMAC_SHA256(secret, canonical) )
 */
import { createHash, createHmac, randomBytes } from "node:crypto";

/** The exact string that is signed for a gateway request. */
export function gatewayCanonical(
  method: string,
  pathWithQuery: string,
  timestamp: string,
  nonce: string,
  bodyString: string,
): string {
  const bodyHash = createHash("sha256").update(bodyString, "utf8").digest("hex");
  return `${method.toUpperCase()}\n${pathWithQuery}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

/** base64( HMAC-SHA256(secret, canonical) ). */
export function computeGatewaySignature(
  secret: string,
  method: string,
  pathWithQuery: string,
  timestamp: string,
  nonce: string,
  bodyString: string,
): string {
  return createHmac("sha256", secret)
    .update(gatewayCanonical(method, pathWithQuery, timestamp, nonce, bodyString), "utf8")
    .digest("base64");
}

// A `type` (not `interface`) so it carries an implicit string index signature and is assignable to
// Record<string,string> at the request-header merge site in client.ts.
export type GatewaySignatureHeaders = {
  "x-cc-key-id": string;
  "x-cc-timestamp": string;
  "x-cc-nonce": string;
  "x-cc-signature": string;
};

/** Build fresh signed headers — a new timestamp and single-use nonce per call (so retries never replay). */
export function buildGatewaySignatureHeaders(
  secret: string,
  keyId: string,
  method: string,
  pathWithQuery: string,
  bodyString: string,
): GatewaySignatureHeaders {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex");
  return {
    "x-cc-key-id": keyId,
    "x-cc-timestamp": timestamp,
    "x-cc-nonce": nonce,
    "x-cc-signature": computeGatewaySignature(secret, method, pathWithQuery, timestamp, nonce, bodyString),
  };
}
