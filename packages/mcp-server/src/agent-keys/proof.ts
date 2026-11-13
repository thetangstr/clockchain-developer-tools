// Proof that an agent holds its Ed25519 key: an RFC 7523 client assertion, a JWT signed with EdDSA whose header carries
// the agent's public JWK (RFC 8037). `iss` and `sub` are the key's RFC 7638 thumbprint. Parsing is strict, the signature
// is checked before any claim is trusted, and no reason ever echoes the assertion. Replay (`jti`) is the caller's job.
import { createHash, createPublicKey, verify } from "node:crypto";
import { ed25519PublicKeyDer } from "../shadow/lib/keys.js";
import { AgentKeyError } from "./book.js";

/** One interface, so the proof format can be swapped (LLD §17 caveat). */
export interface KeyProof {
  verify(input: { assertion: string; audience: string; nowSec: number }): { publicKeyPem: string; jti: string; exp: number };
}

const MAX_LIFETIME_SEC = 300;
const CLOCK_SKEW_SEC = 60;
const MAX_ASSERTION_CHARS = 8 * 1024;
const B64URL = /^[A-Za-z0-9_-]+$/;

const refuse = (reason: string): never => {
  throw new AgentKeyError("invalid_client", reason);
};
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const utf8 = new TextDecoder("utf-8", { fatal: true });

// Canonical unpadded base64url only, so one assertion has exactly one spelling.
function decode(segment: string): Buffer | null {
  if (!B64URL.test(segment)) return null;
  const bytes = Buffer.from(segment, "base64url");
  return bytes.toString("base64url") === segment ? bytes : null;
}

function decodeJson(segment: string): Record<string, unknown> | null {
  const bytes = decode(segment);
  if (!bytes) return null;
  try {
    const value: unknown = JSON.parse(utf8.decode(bytes));
    return isObj(value) ? value : null;
  } catch {
    return null;
  }
}

// RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
const thumbprint = (x: string) =>
  createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest("base64url");

const isSec = (v: unknown): v is number => Number.isSafeInteger(v);

export function jwtBearerProof(): KeyProof {
  return {
    verify({ assertion, audience, nowSec }) {
      if (typeof assertion !== "string" || assertion.length > MAX_ASSERTION_CHARS) return refuse("The assertion is malformed.");
      const parts = assertion.split(".");
      if (parts.length !== 3) return refuse("The assertion is malformed.");
      const [h, p, s] = parts;
      const header = decodeJson(h);
      const claims = decodeJson(p);
      const signature = decode(s);
      if (!header || !claims || !signature) return refuse("The assertion is malformed.");

      if (header.alg !== "EdDSA") return refuse("The assertion must be signed with EdDSA.");
      if (header.typ !== "JWT" || header.crit !== undefined) return refuse("The assertion header is not supported.");
      const jwk = header.jwk;
      if (!isObj(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || "d" in jwk || typeof jwk.x !== "string") {
        return refuse("The assertion has no usable public key.");
      }
      const x = jwk.x;
      if (decode(x)?.length !== 32) return refuse("The assertion has no usable public key.");

      let publicKeyPem: string;
      let ok: boolean;
      try {
        const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
        publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
        ok = signature.length === 64 && verify(null, Buffer.from(`${h}.${p}`, "ascii"), key, signature);
      } catch {
        return refuse("The assertion has no usable public key.");
      }
      if (!ed25519PublicKeyDer(publicKeyPem)) return refuse("The assertion has no usable public key.");
      if (!ok) return refuse("The assertion signature does not match its key.");

      const tp = thumbprint(x);
      if (claims.iss !== tp || claims.sub !== tp) return refuse("The assertion issuer does not match its key.");
      const aud = claims.aud;
      const audOk = typeof aud === "string"
        ? aud === audience
        : Array.isArray(aud) && aud.every((a) => typeof a === "string") && aud.includes(audience);
      if (!audOk) return refuse("The assertion is for another audience.");

      const { iat, exp, jti } = claims;
      if (!isSec(iat) || !isSec(exp)) return refuse("The assertion times are missing or not whole seconds.");
      if (exp <= iat) return refuse("The assertion expires before it was issued.");
      if (exp - iat > MAX_LIFETIME_SEC) return refuse("The assertion lifetime is too long.");
      if (iat > nowSec + CLOCK_SKEW_SEC) return refuse("The assertion was issued in the future.");
      if (exp <= nowSec) return refuse("The assertion has expired.");
      if (typeof jti !== "string" || jti.length < 8 || jti.length > 128) return refuse("The assertion id must be 8 to 128 characters.");

      return { publicKeyPem, jti, exp };
    },
  };
}
