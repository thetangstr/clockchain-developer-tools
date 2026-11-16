// RFC 9449 DPoP proofs from an agent's key: a JWT (typ dpop+jwt, EdDSA, the public JWK in the header) bound to one
// request's method and URL, and at a resource to the access token through `ath`. Parsing is as strict as the client
// assertion's (proof.ts), the signature is checked before any claim is trusted, and no reason ever echoes the proof.
// Nonces are not used (RFC 9449 §8): the `iat` window plus a single-use `jti` (the caller's replay set) is the control.
import { createHash, createPublicKey, verify } from "node:crypto";
import { AgentKeyError } from "./book.js";
import { decode, decodeJson, thumbprint } from "./proof.js";

const CLOCK_WINDOW_SEC = 60;
const MAX_PROOF_CHARS = 8 * 1024;

const refuse = (reason: string): never => {
  throw new AgentKeyError("invalid_dpop_proof", reason);
};
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("base64url");

/** RFC 9449 §4.3. Throws AgentKeyError("invalid_dpop_proof", <reason that never echoes the proof>). */
export function verifyDpopProof(input: {
  proof: string | string[] | undefined; // the raw `dpop` request header
  htm: string; // the request method
  htu: string; // the expected URL: MCP_PUBLIC_URL + path, no query or fragment
  nowSec: number;
  accessToken?: string; // set at a resource: then `ath` is required and must match
}): { jkt: string; jti: string; iat: number; replayKey: string; replayExp: number } {
  const { proof, htm, htu, nowSec, accessToken } = input;
  if (!Number.isSafeInteger(nowSec)) throw new Error("nowSec must be whole seconds");

  // Node joins repeated unknown headers with ", ", and a JWT has no comma, so a comma means more than one proof.
  if (Array.isArray(proof) || (typeof proof === "string" && proof.includes(","))) return refuse("Send exactly one DPoP proof.");
  if (typeof proof !== "string" || proof === "") return refuse("Send a DPoP proof in the DPoP header.");
  if (proof.length > MAX_PROOF_CHARS) return refuse("The DPoP proof is malformed.");
  const parts = proof.split(".");
  if (parts.length !== 3) return refuse("The DPoP proof is malformed.");
  const [h, p, s] = parts;
  const header = decodeJson(h);
  const claims = decodeJson(p);
  const signature = decode(s);
  if (!header || !claims || !signature) return refuse("The DPoP proof is malformed.");

  if (header.typ !== "dpop+jwt" || header.alg !== "EdDSA" || header.crit !== undefined) {
    return refuse("The DPoP proof header must have typ dpop+jwt and alg EdDSA.");
  }
  const jwk = header.jwk;
  if (!isObj(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || "d" in jwk || typeof jwk.x !== "string" || decode(jwk.x)?.length !== 32) {
    return refuse("The DPoP proof has no usable public key.");
  }
  const x = jwk.x;
  let ok: boolean;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
    ok = signature.length === 64 && verify(null, Buffer.from(`${h}.${p}`, "ascii"), key, signature);
  } catch {
    return refuse("The DPoP proof has no usable public key.");
  }
  if (!ok) return refuse("The DPoP proof signature does not match its key.");

  const { jti, iat, ath } = claims;
  if (typeof jti !== "string" || jti.length < 8 || jti.length > 128) return refuse("The DPoP proof id (jti) must be 8 to 128 characters.");
  if (claims.htm !== htm) return refuse("The DPoP proof is for another method (htm).");
  if (typeof claims.htu !== "string" || claims.htu.split(/[?#]/)[0] !== htu) return refuse("The DPoP proof is for another URL (htu).");
  if (!Number.isSafeInteger(iat) || Math.abs((iat as number) - nowSec) > CLOCK_WINDOW_SEC) {
    return refuse("The DPoP proof time (iat) must be whole seconds within 60 seconds of now.");
  }
  if (accessToken !== undefined && ath !== sha256(accessToken)) return refuse("The DPoP proof is for another access token (ath).");

  const jkt = thumbprint(x);
  return { jkt, jti, iat: iat as number, replayKey: sha256(`${jkt}:${jti}`), replayExp: (iat as number) + CLOCK_WINDOW_SEC + 1 };
}

/** RFC 7638 thumbprint of an Ed25519 SPKI PEM (what jwtBearerProof's publicKeyPem is). */
export function jwkThumbprintOfPem(pem: string): string {
  const { x } = createPublicKey(pem).export({ format: "jwk" });
  return thumbprint(x as string);
}
