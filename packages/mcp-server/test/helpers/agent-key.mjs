// A test-side agent: makes its own Ed25519 key and signs what a real agent would sign with it, an RFC 7523 client
// assertion (alg EdDSA, public JWK in the header) and checkpoint hashes. The private key never leaves this object.
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { fingerprint } from "../../dist/shadow/lib/keys.js";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

/** RFC 7638 thumbprint of an Ed25519 OKP JWK. */
export const jwkThumbprint = (jwk) =>
  b64url(createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest());

/** Signs `header.payload` with `privateKey`. Exposed so tests can build malformed assertions on purpose. */
export function signJwt(privateKey, header, claims) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  return `${input}.${b64url(sign(null, Buffer.from(input, "ascii"), privateKey))}`;
}

export function makeAgentKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const { kty, crv, x } = publicKey.export({ format: "jwk" });
  const jwk = { kty, crv, x };
  const thumbprint = jwkThumbprint(jwk);
  return {
    /** For handing this same key to a client under test (the example client); tests never print it. */
    privateKey,
    publicKeyPem,
    fingerprint: fingerprint(publicKeyPem),
    jwk,
    thumbprint,
    /** `header` and `claims` are merged over the defaults; set a member to undefined to drop it. */
    assertion(aud, { iat, exp, jti, header = {}, claims = {} } = {}) {
      const issued = iat ?? Math.floor(Date.now() / 1000);
      return signJwt(
        privateKey,
        { alg: "EdDSA", typ: "JWT", jwk, ...header },
        { iss: thumbprint, sub: thumbprint, aud, iat: issued, exp: exp ?? issued + 300, jti: jti ?? randomUUID(), ...claims },
      );
    },
    /**
     * An RFC 9449 DPoP proof for `htm` `htu`, with `ath` when `accessToken` is given. `header` and `claims` are merged over
     * the defaults; set a member to undefined to drop it.
     */
    dpop(htm, htu, { accessToken, iat, jti, header = {}, claims = {} } = {}) {
      return signJwt(
        privateKey,
        { alg: "EdDSA", typ: "dpop+jwt", jwk, ...header },
        {
          jti: jti ?? randomUUID(), htm, htu, iat: iat ?? Math.floor(Date.now() / 1000),
          ...(accessToken === undefined ? {} : { ath: b64url(createHash("sha256").update(accessToken, "ascii").digest()) }),
          ...claims,
        },
      );
    },
    /** Base64 Ed25519 signature over the 32 hash bytes, in the form `verifySignature` accepts. */
    signHash: (hashHex) => sign(null, Buffer.from(hashHex, "hex"), privateKey).toString("base64"),
    signJwt: (header, claims) => signJwt(privateKey, header, claims),
  };
}
