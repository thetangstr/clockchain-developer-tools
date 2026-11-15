// A minimal agent client: its own Ed25519 key, one signed assertion for a DPoP-bound token, and a fetch that adds a fresh
// DPoP proof to every request. Use it with the MCP TypeScript SDK:
//   const key = agentKey();                                    // keep key.privateKey; Clockchain never sees it
//   const token = tokenSource(key, "https://mcp.clockchain.network/oauth/token");
//   const transport = new StreamableHTTPClientTransport(new URL("https://mcp.clockchain.network/shadow/mcp"),
//     { fetch: dpopFetch(key, token) });
//   await new Client({ name: "my-agent", version: "1" }).connect(transport);
// Use the URLs /shadow/connect and the OAuth metadata give: they are on the server's public URL (MCP_PUBLIC_URL), which
// it checks every assertion's aud and every proof's htu against, so by default each proof's htu is the URL called.
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";
const b64u = (b) => Buffer.from(b).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

export function agentKey(privateKey = generateKeyPairSync("ed25519").privateKey) {
  const { kty, crv, x } = createPublicKey(privateKey).export({ format: "jwk" });
  const jwk = { kty, crv, x };
  const thumbprint = b64u(createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest());
  const jwt = (header, claims) => {
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
    return `${input}.${b64u(sign(null, Buffer.from(input, "ascii"), privateKey))}`;
  };
  return {
    privateKey, jwk, thumbprint,
    assertion: (aud) => jwt({ alg: "EdDSA", typ: "JWT", jwk }, { iss: thumbprint, sub: thumbprint, aud, iat: now(), exp: now() + 300, jti: randomUUID() }),
    dpop: (htm, htu, accessToken) => jwt({ alg: "EdDSA", typ: "dpop+jwt", jwk }, {
      jti: randomUUID(), htm, htu, iat: now(),
      ...(accessToken ? { ath: b64u(createHash("sha256").update(accessToken, "ascii").digest()) } : {}),
    }),
  };
}

/** An async getter for a DPoP-bound access token, signed for again a minute before each one expires (there is no refresh token). */
export function tokenSource(key, tokenEndpoint, { postTo = tokenEndpoint } = {}) {
  let token, until = 0;
  return async () => {
    if (token && now() < until) return token;
    const res = await fetch(postTo, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: key.dpop("POST", tokenEndpoint) },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: key.assertion(tokenEndpoint),
      }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(`token: ${body.error}: ${body.error_description}`);
    token = body.access_token;
    until = now() + body.expires_in - 60;
    return token;
  };
}

/** A fetch for StreamableHTTPClientTransport: "Authorization: DPoP <token>" and a new proof per request. */
export function dpopFetch(key, getToken, { htuOf = (url) => url.split(/[?#]/)[0] } = {}) {
  return async (url, init = {}) => {
    const href = url instanceof URL ? url.href : String(url);
    const accessToken = await getToken();
    const headers = new Headers(init.headers);
    headers.set("authorization", `DPoP ${accessToken}`);
    headers.set("dpop", key.dpop((init.method ?? "GET").toUpperCase(), htuOf(href), accessToken));
    return fetch(href, { ...init, headers });
  };
}
