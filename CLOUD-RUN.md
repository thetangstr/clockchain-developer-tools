# Deploy the Clockchain MCP server to Cloud Run

The robust hosting path: the MCP server runs as a managed container on **GCP Cloud
Run** — always-on, auto-TLS, auto-restart, a stable `*.run.app` HTTPS URL, no VM to
maintain. This replaces the interim Mac-mini + Cloudflare-tunnel setup.

Auth model is unchanged: Cloud Run is publicly reachable (`--allow-unauthenticated`),
and the **app's own token gate** (`MCP_REQUIRE_AUTH=1` + `MCP_AUTH_TOKENS`) controls
who can actually call tools. "Public URL" ≠ "open" — only token holders get in.

## One-time prerequisites (you)

1. A **GCP project** with **billing enabled** (Cloud Run + Cloud Build need it; the
   service itself is a few $/mo with `--min-instances 1`).
2. Authenticate this session and select the project. Run these yourself with the
   `!` prefix so the login lands in this shell:
   ```
   ! gcloud auth login
   ! gcloud config set project <PROJECT_ID>
   ```

## Deploy

Everything below can run from the repo root.

```bash
# 1. Enable the APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com

# 2. Store secrets in Secret Manager (pull values from the Mac mini .env)
printf '%s' '<CLOCKCHAIN_API_KEY>'  | gcloud secrets create clockchain-api-key --data-file=-
printf '%s' '<token1>,<token2>'     | gcloud secrets create mcp-auth-tokens   --data-file=-
openssl rand -hex 32                 | gcloud secrets create mcp-token-signing-secret --data-file=-  # signs self-serve tokens

# 3. Deploy from source (Cloud Build uses the repo Dockerfile)
gcloud run deploy clockchain-mcp \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 1 \
  --timeout 300 \
  --set-env-vars MCP_TRANSPORT=http,MCP_REQUIRE_AUTH=1,MCP_RATE_PER_MIN=30,MCP_LOG_BUDGET=200,MCP_TOKEN_MINT_PER_HOUR=10,MCP_TOKEN_TTL_DAYS=7,CLOCKCHAIN_CLIENT_ID=<you@example.com>,CLOCKCHAIN_WALLET_ID=<you@example.com>,CLOCKCHAIN_ENDPOINT=https://node.clockchain.network \
  --set-secrets CLOCKCHAIN_API_KEY=clockchain-api-key:latest,MCP_AUTH_TOKENS=mcp-auth-tokens:latest,MCP_TOKEN_SIGNING_SECRET=mcp-token-signing-secret:latest
```

`--min-instances 1` avoids cold starts (keeps the demo snappy; drop to 0 to save
cents if you don't mind a ~1s first-hit delay). `--timeout 300` covers the ~15s
`attest_action` block wait with headroom.

If Cloud Run's runtime service account lacks secret access, grant it once:
```bash
PROJECT_NUM=$(gcloud projects describe "$(gcloud config get-value project)" --format='value(projectNumber)')
for S in clockchain-api-key mcp-auth-tokens; do
  gcloud secrets add-iam-policy-binding "$S" \
    --member="serviceAccount:${PROJECT_NUM}-compute@developer.gserviceaccount.com" \
    --role=roles/secretmanager.secretAccessor
done
```

## Verify

```bash
URL=$(gcloud run services describe clockchain-mcp --region us-central1 --format='value(status.url)')
# initialize → expect serverInfo clockchain-mcp
curl -s -X POST "$URL/mcp" -H "Authorization: Bearer <token1>" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
# no token → expect 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$URL/mcp" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

## Custom domain (later, optional)

The `*.run.app` URL is stable and TLS-terminated — fine to use as-is. To put it on
`mcp.clockchain.network` without touching the rest of the zone, map the domain in
Cloud Run and add the **single** record Cloud Run prints at GoDaddy (a CNAME for the
`mcp` subdomain). The apex and `node.clockchain.network` are untouched.

```bash
gcloud run domain-mappings create --service clockchain-mcp \
  --domain mcp.clockchain.network --region us-central1
# then add the CNAME it prints, at GoDaddy, for the `mcp` host only
```

## Retire the Mac mini

Once the `*.run.app` URL passes the checks above and the docs point at it:
```bash
ssh maxiaoer@192.168.86.48 'pm2 delete clockchain-mcp; pkill -f "cloudflared tunnel"'
```

## Operations & security (current state)

- **CI/CD:** push to `main` (code paths) auto-builds + deploys via GitHub Actions
  (`.github/workflows/deploy.yml`) using **Workload Identity Federation** — keyless,
  deploy SA `gh-deploy@clockchain-mcp-yarda`, WIF pool `github` bound to
  `thetangstr/clockchain-developer-tools`. Manual deploy is still `gcloud run deploy
  --source` (preserves env/secrets/scaling).
- **Networking:** external HTTPS LB on static IP `34.111.4.193`; managed cert for
  `mcp.clockchain.network`; **HTTP(:80) → HTTPS 301 redirect**; `min-instances=1`
  (no cold start).
- **Edge protection:** Cloud Armor policy `clockchain-mcp-armor` on backend
  `clockchain-mcp-be` — per-IP rate limit **120 req / 60s**, 5-min ban on abuse. (App
  layer also rate-limits per token: `MCP_RATE_PER_MIN`.)
- **Monitoring:** uptime check `clockchain-mcp-health` on `/health` + alert policy
  "clockchain-mcp endpoint down" → email `yt@d4d.group`.

### Rotate the Clockchain key

```bash
printf '%s' '<NEW_KEY>' | gcloud secrets versions add clockchain-api-key --data-file=-
gcloud run services update clockchain-mcp --region us-central1 \
  --update-secrets=CLOCKCHAIN_API_KEY=clockchain-api-key:latest   # rolls a new revision
```

### Mint / revoke an MCP token

```bash
CUR=$(gcloud secrets versions access latest --secret=mcp-auth-tokens)
# mint: append a new token
printf '%s,%s' "$CUR" "$(openssl rand -hex 24)" | gcloud secrets versions add mcp-auth-tokens --data-file=-
# revoke: re-add the set WITHOUT the token to remove, then roll the revision:
V=$(gcloud secrets versions add mcp-auth-tokens --data-file=- <<<"<remaining,tokens>" --format='value(name)' | grep -o '[0-9]*$')
gcloud run services update clockchain-mcp --region us-central1 --update-secrets=MCP_AUTH_TOKENS=mcp-auth-tokens:${V}
```
Tokens currently issued: tester, playground (Vercel `MCP_SERVER_TOKEN`), exec.

### Self-serve testnet tokens (`POST /token`)

Anyone can mint a short-lived testnet token at `POST /token` — no signup. These
are **stateless HMAC-signed** tokens (`cc_<payload>.<hmac>`); the server verifies
the signature + expiry, no database. A valid one grants the **delegated** key
(shared testnet pool), exactly like a static `MCP_AUTH_TOKENS` entry.

- **Enable/disable:** controlled entirely by the `MCP_TOKEN_SIGNING_SECRET` secret.
  Set → `/token` mints and signed tokens validate. Unset/empty → `/token` returns
  `503` and no signed token validates (fails closed). Startup logs the state.
- **Knobs:** `MCP_TOKEN_MINT_PER_HOUR` (default 10, per client IP via
  `X-Forwarded-For`) and `MCP_TOKEN_TTL_DAYS` (default 7).
- **Revocation is all-or-nothing** — these tokens can't be revoked individually
  (no DB). To invalidate *every* outstanding self-serve token, rotate the signing
  secret (this does not affect static `MCP_AUTH_TOKENS` or BYO keys):

```bash
openssl rand -hex 32 | gcloud secrets versions add mcp-token-signing-secret --data-file=-
gcloud run services update clockchain-mcp --region us-central1 \
  --update-secrets=MCP_TOKEN_SIGNING_SECRET=mcp-token-signing-secret:latest   # rolls a revision
```

> Self-serve grants the **shared testnet** key, so its blast radius is testnet
> credits (refillable) bounded by the per-IP mint limit and `MCP_RATE_PER_MIN`.
> Don't enable it on a deploy wired to a production/funded key.

### Security review item — `allUsers` org-policy override

This project has a **project-scoped override** of `iam.allowedPolicyMemberDomains`
(set to `allValues: ALLOW`) so `allUsers` could be granted `run.invoker` — **required**
to expose a public, token-gated MCP endpoint (the app, not Google IAM, gates access).
It loosens the yarda org's Domain-Restricted-Sharing **for this project only**; every
other project keeps the restriction. It is **reversible** (reset the policy / delete the
project). **Action:** have the yarda security owner review + bless this exception.

## Not yet done (D4-owned decisions, not solo-buildable)

- **OAuth 2.1 for the Cowork/claude.ai cloud connector** — the only client surface still
  unsupported (chat connectors require OAuth, not static tokens). Recommended path:
  an OAuth server that delegates to the network identity (Ory Hydra) — see
  `auth-and-traffic-decision.md`. Needs the "which identity system" decision first.
- **Per-tenant metering + BYO-by-default** for real users (so usage funds its own
  credits). Today: delegated (our credits) + BYO available.
- **Multi-region / formal SLA** — single region (`us-central1`); only worth it once
  this is a product, not a demo.
