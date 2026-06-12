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

# 3. Deploy from source (Cloud Build uses the repo Dockerfile)
gcloud run deploy clockchain-mcp \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 1 \
  --timeout 300 \
  --set-env-vars MCP_TRANSPORT=http,MCP_REQUIRE_AUTH=1,MCP_RATE_PER_MIN=30,MCP_LOG_BUDGET=200,CLOCKCHAIN_CLIENT_ID=<you@example.com>,CLOCKCHAIN_WALLET_ID=<you@example.com>,CLOCKCHAIN_ENDPOINT=https://node.clockchain.network \
  --set-secrets CLOCKCHAIN_API_KEY=clockchain-api-key:latest,MCP_AUTH_TOKENS=mcp-auth-tokens:latest
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
