# Migrate the Clockchain MCP stack to a new GCP project

Move everything currently in **`clockchain-mcp-yarda`** (yarda org/billing) to a new GCP
project, keep `mcp.clockchain.network` serving with **near-zero downtime**, then retire the old
project. The app/container does not change — this is an infra relocation.

## What's being moved (current inventory — source: `CLOUD-RUN.md`)

| Resource | Current (old project `clockchain-mcp-yarda`, #371358326490, us-central1) |
|---|---|
| Cloud Run service | `clockchain-mcp` — allow-unauthenticated, min-instances 1, timeout 300, 512Mi/1cpu, max 2 |
| Env vars | `MCP_TRANSPORT=http, MCP_REQUIRE_AUTH=1, MCP_RATE_PER_MIN=30, MCP_LOG_BUDGET=5000, MCP_TOKEN_MINT_PER_HOUR=10, MCP_TOKEN_TTL_DAYS=7, CLOCKCHAIN_CLIENT_ID, CLOCKCHAIN_WALLET_ID, CLOCKCHAIN_ENDPOINT=https://node.clockchain.network` |
| Secrets (Secret Manager) | `clockchain-api-key`, `mcp-auth-tokens` (tester/playground/exec), `mcp-token-signing-secret` |
| Networking | External HTTPS LB, **static IP `34.111.4.193`**, backend `clockchain-mcp-be` (serverless NEG), URL map, target HTTPS proxy, Google-managed cert for `mcp.clockchain.network`, HTTP→HTTPS 301 |
| Edge | Cloud Armor policy `clockchain-mcp-armor` (120 req/60s per IP, 5-min ban) |
| Monitoring | Uptime check `clockchain-mcp-health` (`/health`) + alert policy → `yt@d4d.group` |
| CI/CD | GitHub Actions `deploy.yml` via WIF: pool `github` / provider `github-provider`, deploy SA `gh-deploy@clockchain-mcp-yarda`, bound to repo `thetangstr/clockchain-developer-tools` |
| Org policy | Project-scoped override `iam.allowedPolicyMemberDomains = ALLOW` (so `allUsers` can `run.invoker`) |
| Budget | $25/mo, 50/90/100% alerts |
| DNS | GoDaddy: `A mcp → 34.111.4.193` (apex + `node.` untouched) |

## Two unavoidable facts that shape the plan

1. **The static IP cannot move.** External IPs are project-scoped — the new LB gets a **new IP**, so the GoDaddy `A mcp` record must change. This is the only user-visible cutover step.
2. **Google-managed certs have a chicken-and-egg** (the domain must resolve to the LB to validate). To avoid a downtime window, we **pre-provision the cert with Certificate Manager DNS-authorization** (one temporary CNAME at GoDaddy) *before* flipping the A record → zero-downtime cutover.

## Phased plan

### Phase 0 — Decisions + access (you; see "What I need" below)
New project ID / org / billing enabled; grant the runner roles; confirm the org-policy path; decide copy-vs-rotate on secrets; confirm config (region, budget, Cloud Armor, min-instances).

### Phase 1 — Stand up the new stack (old keeps serving; no DNS change yet)
1. `gcloud config set project <NEW>`; enable APIs: `run, cloudbuild, artifactregistry, secretmanager, compute, monitoring, certificatemanager`.
2. **Secrets:** copy the 3 values from old → new (I have read access on old), or rotate (see decision). Grant the new project's compute SA `secretmanager.secretAccessor`.
3. **Org policy:** set the project-scoped `iam.allowedPolicyMemberDomains = ALLOW` override (needs org-policy admin — you or the new org's security owner).
4. **Deploy Cloud Run** `clockchain-mcp` from source (same env/secrets/scaling) → yields a new `*.run.app` URL. Grant `allUsers` → `run.invoker`.
5. **LB:** reserve a **new static IP**, create serverless NEG → backend `clockchain-mcp-be`, attach a recreated **Cloud Armor** policy, URL map + HTTP→HTTPS redirect, target HTTPS proxy.
6. **Cert (pre-provision):** Certificate Manager cert for `mcp.clockchain.network` with **DNS authorization** → add the temp CNAME at GoDaddy → wait for cert ACTIVE. (Old A record still points at the old IP, so no traffic impact.)
7. **Monitoring:** recreate uptime check + alert → `yt@d4d.group`. **Budget:** recreate.
8. **CI/CD:** create WIF pool/provider + deploy SA in the new project, bind to the repo; update `deploy.yml` (`project_id`, `workload_identity_provider`, `service_account`).

### Phase 2 — Validate the new stack (before cutover)
- New `*.run.app`: `initialize` returns serverInfo; no-token returns 401.
- New LB IP with `Host: mcp.clockchain.network` (curl `--resolve`) serves correctly + cert valid.

### Phase 3 — Cutover (the only user-visible step)
1. Lower the GoDaddy `A mcp` TTL ahead of time (e.g., 600s).
2. Flip `A mcp → <NEW_IP>`. Because the cert is already ACTIVE (Phase 1.6), there's no provisioning gap. Old LB keeps answering until DNS propagates → no downtime.
3. Verify `https://mcp.clockchain.network/mcp` serves from the new project (check a response header / revision).

### Phase 4 — Decommission old (after a safe window, ~1 week)
- Confirm CI/CD deploys hit the new project; Vercel playground + token holders unaffected (URL unchanged; token changed only if rotated).
- Update `CLOUD-RUN.md` + memory with the new project/IP.
- Tear down old resources or **delete the `clockchain-mcp-yarda` project** (resets its org-policy override automatically). Release the old static IP.

## Risks & mitigations
- **DNS propagation window** → pre-lower TTL; both LBs serve identical app during overlap → no downtime.
- **Cert gap** → Certificate Manager DNS-auth pre-provision (Phase 1.6).
- **New org enforces Domain-Restricted-Sharing** → need org-policy admin for the ALLOW override (same exception as today; reversible).
- **Token rotation** → if `mcp-auth-tokens` rotates, update Vercel `MCP_SERVER_TOKEN` + notify tester/exec holders. Clean migration = copy as-is, rotate later.
- **WIF rebind** → GitHub repo admin to update `deploy.yml` + repo settings.
