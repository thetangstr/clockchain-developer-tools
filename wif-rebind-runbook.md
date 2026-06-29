# CI/CD WIF Rebind Runbook — `clockchain-mcp`

*Goal: GitHub Actions deploys land on the dedicated `clockchain-mcp` project. `deploy.yml` is **already** updated (project_id, WIF provider `…/886160542191/…`, SA `gh-deploy@clockchain-mcp`). What remains is creating the GCP-side WIF infra + secrets in `clockchain-mcp` — all **human gcloud/IAM steps** (Claude cannot run gcloud or change IAM).*

**Until these run, merging the truthful-anchoring PR will make the deploy job fail at the WIF auth step.** So: run this → verify a deploy → then merge PR #78.

## 0. Verify the project number matches deploy.yml
```bash
gcloud projects describe clockchain-mcp --format='value(projectNumber)'   # expect 886160542191
```

## 1. Context + APIs
```bash
gcloud config set project clockchain-mcp
PROJECT_ID=clockchain-mcp; PROJECT_NUMBER=886160542191
GITHUB_REPO=thetangstr/clockchain-developer-tools
DEPLOY_SA=gh-deploy@clockchain-mcp.iam.gserviceaccount.com

gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com compute.googleapis.com monitoring.googleapis.com \
  --project=$PROJECT_ID
```

## 2. Workload Identity Pool + OIDC provider (repo-locked)
```bash
gcloud iam workload-identity-pools create github --project=$PROJECT_ID --location=global --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github-provider \
  --project=$PROJECT_ID --location=global --workload-identity-pool=github \
  --display-name="GitHub provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="attribute.repository == '${GITHUB_REPO}'"
```

## 3. Deploy SA + bindings
```bash
gcloud iam service-accounts create gh-deploy --project=$PROJECT_ID --display-name="GitHub Actions deploy SA"

# WIF principalSet -> SA (lets the repo's Actions tokens impersonate the SA)
gcloud iam service-accounts add-iam-policy-binding $DEPLOY_SA --project=$PROJECT_ID \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/attribute.repository/${GITHUB_REPO}"

# SA working roles (mirror yarda)
for ROLE in roles/run.admin roles/iam.serviceAccountUser roles/cloudbuild.builds.editor roles/artifactregistry.writer; do
  gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:${DEPLOY_SA}" --role=$ROLE
done
```

## 4. Artifact Registry (source-deploy default)
```bash
gcloud artifacts repositories create cloud-run-source-deploy --project=$PROJECT_ID \
  --repository-format=docker --location=us-central1 --description="Cloud Run source-deploy images"
# (harmless error if it already exists)
```

## 5. Secrets (copy from yarda or rotate) + access for the runtime SA
| Secret | Env var |
|---|---|
| `clockchain-api-key` | `CLOCKCHAIN_API_KEY` |
| `mcp-auth-tokens` | `MCP_AUTH_TOKENS` |
| `mcp-token-signing-secret` | `MCP_TOKEN_SIGNING_SECRET` |
```bash
echo -n "VALUE" | gcloud secrets create clockchain-api-key --project=$PROJECT_ID --data-file=-
echo -n "VALUE" | gcloud secrets create mcp-auth-tokens --project=$PROJECT_ID --data-file=-
echo -n "VALUE" | gcloud secrets create mcp-token-signing-secret --project=$PROJECT_ID --data-file=-

COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for S in clockchain-api-key mcp-auth-tokens mcp-token-signing-secret; do
  gcloud secrets add-iam-policy-binding $S --project=$PROJECT_ID \
    --member="serviceAccount:${COMPUTE_SA}" --role=roles/secretmanager.secretAccessor
done
```
Plain env vars on the Cloud Run service: `MCP_TRANSPORT=http`, `MCP_REQUIRE_AUTH=1`, `MCP_RATE_PER_MIN=30`, `MCP_LOG_BUDGET=5000`, `MCP_TOKEN_MINT_PER_HOUR=10`, `MCP_TOKEN_TTL_DAYS=7`, `CLOCKCHAIN_ENDPOINT=https://node.clockchain.network`, `CLOCKCHAIN_CLIENT_ID=<from yarda>`, `CLOCKCHAIN_WALLET_ID=<from yarda>`.
Pull the two CLIENT/WALLET values: `gcloud run services describe clockchain-mcp --region=us-central1 --project=clockchain-mcp-yarda --format='value(spec.template.spec.containers[0].env)'`

## 6. Org policy (if domain-restricted sharing is enforced) — needs `roles/orgpolicy.policyAdmin`
```bash
gcloud org-policies set-policy - --project=$PROJECT_ID <<'EOF'
name: projects/clockchain-mcp/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
    - allowAll: true
EOF
gcloud run services add-iam-policy-binding clockchain-mcp --project=$PROJECT_ID \
  --region=us-central1 --member=allUsers --role=roles/run.invoker
```

## 7. Trigger + verify
Re-run the workflow (`workflow_dispatch` or a no-op push to `main`). The deploy.yml smoke test hits `/health`. Manual spot-check:
```bash
URL=$(gcloud run services describe clockchain-mcp --project=clockchain-mcp --region=us-central1 --format='value(status.url)')
curl -s "$URL/health"                                   # 200
curl -s -o /dev/null -w '%{http_code}' "$URL/mcp"       # 401 (auth guard)
```
*WIF auth failure (`Permission denied on WIF`) is almost always the `principalSet` repo slug not matching — confirm `thetangstr/clockchain-developer-tools`.*

## Human-only (access-control) steps
gcloud auth + all IAM bindings · org-policy override · secret values (copy/rotate from yarda) · the CLIENT/WALLET env values · the GitHub Actions re-run.

## Then
Once a deploy succeeds on `clockchain-mcp`, **merge PR #78** → the truthful-anchoring changes deploy to the live account.
