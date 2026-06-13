# CI/CD — Plan & Rules

How code reaches production for the Clockchain MCP server, the **rules** everyone
(humans and agents) follows, and the **forward plan**. Born from a real incident:
breaking changes shipped to `main` verified only by live curl, no `npm test` run —
CI went red for days while deploys kept succeeding because the two ran independently.
This doc exists so that doesn't recur.

## Current pipeline

```
PR  ──▶ ci.yml          build + test (Node 20 & 22)         [signal only — see note]
push main ─┬─▶ ci.yml   build + test
           └─▶ deploy.yml: test ──gate──▶ deploy (Cloud Run, keyless WIF) ──▶ /health smoke test
```

- **`ci.yml`** — `npm install && npm run build && npm test` on every PR and main push, Node 20 + 22.
- **`deploy.yml`** — on push to `main` (code paths only): a `test` job, then a `deploy`
  job that **`needs: test`** (red tests block the deploy), via Workload Identity
  Federation (no stored keys), then a `/health` smoke test. Manual escape hatch:
  `gcloud run deploy --source . --region us-central1` (preserves env/secrets/scaling).
- Host/ops detail (WIF, Cloud Armor, monitoring, rotation, rollback): see
  [`CLOUD-RUN.md`](CLOUD-RUN.md).

> **Note — no branch protection.** This is a private repo on the free plan, so GitHub
> cannot *enforce* "CI must pass before merge." The **deploy gate is the only hard
> technical guard**: even if red code lands on `main`, the gate stops it reaching
> production. Everything else below is discipline. If the repo goes Pro/public, turn on
> branch protection (required status check = `CI`, require PR review) — see Plan.

## Rules (non-negotiable)

1. **Run `npm test` before you push.** Never verify a change only by live curl / a
   running server. Build + test locally first: `npm run build && npm test` (or per
   package: `npm test -w @clockchain/mcp-server`). This is the exact step that was
   skipped and caused the incident.
2. **Never bypass or disable the deploy gate.** `deploy` must keep `needs: test`. If a
   test is wrong, fix the test — don't remove the gate.
3. **Don't push red code to `main`.** Local tests green is the bar. No branch protection
   means this is on you; the gate is the backstop, not the permission.
4. **One agent per working tree.** Do **not** run two agents/sessions in the same
   checkout. Half-built untracked work (e.g. a package with no `tsconfig.json`) breaks
   the root build and risks cross-contamination. Use a separate clone or `git worktree`.
5. **Commit surgically.** Stage explicit paths (`git add <file> …`), never `git add -A`.
   Check `git status` first; never sweep up another agent's untracked WIP, `.omc/`
   state, or `.gitignore` churn. When pushing only your commits onto `main` from a
   shared branch, confirm `git log origin/main..HEAD` shows **only your commits**, then
   `git push origin HEAD:main`.
6. **No secrets in git or docs.** Server secrets → Secret Manager. CI auth → WIF
   (keyless, no SA key in GitHub). Playground → Vercel env. Tokens/keys never go in
   committed files or public docs — use placeholders (`<your token>`).
7. **Deploys are automated.** Push to `main` (code paths) deploys. Don't hand-deploy
   from a laptop except a real emergency — and if you do, say so and re-run CI after.
8. **Keep the deploy path-filtered.** Doc-only commits must not redeploy. The filter in
   `deploy.yml` (`packages/**`, `Dockerfile`, manifests, the workflow) stays tight.
9. **Verify after deploy.** The workflow smoke-tests `/health`; for anything
   non-trivial, also confirm `tools/list` (25) and a real tool call against
   `mcp.clockchain.network` before calling it done.

## Rollback

Cloud Run keeps every revision. To roll back instantly:
```bash
gcloud run revisions list --service clockchain-mcp --region us-central1   # find the last good one
gcloud run services update-traffic clockchain-mcp --region us-central1 \
  --to-revisions=<GOOD_REVISION>=100
```
Then fix forward (revert the bad commit, let CI/deploy re-ship).

## Forward plan (prioritized)

1. **Enforce CI when possible.** If the repo moves to GitHub Pro or public: branch
   protection on `main` — required status check `CI`, require a PR (no direct pushes),
   dismiss stale reviews. This makes Rule 3 a guarantee, not a request.
2. **De-duplicate the test run.** `ci.yml` and `deploy.yml`'s `test` job both run on main
   pushes. Either (a) gate deploy on `ci.yml` via `workflow_run`, or (b) drop `ci.yml`'s
   `push:main` trigger (keep it PR-only) so main runs tests once, inside the gate.
3. **Fix the playground (`clockchain-research`) CI/CD.** Today production ships via
   `vercel --prod` from a feature branch and `main` lags. Target: Vercel **git-based**
   auto-deploy from `main` + a PR preview, and reconcile the branch/main divergence.
   Stop CLI-from-branch deploys.
4. **Failure notifications.** Route CI/deploy failures to email/Slack (a step in the
   workflow or a GitHub notification rule) so red `main` is noticed in minutes.
5. **Staging (optional).** A pre-prod Cloud Run service for smoke-testing risky changes
   before prod, if/when traffic justifies it.
6. **Secret/token rotation cadence.** Make the rotation runbook in `CLOUD-RUN.md` a
   scheduled habit (quarterly), and prefer per-consumer MCP tokens (revocable).

## When you change the pipeline

- Edit the workflow, push, and **watch the run** (`gh run watch <id> --exit-status`) —
  don't assume. A workflow-file change triggers itself.
- Keep `AGENTS.md` and this doc in sync with what the workflows actually do.
