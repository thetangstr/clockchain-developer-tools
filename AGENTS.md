# AGENTS.md — working in this repo

Clockchain MCP server (npm-workspaces monorepo: `@clockchain/core`, `@clockchain/mcp-server`,
`@clockchain/web-demo`). Hosted on GCP Cloud Run at `https://mcp.clockchain.network/mcp`.

## Build & test (run before every push)

```bash
npm run build                 # all workspaces  (or: -w @clockchain/mcp-server)
npm test                      # all workspaces  (or: -w @clockchain/mcp-server)
```

## Non-negotiable rules

1. **Run `npm test` before pushing.** Verifying only via live curl / a running server is
   not enough — it has already shipped red code to `main`. Build + test locally first.
2. **Never disable the deploy gate.** `deploy.yml`'s `deploy` job `needs: test`; red tests
   must block production. Fix the test, not the gate.
3. **Don't push red code to `main`.** There's no branch protection (private/free repo), so
   the deploy gate is the only hard guard — green local tests are still your job.
4. **One agent per working tree.** Never run two agents/sessions in the same checkout. Use a
   separate clone or `git worktree`. Untracked half-built work breaks the root build and
   cross-contaminates commits.
5. **Commit surgically.** `git add <explicit paths>`, never `git add -A`. Check `git status`
   first; never sweep up another agent's untracked files, `.omc/` state, or `.gitignore`
   churn. From a shared branch, confirm `git log origin/main..HEAD` shows only your commits
   before `git push origin HEAD:main`.
6. **No secrets in git or docs.** Secret Manager (server), WIF (CI, keyless), Vercel env
   (playground). Use placeholders in committed files.
7. **Deploys are automated** (push to `main`, code paths → Cloud Run). Don't hand-deploy from
   a laptop except emergencies. After changing a workflow, `gh run watch` it.

## Where things live

- CI/CD plan + rules: [`cicd-plan.md`](cicd-plan.md)
- Hosting / ops / rotation / rollback: [`CLOUD-RUN.md`](CLOUD-RUN.md)
- Connecting (delegated + bring-your-own-key): [`INSTALL.md`](INSTALL.md)
- Auth & cost model: [`auth-and-traffic-decision.md`](auth-and-traffic-decision.md)
