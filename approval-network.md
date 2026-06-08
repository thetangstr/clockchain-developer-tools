# Clockchain MCP - Network & Tech Approval

**For:** network / tech team · **Separate** from the business-exec meeting. Date: 2026-06.

The business approval (direction + go-ahead) happens live with execs. This is the
separate, focused technical sign-off: **how the MCP server is exposed, and how
business folks reach the playground - without holding the Clockchain key or a VPN.**

## The recommended access model (the verdict)
Two independent gates; the server never holds a private key:

1. **Edge identity gate - Cloudflare Tunnel + Cloudflare Access.** A normal HTTPS
   link (e.g. `mcp-demo.<domain>`), **no inbound ports**, **no VPN/Tailscale for
   testers**. Access allowlists by **email / SSO** - business folks click the link,
   confirm a one-time email code, and they're in. Everyone else is blocked at the edge.
2. **Application gate - the server.** The Clockchain API key stays server-side; a
   per-tester token (for the MCP path), a spend cap, and rate limiting; read +
   notarize/attest tools only; non-custodial.

This replaces Tailscale-for-testers (too much friction for execs) and keeps the
"do not expose the Clockchain server" posture: allowlist-gated, not a public bind.

## Decisions requested from the network/tech team
1. Approve **stdio / local default** for co-located agents (no exposure). [ ]
2. Approve **Cloudflare Access (identity-gated) HTTPS** for business/design-partner
   testers; no public bind, no VPN, key custodied server-side. [ ]
3. Provide a **Cloudflare account + a domain on Cloudflare + Zero Trust enabled**
   (the one thing only the team can do). [ ]
4. v3 cloud (AWS or GCP): public mainnet-gated [ ] / identity-gated only [ ] /
   distribute the local server [ ].

## Deployment dependencies to provision
| Dependency | For | Owner |
|---|---|---|
| Cloudflare domain + Zero Trust Access app/policy + per-tester tokens | gated playground (v2) | Network / Eng |
| Mac mini host prep (already on the tailnet; runs the playground today) | v2 | Eng |
| EVM RPC + chain + ERC-8004 **production registry** (assumption to confirm) | identity read/write | Network / Backend |
| Secrets store + managed RPC (AWS Secrets Manager / GCP Secret Manager) | v3 | Eng |
| Backend: expose `/schedule` (smart contracts, 404 today) + multi-validator | full product | Backend (D4) |

## Sign-off
- Network/tech reviewer: ____________________  Date: __________
- Decision: approved as proposed / approved with changes / needs discussion

Detail: `deployment.md` (network model + hosting), `DELEGATED-ACCESS.md` (the
Cloudflare runbook).
