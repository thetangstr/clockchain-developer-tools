# Delegated Access for Testers (no VPN)

How to give business testers access to a Clockchain test endpoint **without**
handing out the real API key and **without** a VPN - while keeping "just anyone"
out. Two access products, one protection model.

## The protection model: two independent gates

```
Tester ─▶ [ Cloudflare edge: identity gate ] ─▶ [ our server: token + caps ] ─▶ Clockchain gateway
            blocks anyone not on the allowlist     key custodied here, never sent out
```

1. **Edge identity gate (Cloudflare Access).** Nobody reaches the server unless
   they're on your allowlist. Scanners/bots are stopped at Cloudflare before a
   request ever touches the host. No VPN, nothing to install.
2. **App gate (our server).** Even an allowed caller is bounded: token auth,
   per-token rate limit, a logging-credit spend cap, read+log tools only,
   non-custodial (no private key on the box). The real Clockchain API key lives
   only on the server and is never returned to the client.

Two ways testers consume it:
- **Web demo (Option 1)** - a browser page; tester logs in with an email code. Zero install.
- **MCP endpoint (Option 2)** - the real agent experience via Claude; tester pastes a short config.

---

## Prerequisites

- A domain on Cloudflare (e.g. `clockchain.network`) with a free **Zero Trust**
  (Access) plan enabled.
- A host to run the services: the **Mac mini** (`cloudflared` tunnel) or **GCP
  Cloud Run** (see per-host notes at the end).
- The built packages (`npm run build`) and a filled `.env`.

---

## Part A - run the services (hardened)

From `packages/mcp-server` and `packages/web-demo`, with secrets exported
(`set -a; source .env; set +a`). Note the hardening flags:

```bash
# MCP endpoint (Option 2) - tokens REQUIRED, rate-limited, budget-capped
MCP_TRANSPORT=http MCP_PORT=3000 \
MCP_REQUIRE_AUTH=1 \
MCP_AUTH_TOKENS="$(openssl rand -hex 24),$(openssl rand -hex 24)" \
MCP_RATE_PER_MIN=30 MCP_LOG_BUDGET=200 \
node packages/mcp-server/dist/index.js

# Web demo (Option 1) - identity-gated at the edge; spend-capped
WEB_PORT=8080 MCP_LOG_BUDGET=200 \
node packages/web-demo/dist/server.js
```

- `MCP_REQUIRE_AUTH=1` makes the MCP host **refuse to start without tokens** (no
  accidental open endpoint).
- Use **high-entropy tokens** (the `openssl rand` above), one per tester.
- `MCP_RATE_PER_MIN` caps requests per token; `MCP_LOG_BUDGET` caps total writes.
- For real running, use the pm2 path in `deployment.md` (`ecosystem.config.cjs`).

---

## Part B - Cloudflare Tunnel (expose without opening ports)

```bash
brew install cloudflared
cloudflared tunnel login
cloudflared tunnel create clockchain-test
# Route two hostnames to the two local services:
cloudflared tunnel route dns clockchain-test demo.clockchain.network   # web demo
cloudflared tunnel route dns clockchain-test mcp.clockchain.network    # MCP endpoint
```

`~/.cloudflared/config.yml`:

```yaml
tunnel: clockchain-test
credentials-file: /Users/<you>/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: demo.clockchain.network
    service: http://localhost:8080
  - hostname: mcp.clockchain.network
    service: http://localhost:3000
  - service: http_status:404
```

```bash
cloudflared tunnel run clockchain-test         # or install as a service:
sudo cloudflared service install
```

No inbound ports are opened on the Mac mini - the tunnel dials out to Cloudflare.

---

## Part C - Cloudflare Access policies (the identity gate)

In the Cloudflare **Zero Trust** dashboard → Access → Applications:

### Web demo (Option 1): interactive login
- Add a **self-hosted application** for `demo.clockchain.network`.
- Policy: **Allow** when **emails** are in your tester list (or **email domain**
  `@theircompany.com`). Identity method: one-time PIN (email code) or Google/SSO.
- Result: a tester opens the link, enters the emailed code, and uses the page. No
  install, no token to manage.

### MCP endpoint (Option 2): service token (for the programmatic client)
Claude connects programmatically, so it can't do an interactive login - use an
Access **service token**:
- Access → **Service Auth** → create a service token (per tester or per cohort).
  You get a `Client ID` and `Client Secret`.
- Add a **self-hosted application** for `mcp.clockchain.network` with a policy:
  **Allow** → **Service Auth** → that token (the human email policy can also be
  attached for browser checks).

---

## What each tester gets

**Web demo tester:** just the link.
> Open https://demo.clockchain.network, enter the code we email you, and try it.

**Claude (MCP) tester:** the URL + two CF headers + their app token, pasted into
Claude Desktop's MCP config:

```json
{
  "mcpServers": {
    "clockchain": {
      "type": "http",
      "url": "https://mcp.clockchain.network/mcp",
      "headers": {
        "CF-Access-Client-Id": "<their service-token id>",
        "CF-Access-Client-Secret": "<their service-token secret>",
        "x-api-key": "<their per-tester app token>"
      }
    }
  }
}
```

Then they ask Claude in plain English (see `TRY-IT.md`, Option B).

---

## Security checklist ("protect from just anyone")

- [ ] Cloudflare Access policy on **both** hostnames (no app is open to the world).
- [ ] MCP host started with `MCP_REQUIRE_AUTH=1` and high-entropy `MCP_AUTH_TOKENS`.
- [ ] `MCP_RATE_PER_MIN` and `MCP_LOG_BUDGET` set.
- [ ] A **low credit cap on the Clockchain test account** itself (hard backstop).
- [ ] TLS everywhere (automatic via Cloudflare).
- [ ] One token / service token **per tester** → revoke individually; rotate after the test.
- [ ] Per-call logs watched; tear the tunnel + tokens down when the test ends.
- [ ] Only read + `log_action` tools exposed; non-custodial (no private key on the host).

---

## Per-host notes

- **Mac mini:** the `cloudflared` tunnel above is the fit - no ports, no static IP.
- **GCP Cloud Run:** you can either front Cloud Run with the same Cloudflare
  Access setup (custom domain), or use Cloud Run's own controls
  (`--no-allow-unauthenticated` + IAP / IAM). Either way, keep the app-layer token
  + rate limit + budget; put the API key in **Secret Manager**. See
  `deployment.md` section 4.
