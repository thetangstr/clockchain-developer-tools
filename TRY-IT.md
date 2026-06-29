# Try Clockchain Yourself

A hands-on test for non-engineers. If you know what "anchoring a hash on-chain
with a consensus timestamp" means but don't want to wrangle code, this is for you.
About 10 minutes, mostly one-time setup.

## What you'll prove

You'll have an **AI agent put a tamper-evident, independently-timestamped record
on the Clockchain network and verify it later** - with no wallet, no gas, and no
private key in sight. Specifically:

1. Read the network's decentralized **consensus clock**.
2. **Notarize** a document (its hash, anchored on-chain with a consensus timestamp).
3. **Prove** the document is unchanged - and watch the system **catch a tampered copy**.

That last step is the point: verifiable proof of an agent's action.

> **No Clockchain account yet? Start here — zero setup, no key.** One command runs the
> whole alarm flow (anchor + keyless verify) through the hosted network with a free,
> self-serve demo token (requires [`jq`](https://jqlang.github.io/jq/)):
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/thetangstr/clockchain-developer-tools/main/packages/clock-sdk/examples/try-alarm-mcp.sh | bash
> ```
>
> Come back to the steps below when you want to run it under your own account (Option B).

## Before you start (one-time, ~5 min)

You need three things:

1. **Node.js** - the runtime this tool runs on. Install the "LTS" version from
   [nodejs.org](https://nodejs.org). (One install, then forget about it.)
2. **Claude Code** or **Claude Desktop** - the AI assistant you'll talk to.
   See [claude.com/product/claude-code](https://claude.com/product/claude-code).
   *(Only needed for Option B below. Option A doesn't need it.)*
3. **A Clockchain API key** - your access to the network, from your Clockchain
   dashboard (same place you see logs and credits). Treat it like a password.
   You'll also want a handful of **log credits** on the account - each
   notarization spends one.

Everything runs from **Terminal** (on a Mac: press Cmd+Space, type "Terminal",
hit Enter). You'll paste a few lines. That's the extent of the "coding."

## Step 1 - get the tool

Paste these one block at a time:

```bash
git clone https://github.com/thetangstr/clockchain-developer-tools.git
cd clockchain-developer-tools
npm install
npm run build
```

This downloads the tool and gets it ready. The `npm install` step may take a
minute the first time.

> **No Clockchain account yet?** Skip the key steps — run
> `bash packages/clock-sdk/examples/try-alarm-mcp.sh`; it mints a free demo token (no
> signup; requires `jq`) and runs the alarm through the hosted MCP. Come back when you have
> your own account.

## Step 2 - add your key

Replace the placeholders with your own values:

```bash
export CLOCKCHAIN_API_KEY=your-api-key-here
export CLOCKCHAIN_CLIENT_ID=you@example.com
export CLOCKCHAIN_WALLET_ID=you@example.com
```

(These live only in your Terminal window - nothing is saved or shared.)

## The test - pick one

### Option A: the guided tour (simplest, no AI setup)

```bash
cd packages/mcp-server
npm run demo
```

It narrates itself: reads the clock, notarizes a document, waits for the network
to confirm it, verifies the original, then tries a **tampered** copy. It ends with
`RESULT: PASS`.

**What you're looking at, in blockchain terms:**
- `blockHeight` going from pending to a real **block number** = your record is
  anchored on-chain.
- `match: true` on the original and `match: false` on the altered copy =
  tamper-evidence working.

### Option B: ask an AI agent (the "wow")

> **Easiest:** point any MCP client (Claude Code, Cursor, Codex, Hermes, OpenClaw)
> at the **hosted endpoint** — no clone/build. See [`README.md`](README.md) /
> [`INSTALL.md`](INSTALL.md). The steps below self-host it over local stdio.

1. Connect the tool to your client. Claude Code, run from the
   `clockchain-developer-tools` folder (other clients: same `command`/`args` in
   your MCP config):

   ```bash
   claude mcp add clockchain \
     --env CLOCKCHAIN_API_KEY=$CLOCKCHAIN_API_KEY \
     --env CLOCKCHAIN_CLIENT_ID=$CLOCKCHAIN_CLIENT_ID \
     --env CLOCKCHAIN_WALLET_ID=$CLOCKCHAIN_WALLET_ID \
     -- node "$(pwd)/packages/mcp-server/dist/stdio.js"
   ```

2. Open a **new** Claude session and type `/mcp`. You should see **clockchain**
   listed with its tools.
3. Ask, in plain English:
   > "Use clockchain to notarize this text: *Q3 board resolution* - then prove it
   > hasn't changed."
4. Claude does it and shows you the proof. Now the fun part: **change one word**
   and ask it to verify again - it will catch the change.

## What just happened (the business point)

An AI agent created a tamper-evident, independently-timestamped on-chain record
and verified it later - without touching a wallet, gas, faucet, or private key.
That is the wedge use case: **verifiable proof of an agent's action**, riding
Clockchain's two differentiators (verifiable time + the agent's action).

## If something goes wrong

| You see | What it means | Fix |
|---|---|---|
| `command not found: npm` | Node.js isn't installed | Install it (Before you start, step 1) |
| `Authentication failed` | API key missing or wrong | Re-check Step 2 |
| `Insufficient logging credits` | Out of log credits | Top up in your Clockchain dashboard |
| `Rate limit exceeded` | You went too fast | Wait a few seconds and retry |
| `clockchain` not in `/mcp` | Added it in an already-open session | Open a **new** Claude session |

## Go deeper

- `QUICKSTART.md` - the engineer's version (tests, all run options).
- `mcp-deployment-brief.md` - what we're building and why (the approval brief).
- `deployment.md` - hosting a shared test endpoint for a group.

> Note: the current network is a test deployment. The workflow is real and
> verifiable; the data is not yet authoritative (that comes with mainnet).
