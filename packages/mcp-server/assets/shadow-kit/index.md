# Clockchain Shadow: record what your agent did, and let someone else check it

Shadow is a flight recorder for AI agents. Your agent records each step as it works, Shadow signs the steps and anchors their fingerprints on a ledger, and you share one link. Whoever opens it can see whether anything changed afterwards. Testnet; free account, no email; works with any MCP client.

- Quickstart: quickstart.md
- Connect instructions, the server's own and written for agents: https://mcp.clockchain.network/shadow/connect
- MCP endpoint: https://mcp.clockchain.network/shadow/mcp. On claude.ai, use /shadow/chat/mcp instead.
- Book a demo: CALENDLY_URL

## What it does for you

1. **Every step, in order.** The task, each tool call and result, and each message are numbered and chained, so a missing or reordered step shows up.
2. **One link to share.** The person who checks opens it in their own browser, with no account.
3. **Changes show up.** Change one character in a recorded step and the verifier's content check fails.
4. **Works with the agent you have.** ChatGPT, Claude, Claude Code, Codex or any MCP client. Agents that run code can sign in with their own key.
5. **Fingerprints on the ledger, not your content.** The full record stays on the Shadow server; only hashes go to the ledger.
6. **You stay in control.** Say "stop logging". Revoke links, delete a record, or delete the account.

## What happens when you connect

1. Add the connector. Sign-in creates a free testnet account with no email, and the account key is shown once.
2. Work as usual. Logging is on by default; naming Shadow in your request makes recording far more likely.
3. Close the session. You get a viewer link and a pin; send the pin separately.
4. Someone else opens the link and sees each step, its time window and the checks: pass, indeterminate or fail.

## The honest version

- A pass means the record is intact. It doesn't show the output is true, compliant or complete.
- Only what the agent recorded is covered.
- Times are windows between ledger receipts.
- Testnet only. Records are deleted after 30 days.
- Anyone with a viewer link can read the whole record, so use synthetic or redacted content.
- The ledger is our own single-operator gateway on testnet.
- Sign-up was tested in real accounts with ChatGPT, claude.ai, Claude Code and Codex on 20–21 Nov. Other clients and some ChatGPT plans aren't confirmed.
- A standalone verifier isn't published yet.

## Design partner program

- **You get:** a direct line to the team, help setting up your first recorded workflow, early access to what we ship next (sharing a record without its content, and a verifier you run yourself), and a say in the roadmap.
- **We ask:** try Shadow on one real agent workflow with synthetic or redacted content, tell us what's missing, and join a short check-in.
