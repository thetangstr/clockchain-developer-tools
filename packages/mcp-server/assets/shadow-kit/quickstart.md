# Clockchain Shadow Quickstart

Shadow is a flight recorder for AI agents. An agent records each step of a task, Shadow signs the steps and anchors their fingerprints (hashes) on a ledger, and anyone with the record's link can check that nothing changed afterwards. Testnet only.

## If you are an agent

1. Read the server's own instructions, in plain text: https://mcp.clockchain.network/shadow/connect
2. Connect to the MCP endpoint, streamable HTTP: https://mcp.clockchain.network/shadow/mcp
   - On claude.ai use https://mcp.clockchain.network/shadow/chat/mcp instead.
   - There is nothing to install.
3. Sign in, in one of two ways:
   - **OAuth:** a person signs in, and sign-up creates a free testnet account with no email.
   - **Your own key:** if you run code, sign in with your own Ed25519 key and DPoP, with no person or account. The connect page gives the exact fields.
4. Record the task:
   1. `shadow_start_session`;
   2. `shadow_record` for each step: task, prompt, message, tool_call, tool_result, file or note;
   3. `shadow_close_session`;
   4. give the person the viewer link.
5. If you signed in with your own key, sign in this order:
   1. Record your steps.
   2. `shadow_checkpoint`. Check that `sign.count` is your last step's `seq` and `sign.head` is its hash. The server's own opening steps are numbered with yours. Don't sign if either differs.
   3. Sign `sign.hash`: the 32 bytes of the hex decoded, Ed25519, standard base64. Send it with `shadow_sign_checkpoint`.
   4. `shadow_close_session`. The close adds the server's closing steps, so its count is a few higher.
   5. Sign its `sign.hash` the same way, with `shadow_sign_checkpoint`.
   6. Lost a hash? `shadow_checkpoint` returns the one still waiting, even after the close.
6. Never record secrets or personal data. Anyone with the viewer link can read every step.

Prompt a person can paste into their agent:

> Connect to Clockchain Shadow, a flight recorder for AI agents. Read https://mcp.clockchain.network/shadow/connect and follow it to connect (MCP endpoint: https://mcp.clockchain.network/shadow/mcp). Then record this task with Shadow, close the session, and give me the viewer link.

## 1. Connect

| Where your agent runs | How | Status |
|---|---|---|
| Codex, scripts, agents that run code | Own Ed25519 key. Follow https://mcp.clockchain.network/shadow/connect | Tested 20 and 21 Nov 2026 |
| Codex, with a person signing in | `codex mcp add shadow --url https://mcp.clockchain.network/shadow/mcp`; Codex opens the Clockchain sign-in in the browser (or run `codex mcp login shadow`). For unattended runs, allow Shadow's tools first, or every Shadow call is refused: `codex exec -c 'mcp_servers.shadow.default_tools_approval_mode="approve"' "Record this task with Shadow: …"`. | Tested 21 Nov 2026 |
| ChatGPT | Settings, Plugins, Browse directory, then Add and "Add custom MCP server". URL `https://mcp.clockchain.network/shadow/mcp`, authentication OAuth (ChatGPT finds the sign-in settings). Tick the risk notice, Create as a plugin, then Continue to Clockchain Shadow and sign in. In a chat, choose + and pick the connector; ChatGPT asks once before starting a session. Some plans may block tools that write. | Tested 21 Nov 2026 |
| claude.ai | Add a custom connector with `https://mcp.clockchain.network/shadow/chat/mcp`. Set "Sign in when needed" and "Register automatically" by hand. Sign-in opens when you click Add: create the account and save the key it shows once. | Tested 21 Nov 2026 |
| Claude Code | `claude mcp add --transport http shadow https://mcp.clockchain.network/shadow/mcp`, then `/mcp`, choose shadow and sign in in the browser | Tested 21 Nov 2026 |
| Any MCP client | Streamable HTTP with OAuth at `https://mcp.clockchain.network/shadow/mcp` | |

The account is free and on testnet, with no email. Keep the account key: a lost key plus cleared cookies loses the account.

## 2. Record

Logging is on by default once you're connected. Name Shadow in the request: "Record this task with Shadow: <your task>. When you're done, close the session and give me the viewer link." In our ChatGPT tests in November, the agent recorded the run every time Shadow was named in the request, and not when it wasn't.

Record only synthetic or redacted content. Shadow filters some credential formats, not personal data.

## 3. Close and share

- **Viewer link** (`/shadow/s/<link>`): the record as a web page. Send it to the person who checks.
- **Packet link** (`/shadow/p/<link>.json`): the same record as data.
- **Pin:** names the key that signed. Send it separately; the trust check compares against it.

## 4. Check it as a second person

Open the viewer link in a browser, with no account. You'll see a result:

- **pass:** every check that applies passed, and nothing was added, removed or changed since signing.
- **indeterminate:** nothing failed, but something couldn't be confirmed, often a ledger receipt or a time bound. The viewer shows indeterminate until the session is closed, and for about a minute after, until the ledger receipts arrive.
- **fail:** something doesn't match, such as a step changed after it was recorded. Don't rely on the record.

## 5. Stop, revoke, delete

- **Stop logging:** say "stop logging" (`clockchain_logging`). It holds for the whole account.
- **Revoke links:** `shadow_revoke_links`.
- **Delete:** `shadow_delete_session` deletes a record. You can also delete the whole account. Hashes on the ledger stay.

## Tools

`shadow_start_session`, `shadow_record`, `shadow_checkpoint`, `shadow_sign_checkpoint` (agent keys only), `shadow_close_session`, `shadow_verify`, `shadow_get_session`, `shadow_list_sessions`, `shadow_revoke_links`, `shadow_delete_session`, `clockchain_logging`.

## Limits

- **What a pass means:** the record is intact. It doesn't show the output is true, compliant or complete.
- **What's covered:** only what the agent recorded, not hidden reasoning or other apps.
- **Time:** times are windows between ledger receipts, not exact moments.
- **Testnet:** only testnet so far. Records are deleted 30 days after the session starts.
- **The ledger:** our own single-operator gateway, holding hashes only.
- **Not yet available:** a standalone verifier and a public sample record.

Book a demo: see index.md.
