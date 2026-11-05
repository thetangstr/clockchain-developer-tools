# ChatGPT plugin package: Clockchain Shadow

A draft of the ZIP that OpenAI's portal takes. Nothing has been uploaded. `clockchain-shadow/` holds `plugin.json` and
`mcp.json`, following `project-shadow/docs/launch/submission-chatgpt.md`.

## Before it can be uploaded

Only the founder can do these:

- Choose the legal entity and complete OpenAI's business verification. Everything marked `[FILL IN]` waits on it or on the
  pages below.
- Publish the website, support, privacy and terms pages, after counsel review. They must name the same publisher.
- Make `assets/logo.png` and `assets/icon.png`: square, 48x48 or larger, 5 MiB or less. There's no logo file in this repo.
- Choose the countries, after counsel review.
- Record the demo video on ChatGPT web, desktop and mobile, with the test account and fictional data, and host it.
- Test in real ChatGPT with the five positive and three negative cases. **This has never been done.** See below.
- Enter the challenge token the portal gives you (RUNBOOK, "ChatGPT domain check") and the reviewer's key in the secure
  **Review details** form. The key never goes in the ZIP: it rejects `test_credentials` and `reviewer_instructions`.

## Test cases

`plugin.json` holds exactly five positive and three negative cases. `scripts/chatgpt-review-cases.mjs` drives the tools
each case names, against a server, and checks what the server returned:

```bash
node scripts/seed-reviewer-account.mjs --base http://localhost:8080 --key-file /path/to/key.txt
node scripts/chatgpt-review-cases.mjs --base http://localhost:8080 --key-file /path/to/key.txt
```

**What this proves, and what it doesn't.** No model runs here, so it shows that each tool does its part. It can't show that
ChatGPT chooses the right tool, answers well, or leaves Shadow alone when nobody asks to record. Those need the real run.
For the negative cases it can only check the server's side: that merely connecting records nothing, that no tool can
move money, and that a check says it is no verdict on truth or compliance.

`packages/mcp-server/test/chatgpt-review-cases.test.mjs` runs it on every test run, and checks the package against the
limits in OpenAI's docs.
