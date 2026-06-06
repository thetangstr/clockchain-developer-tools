# scripts/ - Markdown to Google Docs

`md-to-gdocs.mjs` turns the spec Markdown in this repo into native Google Docs
using the Google Drive API's Markdown-import conversion (GA since July 2024).

You sign in as yourself in a browser; no password or key is stored in code.
The OAuth scope is `drive.file`, so the script can only touch files it creates.

## One-time setup

1. In Google Cloud Console, create an OAuth client of type **Desktop app**
   (https://developers.google.com/workspace/guides/create-credentials) and save
   the downloaded JSON as `scripts/credentials.json`.
2. Install deps:
   ```bash
   cd specs/scripts
   npm init -y
   npm i googleapis @google-cloud/local-auth
   ```

## Run

```bash
node md-to-gdocs.mjs                          # convert the default spec set
node md-to-gdocs.mjs roadmap.md mcp-deployment-brief.md   # specific files
FOLDER_ID=<driveFolderId> node md-to-gdocs.mjs            # drop into a folder
```

First run opens a browser for consent and caches a token at `scripts/token.json`.
Each created doc's URL is printed.

## Notes

- `credentials.json` and `token.json` are gitignored. Never commit them.
- Inline images in Markdown convert to data URLs and may break; the spec files
  here are text/tables only, so this does not apply.
- Account: pick the Google account at the consent screen (e.g. your Workspace
  account, not a personal one) - the docs land in that account's Drive.

## Alternatives (no code)

- **File > Open** in Google Docs, or drag the `.md` into Drive and
  "Open with Google Docs" - fastest for a one-time batch.
- **Tools > Preferences > Enable Markdown** turns on "Paste from Markdown".
