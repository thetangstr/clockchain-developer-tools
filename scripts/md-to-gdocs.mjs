#!/usr/bin/env node
// md-to-gdocs.mjs
// Turn the spec Markdown in this repo into native Google Docs.
//
// MODES
//   node md-to-gdocs.mjs                 # create docs
//                                        #   - if docs.config.json exists, builds
//                                        #     ONE consolidated doc per group
//                                        #   - else one doc per file (DEFAULT_FILES)
//   node md-to-gdocs.mjs roadmap.md ...  # create one doc per named file (ignores groups)
//   node md-to-gdocs.mjs trash ID ID ... # move the given Doc IDs to Trash (reversible)
//   FOLDER_ID=<id> node md-to-gdocs.mjs  # place created docs in a Drive folder
//
// On create, writes a ledger at scripts/created.json (title -> {id,webViewLink})
// so you can re-trash a prior set with:  node md-to-gdocs.mjs trash $(cat ...)
//
// HOW IT WORKS
//   Drive "create with conversion": upload source mimeType text/markdown with
//   target mimeType application/vnd.google-apps.document. Drive converts to a
//   real Google Doc (native Markdown import, GA July 2024).
//
// AUTH: see README.md. OAuth Desktop client at scripts/credentials.json; token
//   cached at scripts/token.json. Scope drive.file (only files this app creates).
//   Both files are gitignored.

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, resolve, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import { google } from 'googleapis';
import { authenticate } from '@google-cloud/local-auth';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SPECS_DIR = resolve(__dirname, '..');
const CREDENTIALS_PATH = join(__dirname, 'credentials.json');
const TOKEN_PATH = join(__dirname, 'token.json');
const CONFIG_PATH = join(__dirname, 'docs.config.json');
const LEDGER_PATH = join(__dirname, 'created.json');
const SCOPES = ['https://www.googleapis.com/auth/drive.file'];

// Fallback set when there is no docs.config.json and no filenames are passed.
const DEFAULT_FILES = ['mcp-deployment-brief.md', 'roadmap.md'];

/**
 * Refresh the access token ourselves when it is expired/near-expiry.
 *
 * The googleapis library's built-in auto-refresh hangs under Node 23 (gaxios),
 * so we do the refresh with a plain fetch to the token endpoint (fast, reliable)
 * and persist the new access token + expiry. The OAuth2 client is then handed a
 * non-expired token and never triggers its own (hanging) refresh path.
 */
async function ensureFreshToken(key, token) {
  const skewMs = 120_000;
  const valid = token.access_token && token.expiry_date && token.expiry_date - skewMs > Date.now();
  if (valid || !token.refresh_token) return token;
  const body = new URLSearchParams({
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: token.refresh_token,
    grant_type: 'refresh_token',
  });
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const data = await res.json();
  if (!data.access_token) {
    throw new Error(`token refresh failed: ${data.error_description || data.error || res.status}`);
  }
  const updated = {
    ...token,
    access_token: data.access_token,
    expiry_date: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
  await writeFile(TOKEN_PATH, JSON.stringify(updated, null, 2));
  return updated;
}

async function getClient() {
  if (existsSync(TOKEN_PATH)) {
    const creds = JSON.parse(await readFile(CREDENTIALS_PATH, 'utf8'));
    const key = creds.installed || creds.web;
    let token = JSON.parse(await readFile(TOKEN_PATH, 'utf8'));
    token = await ensureFreshToken(key, token);
    const oauth = new google.auth.OAuth2(key.client_id, key.client_secret, key.redirect_uris?.[0]);
    oauth.setCredentials(token);
    return oauth;
  }
  if (!existsSync(CREDENTIALS_PATH)) {
    console.error(`\nMissing ${CREDENTIALS_PATH}.\nDownload an OAuth Desktop client from Google Cloud Console and save it there.\nSee README.md.\n`);
    process.exit(1);
  }
  const client = await authenticate({ scopes: SCOPES, keyfilePath: CREDENTIALS_PATH });
  if (client.credentials) {
    await writeFile(TOKEN_PATH, JSON.stringify(client.credentials, null, 2));
    console.log(`Saved token to ${TOKEN_PATH}`);
  }
  return client;
}

// Demote every Markdown heading by one level (# -> ##) so a group's combined
// outline nests under a single H1 group title. Skips fenced code blocks.
function demoteHeadings(md) {
  let inFence = false;
  return md.split('\n').map((line) => {
    if (/^\s*(```|~~~)/.test(line)) { inFence = !inFence; return line; }
    if (inFence) return line;
    const m = line.match(/^(#{1,6})(\s+.*)$/);
    if (!m) return line;
    const hashes = m[1].length < 6 ? m[1] + '#' : m[1];
    return hashes + m[2];
  }).join('\n');
}

async function readSpec(filename) {
  const path = resolve(SPECS_DIR, filename);
  if (!existsSync(path)) { console.warn(`  (missing, skipped): ${filename}`); return null; }
  return readFile(path, 'utf8');
}

// Raw-fetch Drive access token (the googleapis library's gaxios hangs on Drive
// calls under Node 23; plain fetch works, as the token refresh proved).
async function getAccessToken() {
  const creds = JSON.parse(await readFile(CREDENTIALS_PATH, 'utf8'));
  const key = creds.installed || creds.web;
  let token = JSON.parse(await readFile(TOKEN_PATH, 'utf8'));
  token = await ensureFreshToken(key, token);
  if (!token.access_token) throw new Error('no access token (run the auth flow first)');
  return token.access_token;
}

async function createDoc(token, name, markdown, folderId) {
  const boundary = 'ccb' + Math.random().toString(16).slice(2);
  const meta = { name, mimeType: 'application/vnd.google-apps.document', ...(folderId ? { parents: [folderId] } : {}) };
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n` +
    `--${boundary}\r\nContent-Type: text/markdown\r\n\r\n${markdown}\r\n` +
    `--${boundary}--`;
  const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
    body,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`create failed: ${data.error?.message || res.status}`);
  console.log(`  ✓ ${name}  ->  ${data.webViewLink}`);
  return data;
}

// Update an existing doc IN PLACE (same fileId/URL, comments preserved). Replaces
// the content (Drive re-converts the markdown) and refreshes the name.
async function updateDoc(token, id, name, markdown) {
  const boundary = 'ccu' + Math.random().toString(16).slice(2);
  const meta = { name };
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n` +
    `--${boundary}\r\nContent-Type: text/markdown\r\n\r\n${markdown}\r\n` +
    `--${boundary}--`;
  const res = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${id}?uploadType=multipart&fields=id,webViewLink`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
    body,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`update failed: ${data.error?.message || res.status}`);
  console.log(`  ↻ ${name}  ->  ${data.webViewLink}`);
  return data;
}

// Make a doc commentable by anyone with the link (idempotent; ignores "already exists").
async function setCommentable(token, id) {
  try {
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${id}/permissions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'commenter', type: 'anyone' }),
    });
    if (!res.ok && res.status !== 409) {
      const d = await res.json().catch(() => ({}));
      console.warn(`    (comment-share warn: ${d.error?.message || res.status})`);
    }
  } catch (e) {
    console.warn(`    (comment-share warn: ${e?.message || e})`);
  }
}

// Create a new doc OR update the existing one in place if the ledger has its id.
async function upsertDoc(token, key, name, markdown, folderId, prior) {
  const existing = prior[key]?.id;
  const data = existing
    ? await updateDoc(token, existing, name, markdown)
    : await createDoc(token, name, markdown, folderId);
  await setCommentable(token, data.id);
  return data;
}

async function trash(token, ids) {
  console.log(`Trashing ${ids.length} doc(s) (reversible - Drive Trash):`);
  let ok = 0;
  for (const id of ids) {
    try {
      const res = await fetch(`https://www.googleapis.com/drive/v3/files/${id}?fields=id`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ trashed: true }),
      });
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message || res.status); }
      console.log(`  🗑  ${id}`);
      ok++;
    } catch (e) {
      console.warn(`  !  ${id}: ${e?.message || e}`);
    }
  }
  console.log(`\nDone. ${ok}/${ids.length} moved to Trash.`);
}

async function main() {
  const args = process.argv.slice(2);
  const token = await getAccessToken();

  if (args[0] === 'trash') {
    const ids = args.slice(1).filter(Boolean);
    if (!ids.length) { console.error('Usage: node md-to-gdocs.mjs trash <id> [id ...]'); process.exit(1); }
    return trash(token, ids);
  }

  const folderId = process.env.FOLDER_ID || null;
  const ledger = {};
  // Prior ledger: lets us UPDATE existing docs in place (preserve URL + comments).
  const prior = existsSync(LEDGER_PATH) ? JSON.parse(await readFile(LEDGER_PATH, 'utf8')) : {};

  // --group "<substr>" regenerates only matching group(s) (case-insensitive).
  let groupFilter = null;
  const gi = args.findIndex((a) => a === '--group' || a.startsWith('--group='));
  if (gi !== -1) {
    groupFilter = args[gi].includes('=') ? args[gi].split('=').slice(1).join('=') : args[gi + 1];
  }
  const explicitFiles = args.filter((a) => !a.startsWith('--') && a !== groupFilter);

  // Group mode: docs.config.json present and no explicit filenames passed.
  if (explicitFiles.length === 0 && existsSync(CONFIG_PATH)) {
    const cfg = JSON.parse(await readFile(CONFIG_PATH, 'utf8'));
    let groups = cfg.groups;
    if (groupFilter) {
      const f = groupFilter.toLowerCase();
      groups = groups.filter((g) => g.title.toLowerCase().includes(f));
      if (!groups.length) { console.error(`No group title matches "${groupFilter}".`); process.exit(1); }
    }
    console.log(`Creating ${groups.length} consolidated doc(s)${folderId ? ` in folder ${folderId}` : ''}:`);
    for (const g of groups) {
      const parts = [];
      for (const f of g.files) {
        const md = await readSpec(f);
        if (md != null) parts.push(demoteHeadings(md.trim()));
      }
      const combined = `# ${g.title}\n\n` + parts.join('\n\n---\n\n') + '\n';
      const data = await upsertDoc(token, g.title, g.title, combined, folderId, prior);
      ledger[g.title] = data;
    }
  } else {
    // Per-file mode.
    const files = explicitFiles.length ? explicitFiles : DEFAULT_FILES;
    console.log(`Creating ${files.length} doc(s) (one per file)${folderId ? ` in folder ${folderId}` : ''}:`);
    for (const f of files) {
      const md = await readSpec(f);
      if (md == null) continue;
      const data = await upsertDoc(token, f, basename(f, '.md'), md, folderId, prior);
      ledger[f] = data;
    }
  }

  // Merge into the existing ledger (keeps ids for docs not touched this run).
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, ...ledger }, null, 2));
  console.log(`\nDone. ${Object.keys(ledger).length} Google Doc(s) created. Ledger: ${LEDGER_PATH}`);
}

main().catch((err) => {
  console.error(err?.errors || err?.message || err);
  process.exit(1);
});
