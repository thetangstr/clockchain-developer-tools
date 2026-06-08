#!/usr/bin/env node
// gen-slides.mjs
// Build the "Clockchain MCP - Roadmap (v1 to v3)" deck as a native Google Slides
// presentation (commentable, shareable) from pre-rendered slide images.
//
// The slide images in scripts/slides-assets/ are high-res screenshots of the
// v1→v3 MCP milestones HTML (the page.tsx at research commit 0bdf012), so the
// deck looks EXACTLY like that page. To refresh them: render that page locally
// (HTTP Basic auth clockchain/chainclock) and re-capture each section.
//
//   node gen-slides.mjs            # create or update-in-place the deck from slides-assets/*.png
//   node gen-slides.mjs trash ID   # move a deck to Trash (reversible)
//
// AUTH: same OAuth Desktop client + token as md-to-gdocs.mjs (scope drive.file,
// which the Slides API + Drive uploads accept for files this app created).

import { readFile, writeFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CREDENTIALS_PATH = join(__dirname, 'credentials.json');
const TOKEN_PATH = join(__dirname, 'token.json');
const LEDGER_PATH = join(__dirname, 'slides-created.json');
const ASSETS_DIR = join(__dirname, 'slides-assets');

const DECK_TITLE = 'Clockchain MCP - Roadmap (v1 to v3)';

async function ensureFreshToken(key, token) {
  const skewMs = 120_000;
  const valid = token.access_token && token.expiry_date && token.expiry_date - skewMs > Date.now();
  if (valid || !token.refresh_token) return token;
  const body = new URLSearchParams({
    client_id: key.client_id, client_secret: key.client_secret,
    refresh_token: token.refresh_token, grant_type: 'refresh_token',
  });
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
  });
  const data = await res.json();
  if (!data.access_token) throw new Error(`token refresh failed: ${data.error_description || data.error || res.status}`);
  const updated = { ...token, access_token: data.access_token, expiry_date: Date.now() + (data.expires_in ?? 3600) * 1000 };
  await writeFile(TOKEN_PATH, JSON.stringify(updated, null, 2));
  return updated;
}

async function getAccessToken() {
  const creds = JSON.parse(await readFile(CREDENTIALS_PATH, 'utf8'));
  const key = creds.installed || creds.web;
  let token = JSON.parse(await readFile(TOKEN_PATH, 'utf8'));
  token = await ensureFreshToken(key, token);
  if (!token.access_token) throw new Error('no access token (run the auth flow first)');
  return token.access_token;
}

async function api(token, url, method = 'GET', body) {
  const res = await fetch(url, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}: ${JSON.stringify(data).slice(0, 400)}`);
  return data;
}

// PNG dimensions from the IHDR chunk (width/height at bytes 16..24).
function pngSize(buf) {
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}

async function uploadImage(token, name, buf) {
  const boundary = 'cc_img_boundary_8e21';
  const meta = { name, mimeType: 'image/png' };
  const pre = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: image/png\r\n\r\n`;
  const post = `\r\n--${boundary}--`;
  const body = Buffer.concat([Buffer.from(pre), buf, Buffer.from(post)]);
  const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': `multipart/related; boundary=${boundary}` },
    body,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`upload ${name} -> ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
  // make it fetchable by the Slides API (server-side fetch needs public read)
  await api(token, `https://www.googleapis.com/drive/v3/files/${data.id}/permissions?fields=id`, 'POST', { role: 'reader', type: 'anyone' });
  return data.id;
}

async function setCommentable(token, id) {
  try {
    await api(token, `https://www.googleapis.com/drive/v3/files/${id}/permissions?fields=id`, 'POST', { role: 'commenter', type: 'anyone' });
  } catch (e) {
    if (!String(e).includes('409')) console.warn(`  (permission warn): ${String(e).slice(0, 120)}`);
  }
}

// contain image within the page, centered (EMU math).
function containTransform(page, img) {
  const pageW = page.width.magnitude, pageH = page.height.magnitude;
  const ar = img.w / img.h;
  let w = pageW, h = pageW / ar;
  if (h > pageH) { h = pageH; w = pageH * ar; }
  return { w, h, tx: (pageW - w) / 2, ty: (pageH - h) / 2 };
}

async function upsertDeck(token, prior, assets) {
  let pres;
  if (prior?.id) {
    pres = await api(token, `https://slides.googleapis.com/v1/presentations/${prior.id}`);
    console.log(`  updating in place: ${pres.presentationId}`);
  } else {
    pres = await api(token, 'https://slides.googleapis.com/v1/presentations', 'POST', { title: DECK_TITLE });
    console.log(`  created: ${pres.presentationId}`);
  }
  const presentationId = pres.presentationId;
  const page = pres.pageSize; // EMU; can't be changed post-create, so we lay out to it
  const oldSlideIds = (pres.slides || []).map((s) => s.objectId);

  // upload images first
  const uploaded = [];
  for (const a of assets) {
    const buf = await readFile(a.path);
    const id = await uploadImage(token, `${DECK_TITLE} — ${a.name}`, buf);
    uploaded.push({ id, size: pngSize(buf) });
    console.log(`  uploaded ${a.name}`);
  }

  // build new image slides, then delete the old ones (keeps the file URL + comments)
  const requests = [];
  uploaded.forEach((u, i) => {
    const slideId = `img_slide_${i}`;
    const t = containTransform(page, u.size);
    requests.push({ createSlide: { objectId: slideId, slideLayoutReference: { predefinedLayout: 'BLANK' } } });
    requests.push({ createImage: {
      url: `https://drive.google.com/uc?export=view&id=${u.id}`,
      elementProperties: {
        pageObjectId: slideId,
        size: { width: { magnitude: t.w, unit: 'EMU' }, height: { magnitude: t.h, unit: 'EMU' } },
        transform: { scaleX: 1, scaleY: 1, translateX: t.tx, translateY: t.ty, unit: 'EMU' },
      },
    } });
  });
  oldSlideIds.forEach((objectId) => requests.push({ deleteObject: { objectId } }));

  await api(token, `https://slides.googleapis.com/v1/presentations/${presentationId}:batchUpdate`, 'POST', { requests });
  await setCommentable(token, presentationId);
  return { id: presentationId, url: `https://docs.google.com/presentation/d/${presentationId}/edit` };
}

async function trash(token, ids) {
  for (const id of ids) {
    await api(token, `https://www.googleapis.com/drive/v3/files/${id}?fields=id`, 'PATCH', { trashed: true });
    console.log(`  trashed ${id}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const token = await getAccessToken();
  if (args[0] === 'trash') return trash(token, args.slice(1));

  const files = (await readdir(ASSETS_DIR)).filter((f) => f.toLowerCase().endsWith('.png')).sort();
  if (!files.length) throw new Error(`no PNGs in ${ASSETS_DIR}`);
  const assets = files.map((f) => ({ name: f.replace(/\.png$/i, ''), path: join(ASSETS_DIR, f) }));

  const prior = existsSync(LEDGER_PATH) ? JSON.parse(await readFile(LEDGER_PATH, 'utf8')) : {};
  console.log(`Building deck "${DECK_TITLE}" from ${assets.length} image(s):`);
  const data = await upsertDeck(token, prior[DECK_TITLE], assets);
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, [DECK_TITLE]: data }, null, 2));
  console.log(`\nDone.\n  ${DECK_TITLE}\n  -> ${data.url}\nLedger: ${LEDGER_PATH}`);
}

main().catch((e) => { console.error('\nFAILED:', e.message || e); process.exit(1); });
