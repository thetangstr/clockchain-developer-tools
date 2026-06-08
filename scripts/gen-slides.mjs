#!/usr/bin/env node
// gen-slides.mjs
// Build the "Clockchain MCP - Roadmap (v1 -> v3)" deck as a native Google Slides
// presentation (commentable, shareable). The detailed MCP roadmap lives here as
// slides; the website /plan/milestones page stays high-level (per product).
//
//   node gen-slides.mjs            # create or update-in-place the deck
//   node gen-slides.mjs trash ID   # move a deck to Trash (reversible)
//
// AUTH: same OAuth Desktop client + token as md-to-gdocs.mjs (scope drive.file,
// which the Slides API accepts for files this app created). Token auto-refreshed
// via plain fetch (the googleapis gaxios path hangs under Node 23).

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CREDENTIALS_PATH = join(__dirname, 'credentials.json');
const TOKEN_PATH = join(__dirname, 'token.json');
const LEDGER_PATH = join(__dirname, 'slides-created.json');

const DECK_TITLE = 'Clockchain MCP - Roadmap (v1 to v3)';

// The existing MCP milestone page, broken into slides.
const SLIDES = [
  { layout: 'TITLE', title: 'Clockchain MCP - Roadmap',
    subtitle: 'v1 to v3  ·  build led by Yang (~95% of it)  ·  testnet today\nJune 2026' },
  { layout: 'TITLE_AND_BODY', title: 'The three releases at a glance', bullets: [
    'v1 - Core MCP  ·  SHIPPED on testnet',
    'v2 - Hosted + access-controlled  ·  IN PROGRESS (gated on domain access)',
    'v3 - Production-grade  ·  PLANNED (network sign-off + contract API)',
    'One platform, three steps: prove it -> let people use it -> make it production-grade',
  ] },
  { layout: 'TITLE_AND_BODY', title: 'v1 - Core MCP (shipped on testnet)', bullets: [
    'What it is: the MCP server that turns Clockchain\'s existing network APIs into tools any AI agent can call',
    'Capabilities: verifiable time · document timestamping (TSA) · agent attested receipt · independent verify + tamper · agent identity (read)',
    'Proven end-to-end on the testnet, with a chatbot playground that walks a business user through each use case',
    'Dependencies (all in hand): build owned by Yang · testnet APIs + creds · pinned MCP SDK',
    'Done when: every capability validated on the testnet  ✓',
  ] },
  { layout: 'TITLE_AND_BODY', title: 'v2 - Hosted + access-controlled (in progress)', bullets: [
    'Goal: make v1 usable by people who should not have to install anything',
    'Cloudflare Access playground - zero-install, no VPN, free for up to 50 users',
    'Leadership (Ken & Tetsuji) and design partners try every capability from a link',
    'Confirm an outside agent host (e.g. AgentDash) calls the same hosted MCP',
    'The only blocker: a domain we control (clockchain.network) - about 2 days out',
  ] },
  { layout: 'TITLE_AND_BODY', title: 'v3 - Production-grade (planned)', bullets: [
    'Goal: from a testnet demo to something a company can depend on',
    'Managed cloud hosting (AWS or GCP) with auth + secret handling',
    'On-chain writes - agent-identity write + smart-contract triggers - non-custodial propose-then-approve (the server never holds a key)',
    'Multi-validator / mainnet path for the strongest court-grade proofs',
    'Gated on the network team + the contract API - not on the MCP build',
  ] },
  { layout: 'TITLE_AND_BODY', title: 'Scope & honesty', bullets: [
    'In scope today (testnet): time · TSA · attested receipt · verify/tamper · identity read',
    'Not yet: identity write · smart-contract triggers · multi-validator / mainnet · public launch',
    'Everything runs on the testnet (single validator) until v3',
    'The workflow + proofs are real and verifiable; mainnet brings the supermajority + the strongest claims',
  ] },
];

const PLACEHOLDERS = {
  TITLE: { title: 'CENTERED_TITLE', body: 'SUBTITLE' },
  TITLE_AND_BODY: { title: 'TITLE', body: 'BODY' },
};

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

// Build createSlide + insertText + bullets requests for one slide.
function slideRequests(slide, i) {
  const ids = { slide: `slide_${i}`, title: `title_${i}`, body: `body_${i}` };
  const ph = PLACEHOLDERS[slide.layout];
  const reqs = [{
    createSlide: {
      objectId: ids.slide,
      slideLayoutReference: { predefinedLayout: slide.layout },
      placeholderIdMappings: [
        { layoutPlaceholder: { type: ph.title, index: 0 }, objectId: ids.title },
        { layoutPlaceholder: { type: ph.body, index: 0 }, objectId: ids.body },
      ],
    },
  }];
  reqs.push({ insertText: { objectId: ids.title, text: slide.title } });
  const bodyText = slide.bullets ? slide.bullets.join('\n') : (slide.subtitle || '');
  if (bodyText) {
    reqs.push({ insertText: { objectId: ids.body, text: bodyText } });
    if (slide.bullets) {
      reqs.push({ createParagraphBullets: { objectId: ids.body, textRange: { type: 'ALL' }, bulletPreset: 'BULLET_DISC_CIRCLE_SQUARE' } });
    }
  }
  return reqs;
}

async function setCommentable(token, id) {
  try {
    await api(token, `https://www.googleapis.com/drive/v3/files/${id}/permissions?fields=id`, 'POST',
      { role: 'commenter', type: 'anyone' });
  } catch (e) {
    if (!String(e).includes('409')) console.warn(`  (permission warn): ${String(e).slice(0, 120)}`);
  }
}

async function upsertDeck(token, prior) {
  let presentationId, oldSlideIds;
  if (prior?.id) {
    const pres = await api(token, `https://slides.googleapis.com/v1/presentations/${prior.id}`);
    presentationId = pres.presentationId;
    oldSlideIds = (pres.slides || []).map((s) => s.objectId);
    console.log(`  updating in place: ${presentationId}`);
  } else {
    const pres = await api(token, 'https://slides.googleapis.com/v1/presentations', 'POST', { title: DECK_TITLE });
    presentationId = pres.presentationId;
    oldSlideIds = (pres.slides || []).map((s) => s.objectId);
    console.log(`  created: ${presentationId}`);
  }
  // New slides are appended after the old ones; deleting the old ones last leaves
  // only the freshly built deck (preserves the file URL + file-level comments).
  const requests = [
    ...SLIDES.flatMap((s, i) => slideRequests(s, i)),
    ...oldSlideIds.map((objectId) => ({ deleteObject: { objectId } })),
  ];
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

  const prior = existsSync(LEDGER_PATH) ? JSON.parse(await readFile(LEDGER_PATH, 'utf8')) : {};
  console.log(`Building deck "${DECK_TITLE}" (${SLIDES.length} slides):`);
  const data = await upsertDeck(token, prior[DECK_TITLE]);
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, [DECK_TITLE]: data }, null, 2));
  console.log(`\nDone.\n  ${DECK_TITLE}\n  -> ${data.url}\nLedger: ${LEDGER_PATH}`);
}

main().catch((e) => { console.error('\nFAILED:', e.message || e); process.exit(1); });
