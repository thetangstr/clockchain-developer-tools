#!/usr/bin/env node
// gen-slides.mjs
// Build the "Clockchain MCP - Roadmap (v1 to v3)" deck as NATIVE Google Slides —
// real, editable text boxes + shapes (badges, status pills), NOT images.
// Overview + v1 + v2 + v3, styled to match the v1→v3 milestones look.
//
//   node gen-slides.mjs            # create or update-in-place the deck
//   node gen-slides.mjs trash ID   # move a deck to Trash (reversible)
//
// AUTH: same OAuth Desktop client + token as md-to-gdocs.mjs (scope drive.file).

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CREDENTIALS_PATH = join(__dirname, 'credentials.json');
const TOKEN_PATH = join(__dirname, 'token.json');
const LEDGER_PATH = join(__dirname, 'slides-created.json');
const DECK_TITLE = 'Clockchain MCP - Roadmap (v1 to v3)';

/* ---------- color + geometry helpers ---------- */
const C = {
  ink: '#1f2328', mut: '#5f6368', faint: '#80868b', white: '#ffffff',
  indigo: '#3f51b5', violet: '#7c3aed', slate: '#334155',
  green: '#15803d', amber: '#b45309', gray: '#5f6368',
  tShip: '#e9f6ee', tActive: '#fbf3e6', tPlan: '#eef0f2', hair: '#e7e7ee',
};
function rgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return { red: ((n >> 16) & 255) / 255, green: ((n >> 8) & 255) / 255, blue: (n & 255) / 255 };
}
const E = (pt) => Math.round(pt * 12700); // points -> EMU
const PAGE_W = 720, PAGE_H = 405; // pt (10 x 5.625in, 16:9)

/* ---------- request builders (push onto reqs, return objectId) ---------- */
let _n = 0;
const oid = (p) => `${p}${String(_n++).padStart(4, '0')}`; // >= 5 chars (Slides requirement)

function elProps(slideId, x, y, w, h) {
  return {
    pageObjectId: slideId,
    size: { width: { magnitude: E(w), unit: 'EMU' }, height: { magnitude: E(h), unit: 'EMU' } },
    transform: { scaleX: 1, scaleY: 1, translateX: E(x), translateY: E(y), unit: 'EMU' },
  };
}

// text box (transparent), single style for the whole box.
function textBox(reqs, slideId, x, y, w, h, text, opts = {}) {
  const id = oid('tx');
  reqs.push({ createShape: { objectId: id, shapeType: 'TEXT_BOX', elementProperties: elProps(slideId, x, y, w, h) } });
  if (text) reqs.push({ insertText: { objectId: id, text } });
  const style = { fontFamily: opts.font || 'Arial' };
  let fields = 'fontFamily';
  if (opts.size) { style.fontSize = { magnitude: opts.size, unit: 'PT' }; fields += ',fontSize'; }
  if (opts.bold) { style.bold = true; fields += ',bold'; }
  if (opts.color) { style.foregroundColor = { opaqueColor: { rgbColor: rgb(opts.color) } }; fields += ',foregroundColor'; }
  if (text) reqs.push({ updateTextStyle: { objectId: id, textRange: { type: 'ALL' }, style, fields } });
  if (text && opts.align) reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: { alignment: opts.align }, fields: 'alignment' } });
  if (text && opts.bullets) reqs.push({ createParagraphBullets: { objectId: id, textRange: { type: 'ALL' }, bulletPreset: 'BULLET_DISC_CIRCLE_SQUARE' } });
  if (text && opts.lineSpacing) reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: { lineSpacing: opts.lineSpacing }, fields: 'lineSpacing' } });
  return id;
}

// filled rounded shape with centered text (badge / pill).
function pill(reqs, slideId, x, y, w, h, text, fill, textColor, size, shape = 'ROUND_RECTANGLE') {
  const id = oid('sh');
  reqs.push({ createShape: { objectId: id, shapeType: shape, elementProperties: elProps(slideId, x, y, w, h) } });
  reqs.push({ updateShapeProperties: { objectId: id, fields: 'shapeBackgroundFill.solidFill.color,outline.propertyState,contentAlignment', shapeProperties: { shapeBackgroundFill: { solidFill: { color: { rgbColor: rgb(fill) } } }, outline: { propertyState: 'NOT_RENDERED' }, contentAlignment: 'MIDDLE' } } });
  reqs.push({ insertText: { objectId: id, text } });
  reqs.push({ updateTextStyle: { objectId: id, textRange: { type: 'ALL' }, style: { bold: true, fontFamily: 'Arial', fontSize: { magnitude: size, unit: 'PT' }, foregroundColor: { opaqueColor: { rgbColor: rgb(textColor) } } }, fields: 'bold,fontFamily,fontSize,foregroundColor' } });
  reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: { alignment: 'CENTER' }, fields: 'alignment' } });
  return id;
}

function bar(reqs, slideId, x, y, w, h, fill) {
  const id = oid('bar');
  reqs.push({ createShape: { objectId: id, shapeType: 'RECTANGLE', elementProperties: elProps(slideId, x, y, w, h) } });
  reqs.push({ updateShapeProperties: { objectId: id, fields: 'shapeBackgroundFill.solidFill.color,outline.propertyState', shapeProperties: { shapeBackgroundFill: { solidFill: { color: { rgbColor: rgb(fill) } } }, outline: { propertyState: 'NOT_RENDERED' } } } });
  return id;
}

/* ---------- content ---------- */
const RELEASES = [
  {
    code: 'v1', color: C.indigo, name: 'Core MCP — live on testnet',
    status: '✓ SHIPPED', statusColor: C.green, statusTint: C.tShip,
    goal: "The MCP server that turns Clockchain's existing network APIs into tools any AI agent can call — proven end-to-end on the testnet, with a chatbot playground that walks a business user through every use case. Built and owned by Yang.",
    whatLabel: 'CAPABILITIES',
    what: ['Verifiable time (the consensus clock)', 'Document timestamping — TSA / proof of existence', 'Agent attested receipt — who / what / when, tamper-evident', 'Independent verify + tamper detection', 'Agent identity — read (ERC-8004)'],
    depsLabel: 'DEPENDS ON',
    deps: ['Build owner — Yang (~95% of the build)', 'Testnet APIs + creds — in hand', 'MCP SDK pinned (stdio + HTTP)'],
    done: 'DONE WHEN — every capability validated on the testnet via the playground.',
  },
  {
    code: 'v2', color: C.violet, name: 'Hosted + access-controlled',
    status: '● IN PROGRESS', statusColor: C.amber, statusTint: C.tActive,
    goal: "Make v1 usable by people who shouldn't have to install anything — an access-controlled playground for leadership + design partners, and an outside agent host calling the same hosted server. The only thing gating this is a domain we control.",
    whatLabel: 'WHAT SHIPS',
    what: ['Cloudflare Access playground — zero-install, no VPN', 'Free for up to 50 users', 'Ken & Tetsuji try every capability from a link', 'Outside agent host (e.g. AgentDash) calls the same MCP'],
    depsLabel: 'DEPENDS ON',
    deps: ['v1 shipped', 'Domain we control (clockchain.network) — the only blocker, ~2 days', 'Cloudflare account (free tier)'],
    done: 'DONE WHEN — Ken & Tetsuji open the gated link; every v1 capability, zero install.',
  },
  {
    code: 'v3', color: C.slate, name: 'Production-grade',
    status: 'PLANNED', statusColor: C.gray, statusTint: C.tPlan,
    goal: 'From a testnet demo to something a company can depend on — managed cloud hosting, the non-custodial on-chain write paths, and the multi-validator / mainnet path that backs the strongest court-grade claims. Gated on the network team + the contract API, not on the MCP build.',
    whatLabel: 'WHAT SHIPS',
    what: ['Managed cloud hosting (AWS / GCP) + secrets', 'Agent-identity write — non-custodial propose-then-approve', 'Smart-contract triggers', 'Multi-validator / mainnet path', 'Developer package — one-command install'],
    depsLabel: 'GATED ON',
    deps: ['Network-team sign-off (infra exposure)', 'Production identity registry confirmed', 'Backend /schedule (contract API)', 'Signer + gas for writes'],
    done: 'DONE WHEN — runs as a production service; court-grade claims hold on mainnet.',
  },
];

function overviewRequests(slideId) {
  const reqs = [];
  bar(reqs, slideId, 0, 0, PAGE_W, 8, C.indigo);
  textBox(reqs, slideId, 40, 34, 640, 46, 'Clockchain MCP — Roadmap', { size: 30, bold: true, color: C.ink });
  textBox(reqs, slideId, 40, 90, 640, 30, 'v1 → v3  ·  build led by Yang (~95% of it)  ·  testnet today', { size: 13, color: C.mut });
  const cols = [
    { r: RELEASES[0], one: 'Core MCP live on testnet — time, TSA, attested receipt, verify/tamper, identity read.' },
    { r: RELEASES[1], one: 'Hosted, access-controlled playground for leadership + agents. Gated on domain access.' },
    { r: RELEASES[2], one: 'Managed cloud, non-custodial writes, mainnet path. Gated on network team + contract API.' },
  ];
  const x0 = 40, cw = 200, gap = 20;
  cols.forEach((c, i) => {
    const x = x0 + i * (cw + gap);
    bar(reqs, slideId, x, 160, cw, 5, c.r.color);
    textBox(reqs, slideId, x, 174, 80, 30, c.r.code, { size: 22, bold: true, color: c.r.color });
    pill(reqs, slideId, x + 70, 178, 124, 22, c.r.status, c.r.statusTint, c.r.statusColor, 9);
    textBox(reqs, slideId, x, 214, cw, 150, c.one, { size: 11.5, color: C.ink, lineSpacing: 115 });
  });
  textBox(reqs, slideId, 40, 372, 640, 22, 'Everything runs on the testnet (single validator) until v3. Dates for v2/v3 are estimates, not commitments.', { size: 9, color: C.amber });
  return reqs;
}

function releaseRequests(slideId, r) {
  const reqs = [];
  bar(reqs, slideId, 0, 0, PAGE_W, 8, r.color);
  pill(reqs, slideId, 40, 26, 46, 46, r.code, r.color, C.white, 22);
  textBox(reqs, slideId, 98, 30, 450, 32, r.name, { size: 22, bold: true, color: C.ink });
  pill(reqs, slideId, 566, 34, 118, 24, r.status, r.statusTint, r.statusColor, 10);
  textBox(reqs, slideId, 40, 82, 644, 60, r.goal, { size: 11.5, color: C.mut, lineSpacing: 115 });
  // left column — what's in it
  textBox(reqs, slideId, 40, 150, 320, 16, r.whatLabel, { size: 9, bold: true, color: C.faint });
  textBox(reqs, slideId, 40, 170, 320, 190, r.what.join('\n'), { size: 11, color: C.ink, bullets: true, lineSpacing: 115 });
  // right column — dependencies
  textBox(reqs, slideId, 380, 150, 304, 16, r.depsLabel, { size: 9, bold: true, color: C.faint });
  textBox(reqs, slideId, 380, 170, 304, 160, r.deps.join('\n'), { size: 11, color: C.mut, bullets: true, lineSpacing: 115 });
  // done-when strip
  bar(reqs, slideId, 40, 360, 644, 0.8, C.hair);
  textBox(reqs, slideId, 40, 368, 644, 28, r.done, { size: 10.5, bold: true, color: r.statusColor });
  return reqs;
}

/* ---------- auth + api ---------- */
async function ensureFreshToken(key, token) {
  const skewMs = 120_000;
  if ((token.access_token && token.expiry_date && token.expiry_date - skewMs > Date.now()) || !token.refresh_token) return token;
  const body = new URLSearchParams({ client_id: key.client_id, client_secret: key.client_secret, refresh_token: token.refresh_token, grant_type: 'refresh_token' });
  const res = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
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
  const res = await fetch(url, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}: ${JSON.stringify(data).slice(0, 400)}`);
  return data;
}
async function setCommentable(token, id) {
  try { await api(token, `https://www.googleapis.com/drive/v3/files/${id}/permissions?fields=id`, 'POST', { role: 'commenter', type: 'anyone' }); }
  catch (e) { if (!String(e).includes('409')) console.warn(`  (permission warn): ${String(e).slice(0, 120)}`); }
}

async function upsertDeck(token, prior) {
  let pres;
  if (prior?.id) { pres = await api(token, `https://slides.googleapis.com/v1/presentations/${prior.id}`); console.log(`  updating in place: ${pres.presentationId}`); }
  else { pres = await api(token, 'https://slides.googleapis.com/v1/presentations', 'POST', { title: DECK_TITLE }); console.log(`  created: ${pres.presentationId}`); }
  const presentationId = pres.presentationId;
  const oldSlideIds = (pres.slides || []).map((s) => s.objectId);

  const slideIds = ['sldOverview', 'sldRelV1', 'sldRelV2', 'sldRelV3'];
  const reqs = [];
  slideIds.forEach((sid) => reqs.push({ createSlide: { objectId: sid, slideLayoutReference: { predefinedLayout: 'BLANK' } } }));
  reqs.push(...overviewRequests('sldOverview'));
  RELEASES.forEach((r, i) => reqs.push(...releaseRequests(slideIds[i + 1], r)));
  oldSlideIds.forEach((objectId) => reqs.push({ deleteObject: { objectId } }));

  await api(token, `https://slides.googleapis.com/v1/presentations/${presentationId}:batchUpdate`, 'POST', { requests: reqs });
  await setCommentable(token, presentationId);
  return { id: presentationId, url: `https://docs.google.com/presentation/d/${presentationId}/edit` };
}

async function trash(token, ids) {
  for (const id of ids) { await api(token, `https://www.googleapis.com/drive/v3/files/${id}?fields=id`, 'PATCH', { trashed: true }); console.log(`  trashed ${id}`); }
}

async function main() {
  const args = process.argv.slice(2);
  const token = await getAccessToken();
  if (args[0] === 'trash') return trash(token, args.slice(1));
  const prior = existsSync(LEDGER_PATH) ? JSON.parse(await readFile(LEDGER_PATH, 'utf8')) : {};
  console.log(`Building native deck "${DECK_TITLE}" (4 slides):`);
  const data = await upsertDeck(token, prior[DECK_TITLE]);
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, [DECK_TITLE]: data }, null, 2));
  console.log(`\nDone.\n  ${DECK_TITLE}\n  -> ${data.url}\nLedger: ${LEDGER_PATH}`);
}
main().catch((e) => { console.error('\nFAILED:', e.message || e); process.exit(1); });
