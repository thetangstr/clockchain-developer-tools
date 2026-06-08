#!/usr/bin/env node
// gen-slides.mjs
// "Clockchain MCP - Roadmap (v1 to v3)" — 4 elegant, NATIVE Google Slides
// (real editable text boxes + shapes, not images):
//   1. Status & roadmap (v1/v2/v3 overview)
//   2. What's in v1 — in scope / out of scope
//   3. Testnet now, mainnet later
//   4. Open questions & dependencies
//
//   node gen-slides.mjs            # create or update-in-place
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
const FONT = 'Inter';

/* ---------- palette ---------- */
const C = {
  ink: '#14171f', mut: '#586173', faint: '#9aa1ad', line: '#e6e8ec', white: '#ffffff',
  v1: '#4f46e5', v2: '#7c3aed', v3: '#0f766e',
  green: '#15803d', gray: '#64748b', amber: '#b45309',
  tGreen: '#eaf5ee', tGray: '#eef1f5', tV1: '#ecebfb', tV2: '#f2ecfd', tV3: '#e6f2f0', tAmber: '#fbf2e6',
};
const rgb = (hex) => { const n = parseInt(hex.slice(1), 16); return { red: ((n >> 16) & 255) / 255, green: ((n >> 8) & 255) / 255, blue: (n & 255) / 255 }; };
const E = (pt) => Math.round(pt * 12700);
const PAGE_W = 720, PAGE_H = 405;
const MX = 46, CW = PAGE_W - MX * 2; // margins + content width

/* ---------- request builders ---------- */
let _n = 0;
const oid = (p) => `${p}${String(_n++).padStart(4, '0')}`;
const elProps = (sid, x, y, w, h) => ({
  pageObjectId: sid,
  size: { width: { magnitude: E(w), unit: 'EMU' }, height: { magnitude: E(h), unit: 'EMU' } },
  transform: { scaleX: 1, scaleY: 1, translateX: E(x), translateY: E(y), unit: 'EMU' },
});

function text(reqs, sid, x, y, w, h, str, o = {}) {
  const id = oid('tx');
  reqs.push({ createShape: { objectId: id, shapeType: 'TEXT_BOX', elementProperties: elProps(sid, x, y, w, h) } });
  if (!str) return id;
  reqs.push({ insertText: { objectId: id, text: str } });
  const style = { fontFamily: FONT }; let f = 'fontFamily';
  if (o.size) { style.fontSize = { magnitude: o.size, unit: 'PT' }; f += ',fontSize'; }
  if (o.bold) { style.bold = true; f += ',bold'; }
  if (o.color) { style.foregroundColor = { opaqueColor: { rgbColor: rgb(o.color) } }; f += ',foregroundColor'; }
  reqs.push({ updateTextStyle: { objectId: id, textRange: { type: 'ALL' }, style, fields: f } });
  const ps = {}; let pf = '';
  if (o.align) { ps.alignment = o.align; pf += (pf ? ',' : '') + 'alignment'; }
  if (o.line) { ps.lineSpacing = o.line; pf += (pf ? ',' : '') + 'lineSpacing'; }
  if (o.space) { ps.spaceBelow = { magnitude: o.space, unit: 'PT' }; pf += (pf ? ',' : '') + 'spaceBelow'; }
  if (pf) reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: ps, fields: pf } });
  if (o.bullets) reqs.push({ createParagraphBullets: { objectId: id, textRange: { type: 'ALL' }, bulletPreset: o.bullets } });
  return id;
}
const eyebrow = (reqs, sid, x, y, str, color) => text(reqs, sid, x, y, CW, 14, str.toUpperCase(), { size: 9.5, bold: true, color });
const heading = (reqs, sid, x, y, str) => text(reqs, sid, x, y, CW, 40, str, { size: 27, bold: true, color: C.ink });

function rule(reqs, sid, x, y, w, color = C.line, h = 1) {
  const id = oid('ln');
  reqs.push({ createShape: { objectId: id, shapeType: 'RECTANGLE', elementProperties: elProps(sid, x, y, w, h) } });
  reqs.push({ updateShapeProperties: { objectId: id, fields: 'shapeBackgroundFill.solidFill.color,outline.propertyState', shapeProperties: { shapeBackgroundFill: { solidFill: { color: { rgbColor: rgb(color) } } }, outline: { propertyState: 'NOT_RENDERED' } } } });
  return id;
}
function chip(reqs, sid, x, y, w, h, str, fill, textColor, size = 9) {
  const id = oid('ch');
  reqs.push({ createShape: { objectId: id, shapeType: 'ROUND_RECTANGLE', elementProperties: elProps(sid, x, y, w, h) } });
  reqs.push({ updateShapeProperties: { objectId: id, fields: 'shapeBackgroundFill.solidFill.color,outline.propertyState,contentAlignment', shapeProperties: { shapeBackgroundFill: { solidFill: { color: { rgbColor: rgb(fill) } } }, outline: { propertyState: 'NOT_RENDERED' }, contentAlignment: 'MIDDLE' } } });
  reqs.push({ insertText: { objectId: id, text: str } });
  reqs.push({ updateTextStyle: { objectId: id, textRange: { type: 'ALL' }, style: { bold: true, fontFamily: FONT, fontSize: { magnitude: size, unit: 'PT' }, foregroundColor: { opaqueColor: { rgbColor: rgb(textColor) } } }, fields: 'bold,fontFamily,fontSize,foregroundColor' } });
  reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: { alignment: 'CENTER' }, fields: 'alignment' } });
  return id;
}
const header = (reqs, sid) => rule(reqs, sid, 0, 0, PAGE_W, C.v1, 5); // thin top accent (color, height)

/* ---------- slides ---------- */
function slideOverview(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, 'Clockchain MCP', C.v1);
  heading(reqs, sid, MX, 56, 'Status & roadmap');
  text(reqs, sid, MX, 100, CW, 40,
    "An MCP server that turns Clockchain's network APIs into tools any AI agent can call. v1 is live this week on the testnet — demo-ready today. v2 and v3 are in design.",
    { size: 12, color: C.mut, line: 120 });
  rule(reqs, sid, MX, 150, CW);

  const rows = [
    { code: 'v1', color: C.v1, tint: C.tV1, timing: 'THIS WEEK', one: 'In progress, ready for testing. Core MCP live on the testnet — quick demo today (detail next slide).', stat: 'READY FOR TESTING', statColor: C.green, statTint: C.tGreen },
    { code: 'v2', color: C.v2, tint: C.tV2, timing: 'NEXT WEEK', one: 'Connect to AgentDash for an agent-orchestration test — the same MCP, driven by a real agent host.', stat: 'IN DESIGN', statColor: C.gray, statTint: C.tGray },
    { code: 'v3', color: C.v3, tint: C.tV3, timing: 'LATER', one: 'Tested and hosted on AWS or GCP — production-grade and managed.', stat: 'IN DESIGN', statColor: C.gray, statTint: C.tGray },
  ];
  let y = 168;
  for (const r of rows) {
    rule(reqs, sid, MX, y + 4, 3, r.color, 52); // color tick
    text(reqs, sid, MX + 14, y, 56, 36, r.code, { size: 22, bold: true, color: r.color });
    chip(reqs, sid, MX + 72, y + 6, 92, 20, r.timing, r.tint, r.color, 8.5);
    text(reqs, sid, MX + 178, y + 2, 296, 52, r.one, { size: 11, color: C.ink, line: 115 });
    chip(reqs, sid, PAGE_W - MX - 138, y + 6, 138, 22, r.stat, r.statTint, r.statColor, 9);
    y += 64;
  }
  text(reqs, sid, MX, 372, CW, 20, 'Everything runs on the testnet (single validator). v2 and v3 are in design — not started.', { size: 9, color: C.amber });
}

function twoColumn(reqs, sid, eb, ebColor, title, sub, left, right) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, eb, ebColor);
  heading(reqs, sid, MX, 56, title);
  if (sub) text(reqs, sid, MX, 100, CW, 24, sub, { size: 12, color: C.mut, line: 120 });
  rule(reqs, sid, MX, sub ? 138 : 116, CW);
  const colY = sub ? 156 : 134;
  const colW = (CW - 36) / 2, lx = MX, rx = MX + colW + 36;
  rule(reqs, sid, MX + colW + 18, colY, 1, C.line, PAGE_H - colY - 36); // vertical divider
  // left
  chip(reqs, sid, lx, colY, left.chipW, 22, left.label, left.tint, left.color, 9);
  text(reqs, sid, lx, colY + 34, colW, 200, left.items.join('\n'), { size: 11.5, color: C.ink, line: 130, space: 5, bullets: 'BULLET_DISC_CIRCLE_SQUARE' });
  // right
  chip(reqs, sid, rx, colY, right.chipW, 22, right.label, right.tint, right.color, 9);
  text(reqs, sid, rx, colY + 34, colW, 200, right.items.join('\n'), { size: 11.5, color: right.muted ? C.mut : C.ink, line: 130, space: 5, bullets: 'BULLET_DISC_CIRCLE_SQUARE' });
}

function slideScope(reqs, sid) {
  twoColumn(reqs, sid, 'v1 · this week', C.v1, "What's in v1", 'Ready for testing now — a quick demo is available today.',
    { label: 'IN SCOPE', tint: C.tGreen, color: C.green, chipW: 96, items: [
      'Verifiable time — the consensus clock',
      'Document timestamping — TSA / proof of existence',
      'Agent attested receipt — who / what / when, tamper-evident',
      'Independent verify + tamper detection',
      'Agent identity — read (ERC-8004)',
      'Chatbot playground that walks a user through each',
    ] },
    { label: 'OUT OF SCOPE', tint: C.tGray, color: C.gray, chipW: 116, muted: true, items: [
      'Agent identity — write (validation attestation)',
      'Smart-contract triggers',
      'AgentDash / agent-orchestration integration → v2',
      'Hosting / production on AWS or GCP → v3',
      'Multi-validator / mainnet-grade proofs → later',
    ] });
}

function slideNetwork(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, 'v1 · network', C.v1);
  heading(reqs, sid, MX, 56, 'Testnet now, mainnet later');
  text(reqs, sid, MX, 100, CW, 24, 'Timestamps and proofs are real on both. Mainnet adds permanence and the strongest claims.', { size: 12, color: C.mut, line: 120 });
  // table
  const x0 = MX, c1 = 150, c2 = 240, c3 = CW - c1 - c2;
  const colX = [x0, x0 + c1, x0 + c1 + c2], colW = [c1, c2, c3];
  let y = 150;
  // header row
  chip(reqs, sid, colX[1], y, 150, 22, 'TESTNET — NOW', C.tGreen, C.green, 9);
  chip(reqs, sid, colX[2], y, 158, 22, 'MAINNET — LATER', C.tV2, C.v2, 9);
  y += 34;
  const rowsData = [
    ['Purpose', 'Demo & validate', 'Production reliance'],
    ['Validators', 'Single validator', 'Multi-validator supermajority'],
    ['Ledger', 'Resettable', 'Permanent'],
    ['Stakes', 'None (signed statement)', 'Real — value at stake'],
    ['Claim', '“Designed for court-grade”', 'Court-grade'],
  ];
  for (const r of rowsData) {
    rule(reqs, sid, x0, y - 6, CW, C.line);
    text(reqs, sid, colX[0], y, colW[0], 26, r[0], { size: 11, bold: true, color: C.mut });
    text(reqs, sid, colX[1], y, colW[1], 26, r[1], { size: 11, color: C.ink });
    text(reqs, sid, colX[2], y, colW[2], 26, r[2], { size: 11, color: C.ink });
    y += 34;
  }
  rule(reqs, sid, x0, y - 6, CW, C.line);
}

function slideOpen(reqs, sid) {
  twoColumn(reqs, sid, 'discussion', C.v1, 'Open questions & dependencies', '',
    { label: 'OPEN QUESTIONS', tint: C.tV1, color: C.v1, chipW: 134, items: [
      'Production identity registry (ERC-8004) — confirm which one?',
      'Hosting target — AWS or GCP?',
      'Smart-contract API (/schedule) — when is it exposed?',
      'Mainnet timeline / TGE?',
    ] },
    { label: 'DEPENDENCIES', tint: C.tAmber, color: C.amber, chipW: 118, items: [
      'AgentDash dev access — for the v2 orchestration test',
      'A domain we control — to host the playground behind access',
      'Network-team sign-off — production hosting (v3)',
      'Contract API + signer / gas — on-chain writes (v3)',
    ] });
}

/* ---------- auth + api ---------- */
async function ensureFreshToken(key, token) {
  const skew = 120_000;
  if ((token.access_token && token.expiry_date && token.expiry_date - skew > Date.now()) || !token.refresh_token) return token;
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
  const old = (pres.slides || []).map((s) => s.objectId);

  const ids = ['sldOverview', 'sldScope', 'sldNetwork', 'sldOpen'];
  const reqs = [];
  // delete old slides FIRST so the deterministic new IDs don't collide with them
  old.forEach((objectId) => reqs.push({ deleteObject: { objectId } }));
  ids.forEach((s) => reqs.push({ createSlide: { objectId: s, slideLayoutReference: { predefinedLayout: 'BLANK' } } }));
  slideOverview(reqs, ids[0]);
  slideScope(reqs, ids[1]);
  slideNetwork(reqs, ids[2]);
  slideOpen(reqs, ids[3]);

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
  console.log(`Building elegant native deck "${DECK_TITLE}" (4 slides):`);
  const data = await upsertDeck(token, prior[DECK_TITLE]);
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, [DECK_TITLE]: data }, null, 2));
  console.log(`\nDone.\n  ${DECK_TITLE}\n  -> ${data.url}\nLedger: ${LEDGER_PATH}`);
}
main().catch((e) => { console.error('\nFAILED:', e.message || e); process.exit(1); });
