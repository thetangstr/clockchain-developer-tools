#!/usr/bin/env node
// gen-slides.mjs
// "Clockchain MCP - Roadmap (v1 to v3)" — 9 elegant, NATIVE Google Slides
// (real editable text boxes + shapes, not images):
//   1. Status & roadmap (v1/v2/v3 overview)
//   2. The five modules (Time/Logging/Scheduler/Audit/Identity — design + status)
//   3. Two lanes, one launch (Lane A features / Lane B hosting+CI-CD, phased)
//   4. Our first customer (discovery thesis)
//   5. The AI Act CISO (who-buys customer journey)
//   6. Three ways in (how real users reach the MCP)
//   7. What's in v1 — in scope / out of scope
//   8. Testnet now, mainnet later
//   9. Open questions & dependencies
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
  eyebrow(reqs, sid, MX, 38, 'Executive summary · Clockchain MCP', C.v1);
  heading(reqs, sid, MX, 54, 'Status & roadmap');
  text(reqs, sid, MX, 96, CW, 34,
    "An MCP server that turns Clockchain's network APIs into tools any AI agent can call. v1 is live this week on the testnet — demo-ready today. v2 and v3 are in design.",
    { size: 11.5, color: C.mut, line: 122 });
  rule(reqs, sid, MX, 148, CW);

  const cols = [
    { code: 'v1', color: C.v1, status: 'LIVE · TESTNET', sColor: C.green, sTint: C.tGreen, sW: 106, timing: 'This week', inc: [
      'MCP server — five modules, 25 tools',
      'Playground — redesigned, demo-ready',
      'Cross-party verify (keyless) + valid-at-T identity',
    ] },
    { code: 'v2', color: C.v2, status: 'IN DESIGN', sColor: C.gray, sTint: C.tGray, sW: 78, timing: 'By end of month', inc: [
      'Hosted MCP endpoint + Cloudflare gate',
      'Schedule create (wallet sig) · free / paid tiers',
      'AgentDash agent-orchestration integration',
    ] },
    { code: 'v3', color: C.v3, status: 'IN DESIGN', sColor: C.gray, sTint: C.tGray, sW: 78, timing: 'By end of month', inc: [
      'Cloud launch — AWS & GCP, managed hosting',
      'Mainnet-grade, multi-validator proofs',
      'Identity write + regulator-export presets',
    ] },
  ];
  const gap = 16, cw = (CW - 2 * gap) / 3;
  cols.forEach((c, i) => {
    const x = MX + i * (cw + gap);
    text(reqs, sid, x, 164, 46, 28, c.code, { size: 20, bold: true, color: c.color });
    chip(reqs, sid, x + 44, 168, c.sW, 18, c.status, c.sTint, c.sColor, 8.5);
    text(reqs, sid, x, 194, cw, 14, c.timing, { size: 9.5, color: C.mut });
    text(reqs, sid, x, 214, cw, 12, 'INCLUDES', { size: 8, bold: true, color: C.faint });
    text(reqs, sid, x, 228, cw, 124, c.inc.join('\n'), { size: 9.5, color: C.ink, line: 120, space: 4, bullets: 'BULLET_DISC_CIRCLE_SQUARE' });
  });

  rule(reqs, sid, MX, 360, CW);
  text(reqs, sid, MX, 368, CW, 26, 'Two lanes run in parallel — features (A) + hosting / CI-CD (B), meeting at the hosted endpoint.   Not yet in scope: multi-validator / mainnet, public launch.', { size: 9, color: C.amber, line: 120 });
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
      'Verifiable time + attested receipts, tamper-evident',
      'Audit — trails, Art. 12 / 17a-4 / ISO presets, evidence packs',
      'Identity — mint / revoke / history + valid-at-T',
      'Cross-party verify — keyless, no account needed',
      'Scheduler — types, live cost quotes, listing',
      'Chatbot playground walking a user through all five',
    ] },
    { label: 'OUT OF SCOPE', tint: C.tGray, color: C.gray, chipW: 116, muted: true, items: [
      'Schedule create — needs wallet signature → v2',
      'Identity directory / public resolver → v2',
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

// a column of titled blocks: tag chip + bold title + context line.
// opt: { spacing, titleSize, ctxSize } to tune density.
function column(reqs, sid, x, y0, w, items, opt = {}) {
  const sp = opt.spacing || 52, ts = opt.titleSize || 11.5, cs = opt.ctxSize || 9.5;
  let y = y0;
  for (const it of items) {
    const tColor = it.tColor || (it.tag === 'v2' ? C.v2 : C.v3);
    const tTint = it.tTint || (it.tag === 'v2' ? C.tV2 : C.tV3);
    chip(reqs, sid, x, y, 26, 15, it.tag, tTint, tColor, 8);
    text(reqs, sid, x + 32, y - 2, w - 32, 18, it.title, { size: ts, bold: true, color: C.ink });
    text(reqs, sid, x, y + 15, w, sp - 14, it.ctx, { size: cs, color: C.mut, line: 113 });
    y += sp;
  }
}

// The five lane-A modules — the per-module FEATURE LIST + status, mirroring the
// public /architecture page. Each module shows its three capabilities.
function slideModules(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 34, 'lane A · the MCP feature set', C.v1);
  heading(reqs, sid, MX, 50, 'The five modules');
  text(reqs, sid, MX, 90, CW, 20,
    'One non-custodial MCP server. Three capabilities each — Time, Logging, Scheduler free; Audit + Agent Identity paid.',
    { size: 10.5, color: C.mut, line: 116 });
  rule(reqs, sid, MX, 116, CW);

  const rows = [
    { name: 'Time',      live: 'LIVE',                 amber: false, caps: 'trusted time   ·   verify timestamps   ·   time attestations',          note: 'the clock no single party controls' },
    { name: 'Logging',   live: 'LIVE',                 amber: false, caps: 'write logs   ·   query logs   ·   verify integrity',                    note: 'hash-anchored receipts — your content never leaves you' },
    { name: 'Scheduler', live: 'LIVE · CREATE=PREVIEW', amber: true,  caps: 'cron jobs   ·   schedule future executions   ·   manage recurring tasks', note: 'promised-T vs actual-T; committing needs your wallet signature' },
    { name: 'Audit',     live: 'LIVE',                 amber: false, caps: 'audit trails   ·   compliance reports   ·   evidence packages',         note: 'EU AI Act Art.12 / SEC 17a-4 / ISO 27001 presets (a derivative)' },
    { name: 'Identity',  live: 'LIVE · DIRECTORY=PREVIEW', amber: true, caps: 'registration   ·   verification (valid-at-T)   ·   activity history',  note: 'which agent acted, and whether it was authorized then — not auth' },
  ];
  let y = 128;
  for (const r of rows) {
    text(reqs, sid, MX, y, 110, 16, r.name, { size: 12, bold: true, color: C.ink });
    chip(reqs, sid, MX + 92, y + 1, r.amber ? 150 : 46, 15, r.live, r.amber ? C.tAmber : C.tGreen, r.amber ? C.amber : C.green, 7.5);
    text(reqs, sid, MX, y + 17, CW, 14, r.caps, { size: 10.5, bold: true, color: C.v1, line: 115 });
    text(reqs, sid, MX, y + 30, CW, 12, r.note, { size: 8.5, color: C.mut });
    y += 53;
    if (r !== rows[rows.length - 1]) rule(reqs, sid, MX, y - 7, CW);
  }
}

function slideOpen(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 36, 'discussion · before we launch to real users', C.v1);
  heading(reqs, sid, MX, 52, 'Open questions & dependencies');
  rule(reqs, sid, MX, 96, CW);

  const colW = 300, lx = MX, rx = MX + 328;
  rule(reqs, sid, MX + 312, 110, 1, C.line, PAGE_H - 110 - 22);
  // column headers
  chip(reqs, sid, lx, 110, 116, 17, 'OPEN QUESTIONS', C.tV1, C.v1, 8);
  text(reqs, sid, lx + 124, 112, 180, 14, 'business scenarios to resolve', { size: 8.5, color: C.faint });
  chip(reqs, sid, rx, 110, 100, 17, 'DEPENDENCIES', C.tAmber, C.amber, 8);
  text(reqs, sid, rx + 108, 112, 180, 14, 'what we need from others', { size: 8.5, color: C.faint });

  const QT = C.v1, QTint = C.tV1;
  column(reqs, sid, lx, 140, colW, [
    { tag: '1', tColor: QT, tTint: QTint, title: 'Onboarding & access', ctx: 'A design partner wants their team on the playground next week. How do users get a key and connect their agent — self-serve, or do we provision and gate each one? Who is allowed in?' },
    { tag: '2', tColor: QT, tTint: QTint, title: 'Data & confidentiality', ctx: "A bank's security team asks what we can see. Can we guarantee only the hash is anchored — never their underlying data — and prove it? The first question every regulated buyer asks." },
    { tag: '3', tColor: QT, tTint: QTint, title: 'Reliability & what we promise', ctx: 'A customer wants to rely on receipts in a live workflow. What uptime / support do we commit, and what is the fallback if our node or the network is unreachable?' },
  ], { spacing: 80, titleSize: 11, ctxSize: 9 });

  column(reqs, sid, rx, 140, colW, [
    { tag: 'v2', title: 'AgentDash dev access', ctx: 'A real agent host that can call our MCP for the orchestration test.' },
    { tag: 'v2', title: 'DNS on clockchain.network', ctx: 'Domain is at GoDaddy — set up mcp.clockchain.network with Ken to host the endpoint behind Cloudflare.' },
    { tag: 'v2', title: 'Schedule signature spec', ctx: 'One sentence from backend: what message does the wallet sign for /api/contract/schedule — and is it enforced on testnet?' },
    { tag: 'v2', title: 'Public resolver — identity directory', ctx: 'Unscoped DID lookup + search, so agents can discover identities they were never handed.' },
    { tag: 'v3', title: 'Cloud accounts + network sign-off', ctx: 'AWS & GCP access/billing; production hosting + exposure model.' },
  ], { spacing: 46, titleSize: 10.5, ctxSize: 8.5 });
}

// Slide 2 — business-facing customer journey (the EU AI Act CISO).
function slideJourney(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, 'customer journey · who buys this', C.v1);
  heading(reqs, sid, MX, 56, 'The AI Act CISO');
  text(reqs, sid, MX, 100, CW, 32,
    'A security chief deploying high-risk AI (EU AI Act, applies Aug 2026). Their compliance evidence is self-attested — in an audit, their own logs are not proof.',
    { size: 12, color: C.mut, line: 120 });
  rule(reqs, sid, MX, 150, CW);

  const steps = [
    { n: '1', t: 'Capture the decision', d: 'Every high-risk AI decision — and the human sign-off — is anchored to a ledger no single party controls.' },
    { n: '2', t: 'Timestamp it', d: 'Stamped against a clock the validator network agrees on, not your own server.' },
    { n: '3', t: 'Catch tampering', d: 'Anyone can re-check it later; any edit after the fact fails verification.' },
    { n: '4', t: 'Hand over proof', d: 'A regulator verifies the record without trusting you — evidence, not your word.' },
  ];
  const gap = 14, cw = (CW - 3 * gap) / 4;
  steps.forEach((s, i) => {
    const x = MX + i * (cw + gap);
    chip(reqs, sid, x, 170, 26, 26, s.n, C.tV1, C.v1, 12);
    text(reqs, sid, x, 206, cw, 20, s.t, { size: 12.5, bold: true, color: C.ink });
    text(reqs, sid, x, 228, cw, 96, s.d, { size: 10, color: C.mut, line: 120 });
  });

  rule(reqs, sid, MX, 330, CW, C.tV1, 46);
  text(reqs, sid, MX + 16, 339, CW - 32, 30,
    'Outcome — audit-ready evidence that holds up to a market-surveillance authority, against fines up to €35M / 7% of global turnover.',
    { size: 11.5, bold: true, color: C.ink, line: 118 });
  text(reqs, sid, MX, 384, CW, 14, 'Maps to EU AI Act: Art. 12 logging · Art. 14 human oversight · Annex IV documentation · Art. 74 audit access', { size: 8.5, color: C.faint });
}

// a filled circle with a centered glyph/emoji (simple icon graphic).
function icon(reqs, sid, x, y, d, glyph, fill, color) {
  const id = oid('ic');
  reqs.push({ createShape: { objectId: id, shapeType: 'ELLIPSE', elementProperties: elProps(sid, x, y, d, d) } });
  reqs.push({ updateShapeProperties: { objectId: id, fields: 'shapeBackgroundFill.solidFill.color,outline.propertyState,contentAlignment', shapeProperties: { shapeBackgroundFill: { solidFill: { color: { rgbColor: rgb(fill) } } }, outline: { propertyState: 'NOT_RENDERED' }, contentAlignment: 'MIDDLE' } } });
  reqs.push({ insertText: { objectId: id, text: glyph } });
  reqs.push({ updateTextStyle: { objectId: id, textRange: { type: 'ALL' }, style: { fontSize: { magnitude: 22, unit: 'PT' }, foregroundColor: { opaqueColor: { rgbColor: rgb(color) } } }, fields: 'fontSize,foregroundColor' } });
  reqs.push({ updateParagraphStyle: { objectId: id, textRange: { type: 'ALL' }, style: { alignment: 'CENTER' }, fields: 'alignment' } });
}

// Slide 3 — how real users reach the MCP (three channels).
function slideChannels(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, 'how real users reach the mcp', C.v1);
  heading(reqs, sid, MX, 56, 'Three ways in');
  text(reqs, sid, MX, 100, CW, 22, 'The playground is the human front door; developers and agents connect to the same MCP directly.', { size: 12, color: C.mut, line: 120 });
  rule(reqs, sid, MX, 138, CW);

  const cols = [
    { glyph: '▶', color: C.v1, tint: C.tV1, title: 'Sales & Marketing', sub: 'Try it on our site', body: 'A prospect opens the playground on our marketing page and chats with an AI agent that uses our MCP — seeing our services produce verifiable proof, live and zero-install.' },
    { glyph: '</>', color: C.v3, tint: C.tV3, title: 'Developers', sub: 'API key + open-source client', body: 'Get an API key from our site, clone the MCP client from our GitHub repo, and wire Clockchain’s tools into their own agent in minutes.' },
    { glyph: '◆', color: C.v2, tint: C.tV2, title: 'AI Agents', sub: 'Discover via marketplace', body: 'An agent finds our MCP in a marketplace / registry listing, connects, and acts — with one-time human approval (non-custodial).' },
  ];
  const gap = 16, cw = (CW - 2 * gap) / 3;
  cols.forEach((c, i) => {
    const x = MX + i * (cw + gap);
    icon(reqs, sid, x + (cw - 54) / 2, 162, 54, c.glyph, c.color, C.white);
    text(reqs, sid, x, 228, cw, 18, c.title, { size: 13.5, bold: true, color: c.color, align: 'CENTER' });
    text(reqs, sid, x, 248, cw, 14, c.sub, { size: 9.5, color: C.mut, align: 'CENTER' });
    text(reqs, sid, x, 272, cw, 96, c.body, { size: 9.5, color: C.ink, line: 130, align: 'CENTER' });
  });
}

// Slide 7 — TL;DR from leadership discovery interviews (the first customer).
function cell(reqs, sid, x, y, w, label, labelColor, body) {
  text(reqs, sid, x, y, w, 12, label, { size: 9, bold: true, color: labelColor });
  text(reqs, sid, x, y + 15, w, 100, body, { size: 9.5, color: C.mut, line: 122 });
}
function slideTLDR(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 36, 'discovery · leadership convergence', C.v1);
  heading(reqs, sid, MX, 52, 'Our first customer');
  rule(reqs, sid, MX, 92, CW, C.tV1, 44);
  text(reqs, sid, MX + 16, 99, CW - 32, 32,
    'The compliance officer — CISO / Chief Compliance Officer — at a regulated, EU-exposed enterprise deploying high-risk AI agents (financial-services-leaning), forced by EU AI Act Article 12.',
    { size: 10.5, bold: true, color: C.ink, line: 120 });
  const lx = MX, rx = MX + 328, cw = 300;
  cell(reqs, sid, lx, 150, cw, 'THE PAIN', C.v1,
    "Can't produce regulator-grade, independently-verifiable evidence of what their agents did and when. Their own logs are a claim, not evidence — and across counterparties, no single clock is authoritative.");
  cell(reqs, sid, rx, 150, cw, 'POSITIONING', C.v3,
    'Neutral, independently-verifiable identity + ordering of agent actions — the evidence Article 12 requires that your own logs cannot provide. Lead with neutral ordering + existence, not "prove exactly when".');
  cell(reqs, sid, lx, 258, cw, 'THE HONEST GAP', C.amber,
    'No demand evidence yet — no prospect has asked unprompted. The logic is coherent but untested; treat it as the gating fact. Validate with 5–10 CISO / CCO discovery calls.');
  cell(reqs, sid, rx, 258, cw, 'THE MOVE', C.green,
    'Build the smallest slice — an "Article 12 Evidence Pack": one agent action end-to-end (capture → identity-bind → timestamp → mint → regulator-format export → public verify). Lead every call with the artifact.');
  rule(reqs, sid, MX, 366, CW);
  text(reqs, sid, MX, 374, CW, 24,
    'Open fork: intra-company Article 12 record-keeping vs inter-company multi-party ordering — the first product picks one. Article 12 is the testable, deadline-bound wedge.',
    { size: 8.5, color: C.amber, line: 120 });
}

// a vertical stack of phase blocks for one lane: bold "mark · label" header
// (color-coded by phase) over a bulleted item list. `slot` pt per phase block.
// Items must be short enough to stay on ONE line (~44 chars) so they don't
// wrap into the next block — that was the original overlap bug.
function laneStack(reqs, sid, x, y0, w, phases, slot) {
  let y = y0;
  for (const p of phases) {
    text(reqs, sid, x, y, w, 13, `${p.mark}  ${p.label}`, { size: 9.5, bold: true, color: p.color });
    text(reqs, sid, x, y + 14, w, slot - 16, p.items.join('\n'), { size: 9.5, color: C.ink, line: 116, space: 1, bullets: 'BULLET_DISC_CIRCLE_SQUARE' });
    y += slot;
  }
}

// Two-lane roadmap — Lane A (what users touch & buy) vs Lane B (where it runs),
// each phased ✓ shipped / ▶ next / ◷ later and mapped to v1 / v2 / v3. The amber
// band is the cross-lane gate: cloud agents need Lane B's hosted endpoint.
function slideLanes(reqs, sid) {
  header(reqs, sid);
  eyebrow(reqs, sid, MX, 40, 'roadmap · two lanes to launch', C.v1);
  heading(reqs, sid, MX, 56, 'Two lanes, one launch');
  text(reqs, sid, MX, 96, CW, 26,
    'Lane A is what users touch and buy; Lane B is where it runs. They meet at the hosted endpoint — Lane A can’t reach cloud agents until Lane B ships it.',
    { size: 11, color: C.mut, line: 118 });
  rule(reqs, sid, MX, 142, CW);

  const colW = (CW - 36) / 2, lx = MX, rx = MX + colW + 36, colY = 152;
  rule(reqs, sid, MX + colW + 18, colY, 1, C.line, 196); // vertical divider

  chip(reqs, sid, lx, colY, 224, 19, 'LANE A · WHAT USERS TOUCH & BUY', C.tV1, C.v1, 8.5);
  chip(reqs, sid, rx, colY, 178, 19, 'LANE B · WHERE IT RUNS', C.tV3, C.v3, 8.5);

  const SLOT = 56, py = colY + 28;
  laneStack(reqs, sid, lx, py, colW, [
    { mark: '✓', label: 'SHIPPED · v1', color: C.green, items: [
      'Five modules · receipts · tamper detect',
      'Audit trails · Art. 12 / 17a-4 / ISO packs',
      'Valid-at-T identity · keyless x-party verify',
    ] },
    { mark: '▶', label: 'NEXT · v2', color: C.v2, items: [
      'Schedule create — wallet signature',
      'Identity directory (public resolver)',
      'Free / paid tiers · AgentDash',
    ] },
    { mark: '◷', label: 'LATER · v3', color: C.v3, items: [
      'ERC-8004 identity write (on-chain)',
      'Cron-logger accountability layer',
      'Mainnet-grade, multi-validator proofs',
    ] },
  ], SLOT);

  laneStack(reqs, sid, rx, py, colW, [
    { mark: '✓', label: 'SHIPPED · v1', color: C.green, items: [
      'CI gate — typecheck + build on PRs',
      'Auto release-notes · Vercel deploy',
      'Two-repo sync (playground ↔ core)',
    ] },
    { mark: '▶', label: 'NEXT · v2', color: C.v2, items: [
      'Hosted endpoint — mcp.clockchain.network',
      'DNS at GoDaddy → set up with Ken',
      'Cloudflare gate · tokens / OAuth',
    ] },
    { mark: '◷', label: 'LATER · v3', color: C.v3, items: [
      'AWS / GCP production hosting',
      'Observability + idempotency',
      'Mainnet infra · multi-validator',
    ] },
  ], SLOT);

  rule(reqs, sid, MX, 354, CW, C.tAmber, 44);
  text(reqs, sid, MX + 16, 360, CW - 32, 32,
    'Cross-lane gate — Cowork / claude.ai / Desktop connect from Anthropic’s cloud, so they need Lane B’s hosted HTTPS endpoint. Today only Claude Code (local stdio) connects; mcp.clockchain.network unblocks Lane A’s biggest reach.',
    { size: 9, bold: true, color: C.ink, line: 116 });
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

  // Order: exec overview → the five modules (architecture) → the two-lane roadmap
  // (centerpiece) → the business case (first customer, who-buys journey, three
  // ways in) → v1 scope → network → open Qs.
  const ids = ['sldOverview', 'sldModules', 'sldLanes', 'sldCustomer', 'sldJourney', 'sldChannels', 'sldScope', 'sldNetwork', 'sldOpen'];
  const reqs = [];
  // delete old slides FIRST so the deterministic new IDs don't collide with them
  old.forEach((objectId) => reqs.push({ deleteObject: { objectId } }));
  ids.forEach((s) => reqs.push({ createSlide: { objectId: s, slideLayoutReference: { predefinedLayout: 'BLANK' } } }));
  slideOverview(reqs, ids[0]);
  slideModules(reqs, ids[1]);
  slideLanes(reqs, ids[2]);
  slideTLDR(reqs, ids[3]);
  slideJourney(reqs, ids[4]);
  slideChannels(reqs, ids[5]);
  slideScope(reqs, ids[6]);
  slideNetwork(reqs, ids[7]);
  slideOpen(reqs, ids[8]);

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
  console.log(`Building elegant native deck "${DECK_TITLE}" (9 slides):`);
  const data = await upsertDeck(token, prior[DECK_TITLE]);
  await writeFile(LEDGER_PATH, JSON.stringify({ ...prior, [DECK_TITLE]: data }, null, 2));
  console.log(`\nDone.\n  ${DECK_TITLE}\n  -> ${data.url}\nLedger: ${LEDGER_PATH}`);
}
main().catch((e) => { console.error('\nFAILED:', e.message || e); process.exit(1); });
