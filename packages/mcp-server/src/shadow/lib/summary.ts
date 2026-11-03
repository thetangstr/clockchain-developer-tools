// Vendored from clockchain-shadow/ts/src/summary.ts (source sha256 d65aa9d8c498d83ad1612a8fbb260270e5727c2d8abb855272de9a60b076ec64) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Evidence summary (spec §9): a static HTML page (no scripts, no network) and Markdown, generated from a packet and its
// verification report. Every statement carries one tag: proven, not verified, failed, recorded as reported, or not
// covered.
import { createHash } from 'node:crypto';
import type { Packet } from './types.js';
import type { Report } from './verify.js';

// Every statement carries one tag. "Proven" is used only for what the verifier established against something
// independent of the packet: the pin for integrity and signer, the Clockchain ledger for receipts and time windows
// (v1.1 correction C19). Everything that rests only on the packet itself is "Not verified".
type Tag = 'proven' | 'unverified' | 'failed' | 'reported' | 'not covered';
const TAG_TEXT: Record<Tag, string> = { proven: 'Proven', unverified: 'Not verified', failed: 'Failed', reported: 'Recorded as reported', 'not covered': 'Not covered' };

// Every interpolated value goes through esc (HTML) or md/mdCode (Markdown), numbers included: a packet that failed
// verification can carry anything in any field.
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
const md = (s: unknown) => String(s ?? '').replace(/[\r\n\u2028\u2029]+/g, ' ').replace(/([\\`*_[\]<>|~])/g, '\\$1');
const mdCode = (s: unknown) => '`' + String(s ?? '').replace(/[`\r\n\u2028\u2029|]/g, '') + '`';

function describe(e: Packet['events'][number]): string {
  const p = (e.body.payload ?? {}) as any;
  const text = (c: any) => {
    const t = typeof c?.text === 'string' ? c.text : '';
    return t.slice(0, 140) + (c?.truncated || t.length > 140 ? '…' : '');
  };
  switch (e.body.kind) {
    case 'session.opened': return `Session opened on ${p.network}`;
    case 'task.assigned': return `Task assigned${p.title?.text ? ': ' + text(p.title) : ''}`;
    case 'agent.prompt': return `Prompt: ${text(p.content)}`;
    case 'agent.message': return `Message: ${text(p.content)}`;
    case 'agent.tool.call': return `Tool call ${p.tool}`;
    case 'agent.tool.result': return `Tool result${p.tool ? ' from ' + p.tool : ''}${p.isError ? ' (error)' : ''}`;
    case 'transcript.imported': return `Transcript imported: ${p.messages} messages, ${p.toolCalls} tool calls; reasoning not recorded`;
    case 'artifact.created': return `File written: ${p.path} (${p.bytes} bytes)`;
    case 'artifact.missing': return `File missing: ${p.path}`;
    case 'execution.receipt': return `Run ended: ${p.status}`;
    case 'coverage.gap': return `Capture gap: ${text(p.reason)}`;
    case 'clockchain.anchored': return p.marker === 'start' ? `Start marker on Clockchain, block ${p.blockHeight}` : `Checkpoint of steps 1–${p.checkpoint?.count} on Clockchain, block ${p.blockHeight}`;
    case 'clockchain.error': return `Clockchain write failed (${p.errorKind}${p.errorCode ? ', ' + p.errorCode : ''}); ${p.outcome}`;
    case 'clockchain.verified': return 'Clockchain evidence package checked';
    case 'workflow.error': return `Workflow error: ${text(p.error)}`;
    case 'session.closed': return 'Session closed';
  }
  return String(e.body.kind);
}

export type Summary = { html: string; markdown: string };

const CSS = `:root{--bg:#fff;--fg:#1b1d21;--mute:#5d636e;--line:#e3e5e9;--ok:#1d7a46;--warn:#9a6200;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--mute:#9aa1ac;--line:#2a2e35;--ok:#5cc58a;--warn:#e0a640;--bad:#f07a6e}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:24px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}code{font-size:13px;word-break:break-all}
.meta{color:var(--mute);font-size:13px}.result{font-weight:600}.pass{color:var(--ok)}.indeterminate{color:var(--warn)}.fail{color:var(--bad)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.tag{font-size:11px;white-space:nowrap;color:var(--mute)}.scroll{overflow-x:auto}`;
// The page allows exactly this stylesheet and nothing else: no scripts, no inline styles, no images, no forms.
export const SUMMARY_CSP = `default-src 'none'; style-src 'sha256-${createHash('sha256').update(CSS).digest('base64')}'; img-src 'none'; form-action 'none'; base-uri 'none'`;

export function summarize(packet: Packet, report: Report, o: { packetFile?: string; pinFile?: string } = {}): Summary {
  // The packet may have failed verification, so nothing about its shape is assumed.
  const b: any = (packet as any)?.checkpoint?.body ?? {};
  const cpHash = (packet as any)?.checkpoint?.hash;
  const events: Packet['events'] = Array.isArray((packet as any)?.events)
    ? (packet as any).events.filter((e: any) => e && typeof e === 'object' && e.body && typeof e.body === 'object') : [];
  const status = (n: string) => report.checks.find((c) => c.name === n)?.status ?? '';
  const reason = (n: string) => report.checks.find((c) => c.name === n)?.reason ?? '';
  const failed = report.result === 'fail';
  const pinned = !failed && status('trust') === 'pass';
  const witnessed = !failed && status('witness') === 'pass' && status('anchors') === 'pass';
  const tagOf = (s: string): Tag => (failed ? 'failed' : s === 'pass' ? 'proven' : s === 'fail' ? 'failed' : s === 'not-applicable' ? 'not covered' : 'unverified');
  const facts: [Tag, string][] = [
    failed
      ? ['failed', 'The record failed verification (' + report.failed.join(', ') + '). Do not rely on it.']
      : pinned
        ? ['proven', `The ${b.count} steps below are exactly the steps the operator's recorder signed, in this order, with nothing added, removed or changed since.`]
        : ['unverified', `The ${b.count} steps below are internally consistent and signed, but by a key carried in the packet itself. Without the pin you received separately, this does not show who signed them or that the record was not replaced.`],
    [tagOf(status('trust')), reason('trust')],
    [tagOf(status('witness')), reason('witness')],
    [witnessed ? 'proven' : 'unverified', witnessed
      ? 'Time windows come from Clockchain receipts confirmed against the ledger. They assume ledger ids are unpredictable and that the validators keep good time.'
      : 'Time windows come from Clockchain receipts in the packet that were not confirmed against the ledger here. Run the online check to confirm them.'],
    ['reported', 'What each step says (prompts, messages, tool calls, files, run status) is what the runtime reported; the record proves it was not changed afterwards, not that it is true.'],
    ['not covered', 'Hidden model reasoning, activity outside the captured boundary, and whether the agents were right.'],
  ];
  const windowText = (i: number) => {
    const w = report.windows[i];
    if (!w) return '';
    const lo = w.lower ? `after ${w.lower.time}` : 'no lower bound';
    const hi = w.upper ? `before ${w.upper.time} (block ${w.upper.blockHeight})` : 'not yet anchored';
    return `${lo}; ${hi}${(w.lower || w.upper) && !witnessed ? ' (not verified online)' : ''}`;
  };
  const rows = events.map((e, i) => {
    const kind = e.body.kind, receipt = kind === 'clockchain.anchored' || (kind === 'session.opened' && !!(e.body.payload as any)?.receipt);
    const tag: Tag = e.body.source?.boundary === 'transcript' || kind === 'execution.receipt' || kind === 'artifact.created' ? 'reported'
      : failed ? 'failed' : pinned && (!receipt || witnessed) ? 'proven' : 'unverified';
    return { seq: e.body.seq, actor: e.body.actor, what: describe(e), when: windowText(i), tag };
  });
  const anchors = events.filter((e) => e.body.kind === 'clockchain.anchored' || (e.body.kind === 'session.opened' && (e.body.payload as any)?.receipt));
  const receiptOf = (e: Packet['events'][number]) => {
    const p = e.body.payload as any;
    return (e.body.kind === 'session.opened' ? p.receipt : p) ?? {};
  };
  const confirmed = witnessed ? 'confirmed on the ledger' : 'not confirmed online';
  const verifyCmd = `shadow-verify ${o.packetFile ?? 'packet.json'} --pin ${o.pinFile ?? 'pin.json'} --online`;

  const markdown = [
    `# Shadow evidence summary`,
    ``,
    `**Result: ${md(report.result)}.** ${md(report.summary)}`,
    ``,
    `Session ${mdCode(b.sessionId)} · operator ${mdCode(b.operatorId)} · ${md(b.network)} · ${md(b.count)} steps · checkpoint ${mdCode(cpHash)}`,
    ``,
    `## What this record shows`,
    ...facts.map(([t, s]) => `- **${TAG_TEXT[t]}:** ${md(s)}`),
    ``,
    `## Agents and coverage`,
    `| Agent | Status | Runs | Captured steps | Gaps |`,
    `|---|---|---|---|---|`,
    ...(Array.isArray(b.coverage) ? b.coverage : []).map((c: any) => `| ${md(c?.agent)} | ${md(c?.status)} | ${md(c?.runs)} | ${md(c?.observedEvents)} | ${md(c?.gaps)} |`),
    ``,
    `## Timeline`,
    `| # | Agent | Step | Time window | |`,
    `|---|---|---|---|---|`,
    ...rows.map((r) => `| ${md(r.seq)} | ${md(r.actor)} | ${md(r.what)} | ${md(r.when)} | ${TAG_TEXT[r.tag]} |`),
    ``,
    `## Clockchain receipts (${confirmed})`,
    ...(anchors.length ? anchors.map((e) => {
      const r = receiptOf(e);
      return `- Step ${md(e.body.seq)}: ledger id ${mdCode(r.ledgerId)}, block ${md(r.blockHeight)}, ${md(r.blockTime)}`;
    }) : ['- None.']),
    ``,
    `## Checks`,
    ...report.checks.map((c) => `- ${mdCode(c.name)} ${md(c.status)}: ${md(c.reason)}`),
    ``,
    `## How to verify this yourself`,
    `Run ${mdCode(verifyCmd)}, using the pin you received separately from the packet. Exit code 0 is pass, 2 indeterminate, 1 fail.`,
    ``,
    `_${md(report.interpretation)}_`,
    ``,
  ].join('\n');

  const li = (t: Tag, s: string) => `<li><b>${TAG_TEXT[t]}:</b> ${esc(s)}</li>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${esc(SUMMARY_CSP)}"><meta name="referrer" content="no-referrer">
<title>Shadow evidence summary</title><style>${CSS}</style></head><body>
<h1>Shadow evidence summary</h1>
<p class="meta">Session <code>${esc(b.sessionId)}</code> · operator <code>${esc(b.operatorId)}</code> · ${esc(b.network)} · ${esc(b.count)} steps</p>
<p class="result ${esc(report.result)}">Result: ${esc(report.result)}. ${esc(report.summary)}</p>
<h2>What this record shows</h2><ul>${facts.map(([t, s]) => li(t, s)).join('')}</ul>
<h2>Agents and coverage</h2><div class="scroll"><table><tr><th>Agent</th><th>Status</th><th>Runs</th><th>Captured steps</th><th>Gaps</th></tr>
${(Array.isArray(b.coverage) ? b.coverage : []).map((c: any) => `<tr><td>${esc(c?.agent)}</td><td>${esc(c?.status)}</td><td>${esc(c?.runs)}</td><td>${esc(c?.observedEvents)}</td><td>${esc(c?.gaps)}</td></tr>`).join('')}</table></div>
<h2>Timeline</h2><div class="scroll"><table><tr><th>#</th><th>Agent</th><th>Step</th><th>Time window</th><th></th></tr>
${rows.map((r) => `<tr><td>${esc(r.seq)}</td><td>${esc(r.actor)}</td><td>${esc(r.what)}</td><td>${esc(r.when)}</td><td class="tag">${TAG_TEXT[r.tag]}</td></tr>`).join('')}</table></div>
<h2>Clockchain receipts (${confirmed})</h2><ul>${anchors.length ? anchors.map((e) => {
    const r = receiptOf(e);
    return `<li>Step ${esc(e.body.seq)}: ledger id <code>${esc(r.ledgerId)}</code>, block ${esc(r.blockHeight)}, ${esc(r.blockTime)}</li>`;
  }).join('') : '<li>None.</li>'}</ul>
<h2>Checks</h2><ul>${report.checks.map((c) => `<li><code>${esc(c.name)}</code> <span class="${esc(c.status)}">${esc(c.status)}</span>: ${esc(c.reason)}</li>`).join('')}</ul>
<h2>How to verify this yourself</h2><p>Run <code>${esc(verifyCmd)}</code>, using the pin you received separately from the packet. Exit code 0 is pass, 2 indeterminate, 1 fail.</p>
<p class="meta">${esc(report.interpretation)}</p>
</body></html>
`;
  return { html, markdown };
}
