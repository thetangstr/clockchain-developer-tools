// Vendored from clockchain-shadow/ts/src/verify.ts (source sha256 71eeae4d38729fc3eff2d91d3be4deadc12b95be32472a10eb897b8e0e5593ec) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Verifier (spec §8). pass = no check failed and every decisive check passed; indeterminate = nothing failed but a
// decisive check is not established; fail = any check failed. Exit codes 0, 2, 1.
import { canonical, DOMAIN, hash, merklePrefixRoots, merkleRoot, PROFILE, verifyProof } from './profile.js';
import { coverage, provenanceOk } from './kinds.js';
import { fingerprint, verifySignature } from './keys.js';
import { windows, type Window } from './windows.js';
import { checkReceipts, pendingCheckpointOk, type ReceiptCheck } from './anchors.js';
import { identityDid, IDENTITY_SCHEMA, SALT } from './identity.js';
import { ClockchainError } from './clockchain.js';
import type { CheckpointBody, ShadowEvent } from './types.js';

export type Status = 'pass' | 'fail' | 'indeterminate' | 'not-applicable';
export type Check = { name: string; status: Status; reason: string };
export type Report = {
  result: 'pass' | 'fail' | 'indeterminate';
  exitCode: 0 | 1 | 2;
  summary: string;
  failed: string[];
  indeterminate: string[];
  checks: Check[];
  windows: Window[];
  interpretation: string;
};

// What online verification needs from a Clockchain client; ClockchainClient provides all of it. `search` lists the
// ledger records under a reference id; `network` names the network the client's endpoint serves.
export interface OnlineClient {
  logEntry(ledgerId: string): Promise<{ assetHash: string | null; blockHeight: string | null; blockTime: string | null; submittedAt: string | null }>;
  confirmPackage(ledgerId: string): Promise<{ valid: boolean }>;
  search?(referenceId: string): Promise<{ ledgerId: string; assetHash: string | null }[]>;
  readonly network?: string;
}
// pin: undefined means none was supplied. Anything else, null included, is a supplied pin and must match.
export type VerifyOptions = { pin?: unknown; online?: OnlineClient; requireOnline?: boolean };

const EXIT = { pass: 0, indeterminate: 2, fail: 1 } as const;
const NETWORKS = ['clockchain-testnet', 'clockchain-mainnet'];
const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';
const strOrNull = (v: unknown) => v === null || typeof v === 'string';
const isInt = (v: unknown): v is number => Number.isSafeInteger(v);
const list = (xs: string[], max = 8) => xs.slice(0, max).join(', ') + (xs.length > max ? ` and ${xs.length - max} more` : '');

// Online reads wait out the server's rate limit (Retry-After up to a minute, twice) instead of reporting it unreachable.
async function patient<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const wait = e instanceof ClockchainError && e.kind === 'RateLimited' ? e.retryAfterSeconds ?? 30 : null;
      if (wait == null || wait > 60 || attempt >= 2) throw e;
      await new Promise((r) => setTimeout(r, wait * 1000 + 250));
    }
  }
}

// The shape every later check relies on, so no check reads a value of an unexpected type and both libraries reach the
// same verdict on any input (v1.1 correction C10). Throws the format failure.
function checkShape(packet: any): void {
  if (!isObj(packet) || packet.format !== 'shadow-evidence-v2' || packet.profile !== PROFILE || !Array.isArray(packet.events)) throw new Error('Unsupported packet format');
  const cp = packet.checkpoint, b = isObj(cp) ? cp.body : null;
  if (!isObj(cp) || !isObj(b) || !isStr(cp.hash) || !isStr(cp.publicKey) || !isStr(cp.signature)) throw new Error('Unsupported checkpoint');
  if (b.profile !== PROFILE || b.streamId !== 'collector' || !NETWORKS.includes(b.network) || !isStr(b.operatorId) || !isStr(b.sessionId) ||
    !isInt(b.count) || !strOrNull(b.head) || !isStr(b.merkleRoot) || !strOrNull(b.previousCheckpointHash) || !isStr(b.createdAt) ||
    !Array.isArray(b.coverage) || !Array.isArray(b.knownLimits))
    throw new Error('Unsupported checkpoint');
  const agents = b.inventory?.agents;
  if (!isObj(b.inventory) || b.inventory.profile !== 'shadow-inventory-v1' || !Array.isArray(agents) || !agents.length ||
    !agents.every((a: unknown) => isStr(a) && a !== 'collector') || new Set(agents).size !== agents.length)
    throw new Error('Unsupported inventory');
  packet.events.forEach((e: any, i: number) => {
    const v = isObj(e) ? e.body : null, s = isObj(v) ? v.source : null;
    if (!isObj(e) || !isStr(e.hash) || !isObj(v) || !isStr(v.profile) || !isStr(v.operatorId) || !isStr(v.sessionId) || !isStr(v.streamId) ||
      !isInt(v.seq) || !strOrNull(v.previousHash) || !isStr(v.eventId) || !isStr(v.kind) || !isStr(v.actor) || !isStr(v.collectedAt) ||
      !isObj(s) || !isStr(s.boundary) || !strOrNull(s.agentRunId) || !strOrNull(s.taskId) || !strOrNull(s.transcriptId) || !isObj(v.payload))
      throw new Error(`Malformed step at position ${i + 1}`);
  });
  if (!Array.isArray(packet.proofs)) throw new Error('Proofs missing');
  if (packet.identities !== undefined && !Array.isArray(packet.identities)) throw new Error('Malformed identities');
  if (packet.pendingCheckpoints !== undefined && !Array.isArray(packet.pendingCheckpoints)) throw new Error('Malformed pending checkpoints');
  // The network label is bound across the packet (v1.1 correction C13).
  if (!isObj(packet.manifest) || packet.manifest.network !== b.network) throw new Error('The manifest network does not match the checkpoint');
  canonical(packet);
}

export async function verifyPacket(packet: any, o: VerifyOptions = {}): Promise<Report> {
  const checks: Check[] = [];
  const add = (name: string, status: Status, reason: string) => checks.push({ name, status, reason });
  let wins: Window[] = [];
  let formatChecked = false;
  try {
    checkShape(packet);
    const cp = packet.checkpoint, b: CheckpointBody = cp.body;
    const agents: string[] = b.inventory.agents, agentSet = new Set(agents);
    add('format', 'pass', `shadow-evidence-v2, profile ${PROFILE}, ${b.network}.`);
    formatChecked = true;
    const events: ShadowEvent[] = packet.events;

    // content and sequence
    let digestOK = true, seqOK = true, orderOK = true, prev: string | null = null, closed = false;
    const ids = new Set<string>(), assigned = new Set<string>(), ended = new Set<string>();
    events.forEach((e, i) => {
      const v = e.body, run = v.source.agentRunId;
      if (hash(DOMAIN.event, v) !== e.hash) digestOK = false;
      if (v.profile !== PROFILE || v.seq !== i + 1 || v.previousHash !== prev || v.operatorId !== b.operatorId || v.sessionId !== b.sessionId || v.streamId !== 'collector' || ids.has(v.eventId)) seqOK = false;
      ids.add(v.eventId);
      prev = e.hash;
      // Session and run order (v1.1 correction C15): one session.opened, first; nothing but Clockchain steps after
      // session.closed; a run's steps follow its one task.assigned and stop at its execution.receipt.
      if (v.kind === 'session.opened' && i !== 0) orderOK = false;
      if (closed && !v.kind.startsWith('clockchain.')) orderOK = false;
      if (v.kind === 'session.closed') closed = true;
      if (v.kind === 'task.assigned') {
        if (run === null || assigned.has(run)) orderOK = false;
        else assigned.add(run);
      } else if (run !== null) {
        if (!assigned.has(run) || ended.has(run)) orderOK = false;
        if (v.kind === 'execution.receipt') ended.add(run);
      } else if (v.kind === 'execution.receipt') orderOK = false;
    });
    add('content', digestOK ? 'pass' : 'fail', digestOK ? 'Every step matches its digest.' : 'One or more steps changed after they were recorded.');
    const opened = events[0]?.body;
    seqOK = seqOK && b.count === events.length && b.head === prev && opened?.kind === 'session.opened' && opened.payload.network === b.network;
    add('sequence', seqOK && orderOK ? 'pass' : 'fail', !seqOK ? 'Scope, sequence, count or head does not match the checkpoint.'
      : !orderOK ? 'Steps are out of session or run order (a step after the session closed or after its run ended, a second session.opened or task.assigned, or a run step before its assignment).'
        : `${events.length} steps in one unbroken chain, matching the checkpoint's count and head.`);

    // membership, recomputed independently of the recorder's tree builder
    const hashes = events.map((e) => e.hash);
    const membership = merkleRoot(hashes) === b.merkleRoot && packet.proofs.length === events.length &&
      hashes.every((h, i) => Array.isArray(packet.proofs[i]) && verifyProof(h, i, hashes.length, packet.proofs[i], b.merkleRoot));
    add('membership', membership ? 'pass' : 'fail', membership ? 'Merkle root and every inclusion proof match.' : 'Merkle root or an inclusion proof does not match.');

    const cpHash = hash(DOMAIN.checkpoint, b);
    const sigOK = cpHash === cp.hash && verifySignature(cp.publicKey, cpHash, cp.signature);
    add('signature', sigOK ? 'pass' : 'fail', sigOK ? 'The checkpoint signature verifies under the Ed25519 key in the packet.' : 'Checkpoint digest or signature does not verify.');

    const pin = o.pin as any;
    if (pin === undefined) add('trust', 'indeterminate', 'No pin supplied. The key in the packet proves integrity, not who signed it; supply the pin you received separately.');
    else {
      const ok = isObj(pin) && pin.format === 'shadow-trust-pin-v2' && pin.checkpointHash === cp.hash && pin.publicKeyFingerprint === fingerprint(cp.publicKey) && pin.operatorId === b.operatorId && pin.sessionId === b.sessionId;
      add('trust', ok ? 'pass' : 'fail', ok ? 'Matches the supplied pin. This is independent assurance only if the pin reached you separately from the packet.' : 'Does not match the supplied pin.');
    }

    // Identities (v1.1 correction C13): each DID derives from the operator, agent and salt, and each document names this
    // record's operator and signing key.
    const identities: any[] = packet.identities ?? [];
    if (!identities.length) add('identity', 'not-applicable', 'No agent identities in this packet.');
    else {
      const fp = fingerprint(cp.publicKey), seen = new Set<string>(), badIds: string[] = [];
      identities.forEach((x, k) => {
        const d = isObj(x) ? x.document : null;
        const ok = isObj(x) && isStr(x.agentId) && agentSet.has(x.agentId) && !seen.has(x.agentId) && isStr(x.salt) && SALT.test(x.salt) &&
          x.did === identityDid(b.operatorId, x.agentId, x.salt) && isObj(d) && d.schema === IDENTITY_SCHEMA && d.did === x.did &&
          d.operatorId === b.operatorId && d.recorderKey === fp && isStr(d.labels) && /^[0-9a-f]{64}$/.test(d.labels) && strOrNull(x.docHash) && strOrNull(x.ledgerId);
        if (isObj(x) && isStr(x.agentId)) seen.add(x.agentId);
        if (!ok) badIds.push(String(k + 1));
      });
      add('identity', badIds.length ? 'fail' : 'pass', badIds.length
        ? `Identities at position ${list(badIds)} do not derive from this operator, agent and salt, or do not name this record's signing key.`
        : `${identities.length} agent identit${identities.length === 1 ? 'y derives' : 'ies derive'} from this operator and name this record's signing key.`);
    }

    const recomputed = coverage(events, agents);
    const consistent = canonical(recomputed) === canonical(b.coverage);
    const notCovered = recomputed.filter((c) => c.status === 'partial' || c.status === 'open');
    add('coverage', !consistent ? 'fail' : notCovered.length ? 'indeterminate' : 'pass', !consistent
      ? 'The signed coverage does not match the steps in the record.'
      : notCovered.length
        ? 'Not fully captured: ' + notCovered.map((c) => `${c.agent} (${c.status}${c.gaps ? `, ${c.gaps} gap(s)` : ''})`).join(', ') + '.'
        : `Every run of the ${agents.length} declared agents ended with a receipt and captured steps, with no recorded gap. Activity outside the captured boundary is not covered.`);

    const spoofed = events.filter((e) => !provenanceOk(e, agentSet)).map((e) => String(e.body.seq));
    add('provenance', spoofed.length ? 'fail' : 'pass', spoofed.length ? 'Steps with a kind or agent their boundary does not allow, at sequence ' + list(spoofed) + '.' : 'Transcript steps come only from declared agents; receipts, imports, gaps and anchors only from the collector.');

    const errors = events.filter((e) => e.body.kind === 'workflow.error').length;
    const unfinished = events.filter((e) => e.body.kind === 'execution.receipt' && (e.body.payload as any).status !== 'succeeded').map((e) => `${e.body.actor} (${(e.body.payload as any).status})`);
    const missing = events.filter((e) => e.body.kind === 'artifact.missing').map((e) => e.body.actor);
    const isClosed = events.some((e) => e.body.kind === 'session.closed');
    const incomplete = errors || unfinished.length || missing.length || !isClosed;
    add('completion', incomplete ? 'indeterminate' : 'pass', incomplete
      ? [!isClosed && 'the session is still open', errors && `${errors} workflow error(s)`, unfinished.length && 'runs not succeeded: ' + list(unfinished), missing.length && 'deliverables missing: ' + list(missing)].filter(Boolean).join('; ') + '.'
      : 'The session closed, every run succeeded, every expected deliverable was written and no workflow error was recorded.');

    // Offline proof that each receipt commits to what it claims (v1.1 correction C8), with Merkle prefix roots computed
    // once (v1.1 correction C16).
    const scope = { operatorId: b.operatorId, sessionId: b.sessionId, network: b.network };
    const prefixRoot = merklePrefixRoots(hashes);
    const receipts: ReceiptCheck[] = checkReceipts(events, scope, prefixRoot);
    const pending: unknown[] = packet.pendingCheckpoints ?? [];
    const bad = receipts.filter((r) => !r.ok).map((r) => String(r.seq));
    const badPending = pending.map((p, k) => (pendingCheckpointOk(p, events, scope, prefixRoot) ? null : String(k + 1))).filter((x): x is string => x !== null);
    const cpAnchors = receipts.filter((r) => r.marker === 'checkpoint').length;
    if (bad.length || badPending.length)
      add('anchors', 'fail', [bad.length && `Receipts at sequence ${list(bad)} do not commit to the steps recorded before them`,
        badPending.length && `pending checkpoints ${list(badPending)} do not commit to steps in this record`].filter(Boolean).join('; ') + '.');
    else if (!receipts.length) add('anchors', 'not-applicable', 'No Clockchain receipts in this record.');
    else add('anchors', 'pass', `The start marker and ${cpAnchors} checkpoint anchor(s) each commit to exactly the steps recorded before them.`);

    // Witness (v1.1 correction C9): online, every receipt must match the ledger, and every ledger record under this
    // session's reference must be accounted for by the packet, so a record cut short after a later anchor fails.
    const ref = 'shadow:v1:' + b.sessionId;
    if (!o.online) {
      if (receipts.length) add('witness', 'indeterminate', `${receipts.length} Clockchain receipt(s) in the record. Confirm them online (--online).`);
      else add('witness', o.requireOnline ? 'indeterminate' : 'not-applicable', 'Nothing in this record was sent to Clockchain, so nothing can be confirmed online.');
    } else if (isStr(o.online.network) && o.online.network !== b.network) {
      add('witness', 'indeterminate', `The online client is configured for ${o.online.network}, but this record is on ${b.network}.`);
    } else {
      const online = o.online;
      const problems: string[] = [];
      let unreachable = false, incomplete = false;
      const queried = receipts.filter((r) => isStr(r.ledgerId) && r.ledgerId);
      for (const a of queried) {
        try {
          const r = await patient(() => online.logEntry(a.ledgerId as string));
          if (r.assetHash !== a.expected) problems.push(`seq ${a.seq}: ledger hash differs`);
          else if (r.blockHeight !== a.blockHeight) problems.push(`seq ${a.seq}: block differs`);
          else if (r.blockTime !== a.blockTime) problems.push(`seq ${a.seq}: block time differs`);
          else if (r.submittedAt !== a.submittedAt) problems.push(`seq ${a.seq}: submission time differs`);
        } catch {
          unreachable = true;
        }
      }
      if (queried.length) {
        const last = queried[queried.length - 1];
        try {
          if (!(await patient(() => online.confirmPackage(last.ledgerId as string))).valid) problems.push(`Clockchain's evidence package for ${last.ledgerId} did not verify`);
        } catch {
          unreachable = true;
        }
      }
      // Every hash the packet accounts for: its receipts, its start marker, its own checkpoint and pending checkpoints.
      const accounted = new Set<string>([cp.hash, ...receipts.map((r) => r.expected).filter(isStr), ...pending.map((p: any) => p?.hash).filter(isStr)]);
      if (isStr(opened?.payload?.startHash)) accounted.add(opened.payload.startHash);
      let unexplained = 0;
      if (!online.search) incomplete = true;
      else {
        try {
          const found = await patient(() => online.search!(ref));
          const seenIds = new Set(found.map((f) => f.ledgerId));
          if (queried.some((r) => !seenIds.has(r.ledgerId as string))) incomplete = true;
          const extra = found.filter((f) => !isStr(f.assetHash) || !accounted.has(f.assetHash)).map((f) => String(f.ledgerId).slice(0, 80));
          unexplained = extra.length;
          if (extra.length) problems.push(`the ledger holds ${extra.length} record(s) for this session that the packet does not account for (${list(extra, 3)}); steps may have been left out`);
        } catch {
          unreachable = true;
        }
      }
      if (problems.length) add('witness', 'fail', problems.slice(0, 10).join('; ') + '.');
      else if (!receipts.length) add('witness', o.requireOnline ? 'indeterminate' : 'not-applicable', unexplained === 0 && !unreachable
        ? 'Nothing in this record was sent to Clockchain, and the ledger holds no record for this session that the packet leaves out.'
        : 'Nothing in this record was sent to Clockchain.');
      else if (unreachable) add('witness', 'indeterminate', 'Clockchain could not be reached for every receipt.');
      else if (incomplete) add('witness', 'indeterminate', `All ${queried.length} receipts match the Clockchain ledger, but the ledger search for this session did not return them (it is scoped to the Clockchain account that wrote them), so records left out of the packet cannot be ruled out.`);
      else add('witness', 'pass', `All ${queried.length} receipts match the Clockchain ledger and block times, Clockchain's own evidence package for the last one verifies, and the ledger holds no record for this session that the packet leaves out.`);
    }

    wins = windows(events, { receipts });
    const anchoredBad = checks.find((c) => c.name === 'anchors')?.status === 'fail';
    const bounded = wins.filter((w) => w.lower && w.upper).length;
    add('time', anchoredBad ? 'fail' : 'indeterminate', anchoredBad
      ? 'Windows cannot be trusted because an anchor does not commit to its steps.'
      : `${bounded} of ${wins.length} steps have both bounds. Bounds come only from receipts that commit to their steps; with a single validator they are only as good as its clock, and the lower bound assumes ledger ids are unpredictable.`);
    add('truth', 'not-applicable', 'Hashes do not show that what an agent said or did was correct, compliant or complete.');
  } catch (e) {
    if (formatChecked) add('verifier', 'fail', 'Verification stopped on a malformed record: ' + (e as Error).message);
    else add('format', 'fail', (e as Error).message);
  }
  const decisive = ['trust', 'coverage', 'completion', ...(o.requireOnline ? ['witness'] : [])];
  const failed = checks.filter((c) => c.status === 'fail').map((c) => c.name);
  const indeterminate = checks.filter((c) => decisive.includes(c.name) && c.status === 'indeterminate').map((c) => c.name);
  const result = failed.length ? 'fail' : indeterminate.length ? 'indeterminate' : 'pass';
  const summary = result === 'fail' ? 'Failed: ' + failed.join(', ') + '.'
    : result === 'indeterminate' ? 'No check failed, but not established: ' + indeterminate.join(', ') + '.'
      : 'No check failed; the checkpoint matches the supplied pin, every run was captured and the session completed.';
  return {
    result, exitCode: EXIT[result], summary, failed, indeterminate, checks, windows: wins,
    interpretation: 'A pass is not a verdict on truth, compliance or complete capture. Exit codes: 0 pass, 2 indeterminate, 1 fail.',
  };
}
