// Vendored from clockchain-shadow/ts/src/kinds.ts (source sha256 7eab6428a9ebfddca8bba88e78bc6eee8ba84f4f46bff6ff6d86b3361ca27d73) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Who may produce which step (spec §3.2), and coverage as both the recorder and the verifier compute it (spec §3.5).
import type { Coverage, ShadowEvent } from './types.js';

export const COLLECTOR_KINDS = [
  'session.opened', 'task.assigned', 'execution.receipt', 'transcript.imported', 'artifact.created', 'artifact.missing',
  'coverage.gap', 'clockchain.anchored', 'clockchain.error', 'clockchain.verified', 'workflow.error', 'session.closed',
] as const;
export const TRANSCRIPT_KINDS = ['agent.prompt', 'agent.message', 'agent.tool.call', 'agent.tool.result'] as const;

export const isCollectorKind = (kind: string) => (COLLECTOR_KINDS as readonly string[]).includes(kind);
export const isTranscriptKind = (kind: string) => (TRANSCRIPT_KINDS as readonly string[]).includes(kind);

const has = (agents: readonly string[] | ReadonlySet<string>, a: string) => (agents instanceof Set ? agents.has(a) : (agents as readonly string[]).includes(a));

// Collector steps may name a declared agent as their subject; transcript steps must come from one.
export function provenanceOk(e: ShadowEvent, agents: readonly string[] | ReadonlySet<string>): boolean {
  const { kind, actor, source } = e.body;
  if (source?.boundary === 'transcript') return isTranscriptKind(kind) && has(agents, actor);
  if (source?.boundary === 'collector') return isCollectorKind(kind) && (actor === 'collector' || has(agents, actor));
  return false;
}

// A run is covered when it ended with a receipt, captured at least one transcript step and recorded no gap. An agent
// with no runs is idle, not missing: a session can span a day in which some agents never run. One pass over the steps.
export function coverage(events: ShadowEvent[], agents: readonly string[]): Coverage[] {
  type Acc = { runs: Set<string | null>; ended: Set<string | null>; stepRuns: Set<string | null>; steps: number; gaps: number };
  const per = new Map<string, Acc>();
  for (const a of agents) if (!per.has(a)) per.set(a, { runs: new Set(), ended: new Set(), stepRuns: new Set(), steps: 0, gaps: 0 });
  for (const e of events) {
    const c = per.get(e.body.actor);
    if (!c) continue;
    const run = e.body.source.agentRunId;
    if (e.body.kind === 'task.assigned') c.runs.add(run);
    if (e.body.kind === 'execution.receipt') c.ended.add(run);
    if (e.body.source.boundary === 'transcript') {
      c.steps++;
      c.stepRuns.add(run);
    }
    if (e.body.kind === 'coverage.gap') c.gaps++;
  }
  return agents.map((agent) => {
    const c = per.get(agent)!;
    const uncovered = [...c.runs].filter((r) => c.ended.has(r) && !c.stepRuns.has(r));
    const open = [...c.runs].some((r) => !c.ended.has(r));
    const status = c.gaps || uncovered.length ? 'partial' : open ? 'open' : c.runs.size ? 'observed' : 'idle';
    return { agent, status, runs: c.runs.size, observedEvents: c.steps, gaps: c.gaps };
  });
}
