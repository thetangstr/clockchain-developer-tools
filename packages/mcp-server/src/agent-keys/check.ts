// Who made a Shadow record, in a line a person can read: the checkpoint's signing key looked up in the public book of
// agent keys, its signature, when the key was filed on Clockchain, and whether it was cancelled first. The server is
// checking its own book, so every agent and witness line says so and never claims independence.
import { DOMAIN, hash } from "../shadow/lib/profile.js";
import { fingerprint, verifySignature } from "../shadow/lib/keys.js";
import type { Checkpoint } from "../shadow/lib/types.js";
import { HOSTED_LIMITS } from "../shadow/recorder.js";
import type { KeyEntry } from "./book.js";

export type KeyVerdict = "made_by_agent" | "key_not_filed" | "key_check_unavailable" | "key_filed_after" | "key_revoked_before" | "not_from_agent" | "witnessed" | "legacy";
export type KeyCheck = { verdict: KeyVerdict; text: string };

export const CHECKED = " Checked against Clockchain's public key list.";
const AGENT_OPERATOR = /^agent-([0-9a-f]{32})$/;
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/** A plain UTC date, like "13 November 2026". */
export function plainDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/**
 * The verdict on `cp`'s signing key. `entry` is the book's entry for fingerprint(cp.publicKey): null when it isn't in the
 * book, which ties the record to no key of the agent's. `cpBlock` is the block of the checkpoint's anchor (null until its
 * receipt lands), `anchoredAt` that anchor's time, and `witness` the fingerprint of Clockchain's published witness key.
 * `noBook` says there is no key book to look in (agent keys are off): nothing is checked against a list, so nothing is
 * claimed of the key, and a bad signature is said without claiming a list was checked.
 * When several apply: not_from_agent, then key_revoked_before (revoked or replaced), key_filed_after, key_not_filed, made_by_agent.
 * Cancellation is judged by time against the checkpoint's createdAt, never by block: a checkpoint signed before the key was
 * replaced or revoked can be anchored after that change is filed, and is still the agent's.
 */
export function checkAgentKey(entry: KeyEntry | null, cp: Checkpoint, cpBlock: number | null, opts: { anchoredAt?: string | null; witness?: string; noBook?: boolean } = {}): KeyCheck {
  const operator = AGENT_OPERATOR.exec(cp.body.operatorId);
  if (!operator) {
    if (opts.witness !== undefined && fingerprint(cp.publicKey) === opts.witness) return { verdict: "witnessed", text: `Witnessed by Clockchain for a signed-in account.${CHECKED}` };
    return { verdict: "legacy", text: HOSTED_LIMITS.at(-1)! };
  }
  // The operator id carries the first 32 hex of the agent's root key, so the agent is named even when its key isn't in the book.
  const agentId = operator[1].slice(0, 16);
  const signed = hash(DOMAIN.checkpoint, cp.body) === cp.hash && verifySignature(cp.publicKey, cp.hash, cp.signature);
  if (opts.noBook)
    return signed
      ? { verdict: "key_check_unavailable", text: `Signed by agent ${agentId}. Its key can't be checked right now.` }
      : { verdict: "not_from_agent", text: `Not from agent ${agentId}: the signature doesn't match its key.` };
  // A key missing from the book, or another agent's, ties the record to no key of this agent's.
  if (!signed || entry === null || entry.publicKeyPem !== cp.publicKey || entry.root.slice(0, 32) !== operator[1]) return { verdict: "not_from_agent", text: `Not from agent ${agentId}: the signature doesn't match its key.${CHECKED}` };
  // Replaced counts as cancelled: from its replacement on, the key is no longer the agent's.
  const cancelled = [entry.revokedAt, ...entry.events.filter((e) => e.action === "replaced").map((e) => e.at)].filter((t): t is string => t !== undefined);
  if (cancelled.some((t) => Date.parse(t) <= Date.parse(cp.body.createdAt)))
    return { verdict: "key_revoked_before", text: `Signed by agent ${agentId}, but that key was cancelled before this record.${CHECKED}` };
  const filed = entry.filing.state === "filed";
  if (filed && entry.filing.block !== undefined && cpBlock !== null && entry.filing.block > cpBlock)
    return { verdict: "key_filed_after", text: `Signed by agent ${agentId}, but its key was filed after this record.${CHECKED}` };
  if (!filed) return { verdict: "key_not_filed", text: `Signed by agent ${agentId}. Its key isn't filed on Clockchain yet.${CHECKED}` };
  const filedAt = entry.filing.filedAt ?? entry.events.find((e) => e.action === "filed")?.at ?? entry.firstSeenAt;
  return { verdict: "made_by_agent", text: `Made by agent ${agentId}, unchanged since ${plainDate(opts.anchoredAt ?? cp.body.createdAt)}. Key filed ${plainDate(filedAt)}.${CHECKED}` };
}

/**
 * The verdict for a record that failed its checks for another reason than its key (its steps no longer match the signed
 * checkpoint, say): made_by_agent would claim it unchanged, so it says the record failed. Other verdicts already say what's wrong.
 */
export function failedRecord(r: KeyCheck, cp: Checkpoint): KeyCheck {
  if (r.verdict !== "made_by_agent") return r;
  const agentId = AGENT_OPERATOR.exec(cp.body.operatorId)![1].slice(0, 16);
  return { verdict: r.verdict, text: `Signed by agent ${agentId}, but this record failed its checks.${CHECKED}` };
}
