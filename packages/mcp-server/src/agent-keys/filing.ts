// Filing agent keys on Clockchain, the public book's ledger side: each key event is written under `agent-key:v1:<fp>` with a
// plain-words label, so a checker can see a key existed before any record it signed. A key's "filed" event carries the key's
// own fingerprint as its hash, and is written once. Also the Starter allowance: one daily count of the anchors every new
// agent (ak: owner) spends, filings included, kept apart from accounts.
import { join } from "node:path";
import { createDurableJsonFile } from "../handshake-core/durable-store.js";
import { StarterLimitError, anchorHash, type AnchorRequest, type Failure } from "../shadow/ledger.js";
import { hash } from "../shadow/lib/profile.js";
import { AgentKeyError, type AgentKeyBook, type KeyFiling } from "./book.js";

export type KeyEvent = "filed" | "replaced" | "revoked";

/** Labels are plain words: the gateway strips punctuation. */
export const KEY_EVENT_LABELS: Record<KeyEvent, string> = {
  filed: "agent key filed",
  replaced: "agent key replaced",
  revoked: "agent key revoked",
};

export const keyReferenceId = (fp: string) => `agent-key:v1:${fp}`;

/** Everything anchorHash needs but the write itself: the ledger, budgets, the owner's allowance, retries and the deadline. */
export type FilingLedger = Omit<AnchorRequest, "referenceId" | "hash" | "label" | "ledgerId" | "uncertain">;

/** The filing as it now stands, and why it isn't filed yet when it isn't. `failure` is never kept in the book. */
export type FilingResult = KeyFiling & { failure?: Failure };

/**
 * Writes one key event to Clockchain. For "filed", the book's filing state is the source of truth: a filed key is never
 * written again, a send is marked pending in the book before it starts (so a crash mid-write searches before paying again),
 * and the outcome is saved there. "replaced" and "revoked" hash the book's own event (so a retry has the same hash), always
 * search before writing, and leave the book to the caller.
 */
export async function fileKey(book: AgentKeyBook, ledger: FilingLedger, fp: string, event: KeyEvent, extra: { newFp?: string } = {}): Promise<FilingResult> {
  const entry = book.get(fp);
  if (!entry) throw new AgentKeyError("unknown_key");
  const label = KEY_EVENT_LABELS[event];
  if (event !== "filed") {
    const at = [...entry.events].reverse().find((e) => e.action === event)?.at;
    if (!at) throw new AgentKeyError("no_event");
    const h = hash("agent-key-event:v1", { fp, event, newFp: extra.newFp ?? null, at });
    return outcomeOf(await anchorHash({ ...ledger, referenceId: keyReferenceId(fp), hash: h, label, ledgerId: null, uncertain: true }));
  }
  const prior = entry.filing;
  if (prior.state === "filed") return prior;
  // On disk before the network call, as an outbox row's sendStarted is.
  if (prior.state === "unfiled") book.setFiling(fp, { state: "pending" });
  const result = outcomeOf(await anchorHash({
    ...ledger, referenceId: keyReferenceId(fp), hash: fp, label,
    ledgerId: prior.state === "pending" ? prior.ledgerId ?? null : null, uncertain: prior.state === "pending",
  }));
  const { failure: _failure, ...filing } = result;
  book.setFiling(fp, filing);
  return result;
}

function outcomeOf(o: Awaited<ReturnType<typeof anchorHash>>): FilingResult {
  if (o.kind === "anchored") {
    const block = Number(o.receipt.blockHeight);
    const at = o.receipt.blockTime ?? o.receipt.submittedAt;
    return { state: "filed", ledgerId: o.receipt.ledgerId, ...(Number.isSafeInteger(block) ? { block } : {}), ...(at ? { filedAt: at } : {}) };
  }
  if (o.kind === "pending") return { state: "pending", ledgerId: o.ledgerId };
  // It may be on the ledger: pending, so the next try searches before it pays again.
  if (o.kind === "unconfirmed") return { state: "pending", failure: o.failure };
  return { state: o.maybeWritten ? "pending" : "unfiled", failure: o.failure };
}

type StarterFile = { day: string; anchors: number };

/**
 * The Starter allowance: anchors per UTC day shared by every ak: owner, under the Shadow state dir so a restart keeps the
 * count. check() and record() are a LogBudget's: refuse before a write, count after one lands. Accounts never use it.
 */
export class StarterAnchors {
  private readonly path: string;
  private readonly max: number;
  private readonly today: () => string;

  constructor(o: { stateDir: string; max: number; today: () => string }) {
    this.path = join(o.stateDir, "starter-anchors.json");
    this.max = o.max;
    this.today = o.today;
  }

  /** Throws StarterLimitError when today's allowance is used up. */
  check(): void {
    if (this.used() >= this.max) throw new StarterLimitError();
  }

  record(): void {
    const day = this.today();
    const value: StarterFile = { day, anchors: this.used(day) + 1 };
    this.file(() => value).save("now");
  }

  used(day = this.today()): number {
    const stored = this.file(() => ({ day, anchors: 0 })).load();
    return stored && stored.day === day ? stored.anchors : 0;
  }

  private file(snapshot: () => StarterFile) {
    return createDurableJsonFile<StarterFile>({
      path: this.path, schema: "shadow-starter-anchors-v1", snapshot, maxBytes: 4096,
      validate: (v) => {
        const f = v as StarterFile;
        if (!f || typeof f !== "object" || typeof f.day !== "string" || !Number.isSafeInteger(f.anchors) || f.anchors < 0) throw new Error("bad starter allowance file");
        return f;
      },
    });
  }
}
