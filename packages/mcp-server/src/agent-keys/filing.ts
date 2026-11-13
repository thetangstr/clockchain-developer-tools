// Filing agent keys on Clockchain, the public book's ledger side: each key event is written under `agent-key:v1:<fp>` with a
// plain-words label, so a checker can see a key existed before any record it signed. A key's "filed" event carries the key's
// own fingerprint as its hash, and is written once. Also the Starter allowance: one daily count of the anchors every new
// agent (ak: owner) spends, filings included, kept apart from accounts.
import { join } from "node:path";
import { createDurableJsonFile, type DurableJsonFile } from "../handshake-core/durable-store.js";
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
 * One durable file, read once and then saved from memory, so a damaged file is set aside once and never rotated over its
 * good backup. A count that can't be read at all fails closed: the allowance reads as used up for the rest of that UTC day.
 */
export class StarterAnchors {
  private readonly max: number;
  private readonly today: () => string;
  private readonly file: DurableJsonFile<StarterFile>;
  /** Today's count in memory, once read. */
  private value: StarterFile | undefined;
  /** The UTC day the file was found unreadable on. */
  private unreadableOn: string | undefined;

  constructor(o: { stateDir: string; max: number; today: () => string }) {
    this.max = o.max;
    this.today = o.today;
    this.file = createDurableJsonFile<StarterFile>({
      path: join(o.stateDir, "starter-anchors.json"), schema: "shadow-starter-anchors-v1", snapshot: () => this.value!, maxBytes: 4096,
      validate: (v) => {
        const f = v as StarterFile;
        if (!f || typeof f !== "object" || typeof f.day !== "string" || !Number.isSafeInteger(f.anchors) || f.anchors < 0) throw new Error("bad starter allowance file");
        return { day: f.day, anchors: f.anchors };
      },
    });
  }

  /** Throws StarterLimitError when today's allowance is used up, or today's count can't be read. */
  check(): void {
    if (this.used() >= this.max) throw new StarterLimitError();
  }

  record(): void {
    const day = this.today();
    if (this.current(day) === null) return; // Unreadable today: check() refuses, so nothing is counted against it.
    this.value = { day, anchors: this.used(day) + 1 };
    this.file.save("now");
  }

  /** Today's count; the whole allowance when it can't be read. */
  used(day = this.today()): number {
    return this.current(day) ?? this.max;
  }

  /** Today's stored count, read from disk the first time; null when it couldn't be read today. */
  private current(day: string): number | null {
    if (this.value === undefined && this.unreadableOn === undefined) {
      try {
        this.value = this.file.load() ?? { day, anchors: 0 };
      } catch {
        this.unreadableOn = day;
      }
    }
    if (this.value === undefined) {
      if (this.unreadableOn === day) return null;
      // A later day's count starts afresh whatever the unreadable file said.
      this.value = { day, anchors: 0 };
    }
    return this.value.day === day ? this.value.anchors : 0;
  }
}
