// Mailboxes for handshake addresses (spec B4). A mailbox is claimed by the key whose
// fingerprint is in its address; invitations sent `to` it wait there for its listener.
//
// Durability (B2 patterns): one durable file per mailbox (named by a digest of its address),
// so a large or damaged mailbox never affects another, and a write only ever touches one
// small file. Listen tokens and client IPs are stored as digests only; challenge nonces are
// ephemeral (a restart simply means asking for a new one).
//
// No oracle on the invite path: delivering (or not) an invitation never writes synchronously.
// A delivery is a coalesced ("soon") write, and a refusal writes nothing, so the Initiator's
// call does the same durable work either way. The cost is that a delivery made less than a
// second before a crash can be lost; the Initiator then sees exactly what it sees for an
// absent or ignoring listener (INVITATION_NOT_ACCEPTED at the TTL).
//
// Fill bounds: a mailbox holds at most MAX_PENDING_PER_MAILBOX open invitations, at most one
// per Initiator key and at most MAX_PENDING_PER_SOURCE from one client IP; together with the
// per-IP invite rate limit that bounds how fast any one network can fill a mailbox.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";

import { cleanStaleFiles, createDurableJsonFile, DurableStateError, type DurableJsonFile } from "../handshake-core/durable-store.js";

export const CHALLENGE_TTL_MS = 2 * 60_000;
export const MAILBOX_IDLE_TTL_MS = 24 * 60 * 60_000;
export const MAILBOX_INVITATION_TTL_MS = 60 * 60_000;
export const MAX_PENDING_PER_MAILBOX = 10;
export const MAX_PENDING_PER_SOURCE = 2;
export const MAX_MAILBOXES = 10_000;
export const MAX_MAILBOXES_PER_KEY = 5;
export const MAX_MAILBOXES_PER_CLIENT = 20;
export const MAX_CHALLENGES = 10_000;
export const MAX_MAILBOX_EVENTS = 30;
export const MAX_MAILBOX_HISTORY = 20;
export const SWEEP_INTERVAL_MS = 60_000;
const SCHEMA = "clockchain.standalone-handshake-mailbox/v1";
const MAX_MAILBOX_FILE_BYTES = 256 * 1024;

export type MailboxInvitationStatus = "pending" | "reviewed" | "accepted" | "declined" | "expired";

export interface MailboxInvitation {
  invitationId: string;
  sessionId: string;
  initiatorFingerprint: string;
  sourceDigest: string;
  deliveredAtMs: number;
  expiresAtMs: number;
  status: MailboxInvitationStatus;
}

export interface Mailbox {
  address: string;
  ownerKey: string;
  allow: string[] | null;
  block: string[];
  listenDigest: string;
  clientDigest: string;
  claimedAtMs: number;
  lastActiveAtMs: number;
  invitations: MailboxInvitation[];
  events: Array<Record<string, unknown>>;
}

function digest(kind: string, value: string): string {
  return createHash("sha256").update(`${kind}\u0000${value}`, "utf8").digest("hex");
}

export class MailboxRefusal extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "MailboxRefusal";
  }
}

export function createMailboxStore(options: { now: () => number; stateDir?: string; coalesceMs?: number }) {
  const now = options.now;
  const directory = options.stateDir === undefined ? undefined : join(options.stateDir, "mailboxes");
  const mailboxes = new Map<string, Mailbox>();
  const files = new Map<string, DurableJsonFile<Mailbox>>();
  const byListenDigest = new Map<string, string>(); // digest(token) -> address
  const challenges = new Map<string, { address: string; endpoint: string; expiresAtMs: number }>();

  function fileFor(address: string): DurableJsonFile<Mailbox> | undefined {
    if (directory === undefined) return undefined;
    let file = files.get(address);
    if (file === undefined) {
      file = createDurableJsonFile({
        path: join(directory, `${digest("address", address)}.json`),
        schema: SCHEMA,
        maxBytes: MAX_MAILBOX_FILE_BYTES,
        coalesceMs: options.coalesceMs,
        snapshot: () => mailboxes.get(address) as Mailbox,
        validate: (value) => {
          const box = value as Mailbox;
          if (typeof box?.address !== "string" || typeof box.ownerKey !== "string" || typeof box.listenDigest !== "string" || !Array.isArray(box.invitations) || !Array.isArray(box.events)) {
            throw new Error("bad mailbox");
          }
          return box;
        },
      });
      files.set(address, file);
    }
    return file;
  }

  function persist(box: Mailbox, kind: "now" | "soon"): void {
    fileFor(box.address)?.save(kind);
  }

  function forget(address: string): void {
    const box = mailboxes.get(address);
    if (box !== undefined) byListenDigest.delete(box.listenDigest);
    mailboxes.delete(address);
    files.get(address)?.discard();
    files.delete(address);
    if (directory === undefined) return;
    for (const suffix of [".json", ".json.bak"]) {
      try { unlinkSync(join(directory, `${digest("address", address)}${suffix}`)); } catch { /* gone */ }
    }
  }

  if (directory !== undefined && existsSync(directory)) {
    cleanStaleFiles(directory);
    const seen = new Set<string>();
    for (const name of readdirSync(directory)) {
      const match = /^([0-9a-f]{64})\.json(?:\.bak)?$/.exec(name);
      if (match === null || seen.has(match[1])) continue;
      seen.add(match[1]);
      const loader = createDurableJsonFile<Mailbox>({
        path: join(directory, `${match[1]}.json`),
        schema: SCHEMA,
        maxBytes: MAX_MAILBOX_FILE_BYTES,
        snapshot: () => undefined as never,
        validate: (value) => value as Mailbox,
      });
      try {
        const box = loader.load();
        if (box === undefined || digest("address", box.address) !== match[1]) continue;
        mailboxes.set(box.address, box);
        byListenDigest.set(box.listenDigest, box.address);
      } catch (error) {
        // One unreadable mailbox never affects the others; it stays on disk for an operator.
        if (!(error instanceof DurableStateError)) throw error;
        console.error(JSON.stringify({ event: "handshake_state_mailbox_unreadable", file: match[1] }));
      } finally {
        loader.discard();
      }
    }
  }

  function event(box: Mailbox, type: string, fields: Record<string, unknown> = {}): void {
    box.events.push({ at: new Date(now()).toISOString(), type, ...fields });
    if (box.events.length > MAX_MAILBOX_EVENTS) box.events.splice(0, box.events.length - MAX_MAILBOX_EVENTS);
  }

  function isOpen(item: MailboxInvitation, current: number): boolean {
    return (item.status === "pending" || item.status === "reviewed") && current < item.expiresAtMs;
  }

  // Settles one mailbox: idle ones are dropped, expired invitations marked, history trimmed.
  // Returns false when the mailbox is gone.
  function settle(box: Mailbox, current: number): boolean {
    if (current - box.lastActiveAtMs >= MAILBOX_IDLE_TTL_MS) {
      forget(box.address);
      return false;
    }
    let changed = false;
    for (const item of box.invitations) {
      if ((item.status === "pending" || item.status === "reviewed") && current >= item.expiresAtMs) {
        item.status = "expired";
        changed = true;
      }
    }
    const closed = box.invitations.filter((item) => !isOpen(item, current));
    if (closed.length > MAX_MAILBOX_HISTORY) {
      const drop = new Set(closed.slice(0, closed.length - MAX_MAILBOX_HISTORY));
      box.invitations = box.invitations.filter((item) => !drop.has(item));
      changed = true;
    }
    if (changed) persist(box, "soon");
    return true;
  }

  function live(address: string, current: number): Mailbox | undefined {
    const box = mailboxes.get(address);
    return box !== undefined && settle(box, current) ? box : undefined;
  }

  // Full sweeps run on a timer, never on the request path.
  function sweepAll(): void {
    const current = now();
    for (const box of [...mailboxes.values()]) settle(box, current);
    for (const [nonce, challenge] of challenges) if (current >= challenge.expiresAtMs) challenges.delete(nonce);
  }
  const sweeper = setInterval(sweepAll, SWEEP_INTERVAL_MS);
  sweeper.unref();

  return {
    /** A single-use nonce for claiming `address`, bound to the endpoint it was asked on. */
    issueChallenge(address: string, endpoint: string): { nonce: string; expiresAtMs: number } {
      const current = now();
      if (challenges.size >= MAX_CHALLENGES) challenges.delete(challenges.keys().next().value as string);
      const nonce = randomBytes(24).toString("base64url");
      const expiresAtMs = current + CHALLENGE_TTL_MS;
      challenges.set(nonce, { address, endpoint, expiresAtMs });
      return { nonce, expiresAtMs };
    },

    /** Consumes a nonce whatever happens next: a replay, or a second guess, always fails. */
    takeChallenge(nonce: string): { address: string; endpoint: string } | undefined {
      const challenge = challenges.get(nonce);
      challenges.delete(nonce);
      if (challenge === undefined || now() >= challenge.expiresAtMs) return undefined;
      return { address: challenge.address, endpoint: challenge.endpoint };
    },

    /**
     * Checks a claim without changing anything (so a refusal leaves the owner's access as
     * it was): the address is free or already this key's, and the key and client are
     * within their mailbox caps.
     */
    checkClaim(input: { address: string; ownerKey: string; client: string }): void {
      const current = now();
      const existing = live(input.address, current);
      if (existing !== undefined && existing.ownerKey !== input.ownerKey) throw new MailboxRefusal("ADDRESS_TAKEN");
      if (existing !== undefined) return;
      if (mailboxes.size >= MAX_MAILBOXES) throw new MailboxRefusal("MAILBOXES_FULL");
      const clientDigest = digest("client", input.client);
      let byKey = 0;
      let byClient = 0;
      for (const box of mailboxes.values()) {
        if (box.ownerKey === input.ownerKey) byKey += 1;
        if (box.clientDigest === clientDigest) byClient += 1;
      }
      if (byKey >= MAX_MAILBOXES_PER_KEY) throw new MailboxRefusal("TOO_MANY_ADDRESSES_FOR_KEY");
      if (byClient >= MAX_MAILBOXES_PER_CLIENT) throw new MailboxRefusal("TOO_MANY_ADDRESSES_FOR_CLIENT");
    },

    /** Claims (or re-claims, with the same key) a mailbox and rotates its listen token. */
    claim(input: { address: string; ownerKey: string; allow: string[] | null; block: string[]; client: string }): { token: string; mailbox: Mailbox } {
      this.checkClaim(input);
      const current = now();
      const existing = live(input.address, current);
      const token = `slt_${randomBytes(32).toString("base64url")}`;
      const box: Mailbox = existing ?? {
        address: input.address,
        ownerKey: input.ownerKey,
        allow: null,
        block: [],
        listenDigest: "",
        clientDigest: digest("client", input.client),
        claimedAtMs: current,
        lastActiveAtMs: current,
        invitations: [],
        events: [],
      };
      if (box.listenDigest) byListenDigest.delete(box.listenDigest);
      box.listenDigest = digest("listen", token);
      box.allow = input.allow;
      box.block = input.block;
      box.lastActiveAtMs = current;
      byListenDigest.set(box.listenDigest, box.address);
      mailboxes.set(box.address, box);
      event(box, "listening", { reclaimed: existing !== undefined });
      persist(box, "now");
      return { token, mailbox: box };
    },

    /** The live mailbox behind a listen token (keeps it alive), or undefined. */
    authenticate(token: string): Mailbox | undefined {
      const address = byListenDigest.get(digest("listen", token));
      if (address === undefined) return undefined;
      const current = now();
      const box = live(address, current);
      if (box === undefined || box.listenDigest !== digest("listen", token)) return undefined;
      box.lastActiveAtMs = current;
      persist(box, "soon");
      return box;
    },

    /**
     * Puts an invitation in `address`'s mailbox if it is listening, the sender is allowed
     * (and matches a pinned key, if the Initiator gave one) and there is room. The caller
     * learns nothing either way, and neither outcome writes synchronously.
     */
    deliver(input: { address: string; invitationId: string; sessionId: string; initiatorFingerprint: string; expiresAtMs: number; client: string; pinnedKey?: string }): boolean {
      const current = now();
      const box = live(input.address, current);
      if (box === undefined) return false;
      if (input.pinnedKey !== undefined && input.pinnedKey !== box.ownerKey) return false;
      if (box.allow !== null && !box.allow.includes(input.initiatorFingerprint)) return false;
      if (box.block.includes(input.initiatorFingerprint)) return false;
      const sourceDigest = digest("client", input.client);
      const open = box.invitations.filter((item) => isOpen(item, current));
      if (open.length >= MAX_PENDING_PER_MAILBOX) return false;
      if (open.some((item) => item.initiatorFingerprint === input.initiatorFingerprint)) return false;
      if (open.filter((item) => item.sourceDigest === sourceDigest).length >= MAX_PENDING_PER_SOURCE) return false;
      box.invitations.push({
        invitationId: input.invitationId,
        sessionId: input.sessionId,
        initiatorFingerprint: input.initiatorFingerprint,
        sourceDigest,
        deliveredAtMs: current,
        expiresAtMs: Math.min(input.expiresAtMs, current + MAILBOX_INVITATION_TTL_MS),
        status: "pending",
      });
      event(box, "invitation_delivered", { invitationId: input.invitationId, initiatorFingerprint: input.initiatorFingerprint });
      persist(box, "soon");
      return true;
    },

    /** The oldest invitation still awaiting a decision, or undefined. */
    nextOpen(address: string): MailboxInvitation | undefined {
      const current = now();
      return mailboxes.get(address)?.invitations.find((item) => isOpen(item, current));
    },

    openCount(address: string): number {
      const current = now();
      return mailboxes.get(address)?.invitations.filter((item) => isOpen(item, current)).length ?? 0;
    },

    find(address: string, invitationId: string): MailboxInvitation | undefined {
      return mailboxes.get(address)?.invitations.find((item) => item.invitationId === invitationId);
    },

    /** Marks an invitation; decisions (accepted, declined) are written at once. */
    setStatus(address: string, invitationId: string, status: MailboxInvitationStatus): void {
      const box = mailboxes.get(address);
      const item = box?.invitations.find((entry) => entry.invitationId === invitationId);
      if (box === undefined || item === undefined || item.status === status) return;
      item.status = status;
      event(box, status, { invitationId });
      persist(box, status === "accepted" || status === "declined" ? "now" : "soon");
    },

    timeline(address: string): ReadonlyArray<Record<string, unknown>> {
      return [...(mailboxes.get(address)?.events ?? [])];
    },

    size(): number {
      return mailboxes.size;
    },

    close(): void {
      clearInterval(sweeper);
      for (const file of files.values()) file.close();
    },

    discard(): void {
      clearInterval(sweeper);
      for (const file of files.values()) file.discard();
    },
  };
}

export type StandaloneMailboxStore = ReturnType<typeof createMailboxStore>;
