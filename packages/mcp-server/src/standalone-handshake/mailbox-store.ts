// Mailboxes for handshake addresses (spec B4). A mailbox is claimed by the key whose
// fingerprint is in its address; invitations sent `to` it wait there for its listener.
//
// Durability (B2 patterns): mailboxes, their pending invitations and their timeline persist
// in one durable file; listen tokens are stored as digests only; challenge nonces are
// ephemeral (a restart simply means asking for a new one).
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";

import { createDurableJsonFile, type DurableJsonFile } from "../handshake-core/durable-store.js";

export const CHALLENGE_TTL_MS = 2 * 60_000;
export const MAILBOX_IDLE_TTL_MS = 24 * 60 * 60_000;
export const MAILBOX_INVITATION_TTL_MS = 60 * 60_000;
export const MAX_PENDING_PER_MAILBOX = 10;
export const MAX_MAILBOXES = 10_000;
export const MAX_CHALLENGES = 10_000;
export const MAX_MAILBOX_EVENTS = 100;
const SCHEMA = "clockchain.standalone-handshake-mailboxes/v1";

export type MailboxInvitationStatus = "pending" | "reviewed" | "accepted" | "declined" | "expired";

export interface MailboxInvitation {
  invitationId: string;
  sessionId: string;
  initiatorFingerprint: string;
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
  claimedAtMs: number;
  lastActiveAtMs: number;
  invitations: MailboxInvitation[];
  events: Array<Record<string, unknown>>;
}

function digest(value: string): string {
  return createHash("sha256").update(`listen\u0000${value}`, "utf8").digest("hex");
}

export function createMailboxStore(options: { now: () => number; stateDir?: string; coalesceMs?: number }) {
  const now = options.now;
  const mailboxes = new Map<string, Mailbox>();
  const byListenDigest = new Map<string, string>(); // digest(token) -> address
  const challenges = new Map<string, { address: string; endpoint: string; expiresAtMs: number }>();

  const file: DurableJsonFile<Mailbox[]> | undefined = options.stateDir === undefined ? undefined : createDurableJsonFile({
    path: join(options.stateDir, "mailboxes.json"),
    schema: SCHEMA,
    maxBytes: 64 * 1024 * 1024,
    coalesceMs: options.coalesceMs,
    snapshot: () => [...mailboxes.values()],
    validate: (value) => {
      if (!Array.isArray(value)) throw new Error("mailboxes must be an array");
      for (const box of value) {
        if (typeof box?.address !== "string" || typeof box.ownerKey !== "string" || typeof box.listenDigest !== "string" || !Array.isArray(box.invitations)) {
          throw new Error("bad mailbox");
        }
      }
      return value as Mailbox[];
    },
  });
  for (const box of file?.load() ?? []) {
    mailboxes.set(box.address, box);
    byListenDigest.set(box.listenDigest, box.address);
  }

  function persist(kind: "now" | "soon" = "now"): void {
    file?.save(kind);
  }

  function event(box: Mailbox, type: string, fields: Record<string, unknown> = {}): void {
    box.events.push({ at: new Date(now()).toISOString(), type, ...fields });
    if (box.events.length > MAX_MAILBOX_EVENTS) box.events.splice(0, box.events.length - MAX_MAILBOX_EVENTS);
  }

  // Drops idle mailboxes and settles expired invitations; true when anything changed.
  function sweep(current: number): boolean {
    let changed = false;
    for (const [address, box] of mailboxes) {
      if (current - box.lastActiveAtMs >= MAILBOX_IDLE_TTL_MS) {
        mailboxes.delete(address);
        byListenDigest.delete(box.listenDigest);
        changed = true;
        continue;
      }
      const before = box.invitations.length;
      box.invitations = box.invitations.filter((item) => item.status === "accepted" || item.status === "declined" ? current - item.deliveredAtMs < MAILBOX_INVITATION_TTL_MS : current < item.expiresAtMs);
      if (box.invitations.length !== before) changed = true;
    }
    for (const [nonce, challenge] of challenges) if (current >= challenge.expiresAtMs) challenges.delete(nonce);
    return changed;
  }

  function live(address: string, current: number): Mailbox | undefined {
    const box = mailboxes.get(address);
    return box !== undefined && current - box.lastActiveAtMs < MAILBOX_IDLE_TTL_MS ? box : undefined;
  }

  return {
    /** A single-use nonce for claiming `address`, bound to the endpoint it was asked on. */
    issueChallenge(address: string, endpoint: string): { nonce: string; expiresAtMs: number } {
      const current = now();
      sweep(current);
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

    /** Claims (or re-claims, with the same key) a mailbox and returns a fresh listen token. */
    claim(input: { address: string; ownerKey: string; allow: string[] | null; block: string[] }): { token: string; mailbox: Mailbox } {
      const current = now();
      if (sweep(current)) persist("soon");
      const existing = live(input.address, current);
      if (existing !== undefined && existing.ownerKey !== input.ownerKey) throw new Error("ADDRESS_TAKEN");
      if (existing === undefined && mailboxes.size >= MAX_MAILBOXES) throw new Error("MAILBOXES_FULL");
      const token = `slt_${randomBytes(32).toString("base64url")}`;
      const box: Mailbox = existing ?? {
        address: input.address,
        ownerKey: input.ownerKey,
        allow: null,
        block: [],
        listenDigest: "",
        claimedAtMs: current,
        lastActiveAtMs: current,
        invitations: [],
        events: [],
      };
      if (box.listenDigest) byListenDigest.delete(box.listenDigest);
      box.listenDigest = digest(token);
      box.allow = input.allow;
      box.block = input.block;
      box.lastActiveAtMs = current;
      byListenDigest.set(box.listenDigest, box.address);
      mailboxes.set(box.address, box);
      event(box, "listening", { reclaimed: existing !== undefined });
      persist("now");
      return { token, mailbox: box };
    },

    /** The live mailbox behind a listen token (keeps it alive), or undefined. */
    authenticate(token: string): Mailbox | undefined {
      const address = byListenDigest.get(digest(token));
      if (address === undefined) return undefined;
      const current = now();
      const box = live(address, current);
      if (box === undefined || box.listenDigest !== digest(token)) return undefined;
      box.lastActiveAtMs = current;
      if (sweep(current)) persist("now");
      else persist("soon");
      return box;
    },

    /**
     * Puts an invitation in `address`'s mailbox if it is listening and the sender is allowed.
     * The caller learns nothing either way: false covers absent, idle, blocked, full and
     * duplicate alike, and the Initiator's response is the same in every case.
     */
    deliver(input: { address: string; invitationId: string; sessionId: string; initiatorFingerprint: string; expiresAtMs: number }): boolean {
      const current = now();
      sweep(current);
      const box = live(input.address, current);
      if (box === undefined) return false;
      if (box.allow !== null && !box.allow.includes(input.initiatorFingerprint)) return false;
      if (box.block.includes(input.initiatorFingerprint)) return false;
      const open = box.invitations.filter((item) => item.status === "pending" || item.status === "reviewed");
      if (open.length >= MAX_PENDING_PER_MAILBOX) return false;
      if (open.some((item) => item.initiatorFingerprint === input.initiatorFingerprint)) return false;
      box.invitations.push({
        invitationId: input.invitationId,
        sessionId: input.sessionId,
        initiatorFingerprint: input.initiatorFingerprint,
        deliveredAtMs: current,
        expiresAtMs: Math.min(input.expiresAtMs, current + MAILBOX_INVITATION_TTL_MS),
        status: "pending",
      });
      event(box, "invitation_delivered", { invitationId: input.invitationId, initiatorFingerprint: input.initiatorFingerprint });
      persist("now");
      return true;
    },

    /** The oldest invitation still awaiting a decision, or undefined. */
    nextOpen(address: string): MailboxInvitation | undefined {
      const current = now();
      const box = mailboxes.get(address);
      return box?.invitations.find((item) => (item.status === "pending" || item.status === "reviewed") && current < item.expiresAtMs);
    },

    openCount(address: string): number {
      const current = now();
      return mailboxes.get(address)?.invitations.filter((item) => (item.status === "pending" || item.status === "reviewed") && current < item.expiresAtMs).length ?? 0;
    },

    find(address: string, invitationId: string): MailboxInvitation | undefined {
      return mailboxes.get(address)?.invitations.find((item) => item.invitationId === invitationId);
    },

    setStatus(address: string, invitationId: string, status: MailboxInvitationStatus): void {
      const box = mailboxes.get(address);
      const item = box?.invitations.find((entry) => entry.invitationId === invitationId);
      if (box === undefined || item === undefined || item.status === status) return;
      item.status = status;
      event(box, status, { invitationId });
      persist("now");
    },

    timeline(address: string): ReadonlyArray<Record<string, unknown>> {
      return [...(mailboxes.get(address)?.events ?? [])];
    },

    close(): void {
      file?.close();
    },

    discard(): void {
      file?.discard();
    },
  };
}

export type StandaloneMailboxStore = ReturnType<typeof createMailboxStore>;
