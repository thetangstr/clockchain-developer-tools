/**
 * Ephemeral trial sessions (LLD §4.1 A1/A2, §5.1, §8).
 *
 * A brand-new caller trials Clockchain anonymously: on the first trial call we
 * lazily mint an ephemeral DID and open an EphemeralSession (no signup, no key).
 * The session is keyed by its ephemeral DID so a claim token — which carries only
 * `eph` (LLD §5.3) — maps straight back to it at /promote time.
 *
 * Channel ceilings (LLD §9.1) are config-driven, not hardcoded, so they can be
 * A/B'd: MCP is generous (API integration is a commitment signal), web is tight
 * (tire-kickers).
 *
 * NOT in this layer (deferred to CLO-101 / A3): run open/close + count-on-complete
 * and ceiling ENFORCEMENT. We resolve the ceiling and expose the counter, but we
 * do not yet block at `runsUsed >= runsCeiling`. See {@link checkCeiling}.
 */
import { randomBytes, createHash } from "node:crypto";
import type { Channel, SessionRecord, Store } from "./store.js";

/** Default channel ceilings (LLD §9.1) when env is unset. */
const DEFAULT_CEILINGS: Record<Channel, number> = {
  mcp: 10,
  chatbot: 5,
  web: 3,
};

const CEILING_ENV: Record<Channel, string> = {
  mcp: "MCP_TRIAL_CEILING_MCP",
  chatbot: "MCP_TRIAL_CEILING_CHATBOT",
  web: "MCP_TRIAL_CEILING_WEB",
};

/** Normalize an untrusted channel string to a known Channel (default "mcp"). */
export function normalizeChannel(raw: string | undefined): Channel {
  return raw === "chatbot" || raw === "web" ? raw : "mcp";
}

/**
 * Resolve the run ceiling for a channel from env (config-driven, LLD §9.1).
 * A non-positive or non-numeric override falls back to the default for that
 * channel rather than disabling the ceiling, so a typo cannot silently grant
 * unlimited trial runs.
 */
export function resolveCeiling(
  channel: Channel,
  env: NodeJS.ProcessEnv = process.env,
): number {
  const raw = env[CEILING_ENV[channel]];
  const n = raw != null && raw.trim() !== "" ? Number(raw) : NaN;
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_CEILINGS[channel];
}

/** Mint a fresh ephemeral DID (LLD §10.2 — lightweight Clockchain-native handle). */
export function newEphemeralDid(): string {
  return `did:clockchain:eph:${randomBytes(8).toString("hex")}`;
}

/** sha256 of a claim token — only the hash is stored on the session (LLD §5.3). */
export function hashClaim(claim: string): string {
  return createHash("sha256").update(claim).digest("hex");
}

/** Claim TTL in seconds (LLD §16: MCP_CLAIM_TTL_DAYS, default 7). */
export function claimTtlSeconds(env: NodeJS.ProcessEnv = process.env): number {
  const days = Number(env.MCP_CLAIM_TTL_DAYS ?? "7");
  const d = Number.isFinite(days) && days > 0 ? days : 7;
  return Math.floor(d * 24 * 60 * 60);
}

/**
 * Lazily get-or-create the ephemeral session for a trial caller (LLD §6.4).
 * Idempotent: the same ephemeral DID always resolves to the same session row;
 * a second call never resets `runsUsed`. The ceiling is resolved at creation
 * from the session's channel.
 */
export async function getOrCreateSession(
  store: Store,
  ephemeralDid: string,
  channel: Channel,
  nowSec: number = Math.floor(Date.now() / 1000),
  ttlSeconds: number = claimTtlSeconds(),
  env: NodeJS.ProcessEnv = process.env,
): Promise<SessionRecord> {
  const existing = await store.getSession(ephemeralDid);
  if (existing) return existing;
  const session: SessionRecord = {
    sessionId: ephemeralDid,
    ephemeralDid,
    channel,
    runsUsed: 0,
    runsCeiling: resolveCeiling(channel, env),
    createdAt: nowSec,
    expiresAt: nowSec + ttlSeconds,
    claimTokenHash: null,
    promotedTo: null,
    status: "active",
  };
  await store.putSession(session);
  return session;
}

/**
 * Ceiling check (LLD §6.3 / §9.2). Returns true when a NEW run may open.
 *
 * SEAM (CLO-101): enforcement is not wired into dispatch yet — this is the pure
 * predicate A3 will call when a run opens. A promoted/authenticated session has
 * `runsCeiling=null` (unlimited) and always passes.
 */
export function checkCeiling(session: SessionRecord): boolean {
  if (session.runsCeiling == null) return true;
  return session.runsUsed < session.runsCeiling;
}
