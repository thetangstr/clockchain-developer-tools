/**
 * Promote-in-place — bind an ephemeral trial session to an account (LLD §4.1 A6,
 * §6.5, §10.3). Called by the web checkout/billing callback after a successful
 * upgrade: `POST /promote { claim, accountId }`.
 *
 * Idempotent on `claim` (LLD §6.5): replaying the same claim returns the same
 * result and never double-binds. An expired or replayed-invalid claim is a 409
 * `claim_invalid` (LLD §11).
 *
 * STUB BINDING (this PR): the real binding anchor is Network's B2
 * (`bindEphemeralToErc8004`), which does not exist yet. Until then we do a
 * "manual entitlement flip" (demo mode, LLD §12): mark the session promoted,
 * create/flip the account, and record `promotedFrom`/`promotedTo` in state so
 * E1–E4 demo end-to-end. `erc8004Id` stays null until B2 lands.
 */
import type { Plan, Store } from "./store.js";
import { verifyClaim } from "./token.js";
import { hashClaim } from "./session.js";

export interface PromoteInput {
  claim?: unknown;
  accountId?: unknown;
  /**
   * FIX 3: the caller's `plan` is NEVER trusted. A self-serve /promote caller
   * could otherwise self-assign `"enterprise"`. The tier is derived server-side
   * (demo manual flip = "pro"); the real tier will come from billing (CLO-102).
   * The field is accepted on the wire only so it can be explicitly IGNORED.
   */
  plan?: unknown;
}

export interface PromoteOutcome {
  status: number;
  body: Record<string, unknown>;
}

/**
 * FIX 3: server-derived tier for the demo manual flip. Hardcoded "pro" — the
 * real plan will be resolved from the billing record (CLO-102), never from the
 * untrusted request body.
 */
const DERIVED_PLAN: Plan = "pro";

/**
 * Run /promote. Pure over an injected {@link Store} + secret + clock so it is
 * unit-testable without binding a port.
 */
export async function runPromote(
  store: Store,
  promoteSecret: string,
  input: PromoteInput,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<PromoteOutcome> {
  const claim = typeof input.claim === "string" ? input.claim : "";
  const accountId = typeof input.accountId === "string" ? input.accountId.trim() : "";
  if (!claim || !accountId) {
    return {
      status: 400,
      body: {
        error: "bad_request",
        message: "POST /promote requires { claim, accountId }.",
      },
    };
  }

  // Verify + de-replay the claim (LLD §6.5/§11). Expired/forged -> 409.
  const v = verifyClaim(promoteSecret, claim, nowSec);
  if (!v.valid) {
    return {
      status: 409,
      body: { error: "claim_invalid", reason: v.reason },
    };
  }

  const eph = v.payload.eph;

  // FIX 4: replay-safe on the CLAIM itself. Before doing anything, check a
  // consumed-claim marker keyed by hashClaim(claim). This closes the
  // no-session-row replay hole: for the supported "expired trial, claim still
  // valid, no session row" case (LLD §8), idempotency could NOT key on the
  // session (there is none), so the same claim could be replayed to flip an
  // arbitrary attacker-chosen accountId again and again. The marker makes a
  // second promote with the same claim a no-op that returns the FIRST result.
  const claimHash = hashClaim(claim);
  const already = await store.getConsumedClaim(claimHash);
  if (already) {
    const acct = await store.getAccount(already.accountId);
    return {
      status: 200,
      body: {
        boundReceipts: already.boundReceipts,
        identity: acct?.erc8004Id ?? already.accountId,
        accountId: already.accountId,
        idempotent: true,
      },
    };
  }

  const session = await store.getSession(eph);

  // Idempotent on claim (LLD §6.5): an already-promoted session returns the same
  // result for ANY replay of its claim, regardless of the accountId re-sent.
  if (session && session.status === "promoted" && session.promotedTo) {
    const acct = await store.getAccount(session.promotedTo);
    return {
      status: 200,
      body: {
        boundReceipts: session.runsUsed,
        identity: acct?.erc8004Id ?? session.promotedTo,
        accountId: session.promotedTo,
        idempotent: true,
      },
    };
  }

  // --- manual entitlement flip (stub binding; Network B2 TODO) ---
  // FIX 3: tier is derived server-side; input.plan is ignored entirely.
  const plan: Plan = DERIVED_PLAN;
  const existingAcct = await store.getAccount(accountId);
  const promotedFrom = new Set(existingAcct?.promotedFrom ?? []);
  promotedFrom.add(eph);
  await store.putAccount({
    accountId,
    plan,
    // TODO(B2): real ERC-8004 id from bindEphemeralToErc8004(eph, ...).
    erc8004Id: existingAcct?.erc8004Id ?? null,
    channelCeilings: existingAcct?.channelCeilings ?? {
      mcp: null,
      chatbot: null,
      web: null,
    },
    billingRef: existingAcct?.billingRef ?? null,
    promotedFrom: [...promotedFrom],
  });

  let boundReceipts = 0;
  if (session) {
    boundReceipts = session.runsUsed;
    await store.putSession({
      ...session,
      status: "promoted",
      promotedTo: accountId,
    });
  }
  // If there is no session row (e.g. an expired trial whose claim is still
  // valid, LLD §8), the account is still created so the buyer can proceed; prior
  // receipts resolve once B2's resolver follows the binding edge.

  // FIX 4: record the consumed-claim marker so this exact claim can never be
  // promoted again (replay-safe even with no session row). Persisted AFTER the
  // account/session writes so a replay can never observe a half-applied flip.
  await store.putConsumedClaim({
    claimHash,
    accountId,
    boundReceipts,
    consumedAt: nowSec,
  });

  return {
    status: 200,
    body: {
      boundReceipts,
      // TODO(B2): once binding is real, this is the ERC-8004 id; for now the
      // accountId stands in (demo mode).
      identity: existingAcct?.erc8004Id ?? accountId,
      accountId,
    },
  };
}
