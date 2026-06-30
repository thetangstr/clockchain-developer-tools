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

export interface PromoteInput {
  claim?: unknown;
  accountId?: unknown;
  /** Optional target plan for the manual flip; defaults to "pro". */
  plan?: unknown;
}

export interface PromoteOutcome {
  status: number;
  body: Record<string, unknown>;
}

const isPlan = (v: unknown): v is Plan =>
  v === "trial" || v === "pro" || v === "enterprise";

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
  const plan: Plan = isPlan(input.plan) ? input.plan : "pro";
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
