import { z } from "zod";

/**
 * N4b-10 (spec D13): the Stripe TEST-MODE settlement rail — pattern ported
 * from the ACM4 rail (`acm4 …/src/lib/settlement/stripe-test-rail.ts`),
 * the same safeguards, no `stripe` npm dependency (two HTTPS calls).
 *
 * Key custody (founder ruling): the restricted test key lives in AWS
 * Secrets Manager as `agentcontract/travel-stripe-test-key` (us-west-2).
 * This module is the SOLE resolver — resolution happens AT CALL TIME,
 * never at boot, never cached, never copied into env, receipts, runs or
 * logs. The resolved key goes into the `Authorization: Bearer` header of
 * the rail's own transport call and nowhere else. Errors carry codes
 * only; absence ("absent", empty, or unresolvable) is one state — the
 * failure mode is never distinguished in output.
 *
 * Ordering is the enforcement: `createPaymentIntent` refuses — before
 * any transport call — unless the request binds `runId`,
 * `agreementDigest` AND `verificationDigest`. There is no code path that
 * constructs a PaymentIntent without a verification digest. The intent
 * is created UNCONFIRMED so the signed settlement envelope can name its
 * id BEFORE `confirmPaymentIntent` releases the test-mode payment
 * (sign-then-release). Every POST carries an `Idempotency-Key`.
 *
 * Both seams are injectable: `transport` (default: fetch to
 * `https://api.stripe.com`) and `resolveSecret` (default: a lazily-
 * imported Secrets Manager client — importing this module and
 * constructing a rail performs no AWS traffic; without the SDK the key
 * resolves `absent`). Tests inject recording doubles for both — no
 * network, no Secrets Manager, no real key.
 *
 * Two hardening invariants on top of the ported rail:
 *  - M1: EVERY request — the default fetch AND any injected transport —
 *    runs under a bounded deadline (`requestTimeoutMs`, default 10s).
 *    A hung Stripe endpoint or a custom transport can never stall
 *    settlement; expiry surfaces as a coded `StripeTestRailError`.
 *  - M2: a parsed 2xx response is NOT trusted — the rail verifies the
 *    intent echoes what was sent (create: amount/currency/the metadata
 *    triple; confirm: the requested id, `succeeded`, and `expected`).
 *    A confused or adversarial upstream is a rail failure, never a
 *    settlement.
 */

export const STRIPE_TEST_RAIL_ID = "stripe_test_mode" as const;
export const STRIPE_API_BASE_URL = "https://api.stripe.com" as const;
export const STRIPE_TEST_SECRET_ID = "agentcontract/travel-stripe-test-key" as const;
export const STRIPE_TEST_SECRET_REGION = "us-west-2" as const;

const paymentIntentIdSchema = z.string().regex(/^pi_[A-Za-z0-9]+$/);

export const STRIPE_TEST_RAIL_ERROR_CODES = [
  "STRIPE_TEST_KEY_ABSENT",
  "STRIPE_TEST_KEY_NOT_TEST_MODE",
  "STRIPE_RAIL_INPUT",
  "STRIPE_RAIL_HTTP",
  "STRIPE_RAIL_BAD_RESPONSE",
  "STRIPE_RAIL_LIVEMODE_REFUSED",
] as const;
export type StripeTestRailErrorCode = (typeof STRIPE_TEST_RAIL_ERROR_CODES)[number];

export class StripeTestRailError extends Error {
  readonly code: StripeTestRailErrorCode;
  constructor(code: StripeTestRailErrorCode, message: string) {
    super(message);
    this.name = "StripeTestRailError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Wire surface — the two PaymentIntents calls the contract server needs.
// ---------------------------------------------------------------------------

export interface CreateStripePaymentIntentInput {
  /** Stripe's atomic amount — a canonical decimal string. */
  readonly amountAtomic: string;
  /** Stripe's lowercase ISO code — `usd` from agreement `USD`. */
  readonly currency: string;
  /**
   * `Idempotency-Key` on every POST: the create key is the
   * `agreementDigest`, the confirm key `${agreementDigest}:confirm` —
   * distinct requests carry distinct keys, so an uncertain response
   * retried by the server replays instead of minting a second effect.
   */
  readonly idempotencyKey: string;
  /** The D13 metadata triple — all three are required. */
  readonly metadata: {
    readonly runId: string;
    readonly agreementDigest: string;
    readonly verificationDigest: string;
  };
}

const digestLike = z.string().regex(/^0x[0-9a-f]{64}$/);
export const createPaymentIntentInputSchema = z.object({
  amountAtomic: z.string().regex(/^(0|[1-9][0-9]*)$/),
  currency: z.string().regex(/^[a-z]{3}$/),
  idempotencyKey: z.string().min(1).max(255),
  metadata: z.object({
    runId: z.string().min(1).max(160),
    agreementDigest: digestLike,
    verificationDigest: digestLike,
  }).strict(),
}).strict();

/** The settlement-facing projection of a Stripe PaymentIntent. */
export interface StripePaymentIntent {
  readonly id: string;
  readonly amount: string;
  readonly currency: string;
  readonly status: string;
  readonly livemode: false;
  readonly metadata: Readonly<Record<string, string>>;
}

/** The raw wire request — the shape an injected transport records. */
export interface StripeRailRequest {
  readonly method: "GET" | "POST";
  /** Path under the API base, e.g. `/v1/payment_intents`. */
  readonly path: string;
  /** `application/x-www-form-urlencoded` fields for POST; absent on GET. */
  readonly form?: Readonly<Record<string, string>>;
  /** Stripe's `Idempotency-Key` header — set on every POST. */
  readonly idempotencyKey?: string;
}

export interface StripeRailResponse {
  readonly status: number;
  readonly body: unknown;
}

/**
 * The transport seam: the adapter resolves the Authorization header value
 * itself (the only place key material moves) and hands the transport the
 * complete request to send.
 */
export interface StripeRailTransport {
  readonly request: (
    request: StripeRailRequest,
    auth: { readonly authorization: string },
  ) => Promise<StripeRailResponse>;
}

export interface SettlementRail {
  readonly railId: typeof STRIPE_TEST_RAIL_ID;
  /**
   * The gate oracle: `absent` → settlement_prepare stops honestly at
   * `awaiting_stripe_test_key`; `refused` → a non-test key resolved —
   * fail closed rather than touch a rail that could move real funds.
   */
  readonly keyStatus: () => Promise<"absent" | "configured" | "refused">;
  /** Create WITHOUT confirming — sign-then-release ordering. */
  readonly createPaymentIntent: (
    input: CreateStripePaymentIntentInput,
  ) => Promise<StripePaymentIntent>;
  /**
   * The release step: confirm a created intent (`pm_card_visa`, test mode).
   * `expected` pins the agreement's terms — when given, a confirmed intent
   * whose amount, currency, or metadata runId/agreementDigest disagree (or
   * whose id is not the requested intent, or whose status is not
   * `succeeded`) is a rail failure, NEVER a settlement.
   */
  readonly confirmPaymentIntent: (input: {
    readonly paymentIntentId: string;
    readonly idempotencyKey: string;
    readonly expected?: {
      readonly amountAtomic: string;
      readonly currency: string;
      readonly runId: string;
      readonly agreementDigest: string;
    };
  }) => Promise<StripePaymentIntent>;
}

// ---------------------------------------------------------------------------
// Key custody — the only code that resolves the test key.
// ---------------------------------------------------------------------------

/**
 * Returns the restricted test key's bytes, or `undefined` when
 * absent/unresolvable. Implementations MUST NOT cache, log, or expose the
 * value — the rail consumes it in-place for the Authorization header and
 * drops it. Throwing is equivalent to `undefined`.
 */
export type StripeTestSecretResolver = () => Promise<string | undefined>;

const isTestModeKey = (key: string): boolean =>
  key.startsWith("sk_test_") || key.startsWith("rk_test_");

const normalizeSecretString = (raw: string | undefined): string | undefined => {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  // The secret payload may be a bare key or a small JSON object carrying
  // it under a conventional field — either way the bytes never leave.
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed === "object" && parsed !== null) {
      const record = parsed as Record<string, unknown>;
      for (const field of ["key", "secretKey", "token"]) {
        const candidate = record[field];
        if (typeof candidate === "string" && candidate.trim().length > 0) {
          return candidate.trim();
        }
      }
    }
  } catch {
    // Not JSON — treat the raw string as the key.
  }
  return trimmed;
};

/**
 * The default resolver: `GetSecretValue` on
 * `agentcontract/travel-stripe-test-key` (us-west-2) — AT CALL TIME, per
 * invocation, never at boot and never cached. The AWS SDK is lazily
 * `import()`ed per call so importing this module — or constructing a
 * rail — performs no AWS traffic; where the SDK is not installed the key
 * resolves `absent`. Any failure resolves to `undefined` (absent); the
 * AWS error never surfaces with its detail. `secrets` is an injectable
 * client seam for tests (a recording stub; no AWS call).
 */
export const createSecretsManagerStripeTestKeyResolver = (input?: {
  readonly secrets?: {
    send(command: unknown): Promise<{ SecretString?: unknown }>;
  };
  readonly secretId?: string;
  readonly region?: string;
}): StripeTestSecretResolver => {
  return async () => {
    try {
      let raw: string | undefined;
      if (input?.secrets !== undefined) {
        const response = await input.secrets.send({
          SecretId: input?.secretId ?? STRIPE_TEST_SECRET_ID,
        });
        raw = typeof response.SecretString === "string" ? response.SecretString : undefined;
      } else {
        // Dynamic specifier — no static dependency; absent SDK → absent key.
        const sdk = await import("@aws-sdk/client-secrets-manager" as string);
        const client = new sdk.SecretsManagerClient({
          region: input?.region ?? STRIPE_TEST_SECRET_REGION,
        });
        const response = await client.send(
          new sdk.GetSecretValueCommand({
            SecretId: input?.secretId ?? STRIPE_TEST_SECRET_ID,
          }),
        );
        raw = typeof response.SecretString === "string" ? response.SecretString : undefined;
      }
      return normalizeSecretString(raw);
    } catch {
      // Sanitized: the absence reason never leaves the resolver.
      return undefined;
    }
  };
};

/** Resolve-then-classify, catching resolver failures as `absent`. */
const resolveKeyStatus = async (
  resolveSecret: StripeTestSecretResolver,
): Promise<{ status: "absent" | "configured" | "refused"; key?: string }> => {
  let key: string | undefined;
  try {
    const resolved = await resolveSecret();
    key = resolved === undefined ? undefined : resolved.trim() || undefined;
  } catch {
    return { status: "absent" };
  }
  if (key === undefined) return { status: "absent" };
  return isTestModeKey(key) ? { status: "configured", key } : { status: "refused" };
};

/**
 * The check-config gate oracle — the same custody outcome the rail sees.
 * Never returns or logs the key itself: status only.
 */
export const stripeTestKeyStatus = async (input?: {
  readonly resolveSecret?: StripeTestSecretResolver;
}): Promise<"absent" | "configured" | "refused"> => {
  const { status } = await resolveKeyStatus(
    input?.resolveSecret ?? createSecretsManagerStripeTestKeyResolver(),
  );
  return status;
};

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/**
 * M1: the per-request deadline covering connect, response headers AND
 * the body read (same shape as the close emitter's attempt deadline).
 * Default 10s, clamped to 100ms–120s so a caller can neither disarm it
 * nor park a request for minutes.
 */
export const STRIPE_RAIL_REQUEST_TIMEOUT_DEFAULT_MS = 10_000;
const clampRequestTimeoutMs = (ms: number | undefined): number => {
  if (ms === undefined || !Number.isFinite(ms)) {
    return STRIPE_RAIL_REQUEST_TIMEOUT_DEFAULT_MS;
  }
  return Math.min(120_000, Math.max(100, Math.floor(ms)));
};

/** The HTTPS transport — `fetch` against `https://api.stripe.com`. */
export const fetchStripeTransport = (input?: {
  readonly baseUrl?: string;
  readonly fetchImpl?: typeof fetch;
  /**
   * M1: fetch-level deadline via `AbortSignal.timeout` — aborts a real
   * fetch that honors it (connect + headers + body). The adapter ALSO
   * races this call against the same deadline, so a fetch impl that
   * ignores the signal is still bounded.
   */
  readonly requestTimeoutMs?: number;
}): StripeRailTransport => {
  const baseUrl = (input?.baseUrl ?? STRIPE_API_BASE_URL).replace(/\/+$/, "");
  const fetchImpl = input?.fetchImpl ?? fetch;
  const requestTimeoutMs = clampRequestTimeoutMs(input?.requestTimeoutMs);
  return {
    request: async (request, auth) => {
      const response = await fetchImpl(`${baseUrl}${request.path}`, {
        method: request.method,
        headers: {
          authorization: auth.authorization,
          ...(request.form === undefined
            ? {}
            : { "content-type": "application/x-www-form-urlencoded" }),
          ...(request.idempotencyKey === undefined
            ? {}
            : { "idempotency-key": request.idempotencyKey }),
        },
        ...(request.form === undefined
          ? {}
          : { body: new URLSearchParams(request.form).toString() }),
        signal: AbortSignal.timeout(requestTimeoutMs),
      });
      const body = (await response.json().catch(() => undefined)) as unknown;
      return { status: response.status, body };
    },
  };
};

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/**
 * Deliberately non-strict projection — the upstream object carries dozens
 * of fields the rail never reads; the fields that matter are asserted.
 */
const paymentIntentResponseSchema = z.object({
  id: paymentIntentIdSchema,
  amount: z.number().int().nonnegative().safe(),
  currency: z.string(),
  status: z.string().min(1),
  livemode: z.boolean(),
  metadata: z.record(z.string(), z.string()).optional(),
});

const toPaymentIntent = (body: unknown): StripePaymentIntent => {
  const parsed = paymentIntentResponseSchema.safeParse(body);
  if (!parsed.success) {
    throw new StripeTestRailError(
      "STRIPE_RAIL_BAD_RESPONSE",
      "payment intent response failed the projected schema",
    );
  }
  // A live-mode object on this rail means the key is not test-mode —
  // refuse before the id can flow into any receipt.
  if (parsed.data.livemode !== false) {
    throw new StripeTestRailError(
      "STRIPE_RAIL_LIVEMODE_REFUSED",
      "payment intent is not test-mode (livemode !== false)",
    );
  }
  return {
    id: parsed.data.id,
    amount: String(parsed.data.amount),
    currency: parsed.data.currency,
    status: parsed.data.status,
    livemode: false,
    metadata: parsed.data.metadata ?? {},
  };
};

const errorMessage = (body: unknown): string | undefined => {
  if (typeof body !== "object" || body === null) return undefined;
  const error = (body as { error?: { message?: unknown } }).error;
  return typeof error?.message === "string" ? error.message : undefined;
};

/**
 * M2: Stripe returns currency lowercase on the wire — compare
 * case-insensitively so `USD`/`usd` agreement casing never false-fails.
 */
const currencyMatches = (wire: string, requested: string): boolean =>
  wire.toLowerCase() === requested.toLowerCase();

/**
 * M2: a parsed 2xx body that does not echo the request is a rail
 * failure — same family as a malformed body, never a settlement.
 */
const echoMismatch = (field: string): StripeTestRailError =>
  new StripeTestRailError(
    "STRIPE_RAIL_BAD_RESPONSE",
    `payment intent response does not echo the request: ${field} mismatch`,
  );

/**
 * The real rail. `resolveSecret` is the ONLY source of key material —
 * resolved at call time, never cached, never exposed. `transport` is
 * injectable so tests record the exact wire requests — including the
 * `authorization` header value — with no network and no real key.
 */
export const createStripeTestRail = (input?: {
  readonly resolveSecret?: StripeTestSecretResolver;
  readonly transport?: StripeRailTransport;
  /**
   * M1: the hard deadline applied to EVERY transport call — including
   * injected transports, which may ignore abort signals entirely.
   * Default 10s, clamped 100ms–120s; expiry throws
   * `StripeTestRailError("STRIPE_RAIL_HTTP", …deadline…)`.
   */
  readonly requestTimeoutMs?: number;
}): SettlementRail => {
  const resolveSecret =
    input?.resolveSecret ?? createSecretsManagerStripeTestKeyResolver();
  const requestTimeoutMs = clampRequestTimeoutMs(input?.requestTimeoutMs);
  const transport =
    input?.transport ?? fetchStripeTransport({ requestTimeoutMs });

  const authorization = async (): Promise<string> => {
    const { status, key } = await resolveKeyStatus(resolveSecret);
    if (status === "absent") {
      throw new StripeTestRailError(
        "STRIPE_TEST_KEY_ABSENT",
        `Stripe test key is unavailable (Secrets Manager ${STRIPE_TEST_SECRET_ID})`,
      );
    }
    if (status !== "configured" || key === undefined) {
      throw new StripeTestRailError(
        "STRIPE_TEST_KEY_NOT_TEST_MODE",
        "the resolved Stripe key is not a test-mode key (expected an sk_test_/rk_test_ prefix)",
      );
    }
    return `Bearer ${key}`;
  };

  const call = async (request: StripeRailRequest): Promise<StripePaymentIntent> => {
    // M1: the transport call — default fetch or injected double — runs
    // under ONE hard deadline (emitter-style). The fetch transport's
    // AbortSignal cancels a real request; this race bounds any
    // transport, so a hung endpoint can never stall settlement. The
    // timer is unref'd and always cleared — it can neither keep the
    // process alive nor fire after the request settled.
    const work = (async () =>
      transport.request(request, { authorization: await authorization() })
    )();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new StripeTestRailError(
            "STRIPE_RAIL_HTTP",
            `stripe rail request deadline ${requestTimeoutMs}ms exceeded`,
          ),
        );
      }, requestTimeoutMs);
      timer.unref?.();
    });
    let response: StripeRailResponse;
    try {
      response = await Promise.race([work, timedOut]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // The losing branch may settle later — swallow it so an abandoned
      // transport call never reports as an unhandled rejection.
      work.catch(() => {});
      timedOut.catch(() => {});
    }
    if (response.status < 200 || response.status >= 300) {
      throw new StripeTestRailError(
        "STRIPE_RAIL_HTTP",
        `stripe rail returned HTTP ${response.status}: ${errorMessage(response.body) ?? "unrecognized error body"}`,
      );
    }
    return toPaymentIntent(response.body);
  };

  return {
    railId: STRIPE_TEST_RAIL_ID,
    keyStatus: () => stripeTestKeyStatus({ resolveSecret }),
    createPaymentIntent: async (raw) => {
      // Enforced HERE, before the transport is touched: a request missing
      // any of the three metadata digests never becomes a wire call.
      const parsed = createPaymentIntentInputSchema.safeParse(raw);
      if (!parsed.success) {
        throw new StripeTestRailError(
          "STRIPE_RAIL_INPUT",
          "createPaymentIntent refuses: amountAtomic/currency/idempotencyKey/metadata{runId,agreementDigest,verificationDigest} are required",
        );
      }
      const { metadata } = parsed.data;
      // Created UNCONFIRMED on purpose: the intent id exists for the
      // signed settlement payload before any charge-like transition; only
      // `confirmPaymentIntent` — after signature + approval — releases
      // the test-mode payment.
      const intent = await call({
        method: "POST",
        path: "/v1/payment_intents",
        idempotencyKey: parsed.data.idempotencyKey,
        form: {
          amount: parsed.data.amountAtomic,
          currency: parsed.data.currency,
          "payment_method_types[0]": "card",
          "metadata[runId]": metadata.runId,
          "metadata[agreementDigest]": metadata.agreementDigest,
          "metadata[verificationDigest]": metadata.verificationDigest,
          "metadata[paymentRail]": STRIPE_TEST_RAIL_ID,
        },
      });
      // M2: the intent that comes back MUST be the intent that was sent.
      // A parsed 2xx whose amount, currency, or metadata digests disagree
      // with the request is a confused/adversarial response — a rail
      // failure, never the basis of a settlement.
      if (intent.amount !== parsed.data.amountAtomic) throw echoMismatch("amount");
      if (!currencyMatches(intent.currency, parsed.data.currency)) throw echoMismatch("currency");
      if (intent.metadata.runId !== metadata.runId) throw echoMismatch("metadata.runId");
      if (intent.metadata.agreementDigest !== metadata.agreementDigest) {
        throw echoMismatch("metadata.agreementDigest");
      }
      if (intent.metadata.verificationDigest !== metadata.verificationDigest) {
        throw echoMismatch("metadata.verificationDigest");
      }
      return intent;
    },
    confirmPaymentIntent: async ({ paymentIntentId, idempotencyKey, expected }) => {
      const id = paymentIntentIdSchema.parse(paymentIntentId);
      const key = z.string().min(1).max(255).parse(idempotencyKey);
      const intent = await call({
        method: "POST",
        path: `/v1/payment_intents/${encodeURIComponent(id)}/confirm`,
        idempotencyKey: key,
        form: { payment_method: "pm_card_visa" },
      });
      // M2: confirm must settle EXACTLY the intent the server asked to
      // release — a different id or any non-`succeeded` status is a
      // failure, NEVER a settlement that happens to resolve.
      if (intent.id !== id) throw echoMismatch("id");
      if (intent.status !== "succeeded") {
        throw new StripeTestRailError(
          "STRIPE_RAIL_BAD_RESPONSE",
          `payment intent ${intent.id} did not succeed (status: ${intent.status})`,
        );
      }
      if (expected !== undefined) {
        // The agreement's pinned terms — a confirmed intent that drifts
        // from them is as unacceptable as a drifted create response.
        if (intent.amount !== expected.amountAtomic) throw echoMismatch("amount");
        if (!currencyMatches(intent.currency, expected.currency)) {
          throw echoMismatch("currency");
        }
        if (intent.metadata.runId !== expected.runId) throw echoMismatch("metadata.runId");
        if (intent.metadata.agreementDigest !== expected.agreementDigest) {
          throw echoMismatch("metadata.agreementDigest");
        }
      }
      return intent;
    },
  };
};
