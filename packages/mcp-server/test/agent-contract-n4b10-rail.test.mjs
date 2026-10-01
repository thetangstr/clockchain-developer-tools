import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import {
  createStripeTestRail, createSecretsManagerStripeTestKeyResolver,
  fetchStripeTransport,
  stripeTestKeyStatus, StripeTestRailError, STRIPE_TEST_RAIL_ID,
  STRIPE_TEST_SECRET_ID, STRIPE_TEST_SECRET_REGION,
} from "../dist/agent-contract/settlement-rail.js";

// N4b-10 (D13) — the ported Stripe TEST rail, unit-level: recording
// transport + injected resolver only. No network, no Secrets Manager,
// and no key material ever leaves the seams (asserted below).

// Node 20's runner abandons a pending test once the event loop empties, and
// the rail's deadline timer is deliberately unref'd — a never-resolving
// transport leaves only unref'd work. A ref'd keep-alive per test lets the
// deadline actually fire on every Node version.
let keepAlive;
beforeEach(() => { keepAlive = setInterval(() => {}, 60_000); });
afterEach(() => { clearInterval(keepAlive); });

const PI = (over = {}) => ({
  id: "pi_test000000000000001",
  amount: 437000,
  currency: "usd",
  status: "requires_confirmation",
  livemode: false,
  metadata: {},
  ...over,
});
const DIGEST_A = `0x${"a".repeat(64)}`;
const DIGEST_B = `0x${"b".repeat(64)}`;

// A well-behaved Stripe double: the response ECHOES the form fields the
// rail sent — M2 echo-verification only trips on deliberately
// mismatched responders below.
const echoPi = (request, over = {}) => {
  const form = request.form ?? {};
  return PI({
    amount: form.amount === undefined ? 437000 : Number(form.amount),
    currency: form.currency ?? "usd",
    metadata: form["metadata[runId]"] === undefined ? {} : {
      runId: form["metadata[runId]"],
      agreementDigest: form["metadata[agreementDigest]"],
      verificationDigest: form["metadata[verificationDigest]"],
      paymentRail: form["metadata[paymentRail]"],
    },
    ...over,
  });
};

function recordingRail(opts = {}) {
  const key = "key" in opts ? opts.key : "sk_test_4TestOnly";
  const responder = opts.responder;
  const requests = [];
  const auths = [];
  const resolverCalls = { n: 0 };
  const rail = createStripeTestRail({
    resolveSecret: async () => { resolverCalls.n += 1; return key; },
    requestTimeoutMs: opts.requestTimeoutMs,
    transport: {
      request: async (request, auth) => {
        requests.push(request);
        auths.push(auth.authorization);
        return { status: 200, body: responder ? await responder(request) : echoPi(request) };
      },
    },
  });
  return { rail, requests, auths, resolverCalls };
}

test("N4b-10: createPaymentIntent posts an UNCONFIRMED intent bound to the metadata triple", async () => {
  const { rail, requests, auths } = recordingRail();
  const intent = await rail.createPaymentIntent({
    amountAtomic: "437000", currency: "usd",
    idempotencyKey: DIGEST_A,
    metadata: { runId: "run-1", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
  });
  assert.equal(intent.id, "pi_test000000000000001");
  assert.equal(intent.status, "requires_confirmation");
  assert.equal(intent.livemode, false);

  assert.equal(requests.length, 1);
  const req = requests[0];
  assert.equal(req.method, "POST");
  assert.equal(req.path, "/v1/payment_intents");
  assert.equal(req.idempotencyKey, DIGEST_A, "Idempotency-Key = agreementDigest");
  assert.equal(req.form.amount, "437000");
  assert.equal(req.form.currency, "usd");
  assert.equal(req.form["payment_method_types[0]"], "card");
  // No confirm flag — sign-then-release ordering.
  assert.equal(req.form.confirm, undefined);
  assert.equal(req.form["metadata[runId]"], "run-1");
  assert.equal(req.form["metadata[agreementDigest]"], DIGEST_A);
  assert.equal(req.form["metadata[verificationDigest]"], DIGEST_B);
  assert.equal(req.form["metadata[paymentRail]"], STRIPE_TEST_RAIL_ID);
  assert.equal(auths[0], "Bearer sk_test_4TestOnly");
});

test("N4b-10: confirmPaymentIntent posts pm_card_visa with a distinct idempotency key", async () => {
  const { rail, requests } = recordingRail({ responder: async () => PI({ status: "succeeded" }) });
  const intent = await rail.confirmPaymentIntent({
    paymentIntentId: "pi_test000000000000001",
    idempotencyKey: `${DIGEST_A}:confirm`,
  });
  assert.equal(intent.status, "succeeded");
  const req = requests[0];
  assert.equal(req.path, "/v1/payment_intents/pi_test000000000000001/confirm");
  assert.equal(req.idempotencyKey, `${DIGEST_A}:confirm`);
  assert.equal(req.form.payment_method, "pm_card_visa");
});

test("N4b-10: an absent key refuses before any transport call", async () => {
  const { rail, requests } = recordingRail({ key: undefined });
  await assert.rejects(
    rail.createPaymentIntent({
      amountAtomic: "1", currency: "usd", idempotencyKey: "k",
      metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
    }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_TEST_KEY_ABSENT",
  );
  assert.equal(requests.length, 0, "no wire call without a key");
});

test("N4b-10: a non-test key is refused before any transport call", async () => {
  for (const key of ["sk_live_51abc", "rk_live_abc", "whsec_abc"]) {
    const { rail, requests } = recordingRail({ key });
    await assert.rejects(
      rail.createPaymentIntent({
        amountAtomic: "1", currency: "usd", idempotencyKey: "k",
        metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
      }),
      (e) => e instanceof StripeTestRailError && e.code === "STRIPE_TEST_KEY_NOT_TEST_MODE",
    );
    assert.equal(requests.length, 0, `${key.slice(0, 12)}… never reaches the wire`);
  }
});

test("N4b-10: a livemode:true response is refused before the id can flow", async () => {
  const { rail } = recordingRail({ responder: async () => PI({ livemode: true }) });
  await assert.rejects(
    rail.createPaymentIntent({
      amountAtomic: "1", currency: "usd", idempotencyKey: "k",
      metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
    }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_LIVEMODE_REFUSED",
  );
});

test("N4b-10: non-2xx and malformed responses throw code-only errors", async () => {
  const bad = recordingRail({ responder: async () => { throw "nope"; } });
  // responder throwing → propagate as-is (transport fault)
  const http = createStripeTestRail({
    resolveSecret: async () => "sk_test_x",
    transport: { request: async () => ({ status: 402, body: { error: { message: "card declined" } } }) },
  });
  await assert.rejects(
    http.createPaymentIntent({
      amountAtomic: "1", currency: "usd", idempotencyKey: "k",
      metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
    }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_HTTP" && !e.message.includes("sk_test_x"),
  );
  const malformed = createStripeTestRail({
    resolveSecret: async () => "rk_test_x",
    transport: { request: async () => ({ status: 200, body: { hello: "world" } }) },
  });
  await assert.rejects(
    malformed.confirmPaymentIntent({ paymentIntentId: "pi_abc", idempotencyKey: "k" }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
  );
});

test("N4b-10: createPaymentIntent requires the full metadata triple before any wire call", async () => {
  const { rail, requests } = recordingRail();
  await assert.rejects(
    rail.createPaymentIntent({ amountAtomic: "1", currency: "usd", idempotencyKey: "k", metadata: { runId: "r", agreementDigest: DIGEST_A } }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_INPUT",
  );
  assert.equal(requests.length, 0);
});

test("N4b-10: the key resolves at CALL TIME — never cached", async () => {
  const { rail, resolverCalls } = recordingRail();
  const input = {
    amountAtomic: "1", currency: "usd", idempotencyKey: "k",
    metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
  };
  await rail.createPaymentIntent(input);
  await rail.createPaymentIntent(input);
  assert.equal(resolverCalls.n, 2, "resolver invoked per call, not memoized");
});

test("N4b-10: stripeTestKeyStatus reports absent/configured/refused — never the key", async () => {
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => undefined }), "absent");
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => "" }), "absent");
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => { throw new Error("sm down"); } }), "absent");
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => "sk_live_nope" }), "refused");
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => "sk_test_ok" }), "configured");
  assert.equal(await stripeTestKeyStatus({ resolveSecret: async () => "rk_test_ok" }), "configured");
});

test("N4b-10: the Secrets Manager resolver reads the pinned secret id and unwraps JSON payloads", async () => {
  const seen = [];
  const resolver = createSecretsManagerStripeTestKeyResolver({
    secrets: {
      send: async (cmd) => {
        seen.push(cmd);
        return { SecretString: JSON.stringify({ key: "sk_test_fromJson" }) };
      },
    },
  });
  assert.equal(await resolver(), "sk_test_fromJson");
  assert.equal(seen[0].SecretId, STRIPE_TEST_SECRET_ID);
  assert.equal(STRIPE_TEST_SECRET_REGION, "us-west-2");
  // Bare string payloads and failures are handled the same way — absent.
  const bare = createSecretsManagerStripeTestKeyResolver({
    secrets: { send: async () => ({ SecretString: "sk_test_bare" }) },
  });
  assert.equal(await bare(), "sk_test_bare");
  const failing = createSecretsManagerStripeTestKeyResolver({
    secrets: { send: async () => { throw new Error("denied"); } },
  });
  assert.equal(await failing(), undefined);
});

// ---------------------------------------------------------------------------
// M1 — every transport call runs under a bounded deadline.
// ---------------------------------------------------------------------------

test("N4b-10 M1: a never-resolving transport fails at the request deadline — never hangs", async () => {
  // A custom transport that hangs FOREVER and ignores everything — the
  // rail's own deadline race is the only bound on it.
  const rail = createStripeTestRail({
    resolveSecret: async () => "sk_test_x",
    requestTimeoutMs: 25,
    transport: { request: () => new Promise(() => {}) },
  });
  const started = Date.now();
  await assert.rejects(
    rail.createPaymentIntent({
      amountAtomic: "1", currency: "usd", idempotencyKey: "k",
      metadata: { runId: "r", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
    }),
    (e) =>
      e instanceof StripeTestRailError &&
      e.code === "STRIPE_RAIL_HTTP" &&
      /deadline/.test(e.message) &&
      !e.message.includes("sk_test_x"),
  );
  assert.ok(Date.now() - started < 2_000, "bounded at ~requestTimeoutMs, not forever");
});

test("N4b-10 M1: the deadline also bounds confirmPaymentIntent", async () => {
  const rail = createStripeTestRail({
    resolveSecret: async () => "sk_test_x",
    requestTimeoutMs: 25,
    transport: { request: () => new Promise(() => {}) },
  });
  await assert.rejects(
    rail.confirmPaymentIntent({ paymentIntentId: "pi_test000000000000001", idempotencyKey: "k" }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_HTTP",
  );
});

test("N4b-10 M1: fetchStripeTransport passes a firing AbortSignal to fetchImpl", async () => {
  // A fetchImpl that honors the signal like real fetch does — it must
  // observe an AbortSignal and be rejected by it at the deadline.
  const transport = fetchStripeTransport({
    requestTimeoutMs: 25,
    fetchImpl: (url, init) => new Promise((_, reject) => {
      assert.ok(init.signal instanceof AbortSignal, "fetchImpl received an AbortSignal");
      init.signal.addEventListener("abort", () =>
        reject(new DOMException("The operation was aborted", "AbortError")));
    }),
  });
  const started = Date.now();
  await assert.rejects(
    transport.request(
      { method: "GET", path: "/v1/payment_intents/pi_test000000000000001" },
      { authorization: "Bearer sk_test_x" },
    ),
    (e) => e.name === "AbortError",
  );
  assert.ok(Date.now() - started < 2_000, "AbortSignal.timeout fired promptly");
});

// ---------------------------------------------------------------------------
// M2 — a parsed 2xx response must echo what was sent.
// ---------------------------------------------------------------------------

const CREATE_INPUT = {
  amountAtomic: "437000", currency: "usd", idempotencyKey: "k",
  metadata: { runId: "run-9", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
};

test("N4b-10 M2: create refuses a 200 response that does not echo the request", async () => {
  const mismatches = [
    ["amount", { amount: 437001 }],
    ["currency", { currency: "eur" }],
    ["metadata.runId", { metadata: { runId: "run-OTHER", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B } }],
    ["metadata.agreementDigest", { metadata: { runId: "run-9", agreementDigest: DIGEST_B, verificationDigest: DIGEST_B } }],
    ["metadata.verificationDigest", { metadata: { runId: "run-9", agreementDigest: DIGEST_A, verificationDigest: DIGEST_A } }],
  ];
  for (const [field, over] of mismatches) {
    const { rail } = recordingRail({ responder: async (req) => echoPi(req, over) });
    await assert.rejects(
      rail.createPaymentIntent(CREATE_INPUT),
      (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
      `${field} mismatch is a rail failure`,
    );
  }
});

test("N4b-10 M2: create accepts a faithfully echoed response", async () => {
  const { rail } = recordingRail();
  const intent = await rail.createPaymentIntent(CREATE_INPUT);
  assert.equal(intent.amount, "437000");
  assert.equal(intent.currency, "usd");
  assert.equal(intent.metadata.runId, "run-9");
  assert.equal(intent.metadata.agreementDigest, DIGEST_A);
  assert.equal(intent.metadata.verificationDigest, DIGEST_B);
});

test("N4b-10 M2: confirm refuses a response for a DIFFERENT intent id", async () => {
  const { rail } = recordingRail({
    responder: async () => PI({ id: "pi_evil00000000000000", status: "succeeded" }),
  });
  await assert.rejects(
    rail.confirmPaymentIntent({ paymentIntentId: "pi_test000000000000001", idempotencyKey: "k" }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
  );
});

test("N4b-10 M2: confirm never resolves a non-succeeded status", async () => {
  for (const status of ["requires_payment_method", "requires_action", "requires_confirmation", "processing", "canceled"]) {
    const { rail } = recordingRail({ responder: async () => PI({ status }) });
    await assert.rejects(
      rail.confirmPaymentIntent({ paymentIntentId: "pi_test000000000000001", idempotencyKey: "k" }),
      (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
      `status ${status} is a failure, not a settlement`,
    );
  }
});

test("N4b-10 M2: confirm verifies expected{} when provided, and succeeds when all match", async () => {
  const expected = {
    amountAtomic: "437000", currency: "usd",
    runId: "run-9", agreementDigest: DIGEST_A,
  };
  const mismatches = [
    ["amount", { amount: 1 }],
    ["currency", { currency: "eur" }],
    ["metadata.runId", { metadata: { runId: "run-X", agreementDigest: DIGEST_A } }],
    ["metadata.agreementDigest", { metadata: { runId: "run-9", agreementDigest: DIGEST_B } }],
  ];
  for (const [field, over] of mismatches) {
    const { rail } = recordingRail({
      responder: async () => PI({ status: "succeeded", ...over }),
    });
    await assert.rejects(
      rail.confirmPaymentIntent({
        paymentIntentId: "pi_test000000000000001", idempotencyKey: "k", expected,
      }),
      (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
      `expected ${field} mismatch is a rail failure`,
    );
  }
  // All-good + expected → resolves the confirmed intent.
  const { rail } = recordingRail({
    responder: async () => PI({
      status: "succeeded",
      metadata: { runId: "run-9", agreementDigest: DIGEST_A, verificationDigest: DIGEST_B },
    }),
  });
  const intent = await rail.confirmPaymentIntent({
    paymentIntentId: "pi_test000000000000001", idempotencyKey: "k", expected,
  });
  assert.equal(intent.id, "pi_test000000000000001");
  assert.equal(intent.status, "succeeded");
});

// ---------------------------------------------------------------------------
// N4b-11 (LOW) — retrievePaymentIntent: the READ-ONLY reconcile lookup.
// A confirm that timed out may have succeeded upstream; retrieve GETs the
// intent for post-timeout truth — status is REPORTED, never asserted.
// ---------------------------------------------------------------------------

test("N4b-11 LOW: retrievePaymentIntent issues a bare GET and reports upstream status", async () => {
  const { rail, requests, auths } = recordingRail({
    responder: async () => PI({ status: "requires_confirmation" }),
  });
  const intent = await rail.retrievePaymentIntent({
    paymentIntentId: "pi_test000000000000001",
  });
  // Whatever status upstream reports is returned — NOT refused like confirm.
  assert.equal(intent.id, "pi_test000000000000001");
  assert.equal(intent.status, "requires_confirmation");
  assert.equal(intent.livemode, false);

  assert.equal(requests.length, 1);
  const req = requests[0];
  assert.equal(req.method, "GET");
  assert.equal(req.path, "/v1/payment_intents/pi_test000000000000001");
  assert.equal(req.form, undefined, "GET carries no form body");
  assert.equal(req.idempotencyKey, undefined, "GET carries no Idempotency-Key");
  assert.equal(auths[0], "Bearer sk_test_4TestOnly");
});

test("N4b-11 LOW: retrievePaymentIntent verifies id and expected{} echoes", async () => {
  const expected = {
    amountAtomic: "437000", currency: "usd",
    runId: "run-9", agreementDigest: DIGEST_A,
  };
  const mismatches = [
    ["id", { id: "pi_evil00000000000000" }],
    ["amount", { amount: 1 }],
    ["currency", { currency: "eur" }],
    ["metadata.runId", { metadata: { runId: "run-X", agreementDigest: DIGEST_A } }],
    ["metadata.agreementDigest", { metadata: { runId: "run-9", agreementDigest: DIGEST_B } }],
  ];
  for (const [field, over] of mismatches) {
    const { rail } = recordingRail({ responder: async () => PI(over) });
    await assert.rejects(
      rail.retrievePaymentIntent({
        paymentIntentId: "pi_test000000000000001", expected,
      }),
      (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_BAD_RESPONSE",
      `expected ${field} mismatch is a rail failure`,
    );
  }
  // All-match + expected → resolves the retrieved intent, status reported.
  const { rail } = recordingRail({
    responder: async () => PI({
      status: "processing",
      metadata: { runId: "run-9", agreementDigest: DIGEST_A },
    }),
  });
  const intent = await rail.retrievePaymentIntent({
    paymentIntentId: "pi_test000000000000001", expected,
  });
  assert.equal(intent.id, "pi_test000000000000001");
  assert.equal(intent.status, "processing");
});

test("N4b-11 LOW: a malformed paymentIntentId throws before any transport call", async () => {
  const { rail, requests } = recordingRail();
  await assert.rejects(
    rail.retrievePaymentIntent({ paymentIntentId: "not-a-pi" }),
  );
  assert.equal(requests.length, 0, "no wire call for a malformed id");
});

test("N4b-11 LOW: the deadline bounds retrievePaymentIntent like every call", async () => {
  const rail = createStripeTestRail({
    resolveSecret: async () => "sk_test_x",
    requestTimeoutMs: 25,
    transport: { request: () => new Promise(() => {}) },
  });
  const started = Date.now();
  await assert.rejects(
    rail.retrievePaymentIntent({ paymentIntentId: "pi_test000000000000001" }),
    (e) =>
      e instanceof StripeTestRailError &&
      e.code === "STRIPE_RAIL_HTTP" &&
      /deadline/.test(e.message) &&
      !e.message.includes("sk_test_x"),
  );
  assert.ok(Date.now() - started < 2_000, "bounded at ~requestTimeoutMs, not forever");
});

test("N4b-11 LOW: a livemode:true retrieve response is refused like every call", async () => {
  const { rail } = recordingRail({ responder: async () => PI({ livemode: true }) });
  await assert.rejects(
    rail.retrievePaymentIntent({ paymentIntentId: "pi_test000000000000001" }),
    (e) => e instanceof StripeTestRailError && e.code === "STRIPE_RAIL_LIVEMODE_REFUSED",
  );
});
