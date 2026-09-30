import assert from "node:assert/strict";
import test from "node:test";

import {
  createStripeTestRail, createSecretsManagerStripeTestKeyResolver,
  stripeTestKeyStatus, StripeTestRailError, STRIPE_TEST_RAIL_ID,
  STRIPE_TEST_SECRET_ID, STRIPE_TEST_SECRET_REGION,
} from "../dist/agent-contract/settlement-rail.js";

// N4b-10 (D13) — the ported Stripe TEST rail, unit-level: recording
// transport + injected resolver only. No network, no Secrets Manager,
// and no key material ever leaves the seams (asserted below).

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

function recordingRail(opts = {}) {
  const key = "key" in opts ? opts.key : "sk_test_4TestOnly";
  const responder = opts.responder;
  const requests = [];
  const auths = [];
  const resolverCalls = { n: 0 };
  const rail = createStripeTestRail({
    resolveSecret: async () => { resolverCalls.n += 1; return key; },
    transport: {
      request: async (request, auth) => {
        requests.push(request);
        auths.push(auth.authorization);
        return { status: 200, body: responder ? await responder(request) : PI() };
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
