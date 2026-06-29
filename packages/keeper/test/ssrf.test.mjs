// SSRF guard for webhook targets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertSafeWebhookUrl, isBlockedHost, SsrfError, ssrfOptionsFromEnv } from "../dist/index.js";

test("allows a normal https URL", () => {
  const url = assertSafeWebhookUrl("https://hooks.example.com/x");
  assert.equal(url.hostname, "hooks.example.com");
});

test("rejects non-http(s) schemes", () => {
  assert.throws(() => assertSafeWebhookUrl("ftp://example.com"), SsrfError);
  assert.throws(() => assertSafeWebhookUrl("file:///etc/passwd"), SsrfError);
});

test("blocks loopback / private / metadata literals", () => {
  for (const h of ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "0.0.0.0"]) {
    assert.throws(() => assertSafeWebhookUrl(`http://${h}/x`), SsrfError, `should block ${h}`);
    assert.ok(isBlockedHost(h), `isBlockedHost(${h})`);
  }
  assert.throws(() => assertSafeWebhookUrl("http://localhost:9000/x"), SsrfError);
  assert.throws(() => assertSafeWebhookUrl("http://metadata.google.internal/x"), SsrfError);
});

test("allows public IPs and hostnames", () => {
  assert.ok(!isBlockedHost("8.8.8.8"));
  assert.ok(!isBlockedHost("example.com"));
  assert.doesNotThrow(() => assertSafeWebhookUrl("https://93.184.216.34/x"));
});

test("allowLoopback opt-in permits 127.0.0.1 (local dev / tests)", () => {
  assert.doesNotThrow(() => assertSafeWebhookUrl("http://127.0.0.1:8080/x", { allowLoopback: true }));
});

test("allowlist is deny-by-default when set", () => {
  const opts = { allowlist: ["example.com"] };
  assert.doesNotThrow(() => assertSafeWebhookUrl("https://api.example.com/x", opts));
  assert.doesNotThrow(() => assertSafeWebhookUrl("https://example.com/x", opts));
  assert.throws(() => assertSafeWebhookUrl("https://evil.test/x", opts), SsrfError);
});

test("ssrfOptionsFromEnv parses allowlist + loopback flag", () => {
  const o = ssrfOptionsFromEnv({ KEEPER_WEBHOOK_ALLOWLIST: "a.com, b.com", KEEPER_ALLOW_LOOPBACK: "1" });
  assert.deepEqual(o.allowlist, ["a.com", "b.com"]);
  assert.equal(o.allowLoopback, true);
});
