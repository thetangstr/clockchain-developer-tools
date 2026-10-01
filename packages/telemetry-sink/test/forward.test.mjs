import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  createForwarder,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  sealToken,
} from "../dist/index.js";

const services = generateKeyPairSync("x25519");
const servicesPubHex =
  "0x" + Buffer.from(services.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex");
const servicesPrivJwk = services.privateKey.export({ format: "jwk" });

const BODY = '{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"claude_code.mcp.rpc"}]}]}]}';

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

test("forwarder relays the request body byte-for-byte and attaches the token", async () => {
  const tokens = createTokenStore();
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: generateKeyPairSync("ed25519").privateKey },
    tokens,
  });
  const sinkServer = createTelemetrySinkServer({ sink, tokens });
  const sinkUrl = await listen(sinkServer.write);

  const minted = tokens.mintIngest({ runId: "run-f1", role: "buyer" });
  const sealed = sealToken(servicesPubHex, minted.token, { runId: "run-f1", role: "buyer" });

  const forwarder = createForwarder({
    listen: { host: "127.0.0.1", port: 0 },
    targetBaseUrl: sinkUrl,
    sealedToken: sealed,
    servicesPrivateKeyJwk: servicesPrivJwk,
    runId: "run-f1",
    role: "buyer",
  });
  const fwdUrl = await listen(forwarder);

  // The agent's exporter sends NO token — the forwarder attaches it.
  const res = await fetch(`${fwdUrl}/v1/traces`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: BODY,
  });
  assert.equal(res.status, 200);

  // The sink recorded the EXACT bytes the forwarder received.
  const record = sink.recordsFor("run-f1")[0];
  assert.equal(record.bodyDigest, "0x" + createHash("sha256").update(BODY, "utf8").digest("hex"));
  assert.equal(record.bodyBytes, Buffer.byteLength(BODY));

  forwarder.close();
  sinkServer.write.close();
  sinkServer.read.close();
  sinkServer.close.close();
});

test("forwarder refuses non-loopback binds", async () => {
  const sealed = sealToken(servicesPubHex, "otlp-ing-" + "1".repeat(32), { runId: "run-x", role: "buyer" });
  for (const host of ["0.0.0.0", "192.168.1.10", "example.internal", "localhost"]) {
    assert.throws(
      () =>
        createForwarder({
          listen: { host, port: 0 },
          targetBaseUrl: "http://127.0.0.1:1",
          sealedToken: sealed,
          servicesPrivateKeyJwk: servicesPrivJwk,
          runId: "run-x",
          role: "buyer",
        }),
      /loopback/i,
    );
  }
});

test("forwarder refuses to start on a token it cannot unseal", async () => {
  const otherKeys = generateKeyPairSync("x25519");
  const sealedToOther = sealToken(
    "0x" + Buffer.from(otherKeys.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex"),
    "otlp-ing-" + "2".repeat(32),
    { runId: "run-x", role: "buyer" },
  );
  assert.throws(
    () =>
      createForwarder({
        listen: { host: "127.0.0.1", port: 0 },
        targetBaseUrl: "http://127.0.0.1:1",
        sealedToken: sealedToOther,
        servicesPrivateKeyJwk: servicesPrivJwk,
        runId: "run-x",
        role: "buyer",
      }),
  );
});

test("bin/ac-otlp-forward exists and is executable-shaped", async () => {
  const binPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)), "..", "bin", "ac-otlp-forward",
  );
  const require = createRequire(import.meta.url);
  const src = require("node:fs").readFileSync(binPath, "utf8");
  assert.match(src, /^#!\/usr\/bin\/env node/);
  assert.ok(src.includes("127.0.0.1"), "bin must pin the loopback default");
});
