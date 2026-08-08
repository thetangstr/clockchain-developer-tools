import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { runParity } from "../../../scripts/parity-check.mjs";

const KNOWN_HEIGHT = "42";
const REFERENCE = "parity:test:ref";
const ACTION = "parity harmless action";
const SECRET_TOKEN = "cc_mock.secret.signature";
const CONSENSUS_TIME = "11-06-2026_14:41:29:089";
const BLOCK_TIME = "2026-06-11T14:41:29.089Z";
const LOG_CREATED = "11-06-2026 14:41:29:089 UTC";
const LOG_UPDATED = "2026-06-11T14:41:30.089Z";

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

function jsonRpc(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function sseFrame(payload, newline = "\n") {
  return `event: message${newline}data: ${JSON.stringify(payload)}${newline}${newline}`;
}

async function readJson(req) {
  let body = "";
  for await (const chunk of req) body += chunk;
  return body ? JSON.parse(body) : {};
}

async function startParityServer(name, opts = {}) {
  const ledger = opts.ledger ?? new Map();
  const calls = [];
  let mintCount = 0;
  const server = createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        if (opts.slowHealth) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(
          opts.hugeHealth
            ? { status: "ok", blob: "x".repeat(2048) }
            : { status: "ok", service: "clockchain-mcp" },
        ));
        return;
      }
      if (req.method === "POST" && req.url === "/token") {
        mintCount++;
        const remaining = (opts.quotaStart ?? 10) - mintCount * (opts.quotaStep ?? 1);
        const headers = {
          "content-type": "application/json",
          ...(!opts.omitRateLimitLimit ? { "x-ratelimit-limit": opts.rateLimitLimit ?? "10" } : {}),
          ...(!opts.omitRateLimitRemaining ? { "x-ratelimit-remaining": opts.rateLimitRemaining ?? String(remaining) } : {}),
          ...(!opts.omitRateLimitReset ? { "x-ratelimit-reset": "4070908800" } : {}),
        };
        res.writeHead(200, headers);
        res.end(JSON.stringify({
          token: `${SECRET_TOKEN}.${name}.${mintCount}`,
          tier: "demo",
          expires_at: "2099-01-01T00:00:00.000Z",
          endpoint: `http://127.0.0.1/${name}/mcp`,
          usage: "redacted by script",
        }));
        return;
      }
      if (req.method === "POST" && req.url === "/mcp") {
        const msg = await readJson(req);
        const tool = msg.params?.name;
        calls.push({ authorization: req.headers.authorization, apiKey: req.headers["x-api-key"], tool });
        const args = msg.params?.arguments ?? {};
        const resultForTool = () => {
          if (tool === "get_timestamp") {
            return {
              content: [{ type: "text", text: JSON.stringify(opts.timestamp ?? {
                madMarzulloTime: CONSENSUS_TIME,
                blockHeight: name === "aws" ? "1002" : "1001",
                votes: [{ node: name, offsetMs: 1 }],
              }) }],
            };
          }
          if (tool === "get_block") {
            const block = opts.block ?? {
              height: String(args.height),
              blockHeight: String(args.height),
              proposerAddress: "0xvalidator",
              blockTime: BLOCK_TIME,
              transactions: [],
            };
            return { content: [{ type: "text", text: JSON.stringify(block) }] };
          }
          if (tool === "log_action") {
            const ledgerId = `${name}-ledger-${args.asset_reference_id}`;
            const entry = {
              ledgerId,
              clientId: "parity-client",
              walletId: "parity-wallet",
              assetReferenceId: args.asset_reference_id,
              assetHash: args.asset_hash ?? sha256(args.content ?? ""),
              hashType: "SHA-256",
              versionNumber: 1,
              blockHeight: "900",
              status: "anchored",
              createdTimestamp: LOG_CREATED,
              updatedTimestamp: LOG_UPDATED,
              assetName: null,
              type: null,
              additionalInfo: args.additional_info ?? "",
              ...(opts.logOverrides ?? {}),
              ...(opts.extraLogField ? { extra: true } : {}),
            };
            if (opts.omitLogField) delete entry[opts.omitLogField];
            ledger.set(ledgerId, entry);
            return { content: [{ type: "text", text: JSON.stringify(entry) }] };
          }
          if (tool === "get_log_entry") {
            const entry = ledger.get(args.ledger_id);
            if (!entry || opts.crossReadMissing) {
              return { isError: true, content: [{ type: "text", text: "not found" }] };
            }
            return { content: [{ type: "text", text: JSON.stringify(entry) }] };
          }
          return { isError: true, content: [{ type: "text", text: `unknown tool ${tool}` }] };
        };
        const payload = jsonRpc(msg.id, resultForTool());
        if (opts.sse) {
          res.writeHead(200, { "content-type": "text/event-stream" });
          const notification = {
            jsonrpc: "2.0",
            method: "notifications/progress",
            params: { progress: 1 },
          };
          res.end(
            opts.sseNotificationBeforeResponse
              ? `${sseFrame(notification, "\r\n")}${sseFrame(payload, "\r\n")}`
              : sseFrame(payload),
          );
        } else {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(payload));
        }
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    calls,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function withServers(gcpOpts, awsOpts, fn) {
  const ledger = new Map();
  const gcp = await startParityServer("gcp", { ledger, ...gcpOpts });
  const aws = await startParityServer("aws", { ledger, ...awsOpts });
  try {
    return await fn({ gcp, aws });
  } finally {
    await aws.close();
    await gcp.close();
  }
}

async function runAgainst(gcp, aws, opts = {}) {
  const lines = [];
  const errors = [];
  const result = await runParity({
    gcpBaseUrl: gcp.baseUrl,
    awsBaseUrl: aws.baseUrl,
    blockHeight: KNOWN_HEIGHT,
    reference: REFERENCE,
    action: ACTION,
    timeoutMs: opts.timeoutMs ?? 1000,
    maxBytes: opts.maxBytes ?? 100_000,
    stdout: { write: (s) => lines.push(s) },
    stderr: { write: (s) => errors.push(s) },
  });
  return { result, output: lines.join(""), errors: errors.join("") };
}

test("passes green parity with direct JSON and SSE MCP responses", async () => {
  await withServers({ quotaStart: 7 }, { quotaStart: 10, sse: true }, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, true);
    assert.match(output, /health\s+PASS/);
    assert.match(output, /token mint 1\s+PASS/);
    assert.match(output, /token mint 2\s+PASS/);
    assert.match(output, /get_timestamp\s+PASS/);
    assert.match(output, /get_block\s+PASS/);
    assert.match(output, /log_action aws->gcp\s+PASS/);
    assert.doesNotMatch(output, new RegExp(SECRET_TOKEN));
    assert.doesNotMatch(output, /authorization|bearer|x-api-key/i);
    assert.doesNotMatch(output, new RegExp(ACTION));
  });
});

test("SSE parsing handles CRLF notification frames before the matching JSON-RPC response", async () => {
  await withServers({}, { sse: true, sseNotificationBeforeResponse: true }, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, true);
    assert.match(output, /get_timestamp\s+PASS/);
    assert.match(output, /log_action aws->gcp\s+PASS/);
  });
});

test("fails on response shape mismatch", async () => {
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "later", blockHeight: "1002", extra: true } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_timestamp\s+FAIL/);
    },
  );
});

test("fails when AWS log entry is not readable through GCP", async () => {
  await withServers({ crossReadMissing: true }, {}, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, false);
    assert.match(output, /log_action aws->gcp\s+FAIL/);
  });
});

test("fails when token quota movement differs on the second mint", async () => {
  await withServers({ quotaStart: 10, quotaStep: 1 }, { quotaStart: 9, quotaStep: 2 }, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, false);
    assert.match(output, /token mint 1\s+PASS/);
    assert.match(output, /token mint 2\s+FAIL/);
  });
});

test("fails when token rate-limit headers are missing or non-numeric", async () => {
  await withServers({ omitRateLimitRemaining: true }, {}, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, false);
    assert.match(output, /token mint 1\s+FAIL/);
  });
  await withServers({ rateLimitLimit: "ten" }, {}, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, false);
    assert.match(output, /token mint 1\s+FAIL/);
  });
});

test("fails invalid get_timestamp semantics", async () => {
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "", blockHeight: "-1", votes: [{ node: "aws", offsetMs: 1 }] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_timestamp\s+FAIL/);
    },
  );
});

test("fails invalid normalized timestamp dates", async () => {
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "31-02-2026_14:41:29:089", blockHeight: "1002", votes: [{ node: "aws", offsetMs: 1 }] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_timestamp\s+FAIL/);
    },
  );
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "2026-02-31T14:41:29.089Z", blockHeight: "1002", votes: [{ node: "aws", offsetMs: 1 }] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_timestamp\s+FAIL/);
    },
  );
});

test("fails invalid get_block blockTime semantics", async () => {
  await withServers(
    {},
    { block: { height: KNOWN_HEIGHT, blockHeight: KNOWN_HEIGHT, proposerAddress: "aws", blockTime: "later", transactions: [] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_block\s+FAIL/);
      assert.match(output, /log_action aws->gcp\s+SKIP/);
    },
  );
});

test("fails when known-height get_block payloads differ semantically", async () => {
  await withServers(
    {},
    { block: { height: KNOWN_HEIGHT, blockHeight: KNOWN_HEIGHT, proposerAddress: "0xdifferent", blockTime: BLOCK_TIME, transactions: [] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /get_block\s+FAIL/);
      assert.match(output, /log_action aws->gcp\s+SKIP/);
    },
  );
});

test("skips ledger writes when a pre-write parity row fails", async () => {
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "", blockHeight: "-1", votes: [{ node: "aws", offsetMs: 1 }] } },
    async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /log_action aws->gcp\s+SKIP/);
      assert.equal(gcp.calls.some((c) => c.tool === "log_action"), false);
      assert.equal(aws.calls.some((c) => c.tool === "log_action"), false);
    },
  );
});

test("fails when AWS and GCP direct log_action response shapes diverge", async () => {
  await withServers({}, { extraLogField: true }, async ({ gcp, aws }) => {
    const { result, output } = await runAgainst(gcp, aws);
    assert.equal(result.ok, false);
    assert.match(output, /log_action compare\s+FAIL/);
  });
});

test("fails when AWS and GCP direct log_action response semantics drift", async () => {
  for (const logOverrides of [
    { clientId: "other-client" },
    { walletId: "other-wallet" },
    { versionNumber: 2 },
    { additionalInfo: "other-info" },
  ]) {
    await withServers({}, { logOverrides }, async ({ gcp, aws }) => {
      const { result, output } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.match(output, /log_action compare\s+FAIL/);
    });
  }
});

test("redacts token-shaped values and full log payload content on failure", async () => {
  await withServers(
    {},
    { timestamp: { madMarzulloTime: "later", blockHeight: "1002", secret: SECRET_TOKEN, action: ACTION } },
    async ({ gcp, aws }) => {
      const { result, output, errors } = await runAgainst(gcp, aws);
      assert.equal(result.ok, false);
      assert.doesNotMatch(output + errors, new RegExp(SECRET_TOKEN));
      assert.doesNotMatch(output + errors, new RegExp(ACTION));
      assert.doesNotMatch(output + errors, /authorization|bearer|x-api-key/i);
    },
  );
});

test("fails bounded responses on timeout and max response size", async () => {
  const slow = await startParityServer("gcp", { slowHealth: true });
  const normal = await startParityServer("aws");
  try {
    const timeout = await runParity({
      gcpBaseUrl: slow.baseUrl,
      awsBaseUrl: normal.baseUrl,
      blockHeight: KNOWN_HEIGHT,
      reference: REFERENCE,
      action: ACTION,
      timeoutMs: 50,
      maxBytes: 100_000,
      stdout: { write() {} },
      stderr: { write() {} },
    });
    assert.equal(timeout.ok, false);
  } finally {
    await normal.close();
    await slow.close();
  }

  const normal2 = await startParityServer("gcp");
  const huge = await startParityServer("aws", { hugeHealth: true });
  try {
    const tooLarge = await runParity({
      gcpBaseUrl: normal2.baseUrl,
      awsBaseUrl: huge.baseUrl,
      blockHeight: KNOWN_HEIGHT,
      reference: REFERENCE,
      action: ACTION,
      timeoutMs: 1000,
      maxBytes: 100,
      stdout: { write() {} },
      stderr: { write() {} },
    });
    assert.equal(tooLarge.ok, false);
  } finally {
    await huge.close();
    await normal2.close();
  }
});

test("validates timeout and max response size as positive bounded numbers", async () => {
  await assert.rejects(
    runParity({
      gcpBaseUrl: "http://127.0.0.1",
      awsBaseUrl: "http://127.0.0.1",
      blockHeight: KNOWN_HEIGHT,
      reference: REFERENCE,
      action: ACTION,
      timeoutMs: 0,
      maxBytes: 100_000,
      stdout: { write() {} },
    }),
    /timeoutMs must be a positive number/,
  );
  await assert.rejects(
    runParity({
      gcpBaseUrl: "http://127.0.0.1",
      awsBaseUrl: "http://127.0.0.1",
      blockHeight: KNOWN_HEIGHT,
      reference: REFERENCE,
      action: ACTION,
      timeoutMs: 1000,
      maxBytes: Number.POSITIVE_INFINITY,
      stdout: { write() {} },
    }),
    /maxBytes must be a positive number/,
  );
});

test("does not retry ambiguous log_action writes", async () => {
  await withServers({}, {}, async ({ gcp, aws }) => {
    const { result } = await runAgainst(gcp, aws);
    assert.equal(result.ok, true);
    assert.equal(aws.calls.filter((c) => c.apiKey).length, 4);
    assert.equal(gcp.calls.filter((c) => c.apiKey).length, 4);
  });
});
