// McpClockchainAdapter — drive the clock-sdk primitives through the HOSTED MCP.
//
// The SDK's ClockchainClock / ClockScheduler / stopwatch only need a few client
// methods (getTimestamp, attestAction, log, waitForConfirmation). This adapter
// implements exactly that surface over MCP tool calls, so the SDK runs with a
// demo token and NO gateway credentials — and so the live gates
// (test/gates-live.test.mjs) exercise the real SDK code path end-to-end against
// the deployed endpoint rather than the raw tools alone.
//
//   import { McpClockchainAdapter } from "./mcp-adapter.mjs";
//   const mcp = new McpClockchainAdapter({ token: process.env.CC_MCP_TOKEN });
//   await mcp.connect();
//   const clock = new ClockchainClock(mcp);            // TimestampSource
//   const sch = new ClockScheduler({ clock, client: mcp, confirmSource: mcp });
//   const handle = await stopwatchStart(mcp, "task");  // StopwatchClient
//   await mcp.close();
//
// Field notes baked in (mirrors try-alarm-mcp.sh): the hosted endpoint rate-limits
// per token (30/min) with HTTP 429 + Retry-After, so tool calls back off and retry;
// 401/403 fail fast (auth is never transient); tool errors surface as McpToolError
// with the server's text so a pool-degraded refusal is distinguishable.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parseGatewayTime } from "../dist/index.js";

export const DEFAULT_MCP_URL = "https://mcp.clockchain.network/mcp";

/** A tool call the server answered with isError: true. `text` is the server's message. */
export class McpToolError extends Error {
  constructor(tool, text) {
    super(`${tool}: ${text}`);
    this.name = "McpToolError";
    this.tool = tool;
    this.text = text;
  }
}

/** True when the server refused a write because it believes the node pool is degraded. */
export function isPoolDegradedError(err) {
  return err instanceof McpToolError && /pool is degraded/i.test(err.text);
}

/**
 * Pool participation from a get_timestamp payload, tolerant of the key rename
 * (`nodeParticipation%` → `nodeParticipation`, observed 2026-09-10). NaN if absent.
 */
export function participationOf(ts) {
  const raw = ts?.["nodeParticipation%"] ?? ts?.nodeParticipation;
  return raw == null ? NaN : Number(raw);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function statusOf(err) {
  // StreamableHTTPError carries `code`; fall back to parsing the message.
  if (typeof err?.code === "number") return err.code;
  const m = /HTTP (\d{3})/.exec(String(err?.message ?? ""));
  return m ? Number(m[1]) : undefined;
}

export class McpClockchainAdapter {
  /**
   * @param {object} opts
   * @param {string} [opts.url]           MCP endpoint (default: the hosted one).
   * @param {string} opts.token           x-api-key token.
   * @param {boolean} [opts.allowDegraded] pass allow_degraded on writes.
   * @param {number} [opts.waitMs]        confirmation wait forwarded to attest_action.
   * @param {number} [opts.pollMs]        get_log_entry poll cadence in waitForConfirmation.
   */
  constructor({ url = DEFAULT_MCP_URL, token, allowDegraded = false, waitMs = 30_000, pollMs = 1500 } = {}) {
    if (!token) throw new Error("McpClockchainAdapter: token is required (x-api-key)");
    this.url = url;
    this.token = token;
    this.allowDegraded = allowDegraded;
    this.waitMs = waitMs;
    this.pollMs = pollMs;
    this.client = null;
    /** Every get_timestamp reading, in order: { raw, epochMs, wallMs }. */
    this.readings = [];
    /** Wall-clock ms at which each log() call was issued (for stopwatch wall-elapsed). */
    this.logIssuedAt = [];
    /** Count of tool calls by name (for rate-budget diagnostics). */
    this.calls = {};
  }

  async connect() {
    const transport = new StreamableHTTPClientTransport(new URL(this.url), {
      requestInit: { headers: { "x-api-key": this.token } },
    });
    this.client = new Client({ name: "clock-sdk-gates", version: "0.1.0" });
    await this.client.connect(transport);
    return this;
  }

  async close() {
    if (this.client) {
      await this.client.close().catch(() => undefined);
      this.client = null;
    }
  }

  async listTools() {
    const res = await this.client.listTools();
    return res.tools.map((t) => t.name);
  }

  /**
   * Call a tool and return its JSON-decoded text payload. Retries HTTP 429 with a
   * backoff; fails fast on 401/403; throws McpToolError on isError responses.
   */
  async call(name, args = {}) {
    this.calls[name] = (this.calls[name] ?? 0) + 1;
    let lastErr;
    for (let attempt = 1; attempt <= 4; attempt++) {
      try {
        const res = await this.client.callTool({ name, arguments: args });
        const text = res.content?.find((c) => c.type === "text")?.text ?? "";
        if (res.isError) throw new McpToolError(name, text);
        try {
          return JSON.parse(text);
        } catch {
          return text;
        }
      } catch (err) {
        if (err instanceof McpToolError) throw err;
        const status = statusOf(err);
        if (status === 401 || status === 403) {
          throw new Error(`${name}: auth ${status} — token bad/expired (not retrying)`);
        }
        lastErr = err;
        if (status === 429 || /rate limit/i.test(String(err?.message))) {
          await sleep(10_000 * attempt);
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  }

  // ----- TimestampSource / ConfirmSource (ClockchainClock, ClockScheduler) -----

  async getTimestamp() {
    const raw = await this.call("get_timestamp");
    this.readings.push({ raw, epochMs: parseGatewayTime(raw.madMarzulloTime), wallMs: Date.now() });
    return raw;
  }

  /** The most recent get_timestamp reading, or null. */
  get lastReading() {
    return this.readings.length ? this.readings[this.readings.length - 1] : null;
  }

  // ----- AttestSource (ClockScheduler anchors each fire here) -----

  async attestAction({ agentId, action, inputs, outputs }) {
    const args = {
      agent_id: agentId,
      action,
      inputs,
      outputs,
      wait: true,
      wait_ms: this.waitMs,
    };
    if (this.allowDegraded) args.allow_degraded = true;
    return this.call("attest_action", args);
  }

  // ----- StopwatchClient (stopwatchStart / stopwatchStop) -----

  async log({ assetHash, assetReferenceId, additionalInfo }) {
    const args = { asset_hash: assetHash, asset_reference_id: assetReferenceId, wait: false };
    if (additionalInfo) args.additional_info = additionalInfo;
    if (this.allowDegraded) args.allow_degraded = true;
    this.logIssuedAt.push(Date.now());
    return this.call("log_action", args);
  }

  async waitForConfirmation(ledgerId, timeoutMs = this.waitMs) {
    const deadline = Date.now() + timeoutMs;
    let last;
    for (;;) {
      last = await this.call("get_log_entry", { ledger_id: ledgerId });
      if (last?.blockHeight != null) return last;
      if (Date.now() >= deadline) return last;
      await sleep(this.pollMs);
    }
  }

  // ----- keyless verification -----

  async verifyCrossParty({ ledgerId, blockHeight }) {
    const args = { ledger_id: ledgerId };
    if (blockHeight != null) args.block_height = blockHeight;
    return this.call("verify_cross_party", args);
  }
}

/**
 * Mint a self-serve demo token once and cache it on disk (the /token endpoint is
 * IP-rate-limited with no Retry-After — never mint per run). Returns the token.
 */
export async function mintDemoToken({ base = "https://mcp.clockchain.network", file } = {}) {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const path = await import("node:path");
  const cache = file ?? path.join(os.tmpdir(), "cc_demo_token");
  try {
    const cached = (await fs.readFile(cache, "utf8")).trim();
    if (cached && cached !== "null") return cached;
  } catch {
    /* no cache */
  }
  const res = await fetch(`${base}/token`, { method: "POST" });
  if (!res.ok) throw new Error(`/token failed: HTTP ${res.status} (IP-rate-limited? reuse a cached token)`);
  const body = await res.json();
  if (!body?.token) throw new Error(`/token returned no token: ${JSON.stringify(body)}`);
  await fs.writeFile(cache, body.token, { mode: 0o600 });
  return body.token;
}
