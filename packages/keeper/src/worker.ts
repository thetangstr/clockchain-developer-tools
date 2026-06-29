/**
 * Always-on keeper worker — the deployable entry point.
 *
 * Wires the real dependencies and runs BOTH planes in one process:
 *   - data plane: the dispatch loop (re-armed from the durable store on boot).
 *   - control plane: the keeper MCP server, over HTTP (MCP_TRANSPORT=http, for the
 *     hosted deployment) or stdio (default, for a local agent).
 *
 * Per-user auth (AGE-194): in HTTP mode a caller brings their own Clockchain key
 * via `x-clockchain-api-key`; its fingerprint becomes the request `sub` that
 * scopes keeper_list / keeper_cancel. The keeper's OWN delegated key (from env) is
 * what anchors fires. A bearer-token gate (KEEPER_AUTH_TOKENS) guards the endpoint.
 *
 * TODO (deferred): per-`sub` gateway sub-key + credit budget so each tenant's
 * anchors bill to them; full OAuth; multi-worker leasing for horizontal scale.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readConfigFromEnv, ClockchainClient } from "@clockchain/core";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ClockchainAnchorer } from "./anchor.js";
import { createDisciplinedClock } from "./clock.js";
import { Keeper, type KeeperConfig } from "./keeper.js";
import { buildKeeperServer } from "./mcp.js";
import { ssrfOptionsFromEnv } from "./ssrf.js";
import { FileStore } from "./store.js";

const DEFAULT_STORE_PATH = process.env.KEEPER_STORE_PATH ?? "./data/keeper-store.json";

/** Build a Keeper plus its disciplined clock from environment configuration. */
export function buildKeeperFromEnv(env: NodeJS.ProcessEnv = process.env): {
  keeper: Keeper;
  clock: ReturnType<typeof createDisciplinedClock>;
} {
  const config = readConfigFromEnv(env);
  const client = new ClockchainClient(config);
  const clock = createDisciplinedClock(client, {
    autoResyncMs: Number(env.KEEPER_RESYNC_MS ?? 60_000),
  });
  const store = new FileStore(env.KEEPER_STORE_PATH ?? DEFAULT_STORE_PATH);
  const anchorer = new ClockchainAnchorer(client);

  const keeperConfig: KeeperConfig = {
    agentId: env.KEEPER_AGENT_ID ?? "agent:clockchain-keeper",
    webhookSecret: env.KEEPER_WEBHOOK_SECRET ?? "",
    ssrf: ssrfOptionsFromEnv(env),
    retry: {
      maxAttempts: Number(env.KEEPER_MAX_ATTEMPTS ?? 5),
      baseDelayMs: Number(env.KEEPER_BASE_DELAY_MS ?? 500),
      maxDelayMs: Number(env.KEEPER_MAX_DELAY_MS ?? 30_000),
    },
    anchorRetryDelayMs: Number(env.KEEPER_ANCHOR_RETRY_MS ?? 1000),
  };

  const keeper = new Keeper({
    store,
    anchorer,
    nowMs: () => clock.nowMs(),
    nowUncertaintyMs: () => clock.nowUncertaintyMs(),
    config: keeperConfig,
  });
  return { keeper, clock };
}

/** Parse a comma-separated bearer-token allow-list. */
function parseTokens(raw: string | undefined): string[] {
  return (raw ?? "").split(",").map((t) => t.trim()).filter((t) => t.length > 0);
}

/** Stable, non-reversible owner id from a caller's API key (AGE-194 tenant scope). */
function fingerprint(apiKey: string): string {
  return "byok:" + createHash("sha256").update(apiKey).digest("hex").slice(0, 16);
}

const firstHeader = (h: string | string[] | undefined): string =>
  (Array.isArray(h) ? h[0] : h) ?? "";

/** Run the keeper MCP control plane over HTTP, alongside the dispatch loop. */
async function runHttp(keeper: Keeper, env: NodeJS.ProcessEnv): Promise<void> {
  const port = Number(env.PORT ?? 8080);
  const tokens = parseTokens(env.KEEPER_AUTH_TOKENS);
  const ACCEPT = "application/json, text/event-stream";

  const isAuthorized = (req: IncomingMessage): boolean => {
    if (tokens.length === 0) return true; // open: local/trusted use only
    const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(req.headers.authorization));
    if (bearer && tokens.includes(bearer[1].trim())) return true;
    return false;
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok", service: "clockchain-keeper" }));
      return;
    }
    if (path !== "/mcp") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    if (!isAuthorized(req)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    // BYO-key (AGE-194): the caller's own key fingerprint scopes their triggers.
    const apiKey = firstHeader(req.headers["x-clockchain-api-key"]).trim();
    const requestSub = apiKey ? fingerprint(apiKey) : undefined;
    try {
      const mcp = buildKeeperServer(keeper, { requestSub: () => requestSub });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void mcp.close();
      });
      await mcp.connect(transport);
      await transport.handleRequest(req, res);
    } catch (err) {
      console.error("[keeper] http error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  });
  await new Promise<void>((resolve) => server.listen(port, () => resolve()));
  void ACCEPT; // documented Accept contract is enforced by the transport
  console.error(`[keeper] http control plane on :${port} (POST /mcp, GET /healthz)`);
}

async function main(): Promise<void> {
  const env = process.env;
  const { keeper, clock } = buildKeeperFromEnv(env);

  // Discipline the clock before firing anything; without it now() would throw.
  try {
    await clock.sync();
    console.error("[keeper] clock disciplined to Clockchain consensus time");
  } catch (err) {
    console.error("[keeper] WARNING: initial clock sync failed:", err);
    throw err; // refuse to fire on an undisciplined clock
  }

  const tickMs = Number(env.KEEPER_TICK_MS ?? 1000);
  keeper.start(tickMs, (e) => console.error("[keeper] tick error:", e));
  console.error(`[keeper] dispatch loop started (tick=${tickMs}ms)`);

  const transport = (env.MCP_TRANSPORT ?? "stdio").toLowerCase();
  if (transport === "http") {
    await runHttp(keeper, env);
  } else {
    const { StdioServerTransport } = await import(
      "@modelcontextprotocol/sdk/server/stdio.js"
    );
    const mcp = buildKeeperServer(keeper);
    await mcp.connect(new StdioServerTransport());
    console.error("[keeper] stdio control plane ready");
  }

  const shutdown = () => {
    console.error("[keeper] shutting down");
    keeper.stop();
    clock.stop();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[keeper] fatal:", err);
    process.exit(1);
  });
}
