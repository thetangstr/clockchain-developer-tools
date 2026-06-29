/**
 * MCP control plane for the keeper: keeper_schedule / keeper_list / keeper_cancel.
 *
 * These names are deliberately distinct from the mcp-server's contract-deploy
 * `create_schedule` / `list_schedules` so the two tool sets never collide. This
 * is a SEPARATE MCP server instance ("clockchain-keeper") — registering it here
 * does not touch the deployed mcp-server's surface or its conformance/coverage
 * gates.
 *
 * The data plane (firing) runs in the always-on worker loop, not in these tools.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type Keeper } from "./keeper.js";
import type { ScheduleInput, TriggerMode } from "./types.js";

/** Standard MCP success payload. */
function ok(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
}

/** Standard MCP error payload (isError result, not a thrown protocol error). */
function fail(err: unknown) {
  const text = err instanceof Error ? err.message : String(err);
  return { isError: true as const, content: [{ type: "text" as const, text }] };
}

async function run(work: () => Promise<unknown>) {
  try {
    return ok(await work());
  } catch (err) {
    return fail(err);
  }
}

/**
 * Resolve the acting owner identity (AGE-194). Prefer the per-request `sub`
 * threaded in by the transport (the caller's bring-your-own-key identity);
 * fall back to the tool argument, then to a shared default for local trials.
 */
function resolveSub(argSub: string | undefined, requestSub: string | undefined): string {
  return requestSub ?? argSub ?? "anonymous";
}

/**
 * Parse a fireAt value that may be epoch ms (number) or an ISO-8601 string.
 */
function parseFireAtMs(fireAt: string | number): number {
  if (typeof fireAt === "number") return fireAt;
  const ms = Date.parse(fireAt);
  if (Number.isNaN(ms)) throw new Error(`Invalid fire_at "${fireAt}" (use epoch ms or ISO-8601).`);
  return ms;
}

export interface RegisterKeeperToolsOptions {
  /**
   * Resolve the owner identity for a request (e.g. from a verified token `sub`
   * or BYO-key fingerprint). When omitted, tools fall back to the `sub` argument.
   */
  requestSub?: () => string | undefined;
}

/** Register keeper_schedule / keeper_list / keeper_cancel on an MCP server. */
export function registerKeeperTools(
  server: Pick<McpServer, "registerTool">,
  keeper: Keeper,
  opts: RegisterKeeperToolsOptions = {},
): void {
  const reqSub = () => opts.requestSub?.();

  server.registerTool(
    "keeper_schedule",
    {
      title: "Schedule a verified-time trigger",
      description:
        "Register an off-chain trigger that fires at a Clockchain-verified time even " +
        "while your client is offline. At fire time the hosted keeper delivers a " +
        "Standard-Webhooks-signed POST to your target URL and anchors the fire on-chain " +
        "(keyless-verifiable receipt). Returns the trigger id and status.",
      inputSchema: {
        fire_at: z
          .union([z.string(), z.number()])
          .describe("When to fire: epoch milliseconds, or an ISO-8601 timestamp."),
        target_url: z
          .string()
          .describe("HTTPS webhook URL to POST when the trigger fires (SSRF-guarded)."),
        payload: z
          .unknown()
          .optional()
          .describe("Arbitrary JSON delivered in the fire body and hashed into the anchor."),
        mode: z
          .enum(["once", "interval"])
          .optional()
          .describe('"once" (default) fires a single time; "interval" re-arms after each fire.'),
        interval_ms: z
          .number()
          .optional()
          .describe('For mode "interval": milliseconds between fires.'),
        sub: z
          .string()
          .optional()
          .describe("Owner identity for this trigger (scopes list/cancel). Defaults to the request identity."),
      },
    },
    async ({ fire_at, target_url, payload, mode, interval_ms, sub }) =>
      run(async () => {
        const input: ScheduleInput = {
          sub: resolveSub(sub, reqSub()),
          fireAtMs: parseFireAtMs(fire_at),
          target: target_url,
          payload,
          mode: mode as TriggerMode | undefined,
          intervalMs: interval_ms,
        };
        const t = await keeper.schedule(input);
        return {
          id: t.id,
          status: t.status,
          fireAtMs: t.fireAtMs,
          mode: t.mode,
          target: t.target,
          note: "Armed. The keeper fires this even if you disconnect; each fire is anchored on-chain.",
        };
      }),
  );

  server.registerTool(
    "keeper_list",
    {
      title: "List your scheduled triggers",
      description:
        "List the triggers you registered with the keeper, including each one's status, " +
        "next fire time, and per-fire delivery + anchor status (AGE-193: a fire is not " +
        "done until anchored).",
      inputSchema: {
        sub: z
          .string()
          .optional()
          .describe("Owner identity to list. Defaults to the request identity."),
      },
    },
    async ({ sub }) =>
      run(async () => {
        const owner = reqSub() ?? sub;
        const triggers = await keeper.list(owner);
        return {
          count: triggers.length,
          triggers: triggers.map((t) => ({
            id: t.id,
            status: t.status,
            fireAtMs: t.fireAtMs,
            mode: t.mode,
            target: t.target,
            attempts: t.attempts,
            lastError: t.lastError,
            fires: t.fires.map((f) => ({
              fireId: f.fireId,
              firedAtMs: f.firedAtMs,
              delivery: f.delivery.status,
              anchor: f.anchor.status,
              ledgerId: f.anchor.ledgerId,
              blockHeight: f.anchor.blockHeight,
            })),
          })),
        };
      }),
  );

  server.registerTool(
    "keeper_cancel",
    {
      title: "Cancel a scheduled trigger",
      description:
        "Cancel a trigger you registered so it no longer fires. Scoped to your owner " +
        "identity. Idempotent: cancelling an already-terminal trigger is a no-op.",
      inputSchema: {
        id: z.string().describe("The trigger id returned by keeper_schedule."),
        sub: z
          .string()
          .optional()
          .describe("Owner identity. Defaults to the request identity."),
      },
    },
    async ({ id, sub }) =>
      run(async () => {
        const owner = reqSub() ?? sub;
        const t = await keeper.cancel(id, owner);
        if (!t) return { id, cancelled: false, reason: "not found or not owned" };
        return { id: t.id, cancelled: true, status: t.status };
      }),
  );
}

/** Build a standalone keeper MCP server instance. */
export function buildKeeperServer(
  keeper: Keeper,
  opts: RegisterKeeperToolsOptions = {},
): McpServer {
  const server = new McpServer({ name: "clockchain-keeper", version: "0.1.0" });
  registerKeeperTools(server, keeper, opts);
  return server;
}
