/**
 * Process-wide keeper runtime for the hosted MCP: the verified-time timer/alarm
 * data plane (dispatch loop) that fires triggers registered through the
 * `timer_set` / `alarm_set` tools while the caller is offline.
 *
 * Why in-process: the hosted MCP runs as one always-on container per box and the
 * keeper's file store assumes a single writer, so running the loop here needs no
 * second service, route, or secret. `@clockchain/keeper`'s standalone worker
 * remains the entry point for separate deployments.
 *
 * Boot: `startKeeperRuntime()` disciplines the clock to consensus time (retrying
 * until the gateway answers — the keeper never fires on an undisciplined clock),
 * then starts the loop. Tools use `getRuntimeKeeper()`; before the first sync
 * `schedule()` fails with a clear "clock not disciplined yet" error.
 *
 * Anchoring identity + credits: fires are anchored with the server's delegated
 * key (a trigger fires with no request context) and count against the shared
 * MCP_LOG_BUDGET exactly like a log_action. Per-tenant billing is deferred.
 */
import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import {
  ClockchainAnchorer,
  FileStore,
  Keeper,
  createDisciplinedClock,
  deriveOwnerSecret,
  ssrfOptionsFromEnv,
  type Anchorer,
  type KeeperConfig,
} from "@clockchain/keeper";
import { getSharedLogBudget } from "./budget.js";

/**
 * Hosted defaults: tighter than the standalone worker's, because a public endpoint
 * lets self-serve demo tokens register triggers that spend OUR credits unattended.
 * Bounds that follow: ≤ 20 live triggers per owner, intervals ≥ 60 s, ≤ 10 fires per
 * 1 s tick globally (≤ 600 credits/min worst case), and the shared MCP_LOG_BUDGET as
 * the hard stop. Per-owner billing (gateway sub-keys) is the real fix and is deferred.
 */
const DEFAULTS = Object.freeze({
  storePath: "./data/keeper-store.json",
  tickMs: 1000,
  resyncMs: 60_000,
  maxTriggersPerSub: 20,
  maxPerTick: 10,
  maxRetainedFires: 20,
});

let runtime: { keeper: Keeper; clock: ReturnType<typeof createDisciplinedClock>; disciplined: boolean; starting: boolean } | null = null;

/** True when webhook delivery is configured on this deployment (signing secret present). */
export function keeperWebhooksEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env.KEEPER_WEBHOOK_SECRET ?? "").length > 0;
}

/**
 * The Standard-Webhooks secret an owner verifies their fires with: derived per owner
 * from the server secret, so it can be shown to that owner at registration and the
 * server secret itself is never disclosed. Null when webhooks are not configured.
 */
export function keeperOwnerWebhookSecret(owner: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const server = env.KEEPER_WEBHOOK_SECRET ?? "";
  return server ? deriveOwnerSecret(server, owner) : null;
}

/** Wrap an anchorer so each chargeable anchor write respects the shared log budget. */
function budgeted(inner: Anchorer): Anchorer {
  const budget = getSharedLogBudget();
  return {
    async anchorFire(args) {
      budget.check();
      const out = await inner.anchorFire(args);
      budget.record();
      return out;
    },
    pollAnchor: (receipt) => inner.pollAnchor(receipt),
  };
}

function build(env: NodeJS.ProcessEnv): NonNullable<typeof runtime> {
  const client = new ClockchainClient(readConfigFromEnv(env));
  // No background resync until the runtime is started: building the keeper (e.g. when
  // tools are registered in a test) must not leave a live interval holding the process.
  const clock = createDisciplinedClock(client, { autoResyncMs: 0 });
  const config: KeeperConfig = {
    agentId: env.KEEPER_AGENT_ID ?? "agent:clockchain-mcp-keeper",
    webhookSecret: env.KEEPER_WEBHOOK_SECRET ?? "",
    webhookSecretFor: (sub) => keeperOwnerWebhookSecret(sub, env) ?? "",
    ssrf: ssrfOptionsFromEnv(env),
    maxAttempts: Number(env.KEEPER_MAX_ATTEMPTS ?? 5),
    maxTriggersPerSub: Number(env.KEEPER_MAX_TRIGGERS_PER_SUB ?? DEFAULTS.maxTriggersPerSub),
    maxPerTick: Number(env.KEEPER_MAX_PER_TICK ?? DEFAULTS.maxPerTick),
    maxRetainedFires: Number(env.KEEPER_MAX_RETAINED_FIRES ?? DEFAULTS.maxRetainedFires),
  };
  const state = { disciplined: false };
  const keeper = new Keeper({
    store: new FileStore(env.KEEPER_STORE_PATH ?? DEFAULTS.storePath),
    anchorer: budgeted(new ClockchainAnchorer(client)),
    nowMs: () => {
      if (!state.disciplined) {
        throw new Error(
          "The keeper's clock is not disciplined to consensus time yet (gateway unreachable at boot); retry shortly.",
        );
      }
      return clock.nowMs();
    },
    nowUncertaintyMs: () => clock.nowUncertaintyMs(),
    config,
  });
  return {
    keeper,
    clock,
    starting: false,
    get disciplined() {
      return state.disciplined;
    },
    set disciplined(v: boolean) {
      state.disciplined = v;
    },
  };
}

/** The process-wide keeper (built lazily; the loop runs only after startKeeperRuntime). */
export function getRuntimeKeeper(env: NodeJS.ProcessEnv = process.env): Keeper {
  runtime ??= build(env);
  return runtime.keeper;
}

/** Whether the runtime's clock has been disciplined (fires are possible). */
export function keeperRuntimeReady(): boolean {
  return runtime?.disciplined === true;
}

/**
 * Discipline the clock (retrying in the background) and then start the dispatch
 * loop. Returns immediately: the keeper must never delay or block the MCP server's
 * own startup — if the gateway is unreachable at boot, tools answer "not
 * disciplined yet" until the sync succeeds. Idempotent. Disabled with
 * KEEPER_DISABLED=1 (tools still register; schedule() errors out).
 */
export function startKeeperRuntime(env: NodeJS.ProcessEnv = process.env): void {
  if (env.KEEPER_DISABLED === "1") {
    console.error("[clockchain-mcp] keeper runtime disabled (KEEPER_DISABLED=1)");
    return;
  }
  runtime ??= build(env);
  const rt = runtime;
  if (rt.starting) return;
  rt.starting = true;
  const tickMs = Number(env.KEEPER_TICK_MS ?? DEFAULTS.tickMs);
  const retryMs = Number(env.KEEPER_SYNC_RETRY_MS ?? 10_000);
  const resyncMs = Number(env.KEEPER_RESYNC_MS ?? DEFAULTS.resyncMs);
  const sleep = (ms: number) => new Promise<void>((r) => { const h = setTimeout(r, ms); h.unref?.(); });
  void (async () => {
    for (;;) {
      try {
        await rt.clock.sync();
        break;
      } catch (err) {
        console.error(`[clockchain-mcp] keeper clock sync failed; retrying in ${retryMs}ms:`, err instanceof Error ? err.message : err);
        await sleep(retryMs);
      }
    }
    rt.disciplined = true;
    rt.clock.startAutoResync(resyncMs);
    // The loop starts only on a disciplined clock; its boot tick re-arms anything
    // that came due while the process was down.
    rt.keeper.start(tickMs, (e) => console.error("[clockchain-mcp] keeper tick error:", e));
    console.error(`[clockchain-mcp] keeper loop started (tick=${tickMs}ms, webhooks=${keeperWebhooksEnabled(env) ? "on" : "off (poll only)"})`);
  })();
}

/** Stop the loop and background resync (tests / shutdown). */
export function stopKeeperRuntime(): void {
  runtime?.keeper.stop();
  runtime?.clock.stop();
}
