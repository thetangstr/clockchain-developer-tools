#!/usr/bin/env node
/**
 * check-config-from-ssm (N7c) — pulls the `/clockchain/mcp/<NAME>` SSM
 * parameters for the whole contract env surface into process.env ONLY
 * (never disk, never stdout), then runs the SAME readiness check as
 * check-config.mjs and prints its redacted report plus a `parameters`
 * map of NAME → "present"|"absent".
 *
 *   node scripts/agent-contract/check-config-from-ssm.mjs \
 *     [--region us-west-2] [--prefix /clockchain/mcp]
 *
 * Exit codes:  0 ready · 1 misconfigured/refused/ssm-failure · 2 disabled.
 *
 * No parameter VALUE is ever printed — the report adds names only.
 */

import { checkConfig } from "./check-config.mjs";

/**
 * The complete contract env surface — every CONTRACT_ and TELEMETRY_ name
 * read by src/agent-contract/config.ts plus CONTRACT_OBSERVER_PER_MINUTE
 * (read in src/http.ts, the observer-feed limiter).
 */
export const ENV_PARAMETERS = [
  "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS", "CONTRACT_HOST_ROOTS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_SERVER_KEY_ID", "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_VALID_FROM", "CONTRACT_SERVER_KEY_VALID_UNTIL",
  "CONTRACT_POLICY_DIGESTS", "CONTRACT_PRINCIPALS",
  "CONTRACT_OBSERVER_TOKEN", "CONTRACT_VERIFIER_TOKEN",
  "CONTRACT_ALLOW_SIM_FAULTS", "CONTRACT_SIM_FAULTS",
  "CONTRACT_LEVEL", "CONTRACT_REQUIRE_BIND_STATEMENT",
  "TELEMETRY_CLOSE_URL", "TELEMETRY_CLOSE_BACKOFF_MS",
  "TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS", "TELEMETRY_CLOSE_DEADLINE_MS",
  "CONTRACT_CALLS_PER_MINUTE", "CONTRACT_OBSERVER_PER_MINUTE", "CONTRACT_MAX_RUNS",
  "CONTRACT_MAX_RECEIPTS_PER_RUN",
  "CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL", "CONTRACT_RUN_TTL_MS", "CONTRACT_CERT_GRACE_MS",
  "CONTRACT_SESSION_TTL_MS", "CONTRACT_STATE_DIR",
  "CONTRACT_ERC8004_CHAIN_ID", "CONTRACT_ERC8004_REGISTRY_ADDRESS",
  "CONTRACT_ANCHOR_ENABLED", "CONTRACT_SETTLEMENT_RAIL", "CONTRACT_TRUST_PROXY",
];

/** GetParameters is capped at 10 names per call. */
const SSM_BATCH = 10;

/**
 * AWS-backed fetch: ONE GetParametersCommand for `names` (≤10) with
 * WithDecryption. Lazily imports the SDK so loading this module performs no
 * AWS calls — tests inject `fetchParameters` and never need the package.
 * Returns Map<parameterName, value>; names in InvalidParameters are simply
 * absent from the map.
 */
async function fetchParametersAws({ region, names }) {
  const { SSMClient, GetParametersCommand } = await import("@aws-sdk/client-ssm");
  const client = new SSMClient({ region });
  const res = await client.send(
    new GetParametersCommand({ Names: names, WithDecryption: true }),
  );
  const found = new Map();
  for (const p of res.Parameters ?? []) {
    if (typeof p.Name === "string" && typeof p.Value === "string") {
      found.set(p.Name, p.Value);
    }
  }
  return found;
}

/**
 * Fetch `${prefix}/<NAME>` for every name in ENV_PARAMETERS (chunked at
 * SSM_BATCH) and write the present ones into `env`. Values are never logged.
 * Returns { NAME: "present" | "absent" } for the full surface. A batch that
 * fails with ParameterNotFound counts as absent; any other error propagates.
 */
export async function loadEnvFromSsm({
  region,
  prefix = "/clockchain/mcp",
  env = process.env,
  fetchParameters = fetchParametersAws,
} = {}) {
  const names = ENV_PARAMETERS.map((n) => `${prefix}/${n}`);
  const found = new Map();
  for (let i = 0; i < names.length; i += SSM_BATCH) {
    try {
      const batch = await fetchParameters({
        region,
        names: names.slice(i, i + SSM_BATCH),
      });
      for (const [k, v] of batch) found.set(k, v);
    } catch (err) {
      if (err instanceof Error && err.name === "ParameterNotFound") continue;
      throw err;
    }
  }
  const parameters = {};
  for (let i = 0; i < ENV_PARAMETERS.length; i++) {
    const value = found.get(names[i]);
    if (value !== undefined) {
      env[ENV_PARAMETERS[i]] = value;
      parameters[ENV_PARAMETERS[i]] = "present";
    } else {
      parameters[ENV_PARAMETERS[i]] = "absent";
    }
  }
  return parameters;
}

/**
 * loadEnvFromSsm + checkConfig(env). A fetch failure is reported with the
 * checker's own convention (exit 1, status misconfigured) and carries only
 * the error NAME — SDK messages can echo request detail we keep off stdout.
 */
export async function checkConfigFromSsm({ region, prefix, env, fetchParameters } = {}) {
  const target = env ?? process.env;
  let parameters;
  try {
    parameters = await loadEnvFromSsm({ region, prefix, env: target, fetchParameters });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    return {
      exitCode: 1,
      report: { status: "misconfigured", reason: `ssm fetch failed (${name})` },
    };
  }
  const { exitCode, report } = await checkConfig(target);
  return { exitCode, report: { ...report, parameters } };
}

const USAGE = `usage: node check-config-from-ssm.mjs [--region <r>] [--prefix <p>]
  --region   AWS region (default $AWS_REGION else us-west-2)
  --prefix   SSM parameter prefix (default /clockchain/mcp)
Reads <prefix>/<NAME> for the contract env surface into process.env,
then prints the same redacted report as check-config.mjs.
`;

export function parseArgs(argv, env = process.env) {
  const out = { region: env.AWS_REGION ?? "us-west-2", prefix: "/clockchain/mcp" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
    } else if (a === "--region" || a === "--prefix") {
      const value = argv[++i];
      if (value === undefined) return { error: `${a} wants a value` };
      out[a.slice(2)] = value;
    } else if (a.startsWith("--region=")) {
      out.region = a.slice("--region=".length);
    } else if (a.startsWith("--prefix=")) {
      out.prefix = a.slice("--prefix=".length);
    } else {
      return { error: `unknown argument: ${a}` };
    }
  }
  return out;
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  if (args.error !== undefined) {
    process.stderr.write(`${args.error}\n${USAGE}`);
    process.exit(64);
  }
  const { exitCode, report } = await checkConfigFromSsm({
    region: args.region,
    prefix: args.prefix,
    env: process.env,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCode);
}
