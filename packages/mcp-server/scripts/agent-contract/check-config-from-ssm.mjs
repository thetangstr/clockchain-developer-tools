#!/usr/bin/env node
/**
 * check-config-from-ssm (N7c) — pulls the `/clockchain/mcp/<NAME>` SSM
 * parameters for the whole contract env surface into process.env ONLY
 * (never disk, never stdout), then runs the SAME readiness check as
 * check-config.mjs and prints its redacted report plus a `parameters`
 * map of NAME → "present"|"absent".
 *
 *   node scripts/agent-contract/check-config-from-ssm.mjs \
 *     [--region us-west-2] [--prefix /clockchain/mcp] [--state-dir <dir>]
 *
 * Exit codes:  0 ready · 1 misconfigured/refused/ssm-failure · 2 disabled.
 *
 * It also reads the sink's SINK_PARAMETERS (never into env) and adds a
 * `sink` verdict block; an invalid sink value is a refusal (exit 1).
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
  // CDT wiring (default-off; absent == the b04059e surface). Same order as
  // infra/clockchain-mcp/compose-up.sh reads them.
  "TELEMETRY_LANES", "TELEMETRY_SINK_KEY_ID", "CONTRACT_DIRECTORY", "CONTRACT_MAX_RUNS_PER_KEY",
  "CONTRACT_POLICY_REGISTRATION", "CONTRACT_SERVER_ANCHORS", "CONTRACT_EXPIRE_AT_TTL",
  "CONTRACT_BRIEFS", "CONTRACT_BRIEFS_DIR", "CONTRACT_ROLE_BRIEFS",
];

/**
 * The telemetry-sink parameters sink-up.sh reads (the sink container's env,
 * not the mcp's). Fetched for a verdict only — NEVER written into env.
 */
export const SINK_PARAMETERS = ["TELEMETRY_CONTRACT_KEYS", "TELEMETRY_RUN_SET_HEAD"];

/** Fetch one optional parameter: value, or undefined on ParameterNotFound. */
async function fetchOptional(fetchParameter, region, name) {
  try {
    return await fetchParameter({ region, name });
  } catch (err) {
    if (err instanceof Error && err.name === "ParameterNotFound") return undefined;
    throw err;
  }
}

/**
 * Sink verdicts (names, on/off, keyIds-present booleans — never a value).
 * `refusals` mirror what sink-up.sh would refuse BEFORE building the sink.
 */
export async function checkSinkFromSsm({ region, prefix = "/clockchain/mcp", fetchParameter = fetchParameterAws, signerKeyId } = {}) {
  const values = {};
  const parameters = {};
  for (const name of SINK_PARAMETERS) {
    values[name] = await fetchOptional(fetchParameter, region, `${prefix}/${name}`);
    parameters[name] = values[name] === undefined ? "absent" : "present";
  }
  const refusals = [];
  const rsh = values.TELEMETRY_RUN_SET_HEAD;
  let runSetHead;
  if (rsh === undefined) runSetHead = "absent";
  else if (rsh === "" || rsh === "0") runSetHead = "off";
  else if (rsh === "1") runSetHead = "on";
  else {
    runSetHead = "invalid";
    refusals.push("TELEMETRY_RUN_SET_HEAD wants 0 or 1 (sink-up.sh refuses before build)");
  }
  let contractKeys = "absent";
  let signerKeyPublished = null;
  if (values.TELEMETRY_CONTRACT_KEYS !== undefined) {
    let parsed;
    try { parsed = JSON.parse(values.TELEMETRY_CONTRACT_KEYS); } catch { parsed = undefined; }
    const ok = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      && Object.keys(parsed).length > 0
      && Object.values(parsed).every((v) => typeof v === "string" || (v !== null && typeof v === "object" && !("d" in v)));
    if (ok) {
      contractKeys = "valid";
      if (signerKeyId !== undefined) signerKeyPublished = Object.hasOwn(parsed, signerKeyId);
    } else {
      contractKeys = "invalid";
      refusals.push("TELEMETRY_CONTRACT_KEYS is not a non-empty {keyId: public key} object (sink-up.sh refuses)");
    }
  }
  return { parameters, runSetHead, contractKeys, signerKeyPublished, refusals };
}

/**
 * AWS-backed fetch: ONE GetParameterCommand for `name` with WithDecryption
 * (N11f: per-name, because the box role is granted ssm:GetParameter on the
 * prefix but not ssm:GetParameters). Lazily imports the SDK so loading this
 * module performs no AWS calls — tests inject `fetchParameter` and never
 * need the package. Returns the value, or undefined when the parameter does
 * not exist.
 */
async function fetchParameterAws({ region, name }) {
  const { SSMClient, GetParameterCommand } = await import("@aws-sdk/client-ssm");
  const client = new SSMClient({ region });
  try {
    const res = await client.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
    return typeof res.Parameter?.Value === "string" ? res.Parameter.Value : undefined;
  } catch (err) {
    if (err instanceof Error && err.name === "ParameterNotFound") return undefined;
    throw err;
  }
}

/**
 * Fetch `${prefix}/<NAME>` for every name in ENV_PARAMETERS (one
 * GetParameter each) and write the present ones into `env`. Values are never
 * logged. Returns { NAME: "present" | "absent" } for the full surface. A
 * ParameterNotFound counts as absent; any other error propagates.
 */
export async function loadEnvFromSsm({
  region,
  prefix = "/clockchain/mcp",
  env = process.env,
  fetchParameter = fetchParameterAws,
} = {}) {
  const parameters = {};
  for (const name of ENV_PARAMETERS) {
    let value;
    try {
      value = await fetchParameter({ region, name: `${prefix}/${name}` });
    } catch (err) {
      if (!(err instanceof Error && err.name === "ParameterNotFound")) throw err;
    }
    if (value !== undefined) {
      env[name] = value;
      parameters[name] = "present";
    } else {
      parameters[name] = "absent";
    }
  }
  return parameters;
}

/**
 * loadEnvFromSsm + checkConfig(env). A fetch failure is reported with the
 * checker's own convention (exit 1, status misconfigured) and carries only
 * the error NAME — SDK messages can echo request detail we keep off stdout.
 */
export async function checkConfigFromSsm({ region, prefix, env, fetchParameter, stateDir } = {}) {
  const target = env ?? process.env;
  let parameters;
  try {
    parameters = await loadEnvFromSsm({ region, prefix, env: target, fetchParameter });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    return {
      exitCode: 1,
      report: { status: "misconfigured", reason: `ssm fetch failed (${name})` },
    };
  }
  // N11f: --state-dir wins over the pulled CONTRACT_STATE_DIR so the probe can
  // use a scratch dir (the live dir is lock-held by the running service).
  if (stateDir !== undefined) target.CONTRACT_STATE_DIR = stateDir;
  const { exitCode, report } = await checkConfig(target);
  let sink;
  try {
    sink = await checkSinkFromSsm({
      region, prefix, fetchParameter, signerKeyId: report.signer?.keyId,
    });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    return { exitCode: 1, report: { status: "misconfigured", reason: `ssm fetch failed (${name})`, parameters } };
  }
  const out = { ...report, parameters, sink };
  // Lanes close on the sink: the sink must hold this server's PUBLIC key.
  if (report.features?.telemetryLanes === "on") {
    const warnings = [...(out.warnings ?? [])];
    if (sink.contractKeys === "absent") {
      warnings.push("TELEMETRY_LANES=1 but TELEMETRY_CONTRACT_KEYS is absent: the sink cannot verify lane opens/closes");
    } else if (sink.signerKeyPublished === false) {
      warnings.push("TELEMETRY_LANES=1 but TELEMETRY_CONTRACT_KEYS does not carry this server's signer keyId");
    }
    out.warnings = warnings;
  }
  if (sink.refusals.length > 0) {
    out.status = "refused";
    out.refusals = [...(out.refusals ?? []), ...sink.refusals];
    return { exitCode: 1, report: out };
  }
  return { exitCode, report: out };
}

const USAGE = `usage: node check-config-from-ssm.mjs [--region <r>] [--prefix <p>] [--state-dir <d>]
  --region   AWS region (default $AWS_REGION else us-west-2)
  --prefix   SSM parameter prefix (default /clockchain/mcp)
  --state-dir  override CONTRACT_STATE_DIR (probe a scratch dir, not the live one)
Reads <prefix>/<NAME> for the contract env surface into process.env,
then prints the same redacted report as check-config.mjs.
`;

export function parseArgs(argv, env = process.env) {
  const out = { region: env.AWS_REGION ?? "us-west-2", prefix: "/clockchain/mcp" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
    } else if (a === "--region" || a === "--prefix" || a === "--state-dir") {
      const value = argv[++i];
      if (value === undefined) return { error: `${a} wants a value` };
      out[a === "--state-dir" ? "stateDir" : a.slice(2)] = value;
    } else if (a.startsWith("--region=")) {
      out.region = a.slice("--region=".length);
    } else if (a.startsWith("--state-dir=")) {
      out.stateDir = a.slice("--state-dir=".length);
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
    stateDir: args.stateDir,
    env: process.env,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCode);
}
