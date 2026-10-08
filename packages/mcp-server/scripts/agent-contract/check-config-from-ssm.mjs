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
 *     [--expect-sha <40-hex>] [--allow-local-briefs-dir]
 *
 * Exit codes:  0 ready · 1 misconfigured/refused/ssm-failure · 2 disabled.
 *
 * Every ENV_PARAMETERS name is cleared from the env before the SSM values are
 * loaded, so an absent parameter is absent for the check too (never inherited
 * from the operator's shell).
 *
 * It also reads the sink's SINK_PARAMETERS (never into env, and without
 * decryption, exactly as sink-up.sh reads them) and adds a `sink` verdict
 * block; an invalid sink value is a refusal (exit 1).
 *
 * CONTRACT_BRIEFS_DIR must be IMAGE_BRIEFS_DIR; the committed brief files in
 * this checkout are then checked against their pinned digests
 * (`briefsDir: "image"`). Any other path is refused unless
 * --allow-local-briefs-dir (local use only; never against production SSM).
 *
 * --expect-sha ties the verdict to the deployed commit: it refuses unless this
 * checkout's HEAD is that sha and packages/mcp-server has no uncommitted
 * change (`checkout: "pinned"`; without the flag `checkout: "unpinned"`).
 * dist/ is not tracked, so build it at that sha before the check.
 *
 * No parameter VALUE is ever printed — the report adds names only. A refusal
 * names the setting and may name a brief (names are not secret); never a
 * brief's text, its digest or a local path.
 */

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { checkConfig } from "./check-config.mjs";

/**
 * The frozen brief files ship IN THE IMAGE: they are committed under
 * packages/mcp-server/assets/briefs/<name>.md and the Dockerfile's runtime
 * stage copies packages/mcp-server/assets to this path. No compose volume, no
 * box-side file write, no extra deploy-box drift file.
 */
export const IMAGE_BRIEFS_DIR = "/app/packages/mcp-server/assets/briefs";
/** This checkout's root (scripts/agent-contract → packages/mcp-server → packages → root). */
const CHECKOUT_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

/**
 * The checker runs on the operator's machine from the W checkout, where
 * the image's /app is this checkout. Map the image briefs dir onto it so the
 * committed files are checked against their pinned digests exactly as the
 * container will check them. Any other path is refused: another /app/ path is
 * a dir this checker cannot see (e.g. the mcp_state volume), and a host path
 * would hash this machine's disk, not the box's. `allowLocal` (the
 * --allow-local-briefs-dir flag, local use only) lets a non-/app path through.
 *   → { dir } | { refusal } | {} (nothing to do)
 */
export function briefsDirForCheck(raw, checkoutRoot = CHECKOUT_ROOT, { allowLocal = false } = {}) {
  const dir = (raw ?? "").trim();
  if (dir === "") return {};
  if (dir === IMAGE_BRIEFS_DIR) {
    return { dir: path.join(checkoutRoot, "packages", "mcp-server", "assets", "briefs"), source: "image" };
  }
  if (allowLocal && !dir.startsWith("/app/")) return { dir, source: "local" };
  return { refusal: `CONTRACT_BRIEFS_DIR must be ${IMAGE_BRIEFS_DIR} (briefs committed in the checkout and shipped in the image)` };
}

/**
 * --expect-sha: the checkout must BE the commit being deployed. Refuses unless
 * HEAD equals `expectSha` and packages/mcp-server (the brief files and this
 * checker) has no uncommitted or untracked change. `git` is injectable for tests.
 *   → { checkout: "pinned" } | { refusal }
 */
export function checkoutAtSha(expectSha, checkoutRoot = CHECKOUT_ROOT, git = gitOutput) {
  if (!/^[0-9a-f]{40}$/.test(expectSha ?? "")) {
    return { refusal: "--expect-sha wants the full 40-hex commit sha" };
  }
  let head;
  let dirty;
  try {
    head = git(checkoutRoot, ["rev-parse", "HEAD"]).trim();
    dirty = git(checkoutRoot, ["status", "--porcelain", "--", "packages/mcp-server"]).trim();
  } catch {
    return { refusal: "--expect-sha: this checkout is not a readable git checkout" };
  }
  if (head !== expectSha) {
    return { refusal: `checkout HEAD ${head.slice(0, 12)} is not --expect-sha ${expectSha.slice(0, 12)}` };
  }
  if (dirty !== "") {
    return { refusal: "packages/mcp-server has uncommitted or untracked changes; the verdict would not describe --expect-sha" };
  }
  return { checkout: "pinned" };
}

function gitOutput(cwd, args) {
  return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

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
  "CONTRACT_CALLS_PER_MINUTE", "CONTRACT_OBSERVER_PER_MINUTE", "CONTRACT_OBSERVER_PER_KEY_PER_MINUTE", "CONTRACT_MAX_RUNS",
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
  // Milestone log (default-off; absent == today's behaviour).
  "CONTRACT_MILESTONE_LOG",
  "CONTRACT_FLEX_POLICY",
  "CONTRACT_PRIVATE_FLOOR", "CONTRACT_PRIVATE_FLOOR_BPS",
];

/**
 * The telemetry-sink parameters sink-up.sh reads (the sink container's env,
 * not the mcp's). Fetched for a verdict only — NEVER written into env.
 */
export const SINK_PARAMETERS = ["TELEMETRY_CONTRACT_KEYS", "TELEMETRY_RUN_SET_HEAD"];

/** Fetch one optional parameter: value, or undefined on ParameterNotFound. */
async function fetchOptional(fetchParameter, region, name, withDecryption = true) {
  try {
    return await fetchParameter({ region, name, withDecryption });
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
    // sink-up.sh reads these WITHOUT --with-decryption: read them the same way, so a
    // SecureString (ciphertext there) fails here too instead of passing on plaintext.
    values[name] = await fetchOptional(fetchParameter, region, `${prefix}/${name}`, false);
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
 * AWS-backed fetch: ONE GetParameterCommand for `name`, WithDecryption unless
 * `withDecryption` is false (N11f: per-name, because the box role is granted
 * ssm:GetParameter on the prefix but not ssm:GetParameters). Lazily imports the SDK so loading this
 * module performs no AWS calls — tests inject `fetchParameter` and never
 * need the package. Returns the value, or undefined when the parameter does
 * not exist.
 */
async function fetchParameterAws({ region, name, withDecryption = true }) {
  const { SSMClient, GetParameterCommand } = await import("@aws-sdk/client-ssm");
  const client = new SSMClient({ region });
  try {
    const res = await client.send(new GetParameterCommand({ Name: name, WithDecryption: withDecryption }));
    return typeof res.Parameter?.Value === "string" ? res.Parameter.Value : undefined;
  } catch (err) {
    if (err instanceof Error && err.name === "ParameterNotFound") return undefined;
    throw err;
  }
}

/**
 * Fetch `${prefix}/<NAME>` for every name in ENV_PARAMETERS (one
 * GetParameter each) and write the present ones into `env`. Every
 * ENV_PARAMETERS name is first deleted from `env`, so an absent parameter is
 * absent for the check, exactly as compose passes it to the container (a
 * leftover shell value must not give a false `ready`). Values are never
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
  for (const name of ENV_PARAMETERS) delete env[name];
  for (const name of ENV_PARAMETERS) {
    let value;
    try {
      value = await fetchParameter({ region, name: `${prefix}/${name}`, withDecryption: true });
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
export async function checkConfigFromSsm({
  region, prefix, env, fetchParameter, stateDir, checkoutRoot, expectSha, allowLocalBriefsDir = false, git,
} = {}) {
  const target = env ?? process.env;
  let checkout = "unpinned";
  if (expectSha !== undefined) {
    const pinned = checkoutAtSha(expectSha, checkoutRoot ?? CHECKOUT_ROOT, git);
    if (pinned.refusal !== undefined) {
      return { exitCode: 1, report: { status: "refused", reason: pinned.refusal, checkout: "mismatch" } };
    }
    checkout = pinned.checkout;
  }
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
  // CDT wiring: CONTRACT_BRIEFS_DIR names a path inside the image; check the
  // committed files it will hold (names and verdicts only, never the path or text).
  let briefsDir = "absent";
  if ((target.CONTRACT_BRIEFS ?? "").trim() !== "") {
    const mapped = briefsDirForCheck(target.CONTRACT_BRIEFS_DIR, checkoutRoot, { allowLocal: allowLocalBriefsDir });
    if (mapped.refusal !== undefined) {
      return { exitCode: 1, report: { status: "misconfigured", reason: mapped.refusal, parameters, checkout } };
    }
    if (mapped.dir !== undefined) {
      target.CONTRACT_BRIEFS_DIR = mapped.dir;
      briefsDir = mapped.source;
    }
  }
  const { exitCode, report } = await checkConfig(target);
  let sink;
  try {
    sink = await checkSinkFromSsm({
      region, prefix, fetchParameter, signerKeyId: report.signer?.keyId,
    });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    return { exitCode: 1, report: { status: "misconfigured", reason: `ssm fetch failed (${name})`, parameters, checkout } };
  }
  const out = { ...report, parameters, briefsDir, sink, checkout };
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
                                  [--expect-sha <40-hex>] [--allow-local-briefs-dir]
  --region   AWS region (default $AWS_REGION else us-west-2)
  --prefix   SSM parameter prefix (default /clockchain/mcp)
  --state-dir  override CONTRACT_STATE_DIR (probe a scratch dir, not the live one)
  --expect-sha  refuse unless this checkout's HEAD is <sha> and packages/mcp-server is clean
  --allow-local-briefs-dir  accept a host CONTRACT_BRIEFS_DIR (local use only, never production)
Reads <prefix>/<NAME> for the contract env surface into process.env,
then prints the same redacted report as check-config.mjs.
`;

export function parseArgs(argv, env = process.env) {
  const out = { region: env.AWS_REGION ?? "us-west-2", prefix: "/clockchain/mcp" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
    } else if (a === "--allow-local-briefs-dir") {
      out.allowLocalBriefsDir = true;
    } else if (a === "--region" || a === "--prefix" || a === "--state-dir" || a === "--expect-sha") {
      const value = argv[++i];
      if (value === undefined) return { error: `${a} wants a value` };
      out[{ "--state-dir": "stateDir", "--expect-sha": "expectSha" }[a] ?? a.slice(2)] = value;
    } else if (a.startsWith("--expect-sha=")) {
      out.expectSha = a.slice("--expect-sha=".length);
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
    expectSha: args.expectSha,
    allowLocalBriefsDir: args.allowLocalBriefsDir === true,
    env: process.env,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCode);
}
