import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const composeFile = path.resolve(new URL("../clockchain-mcp/docker-compose.yml", import.meta.url).pathname);

test("compose carries only server-side v2 configuration into persistent services", async () => {
  const source = await readFile(composeFile, "utf8");
  for (const name of [
    "AGENT_HANDSHAKE_RELEASE_PIN",
    "AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE",
    "AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS",
    "AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE",
    "AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS",
    "AGENT_HANDSHAKE_V2_INVITATION_FILE",
    "AGENT_HANDSHAKE_V2_STATE_FILE",
    "AGENT_HANDSHAKE_INVITES_PER_HOUR",
    "AGENT_HANDSHAKE_CALLS_PER_MINUTE",
    "AGENT_HANDSHAKE_TRUSTED_PROXY",
  ]) assert.match(source, new RegExp(`${name}:`));
  assert.match(source, /AGENT_HANDSHAKE_V2_INVITATION_FILE:\s*\/app\/state\/agent-handshake-v2-invitations\.json/);
  assert.match(source, /AGENT_HANDSHAKE_V2_STATE_FILE:\s*\/app\/state\/agent-handshake-v2-state\.json/);
  assert.match(source, /AGENT_HANDSHAKE_INVITES_PER_HOUR:\s*"20"/);
  assert.match(source, /AGENT_HANDSHAKE_CALLS_PER_MINUTE:\s*"120"/);
  assert.match(source, /AGENT_HANDSHAKE_TRUSTED_PROXY:\s*"172\.30\.0\.3"/);
  assert.doesNotMatch(source, /responderAccess|initiatorAccess|rawInvitation|privateKeyPem/);
});

test("the v2 host uses a private root file and restart-safe bounded funding state", async () => {
  const source = await readFile(composeFile, "utf8");
  assert.match(source, /command:\s*\["node",\s*"bin\/agent-handshake-host\.mjs"\]/);
  assert.match(source, /AGENT_HANDSHAKE_PROTOCOL:\s*"clockchain\.agent-handshake\/v2"/);
  assert.match(source, /CLOCKCHAIN_HOST_ROOT_KEY_FILE:\s*\/app\/keys\/agent-handshake-v2-host-root\.pem/);
  assert.match(source, /CLOCKCHAIN_HOST_ROOT_KEY_ID:/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_LEDGER:\s*\/app\/runs\/private\/v2-funding-ledger\.jsonl/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT:\s*"16"/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_ALERT_HOURLY_ETH:\s*"0\.16"/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_ALERT_DAILY_ETH:\s*"0\.80"/);
  assert.match(source, /host_runs:\/app\/runs/);
  assert.match(source, /\/app\/keys:ro/);
});

// N7c: the /contract/mcp env surface — the same name list as
// packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs
// (ENV_PARAMETERS; CONTRACT_OBSERVER_PER_MINUTE is read in src/http.ts).
// compose-up.sh reads each /clockchain/mcp/<NAME> parameter only when it
// exists, so a host-unset var injects "" here — config.ts normalizes ""
// exactly like absent.
const CONTRACT_ENV_NAMES = [
  "CONTRACT_MCP_ENABLED",
  "CONTRACT_AUTH_TOKENS",
  "CONTRACT_HOST_ROOTS",
  "CONTRACT_SERVER_ED25519_SEED",
  "CONTRACT_SERVER_KEY_ID",
  "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_VALID_FROM",
  "CONTRACT_SERVER_KEY_VALID_UNTIL",
  "CONTRACT_POLICY_DIGESTS",
  "CONTRACT_PRINCIPALS",
  "CONTRACT_OBSERVER_TOKEN",
  "CONTRACT_VERIFIER_TOKEN",
  "CONTRACT_ALLOW_SIM_FAULTS",
  "CONTRACT_SIM_FAULTS",
  "CONTRACT_LEVEL",
  "CONTRACT_REQUIRE_BIND_STATEMENT",
  "TELEMETRY_CLOSE_URL",
  "TELEMETRY_CLOSE_BACKOFF_MS",
  "TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS",
  "TELEMETRY_CLOSE_DEADLINE_MS",
  "CONTRACT_CALLS_PER_MINUTE",
  "CONTRACT_OBSERVER_PER_MINUTE",
  "CONTRACT_MAX_RUNS",
  "CONTRACT_MAX_RECEIPTS_PER_RUN",
  "CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL",
  "CONTRACT_RUN_TTL_MS",
  "CONTRACT_CERT_GRACE_MS",
  "CONTRACT_SESSION_TTL_MS",
  "CONTRACT_STATE_DIR",
  "CONTRACT_ERC8004_CHAIN_ID",
  "CONTRACT_ERC8004_REGISTRY_ADDRESS",
  "CONTRACT_ANCHOR_ENABLED",
  "CONTRACT_SETTLEMENT_RAIL",
  "CONTRACT_TRUST_PROXY",
  // CDT wiring (default-off; see CDT_FEATURE_ENV_NAMES below).
  "TELEMETRY_LANES",
  "TELEMETRY_SINK_KEY_ID",
  "CONTRACT_DIRECTORY",
  "CONTRACT_MAX_RUNS_PER_KEY",
  "CONTRACT_POLICY_REGISTRATION",
  "CONTRACT_SERVER_ANCHORS",
  "CONTRACT_EXPIRE_AT_TTL",
  "CONTRACT_BRIEFS",
  "CONTRACT_BRIEFS_DIR",
  "CONTRACT_ROLE_BRIEFS",
  "CONTRACT_MILESTONE_LOG",
  "CONTRACT_FLEX_POLICY",
];

// CDT wiring: the settings b04059e does not read. Each must be an optional SSM
// read in compose-up.sh (absent leaves it unset → compose injects "" → off) and
// a "${NAME:-}" passthrough on the mcp service.
const CDT_FEATURE_ENV_NAMES = CONTRACT_ENV_NAMES.slice(CONTRACT_ENV_NAMES.indexOf("TELEMETRY_LANES"));

test("the mcp service carries the full /contract/mcp environment surface", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  assert.notEqual(mcpBlock.indexOf("environment:"), -1, "mcp service has an environment block");
  for (const name of CONTRACT_ENV_NAMES) {
    assert.match(
      mcpBlock,
      new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"),
      `mcp environment must carry ${name}: "\${${name}:-}" (the :- default silences unset-var warnings)`,
    );
  }
});

// Agent Handshake v2 receipts (opt-in): wired through, read from SSM only when present.
const HANDSHAKE_RECEIPT_ENV_NAMES = [
  "HANDSHAKE_V2_RECEIPTS",
  "HANDSHAKE_V2_RECEIPT_ED25519_SEED",
  "HANDSHAKE_V2_RECEIPT_KEY_ID",
  "HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM",
  "HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL",
  "HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN",
  "HANDSHAKE_V2_RECEIPTS_FILE",
];

test("the mcp service carries the handshake v2 receipts env and compose-up reads each optionally", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  for (const name of HANDSHAKE_RECEIPT_ENV_NAMES) {
    assert.match(mcpBlock, new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"), `mcp environment must carry ${name}`);
    assert.match(up, new RegExp(`^read_optional_env ${name} /clockchain/mcp/${name}$`, "m"), `compose-up must read ${name} optionally`);
  }
});

test("CDT wiring: compose-up reads every new contract setting optionally and compose passes it through", async () => {
  assert.equal(CDT_FEATURE_ENV_NAMES.length, 12);
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  for (const name of CDT_FEATURE_ENV_NAMES) {
    assert.match(mcpBlock, new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"), `mcp environment must carry ${name}`);
    assert.match(up, new RegExp(`^read_optional_env ${name} /clockchain/mcp/${name}$`, "m"), `compose-up must read ${name} optionally`);
    // Never a required read, never a secret read, never a default that turns it on.
    assert.doesNotMatch(up, new RegExp(`^read_(secret|optional_secret|required_env) ${name} `, "m"), name);
    assert.doesNotMatch(mcpBlock, new RegExp(`${name}:\\s*"\\$\\{${name}:-[^}]`), `${name} must have an empty default`);
  }
});

test("the wired contract surface covers check-config-from-ssm ENV_PARAMETERS", async () => {
  const { ENV_PARAMETERS } = await import(
    "../../packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs"
  );
  // Subset, not equality: every name the checker reads must reach the
  // container; a wired extra is benign.
  for (const name of ENV_PARAMETERS) {
    assert.ok(CONTRACT_ENV_NAMES.includes(name), `compose does not wire ${name}`);
  }
});

test("Caddy is the only ingress and has the one trusted internal address", async () => {
  const source = await readFile(composeFile, "utf8");
  assert.doesNotMatch(source, /-\s*"8080:8080"/);
  assert.match(source, /subnet:\s*172\.30\.0\.0\/24/);
  assert.match(source, /ipv4_address:\s*172\.30\.0\.2/);
  assert.match(source, /ipv4_address:\s*172\.30\.0\.3/);
});
