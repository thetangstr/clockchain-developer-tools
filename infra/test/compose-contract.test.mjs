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
  "CONTRACT_OBSERVER_PER_KEY_PER_MINUTE",
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
  "CONTRACT_PRIVATE_FLOOR", "CONTRACT_PRIVATE_FLOOR_BPS",
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

test("/metrics: the token reaches the mcp service from an optional SSM secret, so absent means the route stays 404", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  assert.match(mcpBlock, /^\s+MCP_METRICS_TOKEN:\s*"\$\{MCP_METRICS_TOKEN:-\}"\s*$/m);
  assert.match(up, /^read_optional_secret MCP_METRICS_TOKEN \/clockchain\/mcp\/MCP_METRICS_TOKEN$/m);
});

test("hosted Shadow: the mcp service carries SHADOW_* (empty default = off) and compose-up reads each optionally", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  for (const name of ["SHADOW_NETWORK", "MCP_MAX_OPEN_STREAMS", "MCP_MAINNET_FREE_TOKENS", "SHADOW_IDLE_CLOSE_HOURS", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_MAX_BYTES", "SHADOW_ACCOUNT_MAX_BYTES", "SHADOW_SESSION_STARTS_PER_DAY", "SHADOW_LINK_CONCURRENCY", "SHADOW_LAZY_AUTH", "SHADOW_ANON_PER_MINUTE", "SHADOW_AUTO_LOG", "SHADOW_ANCHORS_PER_DAY", "SHADOW_ANCHORS_PER_SESSION", "SHADOW_LOG_STEPS_PER_MIN", "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_LEDGER_CLIENT_ID", "SHADOW_LEDGER_WALLET_ID", "OPENAI_APPS_CHALLENGE_TOKEN", "MCP_BYO_WRITES"]) {
    assert.match(mcpBlock, new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"), `mcp environment must carry ${name}`);
    assert.match(up, new RegExp(`^read_optional_env ${name} /clockchain/mcp/${name}$`, "m"), `compose-up must read ${name} optionally`);
    assert.doesNotMatch(up, new RegExp(`^read_(secret|optional_secret|required_env) ${name} `, "m"), name);
  }
  // Only the mcp service sees it, and its state stays on the mcp_state volume.
  assert.equal(source.match(/^\s+SHADOW_ENABLED:/gm)?.length, 1);
  // The test-only override that lets non-account tokens use /shadow/mcp never reaches production.
  assert.doesNotMatch(source, /SHADOW_ALLOW_NON_ACCT/);
  assert.doesNotMatch(up, /SHADOW_ALLOW_NON_ACCT/);
  assert.match(mcpBlock, /- mcp_state:\/app\/state/);
});

test("OAuth sign-in: the mcp service carries MCP_OAUTH* and compose-up reads each knob optionally, never turning it on", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  for (const name of ["MCP_OAUTH", "MCP_OAUTH_APPROVALS_PER_HOUR", "MCP_OAUTH_ACCOUNTS_PER_HOUR", "MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR", "MCP_OAUTH_KEY_ATTEMPTS_PER_IP_PER_HOUR"]) {
    assert.match(mcpBlock, new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"), `mcp environment must carry ${name}`);
    assert.match(up, new RegExp(`^read_optional_env ${name} /clockchain/mcp/${name}$`, "m"), `compose-up must read ${name} optionally`);
    assert.doesNotMatch(up, new RegExp(`^(export ${name}=|read_(secret|optional_secret|required_env) ${name} )`, "m"), name);
  }
  // Approval rate limits trust X-Forwarded-For only from Caddy's fixed edge address.
  assert.match(mcpBlock, /^\s+MCP_OAUTH_TRUSTED_PROXY:\s*"172\.30\.0\.3"\s*$/m);
  assert.match(source, /ipv4_address: 172\.30\.0\.3/);
});

test("CDT wiring: compose-up reads every new contract setting optionally and compose passes it through", async () => {
  assert.equal(CDT_FEATURE_ENV_NAMES.length, 14);
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

// H-REQ-01 phase 1. The mcp carries the coordinator's sender-enrollment key
// (optional; "" == absent == enrollments off). The host carries the relay
// binding, off unless set (the host's own default when unset is enforce, so
// an unset or empty value must never reach it), and the coordinator key ring
// only when it is set: a value-less entry leaves an unset variable unset in
// the container, because the host parses any value it is given.
test("H-REQ-01: the enrollment key reaches only mcp; the relay binding (default off) and key ring (only when set) reach only the host", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const hostBlock = source.slice(source.indexOf("  host:"), source.indexOf("  telemetry-sink:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");

  assert.match(mcpBlock, /^\s+AGENT_HANDSHAKE_V2_ENROLLMENT_KEY:\s*"\$\{AGENT_HANDSHAKE_V2_ENROLLMENT_KEY:-\}"\s*$/m);
  assert.match(hostBlock, /^\s+AGENT_HANDSHAKE_V2_RELAY_BINDING:\s*"\$\{AGENT_HANDSHAKE_V2_RELAY_BINDING:-off\}"\s*$/m);
  assert.match(hostBlock, /^\s+AGENT_HANDSHAKE_V2_COORDINATOR_KEYS:\s*$/m);
  assert.doesNotMatch(hostBlock, /AGENT_HANDSHAKE_V2_ENROLLMENT_KEY/);
  assert.doesNotMatch(mcpBlock, /AGENT_HANDSHAKE_V2_RELAY_BINDING|AGENT_HANDSHAKE_V2_COORDINATOR_KEYS/);

  for (const name of ["AGENT_HANDSHAKE_V2_ENROLLMENT_KEY", "AGENT_HANDSHAKE_V2_RELAY_BINDING", "AGENT_HANDSHAKE_V2_COORDINATOR_KEYS"]) {
    assert.match(up, new RegExp(`^${name}_PARAM="\\$\\{${name}_PARAM:-/clockchain/mcp/${name}\\}"$`, "m"), `${name} SSM name`);
    assert.doesNotMatch(up, new RegExp(`^read_(secret|required_env) ${name} `, "m"), `${name} is never a required read`);
  }
  assert.match(up, /^read_optional_secret AGENT_HANDSHAKE_V2_ENROLLMENT_KEY "\$AGENT_HANDSHAKE_V2_ENROLLMENT_KEY_PARAM"$/m);
  assert.match(up, /^read_optional_env AGENT_HANDSHAKE_V2_RELAY_BINDING "\$AGENT_HANDSHAKE_V2_RELAY_BINDING_PARAM"$/m);
  assert.match(up, /^read_optional_env AGENT_HANDSHAKE_V2_COORDINATOR_KEYS "\$AGENT_HANDSHAKE_V2_COORDINATOR_KEYS_PARAM"$/m);
});

test("the comment on SHADOW_AUTO_LOG states the defaults the server uses", async () => {
  const text = (await readFile(composeFile, "utf8")).replace(/\s*#\s*/g, " ");
  assert.match(text, /anchors default to 400 per account per day and 300 per session \(without it, 60 and 100\), and shadow_log_step to 90 calls per account per minute/);
});

// Agent keys (packages/mcp-server/src/oauth.ts, src/shadow/service.ts): each setting reaches only the mcp service with an
// empty default, and the server reads "" exactly like unset (MCP_AGENT_KEYS "" = off; a limit "" = its default).
const AGENT_KEY_ENV_NAMES = [
  "MCP_AGENT_KEYS",
  "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR",
  "MCP_AGENT_KEYS_NEW_PER_HOUR",
  "SHADOW_STARTER_ANCHORS_PER_DAY",
  "SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY",
];

test("agent keys: the mcp service carries the five settings (empty default = off) and compose-up reads each optionally", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  for (const name of AGENT_KEY_ENV_NAMES) {
    assert.match(mcpBlock, new RegExp(`^\\s+${name}:\\s*"\\$\\{${name}:-\\}"\\s*$`, "m"), `mcp environment must carry ${name}`);
    assert.equal(source.match(new RegExp(`^\\s+${name}:`, "gm"))?.length, 1, `${name} reaches only mcp`);
    assert.match(up, new RegExp(`^read_optional_env ${name} /clockchain/mcp/${name}$`, "m"), `compose-up must read ${name} optionally`);
    assert.doesNotMatch(up, new RegExp(`^\\s*(export ${name}=|read_(secret|optional_secret|required_env) ${name} )`, "m"), name);
  }
});

// The witness key (SHADOW_WITNESS_KEY_FILE): with /clockchain/mcp/SHADOW_WITNESS_KEY absent there is no mount, no mount
// source and no value. compose-up.sh writes the key file and adds docker-compose.witness.yml only when the parameter exists.
test("witness key: empty in the base file; only the override sets the fixed path and mounts the key read-only", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcpBlock = source.slice(source.indexOf("  mcp:"), source.indexOf("  host:"));
  assert.match(mcpBlock, /^\s+SHADOW_WITNESS_KEY_FILE:\s*"\$\{SHADOW_WITNESS_KEY_FILE:-\}"\s*$/m);
  assert.equal(source.match(/^\s+SHADOW_WITNESS_KEY_FILE:/gm)?.length, 1);
  assert.doesNotMatch(source, /\/app\/witness|clockchain-mcp-witness|CLOCKCHAIN_MCP_WITNESS_DIR/, "the base file never mounts the witness key");
  const mcpVolumes = mcpBlock.slice(mcpBlock.indexOf("    volumes:"), mcpBlock.indexOf("    expose:"));
  assert.deepEqual(mcpVolumes.match(/^\s+- .+$/gm)?.map((l) => l.trim()), ["- mcp_state:/app/state"]);

  const override = await readFile(new URL("../clockchain-mcp/docker-compose.witness.yml", import.meta.url), "utf8");
  const body = override.replace(/^\s*#.*$/gm, "").replace(/\n\s*\n/g, "\n").trim();
  assert.equal(
    body,
    [
      "services:",
      "  mcp:",
      "    environment:",
      "      SHADOW_WITNESS_KEY_FILE: /app/witness/witness-key.pem",
      "    volumes:",
      "      - ${CLOCKCHAIN_MCP_WITNESS_DIR:-/run/clockchain-mcp-witness}:/app/witness:ro",
    ].join("\n"),
    "the override touches only mcp: the fixed in-container path and one read-only mount",
  );
});

test("witness key: compose-up reads the key optionally, never takes the path from SSM, and adds the override only with the key", async () => {
  const up = await readFile(new URL("../clockchain-mcp/compose-up.sh", import.meta.url), "utf8");
  assert.match(up, /^SHADOW_WITNESS_KEY_PARAM="\$\{SHADOW_WITNESS_KEY_PARAM:-\/clockchain\/mcp\/SHADOW_WITNESS_KEY\}"$/m);
  assert.match(up, /^CLOCKCHAIN_MCP_WITNESS_DIR="\$\{CLOCKCHAIN_MCP_WITNESS_DIR:-\/run\/clockchain-mcp-witness\}"$/m);
  // The path is fixed by the override; an inherited value can never point mcp at a file that isn't mounted.
  assert.match(up, /^unset SHADOW_WITNESS_KEY_FILE$/m);
  assert.doesNotMatch(up, /read_[a-z_]+ SHADOW_WITNESS_KEY_FILE|export SHADOW_WITNESS_KEY_FILE|SHADOW_WITNESS_KEY_FILE=/);
  assert.doesNotMatch(up, /^read_(secret|optional_secret|optional_env) SHADOW_WITNESS_KEY\b/m, "the PEM is never exported into the environment");
  assert.match(up, /^materialize_witness_key$/m);
  const fn = up.slice(up.indexOf("materialize_witness_key() {"), up.indexOf("\n}\n", up.indexOf("materialize_witness_key() {")));
  assert.match(fn, /ParameterNotFound/);
  assert.match(fn, /COMPOSE_FILES\+=\(-f "\$WITNESS_COMPOSE_FILE"\)/);
  assert.equal(up.match(/COMPOSE_FILES\+=/g)?.length, 1, "the override is added in one place only");
  // Both modes recreate mcp, so both use the same file list.
  for (const line of up.split("\n").filter((l) => /exec docker compose/.test(l))) {
    assert.match(line, /docker compose "\$\{COMPOSE_FILES\[@\]\}" up /, line);
  }
});
