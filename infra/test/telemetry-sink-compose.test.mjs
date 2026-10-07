import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

// D22: the telemetry sink runs on the MCP box as its OWN container, behind
// the `telemetry` compose profile, so the default `docker compose up`,
// compose-up.sh (systemd + deploy-box code-only) and `--only mcp` never
// build, start or recreate it. Production only — no staging sink exists.

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const composeFile = path.join(repoRoot, "infra", "clockchain-mcp", "docker-compose.yml");
const composeUp = path.join(repoRoot, "infra", "clockchain-mcp", "compose-up.sh");

/** Text of one top-level service block (two-space indented key up to the next one). */
function serviceBlock(source, name) {
  const services = source.slice(source.indexOf("services:\n"), source.search(/^volumes:/m));
  const re = new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [\\w-]+:\\n|(?![\\s\\S]))`, "m");
  const match = services.match(re);
  return match ? match[1] : undefined;
}

function envBlock(svc) {
  const m = svc.match(/^    environment:\n((?:^      .*\n)+)/m);
  return m ? m[1] : "";
}

test("telemetry-sink is its own service, built from the sink Dockerfile, behind the telemetry profile", async () => {
  const source = await readFile(composeFile, "utf8");
  const svc = serviceBlock(source, "telemetry-sink");
  assert.ok(svc, "telemetry-sink service exists");
  assert.match(svc, /^    profiles:\s*\["telemetry"\]\s*$/m);
  assert.match(svc, /^    build:\n      context:\s*\.\.\/\.\.\n      dockerfile:\s*packages\/telemetry-sink\/Dockerfile\s*$/m);
  assert.match(svc, /^    user:\s*"10001:10001"\s*$/m);
  assert.match(svc, /^    restart:\s*unless-stopped\s*$/m);
  assert.match(svc, /^      - telemetry_state:\/telemetry\/state\s*$/m);
  assert.doesNotMatch(svc, /mcp_state|host_runs|caddy_data|\/app\/keys|docker\.sock/);
  assert.match(source, /^volumes:\n(?:  .*\n)*  telemetry_state:\s*$/m, "telemetry_state volume declared");
});

test("sink ports are compose-network only: expose 8081/8082/8083, never published", async () => {
  const source = await readFile(composeFile, "utf8");
  const svc = serviceBlock(source, "telemetry-sink");
  assert.ok(svc);
  for (const port of ["8081", "8082", "8083"]) assert.match(svc, new RegExp(`^      - "${port}"\\s*$`, "m"));
  assert.doesNotMatch(svc, /^    ports:/m, "no host-published ports");
  assert.doesNotMatch(source, /"?808[123]:808[123]"?/, "no service publishes a sink port");
  assert.match(svc, /^    networks:\n      - clockchain_edge\s*$/m);
  // HIGH-3: DNS name, no static IP (the edge subnet's .2/.3 are mcp/caddy).
  assert.doesNotMatch(svc, /ipv4_address/);
});

/**
 * Reviewed amendment (cdt-sink, O-1/N4b-8 anchor): the sink may read its
 * anchor bearer from a compose SECRET FILE — never from a plaintext env value.
 *
 *   - Exactly one secret-bearing env name is exempt from the name ban:
 *     TELEMETRY_ANCHOR_TOKEN_FILE, and only with the literal value
 *     /run/secrets/telemetry_anchor_token (a path, not the token).
 *   - When it is present, the sink must list the compose secret
 *     `telemetry_anchor_token`, the top-level secret must be `file:`-sourced
 *     (an `environment:`-sourced secret would put the value back in env),
 *     and TELEMETRY_ANCHOR_MCP_URL must be wired beside it.
 *   - The plaintext TELEMETRY_ANCHOR_TOKEN stays banned everywhere in the file.
 *
 * Every other name/value check is unchanged. Compose itself is NOT wired by
 * this change (a missing secret file would fail the deploy); the anchor
 * switch-on is its own reviewed deploy step.
 */
const ANCHOR_TOKEN_FILE_ENV = "TELEMETRY_ANCHOR_TOKEN_FILE";
const ANCHOR_TOKEN_SECRET_PATH = "/run/secrets/telemetry_anchor_token";

function checkSinkEnvironment(source) {
  const svc = serviceBlock(source, "telemetry-sink") ?? "";
  const env = envBlock(svc);
  assert.match(env, /^      TELEMETRY_ENV:\s*"production"\s*$/m);
  assert.match(env, /^      TELEMETRY_STATE_DIR:\s*\/telemetry\/state\s*$/m);
  assert.match(env, /^      TELEMETRY_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS:-\}"\s*$/m);
  assert.match(env, /^      TELEMETRY_PEER_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS_STAGING:-\}"\s*$/m);
  assert.match(env, /^      TELEMETRY_PEER_ENV:\s*"none"\s*$/m);
  let anchorFile = false;
  for (const line of env.split("\n").filter((l) => l && !/^\s*#/.test(l))) {
    const [, name, value] = line.match(/^      (\w+):\s*(.*)$/) ?? [];
    assert.ok(name, `env line parses: ${line}`);
    if (name === ANCHOR_TOKEN_FILE_ENV) {
      // The single exemption: a fixed secret-mount PATH, never the token.
      assert.match(value, /^"?\/run\/secrets\/telemetry_anchor_token"?$/, `${name} must be ${ANCHOR_TOKEN_SECRET_PATH}`);
      anchorFile = true;
      continue;
    }
    // No key material / tokens by name (the sink generates its key in-container).
    assert.doesNotMatch(name, /SECRET|SEED|PRIVATE|PASSWORD|TOKEN|SIGNING|_KEY$|_KEY_FILE|JWK/i, `env name ${name}`);
    // Values are interpolations or short non-secret literals — never inline key material.
    assert.ok(/^"?\$\{\w+(:-[^}]*)?\}"?$/.test(value) || /^"?[\w./-]{0,40}"?$/.test(value),
      `env ${name} value must be an interpolation or a short literal`);
  }
  // The plaintext anchor token is a secret: never an env value, anywhere.
  assert.doesNotMatch(source, /TELEMETRY_ANCHOR_TOKEN(?!_FILE)/);
  if (anchorFile) {
    assert.match(env, /^      TELEMETRY_ANCHOR_MCP_URL:/m, "the token file needs its URL");
    assert.match(svc, /^    secrets:\n(?:      - .*\n)*      - telemetry_anchor_token\s*$/m, "sink lists the compose secret");
    const top = source.match(/^secrets:\n((?:^  .*\n?)+)/m);
    assert.ok(top, "top-level secrets block declared");
    assert.match(top[1], /^  telemetry_anchor_token:\n    file:\s*\S+/m, "the secret is file-sourced");
    assert.doesNotMatch(top[1], /^    environment:/m, "an env-sourced secret puts the value back in env");
  }
}

test("sink environment: production, public keys from the deploy env, explicit no-peer, no secrets", async () => {
  checkSinkEnvironment(await readFile(composeFile, "utf8"));
});

test("amended env check: only a file-sourced TELEMETRY_ANCHOR_TOKEN_FILE secret passes; plaintext stays banned", async () => {
  const source = await readFile(composeFile, "utf8");
  const anchorLines = (value) =>
    `      TELEMETRY_ANCHOR_MCP_URL: "\${TELEMETRY_ANCHOR_MCP_URL:-}"\n      ${ANCHOR_TOKEN_FILE_ENV}: ${value}\n`;
  const withEnv = (extra, { secrets = "    secrets:\n      - telemetry_anchor_token\n", top = "secrets:\n  telemetry_anchor_token:\n    file: ./secrets/telemetry_anchor_token\n" } = {}) =>
    source
      .replace(/(      TELEMETRY_FLUSH_GRACE_MS:.*\n)/, `$1${extra}`)
      .replace(/(    volumes:\n      - telemetry_state:\/telemetry\/state\n)/, `$1${secrets}`)
      .replace(/^volumes:\n/m, `${top}\nvolumes:\n`);

  // The secret-file form passes.
  checkSinkEnvironment(withEnv(anchorLines(`"${ANCHOR_TOKEN_SECRET_PATH}"`)));
  // Plaintext token env is still refused (by name and by the file-wide ban).
  assert.throws(() => checkSinkEnvironment(withEnv(`      TELEMETRY_ANCHOR_TOKEN: "\${TELEMETRY_ANCHOR_TOKEN:-}"\n`)));
  assert.throws(() => checkSinkEnvironment(withEnv(`      TELEMETRY_ANCHOR_TOKEN: "abc"\n`)));
  // The file env must point at the secret mount, not an arbitrary path or a value.
  assert.throws(() => checkSinkEnvironment(withEnv(anchorLines('"/telemetry/state/anchor"'))));
  assert.throws(() => checkSinkEnvironment(withEnv(anchorLines('"${TELEMETRY_ANCHOR_TOKEN_FILE:-}"'))));
  // Without the sink's secrets entry, or with an env-sourced secret, it fails.
  assert.throws(() => checkSinkEnvironment(withEnv(anchorLines(`"${ANCHOR_TOKEN_SECRET_PATH}"`), { secrets: "" })));
  assert.throws(() => checkSinkEnvironment(withEnv(anchorLines(`"${ANCHOR_TOKEN_SECRET_PATH}"`), {
    top: "secrets:\n  telemetry_anchor_token:\n    environment: TELEMETRY_ANCHOR_TOKEN_VALUE\n",
  })));
  // Other secret-smelling names are still refused even next to the exemption.
  assert.throws(() => checkSinkEnvironment(withEnv(`${anchorLines(`"${ANCHOR_TOKEN_SECRET_PATH}"`)}      OTHER_KEY_FILE: /run/secrets/x\n`)));
});

test("compose carries no inline key material anywhere", async () => {
  const source = await readFile(composeFile, "utf8");
  assert.doesNotMatch(source, /BEGIN [A-Z ]*KEY|"kty"|"[dx]"\s*:|0x[0-9a-fA-F]{64}|OKP|Ed25519/);
});

test("the sink is decoupled from mcp/host/caddy: no depends_on either way", async () => {
  const source = await readFile(composeFile, "utf8");
  for (const name of ["mcp", "host", "caddy"]) {
    const svc = serviceBlock(source, name);
    assert.ok(svc, `${name} service exists`);
    const code = svc.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    assert.doesNotMatch(code, /telemetry-sink/, `${name} must not reference the profile-gated sink`);
  }
  assert.doesNotMatch(serviceBlock(source, "telemetry-sink"), /depends_on/);
});

test("the mcp service keeps the PR #168/#169 close-path wiring unchanged", async () => {
  const source = await readFile(composeFile, "utf8");
  const mcp = serviceBlock(source, "mcp");
  for (const name of [
    "TELEMETRY_CLOSE_URL", "TELEMETRY_CLOSE_BACKOFF_MS",
    "TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS", "TELEMETRY_CLOSE_DEADLINE_MS",
  ]) assert.match(mcp, new RegExp(`^      ${name}:\\s*"\\$\\{${name}(?::-)?\\}"\\s*$`, "m"));
});

test("compose-up.sh (systemd + deploy-box) never activates the telemetry profile", async () => {
  const source = await readFile(composeUp, "utf8");
  assert.doesNotMatch(source, /--profile|COMPOSE_PROFILES|telemetry-sink/);
});

function composeServices(extraArgs) {
  const res = spawnSync("docker", ["compose", "-f", composeFile, ...extraArgs, "config", "--services"], {
    cwd: repoRoot,
    encoding: "utf8",
    // Unset interpolation variables only warn; pin the one build path that must exist.
    env: { ...process.env, HANDSHAKE_APP_ROOT: "/tmp/handshake-app", COMPOSE_PROFILES: "" },
  });
  assert.equal(res.status, 0, res.stderr);
  return res.stdout.split("\n").filter(Boolean).sort();
}

test("docker compose: default config has no sink; --profile telemetry adds exactly telemetry-sink", () => {
  assert.deepEqual(composeServices([]), ["caddy", "host", "mcp"]);
  assert.deepEqual(composeServices(["--profile", "telemetry"]), ["caddy", "host", "mcp", "telemetry-sink"]);
});

// CDT wiring: TELEMETRY_RUN_SET_HEAD (CDT-GAPS gap 4) reaches the sink from the
// deploy env (sink-up.sh reads the optional SSM switch); the new mcp settings
// reach mcp. Absent on the host = "" in the container = off (today's behaviour).
const CDT_MCP_NAMES = [
  "TELEMETRY_LANES", "TELEMETRY_SINK_KEY_ID", "CONTRACT_DIRECTORY", "CONTRACT_MAX_RUNS_PER_KEY",
  "CONTRACT_POLICY_REGISTRATION", "CONTRACT_SERVER_ANCHORS", "CONTRACT_EXPIRE_AT_TTL",
  "CONTRACT_BRIEFS", "CONTRACT_BRIEFS_DIR", "CONTRACT_ROLE_BRIEFS",
];

test("sink environment wires TELEMETRY_RUN_SET_HEAD with an empty default", async () => {
  const env = envBlock(serviceBlock(await readFile(composeFile, "utf8"), "telemetry-sink") ?? "");
  assert.match(env, /^      TELEMETRY_RUN_SET_HEAD:\s*"\$\{TELEMETRY_RUN_SET_HEAD:-\}"\s*$/m);
});

function composeConfigJson(extraEnv) {
  const base = { ...process.env, HANDSHAKE_APP_ROOT: "/tmp/handshake-app", COMPOSE_PROFILES: "" };
  for (const name of [...CDT_MCP_NAMES, "TELEMETRY_RUN_SET_HEAD"]) delete base[name];
  const res = spawnSync("docker", ["compose", "-f", composeFile, "--profile", "telemetry", "config", "--format", "json"], {
    cwd: repoRoot, encoding: "utf8", env: { ...base, ...extraEnv },
  });
  assert.equal(res.status, 0, res.stderr);
  return JSON.parse(res.stdout);
}

test("docker compose: CDT settings absent on the host resolve to \"\" (off); present ones pass through verbatim", () => {
  const absent = composeConfigJson({});
  for (const name of CDT_MCP_NAMES) assert.equal(absent.services.mcp.environment[name], "", name);
  assert.equal(absent.services["telemetry-sink"].environment.TELEMETRY_RUN_SET_HEAD, "");

  const set = Object.fromEntries(CDT_MCP_NAMES.map((n, i) => [n, `v${i}-${n.toLowerCase()}`]));
  const present = composeConfigJson({ ...set, TELEMETRY_RUN_SET_HEAD: "1" });
  for (const name of CDT_MCP_NAMES) assert.equal(present.services.mcp.environment[name], set[name], name);
  assert.equal(present.services["telemetry-sink"].environment.TELEMETRY_RUN_SET_HEAD, "1");
  // The sink switch never leaks into mcp, nor the mcp settings into the sink.
  assert.equal(present.services.mcp.environment.TELEMETRY_RUN_SET_HEAD, undefined);
  for (const name of CDT_MCP_NAMES) assert.equal(present.services["telemetry-sink"].environment[name], undefined, name);
});
