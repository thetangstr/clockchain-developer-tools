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

test("sink environment: production, public keys from the deploy env, explicit no-peer, no secrets", async () => {
  const source = await readFile(composeFile, "utf8");
  const env = envBlock(serviceBlock(source, "telemetry-sink") ?? "");
  assert.match(env, /^      TELEMETRY_ENV:\s*"production"\s*$/m);
  assert.match(env, /^      TELEMETRY_STATE_DIR:\s*\/telemetry\/state\s*$/m);
  assert.match(env, /^      TELEMETRY_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS:-\}"\s*$/m);
  assert.match(env, /^      TELEMETRY_PEER_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS_STAGING:-\}"\s*$/m);
  assert.match(env, /^      TELEMETRY_PEER_ENV:\s*"none"\s*$/m);
  for (const line of env.split("\n").filter((l) => l && !/^\s*#/.test(l))) {
    const [, name, value] = line.match(/^      (\w+):\s*(.*)$/) ?? [];
    assert.ok(name, `env line parses: ${line}`);
    // No key material / tokens by name (the sink generates its key in-container).
    assert.doesNotMatch(name, /SECRET|SEED|PRIVATE|PASSWORD|TOKEN|SIGNING|_KEY$|_KEY_FILE|JWK/i, `env name ${name}`);
    // Values are interpolations or short non-secret literals — never inline key material.
    assert.ok(/^"?\$\{\w+(:-[^}]*)?\}"?$/.test(value) || /^"?[\w./-]{0,40}"?$/.test(value),
      `env ${name} value must be an interpolation or a short literal`);
  }
  // The anchor token is a secret: not wired in this deploy.
  assert.doesNotMatch(source, /TELEMETRY_ANCHOR_TOKEN/);
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
