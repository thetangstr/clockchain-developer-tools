import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const deployDir = path.join(repoRoot, "infra", "clockchain-mcp");
const wrapper = path.join(deployDir, "compose-up.sh");
const composeFile = path.join(deployDir, "docker-compose.yml");
const caddyFile = path.join(deployDir, "Caddyfile");
const systemdUnit = path.join(deployDir, "clockchain-mcp.service");
const runbook = path.join(deployDir, "RUNBOOK.md");
const installScript = path.join(repoRoot, "infra", "scripts", "install-clockchain-mcp-deploy-assets.sh");
const rootPackageJson = path.join(repoRoot, "package.json");

const expectedSecretNames = [
  "/clockchain/mcp/CLOCKCHAIN_API_KEY",
  "/clockchain/mcp/MCP_AUTH_TOKENS",
  "/clockchain/mcp/MCP_TOKEN_SIGNING_SECRET",
  "/clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN",
  "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE",
  "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS",
];

const expectedHostSecretNames = [
  "/clockchain/host/FUNDING_WALLET_JSON",
  "/clockchain/host/FUNDING_WALLET_PUBLIC_JSON",
  "/clockchain/host/FUNDING_PASSWORD",
  "/clockchain/host/CLOCKCHAIN_TOKEN",
  "/clockchain/host/AGENT_HANDSHAKE_V2_HOST_ROOT_KEY",
];
const expectedHandshakeSha = "0123456789abcdef0123456789abcdef01234567";

const expectedEnv = {
  CLOCKCHAIN_API_KEY: "api-key-line-1\napi-key-line-2\n",
  MCP_AUTH_TOKENS: "token-a,token-b\n",
  MCP_TOKEN_SIGNING_SECRET: "signing-secret\nwith-newline\n",
  AGENT_HANDSHAKE_RELEASE_PIN: '{"version":"2.1.0","sourceCommit":"0123456789abcdef0123456789abcdef01234567","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowedAssetPrefix":"https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/","hostRoots":[{"kid":"root-2026-08","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}\n',
  AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: '{"kid":"role-active","secretBase64":"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="}\n',
  AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS: '{"kid":"role-previous","secretBase64":"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}\n',
};

const expectedHostSecrets = {
  "funding-wallet.json": '{"wallet":"line-1\\nline-2"}\n',
  "funding-wallet.public.json": '{"public":"wallet"}\n',
  "funding.password": "pass line 1\npass line 2\n",
  "clockchain.token": "clockchain-token\n",
  "agent-handshake-v2-host-root.pem": "-----BEGIN PRIVATE KEY-----\nfixture-root\n-----END PRIVATE KEY-----\n",
};

const oldHostSecrets = {
  "funding-wallet.json": '{"wallet":"old"}\n',
  "funding-wallet.public.json": '{"public":"old"}\n',
  "funding.password": "old password\n",
  "clockchain.token": "old token\n",
  "agent-handshake-v2-host-root.pem": "old root\n",
};

async function pathExists(file) {
  try {
    await access(file, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function run(command, args, options) {
  const child = spawn(command, args, {
    ...options,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const code = await new Promise((resolve) => {
    child.on("close", resolve);
  });
  return { code, stdout, stderr };
}

async function listFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(fullPath)));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

async function createWrapperFixture(options = {}) {
  const temp = await mkdtemp(path.join(tmpdir(), "clockchain-mcp-deploy-test."));
  const binDir = path.join(temp, "bin");
  const fakeDeployDir = path.join(temp, "infra", "clockchain-mcp");
  const fakeHandshakeDir = path.join(temp, "handshake");
  const hostSecretDir = path.join(temp, "host-secrets");
  const callsFile = path.join(temp, "aws-calls.txt");
  const dockerOkFile = path.join(temp, "docker-ok.txt");
  const envJson = JSON.stringify(expectedEnv);
  const hostSecretsJson = JSON.stringify(expectedHostSecrets);

  await mkdir(fakeDeployDir, { recursive: true });
  await mkdir(fakeHandshakeDir, { recursive: true });
  await writeFile(path.join(temp, "expected-env.json"), envJson, "utf8");
  await writeFile(path.join(temp, "expected-host-secrets.json"), hostSecretsJson, "utf8");
  await writeFile(path.join(fakeHandshakeDir, ".git"), "gitdir: fake\n", "utf8");
  await writeFile(path.join(fakeDeployDir, "docker-compose.yml"), "services:\n  mcp:\n    image: fake\n", "utf8");
  await writeFile(path.join(fakeDeployDir, "Caddyfile"), "mcp-aws.clockchain.network { respond ok }\n", "utf8");
  await writeFile(
    path.join(temp, "env-check.mjs"),
    `
import assert from "node:assert/strict";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
const expected = JSON.parse(await readFile(process.env.EXPECTED_ENV_FILE, "utf8"));
for (const [name, value] of Object.entries(expected)) {
  assert.equal(process.env[name], value, name);
}
const expectedHostSecrets = JSON.parse(await readFile(process.env.EXPECTED_HOST_SECRETS_FILE, "utf8"));
assert.equal(process.env.HANDSHAKE_RELAY, "http://44.249.47.220:8080");
assert.equal(process.env.MCP_HANDSHAKE_FILE, "/app/state/handshake.json");
assert.equal(process.env.HANDSHAKE_ALLOW_DEGRADED, process.env.EXPECTED_HANDSHAKE_ALLOW_DEGRADED);
assert.equal(process.env.EVM_RPC_URL, process.env.EXPECTED_EVM_RPC_URL);
assert.equal(process.env.HANDSHAKE_KIT_REPO, "https://github.com/thetangstr/clockchain-handshake-v2.git");
assert.equal(process.env.HANDSHAKE_SHA, "${expectedHandshakeSha}");
assert.equal(process.env.CLOCKCHAIN_FUNDING_PASSWORD_FILE, "/app/keys/funding.password");
assert.equal(process.env.CLOCKCHAIN_HOST_ROOT_KEY_ID, "root-2026-08");
assert.equal(process.env.CLOCKCHAIN_HOST_SECRET_DIR, process.env.EXPECTED_HOST_SECRET_DIR);
assert.deepEqual((await readdir(process.env.CLOCKCHAIN_HOST_SECRET_DIR)).sort(), Object.keys(expectedHostSecrets).sort());
for (const [file, value] of Object.entries(expectedHostSecrets)) {
  const secretPath = path.join(process.env.CLOCKCHAIN_HOST_SECRET_DIR, file);
  assert.equal(await readFile(secretPath, "utf8"), value, file);
  assert.equal((await stat(secretPath)).mode & 0o777, 0o600, file);
}
assert.equal(process.env.PORT, "8080");
assert.equal(process.env.MCP_TRANSPORT, "http");
assert.equal(process.env.MCP_REQUIRE_AUTH, "1");
assert.equal(process.env.MCP_RATE_PER_MIN, "30");
assert.equal(process.env.MCP_LOG_BUDGET, "5000");
assert.equal(process.env.MCP_TOKEN_MINT_PER_HOUR, "10");
assert.equal(process.env.CLOCKCHAIN_CLIENT_ID, "thetangstr@gmail.com");
assert.equal(process.env.CLOCKCHAIN_WALLET_ID, "thetangstr@gmail.com");
assert.equal(process.env.CLOCKCHAIN_ENDPOINT, "https://node.clockchain.network");
assert.equal(process.env.ERC8004_REGISTRY_ADDRESS, "0x8004A818BFB912233c491871b3d84c89A494BD9e");
await writeFile(process.env.DOCKER_OK_FILE, "ok\\n");
`.trimStart(),
    "utf8",
  );
  await mkdir(binDir);
  await writeFile(
    path.join(binDir, "aws"),
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$AWS_CALLS_FILE"
[[ "$1" == "--region" && "$2" == "us-west-2" ]]
shift 2
[[ "$1" == "ssm" && "$2" == "get-parameter" ]]
shift 2
name=""
with_decryption=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) name="$2"; shift 2 ;;
    --with-decryption) with_decryption=1; shift ;;
    --output) [[ "$2" == "json" ]]; shift 2 ;;
    *) echo "unexpected arg: $1" >&2; exit 64 ;;
  esac
done
[[ "$with_decryption" == 1 ]]
case "$name" in
  /clockchain/mcp/CLOCKCHAIN_API_KEY) value=$'api-key-line-1\\napi-key-line-2\\n' ;;
  /clockchain/mcp/MCP_AUTH_TOKENS) value=$'token-a,token-b\\n' ;;
  /clockchain/mcp/MCP_TOKEN_SIGNING_SECRET) value=$'signing-secret\\nwith-newline\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN) value=$'{"version":"2.1.0","sourceCommit":"0123456789abcdef0123456789abcdef01234567","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowedAssetPrefix":"https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/","hostRoots":[{"kid":"root-2026-08","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE) value=$'{"kid":"role-active","secretBase64":"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS) value=$'{"kid":"role-previous","secretBase64":"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}\\n' ;;
  /clockchain/host/FUNDING_WALLET_JSON) value=$'{"wallet":"line-1\\\\nline-2"}\\n' ;;
  /clockchain/host/FUNDING_WALLET_PUBLIC_JSON) value=$'{"public":"wallet"}\\n' ;;
  /clockchain/host/FUNDING_PASSWORD) value=$'pass line 1\\npass line 2\\n' ;;
  /clockchain/host/CLOCKCHAIN_TOKEN) value=$'clockchain-token\\n' ;;
  /clockchain/host/AGENT_HANDSHAKE_V2_HOST_ROOT_KEY) value=$'-----BEGIN PRIVATE KEY-----\\nfixture-root\\n-----END PRIVATE KEY-----\\n' ;;
  /clockchain/host/MISSING_SECRET) value='' ;;
  *) echo "unexpected parameter: $name" >&2; exit 65 ;;
esac
jq -n --arg name "$name" --arg value "$value" '{Parameter:{Name:$name,Value:$value}}'
if [[ "\${AWS_FAIL_PARAMETER:-}" == "$name" ]]; then
  exit 66
fi
if [[ "\${AWS_FAIL_AFTER_VALUE:-0}" == "1" ]]; then
  exit 66
fi
`,
    { mode: 0o755 },
  );
  await writeFile(
    path.join(binDir, "git"),
    `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "-c" && "$2" == "safe.directory=$HANDSHAKE_APP_ROOT" ]]
shift 2
[[ "$1" == "-C" && "$2" == "$HANDSHAKE_APP_ROOT" ]]
shift 2
case "$*" in
  "rev-parse --is-inside-work-tree") printf 'true\\n' ;;
  "rev-parse HEAD") printf '%s\\n' "\${FAKE_HANDSHAKE_SHA:-${expectedHandshakeSha}}" ;;
  "status --porcelain") printf '%s' "\${FAKE_HANDSHAKE_STATUS:-}" ;;
  *) echo "unexpected git command: $*" >&2; exit 67 ;;
esac
`,
    { mode: 0o755 },
  );
  await writeFile(
    path.join(binDir, "docker"),
    `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "compose" ]]
shift
has_wait=0
has_wait_timeout=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait) has_wait=1; shift ;;
    --wait-timeout) has_wait_timeout=1; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$has_wait" == "1" ]]
[[ "$has_wait_timeout" == "1" ]]
if [[ "\${DOCKER_FAIL_HEALTH:-0}" == "1" ]]; then
  exit 78
fi
node "$ENV_CHECK_FILE"
printf 'docker compose invoked\\n'
`,
    { mode: 0o755 },
  );
  await Promise.all([
    chmod(path.join(binDir, "aws"), 0o755),
    chmod(path.join(binDir, "git"), 0o755),
    chmod(path.join(binDir, "docker"), 0o755),
  ]);

  const env = {
    PATH: `${binDir}:${process.env.PATH}`,
    AWS_CALLS_FILE: callsFile,
    DOCKER_OK_FILE: dockerOkFile,
    ENV_CHECK_FILE: path.join(temp, "env-check.mjs"),
    EXPECTED_ENV_FILE: path.join(temp, "expected-env.json"),
    EXPECTED_HOST_SECRETS_FILE: path.join(temp, "expected-host-secrets.json"),
    EXPECTED_HOST_SECRET_DIR: hostSecretDir,
    EXPECTED_HANDSHAKE_ALLOW_DEGRADED: "false",
    EXPECTED_EVM_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
    CLOCKCHAIN_MCP_APP_ROOT: temp,
    CLOCKCHAIN_HOST_SECRET_DIR: hostSecretDir,
    HANDSHAKE_APP_ROOT: fakeHandshakeDir,
    HANDSHAKE_RELAY: "http://44.249.47.220:8080",
    HANDSHAKE_KIT_REPO: "https://github.com/thetangstr/clockchain-handshake-v2.git",
    HANDSHAKE_SHA: expectedHandshakeSha,
    ...options.env,
  };

  return { temp, callsFile, dockerOkFile, env };
}

async function resolvedComposeConfig() {
  const result = await run("docker", ["compose", "-f", composeFile, "config", "--format", "json"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PORT: "8080",
      MCP_TRANSPORT: "http",
      MCP_REQUIRE_AUTH: "1",
      MCP_RATE_PER_MIN: "30",
      MCP_LOG_BUDGET: "5000",
      MCP_TOKEN_MINT_PER_HOUR: "10",
      CLOCKCHAIN_CLIENT_ID: "thetangstr@gmail.com",
      CLOCKCHAIN_WALLET_ID: "thetangstr@gmail.com",
      CLOCKCHAIN_ENDPOINT: "https://node.clockchain.network",
      ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
      CLOCKCHAIN_API_KEY: "dummy-api",
      MCP_AUTH_TOKENS: "dummy-token",
      MCP_TOKEN_SIGNING_SECRET: "dummy-signing",
      AGENT_HANDSHAKE_RELEASE_PIN: JSON.stringify({
        version: "2.1.0",
        sourceCommit: expectedHandshakeSha,
        manifestDigest: "a".repeat(64),
        allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/",
        hostRoots: [{ kid: "root-2026-08", fingerprint: "b".repeat(64) }],
      }),
      AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: "dummy-role-active",
      AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS: "dummy-role-previous",
      HANDSHAKE_APP_ROOT: "/tmp/handshake-app",
      HANDSHAKE_RELAY: "http://44.249.47.220:8080",
      HANDSHAKE_ALLOW_DEGRADED: "false",
      EVM_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
      HANDSHAKE_KIT_REPO: "https://github.com/thetangstr/clockchain-handshake-v2.git",
      HANDSHAKE_SHA: expectedHandshakeSha,
      CLOCKCHAIN_HOST_SECRET_DIR: "/run/clockchain-host-secrets",
      CLOCKCHAIN_HOST_ROOT_KEY_ID: "root-2026-08",
    },
  });
  assert.equal(result.code, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertHostSecretBindMount(mount) {
  const { bind = {}, ...stableMountFields } = mount;
  assert.deepEqual(stableMountFields, {
    type: "bind",
    source: "/run/clockchain-host-secrets",
    target: "/app/keys",
    read_only: true,
  });
  assert.deepEqual(
    Object.keys(bind)
      .filter((key) => key !== "create_host_path")
      .sort(),
    [],
  );
  if ("create_host_path" in bind) {
    assert.equal(bind.create_host_path, true);
  }
}

test("host secret mount assertion accepts compose bind metadata variants", () => {
  for (const bind of [{}, { create_host_path: true }]) {
    assertHostSecretBindMount({
      type: "bind",
      source: "/run/clockchain-host-secrets",
      target: "/app/keys",
      read_only: true,
      bind,
    });
  }
});

test("deployment assets define the locked EC2 compose target", async () => {
  for (const file of [wrapper, composeFile, caddyFile, systemdUnit, runbook]) {
    assert.equal(await pathExists(file), true, `${path.relative(repoRoot, file)} exists`);
  }

  const compose = await readFile(composeFile, "utf8");
  assert.match(compose, /mcp:/);
  assert.match(compose, /host:/);
  assert.match(compose, /caddy:/);
  assert.match(compose, /build:\s*\n\s*context:\s*\.\.\/\.\./);
  assert.match(compose, /target:\s*runtime/);
  assert.match(compose, /restart:\s*unless-stopped/g);
  assert.doesNotMatch(compose, /8080:8080/);
  assert.match(compose, /"80:80"/);
  assert.match(compose, /"443:443"/);
  assert.match(compose, /healthcheck:/);
  assert.match(compose, /-\s+node\s+-\s+-e/s);
  assert.match(compose, /fetch\("http:\/\/127\.0\.0\.1:" \+ \(process\.env\.PORT \?\? "8080"\) \+ "\/health"\)/);
  assert.match(compose, /condition:\s*service_healthy/);
  assert.match(compose, /HANDSHAKE_RELAY:\s*"\$\{HANDSHAKE_RELAY\}"/);
  assert.match(compose, /MCP_HANDSHAKE_FILE:\s*\/app\/state\/handshake\.json/);
  assert.match(compose, /HANDSHAKE_ALLOW_DEGRADED:\s*"\$\{HANDSHAKE_ALLOW_DEGRADED\}"/);
  assert.match(compose, /EVM_RPC_URL:\s*"\$\{EVM_RPC_URL\}"/);
  assert.match(compose, /mcp_state:\/app\/state/);
  assert.match(compose, /context:\s*\$\{HANDSHAKE_APP_ROOT:-\/opt\/clockchain-host\/app\}/);
  assert.match(compose, /HANDSHAKE_RELAY:\s*"\$\{HANDSHAKE_RELAY\}"/);
  assert.match(compose, /HANDSHAKE_SHA:\s*"\$\{HANDSHAKE_SHA\}"/);
  assert.match(compose, /HANDSHAKE_KIT_REPO:\s*"\$\{HANDSHAKE_KIT_REPO\}"/);
  assert.match(compose, /HANDSHAKE_PROTOCOL:\s*"clockchain\.agent-handshake\/v2"/);
  assert.match(compose, /command:\s*\["node",\s*"bin\/agent-handshake-host\.mjs"\]/);
  assert.match(compose, /CLOCKCHAIN_FUNDING_PASSWORD_FILE:\s*\/app\/keys\/funding\.password/);
  assert.match(compose, /\$\{CLOCKCHAIN_HOST_SECRET_DIR:-\/run\/clockchain-host-secrets\}:\/app\/keys:ro/);
  assert.match(compose, /host_runs:\/app\/runs/);
  assert.match(compose, /mcp_state:/);

  const caddy = await readFile(caddyFile, "utf8");
  assert.match(caddy, /^mcp-aws\.clockchain\.network\s*\{/m);
  assert.match(caddy, /^mcp\.clockchain\.network\s*\{/m);
  assert.match(caddy, /tls\s*\{\s*on_demand\s*\}/s);
  assert.match(caddy, /reverse_proxy\s+mcp:8080/g);

  const unit = await readFile(systemdUnit, "utf8");
  assert.match(unit, /ExecStart=\/opt\/clockchain-mcp\/compose-up\.sh/);
  assert.match(unit, /WantedBy=multi-user\.target/);
});

test("deployment runbook fixes the release order, secret boundary, canaries, and rollback", async () => {
  const source = await readFile(runbook, "utf8");
  for (const name of [...expectedSecretNames, ...expectedHostSecretNames]) {
    assert.match(source, new RegExp(name.replaceAll("/", "\\/")));
  }
  assert.match(source, /helper release[\s\S]*host[\s\S]*MCP[\s\S]*Research/i);
  assert.match(source, /portable Node 24 helper release/i);
  assert.match(source, /raw manifest bytes[\s\S]*helper\s+bytes[\s\S]*verified\s+bytes in memory/i);
  assert.doesNotMatch(source, /signed helper release/i);
  assert.match(source, /\/health/);
  assert.match(source, /\/\.well-known\/agent-handshake\.json/);
  assert.match(source, /\/handshake\/mcp/);
  assert.match(source, /AmazonSSMManagedInstanceCore/);
  assert.match(source, /exact new instance is SSM\s+`Online`/i);
  assert.match(source, /rollback/i);
  assert.match(source, /generic v1 and bilateral/i);
  assert.doesNotMatch(source, /secretBase64"\s*:\s*"[A-Za-z0-9+/=]{20,}/);
});

test("resolved compose config gives mcp durable handshake state and relay defaults", async () => {
  const cfg = await resolvedComposeConfig();
  const mcp = cfg.services.mcp;

  assert.equal(mcp.environment.HANDSHAKE_RELAY, "http://44.249.47.220:8080");
  assert.equal(mcp.environment.MCP_HANDSHAKE_FILE, "/app/state/handshake.json");
  assert.equal(mcp.environment.HANDSHAKE_ALLOW_DEGRADED, "false");
  assert.equal(mcp.environment.EVM_RPC_URL, "https://ethereum-sepolia-rpc.publicnode.com");
  assert.equal(mcp.environment.AGENT_HANDSHAKE_V2_INVITATION_FILE, "/app/state/agent-handshake-v2-invitations.json");
  assert.equal(mcp.environment.AGENT_HANDSHAKE_V2_STATE_FILE, "/app/state/agent-handshake-v2-state.json");
  assert.equal(mcp.environment.AGENT_HANDSHAKE_TRUSTED_PROXY, "172.30.0.3");
  assert.deepEqual(
    mcp.volumes.filter((volume) => volume.target === "/app/state"),
    [
      {
        type: "volume",
        source: "mcp_state",
        target: "/app/state",
        volume: {},
      },
    ],
  );
  assert.ok(cfg.volumes.mcp_state);
});

test("resolved compose config adds the external host without network ingress", async () => {
  const cfg = await resolvedComposeConfig();
  const host = cfg.services.host;

  assert.equal(host.build.context, "/tmp/handshake-app");
  assert.equal(host.restart, "unless-stopped");
  assert.equal(host.ports, undefined);
  assert.equal(host.expose, undefined);
  assert.deepEqual(host.command, ["node", "bin/agent-handshake-host.mjs"]);
  assert.deepEqual(host.environment, {
    AGENT_HANDSHAKE_PROTOCOL: "clockchain.agent-handshake/v2",
    AGENT_HANDSHAKE_V2_FUNDING_ALERT_DAILY_ETH: "0.80",
    AGENT_HANDSHAKE_V2_FUNDING_ALERT_HOURLY_ETH: "0.16",
    AGENT_HANDSHAKE_V2_FUNDING_LEDGER: "/app/runs/private/v2-funding-ledger.jsonl",
    AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT: "16",
    HANDSHAKE_KIT_REPO: "https://github.com/thetangstr/clockchain-handshake-v2.git",
    CLOCKCHAIN_FUNDING_KEYSTORE: "/app/keys/funding-wallet.json",
    CLOCKCHAIN_FUNDING_PASSWORD_FILE: "/app/keys/funding.password",
    CLOCKCHAIN_HOST_ROOT_KEY_FILE: "/app/keys/agent-handshake-v2-host-root.pem",
    CLOCKCHAIN_HOST_ROOT_KEY_ID: "root-2026-08",
    HANDSHAKE_PROTOCOL: "clockchain.agent-handshake/v2",
    HANDSHAKE_RELAY: "http://44.249.47.220:8080",
    HANDSHAKE_SHA: expectedHandshakeSha,
    SEPOLIA_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
  });
  assert.equal(host.volumes.length, 2);
  assertHostSecretBindMount(host.volumes[0]);
  assert.deepEqual(host.volumes[1], {
    type: "volume",
    source: "host_runs",
    target: "/app/runs",
    volume: {},
  });
  assert.ok(cfg.volumes.host_runs);
});

test("resolved compose healthcheck builds the correct URL and fails closed", async () => {
  const cfg = await resolvedComposeConfig();
  const healthTest = cfg.services.mcp.healthcheck.test;
  assert.deepEqual(healthTest.slice(0, 3), ["CMD", "node", "-e"]);
  const script = healthTest[3];
  assert.doesNotMatch(script, /\$\$\{/);
  assert.doesNotMatch(script, /\$8080/);

  const probe = `
global.fetch = async (url) => {
  if (url !== "http://127.0.0.1:39123/health") {
    console.error(url);
    process.exit(70);
  }
  return { ok: process.env.FETCH_OK === "1" };
};
${script}
setTimeout(() => {}, 20);
`;

  const ok = await run(process.execPath, ["-e", probe], {
    env: { ...process.env, PORT: "39123", FETCH_OK: "1" },
  });
  assert.equal(ok.code, 0, ok.stderr);

  const unhealthy = await run(process.execPath, ["-e", probe], {
    env: { ...process.env, PORT: "39123", FETCH_OK: "0" },
  });
  assert.notEqual(unhealthy.code, 0);
});

test("compose wrapper fails closed when docker wait reports unhealthy services", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { DOCKER_FAIL_HEALTH: "1" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerOkFile), false, "post-health docker path did not run");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper fetches only locked SSM secrets and preserves bytes into docker env and host files", async () => {
  assert.equal(await pathExists(wrapper), true, "compose wrapper exists");

  const { temp, callsFile, dockerOkFile, env } = await createWrapperFixture();

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.equal(result.code, 0, result.stderr);
    const calls = (await readFile(callsFile, "utf8")).trim().split("\n");
    assert.deepEqual(
      calls.map((line) => line.match(/--name ([^ ]+)/)?.[1]),
      [...expectedSecretNames, ...expectedHostSecretNames],
    );
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
    for (const secret of [...Object.values(expectedEnv), ...Object.values(expectedHostSecrets)]) {
      assert.equal(result.stdout.includes(secret), false, "wrapper stdout does not contain secret bytes");
      assert.equal(result.stderr.includes(secret), false, "wrapper stderr does not contain secret bytes");
    }

    const files = await listFiles(temp);
    for (const file of files) {
      if (
        file.endsWith("expected-env.json") ||
        file.endsWith("expected-host-secrets.json") ||
        file.endsWith("env-check.mjs") ||
        file.endsWith("aws") ||
        file.startsWith(`${env.EXPECTED_HOST_SECRET_DIR}${path.sep}`)
      ) {
        continue;
      }
      const body = await readFile(file, "utf8").catch(() => "");
      for (const secret of [...Object.values(expectedEnv), ...Object.values(expectedHostSecrets)]) {
        assert.equal(body.includes(secret), false, `${path.basename(file)} is not wrapper/file persistence`);
      }
    }

    const mode = (await stat(wrapper)).mode & 0o777;
    assert.equal(mode & 0o111, 0o111, "wrapper is executable");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper rejects invalid degraded handshake mode before docker", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { HANDSHAKE_ALLOW_DEGRADED: "yes" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /HANDSHAKE_ALLOW_DEGRADED must be true or false/);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper rejects invalid release metadata and repeated role signing keys", async () => {
  for (const extra of [
    { AGENT_HANDSHAKE_RELEASE_PIN_PARAM: "/clockchain/host/MISSING_SECRET" },
    { AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS_PARAM: "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE" },
  ]) {
    const { temp, dockerOkFile, env } = await createWrapperFixture({ env: extra });
    try {
      const result = await run(wrapper, [], { cwd: temp, env });
      assert.notEqual(result.code, 0);
      assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
      for (const secret of Object.values(expectedEnv)) {
        assert.equal(result.stdout.includes(secret), false);
        assert.equal(result.stderr.includes(secret), false);
      }
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
});

test("compose wrapper exports operator nonsecret overrides without hardcoding live degraded mode", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: {
      HANDSHAKE_ALLOW_DEGRADED: "true",
      EVM_RPC_URL: "https://sepolia.example.invalid",
      EXPECTED_HANDSHAKE_ALLOW_DEGRADED: "true",
      EXPECTED_EVM_RPC_URL: "https://sepolia.example.invalid",
    },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.equal(result.code, 0, result.stderr);
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses docker when a host SecureString is missing", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM: "/clockchain/host/MISSING_SECRET" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses docker when the host-root SecureString is missing", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { CLOCKCHAIN_HOST_ROOT_KEY_PARAM: "/clockchain/host/MISSING_SECRET" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });
    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper preserves the prior host secret set when a late host fetch fails", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { AWS_FAIL_PARAMETER: "/clockchain/host/CLOCKCHAIN_TOKEN" },
  });

  try {
    await mkdir(env.EXPECTED_HOST_SECRET_DIR, { recursive: true });
    for (const [file, value] of Object.entries(oldHostSecrets)) {
      const secretPath = path.join(env.EXPECTED_HOST_SECRET_DIR, file);
      await writeFile(secretPath, value, { mode: 0o600 });
      await chmod(secretPath, 0o600);
    }

    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
    assert.deepEqual((await readdir(env.EXPECTED_HOST_SECRET_DIR)).sort(), Object.keys(oldHostSecrets).sort());
    for (const [file, value] of Object.entries(oldHostSecrets)) {
      const secretPath = path.join(env.EXPECTED_HOST_SECRET_DIR, file);
      assert.equal(await readFile(secretPath, "utf8"), value, file);
      assert.equal((await stat(secretPath)).mode & 0o777, 0o600, file);
    }
    for (const secret of [...Object.values(expectedHostSecrets), ...Object.values(oldHostSecrets)]) {
      assert.equal(result.stdout.includes(secret), false, "wrapper stdout does not contain secret bytes");
      assert.equal(result.stderr.includes(secret), false, "wrapper stderr does not contain secret bytes");
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses docker when the handshake checkout SHA differs", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { FAKE_HANDSHAKE_SHA: "1111111111111111111111111111111111111111" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /handshake checkout SHA mismatch/);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses docker when the handshake SHA is malformed", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { FAKE_HANDSHAKE_SHA: "not-a-sha", HANDSHAKE_SHA: "not-a-sha" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /handshake checkout SHA is not a 40-character lowercase hex value/);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses docker when the handshake checkout is dirty", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { FAKE_HANDSHAKE_STATUS: " M bin/clockchain-host.mjs\n" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /handshake checkout has uncommitted changes/);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper refuses to run docker if a secret fetch pipeline fails after output", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: { AWS_FAIL_AFTER_VALUE: "1" },
  });

  try {
    const result = await run(wrapper, [], { cwd: temp, env });

    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerOkFile), false, "docker compose was not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("installer enables and restarts the systemd unit", async () => {
  const install = await readFile(installScript, "utf8");
  assert.match(install, /systemctl daemon-reload/);
  assert.match(install, /systemctl enable clockchain-mcp\.service/);
  assert.match(install, /systemctl restart clockchain-mcp\.service/);
});

test("provisioning IAM policy is limited to MCP and host SSM prefixes", async () => {
  const provision = await readFile(path.join(repoRoot, "infra", "scripts", "provision-clockchain-mcp-host.sh"), "utf8");
  assert.match(provision, /parameter\/clockchain\/mcp\/\*/);
  assert.match(provision, /parameter\/clockchain\/host\/\*/);
  assert.doesNotMatch(provision, /parameter\/clockchain\/\*/);
});

test("provisioning attaches only the managed SSM core policy needed for Run Command", async () => {
  const provision = await readFile(path.join(repoRoot, "infra", "scripts", "provision-clockchain-mcp-host.sh"), "utf8");
  assert.match(
    provision,
    /SSM_CORE_POLICY_ARN="arn:aws:iam::aws:policy\/AmazonSSMManagedInstanceCore"/,
  );
  assert.match(
    provision,
    /aws iam attach-role-policy \\\n+\s+--role-name "\$ROLE_NAME" \\\n+\s+--policy-arn "\$SSM_CORE_POLICY_ARN"/,
  );
  assert.doesNotMatch(provision, /arn:aws:iam::aws:policy\/AdministratorAccess/);
  assert.doesNotMatch(provision, /arn:aws:iam::aws:policy\/AmazonSSMFullAccess/);
});

test("provisioning waits for the exact instance to become SSM Online", async () => {
  const provision = await readFile(path.join(repoRoot, "infra", "scripts", "provision-clockchain-mcp-host.sh"), "utf8");
  assert.match(provision, /wait_for_ssm_online\(\) \{/);
  assert.match(
    provision,
    /Key=InstanceIds,Values=\$\{instance_id\}/,
  );
  assert.match(provision, /PingStatus/);
  assert.match(provision, /Online/);
  assert.match(provision, /for attempt in \{1\.\.24\}; do/);
  assert.match(provision, /sleep 5/);
  assert.match(provision, /SSM_STATUS=%s/);
  assert.match(provision, /wait_for_ssm_online "\$instance_id"/);
});

test("root npm test runs workspace and infra tests with deterministic failure propagation", async () => {
  const pkg = JSON.parse(await readFile(rootPackageJson, "utf8"));
  assert.match(pkg.scripts.test, /npm run test --workspaces --if-present/);
  assert.match(pkg.scripts.test, /node --test infra\/test\/\*\.test\.mjs/);
  assert.match(pkg.scripts.test, /&&/);
});
