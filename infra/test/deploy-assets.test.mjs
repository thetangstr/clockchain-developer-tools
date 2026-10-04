import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const deployDir = path.join(repoRoot, "infra", "clockchain-mcp");
const wrapper = path.join(deployDir, "compose-up.sh");
const composeFile = path.join(deployDir, "docker-compose.yml");
const caddyFile = path.join(deployDir, "Caddyfile");
const systemdUnit = path.join(deployDir, "clockchain-mcp.service");
const runbook = path.join(deployDir, "RUNBOOK.md");
const installScript = path.join(repoRoot, "infra", "scripts", "install-clockchain-mcp-deploy-assets.sh");
const deployBoxScript = path.join(repoRoot, "scripts", "deploy-box.sh");
const rootPackageJson = path.join(repoRoot, "package.json");
const mcpServerPackageJson = path.join(repoRoot, "packages", "mcp-server", "package.json");

const expectedSecretNames = [
  "/clockchain/mcp/CLOCKCHAIN_API_KEY",
  "/clockchain/mcp/MCP_AUTH_TOKENS",
  "/clockchain/mcp/MCP_TOKEN_SIGNING_SECRET",
  "/clockchain/mcp/GATEWAY_SIGNING_SECRET",
  "/clockchain/mcp/KEEPER_WEBHOOK_SECRET",
  "/clockchain/mcp/STANDALONE_WEBHOOK_SECRET",
  "/clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN",
  "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE",
  "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS",
  "/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE",
];

const expectedOptionalSecretNames = [
  "/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS",
];

// N7c: the /contract/mcp env surface — every knob is an OPTIONAL SSM read
// (absent parameter → the env var stays untouched; the route ships disabled
// without CONTRACT_MCP_ENABLED). Order matches the compose-up.sh read block,
// which matches ENV_PARAMETERS in check-config-from-ssm.mjs (including
// CONTRACT_OBSERVER_PER_MINUTE — read in src/http.ts, not config.ts).
const expectedContractEnv = {
  CONTRACT_MCP_ENABLED: "1\n",
  CONTRACT_AUTH_TOKENS: "contract-tb:buyer:kb1:9452:initiator,contract-tp:provider:kp1:9453:responder\n",
  CONTRACT_HOST_ROOTS: `root-2026-08:${"c".repeat(64)}\n`,
  CONTRACT_SERVER_ED25519_SEED: "ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ=\n",
  CONTRACT_SERVER_KEY_ID: "contract-server-2026-09\n",
  // Flag values are deliberately non-degenerate: a bare "0"/"1" secret would
  // false-positive the wrapper-output leak scan (e.g. "--wait-timeout 180\n").
  CONTRACT_ALLOW_EPHEMERAL_KEY: "disabled\n",
  CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z\n",
  CONTRACT_SERVER_KEY_VALID_UNTIL: "2027-09-01T00:00:00.000Z\n",
  CONTRACT_POLICY_DIGESTS: `buyer:0x${"7".repeat(64)},provider:0x${"8".repeat(64)}\n`,
  CONTRACT_PRINCIPALS: `kb1:0x${"1".repeat(40)},kp1:0x${"2".repeat(40)}\n`,
  CONTRACT_OBSERVER_TOKEN: "observer-feed-token\n",
  CONTRACT_VERIFIER_TOKEN: "verifier-salt-token\n",
  CONTRACT_ALLOW_SIM_FAULTS: "1\n",
  CONTRACT_SIM_FAULTS: '{"run-fixture":{"issueMismatch":"fare"}}\n',
  CONTRACT_LEVEL: "L\n",
  CONTRACT_REQUIRE_BIND_STATEMENT: "disabled\n",
  TELEMETRY_CLOSE_URL: "http://telemetry-sink-staging:8083\n",
  TELEMETRY_CLOSE_BACKOFF_MS: "250,1000,5000\n",
  TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS: "10000\n",
  TELEMETRY_CLOSE_DEADLINE_MS: "90000\n",
  CONTRACT_CALLS_PER_MINUTE: "60\n",
  CONTRACT_OBSERVER_PER_MINUTE: "45\n",
  CONTRACT_MAX_RUNS: "256\n",
  CONTRACT_MAX_RECEIPTS_PER_RUN: "1024\n",
  CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL: "128\n",
  CONTRACT_RUN_TTL_MS: "86400000\n",
  CONTRACT_CERT_GRACE_MS: "600000\n",
  CONTRACT_SESSION_TTL_MS: "1800000\n",
  CONTRACT_STATE_DIR: "/app/state/contract\n",
  CONTRACT_ERC8004_CHAIN_ID: "eip155:11155111\n",
  CONTRACT_ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e\n",
  CONTRACT_ANCHOR_ENABLED: "1\n",
  CONTRACT_SETTLEMENT_RAIL: "simulated\n",
  CONTRACT_TRUST_PROXY: "disabled\n",
  HANDSHAKE_V2_RECEIPTS: "1\n",
  HANDSHAKE_V2_RECEIPT_ED25519_SEED: "ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=\n",
  HANDSHAKE_V2_RECEIPT_KEY_ID: "handshake-v2-receipts-2026-10\n",
  HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM: "2026-10-01T00:00:00.000Z\n",
  HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL: "2027-10-01T00:00:00.000Z\n",
  HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN: "handshake-receipt-feed-token\n",
  HANDSHAKE_V2_RECEIPTS_FILE: "/app/state/handshake-v2-receipts.jsonl\n",
};
const expectedContractParamNames = Object.keys(expectedContractEnv).map(
  (name) => `/clockchain/mcp/${name}`,
);

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
  CLOCKCHAIN_SIGNING_SECRET: "gateway-signing-secret\n",
  KEEPER_WEBHOOK_SECRET: "whsec_a2VlcGVy\n",
  STANDALONE_WEBHOOK_SECRET: "standalone-webhook-secret\n",
  AGENT_HANDSHAKE_RELEASE_PIN: '{"version":"2.1.8","sourceCommit":"0123456789abcdef0123456789abcdef01234567","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowedAssetPrefix":"https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/","hostRoots":[{"kid":"root-2026-08","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}\n',
  AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: '{"kid":"role-active","secretBase64":"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="}\n',
  AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS: '{"kid":"role-previous","secretBase64":"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}\n',
  AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: '{"kid":"accept-active","secretBase64":"Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M="}\n',
  AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS: '{"kid":"accept-previous","secretBase64":"ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ="}\n',
  // N7c: every /contract/mcp knob is optional in SSM; present values are
  // exported byte-for-byte into the docker-compose environment.
  ...expectedContractEnv,
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
  const dockerInvokedFile = path.join(temp, "docker-invoked.txt");
  const dockerOkFile = path.join(temp, "docker-ok.txt");
  const dockerArgsFile = path.join(temp, "docker-args.txt");
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
// Names in EXPECTED_UNSET must be absent entirely — an SSM parameter that is
// not found leaves the variable untouched (no exported empty string).
for (const name of (process.env.EXPECTED_UNSET ?? "").split(",").filter(Boolean)) {
  assert.equal(process.env[name], undefined, name + " must stay unset");
}
const expectedHostSecrets = JSON.parse(await readFile(process.env.EXPECTED_HOST_SECRETS_FILE, "utf8"));
assert.equal(process.env.HANDSHAKE_RELAY, "http://44.249.47.220:8080");
assert.equal(process.env.MCP_HANDSHAKE_FILE, "/app/state/handshake.json");
assert.equal(process.env.HANDSHAKE_ALLOW_DEGRADED, process.env.EXPECTED_HANDSHAKE_ALLOW_DEGRADED);
assert.equal(process.env.EVM_RPC_URL, process.env.EXPECTED_EVM_RPC_URL);
assert.equal(process.env.HANDSHAKE_KIT_REPO, "https://github.com/thetangstr/clockchain-handshake-v2.git");
assert.equal(process.env.HANDSHAKE_SHA, "${expectedHandshakeSha}");
assert.equal(process.env.CLOCKCHAIN_HOST_ROOT_KEY_ID, "root-2026-08");
assert.equal(process.env.CLOCKCHAIN_HOST_SECRET_DIR, process.env.EXPECTED_HOST_SECRET_DIR);
if (process.env.EXPECT_MCP_ONLY === "1") {
  // Code-only deploy: the host container is untouched, so its private files are not (re)written.
  assert.equal(process.env.CLOCKCHAIN_FUNDING_PASSWORD_FILE, undefined);
  await assert.rejects(readdir(process.env.CLOCKCHAIN_HOST_SECRET_DIR), { code: "ENOENT" });
} else {
  assert.equal(process.env.CLOCKCHAIN_FUNDING_PASSWORD_FILE, "/app/keys/funding.password");
  assert.deepEqual((await readdir(process.env.CLOCKCHAIN_HOST_SECRET_DIR)).sort(), Object.keys(expectedHostSecrets).sort());
  for (const [file, value] of Object.entries(expectedHostSecrets)) {
    const secretPath = path.join(process.env.CLOCKCHAIN_HOST_SECRET_DIR, file);
    assert.equal(await readFile(secretPath, "utf8"), value, file);
    assert.equal((await stat(secretPath)).mode & 0o777, 0o600, file);
  }
}
assert.equal(process.env.PORT, "8080");
assert.equal(process.env.MCP_TRANSPORT, "http");
assert.equal(process.env.MCP_REQUIRE_AUTH, "1");
assert.equal(process.env.MCP_RATE_PER_MIN, "30");
assert.equal(process.env.MCP_LOG_BUDGET, "5000");
assert.equal(process.env.MCP_TOKEN_MINT_PER_HOUR, "10");
assert.equal(process.env.CLOCKCHAIN_CLIENT_ID, "thetangstr@gmail.com");
assert.equal(process.env.CLOCKCHAIN_WALLET_ID, "thetangstr@gmail.com");
assert.equal(process.env.CLOCKCHAIN_ENDPOINT, "http://clockchain-anchor-gateway:8090");
assert.equal(process.env.CLOCKCHAIN_SIGNING_KEY_ID, "default");
assert.equal(process.env.KEEPER_STORE_PATH, "/app/state/keeper-store.json");
assert.equal(process.env.KEEPER_WEBHOOK_ALLOWLIST, "hooks.slack.com,webhook.site");
assert.equal(process.env.CLOCKCHAIN_SUBSTRATE, "anchoring-gateway");
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
if [[ "\${AWS_PARAMETER_NOT_FOUND:-}" == "$name" ]]; then
  echo "An error occurred (ParameterNotFound) when calling the GetParameter operation: Parameter $name not found." >&2
  exit 254
fi
if [[ "\${AWS_DENY_PARAMETER:-}" == "$name" ]]; then
  echo "An error occurred (AccessDeniedException) when calling the GetParameter operation: access denied" >&2
  exit 254
fi
if [[ "\${AWS_TRANSIENT_PARAMETER:-}" == "$name" ]]; then
  echo "An error occurred (ThrottlingException) when calling the GetParameter operation: rate exceeded" >&2
  exit 254
fi
if [[ "\${AWS_MALFORMED_PARAMETER:-}" == "$name" ]]; then
  printf '{not-json'
  exit 0
fi
case "$name" in
  /clockchain/mcp/CLOCKCHAIN_API_KEY) value=$'api-key-line-1\\napi-key-line-2\\n' ;;
  /clockchain/mcp/MCP_AUTH_TOKENS) value=$'token-a,token-b\\n' ;;
  /clockchain/mcp/MCP_TOKEN_SIGNING_SECRET) value=$'signing-secret\\nwith-newline\\n' ;;
  /clockchain/mcp/GATEWAY_SIGNING_SECRET) value=$'gateway-signing-secret\\n' ;;
  /clockchain/mcp/KEEPER_WEBHOOK_SECRET) value=$'whsec_a2VlcGVy\\n' ;;
  /clockchain/mcp/STANDALONE_WEBHOOK_SECRET) value=$'standalone-webhook-secret\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN) value=$'{"version":"2.1.8","sourceCommit":"0123456789abcdef0123456789abcdef01234567","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowedAssetPrefix":"https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/","hostRoots":[{"kid":"root-2026-08","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE) value=$'{"kid":"role-active","secretBase64":"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS) value=$'{"kid":"role-previous","secretBase64":"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE) value=$'{"kid":"accept-active","secretBase64":"Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M="}\\n' ;;
  /clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS) value=$'{"kid":"accept-previous","secretBase64":"ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ="}\\n' ;;
  # N7c /contract/mcp surface — optional reads; every value is synthetic.
  /clockchain/mcp/CONTRACT_MCP_ENABLED) value=$'1\\n' ;;
  /clockchain/mcp/CONTRACT_AUTH_TOKENS) value=$'contract-tb:buyer:kb1:9452:initiator,contract-tp:provider:kp1:9453:responder\\n' ;;
  /clockchain/mcp/CONTRACT_HOST_ROOTS) value=$'root-2026-08:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\n' ;;
  /clockchain/mcp/CONTRACT_SERVER_ED25519_SEED) value=$'ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ=\\n' ;;
  /clockchain/mcp/CONTRACT_SERVER_KEY_ID) value=$'contract-server-2026-09\\n' ;;
  /clockchain/mcp/CONTRACT_ALLOW_EPHEMERAL_KEY) value=$'disabled\\n' ;;
  /clockchain/mcp/CONTRACT_SERVER_KEY_VALID_FROM) value=$'2026-09-01T00:00:00.000Z\\n' ;;
  /clockchain/mcp/CONTRACT_SERVER_KEY_VALID_UNTIL) value=$'2027-09-01T00:00:00.000Z\\n' ;;
  /clockchain/mcp/CONTRACT_POLICY_DIGESTS) value=$'buyer:0x7777777777777777777777777777777777777777777777777777777777777777,provider:0x8888888888888888888888888888888888888888888888888888888888888888\\n' ;;
  /clockchain/mcp/CONTRACT_PRINCIPALS) value=$'kb1:0x1111111111111111111111111111111111111111,kp1:0x2222222222222222222222222222222222222222\\n' ;;
  /clockchain/mcp/CONTRACT_OBSERVER_TOKEN) value=$'observer-feed-token\\n' ;;
  /clockchain/mcp/CONTRACT_VERIFIER_TOKEN) value=$'verifier-salt-token\\n' ;;
  /clockchain/mcp/CONTRACT_ALLOW_SIM_FAULTS) value=$'1\\n' ;;
  /clockchain/mcp/CONTRACT_SIM_FAULTS) value=$'{"run-fixture":{"issueMismatch":"fare"}}\\n' ;;
  /clockchain/mcp/CONTRACT_LEVEL) value=$'L\\n' ;;
  /clockchain/mcp/CONTRACT_REQUIRE_BIND_STATEMENT) value=$'disabled\\n' ;;
  /clockchain/mcp/TELEMETRY_CLOSE_URL) value=$'http://telemetry-sink-staging:8083\\n' ;;
  /clockchain/mcp/TELEMETRY_CLOSE_BACKOFF_MS) value=$'250,1000,5000\\n' ;;
  /clockchain/mcp/TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS) value=$'10000\\n' ;;
  /clockchain/mcp/TELEMETRY_CLOSE_DEADLINE_MS) value=$'90000\\n' ;;
  /clockchain/mcp/CONTRACT_CALLS_PER_MINUTE) value=$'60\\n' ;;
  /clockchain/mcp/CONTRACT_OBSERVER_PER_MINUTE) value=$'45\\n' ;;
  /clockchain/mcp/CONTRACT_MAX_RUNS) value=$'256\\n' ;;
  /clockchain/mcp/CONTRACT_MAX_RECEIPTS_PER_RUN) value=$'1024\\n' ;;
  /clockchain/mcp/CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL) value=$'128\\n' ;;
  /clockchain/mcp/CONTRACT_RUN_TTL_MS) value=$'86400000\\n' ;;
  /clockchain/mcp/CONTRACT_CERT_GRACE_MS) value=$'600000\\n' ;;
  /clockchain/mcp/CONTRACT_SESSION_TTL_MS) value=$'1800000\\n' ;;
  /clockchain/mcp/CONTRACT_STATE_DIR) value=$'/app/state/contract\\n' ;;
  /clockchain/mcp/CONTRACT_ERC8004_CHAIN_ID) value=$'eip155:11155111\\n' ;;
  /clockchain/mcp/CONTRACT_ERC8004_REGISTRY_ADDRESS) value=$'0x8004A818BFB912233c491871b3d84c89A494BD9e\\n' ;;
  /clockchain/mcp/CONTRACT_ANCHOR_ENABLED) value=$'1\\n' ;;
  /clockchain/mcp/CONTRACT_SETTLEMENT_RAIL) value=$'simulated\\n' ;;
  /clockchain/mcp/CONTRACT_TRUST_PROXY) value=$'disabled\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPTS) value=$'1\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPT_ED25519_SEED) value=$'ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPT_KEY_ID) value=$'handshake-v2-receipts-2026-10\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPT_KEY_VALID_FROM) value=$'2026-10-01T00:00:00.000Z\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPT_KEY_VALID_UNTIL) value=$'2027-10-01T00:00:00.000Z\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPT_OBSERVER_TOKEN) value=$'handshake-receipt-feed-token\\n' ;;
  /clockchain/mcp/HANDSHAKE_V2_RECEIPTS_FILE) value=$'/app/state/handshake-v2-receipts.jsonl\\n' ;;
  /clockchain/mcp/BAD_ACCEPTANCE_HMAC_BASE64) value=$'{"kid":"accept-active","secretBase64":"Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=="}\\n' ;;
  /clockchain/mcp/SHORT_ACCEPTANCE_HMAC) value=$'{"kid":"accept-active","secretBase64":"Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYw="}\\n' ;;
  /clockchain/mcp/NEWLINE_KID_HMAC) value=$'{"kid":"accept-fresh\\n","secretBase64":"ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU="}\\n' ;;
  /clockchain/mcp/NEWLINE_SECRET_HMAC) value=$'{"kid":"accept-fresh","secretBase64":"ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=\\n"}\\n' ;;
  # 44 chars ending ZWV= : structurally valid but nonzero pad bits — decodes
  # but re-encodes to ...ZWU=, so only the decode-and-reencode check catches it.
  /clockchain/mcp/NONCANONICAL_PAD_HMAC) value=$'{"kid":"accept-fresh","secretBase64":"ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWV="}\\n' ;;
  # Valid pin except sourceCommit carries an escaped trailing newline —
  # passes a dollar-anchored jq regex and fails the strict runtime validator.
  /clockchain/mcp/NEWLINE_RELEASE_PIN) value=$'{"version":"2.1.8","sourceCommit":"0123456789abcdef0123456789abcdef01234567\\n","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowedAssetPrefix":"https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/","hostRoots":[{"kid":"root-2026-08","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}\\n' ;;
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
printf 'invoked\\n' > "$DOCKER_INVOKED_FILE"
printf '%s\\n' "$*" > "$DOCKER_ARGS_FILE"
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
"$TEST_NODE_BIN" "$ENV_CHECK_FILE"
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
    DOCKER_INVOKED_FILE: dockerInvokedFile,
    DOCKER_OK_FILE: dockerOkFile,
    DOCKER_ARGS_FILE: dockerArgsFile,
    ENV_CHECK_FILE: path.join(temp, "env-check.mjs"),
    // Absolute node path so the fixture's own checks still work when a test
    // strips node from PATH to simulate the systemd unit environment.
    TEST_NODE_BIN: process.execPath,
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

  return { temp, callsFile, dockerInvokedFile, dockerOkFile, dockerArgsFile, env };
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
      CLOCKCHAIN_ENDPOINT: "http://clockchain-anchor-gateway:8090",
      CLOCKCHAIN_SIGNING_KEY_ID: "default",
      KEEPER_STORE_PATH: "/app/state/keeper-store.json",
      KEEPER_WEBHOOK_SECRET: "dummy-webhook",
      KEEPER_WEBHOOK_ALLOWLIST: "hooks.slack.com,webhook.site",
      CLOCKCHAIN_SUBSTRATE: "anchoring-gateway",
      STANDALONE_PUBLIC_ENDPOINT: "https://mcp.clockchain.network/connect/mcp",
      ERC8004_REGISTRY_ADDRESS: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
      CLOCKCHAIN_API_KEY: "dummy-api",
      MCP_AUTH_TOKENS: "dummy-token",
      MCP_TOKEN_SIGNING_SECRET: "dummy-signing",
      CLOCKCHAIN_SIGNING_SECRET: "dummy-gateway-signing",
      AGENT_HANDSHAKE_RELEASE_PIN: JSON.stringify({
        version: "2.1.8",
        sourceCommit: expectedHandshakeSha,
        manifestDigest: "a".repeat(64),
        allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/",
        hostRoots: [{ kid: "root-2026-08", fingerprint: "b".repeat(64) }],
      }),
      AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: "dummy-role-active",
      AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS: "dummy-role-previous",
      AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: "dummy-accept-active",
      AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS: "dummy-accept-previous",
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
  // The MCP anchors to the owned gateway with payload-bound signing: both halves of the pair reach the container.
  assert.match(compose, /CLOCKCHAIN_SIGNING_SECRET:\s*"\$\{CLOCKCHAIN_SIGNING_SECRET\}"/);
  assert.match(compose, /CLOCKCHAIN_SIGNING_KEY_ID:\s*"\$\{CLOCKCHAIN_SIGNING_KEY_ID\}"/);
  // Timer/alarm keeper store lives on the persistent mcp_state volume.
  assert.match(compose, /KEEPER_STORE_PATH:\s*"\$\{KEEPER_STORE_PATH\}"/);
  assert.match(compose, /KEEPER_WEBHOOK_SECRET:\s*"\$\{KEEPER_WEBHOOK_SECRET\}"/);
  assert.match(compose, /KEEPER_WEBHOOK_ALLOWLIST:\s*"\$\{KEEPER_WEBHOOK_ALLOWLIST\}"/);
  assert.match(compose, /CLOCKCHAIN_SUBSTRATE:\s*"\$\{CLOCKCHAIN_SUBSTRATE\}"/);
  // Standalone Handshake: dedicated webhook secret and a pinned public endpoint (never Host-derived).
  assert.match(compose, /STANDALONE_WEBHOOK_SECRET:\s*"\$\{STANDALONE_WEBHOOK_SECRET\}"/);
  assert.match(compose, /STANDALONE_PUBLIC_ENDPOINT:\s*"\$\{STANDALONE_PUBLIC_ENDPOINT\}"/);
  const wrapperSource = await readFile(wrapper, "utf8");
  assert.match(wrapperSource, /read_secret CLOCKCHAIN_SIGNING_SECRET \/clockchain\/mcp\/GATEWAY_SIGNING_SECRET/);
  assert.match(wrapperSource, /CLOCKCHAIN_ENDPOINT=http:\/\/clockchain-anchor-gateway:8090/);
  assert.doesNotMatch(wrapperSource, /CLOCKCHAIN_ENDPOINT=https:\/\/node\.clockchain\.network/);
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
  for (const name of [...expectedSecretNames, ...expectedOptionalSecretNames, ...expectedHostSecretNames]) {
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
  assert.equal(mcp.environment.CLOCKCHAIN_ENDPOINT, "http://clockchain-anchor-gateway:8090");
  assert.equal(mcp.environment.CLOCKCHAIN_SIGNING_KEY_ID, "default");
  assert.equal(mcp.environment.CLOCKCHAIN_SIGNING_SECRET, "dummy-gateway-signing");
  assert.equal(mcp.environment.KEEPER_STORE_PATH, "/app/state/keeper-store.json");
  assert.equal(mcp.environment.KEEPER_WEBHOOK_ALLOWLIST, "hooks.slack.com,webhook.site");
  assert.equal(mcp.environment.CLOCKCHAIN_SUBSTRATE, "anchoring-gateway");
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
      [...expectedSecretNames, ...expectedOptionalSecretNames, ...expectedContractParamNames, ...expectedHostSecretNames],
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
        // The bin/ stubs are test-authored fixtures, not wrapper output —
        // the aws stub legitimately embeds every fixture value (it plays the
        // SSM responder), and degenerate flag values like "1\n"/"0\n" would
        // false-positive inside any shell script.
        file.startsWith(`${temp}${path.sep}bin${path.sep}`) ||
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

test("compose wrapper without arguments brings up the whole stack (systemd full restart path)", async () => {
  const { temp, dockerArgsFile, env } = await createWrapperFixture();
  try {
    const result = await run(wrapper, [], { cwd: temp, env });
    assert.equal(result.code, 0, result.stderr);
    const args = (await readFile(dockerArgsFile, "utf8")).trim();
    assert.match(args, /^-f \S+docker-compose\.yml up -d --build --wait --wait-timeout 180$/);
    assert.doesNotMatch(args, /--no-deps/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

for (const onlyArgs of [["--only", "mcp"], ["--only=mcp"]]) {
  test(`compose wrapper ${onlyArgs.join(" ")} recreates only mcp with the same mcp environment and leaves host files alone`, async () => {
    const { temp, callsFile, dockerOkFile, dockerArgsFile, env } = await createWrapperFixture({
      env: { EXPECT_MCP_ONLY: "1" },
    });
    try {
      const result = await run(wrapper, onlyArgs, { cwd: temp, env });
      assert.equal(result.code, 0, result.stderr);
      // env-check.mjs asserted the full mcp env (every secret byte-for-byte + nonsecret config).
      assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
      const args = (await readFile(dockerArgsFile, "utf8")).trim();
      assert.match(
        args,
        /^-f \S+docker-compose\.yml up -d --no-deps --build --wait --wait-timeout 180 mcp$/,
        "only the mcp service is recreated; caddy and host are not touched",
      );
      const calls = (await readFile(callsFile, "utf8")).trim().split("\n");
      assert.deepEqual(
        calls.map((line) => line.match(/--name ([^ ]+)/)?.[1]),
        [...expectedSecretNames, ...expectedOptionalSecretNames, ...expectedContractParamNames],
        "mcp-only fetches the mcp secrets and no host secrets",
      );
      assert.equal(await pathExists(env.EXPECTED_HOST_SECRET_DIR), false, "host secret files are not rewritten");
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  });
}

test("compose wrapper rejects unknown arguments before any secret fetch or docker", async () => {
  for (const args of [["--only"], ["--only", "caddy"], ["--only", "host"], ["mcp"]]) {
    const { temp, callsFile, dockerInvokedFile, env } = await createWrapperFixture();
    try {
      const result = await run(wrapper, args, { cwd: temp, env });
      assert.equal(result.code, 64, args.join(" "));
      assert.equal(await pathExists(callsFile), false, "no SSM call");
      assert.equal(await pathExists(dockerInvokedFile), false, "docker not invoked");
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
});

test("compose wrapper --only mcp still fails closed on a bad secret before docker", async () => {
  const { temp, dockerInvokedFile, env } = await createWrapperFixture({
    env: { EXPECT_MCP_ONLY: "1", AWS_DENY_PARAMETER: "/clockchain/mcp/MCP_AUTH_TOKENS" },
  });
  try {
    const result = await run(wrapper, ["--only", "mcp"], { cwd: temp, env });
    assert.notEqual(result.code, 0);
    assert.equal(await pathExists(dockerInvokedFile), false, "docker not invoked");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("deploy wrapper and v2 runtime declare one helper release line and derive the asset prefix", async () => {
  const wrapperBody = await readFile(wrapper, "utf8");
  const instructions = await readFile(
    path.join(repoRoot, "packages", "mcp-server", "src", "agent-handshake", "v2", "instructions.ts"),
    "utf8",
  );

  const wrapperVersion = wrapperBody.match(/^[ \t]*v2_helper_version="([0-9]+\.[0-9]+\.[0-9]+)"$/m)?.[1];
  const runtimeVersion = instructions.match(/^export const V2_HELPER_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)";$/m)?.[1];
  assert.ok(wrapperVersion, "compose-up.sh declares v2_helper_version");
  assert.ok(runtimeVersion, "instructions.ts declares V2_HELPER_VERSION");
  assert.equal(wrapperVersion, runtimeVersion, "deploy wrapper and runtime pin the same helper release");

  const expectedPrefix =
    `https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v${runtimeVersion}/`;
  assert.match(
    wrapperBody,
    /^[ \t]*v2_helper_asset_prefix="https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\/releases\/download\/v\$\{v2_helper_version\}\/"$/m,
    "compose-up.sh derives the asset prefix from its declared version",
  );
  assert.match(
    instructions,
    /^export const V2_HELPER_ASSET_PREFIX =\s*\n?\s*`https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\/releases\/download\/v\$\{V2_HELPER_VERSION\}\/`;/m,
    "instructions.ts derives the asset prefix from V2_HELPER_VERSION",
  );
  for (const body of [wrapperBody, instructions]) {
    assert.equal(body.includes(expectedPrefix) || body.includes(`v${runtimeVersion}/`), false,
      "no literal release prefix is scattered outside the derived declarations");
  }
  assert.equal(
    instructions.includes('manifest.version!=="${V2_HELPER_VERSION}"'),
    true,
    "the verified bootstrap checks the declared version, not a literal",
  );
  assert.equal(
    wrapperBody.includes("$helperVersion") && wrapperBody.includes("$helperPrefix"),
    true,
    "the jq release filter consumes the declared version and prefix",
  );
});

test("compose wrapper runs under a systemd PATH with no node on it", async () => {
  // Production runs the wrapper as a systemd unit; that PATH has no node.
  // Reproduce it here: PATH is only the fixture bin dir plus the system dirs,
  // with a `node` stub that exits 127 in case node lives in a system dir on
  // the test host. Any bare `node` invocation in the wrapper fails the run.
  const { temp, dockerOkFile, env } = await createWrapperFixture();
  try {
    const jqPath = spawnSync("which", ["jq"], { encoding: "utf8" }).stdout.trim();
    assert.ok(jqPath, "jq must be installed to run this test");
    const binDir = path.join(temp, "bin");
    await symlink(jqPath, path.join(binDir, "jq"));
    await writeFile(path.join(binDir, "node"), "#!/usr/bin/env bash\nexit 127\n", { mode: 0o755 });

    const result = await run(wrapper, [], {
      cwd: temp,
      env: { ...env, PATH: `${binDir}:/usr/bin:/bin` },
    });

    assert.equal(result.code, 0, result.stderr);
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
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
    // Trailing \n in sourceCommit: slips past a $-anchored jq regex — must
    // still fail closed via \z anchoring.
    { AGENT_HANDSHAKE_RELEASE_PIN_PARAM: "/clockchain/mcp/NEWLINE_RELEASE_PIN" },
    { AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS_PARAM: "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE" },
  ]) {
    const { temp, dockerInvokedFile, dockerOkFile, env } = await createWrapperFixture({ env: extra });
    try {
      const result = await run(wrapper, [], { cwd: temp, env });
      assert.notEqual(result.code, 0);
      assert.equal(await pathExists(dockerInvokedFile), false, "docker compose was not invoked");
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

test("compose wrapper rejects unsafe acceptance HMAC rotation before docker", async () => {
  for (const extra of [
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS_PARAM: "/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE" },
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE" },
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/BAD_ACCEPTANCE_HMAC_BASE64" },
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/SHORT_ACCEPTANCE_HMAC" },
    // Escaped trailing newline: jq's $ anchors before \n and $() strips it —
    // these must still fail closed, matching the strict runtime validator.
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/NEWLINE_KID_HMAC" },
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/NEWLINE_SECRET_HMAC" },
    // Nonzero pad bits at valid apparent length: structurally plausible but
    // not canonical base64 — must fail the decode-and-reencode check.
    { AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE_PARAM: "/clockchain/mcp/NONCANONICAL_PAD_HMAC" },
  ]) {
    const { temp, dockerInvokedFile, dockerOkFile, env } = await createWrapperFixture({ env: extra });
    try {
      const result = await run(wrapper, [], { cwd: temp, env });
      assert.notEqual(result.code, 0);
      assert.equal(await pathExists(dockerInvokedFile), false, "docker compose was not invoked");
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

test("compose wrapper treats missing optional previous acceptance HMAC as absent", async () => {
  const { temp, callsFile, dockerOkFile, env } = await createWrapperFixture({
    env: { AWS_PARAMETER_NOT_FOUND: "/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS" },
  });

  try {
    await writeFile(
      env.EXPECTED_ENV_FILE,
      JSON.stringify({ ...expectedEnv, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS: "" }),
      "utf8",
    );

    const result = await run(wrapper, [], { cwd: temp, env });

    assert.equal(result.code, 0, result.stderr);
    const calls = (await readFile(callsFile, "utf8")).trim().split("\n");
    assert.deepEqual(
      calls.map((line) => line.match(/--name ([^ ]+)/)?.[1]),
      [...expectedSecretNames, ...expectedOptionalSecretNames, ...expectedContractParamNames, ...expectedHostSecretNames],
    );
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
    for (const secret of [...Object.values(expectedEnv), ...Object.values(expectedHostSecrets)]) {
      assert.equal(result.stdout.includes(secret), false);
      assert.equal(result.stderr.includes(secret), false);
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper fails closed on optional previous acceptance HMAC fetch corruption", async () => {
  const previousParam = "/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS";
  for (const extra of [
    { AWS_DENY_PARAMETER: previousParam },
    { AWS_TRANSIENT_PARAMETER: previousParam },
    { AWS_MALFORMED_PARAMETER: previousParam },
    { AWS_FAIL_PARAMETER: previousParam },
  ]) {
    const { temp, dockerInvokedFile, dockerOkFile, env } = await createWrapperFixture({ env: extra });
    try {
      const result = await run(wrapper, [], { cwd: temp, env });
      assert.notEqual(result.code, 0);
      assert.equal(await pathExists(dockerInvokedFile), false, "docker compose was not invoked");
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

test("compose wrapper reads the /contract/mcp surface optionally — absent params leave the env untouched", async () => {
  // CONTRACT_MCP_ENABLED absent in SSM and unset on the host: the route ships
  // disabled — the variable must stay UNSET (never exported empty).
  const { temp, callsFile, dockerOkFile, env } = await createWrapperFixture({
    env: {
      AWS_PARAMETER_NOT_FOUND: "/clockchain/mcp/CONTRACT_MCP_ENABLED",
      EXPECTED_UNSET: "CONTRACT_MCP_ENABLED",
    },
  });

  try {
    const { CONTRACT_MCP_ENABLED: _dropped, ...expectedMinusEnabled } = expectedEnv;
    await writeFile(env.EXPECTED_ENV_FILE, JSON.stringify(expectedMinusEnabled), "utf8");

    const result = await run(wrapper, [], { cwd: temp, env });

    assert.equal(result.code, 0, result.stderr);
    const calls = (await readFile(callsFile, "utf8")).trim().split("\n");
    assert.deepEqual(
      calls.map((line) => line.match(/--name ([^ ]+)/)?.[1]),
      [...expectedSecretNames, ...expectedOptionalSecretNames, ...expectedContractParamNames, ...expectedHostSecretNames],
      "the parameter is still fetched — only the export is skipped",
    );
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
    for (const secret of [...Object.values(expectedEnv), ...Object.values(expectedHostSecrets)]) {
      assert.equal(result.stdout.includes(secret), false);
      assert.equal(result.stderr.includes(secret), false);
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper preserves a pre-set contract env override when the SSM parameter is absent", async () => {
  const { temp, dockerOkFile, env } = await createWrapperFixture({
    env: {
      AWS_PARAMETER_NOT_FOUND: "/clockchain/mcp/CONTRACT_OBSERVER_TOKEN",
      CONTRACT_OBSERVER_TOKEN: "operator-preset-observer",
    },
  });

  try {
    await writeFile(
      env.EXPECTED_ENV_FILE,
      JSON.stringify({ ...expectedEnv, CONTRACT_OBSERVER_TOKEN: "operator-preset-observer" }),
      "utf8",
    );

    const result = await run(wrapper, [], { cwd: temp, env });

    assert.equal(result.code, 0, result.stderr);
    assert.equal(await readFile(dockerOkFile, "utf8"), "ok\n");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("compose wrapper fails closed naming the parameter on a non-ParameterNotFound contract fetch error", async () => {
  const param = "/clockchain/mcp/CONTRACT_MCP_ENABLED";
  for (const extra of [
    { AWS_DENY_PARAMETER: param },
    { AWS_TRANSIENT_PARAMETER: param },
    { AWS_MALFORMED_PARAMETER: param },
  ]) {
    const { temp, dockerInvokedFile, dockerOkFile, env } = await createWrapperFixture({ env: extra });
    try {
      const result = await run(wrapper, [], { cwd: temp, env });
      assert.notEqual(result.code, 0, JSON.stringify(extra));
      assert.match(result.stderr, /CONTRACT_MCP_ENABLED/, "the failing parameter is named");
      assert.equal(await pathExists(dockerInvokedFile), false, "docker compose was not invoked");
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

// ---- deploy-box.sh + installer, executed against stub sudo/git/docker/systemctl/stat ----

const testSha = "0123456789abcdef0123456789abcdef01234567";
const stubMarker = "# deploy-box: supports --only mcp";

async function writeExecutable(file, body) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, body, { mode: 0o755 });
  await chmod(file, 0o755);
}

// A fake box: APP_ROOT with the REAL installer + unit, a logging compose-up.sh stub, and stub
// commands that append every invocation to one command log.
async function createBoxFixture({ oldTarget = false } = {}) {
  const temp = await mkdtemp(path.join(tmpdir(), "clockchain-deploy-box-test."));
  const app = path.join(temp, "app");
  const bin = path.join(temp, "bin");
  const log = path.join(temp, "commands.log");
  const installRoot = path.join(temp, "install");
  const systemdDir = path.join(temp, "systemd");
  await mkdir(systemdDir, { recursive: true });
  const appInstaller = path.join(app, "infra", "scripts", "install-clockchain-mcp-deploy-assets.sh");
  const appComposeUp = path.join(app, "infra", "clockchain-mcp", "compose-up.sh");
  await mkdir(path.dirname(appComposeUp), { recursive: true });
  await writeFile(path.join(app, "infra", "clockchain-mcp", "clockchain-mcp.service"), await readFile(systemdUnit, "utf8"));
  if (oldTarget) {
    // Pre-code-only versions: ignore every argument, always restart / always bring up everything.
    await writeExecutable(appInstaller, `#!/usr/bin/env bash\nset -euo pipefail\nsystemctl restart clockchain-mcp.service\n`);
    await writeExecutable(appComposeUp, `#!/usr/bin/env bash\nprintf 'compose-up %s\\n' "$*" >> "$CMD_LOG"\n`);
  } else {
    await writeExecutable(appInstaller, await readFile(installScript, "utf8"));
    await writeExecutable(appComposeUp, `#!/usr/bin/env bash\n${stubMarker} (test stub)\nprintf 'compose-up %s\\n' "$*" >> "$CMD_LOG"\n`);
  }
  const logLine = `printf '%s %s\\n' "$(basename "$0")" "$*" >> "$CMD_LOG"`;
  await writeExecutable(path.join(bin, "stat"), `#!/usr/bin/env bash\necho owner\n`);
  await writeExecutable(path.join(bin, "sudo"), `#!/usr/bin/env bash\n${logLine}\n[[ "$1" == "-u" ]] && shift 2\nexec "$@"\n`);
  await writeExecutable(
    path.join(bin, "git"),
    `#!/usr/bin/env bash
${logLine}
[[ "$1" == "-c" ]] && shift 2
case "$1 \${2:-}" in
  "rev-parse --short") echo abc1234 ;;
  "rev-parse HEAD") echo ${"f".repeat(40)} ;;
  "status --short") printf '%s' "\${FAKE_DIRTY:-}" ;;
  "diff --name-only") printf '%s' "\${FAKE_DIFF:-}" ;;
  show*) cat "$APP_ROOT_FOR_TEST/\${2#*:}" ;;
  *) ;;
esac
`,
  );
  await writeExecutable(
    path.join(bin, "docker"),
    `#!/usr/bin/env bash
${logLine}
case "$*" in
  *" ps -aq caddy host mcp") printf 'c1\\nh1\\nm1\\n' ;;
  inspect*) echo "/\${!#} created=2026-09-01T00:00:00Z started=2026-09-01T00:00:00Z" ;;
esac
`,
  );
  await writeExecutable(
    path.join(bin, "systemctl"),
    `#!/usr/bin/env bash\n${logLine}\n[[ "$1" == "is-active" ]] && echo active\nexit 0\n`,
  );
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    CMD_LOG: log,
    APP_ROOT_FOR_TEST: app,
    CLOCKCHAIN_MCP_APP_ROOT: app,
    CLOCKCHAIN_MCP_INSTALL_ROOT: installRoot,
    CLOCKCHAIN_MCP_SYSTEMD_DIR: systemdDir,
  };
  return { temp, app, appInstaller, log, installRoot, systemdDir, env };
}

async function renderRemote(args, env) {
  const r = await run("bash", [deployBoxScript, ...args], {
    cwd: repoRoot,
    env: { ...env, DEPLOY_BOX_TEST_RENDER_REMOTE_DO_NOT_DEPLOY: "1" },
  });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /RENDER ONLY — nothing deployed/);
  return r.stdout;
}

async function runRemote(fixture, args, extraEnv = {}) {
  const script = await renderRemote([testSha, ...args], fixture.env);
  const scriptFile = path.join(fixture.temp, "remote.sh");
  await writeFile(scriptFile, script);
  const syntax = await run("bash", ["-n", scriptFile], {});
  assert.equal(syntax.code, 0, `rendered remote script parses: ${syntax.stderr}`);
  const result = await run("bash", [scriptFile], { cwd: fixture.temp, env: { ...fixture.env, ...extraEnv } });
  const log = (await readFile(fixture.log, "utf8").catch(() => "")).split("\n").filter(Boolean);
  return { ...result, log };
}

const indexOfLine = (log, re) => log.findIndex((line) => re.test(line));

test("remote script, code-only: installs without restart, then recreates only mcp", async () => {
  const fx = await createBoxFixture();
  try {
    const r = await runRemote(fx, []);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(indexOfLine(r.log, /^systemctl restart/), -1, "no systemctl restart in code-only");
    assert.equal(indexOfLine(r.log, /^systemctl stop/), -1);
    const checkout = indexOfLine(r.log, new RegExp(`^git .*checkout --quiet --detach ${testSha}$`));
    const build = indexOfLine(r.log, /^docker compose -f infra\/clockchain-mcp\/docker-compose\.yml build mcp$/);
    const reload = indexOfLine(r.log, /^systemctl daemon-reload$/);
    const composeUp = indexOfLine(r.log, /^compose-up --only mcp$/);
    assert.ok(checkout >= 0 && build > checkout, "checkout, then pre-build");
    assert.ok(reload > build, "installer (--no-restart) ran after the pre-build");
    assert.ok(composeUp > reload, "--no-restart installer runs before compose-up.sh --only mcp");
    assert.equal(r.log.filter((l) => l.startsWith("compose-up")).length, 1);
    // Installed copies refreshed on disk.
    assert.equal(await pathExists(path.join(fx.installRoot, "compose-up.sh")), true);
    assert.equal(await pathExists(path.join(fx.systemdDir, "clockchain-mcp.service")), true);
    // Container times printed before and after.
    assert.match(r.stdout, /container times BEFORE[\s\S]*\/h1 created=[\s\S]*container times AFTER[\s\S]*\/c1 created=/);
    assert.match(r.stdout, /deploy assets installed; clockchain-mcp\.service NOT restarted/);
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

test("remote script, --full-restart: runs the installer, which restarts the unit", async () => {
  const fx = await createBoxFixture();
  try {
    const r = await runRemote(fx, ["--full-restart"]);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const build = indexOfLine(r.log, /build mcp$/);
    const restart = indexOfLine(r.log, /^systemctl restart clockchain-mcp\.service$/);
    assert.ok(restart > build, "full mode restarts the unit after the pre-build");
    assert.equal(indexOfLine(r.log, /^compose-up/), -1, "full mode does not call compose-up.sh directly");
    assert.equal(indexOfLine(r.log, /^git .* show /), -1, "no code-only capability probe in full mode");
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

test("remote script refuses a code-only rollback to a target that predates code-only deploys", async () => {
  const fx = await createBoxFixture({ oldTarget: true });
  try {
    const r = await runRemote(fx, []);
    assert.equal(r.code, 4, r.stdout + r.stderr);
    assert.match(r.stdout, /target predates code-only deploy; re-run with --full-restart/);
    assert.equal(indexOfLine(r.log, /checkout/), -1, "box checkout untouched");
    assert.equal(indexOfLine(r.log, /^systemctl/), -1);
    assert.equal(indexOfLine(r.log, /^compose-up/), -1);
    assert.equal(indexOfLine(r.log, /build mcp/), -1);

    // The same target deploys with an explicit --full-restart.
    await writeFile(fx.log, "");
    const full = await runRemote(fx, ["--full-restart"]);
    assert.equal(full.code, 0, full.stdout + full.stderr);
    assert.ok(indexOfLine(full.log, /^systemctl restart clockchain-mcp\.service$/) >= 0);
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

for (const file of [
  "infra/clockchain-mcp/Caddyfile",
  "infra/clockchain-mcp/docker-compose.yml",
  "infra/clockchain-mcp/clockchain-mcp.service",
  "infra/scripts/install-clockchain-mcp-deploy-assets.sh",
  "infra/clockchain-mcp/compose-up.sh",
]) {
  test(`remote script refuses code-only infra drift in ${path.basename(file)} unless --allow-infra-drift`, async () => {
    const fx = await createBoxFixture();
    try {
      const refused = await runRemote(fx, [], { FAKE_DIFF: `${file}\n` });
      assert.equal(refused.code, 5, refused.stdout + refused.stderr);
      assert.match(refused.stdout, /REFUSING: infra drift in code-only mode; re-run with --full-restart .* or --allow-infra-drift/);
      assert.equal(indexOfLine(refused.log, /checkout/), -1, "box checkout untouched");
      assert.equal(indexOfLine(refused.log, /^compose-up/), -1);
      const diffCall = refused.log[indexOfLine(refused.log, /diff --name-only/)];
      assert.ok(diffCall.includes(file), `drift check covers ${file}`);

      await writeFile(fx.log, "");
      const allowed = await runRemote(fx, ["--allow-infra-drift"], { FAKE_DIFF: `${file}\n` });
      assert.equal(allowed.code, 0, allowed.stdout + allowed.stderr);
      assert.match(allowed.stdout, /WARNING: --allow-infra-drift/);
      assert.equal(indexOfLine(allowed.log, /^systemctl restart/), -1);
      assert.ok(indexOfLine(allowed.log, /^compose-up --only mcp$/) >= 0);
    } finally {
      await rm(fx.temp, { recursive: true, force: true });
    }
  });
}

test("remote script still refuses a dirty box checkout before fetching", async () => {
  const fx = await createBoxFixture();
  try {
    for (const args of [[], ["--full-restart"]]) {
      await writeFile(fx.log, "");
      const r = await runRemote(fx, args, { FAKE_DIRTY: " M infra/clockchain-mcp/Caddyfile\n" });
      assert.equal(r.code, 3);
      assert.match(r.stdout, /REFUSING: the box checkout has local changes/);
      assert.equal(indexOfLine(r.log, /fetch|checkout|^systemctl|^compose-up/), -1);
    }
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

test("remote script redirects stdin of child commands so they cannot swallow the SSM heredoc", async () => {
  const fx = await createBoxFixture();
  try {
    const body = await renderRemote([testSha], fx.env);
    for (const re of [
      /"\$INSTALLER" <\/dev\/null/,
      /"\$INSTALLER" --no-restart <\/dev\/null/,
      /"\$COMPOSE_UP" --only mcp <\/dev\/null/,
      /build mcp <\/dev\/null/,
      /checkout --quiet --detach "\$SHA" <\/dev\/null/,
    ]) {
      assert.match(body, re);
    }
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

test("installer run with a stub systemctl: --no-restart never restarts; default restarts; extra args rejected", async () => {
  const fx = await createBoxFixture();
  try {
    const noRestart = await run(fx.appInstaller, ["--no-restart"], { env: fx.env });
    assert.equal(noRestart.code, 0, noRestart.stderr);
    let log = await readFile(fx.log, "utf8");
    assert.match(log, /^systemctl daemon-reload$/m);
    assert.match(log, /^systemctl enable clockchain-mcp\.service$/m);
    assert.doesNotMatch(log, /restart/);
    assert.equal(await pathExists(path.join(fx.installRoot, "compose-up.sh")), true);

    await writeFile(fx.log, "");
    const full = await run(fx.appInstaller, [], { env: fx.env });
    assert.equal(full.code, 0, full.stderr);
    log = await readFile(fx.log, "utf8");
    assert.match(log, /^systemctl restart clockchain-mcp\.service$/m);

    for (const bad of [["--no-restart", "--no-restart"], ["--no-restart", "x"], ["--restart"]]) {
      await writeFile(fx.log, "");
      const r = await run(fx.appInstaller, bad, { env: fx.env });
      assert.equal(r.code, 64, JSON.stringify(bad));
      assert.equal(await readFile(fx.log, "utf8"), "", "no systemctl call on bad args");
    }
  } finally {
    await rm(fx.temp, { recursive: true, force: true });
  }
});

test("the repo's installer and compose-up.sh carry the code-only capability markers deploy-box checks", async () => {
  assert.match(await readFile(installScript, "utf8"), /^# deploy-box: supports --no-restart/m);
  assert.match(await readFile(wrapper, "utf8"), /^# deploy-box: supports --only mcp/m);
  const src = await readFile(deployBoxScript, "utf8");
  assert.ok(src.includes('*"deploy-box: supports --no-restart"*'));
  assert.ok(src.includes('*"deploy-box: supports --only mcp"*'));
});

// Local side of deploy-box.sh after SSM returns: stub aws/git/sleep/curl, real jq.
async function runDeployBoxAgainstSsmResult({ status, responseCode, stdout }) {
  const temp = await mkdtemp(path.join(tmpdir(), "clockchain-deploy-box-local."));
  const bin = path.join(temp, "bin");
  const log = path.join(temp, "commands.log");
  const invocation = path.join(temp, "invocation.json");
  await writeFile(invocation, JSON.stringify({
    Status: status,
    ResponseCode: responseCode,
    StandardOutputContent: stdout,
    StandardErrorContent: "",
  }));
  const logLine = `printf '%s %s\\n' "$(basename "$0")" "$*" >> "$CMD_LOG"`;
  await writeExecutable(path.join(bin, "aws"), `#!/usr/bin/env bash
${logLine}
case "$*" in
  *"send-command"*) echo cmd-123 ;;
  *"--query Status"*) echo "$FAKE_STATUS" ;;
  *"get-command-invocation"*"--output json"*) cat "$FAKE_INVOCATION" ;;
  *) echo "unexpected aws: $*" >&2; exit 65 ;;
esac
`);
  await writeExecutable(path.join(bin, "git"), `#!/usr/bin/env bash\n${logLine}\n[[ "$1" == "log" ]] && echo "abc1234 subject"\nexit 0\n`);
  await writeExecutable(path.join(bin, "sleep"), `#!/usr/bin/env bash\nexit 0\n`);
  await writeExecutable(path.join(bin, "curl"), `#!/usr/bin/env bash\n${logLine}\necho 200\n`);
  try {
    const r = await run("bash", [deployBoxScript, testSha, "--yes"], {
      cwd: repoRoot,
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        CMD_LOG: log,
        FAKE_STATUS: status,
        FAKE_INVOCATION: invocation,
        CC_MCP_TOKEN: "",
      },
    });
    const calls = (await readFile(log, "utf8").catch(() => "")).split("\n").filter(Boolean);
    return { ...r, calls };
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

test("deploy-box.sh reports box-side refusals as REFUSED with the remote exit code, production unchanged", async () => {
  for (const [code, line] of [
    [3, "REFUSING: the box checkout has local changes. Commit them to the repo (or preserve them on a local branch) first:"],
    [4, "REFUSING: target predates code-only deploy; re-run with --full-restart"],
    [5, "REFUSING: infra drift in code-only mode; re-run with --full-restart (after the notices) or --allow-infra-drift"],
  ]) {
    const r = await runDeployBoxAgainstSsmResult({
      status: "Failed",
      responseCode: code,
      stdout: `box: mode=code-only before=abc1234\n${line}\n`,
    });
    assert.equal(r.code, code, r.stderr);
    assert.match(r.stderr, new RegExp(`REFUSED \\(exit ${code}\\): .+ — production unchanged`));
    assert.ok(r.stderr.includes(line.replace(/^REFUSING: /, "")), "reason is the box's REFUSING line");
    assert.doesNotMatch(r.stderr, /deploy FAILED/);
    assert.equal(r.calls.filter((c) => c.startsWith("curl")).length, 0, "no canaries after a refusal");
  }
});

test("deploy-box.sh keeps 'deploy FAILED' (exit 1) for real remote failures", async () => {
  for (const result of [
    { status: "Failed", responseCode: 1, stdout: "box: pre-build\nerror\n" },
    // Exit code in the refusal range but no REFUSING line: a child failed after the checkout.
    { status: "Failed", responseCode: 3, stdout: "box: after=abc1234\ncompose failed\n" },
    // REFUSING text but a non-refusal exit code.
    { status: "Failed", responseCode: 1, stdout: "REFUSING: something\n" },
    { status: "TimedOut", responseCode: -1, stdout: "" },
  ]) {
    const r = await runDeployBoxAgainstSsmResult(result);
    assert.equal(r.code, 1, JSON.stringify(result) + r.stderr);
    assert.match(r.stderr, /deploy FAILED \(.+\) — production may be on the previous build; see the runbook rollback\./);
    assert.doesNotMatch(r.stderr, /REFUSED/);
  }
});

test("deploy-box.sh proceeds to the canaries when the remote run succeeds", async () => {
  const r = await runDeployBoxAgainstSsmResult({ status: "Success", responseCode: 0, stdout: "box: up\n" });
  // The stub curl answers 200 everywhere, so the /mcp 401 canary is what stops it: it did reach the canaries.
  assert.ok(r.calls.some((c) => c.startsWith("curl")), "canaries ran");
  assert.doesNotMatch(r.stderr, /REFUSED|deploy FAILED/);
  assert.match(r.stdout, /box: up/);
});

async function deployBoxParse(args) {
  return run("bash", [deployBoxScript, ...args], {
    cwd: repoRoot,
    env: { ...process.env, DEPLOY_BOX_TEST_PARSE_ONLY_DO_NOT_DEPLOY: "1" },
  });
}

test("deploy-box.sh defaults to the code-only mode and accepts flags in any order", async () => {
  const sha = testSha;
  const plain = await deployBoxParse([sha]);
  assert.equal(plain.code, 0, plain.stderr);
  assert.match(plain.stderr, /PARSE ONLY — nothing deployed/);
  assert.match(plain.stderr, /MODE: CODE-ONLY \(default\)/);
  assert.match(plain.stdout, new RegExp(`mode=code-only sha=${sha} confirm=0 allow_infra_drift=0`));
  assert.doesNotMatch(plain.stderr, /FULL RESTART/);

  for (const args of [[sha, "--yes"], ["--yes", sha]]) {
    const r = await deployBoxParse(args);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`mode=code-only sha=${sha} confirm=1`));
  }
  for (const args of [["--allow-infra-drift", sha], [sha, "--yes", "--allow-infra-drift"]]) {
    const r = await deployBoxParse(args);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /mode=code-only .* allow_infra_drift=1/);
  }
  for (const args of [[sha, "--full-restart"], ["--full-restart", sha, "--yes"], ["--yes", "--full-restart", sha]]) {
    const r = await deployBoxParse(args);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stderr, /MODE: FULL RESTART \(--full-restart\)/);
    assert.match(r.stderr, /travel_mvp orchestrator AND the ACM4 production owner/);
    assert.match(r.stdout, new RegExp(`mode=full-restart sha=${sha} confirm=${args.includes("--yes") ? 1 : 0}`));
  }
  for (const args of [[], ["abc"], [sha, "--bogus"], [sha, sha], ["--yes"]]) {
    const r = await deployBoxParse(args);
    assert.equal(r.code, 64, `rejects ${JSON.stringify(args)}`);
  }
  // Canaries unchanged.
  const src = await readFile(deployBoxScript, "utf8");
  assert.match(src, /\/next\/handshake\/mcp/);
  assert.match(src, /mcp without creds \$A \(expect 401\)/);
});

test("release runbook reinstalls deploy assets before every MCP restart", async () => {
  const runbook = await readFile(path.join(deployDir, "RUNBOOK.md"), "utf8");
  assert.match(
    runbook,
    /infra\/scripts\/install-clockchain-mcp-deploy-assets\.sh/,
    "deploys must refresh the out-of-checkout systemd wrapper before restart",
  );
  assert.doesNotMatch(
    runbook,
    /then run `compose-up\.sh`/,
    "the copied wrapper must not be invoked without first reinstalling it",
  );
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

test("mcp-server ships the AWS SDK clients its lazy import()s need as runtime deps", async () => {
  // settlement-rail.ts resolves the Stripe test key via
  // `await import("@aws-sdk/client-secrets-manager")` and
  // scripts/agent-contract/check-config-from-ssm.mjs reads config via
  // `await import("@aws-sdk/client-ssm")`. Both must land in the production
  // image (npm ci + npm prune --omit=dev → /app/node_modules), so they have to
  // be pinned entries in "dependencies", not devDependencies.
  const pkg = JSON.parse(await readFile(mcpServerPackageJson, "utf8"));
  for (const dep of ["@aws-sdk/client-secrets-manager", "@aws-sdk/client-ssm"]) {
    assert.match(
      pkg.dependencies?.[dep] ?? "",
      /^\d+\.\d+\.\d+$/,
      `${dep} must be an exact-pinned runtime dependency`,
    );
    assert.equal(pkg.devDependencies?.[dep], undefined, `${dep} must not be dev-only`);
  }
});
