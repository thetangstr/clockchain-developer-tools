import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

// sink-up.sh is the box-side half of the D22 sink deploy (run as root over
// SSM). These tests run it against fake docker/aws/git binaries and assert
// it only ever touches the telemetry-sink container and reloads caddy in
// place — never a down, a full restart, or a caddy/host/mcp recreate.

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const script = path.join(repoRoot, "infra", "clockchain-mcp", "telemetry-sink", "sink-up.sh");
const PROD_KEYS = '{"contract-server-v1":{"kty":"OKP","crv":"Ed25519","x":"J3iURWKkx4kAg-leW-NDKp7AUZQNdowUfLb5HHlQ0xU"}}';

function fixture({ ssmValue = PROD_KEYS, ssmMissing = false, sinkRunning = false, inspect = 'echo "/c created=2026-10-01T00:00:00Z started=2026-10-01T00:00:00Z"' } = {}) {
  const temp = mkdtempSync(path.join(tmpdir(), "sink-up-"));
  const bin = path.join(temp, "bin");
  const app = path.join(temp, "app");
  mkdirSync(bin);
  mkdirSync(path.join(app, "infra", "clockchain-mcp"), { recursive: true });
  writeFileSync(path.join(app, "infra", "clockchain-mcp", "Caddyfile"), "mcp.clockchain.network {\n}\n");
  writeFileSync(path.join(app, "infra", "clockchain-mcp", "docker-compose.yml"), "services: {}\n");
  const log = path.join(temp, "calls.log");
  const fake = (name, body) => {
    const file = path.join(bin, name);
    writeFileSync(file, `#!/usr/bin/env bash\nprintf '%s %s\\n' ${name} "$*" >> ${JSON.stringify(log)}\n${body}\n`);
    chmodSync(file, 0o755);
  };
  fake("aws", ssmMissing
    ? "echo 'ParameterNotFound' >&2; exit 254"
    : `printf '%s\\n' ${JSON.stringify(ssmValue)}`);
  fake("docker", `
case "$*" in
  *"ps -q telemetry-sink"*) ${sinkRunning ? "echo sinkcid" : "true"} ;;
  *"ps -q caddy"*) echo caddycid ;;
  *"ps -q mcp"*) echo mcpcid ;;
  *"ps -aq caddy host mcp"*) printf 'caddycid\\nhostcid\\nmcpcid\\n' ;;
  *"logs"*) echo '{"event":"telemetry-sink-ready","keyId":"sink-ed25519-x","keyCreated":true,"contractKeyIds":["contract-server-v1"],"peerEnv":"none"}' ;;
  inspect*) ${inspect} ;;
  *) true ;;
esac`);
  fake("sudo", 'shift 2; exec "$@"');
  fake("git", 'case "$*" in *"status --short"*) true ;; *"rev-parse"*) echo abc1234 ;; *show*) echo "mcp.clockchain.network {\n}" ;; esac');
  fake("sha256sum", 'echo "deadbeef  $1"');
  fake("stat", "echo ubuntu");
  return { temp, app, log, env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CLOCKCHAIN_MCP_APP_ROOT: app } };
}

function runScript(fx, args) {
  const res = spawnSync("bash", [script, ...args], { env: fx.env, encoding: "utf8" });
  let calls = [];
  try { calls = readFileSync(fx.log, "utf8").split("\n").filter(Boolean); } catch {}
  return { ...res, calls };
}

function assertNeverTouchesOthers(calls) {
  for (const call of calls) {
    assert.doesNotMatch(call, /\bdown\b|--full-restart|systemctl|--force-recreate|\brm\b|restart|volume rm/, call);
    if (/ up /.test(call)) {
      assert.match(call, /--profile telemetry up -d --no-deps\b.* telemetry-sink$/, `up only targets the sink: ${call}`);
    }
    if (/^docker compose/.test(call)) {
      assert.doesNotMatch(call, /\b(up|build|create|start|stop)\b.*\b(caddy|host|mcp)\s*$/, `never acts on caddy/host/mcp: ${call}`);
    }
  }
}

test("sink-up.sh parses and is strict-mode", () => {
  const syntax = spawnSync("bash", ["-n", script], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(readFileSync(script, "utf8"), /^set -euo pipefail$/m);
});

test("up: reads the PUBLIC keys param (no decryption), builds + starts only the sink with --no-deps", () => {
  const fx = fixture();
  const r = runScript(fx, ["up"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const ssm = r.calls.filter((c) => c.startsWith("aws "));
  assert.equal(ssm.length, 1, ssm.join("\n"));
  assert.match(ssm[0], /ssm get-parameter --name \/clockchain\/mcp\/TELEMETRY_CONTRACT_KEYS\b/);
  assert.doesNotMatch(ssm[0], /with-decryption/);
  assert.ok(r.calls.some((c) => /docker compose -f infra\/clockchain-mcp\/docker-compose\.yml --profile telemetry build telemetry-sink$/.test(c)), r.calls.join("\n"));
  assert.ok(r.calls.some((c) => /--profile telemetry up -d --no-deps --wait --wait-timeout \d+ telemetry-sink$/.test(c)), r.calls.join("\n"));
  assertNeverTouchesOthers(r.calls);
  assert.match(r.stdout, /telemetry-sink-ready/);
  assert.match(r.stdout, /caddy\/host\/mcp unchanged/);
  // The public key set is never echoed into SSM command output.
  assert.doesNotMatch(r.stdout + r.stderr, /J3iURWKkx4kAg/);
});

test("up refuses when the sink is already running (a restart loses every open run)", () => {
  const fx = fixture({ sinkRunning: true });
  const r = runScript(fx, ["up"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /REFUSING: telemetry-sink is already running/);
  assert.ok(!r.calls.some((c) => / up /.test(c)), "no up issued");
});

test("up refuses before touching docker when the keys param is missing, empty, or carries private material", () => {
  for (const opts of [
    { ssmMissing: true },
    { ssmValue: "{}" },
    { ssmValue: "not json" },
    { ssmValue: '{"k":{"kty":"OKP","crv":"Ed25519","x":"AA","d":"BB"}}' },
  ]) {
    const fx = fixture(opts);
    const r = runScript(fx, ["up"]);
    assert.notEqual(r.status, 0, JSON.stringify(opts));
    assert.match(r.stdout + r.stderr, /REFUSING:/, JSON.stringify(opts));
    assert.ok(!r.calls.some((c) => /^docker compose .* (build|up) /.test(c)), `no build/up: ${JSON.stringify(opts)}`);
  }
});

test("reload-caddy: docker cp + validate + reload in the running caddy; never recreates it", () => {
  const fx = fixture();
  const r = runScript(fx, ["reload-caddy"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const docker = r.calls.filter((c) => c.startsWith("docker "));
  const cp = docker.findIndex((c) => /^docker cp .*\/Caddyfile caddycid:\/tmp\/Caddyfile\.next$/.test(c));
  const validate = docker.findIndex((c) => /^docker exec caddycid caddy validate --config \/tmp\/Caddyfile\.next --adapter caddyfile$/.test(c));
  const reload = docker.findIndex((c) => /^docker exec caddycid caddy reload --config \/tmp\/Caddyfile\.next --adapter caddyfile$/.test(c));
  assert.ok(cp >= 0 && validate > cp && reload > validate, docker.join("\n"));
  assertNeverTouchesOthers(r.calls);
  assert.match(r.stdout, /caddy not recreated/);
});

test("reload-caddy <rev> reloads that revision's Caddyfile (rollback) via git show", () => {
  const fx = fixture();
  const r = runScript(fx, ["reload-caddy", "c6e6846"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(r.calls.some((c) => /^git .*show c6e6846:infra\/clockchain-mcp\/Caddyfile$/.test(c)), r.calls.join("\n"));
  assertNeverTouchesOthers(r.calls);
});

test("stop keeps the volume; unknown modes are rejected", () => {
  const fx = fixture();
  const r = runScript(fx, ["stop"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(r.calls.some((c) => /--profile telemetry stop telemetry-sink$/.test(c)));
  assertNeverTouchesOthers(r.calls);
  const bad = runScript(fixture(), ["down"]);
  assert.equal(bad.status, 64);
});

test("up tolerates host's self-restart (started= moves) but fails on a recreate (created= moves)", () => {
  const counter = (field) => `n=$(cat "$0.n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$0.n"; ` +
    (field === "started"
      ? 'echo "/host created=2026-10-01T00:00:00Z started=2026-10-01T00:00:0${n}Z"'
      : 'echo "/caddy created=2026-10-01T00:00:0${n}Z started=2026-10-01T00:00:00Z"');
  const ok = runScript(fixture({ inspect: counter("started") }), ["up"]);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /caddy\/host\/mcp unchanged/);
  const bad = runScript(fixture({ inspect: counter("created") }), ["up"]);
  assert.equal(bad.status, 1, bad.stdout + bad.stderr);
  assert.match(bad.stdout, /RECREATED/);
});
