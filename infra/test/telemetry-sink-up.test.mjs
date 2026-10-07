import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
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

// runSetHead: undefined = the optional /clockchain/mcp/TELEMETRY_RUN_SET_HEAD parameter is
// absent (ParameterNotFound); a string = its value; DENIED = a non-NotFound read error.
const DENIED = Symbol("denied");
// anchor: the optional /clockchain/mcp/TELEMETRY_ANCHOR switch, same encoding as runSetHead.
// anchorToken: the SecureString /clockchain/mcp/TELEMETRY_ANCHOR_TOKEN as `aws --output text`
// prints it (value + newline); null = unreadable.
const ANCHOR_TOKEN = "a".repeat(24) + "5ec7e7" + "b".repeat(34);
function fixture({ ssmValue = PROD_KEYS, ssmMissing = false, runSetHead, anchor, anchorToken = `${ANCHOR_TOKEN}\n`, sinkRunning = false, inspect = 'echo "/c created=2026-10-01T00:00:00Z started=2026-10-01T00:00:00Z"' } = {}) {
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
  const keysBody = ssmMissing
    ? "echo 'ParameterNotFound' >&2; exit 254"
    : `printf '%s\\n' ${JSON.stringify(ssmValue)}`;
  const rshBody = runSetHead === undefined
    ? "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation' >&2; exit 254"
    : runSetHead === DENIED
      ? "echo 'An error occurred (AccessDeniedException) when calling the GetParameter operation' >&2; exit 254"
      : `printf '%s\\n' ${JSON.stringify(runSetHead)}`;
  const ancBody = anchor === undefined
    ? "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation' >&2; exit 254"
    : anchor === DENIED
      ? "echo 'An error occurred (AccessDeniedException) when calling the GetParameter operation' >&2; exit 254"
      : `printf '%s\\n' ${JSON.stringify(anchor)}`;
  const tokBody = anchorToken === null
    ? "echo 'An error occurred (AccessDeniedException) when calling the GetParameter operation' >&2; exit 254"
    : `printf '%b' ${JSON.stringify(anchorToken)}`;
  fake("aws", `
case "$*" in
  *"--name /clockchain/mcp/TELEMETRY_RUN_SET_HEAD "*) ${rshBody} ;;
  *"--name /clockchain/mcp/TELEMETRY_ANCHOR_TOKEN "*) ${tokBody} ;;
  *"--name /clockchain/mcp/TELEMETRY_ANCHOR "*) ${ancBody} ;;
  *) ${keysBody} ;;
esac`);
  fake("docker", `
case "$*" in
  *"ps -q telemetry-sink"*) ${sinkRunning ? "echo sinkcid" : "true"} ;;
  *"ps -q caddy"*) echo caddycid ;;
  *"ps -q mcp"*) echo mcpcid ;;
  *"ps -aq caddy host mcp"*) printf 'caddycid\\nhostcid\\nmcpcid\\n' ;;
  *"up -d"*) printf 'sink-env TELEMETRY_RUN_SET_HEAD=%s\\n' "\${TELEMETRY_RUN_SET_HEAD-<unset>}" >> ${JSON.stringify(log)} ;;
  *"logs"*) echo '{"event":"telemetry-sink-ready","keyId":"sink-ed25519-x","keyCreated":true,"contractKeyIds":["contract-server-v1"],"peerEnv":"none"}' ;;
  inspect*) ${inspect} ;;
  *) true ;;
esac`);
  fake("sudo", 'shift 2; exec "$@"');
  fake("git", 'case "$*" in *"status --short"*) true ;; *"rev-parse"*) echo abc1234 ;; *show*) echo "mcp.clockchain.network {\n}" ;; esac');
  fake("sha256sum", 'echo "deadbeef  $1"');
  fake("stat", "echo ubuntu");
  // Not root in tests: the owner/dir calls are recorded, not executed (chmod stays real).
  fake("chown", "true");
  fake("install", 'mkdir -p "${@: -1}"');
  const secretDir = path.join(temp, "secrets");
  return {
    temp, app, log, secretDir, secretFile: path.join(secretDir, "telemetry-anchor-token"),
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CLOCKCHAIN_MCP_APP_ROOT: app, TELEMETRY_ANCHOR_SECRET_DIR: secretDir },
  };
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
  // The PUBLIC keys param, then the optional run-set-head and anchor switches; none decrypted.
  assert.equal(ssm.length, 3, ssm.join("\n"));
  assert.match(ssm[0], /ssm get-parameter --name \/clockchain\/mcp\/TELEMETRY_CONTRACT_KEYS\b/);
  assert.match(ssm[1], /ssm get-parameter --name \/clockchain\/mcp\/TELEMETRY_RUN_SET_HEAD\b/);
  assert.match(ssm[2], /ssm get-parameter --name \/clockchain\/mcp\/TELEMETRY_ANCHOR --query\b/);
  for (const c of ssm) assert.doesNotMatch(c, /with-decryption/);
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

// CDT wiring: TELEMETRY_RUN_SET_HEAD (CDT-GAPS gap 4) is an optional SSM switch for the sink.

test("up: TELEMETRY_RUN_SET_HEAD absent in SSM leaves it unset — the pre-wiring sink env", () => {
  const fx = fixture();
  const env = { ...fx.env };
  delete env.TELEMETRY_RUN_SET_HEAD;
  const r = runScript({ ...fx, env }, ["up"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /runSetHead flag: absent/);
  assert.ok(r.calls.includes("sink-env TELEMETRY_RUN_SET_HEAD=<unset>"), r.calls.join("\n"));
  assertNeverTouchesOthers(r.calls);
});

test("up: TELEMETRY_RUN_SET_HEAD=1 / 0 in SSM is exported to the sink build/up; only on/off is printed", () => {
  for (const [value, verdict] of [["1", "on"], ["0", "off"]]) {
    const r = runScript(fixture({ runSetHead: value }), ["up"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, new RegExp(`runSetHead flag: ${verdict}`));
    assert.ok(r.calls.includes(`sink-env TELEMETRY_RUN_SET_HEAD=${value}`), r.calls.join("\n"));
    assertNeverTouchesOthers(r.calls);
  }
});

test("up refuses before build on an invalid TELEMETRY_RUN_SET_HEAD or a non-NotFound read error", () => {
  for (const opts of [{ runSetHead: "yes" }, { runSetHead: "true" }, { runSetHead: DENIED }]) {
    const r = runScript(fixture(opts), ["up"]);
    assert.equal(r.status, 4, String(opts.runSetHead?.toString()) + r.stdout + r.stderr);
    assert.match(r.stdout, /REFUSING: .*TELEMETRY_RUN_SET_HEAD/);
    assert.ok(!r.calls.some((c) => /^docker compose .* (build|up) /.test(c)), "no build/up");
    // The bad value itself is never echoed.
    if (typeof opts.runSetHead === "string") assert.doesNotMatch(r.stdout + r.stderr, new RegExp(`\\b${opts.runSetHead}\\b`));
  }
});

// R13(b) head anchor (N4b-8): TELEMETRY_ANCHOR switch + the dedicated MCP bearer as a 0400 secret file.

const OVERRIDE_RE = /-f infra\/clockchain-mcp\/docker-compose\.anchor\.yml\b/;
const composeCalls = (calls) => calls.filter((c) => /^docker compose /.test(c));
const assertNoToken = (r) => {
  assert.doesNotMatch(r.stdout + r.stderr, /5ec7e7/, "the token is never printed");
  assert.doesNotMatch(r.calls.join("\n"), /5ec7e7/, "the token is never on a command line");
};

test("up: TELEMETRY_ANCHOR absent or 0 = no override, no token read, no token file (an old one is removed)", () => {
  for (const [anchor, verdict] of [[undefined, "absent"], ["0", "off"], ["", "off"]]) {
    const fx = fixture({ anchor });
    mkdirSync(fx.secretDir, { recursive: true });
    writeFileSync(fx.secretFile, "stale\n");
    const r = runScript(fx, ["up"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, new RegExp(`anchor flag: ${verdict}`));
    assert.match(r.stdout, /anchor token file removed/);
    assert.ok(!existsSync(fx.secretFile));
    for (const c of composeCalls(r.calls)) assert.doesNotMatch(c, OVERRIDE_RE, c);
    assert.ok(!r.calls.some((c) => /TELEMETRY_ANCHOR_TOKEN|with-decryption/.test(c)), r.calls.join("\n"));
    assertNeverTouchesOthers(r.calls);
  }
});

test("up: TELEMETRY_ANCHOR=1 writes the token to a 0400 file for uid 10001 and adds the override to build + up", () => {
  const fx = fixture({ anchor: "1" });
  const r = runScript(fx, ["up"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /anchor flag: on/);
  const tokenRead = r.calls.filter((c) => /--name \/clockchain\/mcp\/TELEMETRY_ANCHOR_TOKEN /.test(c));
  assert.equal(tokenRead.length, 1);
  assert.match(tokenRead[0], /--with-decryption/);
  assert.equal(readFileSync(fx.secretFile, "utf8"), `${ANCHOR_TOKEN}\n`);
  assert.equal(statSync(fx.secretFile).mode & 0o777, 0o400);
  assert.ok(r.calls.some((c) => new RegExp(`^chown 10001:10001 ${fx.secretDir}/`).test(c)), r.calls.join("\n"));
  assert.ok(r.calls.some((c) => new RegExp(`^install -d -m 0711 -o root -g root ${fx.secretDir}$`).test(c)), r.calls.join("\n"));
  const build = composeCalls(r.calls).find((c) => / build telemetry-sink$/.test(c));
  const up = composeCalls(r.calls).find((c) => / up -d /.test(c));
  assert.match(build, OVERRIDE_RE);
  assert.match(up, OVERRIDE_RE);
  assert.match(up, /docker-compose\.yml -f infra\/clockchain-mcp\/docker-compose\.anchor\.yml --profile telemetry up -d --no-deps --wait --wait-timeout \d+ telemetry-sink$/);
  assertNeverTouchesOthers(r.calls);
  assertNoToken(r);
});

test("up refuses before build on a bad TELEMETRY_ANCHOR, a denied read, or an unusable token", () => {
  for (const opts of [
    { anchor: "yes" }, { anchor: "true" }, { anchor: DENIED },
    { anchor: "1", anchorToken: null },
    { anchor: "1", anchorToken: "\n" },
    { anchor: "1", anchorToken: `${ANCHOR_TOKEN} ${ANCHOR_TOKEN}\n` },
    { anchor: "1", anchorToken: `${ANCHOR_TOKEN},${ANCHOR_TOKEN}\n${ANCHOR_TOKEN}\n` },
  ]) {
    const fx = fixture(opts);
    const r = runScript(fx, ["up"]);
    assert.equal(r.status, 4, String(opts.anchor?.toString()) + r.stdout + r.stderr);
    assert.match(r.stdout, /REFUSING: .*TELEMETRY_ANCHOR/);
    assert.ok(!r.calls.some((c) => /^docker compose .* (build|up) /.test(c)), "no build/up");
    assert.ok(!existsSync(fx.secretFile), "no token file left behind");
    assertNoToken(r);
  }
});

test("status prints the ready line's anchor field", () => {
  const r = runScript(fixture(), ["status"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^anchor: unknown$/m); // the fixture's ready line has no anchor field
});
