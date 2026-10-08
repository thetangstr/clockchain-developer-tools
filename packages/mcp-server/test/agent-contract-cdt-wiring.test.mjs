// CDT wiring (track-b/cdt-wiring): the new optional settings reach the box
// through compose-up.sh (read_optional_env) and docker-compose.yml
// ("${NAME:-}"). An absent SSM parameter leaves the host variable unset and
// compose then injects "" — so "" must give exactly today's (b04059e)
// surface and behaviour. check-config / check-config-from-ssm know every new
// name and print verdicts, never values. Offline: OS-assigned loopback ports.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { buildServerCard } from "../dist/agent-contract/server-card.js";
import { checkConfig } from "../scripts/agent-contract/check-config.mjs";
import {
  ENV_PARAMETERS, IMAGE_BRIEFS_DIR, SINK_PARAMETERS, briefsDirForCheck, checkConfigFromSsm, checkoutAtSha, parseArgs,
} from "../scripts/agent-contract/check-config-from-ssm.mjs";
import { ACCEPT, HOST_ROOTS, POLICY } from "./n4b9-harness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const B04059E = JSON.parse(readFileSync(path.join(here, "fixtures", "b04059e-tools-list.json"), "utf8"));

/** The settings b04059e does not read — the exact list compose-up.sh gained. */
const CDT_NAMES = [
  "TELEMETRY_LANES", "TELEMETRY_SINK_KEY_ID", "CONTRACT_DIRECTORY", "CONTRACT_MAX_RUNS_PER_KEY",
  "CONTRACT_POLICY_REGISTRATION", "CONTRACT_SERVER_ANCHORS", "CONTRACT_EXPIRE_AT_TTL",
  "CONTRACT_BRIEFS", "CONTRACT_BRIEFS_DIR", "CONTRACT_ROLE_BRIEFS",
  "CONTRACT_MILESTONE_LOG",
  "CONTRACT_FLEX_POLICY",
  "CONTRACT_PRIVATE_FLOOR", "CONTRACT_PRIVATE_FLOOR_BPS",
];
/** What compose injects for every one of them when its SSM parameter is absent. */
const COMPOSE_ABSENT = Object.fromEntries(CDT_NAMES.map((n) => [n, ""]));

const TOKENS_RAW = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder";
const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const SINK_KEY_ID = "sink-ed25519-wiring-fixture";

function baseEnv(extra = {}) {
  return {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS_RAW,
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-wiring",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-")),
    ...extra,
  };
}

function briefsFixture() {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-wiring-briefs-"));
  const text = "# family travel brief (wiring fixture)\n";
  writeFileSync(path.join(dir, "family-travel.md"), text);
  const digest = `0x${createHash("sha256").update(text).digest("hex")}`;
  return { dir, raw: `family-travel:${digest}`, digest };
}

/** Every CDT feature on, valid (lanes need the close URL + sink keyId). */
function allOnEnv() {
  const briefs = briefsFixture();
  return {
    env: baseEnv({
      TELEMETRY_CLOSE_URL: "http://127.0.0.1:9",
      TELEMETRY_LANES: "1",
      TELEMETRY_SINK_KEY_ID: SINK_KEY_ID,
      CONTRACT_DIRECTORY: "roma-travel:kp1",
      CONTRACT_MAX_RUNS_PER_KEY: "4",
      CONTRACT_POLICY_REGISTRATION: "1",
      CONTRACT_SERVER_ANCHORS: "1",
      CONTRACT_EXPIRE_AT_TTL: "1",
      CONTRACT_BRIEFS: briefs.raw,
      CONTRACT_BRIEFS_DIR: briefs.dir,
      CONTRACT_ROLE_BRIEFS: "buyer:family-travel,provider:family-travel",
      CONTRACT_MILESTONE_LOG: "1",
      CONTRACT_FLEX_POLICY: "1",
    }),
    briefs,
  };
}

const closeServer = (srv) => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });

/** Production wiring (loadContractConfig → the HTTP handler) on an OS-assigned loopback port. */
async function bootWire(t, env) {
  const cfg = loadContractConfig(env);
  assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
  t.after(() => cfg.service.close());
  const srv = createServer(createContractHttpHandler({
    authenticate: cfg.authenticate, hostRoots: cfg.hostRoots, signer: cfg.signer, service: cfg.service,
    ...(cfg.telemetryLanes !== undefined ? { telemetryLanes: cfg.telemetryLanes } : {}),
  }));
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => closeServer(srv));
  const baseUrl = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
  const sessions = new Map();
  let id = 1;
  const post = (token, sid, body) => fetch(baseUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`,
      ...(sid ? { "mcp-session-id": sid } : {}),
    },
    body: JSON.stringify(body),
  });
  const rpc = async (token, method, params) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await post(token, undefined, { jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "wiring", version: "1" } } });
      sid = init.headers.get("mcp-session-id");
      await init.text();
      sessions.set(token, sid);
      await (await post(token, sid, { jsonrpc: "2.0", method: "notifications/initialized" })).text();
    }
    const text = await (await post(token, sid, { jsonrpc: "2.0", id: id++, method, params })).text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    return JSON.parse(data ? data.slice(5) : text);
  };
  const callTool = async (token, name, args = {}) => {
    const body = await rpc(token, "tools/call", { name, arguments: args });
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  return { cfg, listTools: async (token) => (await rpc(token, "tools/list", {})).result, callTool };
}

// =============================================================================
// P2 item 4: absent parameters give exactly today's behaviour.
// =============================================================================

test("wiring: every new setting as compose injects it when absent (\"\") serves exactly b04059e's surface", async (t) => {
  const env = await bootWire(t, baseEnv(COMPOSE_ABSENT));
  const { cfg } = env;
  assert.deepEqual(cfg.service.features, {});
  assert.equal(cfg.service.serverAnchors, false);
  assert.equal(cfg.service.roleBriefs, false);
  assert.equal(cfg.telemetryLanes, undefined, "no lanes object without TELEMETRY_LANES=1");

  const buyerList = await env.listTools("tb1");
  const providerList = await env.listTools("tp1");
  assert.deepEqual(buyerList, B04059E.buyer.toolsList);
  assert.deepEqual(providerList, B04059E.provider.toolsList);
  assert.equal(canonicalDigest(buyerList), B04059E.buyer.guidance.toolsListDigest);
  assert.equal(canonicalDigest(providerList), B04059E.provider.guidance.toolsListDigest);
  const card = buildServerCard([], { features: cfg.service.features });
  assert.deepEqual(card.guidance.buyer, B04059E.buyer.guidance);
  assert.deepEqual(card.guidance.provider, B04059E.provider.guidance);

  // The gated tools answer NOT_FOUND exactly like at b04059e.
  for (const [token, name] of [["tb1", "contract_register_policy"], ["tb1", "contract_get_brief"], ["tp1", "telemetry_open"]]) {
    assert.equal((await env.callTool(token, name, {})).error, "NOT_FOUND", name);
  }
});

test("wiring: \"\" and truly unset load the same config (the compose passthrough is neutral)", async () => {
  const stateA = mkdtempSync(path.join(tmpdir(), "cdt-wiring-a-"));
  const stateB = mkdtempSync(path.join(tmpdir(), "cdt-wiring-b-"));
  const unset = loadContractConfig(baseEnv({ CONTRACT_STATE_DIR: stateA }));
  const empty = loadContractConfig(baseEnv({ ...COMPOSE_ABSENT, CONTRACT_STATE_DIR: stateB }));
  try {
    assert.equal(unset.kind, "ready");
    assert.equal(empty.kind, "ready");
    assert.deepEqual(empty.service.features, unset.service.features);
    assert.equal(empty.service.serverAnchors, unset.service.serverAnchors);
    assert.equal(empty.service.roleBriefs, unset.service.roleBriefs);
    assert.equal(empty.telemetryLanes, unset.telemetryLanes);
  } finally {
    unset.service?.close();
    empty.service?.close();
  }

  // check-config: the same report either way (state dir aside), all features off.
  const a = await checkConfig(baseEnv());
  const b = await checkConfig(baseEnv(COMPOSE_ABSENT));
  assert.equal(a.exitCode, 0, JSON.stringify(a.report));
  assert.equal(b.exitCode, 0, JSON.stringify(b.report));
  const strip = ({ stateDir: _s, ...rest }) => rest;
  assert.deepEqual(strip(b.report), strip(a.report));
  assert.deepEqual(b.report.features, {
    telemetryLanes: "off", telemetrySinkKeyId: "absent", policyRegistration: "off", serverAnchors: "off",
    expireAtTtl: "off", roleBriefs: "off", milestoneLog: "off", briefs: 0, directory: 0,
  });
  assert.equal(b.report.limits.maxRunsPerKey, 1);
  assert.deepEqual(b.report.warnings, []);
});

// =============================================================================
// P2 item 2: check-config knows and validates the new names; verdicts only.
// =============================================================================

test("check-config: all CDT features on → on/configured verdicts and counts, no values", async () => {
  const { env, briefs } = allOnEnv();
  const out = await checkConfig({ ...env, CONTRACT_ANCHOR_ENABLED: "1" });
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  assert.deepEqual(out.report.features, {
    telemetryLanes: "on", telemetrySinkKeyId: "configured", policyRegistration: "on", serverAnchors: "on",
    expireAtTtl: "on", roleBriefs: "on", milestoneLog: "on", flexPolicy: "on", briefs: 1, directory: 1,
  });
  assert.equal(out.report.limits.maxRunsPerKey, 4);
  assert.deepEqual(out.report.warnings, []);
  const text = JSON.stringify(out.report);
  for (const value of [SINK_KEY_ID, briefs.digest, briefs.dir, "roma-travel", "family-travel", SEED_B64, "tb1", "tp1"]) {
    assert.equal(text.includes(value), false, `report leaks ${value}`);
  }
});

test("check-config: invalid or incomplete CDT settings are misconfigurations naming the setting", async () => {
  const cases = [
    [{ TELEMETRY_LANES: "1", TELEMETRY_CLOSE_URL: "http://127.0.0.1:9" }, /TELEMETRY_SINK_KEY_ID/],
    [{ TELEMETRY_LANES: "1", TELEMETRY_SINK_KEY_ID: SINK_KEY_ID }, /TELEMETRY_CLOSE_URL/],
    [{ TELEMETRY_LANES: "yes" }, /TELEMETRY_LANES wants 0 or 1/],
    [{ CONTRACT_MAX_RUNS_PER_KEY: "0" }, /CONTRACT_MAX_RUNS_PER_KEY/],
    [{ CONTRACT_MAX_RUNS_PER_KEY: "65" }, /CONTRACT_MAX_RUNS_PER_KEY/],
    [{ CONTRACT_POLICY_REGISTRATION: "true" }, /CONTRACT_POLICY_REGISTRATION wants 0 or 1/],
    [{ CONTRACT_SERVER_ANCHORS: "on" }, /CONTRACT_SERVER_ANCHORS wants 0 or 1/],
    [{ CONTRACT_EXPIRE_AT_TTL: "2" }, /CONTRACT_EXPIRE_AT_TTL wants 0 or 1/],
    [{ CONTRACT_BRIEFS: `x:0x${"ab".repeat(32)}` }, /absolute CONTRACT_BRIEFS_DIR/],
    [{ CONTRACT_BRIEFS: `x:0x${"ab".repeat(32)}`, CONTRACT_BRIEFS_DIR: "relative/dir" }, /absolute CONTRACT_BRIEFS_DIR/],
    [{ CONTRACT_ROLE_BRIEFS: "buyer:x" }, /CONTRACT_ROLE_BRIEFS requires CONTRACT_SERVER_ANCHORS=1/],
    [{ CONTRACT_DIRECTORY: "roma-travel:kb1" }, /CONTRACT_DIRECTORY/],
  ];
  for (const [extra, re] of cases) {
    const out = await checkConfig(baseEnv(extra));
    assert.equal(out.exitCode, 1, JSON.stringify(extra));
    assert.equal(out.report.status, "misconfigured", JSON.stringify(extra));
    assert.match(out.report.reason, re, JSON.stringify(extra));
    assert.equal(JSON.stringify(out.report).includes(SINK_KEY_ID), false);
  }
});

test("check-config: settings that load but do nothing as combined are warnings, not refusals", async () => {
  const briefs = briefsFixture();
  const out = await checkConfig(baseEnv({
    CONTRACT_SERVER_ANCHORS: "1",
    TELEMETRY_SINK_KEY_ID: SINK_KEY_ID,
    CONTRACT_BRIEFS_DIR: briefs.dir,
  }));
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  assert.equal(out.report.warnings.length, 3, JSON.stringify(out.report.warnings));
  assert.match(out.report.warnings.join("\n"), /CONTRACT_SERVER_ANCHORS=1 without CONTRACT_ANCHOR_ENABLED=1/);
  assert.match(out.report.warnings.join("\n"), /TELEMETRY_SINK_KEY_ID is set but TELEMETRY_LANES is off/);
  assert.match(out.report.warnings.join("\n"), /CONTRACT_BRIEFS_DIR is set without CONTRACT_BRIEFS/);
  assert.equal(JSON.stringify(out.report).includes(SINK_KEY_ID), false);
  assert.equal(JSON.stringify(out.report).includes(briefs.dir), false);
});

// =============================================================================
// check-config-from-ssm: the new names are fetched; the sink switch is a verdict.
// =============================================================================

const PREFIX = "/clockchain/mcp";
const PUBLIC_KEYS = (keyId) => JSON.stringify({ [keyId]: { kty: "OKP", crv: "Ed25519", x: "J3iURWKkx4kAg-leW-NDKp7AUZQNdowUfLb5HHlQ0xU" } });

function ssmFetch(values, calls = []) {
  const found = new Map(Object.entries(values).map(([k, v]) => [`${PREFIX}/${k}`, v]));
  return async ({ name }) => { calls.push(name); return found.get(name); };
}

test("check-config-from-ssm: ENV_PARAMETERS carries every new mcp name; the sink names are separate", () => {
  for (const name of CDT_NAMES) assert.ok(ENV_PARAMETERS.includes(name), name);
  assert.deepEqual(SINK_PARAMETERS, ["TELEMETRY_CONTRACT_KEYS", "TELEMETRY_RUN_SET_HEAD"]);
  for (const name of SINK_PARAMETERS) assert.equal(ENV_PARAMETERS.includes(name), false, name);
});

test("check-config-from-ssm: all new parameters absent → today's report, sink switch absent, nothing written for the sink", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-"));
  const values = { ...baseEnv(), CONTRACT_STATE_DIR: stateDir };
  const calls = [];
  const env = {};
  const out = await checkConfigFromSsm({ env, fetchParameter: ssmFetch(values, calls) });
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  for (const name of CDT_NAMES) {
    assert.equal(out.report.parameters[name], "absent", name);
    assert.equal(env[name], undefined, `${name} stays unset`);
  }
  assert.deepEqual(out.report.sink, {
    parameters: { TELEMETRY_CONTRACT_KEYS: "absent", TELEMETRY_RUN_SET_HEAD: "absent" },
    runSetHead: "absent", contractKeys: "absent", signerKeyPublished: null, refusals: [],
  });
  assert.equal(env.TELEMETRY_RUN_SET_HEAD, undefined);
  assert.equal(env.TELEMETRY_CONTRACT_KEYS, undefined);
  // Every mcp name, then the two sink names — one GetParameter each.
  assert.deepEqual(calls, [...ENV_PARAMETERS, ...SINK_PARAMETERS].map((n) => `${PREFIX}/${n}`));
});

test("check-config-from-ssm: sink TELEMETRY_RUN_SET_HEAD verdicts; an invalid value refuses (exit 1) without echoing it", async () => {
  for (const [value, verdict] of [["1", "on"], ["0", "off"], ["", "off"]]) {
    const out = await checkConfigFromSsm({
      env: {}, fetchParameter: ssmFetch({ ...baseEnv(), TELEMETRY_RUN_SET_HEAD: value }),
    });
    assert.equal(out.exitCode, 0, JSON.stringify(out.report));
    assert.equal(out.report.sink.runSetHead, verdict);
    assert.equal(out.report.sink.parameters.TELEMETRY_RUN_SET_HEAD, "present");
  }
  const bad = await checkConfigFromSsm({
    env: {}, fetchParameter: ssmFetch({ ...baseEnv(), TELEMETRY_RUN_SET_HEAD: "enabled-please" }),
  });
  assert.equal(bad.exitCode, 1);
  assert.equal(bad.report.status, "refused");
  assert.equal(bad.report.sink.runSetHead, "invalid");
  assert.match(bad.report.refusals.join("\n"), /TELEMETRY_RUN_SET_HEAD wants 0 or 1/);
  assert.equal(JSON.stringify(bad.report).includes("enabled-please"), false);
});

test("check-config-from-ssm: lanes on warns when the sink's public key set is absent or lacks the signer keyId", async () => {
  const { env: onEnv } = allOnEnv();
  // onEnv carries a local fixture briefs dir (not the image dir): local use.
  const run = async (extra) => checkConfigFromSsm({ env: {}, allowLocalBriefsDir: true, fetchParameter: ssmFetch({ ...onEnv, CONTRACT_ANCHOR_ENABLED: "1", ...extra }) });

  const missing = await run({});
  assert.equal(missing.exitCode, 0, JSON.stringify(missing.report));
  assert.match(missing.report.warnings.join("\n"), /TELEMETRY_CONTRACT_KEYS is absent/);

  const other = await run({ TELEMETRY_CONTRACT_KEYS: PUBLIC_KEYS("some-other-key") });
  assert.equal(other.report.sink.contractKeys, "valid");
  assert.equal(other.report.sink.signerKeyPublished, false);
  assert.match(other.report.warnings.join("\n"), /does not carry this server's signer keyId/);

  const good = await run({ TELEMETRY_CONTRACT_KEYS: PUBLIC_KEYS("contract-server-wiring") });
  assert.equal(good.report.sink.signerKeyPublished, true);
  assert.deepEqual(good.report.warnings, []);
  assert.equal(JSON.stringify(good.report).includes("J3iURWKkx4kAg"), false, "the key bytes are never printed");

  const priv = await run({ TELEMETRY_CONTRACT_KEYS: JSON.stringify({ k: { kty: "OKP", x: "AA", d: "BB" } }) });
  assert.equal(priv.exitCode, 1);
  assert.equal(priv.report.sink.contractKeys, "invalid");
});

// =============================================================================
// Frozen briefs: committed under packages/mcp-server/assets/briefs and shipped
// in the image (no compose volume, no box-side write, no extra drift file).
// Track C's production shape: registration on, role briefs on, directory off,
// one run per key.
// =============================================================================

const REPO_ROOT = path.resolve(here, "..", "..", "..");

test("briefs ship in the image: the runtime stage copies packages/mcp-server/assets to /app; .dockerignore keeps nested .md files", () => {
  const dockerfile = readFileSync(path.join(REPO_ROOT, "Dockerfile"), "utf8");
  const runtime = dockerfile.slice(dockerfile.indexOf("AS runtime"));
  assert.ok(runtime.length < dockerfile.length, "a runtime stage exists");
  assert.match(runtime, /^WORKDIR \/app$/m);
  assert.match(runtime, /^COPY --from=build \/app\/packages\/mcp-server\/assets \.\/packages\/mcp-server\/assets$/m);
  assert.match(dockerfile, /^COPY packages\/mcp-server packages\/mcp-server$/m, "the build stage takes the whole package");
  assert.equal(IMAGE_BRIEFS_DIR, "/app/packages/mcp-server/assets/briefs");
  // .dockerignore patterns are root-anchored: "*.md" drops root-level docs only.
  const ignore = readFileSync(path.join(REPO_ROOT, ".dockerignore"), "utf8").split("\n").map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));
  for (const pattern of ignore) {
    assert.ok(!/^\*\*\/\*\.md$|assets|briefs|^packages\/mcp-server\/?$|^packages\/?$/.test(pattern), `.dockerignore would drop the briefs: ${pattern}`);
  }
});

function checkoutWithBrief(name, text) {
  const root = mkdtempSync(path.join(tmpdir(), "cdt-wiring-checkout-"));
  const dir = path.join(root, "packages", "mcp-server", "assets", "briefs");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, `${name}.md`), text);
  return { root, digest: `0x${createHash("sha256").update(text).digest("hex")}` };
}

test("briefsDirForCheck: the image dir maps onto the checkout; any other path is refused unless allowLocal (host paths only)", () => {
  assert.deepEqual(briefsDirForCheck("", "/r"), {});
  assert.deepEqual(briefsDirForCheck(IMAGE_BRIEFS_DIR, "/r"), { dir: "/r/packages/mcp-server/assets/briefs", source: "image" });
  const must = /CONTRACT_BRIEFS_DIR must be \/app\/packages\/mcp-server\/assets\/briefs/;
  assert.match(briefsDirForCheck("/app/state/briefs", "/r").refusal, must);
  // A host path would hash this machine's disk, not the box's: refused by default.
  assert.match(briefsDirForCheck("/opt/briefs", "/r").refusal, must);
  assert.match(briefsDirForCheck("/tmp/b", "/r").refusal, must);
  assert.deepEqual(briefsDirForCheck("/tmp/b", "/r", { allowLocal: true }), { dir: "/tmp/b", source: "local" });
  assert.match(briefsDirForCheck("/app/state/briefs", "/r", { allowLocal: true }).refusal, must);
});

test("check-config-from-ssm: Track C's production shape (registration on, role briefs on, directory off, 1 run per key) is ready; names and verdicts only", async () => {
  const text = "# family travel door brief (wiring fixture)\n";
  const { root, digest } = checkoutWithBrief("family-travel-door", text);
  const stateDir = mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-"));
  const shape = {
    ...baseEnv(), CONTRACT_STATE_DIR: stateDir,
    CONTRACT_ANCHOR_ENABLED: "1",
    CONTRACT_POLICY_REGISTRATION: "1",
    CONTRACT_SERVER_ANCHORS: "1",
    CONTRACT_BRIEFS: `family-travel-door:${digest}`,
    CONTRACT_BRIEFS_DIR: IMAGE_BRIEFS_DIR,
    CONTRACT_ROLE_BRIEFS: "buyer:family-travel-door,provider:family-travel-door",
    CONTRACT_MAX_RUNS_PER_KEY: "1",
  };
  const env = {};
  const out = await checkConfigFromSsm({ env, checkoutRoot: root, fetchParameter: ssmFetch(shape) });
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  assert.equal(out.report.status, "ready");
  assert.equal(out.report.briefsDir, "image");
  assert.deepEqual(out.report.features, {
    telemetryLanes: "off", telemetrySinkKeyId: "absent", policyRegistration: "on", serverAnchors: "on",
    expireAtTtl: "off", roleBriefs: "on", milestoneLog: "off", briefs: 1, directory: 0,
  });
  assert.equal(out.report.limits.maxRunsPerKey, 1);
  assert.deepEqual(out.report.warnings, []);
  assert.equal(out.report.parameters.CONTRACT_DIRECTORY, "absent");
  const printed = JSON.stringify(out.report);
  for (const value of [digest, root, text.trim(), "family-travel-door", SEED_B64]) {
    assert.equal(printed.includes(value), false, `report leaks ${value}`);
  }

  // Refusals, each naming the setting (never the brief text or the checkout path).
  const refuse = async (extra, re, checkoutRoot = root) => {
    const r = await checkConfigFromSsm({ env: {}, checkoutRoot, fetchParameter: ssmFetch({ ...shape, CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")), ...extra }) });
    assert.equal(r.exitCode, 1, JSON.stringify(extra));
    assert.equal(r.report.status, "misconfigured", JSON.stringify(r.report));
    assert.match(r.report.reason, re);
    assert.equal(JSON.stringify(r.report).includes(text.trim()), false);
  };
  await refuse({ CONTRACT_BRIEFS: `family-travel-door:0x${"ab".repeat(32)}` }, /does not match its pinned digest/);
  await refuse({}, /no brief file for family-travel-door/, mkdtempSync(path.join(tmpdir(), "cdt-wiring-empty-")));
  await refuse({ CONTRACT_BRIEFS_DIR: "/app/state/briefs" }, /CONTRACT_BRIEFS_DIR must be/);
  await refuse({ CONTRACT_ROLE_BRIEFS: "buyer:other-brief" }, /CONTRACT_ROLE_BRIEFS: other-brief is not a CONTRACT_BRIEFS name/);
  await refuse({ CONTRACT_SERVER_ANCHORS: "" }, /CONTRACT_ROLE_BRIEFS requires CONTRACT_SERVER_ANCHORS=1/);
  await refuse({ CONTRACT_BRIEFS: "", CONTRACT_BRIEFS_DIR: "" }, /CONTRACT_ROLE_BRIEFS requires CONTRACT_BRIEFS/);
});

test("check-config-from-ssm: Track C's revised shape with the committed family-travel-tc-door brief (role briefs absent) is ready; names and verdicts only", async () => {
  const name = "family-travel-tc-door";
  const text = readFileSync(path.join(REPO_ROOT, "packages", "mcp-server", "assets", "briefs", `${name}.md`), "utf8");
  const digest = `0x${createHash("sha256").update(text).digest("hex")}`;
  assert.equal(digest, "0xaac93fd922c8b712ef48ab839066cda166faad979b75b3425697785229dc324b", "the committed brief is the exact file Track C pinned");
  const shape = {
    ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")),
    CONTRACT_ANCHOR_ENABLED: "1",
    CONTRACT_POLICY_REGISTRATION: "1",
    CONTRACT_SERVER_ANCHORS: "1",
    CONTRACT_BRIEFS: `${name}:${digest}`,
    CONTRACT_BRIEFS_DIR: IMAGE_BRIEFS_DIR,
    CONTRACT_MAX_RUNS_PER_KEY: "1",
  };
  const out = await checkConfigFromSsm({ env: {}, checkoutRoot: REPO_ROOT, fetchParameter: ssmFetch(shape) });
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  assert.equal(out.report.status, "ready");
  assert.equal(out.report.briefsDir, "image");
  assert.deepEqual(out.report.features, {
    telemetryLanes: "off", telemetrySinkKeyId: "absent", policyRegistration: "on", serverAnchors: "on",
    expireAtTtl: "off", roleBriefs: "off", milestoneLog: "off", briefs: 1, directory: 0,
  });
  assert.equal(out.report.limits.maxRunsPerKey, 1);
  assert.equal(out.report.parameters.CONTRACT_ROLE_BRIEFS, "absent");
  assert.equal(out.report.parameters.CONTRACT_DIRECTORY, "absent");
  const printed = JSON.stringify(out.report);
  for (const value of [digest, digest.slice(2), name, text.slice(0, 40).trim(), SEED_B64]) {
    assert.equal(printed.includes(value), false, `report leaks ${value.slice(0, 12)}…`);
  }
});

// =============================================================================
// Track C wiring review (2026-10-07) fixes 1-3 and 7.
// =============================================================================

test("review fix 1: a leftover shell CONTRACT_MAX_RUNS_PER_KEY / CONTRACT_BRIEFS does not give a false ready when SSM lacks them", async () => {
  const { root } = checkoutWithBrief("family-travel-door", "# leftover\n");
  const env = {
    CONTRACT_MAX_RUNS_PER_KEY: "5",
    CONTRACT_BRIEFS: `family-travel-door:0x${"cd".repeat(32)}`,
    CONTRACT_BRIEFS_DIR: IMAGE_BRIEFS_DIR,
    CONTRACT_POLICY_REGISTRATION: "1",
    UNRELATED_SHELL_VAR: "kept",
  };
  const out = await checkConfigFromSsm({
    env, checkoutRoot: root,
    fetchParameter: ssmFetch({ ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")) }),
  });
  assert.equal(out.exitCode, 0, JSON.stringify(out.report));
  for (const name of ["CONTRACT_MAX_RUNS_PER_KEY", "CONTRACT_BRIEFS", "CONTRACT_BRIEFS_DIR", "CONTRACT_POLICY_REGISTRATION"]) {
    assert.equal(out.report.parameters[name], "absent", name);
    assert.equal(env[name], undefined, `${name} must not be inherited from the shell`);
  }
  assert.equal(env.UNRELATED_SHELL_VAR, "kept", "only the contract surface is cleared");
  assert.equal(out.report.briefsDir, "absent");
  assert.equal(out.report.features.briefs, 0);
  assert.equal(out.report.features.policyRegistration, "off");
  assert.notEqual(out.report.limits.maxRunsPerKey, 5);
});

test("review fix 2: against SSM a host CONTRACT_BRIEFS_DIR is refused (it would hash the operator's disk); --allow-local-briefs-dir lets it through", async () => {
  const text = "# local brief\n";
  const { root, digest } = checkoutWithBrief("family-travel-door", text);
  const hostDir = path.join(root, "packages", "mcp-server", "assets", "briefs");
  const shape = {
    ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")),
    CONTRACT_BRIEFS: `family-travel-door:${digest}`, CONTRACT_BRIEFS_DIR: hostDir,
  };
  const refused = await checkConfigFromSsm({ env: {}, checkoutRoot: root, fetchParameter: ssmFetch(shape) });
  assert.equal(refused.exitCode, 1);
  assert.match(refused.report.reason, /CONTRACT_BRIEFS_DIR must be/);
  assert.equal(JSON.stringify(refused.report).includes(hostDir), false, "the local path is not printed");
  const local = await checkConfigFromSsm({
    env: {}, checkoutRoot: root, allowLocalBriefsDir: true,
    fetchParameter: ssmFetch({ ...shape, CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")) }),
  });
  assert.equal(local.exitCode, 0, JSON.stringify(local.report));
  assert.equal(local.report.briefsDir, "local");
  assert.deepEqual(parseArgs(["--allow-local-briefs-dir"]).allowLocalBriefsDir, true);
});

test("review fix 3: --expect-sha refuses unless HEAD is that sha and packages/mcp-server is clean; pinned verdicts say so", async () => {
  const W = "a".repeat(40);
  const fakeGit = (head, dirty = "") => (_cwd, args) => (args[0] === "rev-parse" ? `${head}\n` : dirty);
  assert.deepEqual(checkoutAtSha(W, "/r", fakeGit(W)), { checkout: "pinned" });
  assert.match(checkoutAtSha(W, "/r", fakeGit("b".repeat(40))).refusal, /checkout HEAD bbbbbbbbbbbb is not --expect-sha aaaaaaaaaaaa/);
  assert.match(checkoutAtSha(W, "/r", fakeGit(W, " M packages/mcp-server/assets/briefs/x.md\n")).refusal, /uncommitted or untracked/);
  assert.match(checkoutAtSha("734c81b", "/r", fakeGit(W)).refusal, /full 40-hex/);
  assert.match(checkoutAtSha(W, "/r", () => { throw new Error("not a repo"); }).refusal, /not a readable git checkout/);
  const git = fakeGit(W);
  const calls = [];
  const fetchParameter = ssmFetch({ ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")) }, calls);
  const pinned = await checkConfigFromSsm({ env: {}, expectSha: W, git, fetchParameter });
  assert.equal(pinned.exitCode, 0, JSON.stringify(pinned.report));
  assert.equal(pinned.report.checkout, "pinned");
  const before = calls.length;
  const mismatch = await checkConfigFromSsm({ env: {}, expectSha: W, git: fakeGit("c".repeat(40)), fetchParameter });
  assert.equal(mismatch.exitCode, 1);
  assert.equal(mismatch.report.status, "refused");
  assert.equal(mismatch.report.checkout, "mismatch");
  assert.equal(calls.length, before, "a wrong checkout reads nothing from SSM");
  const unpinned = await checkConfigFromSsm({
    env: {}, fetchParameter: ssmFetch({ ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")) }),
  });
  assert.equal(unpinned.report.checkout, "unpinned");
  assert.equal(parseArgs(["--expect-sha", W]).expectSha, W);
  assert.equal(parseArgs([`--expect-sha=${W}`]).expectSha, W);
  assert.match(parseArgs(["--expect-sha"]).error, /wants a value/);
});

test("review fix 3: --expect-sha against this real checkout: HEAD passes only when packages/mcp-server is clean", () => {
  const head = execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const dirty = execFileSync("git", ["-C", REPO_ROOT, "status", "--porcelain", "--", "packages/mcp-server"], { encoding: "utf8" }).trim();
  const r = checkoutAtSha(head, REPO_ROOT);
  if (dirty === "") assert.deepEqual(r, { checkout: "pinned" });
  else assert.match(r.refusal, /uncommitted or untracked/);
  assert.match(checkoutAtSha("0".repeat(40), REPO_ROOT).refusal, /is not --expect-sha/);
});

test("review fix 7: the sink parameters are read WITHOUT decryption (as sink-up.sh reads them); the mcp surface with it", async () => {
  const seen = [];
  const values = new Map(Object.entries({
    ...baseEnv(), CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-wiring-ssm-")),
    TELEMETRY_RUN_SET_HEAD: "1",
  }).map(([k, v]) => [`${PREFIX}/${k}`, v]));
  // A SecureString: plaintext only when decrypted; sink-up.sh would see ciphertext.
  const fetchParameter = async ({ name, withDecryption }) => {
    seen.push({ name: name.slice(PREFIX.length + 1), withDecryption });
    if (name.endsWith("/TELEMETRY_RUN_SET_HEAD") && withDecryption !== true) return "AQICAHh-ciphertext";
    return values.get(name);
  };
  const out = await checkConfigFromSsm({ env: {}, fetchParameter });
  assert.equal(out.exitCode, 1);
  assert.equal(out.report.sink.runSetHead, "invalid");
  assert.equal(JSON.stringify(out.report).includes("ciphertext"), false);
  for (const { name, withDecryption } of seen) {
    assert.equal(withDecryption, !SINK_PARAMETERS.includes(name), name);
  }
});
