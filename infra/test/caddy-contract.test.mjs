import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const caddyFile = path.resolve(new URL("../clockchain-mcp/Caddyfile", import.meta.url).pathname);

test("the plain AWS hostname proxies unchanged to the production MCP service", async () => {
  const source = await readFile(caddyFile, "utf8");
  const match = source.match(/mcp-aws\.clockchain\.network\s*\{([\s\S]*?)\n\}/);
  assert.ok(match, "mcp-aws site block exists");
  assert.match(match[1], /reverse_proxy\s+mcp:8080/);
  assert.doesNotMatch(match[1], /handle_path|uri\s+(?:strip_prefix|replace)|rewrite/);
});

test("the public hostname keeps production untouched outside the staging and pinned ACM4 prefixes", async () => {
  const source = await readFile(caddyFile, "utf8");
  const match = source.match(/mcp\.clockchain\.network\s*\{([\s\S]*?)\n\}/);
  assert.ok(match, "mcp.clockchain.network site block exists");
  const block = match[1];
  // Staging lives only inside a prefix-stripping handle_path routed at the staging
  // container — never at production's service.
  const staging = block.match(/handle_path\s+\/staging\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(staging, "handle_path /staging/* block exists");
  assert.match(staging[1], /reverse_proxy\s+mcp-staging:8080/);
  assert.match(staging[1], /header_up\s+X-Forwarded-Prefix\s+\/staging/);
  // ACM4 routing: /handshake/mcp serves the current build (flipped from the
  // pinned mcp-acm4 instance for packet #13) while the pinned 2.1.6 instance
  // stays reachable at /acm4/* for rollback, and the current build's handshake
  // surface is also exposed prefix-forwarded at /next/*.
  const acm4 = block.match(/handle_path\s+\/acm4\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(acm4, "handle_path /acm4/* block exists");
  assert.match(acm4[1], /reverse_proxy\s+mcp-acm4:8080/);
  assert.match(acm4[1], /header_up\s+X-Forwarded-Prefix\s+\/acm4/);
  const handshake = block.match(/handle\s+\/handshake\/mcp\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(handshake, "handle /handshake/mcp block exists");
  assert.match(handshake[1], /reverse_proxy\s+mcp:8080/);
  const next = block.match(/handle_path\s+\/next\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(next, "handle_path /next/* block exists");
  assert.match(next[1], /reverse_proxy\s+mcp:8080/);
  assert.match(next[1], /header_up\s+X-Forwarded-Prefix\s+\/next/);
  // Telemetry sink (D22): ingest, query and the public key route to the sink's
  // write (8081) and read (8082) listeners by compose DNS name; the close
  // listener (8083) is never routed — only mcp reaches it on clockchain_edge.
  const sinkIngest = block.match(/handle\s+\/telemetry\/v1\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(sinkIngest, "handle /telemetry/v1/* block exists");
  assert.match(sinkIngest[1], /^\s*uri\s+strip_prefix\s+\/telemetry\s*$/m);
  assert.match(sinkIngest[1], /^\s*reverse_proxy\s+telemetry-sink:8081\s*$/m);
  const sinkKeys = block.match(/handle\s+\/telemetry\/keys\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(sinkKeys, "handle /telemetry/keys block exists");
  assert.match(sinkKeys[1], /^\s*uri\s+replace\s+\/telemetry\/keys\s+\/v1\/keys\s*$/m);
  assert.match(sinkKeys[1], /^\s*reverse_proxy\s+telemetry-sink:8082\s*$/m);
  const sinkQuery = block.match(/handle\s+\/telemetry\/query\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(sinkQuery, "handle /telemetry/query/* block exists");
  assert.match(sinkQuery[1], /^\s*uri\s+replace\s+\/telemetry\/query\s+\/v1\s*$/m);
  assert.match(sinkQuery[1], /^\s*reverse_proxy\s+telemetry-sink:8082\s*$/m);
  assert.doesNotMatch(source, /8083|telemetry-sink[\w-]*:(?!808[12]\b)\d+/, "the close listener is never routed");
  assert.doesNotMatch(source, /\/close\b/);
  // Production only: no staging sink exists, so nothing routes to one.
  assert.doesNotMatch(source, /telemetry-sink-staging|\/staging\/telemetry/);
  // Everything outside those blocks must proxy unchanged to production.
  const rest = block.replace(staging[0], "").replace(acm4[0], "").replace(handshake[0], "").replace(next[0], "")
    .replace(sinkIngest[0], "").replace(sinkKeys[0], "").replace(sinkQuery[0], "")
    .split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");
  assert.match(rest, /reverse_proxy\s+mcp:8080/);
  assert.doesNotMatch(rest, /handle_path|handle\s|uri\s+(?:strip_prefix|replace)|rewrite|mcp-staging|mcp-acm4|telemetry/);
  assert.doesNotMatch(source, /role-access|responderAccess|initiatorAccess|capability/i);
});

test("the plain AWS hostname does not expose the telemetry sink", async () => {
  const source = await readFile(caddyFile, "utf8");
  const match = source.match(/mcp-aws\.clockchain\.network\s*\{([\s\S]*?)\n\}/);
  assert.ok(match);
  assert.doesNotMatch(match[1], /telemetry/);
});

test("every telemetry upstream Caddy routes to is a compose service on the edge network", async () => {
  const source = await readFile(caddyFile, "utf8");
  const compose = await readFile(new URL("../clockchain-mcp/docker-compose.yml", import.meta.url), "utf8");
  const upstreams = [...source.matchAll(/reverse_proxy\s+(telemetry[\w-]*):(\d+)/g)];
  assert.ok(upstreams.length > 0, "telemetry upstreams exist");
  for (const [, name, port] of upstreams) {
    const svc = compose.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [\\w-]+:\\n|^\\S)`, "m"));
    assert.ok(svc, `${name} is a compose service`);
    assert.match(svc[1], new RegExp(`^      - "${port}"\\s*$`, "m"), `${name} exposes ${port}`);
    assert.match(svc[1], /clockchain_edge/);
  }
});
