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
  // Everything outside those blocks must proxy unchanged to production.
  const rest = block.replace(staging[0], "").replace(acm4[0], "").replace(handshake[0], "").replace(next[0], "");
  assert.match(rest, /reverse_proxy\s+mcp:8080/);
  assert.doesNotMatch(rest, /handle_path|handle\s|uri\s+(?:strip_prefix|replace)|rewrite|mcp-staging|mcp-acm4/);
  assert.doesNotMatch(source, /role-access|responderAccess|initiatorAccess|capability/i);
});
